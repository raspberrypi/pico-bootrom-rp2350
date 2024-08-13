/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "varm_boot_path.h"
#include "bootrom_otp.h"
#include "native_generic_flash.h"
#include "arm8_sig.h"
#include "hardware/structs/qmi.h"
#include "sb_sha256.h"

#if defined(__ARM_ARCH_8M_MAIN__) || !defined(__ARM_ARCH_8M_BASE__)
#error this must be compiled with armv8m-base
#endif

static_assert(PICOBIN_PARTITION_LOCATION_SECTOR_BIT_MASK == (1u << PICOBIN_PARTITION_LOCATION_LAST_SECTOR_LSB) - 1u, "");
static_assert(PICOBIN_PARTITION_LOCATION_SECTOR_BIT_MASK == MAX_FLASH_ADDR_OFFSET / FLASH_SECTOR_SIZE - 1, "");

#define varm_to_native_memcpy dont_use_this_here
#define varm_to_native_memset dont_use_this_here
#define varm_to_native_memset0 dont_use_this_here

// maximum distance into window to search for a block list start in flash
#define BLOCK_LIST_SEARCH_MAX 4096

static bool s_varm_crit_ram_trash_pick_boot_slot(flash_boot_scan_context_t *flash_ctx, uint32_t slot_size);
static void s_varm_crit_init_resident_partition_table_from_buffer(boot_scan_context_t *ctx, parsed_block_loop_t *parsed_block_loop);
static bool s_varm_crit_prefer_new_partition_table(const boot_scan_context_t *ctx, parsed_block_loop_t *parsed_block_loop, parsed_partition_table_t *new_partition_table);
static bool s_varm_crit_prefer_new_image_def(const boot_scan_context_t *ctx, parsed_block_loop_t *parsed_block_loop, parsed_image_def_t *new_image_def);

// to avoid GCC compiler warnings about stringop-overflow when using pointers of the form ((foo *)USBCTRL_DPRAM_BASE) when passed to
// functions taking arrays with checked sizes, we provide the address of core0_boot_usbram_workspace in the linker script

static_assert(sizeof(core0_boot_usbram_workspace) <= CORE0_BOOT_USBRAM_MAX_WORKSPACE_SIZE, "");

void s_varm_crit_ram_trash_try_flash_boot(flash_boot_scan_context_t *flash_ctx) {
    canary_entry(S_VARM_CRIT_RAM_TRASH_TRY_FLASH_BOOT);

    s_varm_api_crit_flash_reset_address_trans();
    s_varm_api_crit_connect_internal_flash();
    s_varm_api_crit_flash_exit_xip();

    flash_ctx->flash_combinations_remaining = 0; // still searching for correct settings (i.e. we will do a scan)
    printf(">>>> flash scan for flash boot\n");
    s_varm_crit_ram_trash_perform_flash_scan_and_maybe_run_image(flash_ctx);
    canary_exit_void(S_VARM_CRIT_RAM_TRASH_TRY_FLASH_BOOT);
}

static void s_varm_crit_init_search_window_from_partition(boot_scan_context_t *ctx, const resident_partition_t *partition) {
    ctx->current_search_window.base = inline_s_xip_window_base_from_offset(inline_s_partition_start_offset(partition));
    ctx->current_search_window.size = inline_s_partition_end_offset(partition) - inline_s_partition_start_offset(partition);
    if ((int32_t)ctx->current_search_window.size < 0) {
        printf("window size is negative, making zero\n");
        ctx->current_search_window.size = 0;
    }
}

// note this function loads/initializes the resident partition table as a side effect
void s_varm_crit_ram_trash_perform_flash_scan_and_maybe_run_image(flash_boot_scan_context_t *flash_ctx) {
    canary_entry(S_VARM_CRIT_RAM_TRASH_PERFORM_FLASH_SCAN_AND_MAYBE_RUN_IMAGE);
    printf(">>>> flash_scan SP=%08x\n", get_sp());
    // note 0x180 bottoms out stack exactly during boot path with printf, assert and full hardening... without printf/assert we actually get here with 0x190
    bootrom_assert(MISC, hx_is_false(flash_ctx->boot_context.booting) || get_sp() >= 0x400e0180);

    // Repeatedly poll flash until we can find something that makes sense as a flash boot path
    // (note that on early attempts we may read nothing, or garbage)

    flash_ctx->boot_context.current_search_window.base = inline_s_xip_window_base_from_offset(0);
    // we just want to search the first chip select
    flash_ctx->boot_context.current_search_window.size = s_varm_flash_devinfo_get_size(0);

    uint slot_size = inline_s_otp_read_ecc_guarded(OTP_DATA_FLASH_PARTITION_SLOT_SIZE_ROW);
    slot_size = hx_is_true(hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_OVERRIDE_FLASH_PARTITION_SLOT_SIZE_LSB)) ? slot_size : 0;
    slot_size = (slot_size + 1) << 12u;
    printf("SLOT size %08x\n", slot_size);

    check_diagnostic_is_aligned(flash_ctx->boot_context.diagnostic);

    if (flash_ctx->flash_combinations_remaining >= 0) {
        printf("=====================================================\n");
        flash_ctx->flash_combinations_remaining = FLASH_SETTING_COMBINATION_COUNT;
        flash_ctx->boot_context.flash_mode = BOOTROM_XIP_MODE_N_MODES-1;
        flash_ctx->boot_context.flash_clkdiv = BOOTROM_SPI_CLKDIV_FLASH_BOOT_MIN;
    }
    do {
        printf("flash search %06x->%06x rem=%d mode=%d clkdiv=%d\n", 0, BLOCK_LIST_SEARCH_MAX, flash_ctx->flash_combinations_remaining, flash_ctx->boot_context.flash_mode, flash_ctx->boot_context.flash_clkdiv);
        bootrom_assert(FLASH_BOOT, flash_ctx->boot_context.flash_clkdiv >= BOOTROM_SPI_CLKDIV_FLASH_BOOT_MIN &&
                                   flash_ctx->boot_context.flash_clkdiv <= BOOTROM_SPI_CLKDIV_FLASH_BOOT_MAX);
        s_varm_api_crit_flash_select_xip_read_mode((bootrom_xip_mode_t) flash_ctx->boot_context.flash_mode, flash_ctx->boot_context.flash_clkdiv);
        // 1. look in slot 0, and possibly slot 1 for PT and/or IMAGE_DEF
        // ------------------------------------------------------------
        //
        // * if there is a returned slot_pair.partition_table, it will have been "verified" (hash check, and if OTP says PT
        //   sig is required, it will have had its signature checked)
        // * There can be a returned slot_pair.image_def in two cases
        //    i. the block list has an IMAGE_DEF but no PT,
        //    ii. the block list has both a PT and IMAGE_DEF.
        //
        // note; that only potentially bootable IMAGE_DEFs are returned (RP2350, right CPU unless we support CPU switching, etc.),
        //       however they are not generally "verified" for match of hash/sig, unless the signature check was needed
        //       to verify the partition table (there was just an IMAGE_DEF signature, and it also covered the partition table).

        parsed_block_loop_t *parsed_block_loop = &flash_ctx->boot_context.scan_workarea->parsed_block_loops[0];

        // returns true if we found at least one valid block loop
        if (s_varm_crit_ram_trash_pick_boot_slot(flash_ctx, slot_size)) {
            // if the PT is actually internally invalid, an empty PT will be used
            s_varm_crit_init_resident_partition_table_from_buffer(&flash_ctx->boot_context, parsed_block_loop);
            if (is_partition_table_populated(&parsed_block_loop->partition_table) && hx_is_false(is_partition_table_verified(&parsed_block_loop->partition_table))) {
                printf("since a partition table was present but failed verification, failing boot\n");
            } else if (hx_is_true(flash_ctx->boot_context.booting)) { // if we are not booting Then loading the PT is all that was wanted
                // if we have found an IMAGE_DEF, then we try to boot that, otherwise we will look through partitions
                // in the partition table if present to find a bootable IMAGE_DEF.
                //
                // if there is an IMAGE_DEF, but its verification fails, we treat that as a flash boot failure, since
                // the only recourse would be to look through the partitions of the partition table from the same block
                // list, and we don't do that by design (the embedded PT is only for describing ancillary partitions)
                if (is_image_def_populated(&parsed_block_loop->image_def)) {
                    // if not already verified, s_varm_crit_ram_trash_launch_image will verify hash/sig/version/thermo during call
                    bootram->always.recent_boot.partition = parsed_block_loop->flash_start_offset ? BOOT_PARTITION_SLOT1 : BOOT_PARTITION_SLOT0;
                    s_varm_crit_ram_trash_verify_and_launch_flash_image(&flash_ctx->boot_context, parsed_block_loop);
                    // if that returns, we're falling through to ns boot
                    *flash_ctx->boot_context.diagnostic = BOOT_DIAGNOSTIC_IMAGE_CONDITION_FAILURE;
                    goto flash_boot_failed_clear_boot_partition;
                } else if (hx_is_true(is_partition_table_verified(&parsed_block_loop->partition_table))) {
                    // booting with PT (which should have been verified at this point - if valid)
                    // note we might have an unverified PT if it was not valid... this happens
                    // because we always latch at least one block if we recognize the type even if
                    // the contents are garbage
                    flash_ctx->boot_context.dont_scan_for_partition_tables = hx_true(); // no longer need to scan for partition tables
                    printf("Scanning partition table at %08x\n", parsed_block_loop->partition_table.core.enclosing_window.base + parsed_block_loop->partition_table.core.window_rel_block_offset);
#if !BOOTROM_ASSERT_DISABLED
                    // note: maybe remove this or make it NDEBUG only.. basically we are about to change the window_base, so
                    //       we want to poison anything relative to the original (which should no longer be referenced)
                    parsed_block_loop->partition_table.core.window_rel_block_offset = 0x80000000;
                    parsed_block_loop->image_def.core.window_rel_block_offset = 0x80000000;
#endif
                    // we look for the first bootable partition, including picking amongst A/B partitions based on which bootable IMAGE_DEF
                    // has the highest version
                    uintptr_t pt_addr = __get_opaque_ptr(BOOTRAM_BASE + offsetof(bootram_t, always.partition_table));
                    resident_partition_table_t *pt = (resident_partition_table_t *)pt_addr;
                    for (uint pi = 0; pi < pt->partition_count; pi++) {
                        const resident_partition_t *partition = &pt->partitions[pi];
                        printf("  looking at partition %d %08x->%08x\n", pi, inline_s_partition_start_offset(partition), inline_s_partition_end_offset(partition));
                        uint32_t partition_ends_in_cs0 = partition->permissions_and_location;
                        static_assert(((16*1024*1024/4096) << PICOBIN_PARTITION_LOCATION_LAST_SECTOR_LSB) == (1u << (26-1)), "");
                        pico_default_asm(
                                "lsrs %0, %0, #26\n"
                                "sbcs %0, %0\n"
                                : "+l" (partition_ends_in_cs0)
                                :
                                : "cc"
                                );
                        if (partition_ends_in_cs0 && inline_s_partition_is_marked_bootable(partition, flash_ctx->boot_context.boot_cpu) &&
                            !inline_s_is_b_partition(partition)) {
                            printf("partition is bootable for current_cpu\n");

                            // because A/B check requires verifying hash/sig, we go ahead and load the load map
                            // comparator picks bootable image_def amongst A/B in a partition... if there is a load map, it is loaded
                            //   since we want to check hash/sig. version/thermo validity is also verified while loading the load map
                            bootrom_assert(FLASH_BOOT, !is_image_def_populated(&parsed_block_loop->image_def)); // should already be marked invalid
                            int which = s_varm_crit_ram_trash_pick_ab_image(&flash_ctx->boot_context, pi);
                            if (is_image_def_populated(&parsed_block_loop->image_def)) {
                                bootrom_assert(FLASH_BOOT, !is_partition_table_populated(&parsed_block_loop->partition_table)); // should be no partition table
                                bootrom_assert(FLASH_BOOT, !which || s_varm_api_crit_get_b_partition(pi) >= 0);
                                bootram->always.recent_boot.partition = (int8_t) (which ? s_varm_api_crit_get_b_partition(pi) : (int)pi);
                                // set diagnostic pointer based on which partition we chose
                                flash_ctx->boot_context.diagnostic = (uint16_t *)((uintptr_t)flash_ctx->boot_context.diagnostic | (((uint)which) << 1));
                                // will return if not verified
                                s_varm_crit_ram_trash_verify_and_launch_flash_image(&flash_ctx->boot_context, parsed_block_loop);
                                // if we didn't boot the image, mark it unpopulated for assert next time around the loop
                                mark_image_def_unpopulated(&parsed_block_loop->image_def);
                                // if that returns, we're falling through to next bootable partition, or flash boot failed
                                *flash_ctx->boot_context.diagnostic = BOOT_DIAGNOSTIC_IMAGE_CONDITION_FAILURE;
                            }
                        }
                    }
                } else {
                    printf("Best partition table was present but not valid, so skipping flash boot\n");
                }
                flash_boot_failed_clear_boot_partition:
                bootram->always.recent_boot.partition = BOOT_PARTITION_NONE;
            }
            // if we found a valid block list then are happily done searching flash modes, and will fall through to ns boot
            goto flash_boot_failed;
        }
        if (--flash_ctx->flash_combinations_remaining <= 0) {
            // ASR to set <0 to -1, so we don't keep counting down and overflow 8 bits for large search ranges
            flash_ctx->flash_combinations_remaining = (int8_t)(flash_ctx->flash_combinations_remaining >> 7);
            // we didn't find a valid block list, but should still install a partition table (which
            // will be empty, because we are unpopulating the parsed_partition_table) - note the partition_table
            // might have been populated even if the block loop then turned out to be invalid
            mark_partition_table_unpopulated(&parsed_block_loop->partition_table);
            s_varm_crit_init_resident_partition_table_from_buffer(&flash_ctx->boot_context, parsed_block_loop);
            break;
        }
        // Work backward from faster to slower modes. Back off SCK frequency after trying all modes
        if (--flash_ctx->boot_context.flash_mode < 0) {
            flash_ctx->boot_context.flash_mode = BOOTROM_XIP_MODE_N_MODES - 1;
            // check is superfluous as FLASH_SETTING_COMBINATION_COUNT is based on this... have
            // added an assert above
//                if (flash_ctx->boot_context.flash_clkdiv < BOOTROM_SPI_CLKDIV_FLASH_BOOT_MAX) {
                flash_ctx->boot_context.flash_clkdiv <<= 1;
//                }
        }
    } while (true);
    flash_boot_failed:
    canary_exit_void(S_VARM_CRIT_RAM_TRASH_PERFORM_FLASH_SCAN_AND_MAYBE_RUN_IMAGE);
}

int s_varm_crit_choose_by_tbyb_flash_update_boot_and_version(boot_scan_context_t *ctx, uint block_loop_struct_offset) {
    int rc;
    canary_entry(S_VARM_CRIT_CHOOSE_BY_TBYB_FLASH_UPDATE_BOOT_AND_VERSION);
    // the relieving news is that the logic is basically the same between choosing partitions with slot 0 & 1, and choosing image_defs
    // in partition A & B, so we share the code
    bootrom_assert(FLASH_BOOT, block_loop_struct_offset == offsetof(parsed_block_loop_t,image_def) || block_loop_struct_offset == offsetof(parsed_block_loop_t,partition_table));
    // note X is slot 0, or partition A
    // note Y is slot 1, or partition B
    parsed_block_loop_t *block_loop_x = &ctx->scan_workarea->parsed_block_loops[0];
    parsed_block_loop_t *block_loop_y = &ctx->scan_workarea->parsed_block_loops[1];
    parsed_block_t *block_x = (parsed_block_t *)((uintptr_t)block_loop_x + block_loop_struct_offset);
    parsed_block_t *block_y = (parsed_block_t *)((uintptr_t)block_loop_y + block_loop_struct_offset);
#if MINI_PRINTF
    static const char * const list_desc_array[] = { "slot 0", "slot 1", "partition A", "partition B"};
    const char * const *list_desc = &list_desc_array[(block_loop_struct_offset == offsetof(parsed_block_loop_t, image_def)) * 2];
    const char *block_desc = block_loop_struct_offset == offsetof(parsed_block_loop_t, image_def) ? "image_def" : "partition_table";
#endif
    // we only have interesting things to do if we have something in y
    uint16_t *diagnostic = ctx->diagnostic;
    check_diagnostic_is_aligned(diagnostic);
    uint32_t version_downgrade_erase_flash_addr = 0;
    if (is_block_populated(block_y)) {
        bool greater_y = !is_block_populated(block_x) || is_version_greater(block_y, block_x);
        // if we're trying X, then we may later want to poison Y
        if (is_block_populated(block_x) && ctx->flash_update_boot_offset == block_loop_x->flash_start_offset) {
            printf("  Verifying %s in %s, since is is the flash update, and we must decide on erasing %s in %s\n",
                   block_desc, list_desc[0], block_desc, list_desc[1]);
//            printf("XXX CHOOSE1 %08x\n", get_sp());
            diagnostic[0] = BOOT_DIAGNOSTIC_CONSIDERED;
//            printf("%p --> 0 CONSIDERED\n", diagnostic);
            s_varm_crit_ram_trash_verify_parsed_blocks(ctx, block_loop_x);
            if (hx_is_false(is_block_verified(block_x))) {
                printf("  %s in %s is the flash update, however it failed, so we don't consider version downgrade of other\n", block_desc, list_desc[0]);
                printf("  ... since flash update %s in %s is invalid, trying %s in %s\n", block_desc, list_desc[0], block_desc, list_desc[1]);
                // use goto otherwise GCC makes code much bigger if we change nesting level of use_y_if_valid var
                goto consider_y;
            } else if (greater_y) {
                // we are TBYBing X, so if present we try to use that (i.e. we don't look at slot Y, other than to potentially erase it)
                printf("  %s in %s is the flash update, and %s in %s has greater or higher version so %s marked for erase\n", block_desc, list_desc[0], block_desc, list_desc[0], list_desc[1]);
                version_downgrade_erase_flash_addr = XIP_BASE + block_loop_y->flash_start_offset;
            } else {
                printf("  %s in %s is the flash update, and %s in %s has lower version so %s NOT marked for erase\n", block_desc, list_desc[0], block_desc, list_desc[0], list_desc[1]);
            }
        } else {
            bool use_y_if_valid = // if we're doing a flash update boot for this slot/partition
                    ctx->flash_update_boot_offset == block_loop_y->flash_start_offset ||
                    // or if X is an image_def which is TBYB flagged (note we can't be doing a flash update boot for that since
                    // that is the first IF above). Note we will end up picking Y always in the case that both are TBYB flagged,
                    // but that is fine as neither will be booted in the end if they aren't the update window.
                    block_x->tbyb_flagged;
            if (!use_y_if_valid) {
                // if y is greater version and isn't TBYB flagged
                if (greater_y && !block_y->tbyb_flagged) {
                    use_y_if_valid = true;
                } else if (is_block_populated(block_x)) {
                    printf("  Verifying %s in %s as it is newer or equal version or %s in %s is TBYB flagged but not update window\n",
                           block_desc, list_desc[0], block_desc, list_desc[1]);
                    // we ignore greater or equal versioned block X if it fails verification
                    diagnostic[0] = BOOT_DIAGNOSTIC_CONSIDERED;
                    s_varm_crit_ram_trash_verify_parsed_blocks(ctx, block_loop_x);
                    use_y_if_valid = hx_is_false(is_block_verified(block_x));
                }
            }
            if (use_y_if_valid) {
                consider_y:
                printf("  Verifying %s in %s, since either no %s in %s, or %s matches flash update boot, or its %s is the newer version (or the other just failed verification)%s\n",
                       block_desc, list_desc[1], block_desc, list_desc[0], list_desc[1], block_desc,
                       block_loop_struct_offset == offsetof(parsed_block_loop_t, image_def) ? ", or the image in partition A is marked TBYB" : "");
                // if Y is verified, then we know it is the one we want - we don't care if
                // X is verified or not, as it lost in the tests above (e.g. it might have been lower version)
    //            printf("XXX CHOOSE2 %08x\n", get_sp());
                ctx->diagnostic++;
                ctx->diagnostic[0] = BOOT_DIAGNOSTIC_CONSIDERED; // note this is obviouslt [1] compared to the base value of ctx->diagnostic
                s_varm_crit_ram_trash_verify_parsed_blocks(ctx, block_loop_y);
                ctx->diagnostic--; // restore base value
                if (hx_is_true(is_block_verified(block_y))) {
                    printf("  ... it is verified so we will use it\n");
                    // if we're trying Y, then we may later want to downgrade X
                    if (ctx->flash_update_boot_offset == block_loop_y->flash_start_offset) {
                        if (!greater_y) { // note greater_y is already true if block_x is not populated, so we don't need to check again
                            version_downgrade_erase_flash_addr = XIP_BASE + block_loop_x->flash_start_offset;
                            printf("  %s in %s is the flash update, and %s in %s has greater or higher version so %s marked for erase", block_desc, list_desc[1], block_desc, list_desc[1], list_desc[0]);
                        }
                    }
                    // note: we are copying the whole of the slot (including the slot buffers)
                    //       but not updating the parsed_block-block_data pointers...
                    //       we could update them here, but that is more code, and we
                    //       don't need both slots' buffers at this point, so
                    //       perhaps best to use a smaller copy (just the first half of the parsed_blcok_list,
                    //       i.e. up to the data)
                    // copy Y into X as it is newer or the only valid one
                    static_assert(sizeof(*block_loop_y) % 4 == 0, "");
                    s_varm_crit_mem_copy_by_words((uint32_t *) block_loop_x, (const uint32_t *) block_loop_y,
                                               sizeof(*block_loop_y));
                    diagnostic[1] = BOOT_DIAGNOSTIC_CHOSEN;
                    rc = 1;
                    goto update_boot_and_version_done;
                }
            } else {
                printf("  Using %s in %s, since either no verified %s in %s, or the %s in %s is valid, and the newer (or equal) version\n",
                       block_desc, list_desc[0], block_desc, list_desc[1], block_desc, list_desc[0]);
            }
        }
    } else {
        printf("%s has no %s, so using %s (it may not have one either of course)\n", list_desc[1], block_desc, list_desc[0]);
    }
//    printf("%p --> CHOSEN 0\n", diagnostic);
    diagnostic[0] = BOOT_DIAGNOSTIC_CHOSEN;
    ctx->diagnostic = diagnostic;
    rc = 0;
    update_boot_and_version_done:
    bootram->always.zero_init.version_downgrade_erase_flash_addr = version_downgrade_erase_flash_addr;
    canary_exit_return(S_VARM_CRIT_CHOOSE_BY_TBYB_FLASH_UPDATE_BOOT_AND_VERSION, rc);
}

// range is byte range in slot  to search
// verified_active_pt is out param, and will hold "invalid" or a verified valid partition table (hash + sig verified if present (and pt sig check required))
// possibly_verified_boot_image_def is out param, and will hold "invalid" or an unverified (valid for RP2350, but no hash/sig verification) image_def if one is in the same
//                            block list as the active partition (or there is no partition table)
// return true if we have found a block loop (i.e. need not continue searching
static bool s_varm_crit_ram_trash_pick_boot_slot(flash_boot_scan_context_t *flash_ctx, uint32_t slot_size) {
//    printf("pick_boot_slot SP=%08x\n", get_sp());
    // Note this method used, incorrectly, to assume that once it found something in either slot it could stop the scan, however this is NOT
    // true, as the block lists in the two slots might start in different ranges.
    // We do however track which slots we have found block lists in, and flash_ctx->flash_combinations_remaining to FLASH_MODE_STATE_SEARCH_ENDED once we find any block
    // list, indicating that the flash mode/clkdiv are good, and we can continue searching with current settings.

    // At this point we do not know if there is a PT, and whether we are doing A/B binaries.
    // We look for (and follow if present) a block list starting in the first slot (generally 4K one sector) of flash (slot 0)
    // If we have two (slot 0/1) partition tables, the slot 1's table's of blocks would start in the second slot (generally the second 4K sector)

    parsed_block_loop_t *slots = &flash_ctx->boot_context.scan_workarea->parsed_block_loops[0];
    parsed_block_loop_t *slot0 = slots;

    // we only tore diagnostics if we're asked to look at SLOT0 or SLOT1
    uint32_t *diagnostic32 = s_varm_init_diagnostic32(bootram->always.diagnostic_partition_index <= -2 && hx_is_true(flash_ctx->boot_context.booting));
    flash_ctx->boot_context.diagnostic = (uint16_t *)diagnostic32;
//    printf("*** SET DIAG SLOT %p\n", flash_ctx->boot_context.diagnostic);

    bool found_block_list = s_varm_crit_search_window(&flash_ctx->boot_context, 0, BLOCK_LIST_SEARCH_MAX, slot0);
    if (found_block_list) {
        printf("Found a valid block list in slot 0\n");
    }

    // we need to decide whether to look for a PT in slot 1
    //
    // - if we found a partition table in slot 0 and that is marked as a singleton partition table, then we respect that;
    //   user will have to overwrite it to switch to A/B (note that it is hashed, so bit error won't cause this)
    // - If we found a bootable image_def in slot 0 and no partition table then we assume no slot 1.
    hx_bool short_circuit = hx_false();
    // we skip the short-circuit in secure mode, as we'd potentially have to do a signature check, and it's cheaper to just look at slot 1 first
    // we also skip if we are TBYB slot 1
    if (hx_is_xfalse(bootram->always.secure) && flash_ctx->boot_context.flash_update_boot_offset != slot_size) {
        // note if slot 0 has no block list, then both of these short-circuit tests will fail anyway, so we don't need to guard with (flash_ctx->block_loop_status & 1)
        if ((is_partition_table_populated(&slot0->partition_table) &&
             is_partition_table_singleton(&slot0->partition_table))) {
            printf("(re)verifying singleton pt in slot 0\n");
            // verify the partition table (and image)
//            printf("XXX PICKSLOT1 %08x\n", get_sp());
            s_varm_crit_ram_trash_verify_parsed_blocks(&flash_ctx->boot_context, slot0);
            short_circuit = is_partition_table_verified(&slot0->partition_table);
        } else if (!is_partition_table_populated(&slot0->partition_table) &&
                   is_image_def_populated(&slot0->image_def)) {
            // need to actually verify slot 0 before we can short-circuit
            printf("(re)verifying image_def in slot 0\n");
            // verify the image
//            printf("XXX PICKSLOT2 %08x\n", get_sp());
            s_varm_crit_ram_trash_verify_parsed_blocks(&flash_ctx->boot_context, slot0);
            short_circuit = is_image_def_verified(&slot0->image_def);
        }
    } else {
        printf("note: below; must check slot 1 as secure boot (avoid sig check of slot 0) or flash update on slot 1\n");
    }

    // if we have a short circuit it means we found evidence in slot 0 that we don't care about slot 1, which means we're done
    if (hx_is_false(short_circuit)) {
        parsed_block_loop_t *slot1 = &slots[1];

        flash_ctx->boot_context.diagnostic++; // second slot uses second diagnostic position
        bool found_block_list2 = s_varm_crit_search_window(&flash_ctx->boot_context, slot_size, BLOCK_LIST_SEARCH_MAX, slot1);
        if (found_block_list2) {
            printf("Found a valid block list in slot 1\n");
            found_block_list = true;
        }
        flash_ctx->boot_context.diagnostic--;
        s_varm_crit_choose_by_tbyb_flash_update_boot_and_version(&flash_ctx->boot_context,
                                                                 offsetof(parsed_block_loop_t, partition_table));
    } else {
        printf("Ignoring slot 1 as we have short-circuit=true\n");
    }
    // note chosen slot if any is now in slot0
    printf(">> pick_boot_slot is done; slot=%d (%p); ", slot0->flash_start_offset != 0, XIP_BASE + slot0->flash_start_offset);
    // note window is always at zero when picking slots
    if (is_partition_table_populated(&slot0->partition_table)) printf("PT at %08x; ", XIP_BASE + slot0->partition_table.core.window_rel_block_offset); else printf("no PT; ");
    if (is_image_def_populated(&slot0->image_def)) printf("IMG at %08x\n", XIP_BASE + slot0->image_def.core.window_rel_block_offset); else printf("no IMG\n");
//    printf("XXX PICKSLOT3 %08x\n", get_sp());
    s_varm_crit_ram_trash_verify_parsed_blocks(&flash_ctx->boot_context, slot0);
    return found_block_list;
}

/**
 * Copy a parsed block with data in thw workarea->block_buffer_or_signature_workspace.find_block_buffer, and source_parsed_block
 * on the stack (because it is temporary)
 * @param target_parsed_block
 * @param target_parsed_block_data
 * @param source_parsed_block
 * @param parsed_block_size_words
 */
static void s_varm_crit_latch_block(parsed_block_t *target_parsed_block, uint32_t *target_parsed_block_data,
                                    parsed_block_t *source_parsed_block, uint parsed_block_size_words) {
    hx_set_step_nodelay(STEPTAG_S_VARM_CRIT_LATCH_BLOCK);
    bootrom_assert(BLOCK_SCAN, target_parsed_block != source_parsed_block);
    bootrom_assert(BLOCK_SCAN, source_parsed_block->block_data);
    hx_assert_equal2i(source_parsed_block->block_data != NULL, 1);
    s_varm_crit_mem_copy_by_words((uint32_t *) target_parsed_block, (const uint32_t *) source_parsed_block, parsed_block_size_words * 4u);
    s_varm_crit_mem_copy_by_words(target_parsed_block_data, source_parsed_block->block_data, source_parsed_block->block_size_words * 4u);
    // make sure we point at the new copy of the data
    target_parsed_block->block_data = target_parsed_block_data;
    hx_check_step_nodelay(STEPTAG_S_VARM_CRIT_LATCH_BLOCK);
}

// return true if valid block list found
// we are want to search in a sub-range of the ctx's window for a block list, and if found
// pick out the best image_def and partition_table (if partitions are not disabled in the context)...
// note: this is also used by A/B test code
bool s_varm_crit_search_window(const boot_scan_context_t *ctx, uint32_t range_base, uint32_t range_size, parsed_block_loop_t *parsed_block_loop) {
    canary_entry(S_VARM_CRIT_SEARCH_WINDOW);
    bool rc;
    block_scan_t bs;

    // we want to set fso to 0 for RAM, otherwise to range_base + ctx->current_search_window.base - XIP_BASE

    uint32_t fso = ctx->current_search_window.base;
#if !GENERAL_SIZE_HACKS
    fso = varm_is_sram_or_xip_ram(fso) ? 0 : fso + range_base - XIP_BASE;
#else
    // range_base should be zero for non-flash
    bootrom_assert(MISC, !range_base || (ctx->current_search_window.base & XIP_BASE));
    uint32_t mask = varm_is_sram_or_xip_ram(fso);
    // mask = 0x00000001 if RAM
    //        0x00000000 if XIP
    mask -= 1;
    // mask = 0x00000000 if RAM
    //        0xffffffff if XIP
    mask >>= 4;
    // mask = 0x00000000 if RAM
    //        0x0fffffff if XIP
    fso = (fso + range_base) & mask;
#endif
    parsed_block_loop->flash_start_offset = fso;

    //printf("%p --> WINDOW SEARCHED\n", ctx->diagnostic);
    *ctx->diagnostic = BOOT_DIAGNOSTIC_WINDOW_SEARCHED; // note when actually pointing at bootram, this is the SET alias
    // should this be based on scan_partitions?
    //     - actually yes because when ctx->scan_partitions is false we want to not find PTs in slots (and we rely on there not being a PT)
    //     - the worry is when we use search slot for a/b images in which case we are depopulating slot 0's PT where the PT was (but we have already loaded the resident PT by this point, so should be fine)
    mark_partition_table_unpopulated(&parsed_block_loop->partition_table);
    mark_image_def_unpopulated(&parsed_block_loop->image_def);

    bootrom_assert(FLASH_BOOT, ctx->current_search_window.base);
// not invalid to have zero sized partition
//    bootrom_assert(FLASH_BOOT, ctx->current_search_window.size);
    printf("Searching window %08x+%08x fwo=%08x range %08x->%08x\n", ctx->current_search_window.base, ctx->current_search_window.size, parsed_block_loop->flash_start_offset, range_base, range_size);

    s_varm_crit_init_block_scan(&bs, ctx, range_base, range_size);
    int block_size_words;
    bool had_block = false;

    // note we don't check signatures until the end; i.e. if a partition table or image_def is acceptable, then we will
    // choose it, and not look at others if it's signature check fails. what this means in practice, is that you should not,
    // for example, have two image_defs in the same block list with the same key, architecture etc, but only one of which
    // is valid. it is ok, however to have multiple image_defs with different signing keys, as only one will match the boot key
    // and thus be acceptable
    do {
        block_size_words = s_varm_crit_next_block(&bs);
        if (block_size_words <= 0) break; // error or end of list
        had_block = true;

        // note (0041) moving this off stack didn't save anything (not the deepest branch)
        union {
            parsed_partition_table_t parsed_partition_table;
            parsed_image_def_t parsed_image_def;
            parsed_block_t parsed_block;
        } candidate_block;
        if (hx_is_false(ctx->dont_scan_for_partition_tables) &&
            s_varm_crit_parse_partition_table(&bs, (uint32_t)block_size_words, &candidate_block.parsed_partition_table)) {
            // we pick the latest valid PARTITION_TABLE (no version check)
            static_assert(sizeof(candidate_block.parsed_partition_table) % 4 == 0, "");
#if MINI_PRINTF
            printf("Candidate PT:\n");
            dump_partition_table(&candidate_block.parsed_partition_table, ctx->scan_workarea->block_buffer_or_signature_workspace.block_buffer);
#endif

            if (s_varm_crit_prefer_new_partition_table(ctx, parsed_block_loop, &candidate_block.parsed_partition_table)) {
                printf(".. is new best PARTITION_TABLE\n");
//                printf("%p --> VALID PT\n", ctx->diagnostic);
                *ctx->diagnostic = BOOT_DIAGNOSTIC_HAS_PARTITION_TABLE; // note when actually pointing at bootram, this is the SET alias
                s_varm_crit_latch_block(&parsed_block_loop->partition_table.core, parsed_block_loop->partition_table_data,
                                        &candidate_block.parsed_partition_table.core, PARSED_PARTITION_TABLE_WORD_SIZE);
            }
        } else {
            if (s_varm_crit_parse_image_def(&bs, (uint32_t) block_size_words, &candidate_block.parsed_image_def)) {
                candidate_block.parsed_image_def.core.slot_roll = range_base;
#if MINI_PRINTF
                printf("Candidate IMAGE_DEF:\n");
                dump_image_def(&candidate_block.parsed_image_def, candidate_block.parsed_image_def.core.block_data);
#endif
                if (s_varm_crit_prefer_new_image_def(ctx, parsed_block_loop, &candidate_block.parsed_image_def)) {
                    printf(".. is new best IMAGE_DEF\n");
                    *ctx->diagnostic = BOOT_DIAGNOSTIC_VALID_IMAGE_DEF; // note when actually pointing at bootram, this is the SET alias
//                    printf("%p --> VALID IMAGE_DEF\n", ctx->diagnostic);
                    s_varm_crit_latch_block(&parsed_block_loop->image_def.core, parsed_block_loop->image_def_data, &candidate_block.parsed_image_def.core,
                                            PARSED_IMAGE_DEF_WORD_SIZE);
                }
            }
        }
    } while (true);
    if (block_size_words < 0) {
        *ctx->diagnostic = BOOT_DIAGNOSTIC_INVALID_BLOCK_LOOP;
//        printf("%p --> INVALID_BLOCK_LOOP\n", ctx->diagnostic);
        mark_partition_table_unpopulated(&parsed_block_loop->partition_table);
        mark_image_def_unpopulated(&parsed_block_loop->image_def);
        rc = false;
        goto search_window_done;
    }
    if (had_block) *ctx->diagnostic = BOOT_DIAGNOSTIC_VALID_BLOCK_LOOP;
//    printf("%p --> VALID_BLOCK_LOOP\n", ctx->diagnostic);
    rc = had_block; // no error, and actually found a block_loop
    search_window_done:
    canary_exit_return(S_VARM_CRIT_SEARCH_WINDOW, rc);
}

void s_varm_crit_ram_trash_verify_parsed_blocks(boot_scan_context_t *ctx, parsed_block_loop_t *parsed_block_loop) {
    canary_entry(S_VARM_CRIT_RAM_TRASH_VERIFY_PARSED_BLOCKS);
    // this function used to be sequential, but it has been turned into a loop so that
    // s_varm_crit_ram_trash_verify_block can be inlined to save stack space; other uses of the latter have been converted
    // to use this function instead along with depopulating the uninteresting block.
//    printf("XXX VERIFY PARSED BLOCKS %08x\n", get_sp());
    parsed_block_t *parsed_block = &parsed_block_loop->partition_table.core;
    if (is_block_populated(&parsed_block_loop->partition_table.core) && hx_is_null(parsed_block_loop->partition_table.core.verified)) {
        printf("verify parsed blocks (partition table)\n");
    }
    hx_bool sig_required = ctx->signed_partition_table_required;
    hx_bool hash_required = hx_xbool_to_bool(ctx->hashed_partition_table_required, boot_flag_selector(OTP_DATA_BOOT_FLAGS0_HASHED_PARTITION_TABLE_LSB));
    parsed_block_t *cover_parsed_block = NULL;
    do {
        parsed_block->verify_diagnostic = 0;
        hx_bool covered = s_varm_crit_ram_trash_verify_block(ctx, sig_required, hash_required, parsed_block, cover_parsed_block);
        if (cover_parsed_block && hx_is_true(covered)) {
            printf("Using IMAGE_DEF verified/signature_verified for PT since it covers it\n");
            parsed_block_loop->partition_table.core.verified = parsed_block_loop->image_def.core.verified;
            parsed_block_loop->partition_table.core.signature_verified = parsed_block_loop->image_def.core.signature_verified;
        }
        // loop 0 = partition_table
        // loop 1 = image_def
        if (parsed_block == &parsed_block_loop->image_def.core) {
            *ctx->diagnostic = (uint16_t)(parsed_block->verify_diagnostic << BOOT_DIAGNOSTIC_IMAGE_DEF_LSB);
            break;
        }
        *ctx->diagnostic = (uint16_t)(parsed_block->verify_diagnostic << BOOT_DIAGNOSTIC_PARTITION_TABLE_LSB);

        // now set up for image_def
        if (is_block_populated(&parsed_block_loop->image_def.core) &&
            hx_is_null(parsed_block_loop->image_def.core.verified)) {
            // note that we will be verifying an image even if ctx->booting == false and ctx->loading_pt_only == true
            // which seems inefficient, but verify_block is trivial if hash_req = false and sig_req = false (unless booting = true
            // and there is a hash)
            printf("verify parsed blocks (image_def)\n");
        }
        // we check the image_def, and return whether the hash covers the partition table block contents (which we pass as the last argument)
        // note if this is glitched to the wrong value, we'll still fail an assertion in launch_image later
        sig_required = hx_and_notb(hx_xbool_to_bool_checked(bootram->always.secure, HX_XOR_SECURE), ctx->verify_image_defs_without_signatures);

        // we need a covering signature (of pt by image_def) if partition table requires sig, and we have one, but it hasn't
        // yet been signature_verified.
        // note: this does not need to be hx_bool, because worst case is you can cause the wrong thing to be considered for boot
        //       but it would still have to be correctly signed.
        bool covering_sig_required = is_block_populated(&parsed_block_loop->partition_table.core) &&
                                     is_block_signature_verified(&parsed_block_loop->partition_table.core) &&
                                     hx_is_true(ctx->signed_partition_table_required);

        if (covering_sig_required) {
            cover_parsed_block = parsed_block;
            sig_required = hx_or(sig_required, ctx->signed_partition_table_required);
        } else {
            // we leave hash_required set to partition setting above if we're doing covering sig
            hash_required = hx_false();
        }
        parsed_block = &parsed_block_loop->image_def.core;
    } while (true);
    canary_exit_void(S_VARM_CRIT_RAM_TRASH_VERIFY_PARSED_BLOCKS);
}

static bool s_varm_crit_prefer_block_common(hx_bool secure, parsed_block_t *current_block, parsed_block_t *candidate_block) {
    // only ignore other blocks if we don't have one already
    if (is_block_populated(current_block)) {
        if (!hx_is_null(current_block->verified)) {
            // only way we should have a value for verified at this point, is if parse_block marked it false
            // because it didn't parse it fully; either it didn't understand it (potentially from the future),
            // or it was for example an executable not for RP2350
            bootrom_assert(BLOCK_SCAN, hx_is_false(current_block->verified));
            printf(".. ignored because it was not accepted by parsing\n");
            return false;
        }

        // ignore block with the wrong signature key if we already have one with the right sig key (and this is secure mode)
        if (is_block_populated(current_block) &&
            hx_is_true(secure) &&
            hx_is_xtrue(current_block->sig_otp_key_match_and_block_hashed) &&
            hx_is_xfalse(candidate_block->sig_otp_key_match_and_block_hashed)) {
            printf(".. ignored because this is secure mode, and is not signed with a correct key, and we already have one signed with a correct key\n");
            return false;
        }
    }
    return true;
}

static bool s_varm_crit_prefer_new_partition_table(const boot_scan_context_t *ctx, parsed_block_loop_t *parsed_block_loop, parsed_partition_table_t *new_partition_table) {
    return s_varm_crit_prefer_block_common(ctx->signed_partition_table_required,
                                           &parsed_block_loop->partition_table.core,
                                           &new_partition_table->core);
}

static bool s_varm_crit_prefer_new_image_def(const boot_scan_context_t *ctx, parsed_block_loop_t *parsed_block_loop, parsed_image_def_t *new_image_def) {
    // note: this is the only time we discard a new IMAGE_DEF iF we don't already have one (and that's because we're only looking for executable IMAGE_DEFs).
    // the reason we always keep one executable IMAGE_DEF even if it is not bootable, is that we want to treat a PARTITION_TABLE with an executable IMAGE_DEF
    // as a pair even if the IMAGE_DEF can't be booted (rather than potentially - if there are no later desirable IMAGE_DEFS - ending up with a PT but no IMAGE_DEF, and
    // trying to boot using partitions in the PT).
    if (!inline_s_is_executable(new_image_def) && ctx->executable_image_def_only) {
        printf(".. ignored as it is not executable\n");
        return false;
    }
    const parsed_image_def_t *current_image_def = &parsed_block_loop->image_def;
    if (!s_varm_crit_prefer_block_common(hx_xbool_to_bool(bootram->always.secure, hx_bit_pattern_xor_secure()), &parsed_block_loop->image_def.core,
                                         &new_image_def->core)) {
        return false;
    }
    // we prefer the correct CPU unless we don't have an IMAGE_DEF
    if (is_image_def_populated(current_image_def) && inline_s_is_executable(new_image_def) && inline_s_executable_image_def_cpu_type(new_image_def) != ctx->boot_cpu) {
        if (inline_s_executable_image_def_cpu_type(current_image_def) == ctx->boot_cpu) {
            printf(".. ignored because it has wrong CPU, and we already have one with the right CPU\n");
            return false;
        }
    }
    return true;
}

// if this returns true, it should immediately be followed by a call to s_varm_crit_ram_trash_perform_flash_scan_and_maybe_run_image;
// this is not done in the method for stack space reasons during NSBOOT.
bool s_varm_crit_load_init_context_and_prepare_for_resident_partition_table_load(scan_workarea_t *scan_workarea, bool force_reload) {
    canary_entry(S_VARM_CRIT_LOAD_INIT_CONTEXT_AND_PREPARE_FOR_RESIDENT_PARTITION_TABLE_LOAD);
    // first we need to locate the partition table (note we do not need to verify image_def signatures here
    // as we just care about partition tables - this saves us wasting time on image verification)
    s_varm_crit_get_non_booting_boot_scan_context(scan_workarea,
                                                  true, // executable_image_def_only
                                                  true); // verify_image_defs_without_signatures
    scan_workarea->ctx_holder.ctx.dont_scan_for_partition_tables = hx_false(); // always scan for partition table
    scan_workarea->ctx_holder.ctx.flash_mode = 0;
    scan_workarea->ctx_holder.ctx.flash_clkdiv = BOOTROM_SPI_CLKDIV_NSBOOT;
    // the following fields are uninitialized at this point
    //    uint16_t *diagnostic;
    //    boot_window_t current_search_window;
    //    uint8_t load_image_counter; // which doesn't matter it just needs to not change from A to B
    printf("load resident partition table\n");
    // note we do this check after initializing the context, as we are relied on to initialize the flash_boot_scan_context
    bool rc;
    if (!force_reload && inline_s_is_resident_partition_table_loaded()) {
        printf("  ... already loaded!\n");
        rc = false;
        goto prepare_for_load_done;
    }
#if MINI_PRINTF
    if (is_partition_table_populated(&scan_workarea->parsed_block_loops[0].partition_table)) {
        printf("XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX\n");
//        printf("Load PT:\n");
//        dump_partition_table(&scan_workarea->parsed_block_loops[0].partition_table,
//                             scan_workarea->parsed_block_loops[0].partition_table_data);
    }
#endif

    // we assume XIP is setup already (it is for NS boot, and user should have for boot_to_ram binary)
    scan_workarea->ctx_holder.flash_ctx.flash_combinations_remaining = -1;
    // we will go on to call s_varm_crit_ram_trash_perform_flash_scan_and_maybe_run_image
    rc = true;
    prepare_for_load_done:
    canary_exit_return(S_VARM_CRIT_LOAD_INIT_CONTEXT_AND_PREPARE_FOR_RESIDENT_PARTITION_TABLE_LOAD, rc);
}

__force_inline void s_varm_crit_get_non_booting_boot_scan_context(scan_workarea_t *scan_workarea, bool executable_image_def_only, bool verify_image_defs_without_signatures) {
    // bit dumpster for ARM and RISC-V (we don't want to affect the MPU at this point)
    mpu_hw_t *mpu_on_arm = get_fake_mpu_sau();
    s_varm_crit_init_boot_scan_context(scan_workarea,
                                       mpu_on_arm,
                                       executable_image_def_only);

    boot_scan_context_t *ctx = &scan_workarea->ctx_holder.ctx;
    ctx->booting = hx_false();
    ctx->verify_image_defs_without_signatures = verify_image_defs_without_signatures;
    ctx->flash_update_boot_offset = INVALID_FLASH_UPDATE_BOOT_OFFSET;

    // the following fields are uninitialized at this point
    //    boot_window_t current_search_window;
    //    uint8_t load_image_counter;
    //    int8_t flash_mode;
    //    uint8_t flash_clkdiv;
}

int s_varm_api_crit_get_b_partition(uint pi_a) {
    canary_set_step(STEPTAG_S_VARM_CRIT_B_PARTITION);
    bootrom_assert(MISC, inline_s_is_resident_partition_table_loaded());
    // slightly painful, but so is GCC
    uintptr_t pt_addr = BOOTRAM_BASE + offsetof(bootram_t, always.partition_table);
    resident_partition_table_t *pt = (resident_partition_table_t *)pt_addr;
    uintptr_t p_addr = __get_opaque_value(pt_addr) + offsetof(resident_partition_table_t,partitions[0]);
    resident_partition_t *partition = (resident_partition_t *)p_addr;
    int rc = BOOTROM_ERROR_NOT_FOUND;
    for(int pi=0; pi < pt->partition_count; pi++) {
        if (inline_s_is_b_partition(partition) &&
            inline_s_partition_link_value(partition) == pi_a) {
            printf("B Partition of partition %d(A) is %d\n", pi_a, pi);
            rc = pi;
            goto b_partition_done;
        }
        partition++;
    }
    printf("Partition %d(A) has no B partition\n", pi_a);
    b_partition_done:
    canary_check_step(STEPTAG_S_VARM_CRIT_B_PARTITION);
    return rc;
}

#if MINI_PRINTF
void print_partition_default_families(uint32_t flags_and_permissions) {
    if (flags_and_permissions & PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_ABSOLUTE_BITS) printf(" absolute,");
    if (flags_and_permissions & PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_RP2040_BITS) printf(" rp2040,");
    if (flags_and_permissions & PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_RP2350_ARM_S_BITS) printf(" rp2350-arm-s,");
    if (flags_and_permissions & PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_RP2350_ARM_NS_BITS) printf(" rp2350-arm-ns,");
    if (flags_and_permissions & PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_RP2350_RISCV_BITS) printf(" rp2350-riscv,");
    if (flags_and_permissions & PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_DATA_BITS) printf(" data,");
}

void print_partition_permissions(uint p) {
    static_assert(PICOBIN_PARTITION_PERMISSION_S_R_BITS == (1u << 26), "");
    static_assert(PICOBIN_PARTITION_PERMISSION_S_W_BITS == (1u << 27), "");
    static_assert(PICOBIN_PARTITION_PERMISSION_NS_W_BITS == (1u << 29), "");
    static_assert(PICOBIN_PARTITION_PERMISSION_NSBOOT_W_BITS == (1u << 31), "");
    printf(" S(");
    uint r = (p >> 26) & 3;
    if (r & 1) printf("r");
    if (r & 2) printf("w"); else if (!r) printf("-");
    printf(") NSBOOT(");
    r = (p >> 30) & 3;
    if (r & 1) printf("r");
    if (r & 2) printf("w"); else if (!r) printf("-");
    printf(") NS(");
    r = (p >> 28) & 3;
    if (r & 1) printf("r");
    if (r & 2) printf("w"); else if (!r) printf("-");
    printf(")");
}
#endif

#if MINI_PRINTF
// note:Added __noinline because with extra debugging we run out of stack
static void __noinline
#else
static void
#endif
s_varm_crit_init_resident_partition_table_from_buffer(boot_scan_context_t *ctx, parsed_block_loop_t *parsed_block_loop) {
    canary_entry(S_VARM_CRIT_INIT_RESIDENT_PARTITION_TABLE_FROM_BUFFER);
    parsed_partition_table_t *partition_table = &parsed_block_loop->partition_table;
    uintptr_t rpt_addr = BOOTRAM_BASE + offsetof(bootram_t, always.partition_table);
    rpt_addr = __get_opaque_value(rpt_addr);
    resident_partition_table_t *rpt = (resident_partition_table_t *)rpt_addr;
    static_assert(offsetof(resident_partition_table_t, partition_count) == offsetof(resident_partition_table_t, counts_and_load_flag), "");
    static_assert(offsetof(resident_partition_table_t, permission_partition_count) == offsetof(resident_partition_table_t, counts_and_load_flag) + 1, "");
    static_assert(offsetof(resident_partition_table_t, loaded) == offsetof(resident_partition_table_t, counts_and_load_flag) + 2, "");
    // all paths actually set loaded = true, as we initialize and empty one otherwise
    rpt->counts_and_load_flag = 0x10000;

    if (is_partition_table_populated(partition_table)) {
        if (hx_is_true(is_partition_table_verified(partition_table))) {
            // note that we call things loaded if the count is set
            printf("Loading partition table from %p (came from %08x)\n", partition_table->core.block_data,
                   XIP_BASE + partition_table->core.window_rel_block_offset);
            bootrom_assert(PARTITION_TABLE,
                           partition_table->core.block_data); // should be no partition table at this point
            printf("  singleton: %d\n", partition_table->singleton);
            const uint32_t *item_data = partition_table->core.block_data + 1;
            resident_partition_t *partitions = rpt->partitions;
            bootrom_assert(PARTITION_TABLE, PICOBIN_BLOCK_ITEM_PARTITION_TABLE == (item_data[0] & 0x7fu));
            rpt->unpartitioned_space_permissions_and_flags = item_data[1];
#if MINI_PRINTF
            printf("  un-partitioned space: ");
            print_partition_permissions(rpt->unpartitioned_space_permissions_and_flags);
            printf(", families { ");
            print_partition_default_families(rpt->unpartitioned_space_permissions_and_flags);
            printf("}\n");
#endif
            int words = s_varm_crit_get_pt_partition_info(
                    (uint32_t *) partitions,
                    sizeof(rpt->partitions) / 4,
                    PT_INFO_PARTITION_LOCATION_AND_FLAGS,
                    item_data, partition_table->partition_count,
                    /* first_load_from_buffer */true);
            if (words >= 0) {
                bootrom_assert(FLASH_BOOT, words == partition_table->partition_count * 2);
                // note the PT item starts 1 word into the block by definition
                bootrom_assert(MISC, PICOBIN_BLOCK_ITEM_PARTITION_TABLE == (uint8_t)*resolve_ram_or_absolute_flash_addr( partition_table->core.enclosing_window.base + partition_table->core.window_rel_block_offset + 4));
                rpt->secure_item_address = partition_table->core.enclosing_window.base + partition_table->core.window_rel_block_offset + 4;
                printf("Resident partition table came from flash at %08x\n",
                       rpt->secure_item_address - 4);
                rpt->partition_count = rpt->permission_partition_count = partition_table->partition_count;
                hx_assert_true(is_partition_table_verified(partition_table));
                hx_assert_bequal(ctx->signed_partition_table_required, hx_xbool_to_bool(
                        is_partition_table_signature_verifiedx(partition_table), hx_bit_pattern_xor_sig_verified()));
                goto table_from_buffer_done;
            } else {
                printf("partition table is not valid, so initializing empty table\n");
            }
        } else {
            printf("partition table failed verification, so initializing empty table\n");
        }
        *ctx->diagnostic = BOOT_DIAGNOSTIC_INVALID_BLOCK_LOOP; // this will end us with both INVALID/VALID block loop which we are overriding with special meaning as we have no more bits
    }
    printf("Initialized empty partition table\n");
    // reset of these done via counts_and_load_flag above
//    rpt->partition_count = 0;
//    rpt->permission_partition_count = 0;
    rpt->secure_item_address = 0;
    uint32_t permissions_and_flags = PICOBIN_PARTITION_PERMISSIONS_BITS |
             PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_ABSOLUTE_BITS | PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_DATA_BITS |
             PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_RP2350_ARM_S_BITS | PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_RP2350_RISCV_BITS;

    uint32_t critical = otp_hw->critical;
    static_assert(OTP_CRITICAL_ARM_DISABLE_BITS        == 0x10000, "");
    static_assert(OTP_CRITICAL_RISCV_DISABLE_BITS      == 0x20000, "");
    static_assert(OTP_CRITICAL_SECURE_BOOT_ENABLE_BITS == 0x00001, "");
    // combine SECURE_BOOT into RISCV_DISABLE
    critical |= (critical & 1) << 17;
    static_assert((PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_RP2350_ARM_S_BITS >> 17) == 1, "");
    static_assert((PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_RP2350_RISCV_BITS >> 17) == 2, "");
    // disable the corresponding permissions
    permissions_and_flags ^= (critical << 1) & (PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_RP2350_ARM_S_BITS |
                                                PICOBIN_PARTITION_FLAGS_ACCEPTS_DEFAULT_FAMILY_RP2350_RISCV_BITS);

    rpt->unpartitioned_space_permissions_and_flags = permissions_and_flags;
    table_from_buffer_done:
    canary_exit_void(S_VARM_CRIT_INIT_RESIDENT_PARTITION_TABLE_FROM_BUFFER);
}

void s_varm_crit_ram_trash_pick_ab_image_part1(boot_scan_context_t *ctx, uint pi) {
    canary_entry(S_VARM_CRIT_RAM_TRASH_PICK_AB_IMAGE_PART1);
    parsed_block_loop_t *parsed_partitions = ctx->scan_workarea->parsed_block_loops;
    resident_partition_table_t *pt = &bootram->always.partition_table;

    // this method is used in.
    // 1. flash boot when pick A/B partitions to boot from
    // 2. s_varm_api_pick_ab_partition (duh)
    // 3. xxx_find_uf2_target_partition
    //
    // in case 1. we DO want to use signature checking in secure mode
    // in case 2 & 3, we don't necessarily want to. for example, we might be dealing with something that is either
    //    not an executable image, or isn't an ARM binary, so can't be signed
    //
    // the simplest test which matches this condition is actually to see if it is marked not ARM bootable;
    // if not ARM bootable, then we will not verifyin signatures when picking A/B partition
    //
    // this test has the added benefit of always being false when using in flash boot on ARM (since the partitions
    // must be ARM bootable).

    // Side note, the other important flag is ctx->executable_image_def only.
    //
    // for:
    //     1, we want this to be true
    //     2. more on this below
    //     3. we already try both variants
    //
    // for the s_varm_api_pick_ab_partition, we will just pick executable_image_def only = false. at this point
    // we are just comparing images in the A/B partitions, so this handles pretty much all likely
    // cases unless you have a mixture of exectuable and non executable images (either in the same partition or A vs B)

    ctx->verify_image_defs_without_signatures = pt->partitions[pi].permissions_and_flags & PICOBIN_PARTITION_FLAGS_IGNORED_DURING_ARM_BOOT_BITS;
    const resident_partition_t *resident_partitions[2];
    resident_partitions[0] = &pt->partitions[pi];
    int bpi = s_varm_api_crit_get_b_partition(pi);
    // can be negative for error, or should be in range
    bootrom_assert(FLASH_BOOT, bpi < pt->partition_count);
    resident_partitions[1] = bpi >= 0 ? &pt->partitions[bpi] : 0;
    uint32_t *diagnostic32 = s_varm_init_diagnostic32((int8_t)pi == bootram->always.diagnostic_partition_index && hx_is_true(ctx->booting));
    ctx->diagnostic = (uint16_t *)diagnostic32;
//    printf("*** SET DIAG AB %p\n", ctx->diagnostic);
    for(uint s = 0; s < 2; s++) {
        mark_image_def_unpopulated(&parsed_partitions[s].image_def); // in case there is only one slot
        if (resident_partitions[s]) {
            s_varm_crit_init_search_window_from_partition(ctx, resident_partitions[s]);
            if (hx_is_false(ctx->booting) || ctx->current_search_window.base + ctx->current_search_window.size <= XIP_BASE + 16 * 1024 * 1024) {
                s_varm_crit_search_window(ctx, 0, BLOCK_LIST_SEARCH_MAX, &parsed_partitions[s]);
            } else {
                printf("ignoring partition %d as it is not fully contained in first 16M\n", resident_partitions[s] - pt->partitions);
            }
        }
        ctx->diagnostic++;
    }
    // reset diagnostic back
    ctx->diagnostic -= 2;
    canary_exit_void(S_VARM_CRIT_RAM_TRASH_PICK_AB_IMAGE_PART1);
}

// note this method does not check the validity of the address
__force_inline uint32_t *resolve_ram_or_absolute_flash_addr(uint32_t addr) {
    // note: we only do noalloc/notranslate on CS0 since we want CS1 to be usable as RAM (and
    // we do not do any translation on it in the boot path ourselves)
    static_assert(((XIP_BASE + (MAX_FLASH_ADDR_OFFSET / 2u)) & 0xffffffu) == 0, "");
    // if (addr < XIP_BASE + (MAX_FLASH_ADDR_OFFSET / 2)) {
    if ((addr >> 24) < ((XIP_BASE + (MAX_FLASH_ADDR_OFFSET / 2u)) >> 24)) {
        addr += XIP_NOCACHE_NOALLOC_NOTRANSLATE_BASE - XIP_BASE;
    }
    return (uint32_t *)addr;
}

void s_varm_crit_load_resident_partition_table(scan_workarea_t *workspace, bool force_reload) {
    // regalloc: use prolog-saved reg to avoid separate stack spill over call
    canary_entry_reg(r6, S_VARM_CRIT_LOAD_RESIDENT_PARTITION_TABLE);
    if (s_varm_crit_load_init_context_and_prepare_for_resident_partition_table_load(workspace, force_reload)) {
        // we re-use boot path to load the partition table - only difference is that "booting" is set to false,
        // so no RAM will be trashed (sigs will be checked in place) and the image will not be booted
        printf(">>>> flash scan for load pt\n");
        s_varm_crit_ram_trash_perform_flash_scan_and_maybe_run_image(&workspace->ctx_holder.flash_ctx);
    }
    canary_exit_void(S_VARM_CRIT_LOAD_RESIDENT_PARTITION_TABLE);
}
