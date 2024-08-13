/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "varm_boot_path.h"
#include "native_generic_flash.h"
#include "bootrom_otp.h"
#include "varm_resets.h"
#include "arm8_sig.h"
#include "hardware/structs/accessctrl.h"
#include "hardware/structs/watchdog.h"

#if defined(__ARM_ARCH_8M_MAIN__) || !defined(__ARM_ARCH_8M_BASE__)
#error this must be compiled with armv8m-base
#endif

#define varm_to_native_memcpy dont_use_this_here
#define varm_to_native_memset dont_use_this_here
#define varm_to_native_memset0 dont_use_this_here

void s_varm_crit_buy_erase_other_version(__unused bool explicit) {
    canary_entry(S_VARM_CRIT_BUY_ERASE_OTHER_VERSION);

    typeof(bootram->always) *always = __get_opaque_ptr(&bootram->always);
    if (always->zero_init.version_downgrade_erase_flash_addr) {
        printf("Erasing flash sector at address %08x due to %s buy\n", always->zero_init.version_downgrade_erase_flash_addr, explicit ? "explicit" : "implicit");
        s_varm_flash_sector_erase(always->zero_init.version_downgrade_erase_flash_addr - XIP_BASE);
        // clear what we erased, as we could be called again from a chained into image (the
        // flash erase is probably idempotent but why worry)
        always->zero_init.version_downgrade_erase_flash_addr = 0;
        always->recent_boot.tbyb_and_update_info |= BOOT_TBYB_AND_UPDATE_FLAG_OTHER_ERASED;
    }
    // set count so it is correct for caller (done here rather than in caller as it can't be jumped to, due to canary
    hx_set_step(STEPTAG_S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_POST_CHECK + 1);
    canary_exit_void(S_VARM_CRIT_BUY_ERASE_OTHER_VERSION);
}

int __noinline s_varm_crit_update_rbit3(uint row, uint bit) {
    canary_entry(S_VARM_CRIT_UPDATE_RBIT3);
    uint32_t words[3];
    otp_cmd_t cmd = {
            .flags = row << OTP_CMD_ROW_LSB
    };
    int rc = s_varm_api_otp_access((aligned4_uint8_t *) words, sizeof(words), cmd);
    if (!rc) {
        cmd.flags |= OTP_CMD_WRITE_BITS;
        words[0] |= 1u << bit;
        words[1] |= 1u << bit;
        words[2] |= 1u << bit;
        rc = s_varm_api_otp_access((aligned4_uint8_t *) words, sizeof(words), cmd);
    }
    canary_exit_return(S_VARM_CRIT_UPDATE_RBIT3, rc);
}

#if !ASM_SIZE_HACKS
int s_varm_crit_redo_last_reboot(uint32_t flags) {
    flags |= bootram->always.boot_type | REBOOT2_FLAG_NO_RETURN_ON_SUCCESS;
    uint32_t *params = __get_opaque_ptr(bootram->always.zero_init.reboot_params.e);
    return s_varm_api_reboot(flags, BOOTROM_SHORT_REBOOT_MS, params[0], params[1]);
}
#else
static_assert(sizeof(bootram->always.boot_type)==1, "");
static_assert(REBOOT2_FLAG_NO_RETURN_ON_SUCCESS >= 0x100, ""); // needs mov.w
int __attribute__((naked)) s_varm_crit_redo_last_reboot(__unused uint32_t flags) {
    pico_default_asm_volatile(
            "movw r2, %[reboot2_flag_no_return_on_success]\n"
            "orrs r0, r2\n"
            "ldr r1, =%[reboot_params]\n"
            "ldmia r1!, {r2, r3}\n"
            "adds r1, %[boot_type_minus_reboot_params] - 8\n"
            "ldrb r1, [r1]\n"
            "orrs r0, r1\n"
            "movs r1, %[short_reboot_ms]\n"
            "b.n s_varm_api_reboot\n"
            :
            : [reboot_params] "i" (bootram->always.zero_init.reboot_params.e),
              [boot_type_minus_reboot_params] "i" (offsetof(bootram_t, always.boot_type) - offsetof(bootram_t, always.zero_init.reboot_params)),
              [short_reboot_ms] "i" (BOOTROM_SHORT_REBOOT_MS),
              [reboot2_flag_no_return_on_success] "i" (REBOOT2_FLAG_NO_RETURN_ON_SUCCESS)
            );
}
#endif

int s_varm_crit_buy_update_otp_version(__unused bool explicit) {
    canary_entry(S_VARM_CRIT_BUY_UPDATE_OTP_VERSION);
    int rc = BOOTROM_OK;
    typeof(bootram->always) *always = __get_opaque_ptr(&bootram->always);
    if (always->zero_init.pending_rollback_version_otp_info.row) {
        printf("Applying OTP version (row %04x bit %d) due to %s buy\n", always->zero_init.pending_rollback_version_otp_info.row, always->zero_init.pending_rollback_version_otp_info.bit,
               explicit ? "explicit" : "implicit");
        rc = s_varm_crit_update_rbit3(always->zero_init.pending_rollback_version_otp_info.row, always->zero_init.pending_rollback_version_otp_info.bit);
        if (rc) {
            printf("FAILED to write thermometer OTP bit\n");
        } else {
            // not using | as it should be zero to start with
            bootrom_assert(MISC, always->recent_boot.tbyb_and_update_info == 0);
            always->recent_boot.tbyb_and_update_info = BOOT_TBYB_AND_UPDATE_FLAG_OTP_VERSION_APPLIED;
            if (!(always->boot_type & BOOT_TYPE_CHAINED_FLAG)) {
                printf("Setting rollback required bit\n");
                // note we could check this is already the case, but writing them again i think is not a big issue
                rc = s_varm_crit_update_rbit3(OTP_DATA_BOOT_FLAGS0_ROW, OTP_DATA_BOOT_FLAGS0_ROLLBACK_REQUIRED_LSB);
                if (rc) {
                    printf("FAILED to write rollback required bit\n");
                }
            } else {
                printf("Not auto-setting OTP rollback required bit as this is a chained image\n");
            }
            if (always->zero_init.pending_rollback_version_otp_info.reboot) {
                printf("REBOOTING because we aren't done writing rollback rows!");
                rc = s_varm_crit_redo_last_reboot(0);
            }
            always->zero_init.pending_rollback_version_otp_info.word = 0;
        }
    }
    // set count so it is correct for caller (done here rather than in caller as it can't be jumped to, due to canary
    hx_set_step(STEPTAG_S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_POST_CHECK + 1);
    canary_exit_return(S_VARM_CRIT_BUY_UPDATE_OTP_VERSION, rc);
}

int __exported_from_arm s_varm_api_explicit_buy(uint8_t *buffer, uint32_t buffer_size) {
    canary_entry(S_VARM_API_EXPLICIT_BUY);
    hw_clear_bits(&watchdog_hw->ctrl, WATCHDOG_CTRL_ENABLE_BITS);
    int rc;
    typeof(bootram->always) *always = __get_opaque_ptr(&bootram->always);
    // clear this; the next commands will add any flags
    always->recent_boot.tbyb_and_update_info = 0;
    // note we do this first because it can cause a reboot, and we don't want to clear TBYB flag or erase
    // other image until after that
    rc = s_varm_crit_buy_update_otp_version(true);
    if (rc) goto explicit_buy_done;
    // if applying the version fails, we do go ahead and clear the TBYB flag; we count this as a TBYB failure
    if (always->zero_init.tbyb_flag_flash_addr) {
        printf("CLEARING TBYB flag at %08x\n", always->zero_init.tbyb_flag_flash_addr);
        // clear TBYB flag
        if (buffer_size < FLASH_SECTOR_SIZE) {
            rc = BOOTROM_ERROR_BUFFER_TOO_SMALL;
            goto explicit_buy_done;
        }
        uint32_t sector_base = always->zero_init.tbyb_flag_flash_addr & ~FLASH_SECTOR_REMAINDER_MASK;
        uint32_t sector_offset = always->zero_init.tbyb_flag_flash_addr - sector_base;
        s_varm_crit_flash_read_data(buffer, sector_base - XIP_BASE, FLASH_SECTOR_SIZE);
        s_varm_flash_sector_erase(sector_base - XIP_BASE);
        bootrom_assert(MISC, (always->zero_init.tbyb_flag_flash_addr & 3u) == 0);
        // Patch most-significant byte of IMAGE_TYPE_EXE halfword. This is offset by 3 bytes from
        // tbyb_flag_flash_addr, which points to the IMAGE_TYPE block item (4 bytes into the
        // block). Note this addition is safe because the block item is word-aligned in flash,
        // therefore does not span a sector boundary. (Not necessarily aligned in buf though)
        static_assert(((PICOBIN_IMAGE_TYPE_EXE_TBYB_BITS >> 8) << 8) == PICOBIN_IMAGE_TYPE_EXE_TBYB_BITS, "");
        bootrom_assert(MISC, buffer[sector_offset + 3] & ((uint32_t)PICOBIN_IMAGE_TYPE_EXE_TBYB_BITS >> 8));
        buffer[sector_offset + 3] &= 0xffu & ~((uint32_t)PICOBIN_IMAGE_TYPE_EXE_TBYB_BITS >> 8);
        s_varm_api_flash_range_program(sector_base - XIP_BASE, buffer, FLASH_SECTOR_SIZE);
        always->zero_init.tbyb_flag_flash_addr = 0;
    }

    // let's erase the other one anyway; we know we ran at least once (note this must be after the otp update, because that can fail)
    s_varm_crit_buy_erase_other_version(true);
    // this ^ sets rcp_count to S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_POST_CHECK_STEP + 1
explicit_buy_done:
    canary_exit_return(S_VARM_API_EXPLICIT_BUY, rc);
}

__noinline int s_varm_crit_ram_trash_verify_and_launch_flash_image(boot_scan_context_t *ctx, parsed_block_loop_t *parsed_block_loop) {
    int rc;
    canary_entry(S_VARM_CRIT_RAM_TRASH_VERIFY_AND_LAUNCH_FLASH_IMAGE);
    parsed_image_def_t * image_def = &parsed_block_loop->image_def;

    typeof(bootram->always) *always = __get_opaque_ptr(&bootram->always);

    // SECURITY NOTE: WE DO WORK HERE BEFORE VERIFYING THE IMAGE, HOWEVER NOTHING MORE UNPLEASANT THAN SETTING UP ATRANS, WHICH WE
    //                WILL UNDO AGAIN IF THE VERIFICATION FAILS. This is done to keep all the (final) verification in one place

    static_assert(4*1024*1024 == (1u << 22), "");
    if ((int32_t)image_def->rolling_window_delta < 0 && image_def->rolling_window_delta << 10) {
        printf("negative roll is not a multiple of 4M\n");
        rc = BOOTROM_ERROR_INVALID_ADDRESS;
        goto verify_and_launch_flash_image_done;
    }

    // because we set the version_downgrade during initial scan, it is possible it has been overwritten
    if (ctx->flash_update_boot_offset != parsed_block_loop->flash_start_offset) {
        if (always->zero_init.version_downgrade_erase_flash_addr) {
            printf("Clearing flash downgrade address which wasn't for flash update partition\n");
        }
        always->zero_init.version_downgrade_erase_flash_addr = 0;
        if (image_def->core.tbyb_flagged) {
            printf("NOT booting TBYB flagged image which isn't the flash update\n");
            rc = BOOTROM_ERROR_INVALID_STATE;
            goto verify_and_launch_flash_image_done;
        }
        bootrom_assert(IMAGE_BOOT, !always->zero_init.tbyb_flag_flash_addr);
    } else if (image_def->core.tbyb_flagged) {
        always->zero_init.tbyb_flag_flash_addr = image_def->core.enclosing_window.base + image_def->core.window_rel_block_offset + 4;
        printf("SAVING TBYB flash address %08x\n", always->zero_init.tbyb_flag_flash_addr);
    }

    int32_t roll = (int32_t)(parsed_block_loop->flash_start_offset + image_def->rolling_window_delta);
    if (roll) {
        printf("NEED TO ROLL %08x to %08x\n", (int)XIP_BASE + roll, XIP_BASE);
        if ((uint32_t)roll & FLASH_SECTOR_REMAINDER_MASK) {
            printf("CAN ONLY ROLL in sector multiples (4k)");
            // not bootable
            rc = BOOTROM_ERROR_INVALID_DATA;
            goto verify_and_launch_flash_image_done;
        }
        // window base is used during s_varm_crit_ram_trash_launch_image, so we need to roll it now
        roll >>= FLASH_SECTOR_SHIFT;
        bootrom_assert(FLASH_BOOT, image_def->core.enclosing_window.size % FLASH_SECTOR_SIZE == 0);
        int32_t size = (int32_t)((image_def->core.enclosing_window.size - image_def->core.slot_roll) >> FLASH_SECTOR_SHIFT);
// 0x07ff0000 [26:16] : SIZE (0x400): Translation aperture size for this virtual address range, in units of 4 kiB (one...
// 0x00000fff [11:0]  : BASE (0): Physical address base for this virtual address range, in units of 4 kiB (one flash sector)
        for (uint i = 0; i < 4; i++) {
            static_assert(4 * 1024 * 1024 / FLASH_SECTOR_SIZE == 0x400, "");
            if (roll < 0) {
                roll += 0x400;
                qmi_hw->atrans[i] = 0;
            } else {
                int32_t this_size = MIN(size, 0x400);
                printf("ATRANS %d at %08x exposes %08x -> %08x\n", i, XIP_BASE + i * 4 * 1024 * 1024, (int) (XIP_BASE + (uint)roll * FLASH_SECTOR_SIZE),
                       (int) (XIP_BASE + (uint)(roll + this_size) * FLASH_SECTOR_SIZE));
                qmi_hw->atrans[i] = (uint)((this_size << 16) | roll);
                size -= this_size;
                roll += this_size;
            }
        }

    }

    rc = s_varm_crit_ram_trash_verify_and_launch_image(ctx, parsed_block_loop);
    // if we can't boot that image, clear any roll
    verify_and_launch_flash_image_done:
    always->zero_init.tbyb_flag_flash_addr = 0;
    s_varm_api_crit_flash_reset_address_trans();
    canary_exit_return(S_VARM_CRIT_RAM_TRASH_VERIFY_AND_LAUNCH_FLASH_IMAGE, rc);
}

int s_varm_crit_ram_trash_verify_and_launch_image(boot_scan_context_t *ctx, parsed_block_loop_t *parsed_block_loop) {
    int rc;
    canary_entry(S_VARM_CRIT_RAM_TRASH_VERIFY_AND_LAUNCH_IMAGE);
    s_varm_crit_ram_trash_verify_parsed_blocks(ctx, parsed_block_loop);
    hx_set_step(STEPTAG_S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_BASE);
    parsed_image_def_t * image_def = &parsed_block_loop->image_def;
    if (hx_is_false(is_image_def_verified(image_def))) {
        printf("  can't launch unverified image!\n");
        rc = BOOTROM_ERROR_NOT_PERMITTED;
        goto verify_and_launch_image_done;
    }

    // note: it should never be possible to load an image, verify it, then load another image
    // (thus invalidating the first verification) because we always choose our best choice
    // image first, then fall back only if its verification failed.
    //
    // still, because this would be really bad if there is some obscure set of data that caused
    // this, we keep this check out of an abundance of caution.
    bootrom_assert(IMAGE_BOOT, ctx->load_image_counter == image_def->core.load_image_counter);
    hx_assert_equal2i(ctx->load_image_counter, image_def->core.load_image_counter);

    if (inline_s_executable_image_def_cpu_type(image_def) == PICOBIN_IMAGE_TYPE_EXE_CPU_ARM) {
        if ((image_def->image_type_flags & PICOBIN_IMAGE_TYPE_EXE_SECURITY_BITS) == PICOBIN_IMAGE_TYPE_EXE_SECURITY_AS_BITS(NS)) {
            printf("Not booting image marked as NS\n");
            rc = BOOTROM_ERROR_NOT_PERMITTED;
            goto verify_and_launch_image_done;
        }
    }

    uint32_t image_base_vma = image_def->core.enclosing_window.base;
    // rolled_window_base is where the start of the image is in its rolled address space (ignore
    // rolling_window_delta on non-rollable binaries; i.e. everything except XIP CS 0)
    if ((image_base_vma >> 24) == (XIP_BASE >> 24)) {
        image_base_vma = XIP_BASE - image_def->rolling_window_delta;
    }
    if (!image_def->rolled_vector_table_addr) {
        // the default vector table addr is the start of the image
        image_def->rolled_vector_table_addr = image_base_vma;
    }
    if (!image_def->rolled_entry_point_addr) {
        // note: check image_type not current boot cpu to clarify printfs as much as anything... if it
        // is the wrong CPU it won't be booted anyway, so whatever we set doesn't matter
        if (inline_s_executable_image_def_cpu_type(image_def) != PICOBIN_IMAGE_TYPE_EXE_CPU_RISCV) {
            uintptr_t vector_table_addr = image_def->rolled_vector_table_addr;
            // we don't check alignment of the vtable for size; if it is bad, it is bad at this point.
            printf("initializing ARM entry point from vtable at %08x\n", (uint)vector_table_addr);
            static_assert(offsetof(parsed_image_def_t, rolled_entry_point_addr) ==
                          offsetof(parsed_image_def_t, initial_sp) + 4, "");
            // Note ctx->window_base has been rolled, so for flash images we read through a
            // translating XIP alias. Cached is fine: we should have flushed during verification.
            void *sp_pc_src = (void*)(vector_table_addr);
            static_assert(offsetof(parsed_image_def_t, rolled_entry_point_addr) == offsetof(parsed_image_def_t, initial_sp) + 4, "");
            s_varm_crit_mem_copy_by_words(&image_def->initial_sp, sp_pc_src, 8);
        } else {
            // default to start of image
            image_def->rolled_entry_point_addr = image_base_vma;
            image_def->initial_sp = INVALID_STACK_PTR;
        }
        image_def->initial_sp_limit = 0;
    }
#if MINI_PRINTF
    printf("Launch IMAGE_DEF (note: flash address is rolled when rolling):\n");
    dump_image_def(image_def, image_def->core.block_data);
#endif
    static_assert(PICOBIN_IMAGE_TYPE_EXE_CPU_ARM < PICOBIN_IMAGE_TYPE_EXE_CPU_VARMULET, "");
    static_assert(PICOBIN_IMAGE_TYPE_EXE_CPU_RISCV < PICOBIN_IMAGE_TYPE_EXE_CPU_VARMULET, "");
    if (inline_s_executable_image_def_cpu_type(image_def) != ctx->boot_cpu && inline_s_executable_image_def_cpu_type(image_def) < PICOBIN_IMAGE_TYPE_EXE_CPU_VARMULET) {
        // hardening: since swap cpu doesn't work on a secure chip; i think a regular boolean is fine
        hx_bool swap_cpu_disabled = hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_DISABLE_AUTO_SWITCH_ARCH_LSB);
        if (hx_is_true(swap_cpu_disabled)) {
            printf("Not booting image as swap-cpu is disabled\n");
            rc = BOOTROM_ERROR_INVALID_STATE; // not bootable on current architecture
            goto verify_and_launch_image_done;
        } else {
            printf("image has other CPU\n");
            uint flags = (ctx->boot_cpu == PICOBIN_IMAGE_TYPE_EXE_CPU_ARM ? REBOOT2_FLAG_REBOOT_TO_RISCV
                                                                         : REBOOT2_FLAG_REBOOT_TO_ARM);
            rc = s_varm_crit_redo_last_reboot(flags);
            // since we pass REBOOT2_FLAG_NO_RETURN, it will only return if there is an error
            bootrom_assert(MISC, rc);
            goto verify_and_launch_image_done;
        }
    }
    if (!has_feature_exec2 || hx_is_false(inline_s_is_exec2(ctx))) {
        puts("IMAGE_DEF launch is go");
        set_boot_once_bit(BOOT_ONCE_NSBOOT_API_DISABLED);
    } else {
        puts("EXEC2 launch is go");
    }

    printf("do security re-checks...\n");
    typeof(bootram->always) *always = __get_opaque_ptr(&bootram->always);
    hx_check_step(STEPTAG_S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_BASE);
    hx_assert_true(is_image_def_verified(image_def));
    // if secure, then sig_key_match must be true
    hx_assert_notx_orx_true(always->secure, hx_bit_pattern_xor_secure(),
                             image_def->core.sig_otp_key_match_and_block_hashed, hx_bit_pattern_xor_key_match());
    // don't think this is super necessary
//    hx_assert_equal2i(image_def->image_type_flags & PICOBIN_IMAGE_TYPE_EXE_CHIP_BITS, PICOBIN_IMAGE_TYPE_EXE_CHIP_AS_BITS(RP2350));
    hx_check_step(STEPTAG_S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_MID_CHECK);
    hx_xbool secure_and_need_rollback_version = hx_step_safe_get_boot_flagx(OTP_DATA_BOOT_FLAGS0_ROLLBACK_REQUIRED_LSB);
    hx_bool has_rollback_version = hx_uint32_to_bool_checked(image_def->core.rollback_version);
    // note we don't verify signature in non-secure mode, so signature_verified will be false
    // note, this check also makes sure that we didn't try to boot an image which we verified
    // with ctx->verify_without_signatures == true
    hx_assert_bequal(hx_xbool_to_bool(always->secure, hx_bit_pattern_xor_secure()),
                      hx_xbool_to_bool(is_image_def_signature_verifiedx(image_def), hx_bit_pattern_xor_sig_verified()));
    hx_assert_or(has_rollback_version, hx_notx_constant_diff(secure_and_need_rollback_version, boot_flag_selector(OTP_DATA_BOOT_FLAGS0_ROLLBACK_REQUIRED_LSB), hx_bit_pattern_xor_secure()));
    hx_check_step(STEPTAG_S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_POST_CHECK);

    *ctx->diagnostic = BOOT_DIAGNOSTIC_IMAGE_LAUNCHED;
    static_assert(BOOT_TBYB_AND_UPDATE_FLAG_BUY_PENDING == 1, ""); // because we initialize it with a boolean
    always->recent_boot.tbyb_and_update_info = image_def->core.tbyb_flagged; // zero most and set bottom bit to whether we have TBYB
    if (!has_feature_exec2 || hx_is_false(inline_s_is_exec2(ctx))) {
        if (inline_s_executable_image_def_cpu_type(image_def) >= PICOBIN_IMAGE_TYPE_EXE_CPU_VARMULET) {
            rcp_panic();
        }
        hx_assert_true(ctx->booting);
        if (hx_is_xtrue(always->secure) && image_def->rollback_version_otp_info.row) {
            always->zero_init.pending_rollback_version_otp_info = image_def->rollback_version_otp_info;
            if (!image_def->core.tbyb_flagged) {
                rc = s_varm_crit_buy_update_otp_version(false);
                // on success (rc == 0) this ^ sets rcp_count to S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_POST_CHECK_STEP + 1
                if (rc) {
                    goto verify_and_launch_image_done;
                }
            } else if (always->zero_init.pending_rollback_version_otp_info.row) {
                printf("not updating OTP rollback version as explicit TBYB flagged\n");
            }
        }
        if (!image_def->core.tbyb_flagged) {
            // this is a no-op if nothing to do (there is no failure code)
            // note this must come after any otp row update as the otp row update may fail
            s_varm_crit_buy_erase_other_version(false);
            // this ^ sets rcp_count to expected value S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_POST_CHECK_STEP + 1
        } else {
            if (always->zero_init.version_downgrade_erase_flash_addr) {
                printf("not erasing other slot as explicit TBYB flagged\n");
            }
            static_assert(WATCHDOG_CTRL_TIME_BITS == 0xffffffu, "");
            printf("Setting %d second watchdog timer for TBYB (will do regular reboot then)\n", WATCHDOG_CTRL_TIME_BITS / 1000);
            s_varm_api_reboot(REBOOT2_FLAG_REBOOT_TYPE_NORMAL, WATCHDOG_CTRL_TIME_BITS, 0, 0);
        }
        always->zero_init.allow_core0_autovarm = 1; // we're no longer in preboot
        printf("entering image...\n");
        // Wait until UART FIFO is empty, as the UART may be imminently reset (for development builds only!)
        mini_printf_flush();
        hx_bool disable_xip = hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_DISABLE_XIP_ACCESS_ON_SRAM_ENTRY_LSB);
        if (hx_is_true(disable_xip)) {
            static_assert((XIP_BASE >> 28) == 0x1, "");
            static_assert((SRAM_BASE >> 28) == 0x2, "");
            uint32_t pc_hi = image_def->rolled_entry_point_addr >> 28;
            if (pc_hi == 2) {
                --pc_hi;
                // Make XIP non-executable, wtthout relying on MPU: best we can do is disable all proc access.
                accessctrl_hw->xip_main = ACCESSCTRL_PASSWORD_BITS | (ACCESSCTRL_XIP_MAIN_RESET & ~(
                    ACCESSCTRL_XIP_MAIN_CORE0_BITS | ACCESSCTRL_XIP_MAIN_CORE1_BITS
                ));
            }
            hx_assert_equal2i(pc_hi, 1);
        } else {
            hx_assert_false(disable_xip);
        }
        mpu_save_state_t save_state;
        s_save_clear_and_disable_mpu(ctx->mpu_on_arm, &save_state); // re-enable rwx
        hx_check_step(STEPTAG_S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_PRE_THUNK);
        // thunk which sets up default XIP setup (default is to restore the mode/clkdiv found by try_flash_boot), then adjusts the stack
        varm_to_s_native_crit_init_default_xip_setup_and_enter_image_thunk(ctx->flash_mode, ctx->flash_clkdiv,
                                                                           image_def->rolled_entry_point_addr,
                                                                           image_def->initial_sp,
                                                                           image_def->initial_sp_limit,
                                                                           image_def->rolled_vector_table_addr);
        rcp_panic();
    } else {
        hx_assert_false(ctx->booting);
        hx_assert_false(hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_DISABLE_BOOTSEL_EXEC2_BITS));

        if (inline_s_executable_image_def_cpu_type(image_def) == PICOBIN_IMAGE_TYPE_EXE_CPU_VARMULET) {
            printf("CALLING EXEC2 under varmulet at pc = %08x, sp = %08x\n", image_def->rolled_entry_point_addr,
                   image_def->initial_sp);
            canary_set_step(STEPTAG_S_VARM_SECURE_CALL);
            s_varm_secure_call(image_def->rolled_entry_point_addr | 1,
                                       image_def->initial_sp);
        } else {
            printf("CALLING EXEC2 native at pc = %08x, sp = %08x\n", image_def->rolled_entry_point_addr,
                   image_def->initial_sp);
            canary_set_step(STEPTAG_S_VARM_SECURE_CALL);
            varm_to_s_native_secure_call_pc_sp(image_def->rolled_entry_point_addr,
                                         image_def->initial_sp);
        }
    }
    rc = BOOTROM_OK;
    verify_and_launch_image_done:
    canary_exit_return(S_VARM_CRIT_RAM_TRASH_VERIFY_AND_LAUNCH_IMAGE, rc);
}

int s_varm_crit_ram_trash_checked_ram_or_flash_window_launch(boot_scan_context_t *ctx) {
    canary_entry(S_VARM_CRIT_RAM_TRASH_TRY_RAM_BOOT);
    printf("Scanning for image in RAM %08x->%08x\n", ctx->current_search_window.base, ctx->current_search_window.base + ctx->current_search_window.size);
    uintptr_t upper_s = ctx->current_search_window.base;
    uintptr_t upper_e = (ctx->current_search_window.base + ctx->current_search_window.size - !!ctx->current_search_window.size);
    // ram boot region may not cross 32M aligned regions (and XIP RAM must be in the top half 0x12000000->0x14000000)
    int rc = BOOTROM_ERROR_INVALID_ADDRESS;
    bool inside_out = upper_e < upper_s;
    bool within_32meg_naturally_aligned = (upper_s >> 25) == (upper_e >> 25);
    bool within_xip = (upper_s >> 25) == (upper_e >> 25) && (upper_s >> 25) == (XIP_BASE >> 25);
    bool within_ram = varm_is_sram_or_xip_ram(upper_s) && varm_is_sram_or_xip_ram(upper_e);
    if (!inside_out && within_32meg_naturally_aligned && (within_xip || within_ram)) {
        parsed_block_loop_t *parsed_block_loop = &ctx->scan_workarea->parsed_block_loops[0];
        // we never look for partition tables when launching an image from a window
        ctx->dont_scan_for_partition_tables = hx_true();

        // always update diagnostics for RAM boot (or flash boot as a result of chain image, which is what gets us here with flash)
        //
        // todo note: that in the case of OTP boot failure we will leave diagnostics behind, but i think that is a rare enough case to leave
        //      that vs code size
        register uintptr_t r0 asm ("r0") = 1; // true arg
        register uintptr_t r1 asm ("r1");
        // on return
        // r0 = hw_set_alias(&bootrom->always->boot_diagnostic)
        // r1 = &bootrom->always->boot_diagnostic
        pico_default_asm_volatile(
                "bl s_varm_init_diagnostic32_impl\n"
        : "+l" (r0), "=l" (r1) : : "r2", "ip", "lr", "cc"
        );
        ctx->diagnostic = (uint16_t *)r0;
        bootrom_assert(MISC, (uint16_t *)r1 == (uint16_t *)&bootram->always.boot_diagnostic);
        static_assert(offsetof(bootram_t, always.diagnostic_partition_index) == offsetof(bootram_t, always.boot_diagnostic) - 4, "");
        *(int8_t *)(r1 - 4) = BOOT_PARTITION_WINDOW;
        if (s_varm_crit_search_window(ctx, 0, ctx->current_search_window.size, parsed_block_loop) && is_image_def_populated(&parsed_block_loop->image_def)) {
            // used parsed_blocks method with no pt, to avoid multiple call sites for verify_block() method (for inlining)
            mark_partition_table_unpopulated(&parsed_block_loop->partition_table);
            if (ctx->current_search_window.base < XIP_BASE + MAX_FLASH_ADDR_OFFSET) {
                rc = s_varm_crit_ram_trash_verify_and_launch_flash_image(ctx, parsed_block_loop);
            } else {
                rc = s_varm_crit_ram_trash_verify_and_launch_image(ctx, parsed_block_loop);
            }
            bootrom_assert(IMAGE_BOOT, rc);
            *ctx->diagnostic = BOOT_DIAGNOSTIC_IMAGE_CONDITION_FAILURE;
        } else {
            rc = BOOTROM_ERROR_NOT_FOUND;
        }
    } else {
        printf("ram_boot address range is not in RAM range or second half of XIP window\n");
    }
    canary_exit_return(S_VARM_CRIT_RAM_TRASH_TRY_RAM_BOOT, rc);
}

