/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

// These functions are shims between the nsboot service SG, and the secure
// varm-able functions which implement its services. They implement parameter
// checking, and/or conversion to the internal API
//
// These functions are compiled for varm compatiblity, so that they can be run under RISC-V
// emulation. The NS buffer validation is dispatched back to native
// code so that Armv8-M tt* instructions can be used in a native Arm context.
//
// Note funcitons of the form s_from_nsboot_ are only called via the NSBOOT SG, however
// there are some functions here of the form s_from_ns_ which (because their behavior
// is the same when calling from NS or NSBOOT) may be called from either

#include "bootrom.h"

#include "varm_checked_flash.h"
#include "arm8_validate_ns_buffer.h"
#include "nsboot_secure_calls.h"
#include "hardware/structs/timer.h"

int s_from_ns_varm_api_get_partition_table_info(uint32_t *out_buffer, uint32_t out_buffer_word_size, uint32_t partition_and_flags) {
    int rc;
    // regalloc: use prolog-saved reg to avoid separate spill over call
    canary_entry_reg(r4, S_FROM_NS_VARM_API_GET_PARTITION_TABLE_INFO);
    hx_bool addr_ok = hx_bool_invalid();
    uint32_t out_buffer_byte_size = out_buffer_word_size * 4u;
    out_buffer = varm_to_s_native_api_validate_ns_buffer(out_buffer, out_buffer_byte_size, hx_true(), &addr_ok);
    if (hx_is_false(addr_ok)) {
        // rc = BOOTROM_ERROR_INVALID_ADDRESS;
        rc = (int)out_buffer;
        goto get_partition_table_info_done;
    }
    hx_assert_true(addr_ok);
    // Note we use out_buffer_byte_size / 4, not out_buffer_word_size, since it's not necessarily
    // true that x * 4 >= x when accounting for unsigned wrapping
    rc = s_varm_api_get_partition_table_info(out_buffer, out_buffer_byte_size / 4, partition_and_flags);
    get_partition_table_info_done:
    canary_exit_return(S_FROM_NS_VARM_API_GET_PARTITION_TABLE_INFO, rc);
}

int s_from_nsboot_varm_ram_trash_get_uf2_target_partition(resident_partition_t *partition_out, uint family_id) {
    // regalloc: use prolog-saved reg to avoid separate spill over call
    canary_entry_reg(r4, S_FROM_NSBOOT_VARM_RAM_TRASH_GET_UF2_TARGET_PARTITION);
    int rc;
    hx_bool addr_ok = hx_bool_invalid();
    partition_out = varm_to_s_native_api_validate_ns_buffer(partition_out, sizeof(resident_partition_t), hx_true(), &addr_ok);
    if (hx_is_false(addr_ok)) {
        // rc = BOOTROM_ERROR_INVALID_ADDRESS;
        rc = (int)partition_out;
        goto get_uf2_target_partition_done;
    }
    hx_assert_true(addr_ok);
    rc = s_varm_ram_trash_get_uf2_target_partition(family_id, partition_out);
    get_uf2_target_partition_done:
    canary_exit_return(S_FROM_NSBOOT_VARM_RAM_TRASH_GET_UF2_TARGET_PARTITION, rc);
}


int s_from_nsboot_varm_flash_page_program(const uint8_t *data, uint32_t addr) {
    int rc;
    // regalloc: use prolog-saved reg to avoid separate spill over call
    canary_entry_reg(r4, S_FROM_NSBOOT_VARM_FLASH_PAGE_PROGRAM);
    hx_bool addr_ok = hx_bool_invalid();
    data = varm_to_s_native_api_validate_ns_buffer(data, FLASH_PAGE_SIZE, hx_false(), &addr_ok);
    if (hx_is_false(addr_ok)) {
//        rc = BOOTROM_ERROR_INVALID_ADDRESS;
        rc = (int)data;
        goto flash_page_program_done;
    }
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    // diagnostic: constness is discarded here to go into generic check+dispatch code, then restored
    // on the other side. We don't write through the const pointer.
    hx_assert_true(addr_ok);
    rc = s_varm_api_checked_flash_op(
        (cflash_flags_t) {.flags =
            (CFLASH_ASPACE_VALUE_STORAGE  << CFLASH_ASPACE_LSB  ) |
            (CFLASH_SECLEVEL_VALUE_BOOTLOADER << CFLASH_SECLEVEL_LSB) |
            (CFLASH_OP_VALUE_PROGRAM      << CFLASH_OP_LSB      )
        },
        XIP_BASE + addr,
        FLASH_PAGE_SIZE,
        (uint8_t*)data
    );
#pragma GCC diagnostic pop
    flash_page_program_done:
    canary_exit_return(S_FROM_NSBOOT_VARM_FLASH_PAGE_PROGRAM, rc);
}

#if !ASM_SIZE_HACKS
int s_from_nsboot_varm_flash_sector_erase(uint32_t addr) {
    canary_entry(S_FROM_NSBOOT_VARM_FLASH_SECTOR_ERASE);
    int rc = s_varm_api_checked_flash_op(
        (cflash_flags_t) {.flags =
            (CFLASH_ASPACE_VALUE_STORAGE  << CFLASH_ASPACE_LSB  ) |
            (CFLASH_SECLEVEL_VALUE_NSBOOT << CFLASH_SECLEVEL_LSB) |
            (CFLASH_OP_VALUE_ERASE        << CFLASH_OP_LSB      )
        },
        XIP_BASE + addr,
        FLASH_SECTOR_SIZE,
        NULL
    );
    canary_exit_return(S_FROM_NSBOOT_VARM_FLASH_SECTOR_ERASE, rc);
}
#else
static_assert(XIP_BASE == 0x10000000, "");
static_assert(FLASH_SECTOR_SIZE == (XIP_BASE >> 16), "");
int __attribute__((naked)) s_from_nsboot_varm_flash_sector_erase(__unused uint32_t addr) {
    pico_default_asm_volatile(
            "movs r1, #0x10\n"
            "lsls r1, r1, #24\n"
            "lsrs r2, r1, #16\n"
            "adds r1, r0\n"
            "ldr r0, =%[flags]\n"
            "movs r3, #0\n"
            ".global s_from_nsboot_varm_flash_sector_erase_end\n"
            "s_from_nsboot_varm_flash_sector_erase_end:\n"
            // fall trhue "b s_varm_api_checked_flash_op\n"
            :
            : [flags] "i" ((CFLASH_ASPACE_VALUE_STORAGE  << CFLASH_ASPACE_LSB  ) |
                           (CFLASH_SECLEVEL_VALUE_BOOTLOADER << CFLASH_SECLEVEL_LSB) |
                           (CFLASH_OP_VALUE_ERASE        << CFLASH_OP_LSB      ))
            );
}
#endif

int s_from_nsboot_varm_flash_read_data(uint8_t *rx, uint32_t addr, size_t count) {
    int rc;
    // regalloc: use prolog-saved reg to avoid separate spill over call
    canary_entry_reg(r4, S_FROM_NSBOOT_VARM_FLASH_READ_DATA);
    hx_bool addr_ok = hx_bool_invalid();
    rx = varm_to_s_native_api_validate_ns_buffer(rx, count, hx_true(), &addr_ok);
    if (hx_is_false(addr_ok)) {
        rc = PICOBOOT_INVALID_ADDRESS;
        goto flash_read_data_done;
    }
    hx_assert_true(addr_ok);
    rc = s_varm_api_checked_flash_op(
        (cflash_flags_t) {.flags =
            (CFLASH_ASPACE_VALUE_STORAGE  << CFLASH_ASPACE_LSB  ) |
            (CFLASH_SECLEVEL_VALUE_BOOTLOADER << CFLASH_SECLEVEL_LSB) |
            (CFLASH_OP_VALUE_READ         << CFLASH_OP_LSB      )
        },
        XIP_BASE + addr,
        count,
        rx
    );
    flash_read_data_done:
    canary_exit_return(S_FROM_NSBOOT_VARM_FLASH_READ_DATA, rc);
}

// secure is set to true if we're coming from nsboot (as secure locks are already advanced to match nsboot locks)
int __noinline s_from_ns_varm_api_otp_access_internal(aligned4_uint8_t *buf, uint32_t buf_len, otp_cmd_t cmd, hx_xbool secure) {
    // regalloc: use prolog-saved reg to avoid separate spill over call
    canary_entry_reg(r4, S_FROM_NS_VARM_API_OTP_ACCESS_INTERNAL);
    int rc;
    hx_bool addr_ok = hx_bool_invalid();
    buf = varm_to_s_native_api_validate_ns_buffer(buf, buf_len, make_hx_bool(!(cmd.flags & OTP_CMD_WRITE_BITS)), &addr_ok);
    if (hx_is_false(addr_ok)) {
        rc = (int)buf;
        //rc = BOOTROM_ERROR_INVALID_ADDRESS;
        goto access_internal_done;
    }

    // checked in s_varm_api_hx_otp_access
//    if ((uintptr_t)buf & 0x3u) {
//        return BOOTROM_ERROR_INVALID_ADDRESS;
//    }
//    if ((uintptr_t)io->row & ~(OTP_CMD_ROW_BITS >> OTP_CMD_ROW_LSB)) {
//        return BOOTROM_ERROR_INVALID_ARG;
//    }
    hx_assert_true(addr_ok);
    rc = s_varm_api_hx_otp_access(
            buf,
            buf_len,
            cmd,
            secure);

    access_internal_done:
    canary_exit_return(S_FROM_NS_VARM_API_OTP_ACCESS_INTERNAL, rc);
}

int s_from_nsboot_varm_otp_access(aligned4_uint8_t *buf, uint32_t buf_len, otp_cmd_t cmd) {
    // regalloc: use prolog-saved reg to avoid separate spill over call
    canary_entry_reg(r4, S_FROM_NSBOOT_VARM_OTP_ACCESS);
    // note: we assume interrupts are enabled at this point to save space, as there is no reason
    // the NS code would call us with IRQs disabled
    bootrom_assert(MISC, !save_and_disable_interrupts());
    disable_irqs(); // uint32_t save = save_and_disable_interrupts();
    // OTP locks are already advanced, so pass true for secure access
    int rc = s_from_ns_varm_api_otp_access_internal(buf, buf_len, cmd, hx_otp_secure_true());
    enable_irqs(); // restore_interrupts(save);
    canary_exit_return(S_FROM_NSBOOT_VARM_OTP_ACCESS, rc);
}

#if !TAIL_CALL_HACKS
int s_from_ns_varm_api_otp_access(aligned4_uint8_t *buf, uint32_t buf_len, otp_cmd_t cmd) {
    return s_from_ns_varm_api_otp_access_internal(buf, buf_len, cmd, hx_bit_pattern_otp_secure_false());
}
#else
static_assert((OTP_CMD_ECC_BITS | OTP_CMD_ROW_BITS | OTP_CMD_WRITE_BITS) == 0x3ffff, "");
void __exported_from_arm __attribute__((naked)) s_from_ns_varm_api_otp_access(__unused aligned4_uint8_t *buf, __unused uint32_t buf_len, __unused otp_cmd_t cmd) {
    pico_default_asm_volatile(
            // load value twice to make it harder to skip; seems better than a hardened false value,
            // since we care more that the user can't pass in their own correct xtrue value than
            // what the value is; note this method does not check validity of false values
            "movs r3, #0\n"
            "movs r3, #0\n"
            "b.n s_from_ns_varm_api_otp_access_internal\n"
    );
}
#endif

#if FEATURE_EXEC2
int s_from_ns_varm_picoboot_exec2(struct picoboot_exec2_cmd *_cmd) {
    int rc;
    canary_entry(S_FROM_NS_VARM_PICOBOOT_EXEC2);
    struct picoboot_exec2_cmd *cmd = __builtin_assume_aligned(_cmd, 4);
    hx_bool addr_ok;
    cmd = varm_to_s_native_api_validate_ns_buffer(cmd, sizeof(*cmd), hx_false(), &addr_ok);
    struct picoboot_exec2_cmd cpy;
    bootram->always.nonce++;
    if (hx_is_xtrue(hx_step_safe_get_boot_flagx(OTP_DATA_BOOT_FLAGS0_DISABLE_BOOTSEL_EXEC2_LSB))) {
        rc = BOOTROM_ERROR_NOT_PERMITTED;
        goto exec2_done;
    }
    rc = BOOTROM_ERROR_INVALID_ADDRESS;
    if (hx_is_true(addr_ok)) {
        cpy = *cmd;
        varm_to_s_native_api_validate_ns_buffer((void *)cpy.image_base, cpy.image_size, hx_false(), &addr_ok);
        uint aligns = cpy.image_base | cpy.image_size | cpy.workarea_base | cpy.workarea_size;
        if (hx_is_true(addr_ok) && !(aligns & 0x1f)) {
            varm_to_s_native_api_validate_ns_buffer((void *)cpy.workarea_base, cpy.workarea_size, hx_true(), &addr_ok);
            if (hx_is_true(addr_ok)) {
                hx_assert_true(addr_ok);
                if (cpy.workarea_size < sizeof(scan_workarea_t)) {
                    rc = BOOTROM_ERROR_BUFFER_TOO_SMALL;
                    goto exec2_done;
                }
                scan_workarea_t *scan_workarea = (scan_workarea_t *) cpy.workarea_base;
                s_varm_crit_get_non_booting_boot_scan_context(scan_workarea, true, false);
                boot_scan_context_t *ctx = &scan_workarea->ctx_holder.ctx;
                ctx->exec2 = hx_true();
                ctx->current_search_window.base = cpy.image_base;
                ctx->current_search_window.size = cpy.image_size;

                branch_under_varmulet(varm);
                // make regions secure-only, so
                //   a) NS can't mess with them
                //   b) we can execute from the image
                // this will overlap existing regions thus making it secure again
                INIT_SAU_REGION_D(4, cpy.image_base, cpy.image_base + cpy.image_size, false, true);
                INIT_SAU_REGION_D(5, cpy.workarea_base, cpy.workarea_base + cpy.workarea_size, false, true);
                varm:

                rc = s_varm_crit_ram_trash_checked_ram_or_flash_window_launch(ctx);
                branch_under_varmulet(varm2);
                DISABLE_SAU_REGION(4);
                DISABLE_SAU_REGION(5);
                varm2: ;
            }
        }
    }
    exec2_done:
    canary_exit_return(S_FROM_NS_VARM_PICOBOOT_EXEC2, rc);
}
#endif

int s_from_ns_varm_api_get_sys_info(uint32_t *buffer, uint32_t buffer_size_words, uint flags) {
    // regalloc: use prolog-saved reg to avoid separate spill over call
    canary_entry_reg(r4, S_FROM_NS_VARM_API_GET_SYS_INFO);
    hx_bool ok = hx_bool_invalid();
    uint32_t buffer_size_bytes = buffer_size_words * 4u;
    uint32_t *addr = varm_to_s_native_api_validate_ns_buffer(buffer, buffer_size_bytes, hx_true(), &ok);
    int rc = (int)addr; //BOOTROM_ERROR_INVALID_ADDRESS;
    if (hx_is_true(ok)) {
        // Note we use buffer_size_bytes / 4, not buffer_size_words, since it's not necessarily true
        // that x * 4 >= x when accounting for unsigned wrapping
        rc = s_varm_api_get_sys_info(addr, buffer_size_bytes / 4, flags);
    }
    canary_exit_return(S_FROM_NS_VARM_API_GET_SYS_INFO, rc);
}

