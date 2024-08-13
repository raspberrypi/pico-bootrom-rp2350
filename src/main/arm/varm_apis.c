/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bootram.h"
#include "bootrom.h"
#include "bootrom_otp.h"
#include "hardware/regs/sysinfo.h"
#include "hardware/regs/tbman.h"
#include "hardware/structs/psm.h"
#include "hardware/structs/syscfg.h"
#include "hardware/structs/ticks.h"
#include "hardware/structs/watchdog.h"
#include "mini_printf.h"
#include "sb_sha256.h"
#include "varm_boot_path.h"
#include "varm_flash_permissions.h"

#if defined(__ARM_ARCH_8M_MAIN__) || !defined(__ARM_ARCH_8M_BASE__)
#error this must be compiled with armv8m-base
#endif

// this is ued by arm6 code so don't use the one from SDK platform.c
bool running_on_fpga(void) {
    return (*(io_ro_32 *)TBMAN_BASE) & TBMAN_PLATFORM_FPGA_BITS;
}

#if !SILICON_BUILD
static int varm_running_in_sim(void) {
    return *(io_rw_32 *)(TBMAN_BASE + TBMAN_PLATFORM_OFFSET) & TBMAN_PLATFORM_HDLSIM_BITS;
}
#endif

// these must be the same (see IDENTITY_REASON below)
static_assert(BOOT_TYPE_PC_SP == REBOOT2_FLAG_REBOOT_TYPE_PC_SP, "");
static_assert(BOOT_TYPE_NORMAL == REBOOT2_FLAG_REBOOT_TYPE_NORMAL, "");
static_assert(BOOT_TYPE_BOOTSEL == REBOOT2_FLAG_REBOOT_TYPE_BOOTSEL, "");
static_assert(BOOT_TYPE_RAM_IMAGE == REBOOT2_FLAG_REBOOT_TYPE_RAM_IMAGE, "");
static_assert(BOOT_TYPE_FLASH_UPDATE == REBOOT2_FLAG_REBOOT_TYPE_FLASH_UPDATE, "");

static __force_inline uint inline_picoboot_reboot2_cmd_reboot_type(uint32_t flags) {
    return flags & REBOOT2_TYPE_MASK;
}

int __exported_from_arm __used s_varm_hx_reboot(uint32_t flags, uint32_t delay_ms, uint32_t p0, uint32_t p1, uint32_t flags2) {
    canary_entry(S_VARM_API_REBOOT);
    int rc;
#if !SILICON_BUILD
    if (varm_running_in_sim()) delay_ms = 1;
#endif
    hx_assert_equal2i(flags, flags2);
    check_hw_layout(watchdog_hw_t, scratch[7], WATCHDOG_SCRATCH7_OFFSET);
    // Disable watchdog before configuring, and clear PAUSE bits to ensure we
    // reboot even under debugger:
    watchdog_hw->ctrl = 0;
    // Configure PSM to perform a full reset on watchdog trigger, except for
    // the processor cold reset domain (the first PSM stage) which includes
    // things like the Arm debug halt-on-reset bits.
    psm_hw->wdsel = ~PSM_WDSEL_PROC_COLD_BITS;

    uint reboot_type = inline_picoboot_reboot2_cmd_reboot_type(flags);
    if (reboot_type != REBOOT2_FLAG_REBOOT_TYPE_PC_SP) {
        watchdog_hw->scratch[2] = p0;
        watchdog_hw->scratch[3] = p1;
        p0 = REBOOT_TO_MAGIC_PC;
        p1 = reboot_type;
    }

    //    printf("reboot flags %02x\n", reboot_cmd->bFlags);
    if (flags & (REBOOT2_FLAG_REBOOT_TO_ARM | REBOOT2_FLAG_REBOOT_TO_RISCV)) {
        uint archsel_request = (flags & REBOOT2_FLAG_REBOOT_TO_RISCV) ? OTP_ARCHSEL_BITS : 0;
        otp_hw->archsel = archsel_request;
        // archsel ignores writes of unsupported values. If we continue with the reboot then we will
        // get stuck in a boot loop of repeated switch attempts, so it's preferable to bail out:
        if (otp_hw->archsel != archsel_request) {
            printf("Can't reboot with requested ARCHSEL: not available, due to OTP\n");
            // NO_RETURN does not apply, as the reboot failed.
            rc = BOOTROM_ERROR_NOT_PERMITTED;
            goto reboot_return;
        }
    }
    if (reboot_type == REBOOT2_FLAG_REBOOT_TYPE_NORMAL) {
#if MINI_PRINTF
        printf("WATCHDOG REBOOT regular\n");
#endif
        bootram->always.diagnostic_partition_index = (int8_t)watchdog_hw->scratch[2];
        printf("SETTING DIAGNOSTIC PARTITION TO %d\n", (int8_t)watchdog_hw->scratch[2]);
        watchdog_hw->scratch[4] = 0;
    } else {
#if MINI_PRINTF
        printf("WATCHDOG REBOOT %d %08x %08x %d\n", reboot_type, (int)p0, (int)p1, (int)delay_ms);
        mini_printf_flush();
#endif
        watchdog_hw->scratch[4] = VECTORED_BOOT_MAGIC;
        watchdog_hw->scratch[5] = p0 ^ -watchdog_hw->scratch[4];
        watchdog_hw->scratch[6] = p1;
        watchdog_hw->scratch[7] = p0;
    }
    watchdog_hw->load = delay_ms * 1000u;

    // Make sure watchdog tick is running. If not, we probably got here from a
    // cold boot, and clk_ref is running from the ROSC at approx 12 MHz. If it
    // is already running then assume the current divisor is correct.
    if (!(ticks_hw->ticks[TICK_WATCHDOG].ctrl & TICKS_WATCHDOG_CTRL_ENABLE_BITS)) {
        ticks_hw->ticks[TICK_WATCHDOG].cycles = 12u;
        ticks_hw->ticks[TICK_WATCHDOG].ctrl = TICKS_WATCHDOG_CTRL_ENABLE_BITS;
    }
    // Use SYSCFG register to force powman to switch away from clk_ref before enabling watchdog, to
    // avoid potential clock glitches on clk_pow upon the watchdog resetting the system-level clock
    // generators. Since we are using the watchdog timer mode only (not immediate trigger) there
    // should always be sufficient delay between the clock switch and the watchdog triggering
    // (minimum: approx 5 cycles of clk_ref)
    hw_set_bits(&syscfg_hw->auxctrl, 0x01);
    // Actually start counting down for the reset:
    watchdog_hw->ctrl = WATCHDOG_CTRL_ENABLE_BITS;

    while (flags & REBOOT2_FLAG_NO_RETURN_ON_SUCCESS) __wfi();
    rc = BOOTROM_OK;
    reboot_return:
    canary_exit_return(S_VARM_API_REBOOT, rc);
}

int __exported_from_arm s_varm_api_get_sys_info(uint32_t *out_buffer, uint32_t out_buffer_word_size, uint32_t flags) {
    canary_entry(S_VARM_API_GET_SYS_INFO);
    // indicate what we support
    flags &= (SYS_INFO_CHIP_INFO |
              SYS_INFO_CRITICAL |
              SYS_INFO_CPU_INFO |
              SYS_INFO_FLASH_DEV_INFO |
              SYS_INFO_BOOT_RANDOM |
              #if FEATURE_EXEC2
              SYS_INFO_NONCE |
              #endif
              SYS_INFO_BOOT_INFO);
    uint32_t dest_index;
#if !ASM_SIZE_HACKS
    if (3 & ((uintptr_t)out_buffer)) {
        dest_index = (uint32_t)BOOTROM_ERROR_BAD_ALIGNMENT;
        goto sys_info_done;
    }
#else
    pico_default_asm_goto (
        "lsls %[dest_index], %[out_buffer], #30\n"
        "beq 1f\n"
        "movs %[dest_index], %[bad_alignment]\n"
        "b.n %l[return_minus_dest_index]\n"
        "1:"
        : [dest_index] "=l" (dest_index)
        : [out_buffer] "l" (out_buffer), [bad_alignment] "i" (-BOOTROM_ERROR_BAD_ALIGNMENT)
        : "cc"
        : return_minus_dest_index
    );
#endif

    uint32_t outputs[10];
    uint8_t lens[(count_of(outputs)+3u)&~3u] __aligned(4);
    // bad GCC, why is assume_aligned needed here?
    uint32_t *lens32 = (uint32_t *)__builtin_assume_aligned(lens, 4);

    // return what we supported
    outputs[0] = (uintptr_t)&flags;
    lens32[0] = 0x0;
    lens32[1] = 0x0;
    lens32[2] = 0x0;

    uint output_count = 1;
    typeof(bootram->always) *always = __get_opaque_ptr(&bootram->always);
    if (flags & SYS_INFO_CHIP_INFO) {
        // first three counts are 1 (returned flags), 1 (package sel), 2 (chip id)
        lens32[0] = 0x10000;
        outputs[output_count++] = SYSINFO_BASE + SYSINFO_PACKAGE_SEL_OFFSET;
        outputs[output_count++] = (uintptr_t)&always->chip_id;
    }
    io_ro_32 *otp_critical = __get_opaque_ptr(&otp_hw->critical);
    if (flags & SYS_INFO_CRITICAL) {
        outputs[output_count++] = (uintptr_t)otp_critical;
    }
    uint32_t cpu_info;
    uint32_t flash_dev_info;
    if (flags & SYS_INFO_CPU_INFO) {
        // read otp->archsel relative to otp->critical to save code size
        uint32_t archsel_bits = otp_critical[(OTP_ARCHSEL_STATUS_OFFSET - OTP_CRITICAL_OFFSET)/4];
        static_assert(PICOBIN_IMAGE_TYPE_EXE_CPU_RISCV == 1, "");
        static_assert(PICOBIN_IMAGE_TYPE_EXE_CPU_ARM == 0, "");
        static_assert(OTP_ARCHSEL_CORE0_BITS == 1, "");
        static_assert(OTP_ARCHSEL_CORE1_BITS == 2, "");
        cpu_info = (archsel_bits >> get_core_num()) & 1;
        outputs[output_count++] = (uintptr_t)&cpu_info;
    }
    if (flags & SYS_INFO_FLASH_DEV_INFO) {
        flash_dev_info = always->zero_init.flash_devinfo;
        outputs[output_count++] = (uintptr_t)&flash_dev_info;
    }
    if (flags & SYS_INFO_BOOT_RANDOM) {
        lens[output_count] = 3;
        outputs[output_count++] = (uintptr_t)&always->boot_random;
    }
#if FEATURE_EXEC2
    if (flags & SYS_INFO_NONCE) {
        lens[output_count] = 1;
        outputs[output_count++] = (uintptr_t)&always->nonce;
    }
#endif
    if (flags & SYS_INFO_BOOT_INFO) {
        lens[output_count] = 1;
        outputs[output_count++] = (uintptr_t)&always->boot_type_and_diagnostics;
        lens[output_count] = 1;
        outputs[output_count++] = (uintptr_t)&always->zero_init.reboot_params;
    }
    // helpful assert in case you add more
    bootrom_assert(MISC, output_count <= count_of(outputs));
    dest_index = 0;
    for(uint i=0;i<output_count;i++) {
        uint len = lens[i] + 1;
        if (dest_index + len > out_buffer_word_size) {
            printf("buffer isn't big enough to hold sys info %d %d\n", dest_index + len, out_buffer_word_size);
            dest_index = (uint32_t)-BOOTROM_ERROR_BUFFER_TOO_SMALL;
return_minus_dest_index:
            dest_index = -dest_index;
            goto sys_info_done;
        }
        const uint32_t *src = (const uint32_t *)outputs[i];
        varm_to_native_memcpy(out_buffer+dest_index, src, len * 4);
        dest_index += len;
    }
    sys_info_done:
    canary_exit_return(S_VARM_API_GET_SYS_INFO, (int)dest_index);
}

int __exported_from_arm s_varm_api_get_partition_table_info(uint32_t *out_buffer, uint32_t out_buffer_word_size, uint32_t flags_and_partition) {
    // using negrc (-rc) rather than rc to help GCC out with code size
    int negrc;
    // regalloc: best to leave this alone as the compiler already wants all of r4-r7
    canary_entry(S_VARM_API_GET_PARTITION_TABLE_INFO);
    uintptr_t pt_addr = __get_opaque_ptr(BOOTRAM_BASE + offsetof(bootram_t, always.partition_table));
    resident_partition_table_t *partition_table = (resident_partition_table_t *)pt_addr;
    if (!inline_s_is_resident_partition_table_loaded_pt(partition_table)) {
        negrc = -BOOTROM_ERROR_PRECONDITION_NOT_MET;
        goto get_partition_table_info_done;
    }
    
    bootrom_assert(MISC, !partition_table->partition_count || partition_table->secure_item_address);
    // note this is ignored if partition_count == 0
    const uint32_t *item_data = (const uint32_t *) (partition_table->secure_item_address + XIP_NOCACHE_NOALLOC_NOTRANSLATE_BASE - XIP_BASE);
    if ((uintptr_t)out_buffer << 30) {
        negrc = -BOOTROM_ERROR_BAD_ALIGNMENT;
        goto get_partition_table_info_done;
    }
    uint32_t *adjusted_out_buffer = out_buffer + 1;
    // return the flags we can have included
    if (flags_and_partition & PT_INFO_PT_INFO) {
        if (out_buffer_word_size >= 4) {
            adjusted_out_buffer[0] = partition_table->partition_count |
                                     (partition_table->secure_item_address != 0 ? 256 : 0);
            *(resident_partition_t *)&adjusted_out_buffer[1] = s_varm_flashperm_get_default_partition();
        }
        adjusted_out_buffer += 3;
    }
    out_buffer_word_size += (uint32_t)(out_buffer - adjusted_out_buffer);
    if ((int32_t)out_buffer_word_size < 0) {
        negrc = -BOOTROM_ERROR_BUFFER_TOO_SMALL;
        goto get_partition_table_info_done;
    }
    // fill in first word once we've checked space (word is what flags we supported)
    out_buffer[0] = flags_and_partition & (PT_INFO_PT_INFO |
                                           PT_INFO_PARTITION_LOCATION_AND_FLAGS |
                                           PT_INFO_PARTITION_ID |
                                           PT_INFO_PARTITION_FAMILY_IDS |
                                           PT_INFO_PARTITION_NAME |
                                           PT_INFO_SINGLE_PARTITION);
    int rc = s_varm_crit_get_pt_partition_info(adjusted_out_buffer, out_buffer_word_size , flags_and_partition,
                                              item_data, partition_table->partition_count,
                                              false);
    if (rc >= 0) {
        rc += (adjusted_out_buffer - out_buffer);
    }
    negrc = -rc;
    get_partition_table_info_done:
    negrc = -negrc;
    canary_exit_return(S_VARM_API_GET_PARTITION_TABLE_INFO, negrc);
}

uint __exported_from_arm s_varm_step_safe_api_crit_bootrom_state_reset(uint sr_type) {
    canary_entry_reg(ip, S_VARM_STEP_SAFE_API_CRIT_BOOTROM_STATE_RESET);
    // Note BOOTROM_STATE_RESET_CURRENT_CORE can't be handled inside of
    // varmulet, as it's attempting to reset varmulet state which is actually
    // saved/restored in varm_wrapper. It also should do nothing on Arm. See
    // RISC-V s_riscv_bootrom_state_reset asm routine.
    uint i = sr_type;
    if (sr_type & BOOTROM_STATE_RESET_OTHER_CORE) {
        int other_core = !get_core_num();
        static_assert(sizeof(bootram->runtime.core[other_core].arm) == 0, "");
        // note: arm core 1 may use this area for stack when launched from NS core 0
        if (otp_hw->archsel_status & (1u << other_core)) {
            // bootram->runtime.core[other_core].riscv.varmulet_enclosing_cpu = 0;
            // bootram->runtime.core[other_core].riscv.varmulet_user_stack_size = 0;
            uint32_t *user_stack_size = __get_opaque_ptr(&bootram->runtime.core[0].riscv.varmulet_user_stack_size);
            if (other_core) user_stack_size += sizeof(bootram->runtime.core[0]) / 4;

            static_assert(offsetof(bootram_t, runtime.core[0].riscv.varmulet_enclosing_cpu) ==
                          offsetof(bootram_t, runtime.core[0].riscv.varmulet_user_stack_size) + 4, "");
            bootrom_assert(MISC, &user_stack_size[1] == (uint32_t *)&bootram->runtime.core[other_core].riscv.varmulet_enclosing_cpu);
            user_stack_size[1] = 0;
            bootrom_assert(MISC, user_stack_size == &bootram->runtime.core[other_core].riscv.varmulet_user_stack_size);
            *user_stack_size = 0;
        }
    }
    if (sr_type & BOOTROM_STATE_RESET_GLOBAL_STATE) {
        // un-claim our locking flag spinlock (meaning no locks are required for things like SHA, flash write, OTP write)

        // the value written doesn't matter, so let's use stmia (also we don't care about writing multiple times in case of interrupt)
        //for (uint i = 0; i < count_of(bootram_hw->bootlock); i++) {
        //    bootram_hw->bootlock[i] = 0;
        //}
        static_assert(count_of(bootram_hw->bootlock) == 8, "");
        register uint32_t r0 asm ("r0") = (uintptr_t)bootram_hw->bootlock;
        pico_default_asm_volatile(
                "stmia r0!, {r0-r7}\n" :
                "+l" (r0)
                );
        typeof (bootram->always) *always = __get_opaque_ptr(&bootram->always);
#if 1
        // avoid compiler use of memset
        static_assert(count_of(always->ns_api_permissions) == 8, "");
        uint t0 = hx_bit_pattern_c3c3c3c3();
        uint t1 = (uintptr_t)always->ns_api_permissions;
        pico_default_asm_volatile("str %0, [%1]\n"
                                  "str %0, [%1, 4]\n"
            : : "l" (t0), "l" (t1));
#else
        for (uint i = 0; i < BOOTROM_NS_API_COUNT; i++) {
            always->ns_api_permissions[i] = 0xc3;
        }
#endif
        for (i = 0; i < BOOTROM_API_CALLBACK_COUNT; i++) {
            always->callbacks[i] = 0;
        }
    }
    canary_exit_return(S_VARM_STEP_SAFE_API_CRIT_BOOTROM_STATE_RESET, i);
}

// Set numbered callback, and return its original value. Return negative
// integer, no less than BOOTROM_ERROR_LAST, on failure. Magic argument of -1
// means do not change current callback (but still return it).
bootrom_api_callback_generic_t __exported_from_arm s_varm_api_set_rom_callback(uint callback_num, bootrom_api_callback_generic_t funcptr) {
    // GCC fails to use IP without holding its hand
    canary_entry_reg(ip, S_VARM_API_SET_ROM_CALLBACK);
    bootrom_api_callback_generic_t old;
    if (callback_num >= BOOTROM_API_CALLBACK_COUNT) {
        // A little bit dirty, but negative signed integers are always invalid
        // function pointers on RP2350 (and you will find this out very
        // quickly if you try to call one)
        old = (bootrom_api_callback_generic_t)BOOTROM_ERROR_INVALID_ARG;
        goto set_rom_callback_done;
    }
    old = bootram->always.callbacks[callback_num];
    if ((intptr_t)funcptr >= 0) {
        bootram->always.callbacks[callback_num] = funcptr;
    }
    set_rom_callback_done:
    canary_exit_return(S_VARM_API_SET_ROM_CALLBACK, old);
}

// note we actually just check for the maximum of our two values to save code space
void __noinline *s_varm_check_scan_work_area_and_check_sha_lock(uint8_t *workarea_base, uint32_t workarea_size, __unused uint32_t required_size) {
    canary_entry(S_VARM_CHECK_SCAN_WORK_AREA_AND_CHECK_SHA_LOCK);
    scan_workarea_t *scan_workarea;
    if ((uintptr_t)workarea_base & 3) {
        scan_workarea = (scan_workarea_t *)BOOTROM_ERROR_BAD_ALIGNMENT;
        goto check_scan_workarea_done;
    }
#define WORKAREA_CHECK_SIZE MAX(sizeof(scan_workarea_t), sizeof(uf2_target_workarea_t))
    bootrom_assert(MISC, required_size <= WORKAREA_CHECK_SIZE);
    if (workarea_size < WORKAREA_CHECK_SIZE) {
        scan_workarea = (scan_workarea_t *)BOOTROM_ERROR_BUFFER_TOO_SMALL;
        goto check_scan_workarea_done;
    }
    // methods that need a scan workarea may also do verification/hashing
    scan_workarea = (scan_workarea_t *)inline_s_lock_check(BOOTROM_LOCK_SHA_256);
    if (!scan_workarea) {
        scan_workarea = (scan_workarea_t *)__builtin_assume_aligned(workarea_base, 4);
    }
    check_scan_workarea_done:
    canary_exit_return(S_VARM_CHECK_SCAN_WORK_AREA_AND_CHECK_SHA_LOCK, scan_workarea);
}

int __exported_from_arm s_varm_api_chain_image(uint8_t *workarea_base, uint32_t workarea_size, uint32_t window_base, uint32_t window_size) {
    canary_entry(S_VARM_API_CHAIN_IMAGE);
    scan_workarea_t *scan_workarea = s_varm_check_scan_work_area_and_check_sha_lock(workarea_base, workarea_size,
                                                                                    sizeof(scan_workarea_t));
    int rc;
    if ((intptr_t)scan_workarea < 0) {
        rc = (intptr_t)scan_workarea;
        goto chain_image_done;
    }
    s_varm_crit_get_non_booting_boot_scan_context(scan_workarea,
                                                  true, // executable_image_def_only
                                                  false); // verify_without_signatures
    boot_scan_context_t *ctx = &scan_workarea->ctx_holder.ctx;

    // if window_base < 0 then it means the value needs to be negated,  and also used as the flash_update_partition
    // if window_base >= 0 then the negated value is still used as the flash_update_boot_offset, so will be invalid
    ctx->flash_update_boot_offset = (-window_base) - XIP_BASE;
    if ((int32_t)window_base < 0) {
        window_base = -window_base;
    }

    // the following fields are uninitialized at this point
    //    boot_window_t current_search_window;
    //    uint8_t load_image_counter; // which doesn't matter it just needs to not change from A to B
    //    int8_t flash_mode;
    //    uint8_t flash_clkdiv;
    static_assert(offsetof(bootram_t, always.boot_type_and_diagnostics) < offsetof(bootram_t, always.partition_table), "");
    uintptr_t bootram_type_and_diagnostics = BOOTRAM_BASE + offsetof(bootram_t, always.boot_type_and_diagnostics);
    bootram_type_and_diagnostics = __get_opaque_value(bootram_type_and_diagnostics);

    resident_partition_table_t *pt = (resident_partition_table_t *)
            (bootram_type_and_diagnostics + offsetof(bootram_t, always.partition_table) - offsetof(bootram_t, always.boot_type_and_diagnostics));
    if (inline_s_is_resident_partition_table_loaded_pt(pt)) {
        for(uint i=0;i<pt->partition_count;i++) {
            if (inline_s_partition_start_offset(&pt->partitions[i]) == window_base - XIP_BASE) {
                typeof(bootram->always.recent_boot.partition) *recent_boot_partition = (typeof(bootram->always.recent_boot.partition) *)
                        (bootram_type_and_diagnostics + offsetof(bootram_t, always.recent_boot.partition) - offsetof(bootram_t, always.boot_type_and_diagnostics));
                *recent_boot_partition = (int8_t)i;
            }
        }
    }

    ctx->current_search_window.base = window_base;
    ctx->current_search_window.size = window_size;
    ctx->booting = hx_true();
    typeof(bootram->always.boot_type) *boot_type = (typeof(bootram->always.boot_type) *)
            (bootram_type_and_diagnostics + offsetof(bootram_t, always.boot_type) - offsetof(bootram_t, always.boot_type_and_diagnostics));
    uint saved_boot_type = *boot_type;
    *boot_type |= (uint8_t)BOOT_TYPE_CHAINED_FLAG;
    rc = s_varm_crit_ram_trash_checked_ram_or_flash_window_launch(ctx);
    *boot_type = (uint8_t)saved_boot_type;
    chain_image_done:
    canary_exit_return(S_VARM_API_CHAIN_IMAGE, rc);
}

int __exported_from_arm s_varm_api_load_partition_table(uint8_t *workarea_base, uint32_t workarea_size, bool force_reload) {
    // regalloc: force use of callee-save, smaller when not all of r4-r7 are already in use
    canary_entry_reg(r4, S_VARM_API_LOAD_PARTITION_TABLE);
    scan_workarea_t *scan_workarea = s_varm_check_scan_work_area_and_check_sha_lock(workarea_base, workarea_size,
                                                                                    sizeof(scan_workarea_t));
    if ((intptr_t)scan_workarea >= 0) {
        s_varm_crit_load_resident_partition_table(scan_workarea, force_reload);
        scan_workarea = (scan_workarea_t *) BOOTROM_OK;
    }
    canary_exit_return(S_VARM_API_LOAD_PARTITION_TABLE, (intptr_t)scan_workarea);
}

#define read_word_and_hash() ({ uint tmp = pt_item_data[item_pos++]; s_varm_sha256_put_word_inc(tmp, &sha256); tmp; })
#define checked_write(t, v) ({ uint sz = (sizeof(t) + 3) / 4; uint next = dest_index + sz; if (dest_index + sz <= out_buffer_word_size) *(t *)(out_buffer + dest_index) = v; dest_index = next; })

// This method is called initial to populate the resident partition table fields (from a secure trusted buffer) with first_load_from_buffer = true,
// so we calculate the hash during that call, and then check it on the subsequent ones. Note, care must be taken on subsequent calls to not let invalid data
// cause us to run off the end of the buffer.
int s_varm_crit_get_pt_partition_info(uint32_t *out_buffer, uint32_t out_buffer_word_size, uint32_t flags_and_partition, const uint32_t *pt_item_data, uint partition_count, bool first_load_from_buffer) {
    canary_entry(S_VARM_CRIT_GET_PT_PARTITION_INFO);
    // combine init of dest_index with 0 to lock check
    uint32_t dest_index = (uint32_t)inline_s_lock_check(BOOTROM_LOCK_SHA_256);
    if (dest_index) goto done;
    // note if no partition count then the other args are ignored
    if (partition_count) {
        if (partition_count > PARTITION_TABLE_MAX_PARTITIONS) {
            dest_index = (uint32_t) BOOTROM_ERROR_INVALID_ARG;
            goto done;
        }
        uint item_pos = 0;
        uint item_size = inline_decode_item_size(pt_item_data[item_pos++]);
        item_pos++; // skip un-permissioned_space flags
        sb_sha256_state_t sha256;
        sb_sha256_init(&sha256);
        printf("  partitions:\n");
        for (uint i = 0; i < partition_count; i++) {
            uint this_time_flags;
            if ((flags_and_partition & PT_INFO_SINGLE_PARTITION) && i != (flags_and_partition >> 24u)) {
                this_time_flags = 0; // avoid writing data
            } else {
                this_time_flags = flags_and_partition;
            }
            resident_partition_t partition;
            // warning: this could read two words off the end of the input data - we will catch the error later (due
            // to size mismatch, and we deem this over-read safe because the caller's input buffer is either in the UNCACHED_UNTRANSLATED region
            // of XIP CS 0, or is in the scan_workarea->parsed_block_loops[0] which definitely has readable data after it
            partition.permissions_and_location = read_word_and_hash();
            partition.permissions_and_flags = read_word_and_hash();
            if (this_time_flags & PT_INFO_PARTITION_LOCATION_AND_FLAGS) {
                checked_write(resident_partition_t, partition);
            }
#if MINI_PRINTF
            printf("    %d", i);
            if (inline_s_is_b_partition(&partition)) {
                printf("(B w/ %d)", inline_s_partition_link_value(&partition));
            } else {
                // b_partition doesn't work without the PT loaded
                printf("(A)     ");
            }
            printf(" %08x->%08x", inline_s_partition_start_offset(&partition),
                   inline_s_partition_end_offset(&partition));
            if ((partition.location_and_permissions ^ partition.flags_and_permissions) &
                PICOBIN_PARTITION_PERMISSIONS_BITS) {
                printf(" (PERMISSION MISMATCH)\n");
                dest_index = (uint32_t)BOOTROM_ERROR_INVALID_DATA;
                goto done;
            }
            uint p = partition.location_and_permissions & partition.flags_and_permissions;
            print_partition_permissions(p);
#endif
            if (partition.permissions_and_flags & PICOBIN_PARTITION_FLAGS_HAS_ID_BITS) {
                printf(", has_id");
                uint32_pair_t id;
                // warning: this could read two words off the end of the input data - we will catch the error later (due
                // to size mismatch, and we deem this over-read safe because the caller's input buffer is either in the UNCACHED_UNTRANSLATED region
                // of XIP CS 0, or is in the scan_workarea->parsed_block_loops[0] which definitely has readable data after it
                id.e[0] = read_word_and_hash();
                id.e[1] = read_word_and_hash();
                if (this_time_flags & PT_INFO_PARTITION_ID) {
                    checked_write(uint32_pair_t, id);
                }
            }
            uint32_t num_extra_families =
                    (partition.permissions_and_flags & PICOBIN_PARTITION_FLAGS_ACCEPTS_NUM_EXTRA_FAMILIES_BITS)
                            >> PICOBIN_PARTITION_FLAGS_ACCEPTS_NUM_EXTRA_FAMILIES_LSB;
            printf(", families = {");
            // middle is the index in the source data between the extra families and the names
            // (note this code is a bit weird to save space)
            uint middle = item_pos + num_extra_families;
#if MINI_PRINTF
            print_partition_default_families(partition.flags_and_permissions);
            for(uint ip = item_pos; ip < middle; ip++) {
                 printf(" %08x,", pt_item_data[ip]);
                 if (ip != middle - 1) {
                     printf(", ");
                 }
            }
#endif
            uint end = middle;
            if (partition.permissions_and_flags & PICOBIN_PARTITION_FLAGS_HAS_NAME_BITS) {
                uint byte_len = pt_item_data[middle] & 0x7f;
                // byte_len + 1 rounded up
                end += (byte_len + 4) / 4;
            }
            uint include = this_time_flags & PT_INFO_PARTITION_FAMILY_IDS;
            // at this point we want to protect against reading arbitrarily large amounts
            // of data off the end of the data, so we take the code size hit.
            if (end > item_size) {
                // make sure item_size != item_pos for check below
                // note: that -1 or item_size + 1 would be better, as this does the wrong thing
                // if item_size == 0 (we return 0 - meaning zero words - rather than an error);
                // however using either of those causes sizable GCC bloat, and item_size
                // should not be zero (since that would be an invalid block)
                item_pos = 0;
                break;
            }

            while (item_pos < end) {
                if (item_pos == middle) include = this_time_flags & PT_INFO_PARTITION_NAME;
                uint32_t data = read_word_and_hash();
                if (include) {
                    if (dest_index < out_buffer_word_size) out_buffer[dest_index] = data;
                    dest_index++;
                }
            }
            if (dest_index > out_buffer_word_size) {
                printf("buffer isn't big enough to hold partition info\n");
                dest_index = (uint32_t) BOOTROM_ERROR_BUFFER_TOO_SMALL;
                goto done;
            }

            printf("}, arm_boot %d",
                   !(partition.permissions_and_flags & PICOBIN_PARTITION_FLAGS_IGNORED_DURING_ARM_BOOT_BITS));
            printf(", riscv_boot %d",
                   !(partition.permissions_and_flags & PICOBIN_PARTITION_FLAGS_IGNORED_DURING_RISCV_BOOT_BITS));
            printf("\n");
        }
        if (item_pos != item_size) {
            printf("\nbad PARTITION_TABLE item (size mismatch) %d!=%d\n", item_pos, item_size);
            dest_index = (uint32_t)BOOTROM_ERROR_INVALID_DATA;
            goto done;
        }
        sb_sw_message_digest_t digest;
        sb_sha256_finish(&sha256, digest.bytes);
        static_assert(PARTITION_TABLE_SHA256_HASH_WORDS == 1, ""); // i think one is sufficient
        if (first_load_from_buffer) {
            bootram->always.partition_table.hash[0] = digest.words[0];
        } else {
            if (bootram->always.partition_table.hash[0] != digest.words[0]) {
                printf("PT hash does not match that which was loaded originally\n");
                dest_index = (uint32_t)BOOTROM_ERROR_MODIFIED_DATA;
            }
        }
    }
    done:
    canary_exit_return(S_VARM_CRIT_GET_PT_PARTITION_INFO, (int)dest_index);
}
#undef read_word_and_hash
#undef checked_write

int __exported_from_arm s_varm_api_pick_ab_partition(uint8_t *workarea_base, uint32_t workarea_size, uint partition_a_num, uint32_t flash_update_boot_window_base) {
    // regalloc: force use of callee-save, smaller when not all of r4-r7 are already in use
    canary_entry_reg(r4, S_VARM_API_PICK_AB_PARTITION);
    scan_workarea_t *scan_workarea = s_varm_check_scan_work_area_and_check_sha_lock(workarea_base, workarea_size,
                                                                                    sizeof(scan_workarea_t));
    if ((intptr_t)scan_workarea < 0) {
        partition_a_num = (uintptr_t)scan_workarea;
        goto pick_ab_partition_done;
    }
    if (s_varm_crit_load_init_context_and_prepare_for_resident_partition_table_load(scan_workarea, false)) {
        // we don't auto-load the PT arguably, where would the partition number have come from
        partition_a_num = (uint)BOOTROM_ERROR_PRECONDITION_NOT_MET;
        goto pick_ab_partition_done;
    }
    bootrom_assert(MISC, inline_s_is_resident_partition_table_loaded());
    resident_partition_table_t *pt = &bootram->always.partition_table;
    if (partition_a_num >= pt->partition_count) {
        partition_a_num = (uint)BOOTROM_ERROR_INVALID_ARG;
        goto pick_ab_partition_done;
    }
    boot_scan_context_t *ctx = &scan_workarea->ctx_holder.ctx;
    ctx->flash_update_boot_offset = flash_update_boot_window_base - XIP_BASE;
    // we don't want the user to have to specify whether they are looking for executable or non-executable
    // image_defs, and for this particular API it would only matter if you were mixing both executable and
    // non-executable IMAGE_DEFs in the same partition
    ctx->executable_image_def_only = false;
    // note not ram trashing in this case, as we aren't using a booting ctx
    int which = s_varm_crit_ram_trash_pick_ab_image(ctx, partition_a_num);
    if (which) {
        partition_a_num = (uint) s_varm_api_crit_get_b_partition(partition_a_num);
        bootrom_assert(MISC, partition_a_num < pt->partition_count);
    }
    pick_ab_partition_done:
    canary_exit_return(S_VARM_API_PICK_AB_PARTITION, (int)partition_a_num);
}

int __exported_from_arm s_varm_api_get_uf2_target_partition(uint8_t *workarea_base, uint32_t workarea_size, uint32_t family_id, resident_partition_t *partition_out) {
    canary_entry(S_VARM_API_GET_UF2_TARGET_PARTITION);
    int rc;
    uf2_target_workarea_t *target_workarea = s_varm_check_scan_work_area_and_check_sha_lock(workarea_base,
                                                                                            workarea_size,
                                                                                            sizeof(uf2_target_workarea_t));
    if ((intptr_t) target_workarea < 0) {
        rc = (intptr_t) target_workarea;
        goto get_uf2_target_partition_done;
    }
    if (s_varm_crit_load_init_context_and_prepare_for_resident_partition_table_load(&target_workarea->scan_workarea, false)) {
        // we don't auto-load the PT arguably, where would the partition number have come from
        rc = BOOTROM_ERROR_PRECONDITION_NOT_MET;
        goto get_uf2_target_partition_done;
    }
    rc = s_varm_ram_trash_get_uf2_target_partition_workarea(family_id, partition_out, target_workarea);
    get_uf2_target_partition_done:
    canary_exit_return(S_VARM_API_GET_UF2_TARGET_PARTITION, (int) rc);
}
