/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "pico.h"
#include "bootrom_common.h"
#include "bootrom_assert.h"
#include "hardening.h"
#include "rcp_tags.h"
#include "varm_to_riscv_hints.h"
#include "pico/bootrom_constants.h"
#include "boot/picobin.h"
#ifndef SB_TEST
#include "bootrom_layout.h"
#ifndef __riscv
#include "p16.h"
#endif
#endif
#ifndef __ASSEMBLER__
#include "bootrom_error.h"
#include "boot/picoboot.h"
#include "hardware/structs/bootram.h"
#include "hardware/structs/otp.h"
#include "hardware/structs/sau.h"
#include "hardware/structs/mpu.h"
#include "hardware/sync.h"
#include "native_exports.h"
#endif

// CLK_SYS FREQ ON STARTUP (in MHz)
// +-----------------------
// | min    |  3.6        |
// | typ    |  13.0       |
// | max    |  22.6       |
// +----------------------+
#define ROSC_MHZ_MAX 23
#define ROSC_MHZ_TYP 13

#define BOOTROM_SHORT_REBOOT_MS 1

#define BOOT_ONCE_NSBOOT_API_DISABLED 0
// detect that OTP boot was used (nice to know if someone has injected some code in the boot path)
#define BOOT_ONCE_OTP_BOOT_TAKEN 1

#define INVALID_STACK_PTR 0xf0000000 // chosen to make things easier for varmulet_hooks_bootrom which has this in a reg already

#define VECTORED_BOOT_MAGIC          0xb007c0d3
// we reuse the same pattern to save on code/data space
#define REBOOT_TO_MAGIC_PC           VECTORED_BOOT_MAGIC

// Must match the definition of s_native_default_xip_setup in varm_misc.S
#define DEFAULT_ARM_XIP_SETUP_SIZE_BYTES 12

// Must match the definition of s_native_default_xip_setup in riscv_bootrom_rt0.S
#define DEFAULT_RISCV_XIP_SETUP_SIZE_BYTES 16

// Static region assignment: 0=SRAM, 1=XIP, 2=ROM:rodata+ns, 3=bootram_core1
#define BOOTROM_MPU_REGION_RAM           0
#define BOOTROM_MPU_REGION_FLASH         1
#define BOOTROM_MPU_REGION_SECURE_XN     2
#define BOOTROM_MPU_REGION_BOOTRAM_CORE1 3

#define BOOTROM_MPU_REGION_COUNT         4

#ifndef __ASSEMBLER__

#if !USE_64K_BOOTROM
#define __sg_filler __attribute__((section(".sg_fillers")))
#else
#define __sg_filler
#endif

#define __exported_from_arm __used __noinline

#if TAIL_CALL_HACKS
// need to manually mark symbols tail-called from inline asm as used
#define __used_if_tail_call_hacks __used
#else
#define __used_if_tail_call_hacks
#endif

#define debug_label(l) ({asm volatile ( "___" __STRING(l) ":");})

// note:: we chose a small number to keep this small, though we still want to be relatively confident that
// the pt data in flash hasn't changed. 32 bits seems fine for this
#define PARTITION_TABLE_SHA256_HASH_WORDS 1

// rp2040, rp2350 arm, rp2350 riscv, global, data
static_assert((int8_t)PARTITION_TABLE_NO_PARTITION_INDEX == -1, "");

typedef struct uf2_target_workarea uf2_target_workarea_t;

// sp can be 0 to use current stack
void varm_to_s_native_secure_call_pc_sp(uint32_t pc, uint32_t sp);
void s_varm_secure_call(uint32_t pc, uint32_t sp);

int s_varm_api_get_partition_table_info(uint32_t *out_buffer, uint32_t out_buffer_word_size, uint32_t flags);

// this is the internal method used by the previous
int s_varm_crit_get_pt_partition_info(uint32_t *out_buffer, uint32_t out_buffer_word_size, uint32_t flags_and_partition, const uint32_t *pt_item_data, uint partition_count, bool first_load_from_buffer);
int s_varm_ram_trash_get_uf2_target_partition(uint32_t family_id, resident_partition_t *partition_out);
int s_varm_ram_trash_get_uf2_target_partition_workarea(uint32_t family_id, resident_partition_t *partition_out, uf2_target_workarea_t *uf2_target_workarea);

int s_varm_api_get_sys_info(uint32_t *buffer, uint32_t buffer_size_words, uint32_t flags);
int s_varm_api_reboot(uint32_t flags, uint32_t delay_ms, uint32_t p0, uint32_t p1);
uint s_varm_step_safe_api_crit_bootrom_state_reset(uint reset_flags);

void varm_callable(s_native_busy_wait_at_least_cycles)(uint32_t cycles);
void varm_callable(s_native_crit_init_default_xip_setup_and_enter_image_thunk)(/*bootrom_xip_mode_t*/int8_t mode, uint clkdiv, uint32_t pc, uint32_t sp, uint32_t sp_lim, uint32_t vector_table);
void __attribute__((noreturn)) varm_callable(s_native_crit_launch_nsboot)(void);

void __attribute__((noreturn)) varm_and_native(dead)(void);
void __attribute__((noreturn)) varm_and_native(wait_rescue)(void);

static __force_inline int inline_s_lock_check(uint lock_type) {
    bootrom_assert(MISC, lock_type <= BOOTROM_LOCK_ENABLE);
    // note bits are 1 for unowned, 0 for owned
    uint stat = (~bootram_hw->bootlock_stat) & ((1u << BOOTROM_LOCK_ENABLE) | (1u << lock_type));
    if (stat < (1u << BOOTROM_LOCK_ENABLE) || stat == ((1u << BOOTROM_LOCK_ENABLE) | (1u << lock_type))) {
        return BOOTROM_OK;
    }
    // don't ask me how i figured this out, but this saves 28 bytes ;-)
    pico_default_asm_volatile("" : : : "memory");
    return BOOTROM_ERROR_LOCK_REQUIRED;
}

static __force_inline void __attribute__((noreturn)) sudden_death(void) {
#ifndef __riscv
    pico_default_asm_volatile(
            ".cpu cortex-m33\n"
            "cdp p7, #0, c0, c0, c0, #1\n" // rcp_panic
            ".cpu cortex-m23\n"
            "b.w native_dead\n"
    );
#else
    native_dead();
#endif
    __builtin_unreachable();
}

#endif // __ASSEMBLER__
