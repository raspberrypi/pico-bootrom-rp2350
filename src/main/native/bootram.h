/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "bootrom.h"
#include "hardware/regs/bootram.h"

#define BOOTRAM_PREBOOT_OFFSET 0
#define BOOTRAM_PREBOOT_OFFSET_HX_NSBOOT_FLAG (0x210 + HACK_STACK_WORDS * 4)

// Needed in ASM:
#define BOOTRAM_ALWAYS_OFFSET (BOOTRAM_SIZE - BOOTRAM_ALWAYS_SIZE)
#define BOOTRAM_ALWAYS_SECURE_OFFSET (BOOTRAM_ALWAYS_OFFSET + 40)
#define BOOTRAM_ALWAYS_CALLBACKS_OFFSET (BOOTRAM_ALWAYS_SECURE_OFFSET + 4)
#define BOOTRAM_NS_API_PERMISSIONS_OFFSET (BOOTRAM_SIZE - 16)
#define BOOTRAM_RUNTIME_CORE1_VARMULET_ENCLOSING_CPU_OFFSET (BOOTRAM_SIZE - BOOTRAM_ALWAYS_SIZE - 4)
#define BOOTRAM_RUNTIME_CORE0_VARMULET_ENCLOSING_CPU_OFFSET (BOOTRAM_RUNTIME_CORE1_VARMULET_ENCLOSING_CPU_OFFSET - BOOTRAM_RUNTIME_PER_CORE_SIZE)
#define BOOTRAM_RUNTIME_CORE1_VARMULET_USER_STACK_SIZE_OFFSET (BOOTRAM_SIZE - BOOTRAM_ALWAYS_SIZE - 8)
#define BOOTRAM_RUNTIME_CORE0_VARMULET_USER_STACK_SIZE_OFFSET (BOOTRAM_RUNTIME_CORE1_VARMULET_USER_STACK_SIZE_OFFSET - BOOTRAM_RUNTIME_PER_CORE_SIZE)
#define BOOTRAM_ALWAYS_PARTITION_TABLE_OFFSET (BOOTRAM_NS_API_PERMISSIONS_OFFSET - 144)
#define BOOTRAM_ALWAYS_FLASH_DEVINFO_OFFSET (BOOTRAM_ALWAYS_CALLBACKS_OFFSET - 24)
#define BOOTRAM_ALWAYS_BOOT_DIAGNOSTIC_OFFSET (BOOTRAM_ALWAYS_CALLBACKS_OFFSET + 8)
#define BOOTRAM_PREBOOT_WORKAREA_SIZE 4
#ifndef __ASSEMBLER__
#include "nsboot_config.h" // for chip_id_t
#include "hardware/structs/bootram.h"

static inline bool get_boot_once_bit(uint index) {
    bootrom_assert(MISC, index < 64);
    return bootram_hw->write_once[index/32] & 1u << index;
}

static inline void set_boot_once_bit(uint index) {
    bootram_hw->write_once[index/32] = 1u << index;
}

#define BOOTRAM_RUNTIME_PER_CORE_WORDS (BOOTRAM_RUNTIME_PER_CORE_SIZE/4)
#define BOOTRAM_RUNTIME_XIP_SETUP_CODE_WORDS (256 - BOOTRAM_ALWAYS_SIZE / 4 - BOOTRAM_RUNTIME_PER_CORE_WORDS * 2)
static_assert(BOOTRAM_RUNTIME_XIP_SETUP_CODE_WORDS == 64, "");

typedef struct {
    union {
        struct {
            uint8_t partition_count;
            uint8_t permission_partition_count; // >= partition_count and includes any regions added at runtime
            bool loaded;
        };
        uint32_t counts_and_load_flag;
    };
    uint32_t unpartitioned_space_permissions_and_flags;
    resident_partition_t partitions[PARTITION_TABLE_MAX_PARTITIONS];
    // -- below here is nominally private
    uint32_t secure_item_address;
    uint32_t hash[PARTITION_TABLE_SHA256_HASH_WORDS];
} resident_partition_table_t;

typedef struct {
    union {
        struct {
            uint16_t row;
            union {
                struct {
                    uint8_t bit;
                    uint8_t reboot;
                };
                uint16_t hbit;
            };
        };
        uint32_t word;
    };
} otp_row_and_bit_t;

typedef struct bootram {
    union {
        // Early in boot path for core 0:
        struct {
            // note both stacks bottom out at the beginning of bootram, so stack overflow will fault
            union {
                // only used when rebooting into image, before the stack can extend this far
                struct {
                    uint8_t varmulet_cpu_state[VARMULET_CPU_STATE_SIZE];
                    uint32_t flash_update_boot_window_base;
                    uint32_t vector_workarea_end; // unused marker field
                };
                uint32_t arm_secure_stack[BOOTRAM_PREBOOT_STACK_SIZE/4];
                uint32_t riscv_varmulet_stack[BOOTRAM_PREBOOT_STACK_SIZE/4];
            };
            hx_bool boot_to_ram_image;
            hx_bool enter_nsboot;
            union {
                uint32_t core1[BOOTRAM_RUNTIME_PER_CORE_WORDS-HACK_STACK_WORDS]; // leave the core1 space alone in case debugger is using it
//                secure_erase_list_t secure_erase; // but use it for secure erase (note core 1 is forced into reset during secure boot verification)
            };
        } pre_boot;
        // When in USB boot:
        struct {
            // note both stacks bottom out at the beginning of bootram, so stack overflow will fault
            union {
                struct {
                    uint32_t secure_stack[BOOTRAM_RUNTIME_XIP_SETUP_CODE_WORDS + BOOTRAM_RUNTIME_PER_CORE_WORDS * 2 - BOOTRAM_ARM_STATIC_DATA_SIZE / 4];
                    // the .allowed_static_data state goes here
                    uint32_t static_data_shadow[BOOTRAM_ARM_STATIC_DATA_SIZE / 4];
                } arm;
                struct {
                    uint32_t varmulet_stack[BOOTRAM_RUNTIME_XIP_SETUP_CODE_WORDS + BOOTRAM_RUNTIME_PER_CORE_WORDS * 2 - BOOTRAM_RISCV_STATIC_DATA_SIZE / 4];
                    // the .allowed_bss state goes here
                    uint8_t static_data_shadow[BOOTRAM_RISCV_STATIC_DATA_SIZE];
                } riscv;
            };
        } nsboot;
        // In regular mode (note we currently expect this to be here at the start):
        struct {
            uint32_t xip_setup_code[BOOTRAM_RUNTIME_XIP_SETUP_CODE_WORDS];
            union {
                struct {
                } arm;
                struct {
                    uint32_t varmulet_stack[BOOTRAM_RUNTIME_PER_CORE_WORDS - 3];
                    union {
                        struct {
                            // note ordering here is important as we access via the pair below also
                            uint32_t varmulet_user_stack_base;
                            uint32_t varmulet_user_stack_size;
                        };
                        uint32_pair_t varmulet_user_stack_pair;
                    };
                    struct armulet_cpu *varmulet_enclosing_cpu;
                } riscv;
            } core[NUM_CORES];
            // beware then end of runtime is also the stack used when calling into boot stage2
        } runtime;
    };
    // common stuff goes at end, so we don't ever write over with stacks
    struct {
        union {
            struct
            {
                uint32_quad_t boot_random;
#if FEATURE_EXEC2
                // there is no longer room for this
                uint64_t nonce;
#endif
            };
#if FEATURE_EXEC2
            uint32_sext_t six_words;
#endif
        };
        struct {
            // note only valid if low 11 bits are zero (i.e. it is an actual flash sector)
            uint32_t version_downgrade_erase_flash_addr;
            uint16_t flash_devinfo;
            uint8_t allow_core0_autovarm;
            uint8_t _pad;
            uint32_pair_t reboot_params;
            uint32_t tbyb_flag_flash_addr;
            otp_row_and_bit_t pending_rollback_version_otp_info;
        } zero_init;
        volatile hx_xbool secure;
        bootrom_api_callback_generic_t callbacks[BOOTROM_API_CALLBACK_COUNT];
        union {
            struct {
                union {
                    struct __packed {
                        int8_t diagnostic_partition_index; // used BOOT_PARTITION constants
                        uint8_t boot_type;
                        union {
                            struct __packed {
                                int8_t partition;
                                uint8_t tbyb_and_update_info;
                            } ;
                            uint16_t hword;
                        } recent_boot;
                    };
                    uint32_t boot_word;
                };
                uint32_t boot_diagnostic;
            };
            uint64_t boot_type_and_diagnostics;
        };

        // API permissions
        // at the end to make loading it easier easy (don't need to check for running off end)
        resident_partition_table_t partition_table;
        uint8_t ns_api_permissions[(BOOTROM_NS_API_COUNT+3) & ~3]; // round up so we can clear efficiently
        chip_id_t chip_id;
    } always;
} bootram_t;

#define bootram ((bootram_t * const) BOOTRAM_BASE)
static_assert(BOOTRAM_ARM_STATIC_DATA_START == (uintptr_t)&bootram->nsboot.arm.static_data_shadow[0], "");
static_assert(BOOTRAM_RISCV_STATIC_DATA_START == (uintptr_t)&bootram->nsboot.riscv.static_data_shadow[0], "");
static_assert(offsetof(bootram_t, runtime.xip_setup_code) == BOOTRAM_XIP_SETUP_CODE_OFFSET, "");
static_assert(sizeof(((bootram_t*)0)->nsboot.riscv.varmulet_stack) > 512, ""); // seems like a reasonable minimum
static_assert(offsetof(bootram_t, pre_boot) == BOOTRAM_PREBOOT_OFFSET, "");
static_assert(sizeof(bootram_t) == BOOTRAM_SIZE, "");
// make sure the stages don't have gaps
static_assert(offsetof(bootram_t, nsboot.arm) + sizeof(((bootram_t*)0)->nsboot.arm) == offsetof(bootram_t, always), "");
static_assert(offsetof(bootram_t, pre_boot) + sizeof(((bootram_t*)0)->pre_boot) == offsetof(bootram_t, always), "");
static_assert(offsetof(bootram_t, always) == BOOTRAM_SIZE - BOOTRAM_ALWAYS_SIZE, "");
static_assert(sizeof(((bootram_t*)0)->pre_boot.arm_secure_stack) == BOOTRAM_PREBOOT_STACK_SIZE, "");
// make sure the secure_stack butts up against the beginning
static_assert(offsetof(bootram_t, pre_boot.arm_secure_stack) == 0, "");
static_assert(offsetof(bootram_t, pre_boot.vector_workarea_end) == VARMULET_CPU_STATE_SIZE + BOOTRAM_PREBOOT_WORKAREA_SIZE, "");
static_assert(offsetof(bootram_t, pre_boot.varmulet_cpu_state) == 0, "");
static_assert(offsetof(bootram_t, pre_boot.enter_nsboot) == BOOTRAM_PREBOOT_OFFSET_HX_NSBOOT_FLAG, "");
static_assert(offsetof(bootram_t, runtime.core[0]) == BOOTRAM_RUNTIME_CORE0_OFFSET, "");
static_assert(offsetof(bootram_t, runtime.core[1]) == BOOTRAM_RUNTIME_CORE1_OFFSET, "");
static_assert(offsetof(bootram_t, runtime.core[0].riscv.varmulet_enclosing_cpu) == BOOTRAM_RUNTIME_CORE0_VARMULET_ENCLOSING_CPU_OFFSET, "");
static_assert(offsetof(bootram_t, runtime.core[1].riscv.varmulet_enclosing_cpu) == BOOTRAM_RUNTIME_CORE1_VARMULET_ENCLOSING_CPU_OFFSET, "");
static_assert(offsetof(bootram_t, runtime.core[0].riscv.varmulet_user_stack_size) == BOOTRAM_RUNTIME_CORE0_VARMULET_USER_STACK_SIZE_OFFSET, "");
static_assert(offsetof(bootram_t, runtime.core[1].riscv.varmulet_user_stack_size) == BOOTRAM_RUNTIME_CORE1_VARMULET_USER_STACK_SIZE_OFFSET, "");
static_assert(sizeof(((bootram_t*)0)->runtime.core[0]) == BOOTRAM_RUNTIME_PER_CORE_SIZE, "");
static_assert(offsetof(bootram_t, always) == BOOTRAM_RUNTIME_CORE1_OFFSET + BOOTRAM_RUNTIME_PER_CORE_SIZE, "");
static_assert(offsetof(bootram_t, always) == BOOTRAM_ALWAYS_OFFSET, "");
static_assert(offsetof(bootram_t, always.callbacks[0]) == BOOTRAM_ALWAYS_CALLBACKS_OFFSET, "");
static_assert(offsetof(bootram_t, always.ns_api_permissions) == BOOTRAM_NS_API_PERMISSIONS_OFFSET, "");
static_assert(offsetof(bootram_t, always.partition_table) == BOOTRAM_ALWAYS_PARTITION_TABLE_OFFSET, "");
static_assert(offsetof(bootram_t, always.zero_init.flash_devinfo) == BOOTRAM_ALWAYS_FLASH_DEVINFO_OFFSET, "");
static_assert(offsetof(bootram_t, always.boot_diagnostic) == BOOTRAM_ALWAYS_BOOT_DIAGNOSTIC_OFFSET, "");
static_assert(offsetof(bootram_t, always.secure) == BOOTRAM_ALWAYS_SECURE_OFFSET, "");
#endif
