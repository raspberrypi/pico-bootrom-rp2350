// -----------------------------------------------------------------------------
// ROM Table for RP2350
// Copyright (c) 2023 Raspberry Pi Ltd.
// SPDX-License-Identifier: BSD-3-Clause
// -----------------------------------------------------------------------------
//
// There is a single ROM table, with pointers to both Arm and RISC-V
// implementations of ROM functions. It's built as part of the RISC-V ROM
// build so that it has access to both Arm and RISC-V symbols (the former via
// symbol export from the Arm build). It is placed at the end of the RISC-V
// ROM, so that the Arm ROM can point to its known location without
// additional build steps.
//
// Each ROM table entry has a 2-char symbol, an hword of flags, and some
// content. There is always 1 hword of content for every flag bit set, and
// these hwords appear in the same order as the flag bits (going LSB-first).
// Each 2-char symbol appears at most once in the table.
//
// The flag masks are:
//
//     RT_FLAG_FUNC_RISCV      0x01 (c.j func)
//     RT_FLAG_FUNC_RISCV_FAR  0x03 (j func)
//     RT_FLAG_FUNC_ARM_SEC    0x04 (.hword func_ptr)
//     32-bit version of same: 0x0c (.word func_ptr)
//     RT_FLAG_FUNC_SHARED     0x07 (jal a4, load_a4_goto_varm_wrapper; .hword func_ptr)
//     RT_FLAG_FUNC_ARM_NONSEC 0x10 (.hword func_ptr)
//     32-bit version of same: 0x30 (.word func_ptr)
//     RT_FLAG_DATA            0x40 (.hword data_ptr)
//     RT_FLAG_DATA_HWORD      0x40 (.hword data)
//     RT_FLAG_DATA_WORD       0xc0 (.word data)

#include "bootrom.h"
#include "arm_imports.h"
#include "bootrom_riscv_asm_macros.inc.S"

#if BOOTROM_32BIT_FUNC_POINTERS
// (e.g. for bootrom-in-RAM development builds)

.macro .funcptr p
.word \p
.endm
.macro .dataptr p
.word \p
.endm
#define FLAG_FUNCPTR_ARM_SEC    (RT_FLAG_FUNC_ARM_SEC    | (RT_FLAG_FUNC_ARM_SEC    << 1))
#define FLAG_FUNCPTR_ARM_NONSEC (RT_FLAG_FUNC_ARM_NONSEC | (RT_FLAG_FUNC_ARM_NONSEC << 1))
#define FLAG_DATAPTR            (RT_FLAG_DATA            | (RT_FLAG_DATA            << 1))

#else
// (smaller table size when bootrom is linked at address 0)

.macro .funcptr p
.hword \p
.endm
.macro .dataptr p
.hword \p
.endm
#define FLAG_FUNCPTR_ARM_SEC     RT_FLAG_FUNC_ARM_SEC
#define FLAG_FUNCPTR_ARM_NONSEC  RT_FLAG_FUNC_ARM_NONSEC
#define FLAG_DATAPTR             RT_FLAG_DATA

#endif

// Not defined in public header because it should not be used for lookups:
#define RT_FLAG_FUNC_SHARED (RT_FLAG_FUNC_RISCV_FAR | FLAG_FUNCPTR_ARM_SEC)

// ----------------------------------------------------------------------------
// Formats

#define _RT_ARM_ADDR(x) x
#define RT_ARM_ADDR(x) _RT_ARM_ADDR(__armexport_ ## x ## _addr)

// A function implemented on Arm only, for Secure callers only

#define RT_FUNC_ENTRY_ARM_SEC(code, func) \
    _RT_FUNC_ENTRY_ARM_SEC code, func, RT_ARM_ADDR(func) | 0x1

.macro _RT_FUNC_ENTRY_ARM_SEC code, label, func
.global _rt_entry_\label
_rt_entry_\label:
.hword \code
.hword FLAG_FUNCPTR_ARM_SEC
.funcptr \func
.endm

// A function implemented on Arm only, with both Secure and NonSecure
// entry points (which may be the same address)

#define RT_FUNC_ENTRY_ARM_SEC_NONSEC(code, func_sec, func_nonsec) \
    _RT_FUNC_ENTRY_ARM_SEC_NONSEC code, func_sec, RT_ARM_ADDR(func_sec) | 0x1, RT_ARM_ADDR(func_nonsec) | 0x1

.macro _RT_FUNC_ENTRY_ARM_SEC_NONSEC code, label, func_sec, func_nonsec
.global _rt_entry_\label
_rt_entry_\label:
.hword \code
.hword FLAG_FUNCPTR_ARM_SEC | FLAG_FUNCPTR_ARM_NONSEC
.funcptr \func_sec
.funcptr \func_nonsec
.endm

// A function implemented on Arm only, intended for NonSecure callers only

#define RT_FUNC_ENTRY_ARM_NONSEC(code, func_nonsec) \
    _RT_FUNC_ENTRY_ARM_NONSEC code, func_nonsec, RT_ARM_ADDR(func_nonsec) | 0x1

.macro _RT_FUNC_ENTRY_ARM_NONSEC code, label, func_nonsec
.global _rt_entry_\label
_rt_entry_\label:
.hword \code
.hword FLAG_FUNCPTR_ARM_NONSEC
.funcptr \func_nonsec
.endm

// A native function on RISC-V is stored as a jump instruction embedded in the
// table, and a pointer to the table entry itself is returned. This is a
// workaround for lack of 16-bit data relocations on RISC-V, and also for
// consistency with RT_FLAG_FUNC_SHARED entries.

#if USE_64K_BOOTROM
// Force use of _FAR because we don't do the c.j relocation forcing on bigger bootrom builds
#define RT_FUNC_ENTRY_RISCV(code, func) \
    _RT_FUNC_ENTRY_RISCV_FAR code, func
#else
#define RT_FUNC_ENTRY_RISCV(code, func) \
    _RT_FUNC_ENTRY_RISCV code, func
#endif

.macro _RT_FUNC_ENTRY_RISCV code, func
.global _rt_entry_\func
_rt_entry_\func:
.hword \code
.hword RT_FLAG_FUNC_RISCV
j_force_rvc \func
.endm

// (Due to limited 16-bit jump range we may have to embed a 32-bit jump
// instruction instead. This fits into the same space as the `jal` for shared
// function entries.)

#define RT_FUNC_ENTRY_RISCV_FAR(code, func) \
    _RT_FUNC_ENTRY_RISCV_FAR code, func

.macro _RT_FUNC_ENTRY_RISCV_FAR code, func
.global _rt_entry_\func
_rt_entry_\func:
.hword \code
.hword RT_FLAG_FUNC_RISCV_FAR
// This is a regular uncompressed j instruction -- note .option norvc is
// broken on recent binutils (when Zca is present) and does not yet have a
// working alternative
.insn j 0x6f, zero, \func
.endm

// A function implemented natively on both Arm and RISC-V.

#if USE_64K_BOOTROM
// Force use of _FAR because we don't do the c.j relocation forcing on bigger bootrom builds
#define RT_FUNC_ENTRY_RISCV_AND_ARM_SEC(code, func_riscv, func_arm) \
    _RT_FUNC_ENTRY_RISCV_FAR_AND_ARM_SEC code, func_riscv, RT_ARM_ADDR(func_arm) | 0x1
#else
#define RT_FUNC_ENTRY_RISCV_AND_ARM_SEC(code, func_riscv, func_arm) \
    _RT_FUNC_ENTRY_RISCV_AND_ARM_SEC code, func_riscv, RT_ARM_ADDR(func_arm) | 0x1
#endif

.macro _RT_FUNC_ENTRY_RISCV_AND_ARM_SEC code, func_riscv, func_arm
.global _rt_entry_\func_riscv
_rt_entry_\func_riscv:
.hword \code
.hword RT_FLAG_FUNC_RISCV | FLAG_FUNCPTR_ARM_SEC
j_force_rvc \func_riscv
.funcptr \func_arm
.endm

// (the same, but with more jump range)

#define RT_FUNC_ENTRY_RISCV_FAR_AND_ARM_SEC(code, func_riscv, func_arm) \
    _RT_FUNC_ENTRY_RISCV_FAR_AND_ARM_SEC code, func_riscv, RT_ARM_ADDR(func_arm) | 0x1

.macro _RT_FUNC_ENTRY_RISCV_FAR_AND_ARM_SEC code, func_riscv, func_arm
.global _rt_entry_\func_riscv
_rt_entry_\func_riscv:
.hword \code
.hword RT_FLAG_FUNC_RISCV_FAR | FLAG_FUNCPTR_ARM_SEC
.insn j 0x6f, zero, \func_riscv
.funcptr \func_arm
.endm

// A function callable from either Arm or RISC-V, with one implementation. A
// lookup using the flag RT_FLAG_FUNC_ARM_SEC returns the hword pointer
// value, whereas a lookup using RT_FLAG_FUNC_RISCV returns the address of
// the table entry itself. Jumping into the table entry will invoke varmulet
// on the hword pointer.

#define RT_FUNC_ENTRY_SHARED_SEC(code, func) \
    _RT_FUNC_ENTRY_SHARED_SEC code, func, RT_ARM_ADDR(func) | 0x1

.macro _RT_FUNC_ENTRY_SHARED_SEC code, label, func
.global _rt_entry_\label
_rt_entry_\label:
.hword \code
.hword RT_FLAG_FUNC_SHARED
jal a4, load_a4_goto_varm_wrapper
.funcptr \func
.endm

// A function callable from either Arm or RISC-V, with an additional entry
// point for NonSecure callers on Arm.

#define RT_FUNC_ENTRY_SHARED_SEC_NONSEC(code, func_sec, func_nonsec) \
    _RT_FUNC_ENTRY_SHARED_SEC_NONSEC code, func_sec, \
        RT_ARM_ADDR(func_sec) | 0x1, RT_ARM_ADDR(func_nonsec) | 0x1

.macro _RT_FUNC_ENTRY_SHARED_SEC_NONSEC code, label, func_sec, func_nonsec
.global _rt_entry_\label
_rt_entry_\label:
.hword \code
.hword RT_FLAG_FUNC_SHARED | FLAG_FUNCPTR_ARM_NONSEC
jal a4, load_a4_goto_varm_wrapper
.funcptr \func_sec
.funcptr \func_nonsec
.endm

// Data included in the table -- usually an hword pointer to something
// out-of-table.

#define RT_DATA_ENTRY_PTR(code, data) \
    _RT_DATA_ENTRY_PTR code, data

.macro _RT_DATA_ENTRY_PTR code, data
_rt_entry_data_\@:
.hword \code
.hword FLAG_DATAPTR
.dataptr \data
.endm

#define RT_DATA_ENTRY_HWORD(code, data) \
    _RT_DATA_ENTRY_HWORD code, data

.macro _RT_DATA_ENTRY_HWORD code, data
_rt_entry_data_\@:
.hword \code
.hword RT_FLAG_DATA
.hword \data
.endm

#define RT_DATA_ENTRY_WORD(code, data) \
    _RT_DATA_ENTRY_WORD code, data

.macro _RT_DATA_ENTRY_WORD code, data
_rt_entry_data_\@:
.hword \code
.hword RT_FLAG_DATA_32BIT
.word \data
.endm

// ----------------------------------------------------------------------------
// Contents

.section .romtable, "ax"

.global _rom_table_start, _rom_table_end

.option push
.option norelax

_rom_table_start:
#if 0
// Removed for size and not particularly useful compared to compiler ones which are fast
RT_FUNC_ENTRY_RISCV_FAR_AND_ARM_SEC ( ROM_FUNC_MEMSET,                        native_memset, native_memset                                                   )
RT_FUNC_ENTRY_RISCV_FAR_AND_ARM_SEC ( ROM_FUNC_MEMCPY,                        native_memcpy, native_memcpy                                                   )
#endif

RT_FUNC_ENTRY_RISCV_AND_ARM_SEC     ( ROM_FUNC_BOOTROM_STATE_RESET,           s_native_api_bootrom_state_reset, s_varm_step_safe_api_crit_bootrom_state_reset )
RT_FUNC_ENTRY_SHARED_SEC_NONSEC     ( ROM_FUNC_GET_SYS_INFO,                  s_varm_api_get_sys_info,                  sg_api_get_sys_info                  )
RT_FUNC_ENTRY_ARM_NONSEC            ( ROM_FUNC_SECURE_CALL,                   sg_api_secure_call                                                             )

RT_FUNC_ENTRY_SHARED_SEC            ( ROM_FUNC_LOAD_PARTITION_TABLE,          s_varm_api_load_partition_table                                                )
RT_FUNC_ENTRY_SHARED_SEC_NONSEC     ( ROM_FUNC_GET_PARTITION_TABLE_INFO,      s_varm_api_get_partition_table_info,      sg_api_get_partition_table_info      )
RT_FUNC_ENTRY_SHARED_SEC_NONSEC     ( ROM_FUNC_GET_B_PARTITION,               s_varm_api_crit_get_b_partition,          sg_api_get_b_partition               )
RT_FUNC_ENTRY_SHARED_SEC_NONSEC     ( ROM_FUNC_FLASH_RUNTIME_TO_STORAGE_ADDR, s_varm_api_flash_runtime_to_storage_addr, sg_api_flash_runtime_to_storage_addr )
RT_FUNC_ENTRY_SHARED_SEC_NONSEC     ( ROM_FUNC_REBOOT,                        s_varm_api_reboot,                        sg_api_reboot                        )

RT_FUNC_ENTRY_SHARED_SEC_NONSEC     ( ROM_FUNC_OTP_ACCESS,                    s_varm_api_otp_access,                    sg_api_otp_access                    )
RT_FUNC_ENTRY_SHARED_SEC            ( ROM_FUNC_CONNECT_INTERNAL_FLASH,        s_varm_api_crit_connect_internal_flash                                         )
RT_FUNC_ENTRY_SHARED_SEC            ( ROM_FUNC_FLASH_RESET_ADDRESS_TRANS,     s_varm_api_crit_flash_reset_address_trans                                      )
RT_FUNC_ENTRY_SHARED_SEC            ( ROM_FUNC_FLASH_EXIT_XIP,                s_varm_api_crit_flash_exit_xip                                                 )
RT_FUNC_ENTRY_SHARED_SEC            ( ROM_FUNC_FLASH_RANGE_ERASE,             s_varm_api_flash_range_erase                                                   )
RT_FUNC_ENTRY_SHARED_SEC            ( ROM_FUNC_FLASH_RANGE_PROGRAM,           s_varm_api_flash_range_program                                                 )
RT_FUNC_ENTRY_SHARED_SEC            ( ROM_FUNC_FLASH_FLUSH_CACHE,             s_varm_api_crit_flash_flush_cache_impl                                         )
RT_FUNC_ENTRY_SHARED_SEC            ( ROM_FUNC_FLASH_ENTER_CMD_XIP,           s_varm_api_flash_enter_cmd_xip                                                 )
RT_FUNC_ENTRY_SHARED_SEC            ( ROM_FUNC_FLASH_SELECT_XIP_READ_MODE,    s_varm_api_crit_flash_select_xip_read_mode                                     )
RT_FUNC_ENTRY_SHARED_SEC_NONSEC     ( ROM_FUNC_FLASH_OP,                      s_varm_api_checked_flash_op,              sg_api_checked_flash_op              )

RT_FUNC_ENTRY_SHARED_SEC            ( ROM_FUNC_SET_ROM_CALLBACK,              s_varm_api_set_rom_callback                                                    )
RT_FUNC_ENTRY_ARM_SEC               ( ROM_FUNC_VALIDATE_NS_BUFFER,            s_native_api_validate_ns_buffer                                                )
RT_FUNC_ENTRY_ARM_SEC               ( ROM_FUNC_SET_NS_API_PERMISSION,         s_varm_api_set_ns_api_permission                                               )

RT_FUNC_ENTRY_SHARED_SEC            ( ROM_FUNC_PICK_AB_PARTITION,             s_varm_api_pick_ab_partition                                                   )
RT_FUNC_ENTRY_SHARED_SEC            ( ROM_FUNC_EXPLICIT_BUY,                  s_varm_api_explicit_buy                                                        )
RT_FUNC_ENTRY_SHARED_SEC            ( ROM_FUNC_CHAIN_IMAGE,                   s_varm_api_chain_image                                                         )
RT_FUNC_ENTRY_SHARED_SEC            ( ROM_FUNC_GET_UF2_TARGET_PARTITION,      s_varm_api_get_uf2_target_partition                                            )

RT_FUNC_ENTRY_RISCV                 ( ROM_FUNC_SET_BOOTROM_STACK,             s_native_set_varmulet_user_stack                                               )

RT_DATA_ENTRY_PTR                   ( ROM_DATA_SOFTWARE_GIT_REVISION,         RT_ARM_ADDR(software_git_revision)                                             )
RT_DATA_ENTRY_PTR                   ( ROM_DATA_PARTITION_TABLE_PTR,           RT_ARM_ADDR(partition_table_ptr)                                               )
RT_DATA_ENTRY_PTR                   ( ROM_DATA_SAVED_XIP_SETUP_FUNC_PTR,      RT_ARM_ADDR(xip_setup_func_ptr)                                                )
RT_DATA_ENTRY_PTR                   ( ROM_DATA_FLASH_DEVINFO16_PTR,           RT_ARM_ADDR(flash_devinfo16_ptr)                                               )
_rom_table_end:
.hword 0

.option pop

// ----------------------------------------------------------------------------
// Helpers

// Separate section so we can get the fine tweezers out and make it fall
// through into varm_wrapper via linker script hack. The jumps to this
// address are all 4-byte jals already due to nondefault link register.
.section .text.load_a4_goto_varm_wrapper, "ax"
.global load_a4_goto_varm_wrapper
load_a4_goto_varm_wrapper:
#if BOOTROM_32BIT_FUNC_POINTERS
    lhu a5, 2(a4)
#endif
    lhu a4, (a4)
#if BOOTROM_32BIT_FUNC_POINTERS
    pack a4, a4, a5
#endif
    // implemented via linker script fallthrough:
    // j varm_wrapper
