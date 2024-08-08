/**
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pico.h"

.section .text.crc, "ax"

// ----------------------------------------------------------------------------
// memcpy

// Note we expose native_memcpy and native_memset as memcpy and memset on
// RISC-V as the compiler seems to use them

// Replace the C function in riscv_nsboot_vm.c
#if !MINI_PRINTF
.global native_nsboot_init
native_nsboot_init:
    mv a1, a0
    la a0, armv6m_pointers // should be gp-relative
    li a2, 12
    // fall through
#endif

#if FANCY_MEMCPY
#error "No fancy memcpy available"
// (removed as not well-tested and we're unlikely to have room for it)
#elif TINY_MEMCPY

.p2align 2
.global __memcpy_44
__memcpy_44:
.global native_memcpy, memcpy
native_memcpy:
memcpy:
    add a2, a2, a1
    mv a3, a0
    j 2f
1:
    lbu a5, (a3)
    sb a5, (a1)
    addi a3, a3, 1
    addi a1, a1, 1
2:
    bltu a1, a2, 1b
    ret

#else // Balanced memcpy (default)


// This is meant to be fairly small but still transfer a word at a time for
// the case where both buffers are word-aligned. __memcpy_44 is merged as it
// would only save 4 cycles, and adding a second entry point which skips the
// alignment check is not free, due to requirement to save a0 for return value
.global native_memcpy, __memcpy_44, memcpy
native_memcpy:
__memcpy_44:
memcpy:
    mv a3, a0
    add a2, a2, a3
    or a4, a1, a3
    andi a4, a4, 0x3
    bnez a4, 5f

    addi a2, a2, -3
    bgeu a3, a2, 3f

    // Word loop
1:
    lw a4, (a1)
    sw a4, (a3)
    addi a1, a1, 4
    addi a3, a3, 4
2:
    bltu a3, a2, 1b
3:
    addi a2, a2, 3
    bgeu a3, a2, 6f

    // Byte loop
4:
    lbu a4, (a1)
    sb  a4, (a3)
    addi a1, a1, 1
    addi a3, a3, 1
5:
    bltu a3, a2, 4b
6:
    ret

#endif

// ----------------------------------------------------------------------------
// memset

.global native_memset0, varm_to_native_memset0
varm_to_native_memset0: // we do this as the riscv_subset of USB boot uses this
native_memset0:
    mv a2, a1
    li a1, 0
    // fall-thru

#if FANCY_MEMSET
#error "No fancy memset available"
#elif TINY_MEMSET
#error "usb_device.c usb_device_start requires aligned word clears"
.global native_memset, memset
native_memset:
memset:
.global __memset_4
__memset_4:
    add a2, a2, a0
    mv a3, a0
    j 2f
1:
    sb a1, (a3)
    addi a3, a3, 1
2:
    bltu a3, a2, 1b
    ret

#else // Balanced memset (default)

// __memset 4 is merged because it's not a good trade: saves 3 cycles, but
// makes regular memset 1 cycle slower due to redundant save of a0.

.global native_memset, __memset_4, memset
native_memset:
__memset_4:
memset:
    mv a3, a0
    add a2, a2, a3
    andi a4, a3, 0x3
    bnez a4, 5f

    addi a2, a2, -3
    bgeu a3, a2, 3f
    // Replicate byte x4 for word loop
    packh a1, a1, a1
    pack a1, a1, a1

    // Word loop
1:
    sw a1, (a3)
    addi a3, a3, 4
2:
    bltu a3, a2, 1b
3:
    addi a2, a2, 3
    bgeu a3, a2, 6f

    // Byte loop
4:
    sb  a1, (a3)
    addi a3, a3, 1
5:
    bltu a3, a2, 4b
6:
    ret

#endif

// ----------------------------------------------------------------------------

// void __exported_from_arm *s_native_api_validate_ns_buffer(
//     const void *addr, uint32_t size, hx_bool write, hx_bool *ok);
//
// On RISC-V there is no such thing as S/NS, so this function is stubbed out
// to always return true. We support it as a stub (overloaded for Arm/RISC-V
// via an emulator hint) so that the nsboot-to-Secure shims can be run under
// emulation, avoiding duplicated code which is a waste of size and has been
// a source of bugs.

// Not available usually when __riscv is defined:
#define RCP_MASK_TRUE   0xa500a500u

.global s_native_api_validate_ns_buffer
s_native_api_validate_ns_buffer:
    // This should really be RCP_MASK_TRUE but we only branch on the sign bit.
    // The full bit pattern is only checked by real RCP instructions.
    li a4, -1
    sw a4, (a3)
    // Return the addr that was passed in. This is just a0 -> a0, so nothing to do.
    ret

// This is just the loop part, which is punted to native code for performance
// reasons. a0 contains top of maintenance region, plus maintenance op 0-7,
// minus cache size in bytes.
.global s_native_crit_xip_cache_maintenance
s_native_crit_xip_cache_maintenance:
    lui a1, (XIP_SRAM_END + (XIP_MAINTENANCE_BASE - XIP_BASE)) >> 12
1:
    sb   a0,0(a0)
    addi a0,a0,8
    bltu a0, a1, 1b
    ret
