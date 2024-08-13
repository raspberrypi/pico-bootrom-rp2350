/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#define HINT_OPCODE_BASE            0xbf00

// The first _n_ of these just run some local RISC-V code, extending the emulator
#define HINT_WFE                     2
#define HINT_WFI                     3
#define HINT_SEV                     4

#define HINT_RELOCATE_VARM_REGISTERS 5
#define HINT_MULTIPLEX               6 // this does decode then continues into a native call
#define HINT_INVALIDATE_NATIVE_SP    7 // this just sets RISCV-V sp to INVALID_STACK_PTR
#define HINT_TRNG_SHOVELLING         8 // hot code fragment from boot path
// Special case: replacing an Arm implementation with a different Arm
// implementation under RISC-V:
#define HINT_s_native_step_safe_hx_get_boot_flag_impl                   9

// Beyond this point, we are performing a call from an Arm fn entry into a
// native RISC-V fn, so need marshalling of args and return value
#define HINT_FIRST_TO_REQUIRE_MARSHALLING 10

#define HINT_s_native_crit_flash_put_get                                10
#define HINT_s_native_busy_wait_at_least_cycles                         11
#define HINT_s_native_crit_init_default_xip_setup_and_enter_image_thunk 12
#define HINT_s_native_api_validate_ns_buffer                            13
#define HINT_native_memcpy                                              14
#define HINT_native_memset                                              15
// these could have been regular hints above, but we have run out, so these
// are passed in r3 to HINT_MULTIPLEX (therefore max of 3 args):
#define MULTIPLEX_native_nsboot_init                  0x0
#define MULTIPLEX_native_usb_irq_enable               0x1
#define MULTIPLEX_native_usb_packet_done              0x2
#define MULTIPLEX_s_native_crit_xip_cache_maintenance 0x3
#define MULTIPLEX_s_native_secure_call_pc_sp          0x4
#define MULTIPLEX_s_native_crit_launch_nsboot         0x5
#define NUM_MULTIPLEX 6

#ifdef __ASSEMBLER__
.macro varm_hint num
.hword HINT_OPCODE_BASE + \num * 16
.endm

#define RISCV_REDIRECT_HINT(func) varm_hint HINT_##func

.macro VARM_TO_PREAMBLE_raw func, num
.section .text.varm_to_\()\func
.global varm_to_\()\func
.thumb_func
varm_to_\()\func:
varm_hint \num
.p2align 2
    // fall thru to impl
.endm

#define VARM_TO_PREAMBLE(func) VARM_TO_PREAMBLE_raw func, HINT_##func

.macro VARM_TO_MULTIPLEX_PREAMBLE_raw func, num
.section .text.varm_to_\()\func
.global varm_to_\()\func
.thumb_func
varm_to_\()\func:
movs r3, #\num
varm_hint HINT_MULTIPLEX
.p2align 2
    // fall thru to impl
.endm

#define VARM_TO_MULTIPLEX_PREAMBLE(func) VARM_TO_MULTIPLEX_PREAMBLE_raw func, MULTIPLEX_##func

#endif // __ASSEMBLER__
