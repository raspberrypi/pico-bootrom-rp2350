/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bootrom.h"
#include "bootram.h"
#include "pico/bootrom_constants.h"

.cpu cortex-m33
.thumb
.section .secure_gateways.first, "ax"
.syntax unified

// returns a 32 bit value (note all args must be in registers)
.macro sg_uint32_func name
.global sg_\name
sg_\name:
    sg
#if !FEATURE_CANARIES
    push {r1, lr} // save r1 for stack alignment
#else
    rcp_canary_get_nodelay ip, CTAG_SG_CALL
    push {ip, lr}
#endif
    adr lr, return_to_ns_preserve_r0 + 1
    b.w s_from_ns_\name
.endm

.set num_of_sg_table_funcs, 0
.macro sg_table_func name idx prefix
    // The order is important here because the entry PC is used to get the
    // table index
    .if num_of_sg_table_funcs != \idx
        .error "Wrong SG table func order, compare the bootrom_constants.h BOOTROM_NS_API constants to the asm table"
    .endif

    // Insert function table entry
    .section .rodata.keep, "a"
    .if num_of_sg_table_funcs == 0
        .global sg_api_table
        sg_api_table:
    .endif
    sg_functable_\name:
#if BOOTROM_32BIT_FUNC_POINTERS
    .word s_from_ns_\prefix\()_api_\name + 1
#else
    .hword s_from_ns_\prefix\()_api_\name + 1
#endif
    .if num_of_sg_table_funcs == BOOTROM_NS_API_COUNT - 1
        .global sg_api_table_end
        sg_api_table_end:
    .endif

    // Insert gateway with same index
    .section .secure_gateways.first, "ax"
    // 8 bytes per gateway: 32-bit SG, 16-bit mov, 16-bit branch. Note the mov
    // points ip at the *next slot*, not the one we entered.
    .if num_of_sg_table_funcs == 0
        .p2align 2
    .endif
    .global sg_api_\name
    sg_api_\name:
    .if num_of_sg_table_funcs == 1
        .global sg_second_table_entry_point
        sg_second_table_entry_point:
    .endif
        sg
        mov ip, pc
        b.n sg_table_entry_longbranch

    .set num_of_sg_table_funcs, num_of_sg_table_funcs + 1
.endm

// catch all entry point for nsboot - it is permanently disabled (until bootram
// reset, which implies proc reset) if nsboot path is not taken
sg_uint32_func nsboot_service_call

// The BOOTROM_NS_API_xxx numbers here are defined in bootrom_constants.h
#define SG_TABLE_FUNC(name, prefix) sg_table_func name BOOTROM_NS_API_ ## name prefix

// The order here must match the SG_API_xxx numbers defined in bootrom.h
// (and we check this and .error on mismatch)
// NOTE: these functions must all return a value, or secure r0 is exposed
SG_TABLE_FUNC(get_sys_info, varm)
SG_TABLE_FUNC(checked_flash_op, arm8)
SG_TABLE_FUNC(flash_runtime_to_storage_addr, arm8)
SG_TABLE_FUNC(get_partition_table_info, varm)
SG_TABLE_FUNC(secure_call, arm8)
SG_TABLE_FUNC(otp_access, varm)
SG_TABLE_FUNC(reboot, varm)
SG_TABLE_FUNC(get_b_partition, varm)

sg_table_entry_longbranch:
    // b.w sg_table_entry
    // fall-through:

// ip has table index
.global sg_table_entry
sg_table_entry:
#if FEATURE_CANARIES
    rcp_count_set_nodelay STEPTAG_SG_CALL
#endif
    push {r1, lr} // save r1 for stack alignment (and for canary space)
    // The tabled SGs are 8 bytes apart, in SG_API index order, so we can
    // calculate the API index from the PC which was stashed in IP. Note the
    // captured PC actually points at slot + 1 (because reading PC does not
    // point to the current instruction on Arm) so we take the difference
    // starting at the *second* slot to cancel out the off-by-one.
    adr lr, sg_second_table_entry_point
    subs ip, lr
#if FEATURE_CANARIES
    rcp_canary_get_nodelay lr, CTAG_SG_CALL
    str lr, [sp, #0]
#endif
    lsrs ip, #3
    cmp ip, #BOOTROM_NS_API_COUNT
    bhs 1f // bhs is unsigned-greater-or-equal

    // permission check
    ldr lr, =BOOTRAM_BASE + BOOTRAM_NS_API_PERMISSIONS_OFFSET
    ldrb lr, [lr, ip]
    orrs lr, lr, lr, lsl #16
    // lr = true ? 0xa500a5 : 0xc300c3
    tst lr, #2
    bne 2f
    lsls lr, lr, #8
    // lr is 0xa500a500 if permission was 0xa5
    rcp_btrue_nodelay lr

    ldr lr, =P16(sg_api_table)
#if BOOTROM_HARDENING
    cmp ip, #BOOTROM_NS_API_COUNT
    bhs 1f // bhs is unsigned-greater-or-equal
#endif
#if BOOTROM_32BIT_FUNC_POINTERS
    ldr ip, [lr, ip, lsl #2]
#else
    ldrh ip, [lr, ip, lsl #1]
#endif
    adr  lr, return_to_ns_preserve_r0 + 1
#if FEATURE_CANARIES
    rcp_count_check_nodelay STEPTAG_SG_CALL
#endif
    bx   ip
1:
    movs r0, #-BOOTROM_ERROR_INVALID_ARG
    b 3f
2:
    movs r0, #-BOOTROM_ERROR_NOT_PERMITTED
3:
    negs r0, r0
    // fall thru since clear4 no longer used
            // b    return_to_ns_preserve_r0
            //clear4:
            //    mov r0, r4
.global return_to_ns_preserve_r0
.thumb_func
return_to_ns_preserve_r0:
    // we clear the non-callee saved regs on exit from secure code (other than r0 which is the return code)
    pop {r1, lr}
    mov r2, lr
    mov r3, lr
    mov ip, lr
    msr APSR_nzcvqg, lr
#if FEATURE_CANARIES
    rcp_canary_check_nodelay r1, CTAG_SG_CALL
    mov r1, lr
#endif
    bxns lr

// Assert that the bootrom.h constant matches the number of table entries, as
// it's used for bounds checking in arm8_bootrom_rt0.S
.if num_of_sg_table_funcs != BOOTROM_NS_API_COUNT
.error "Number of SG table funcs does not match BOOTROM_NS_API_COUNT from bootrom_constants.h"
.endif
