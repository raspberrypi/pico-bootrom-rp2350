/**
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bootrom.h"
#include "bootram.h"
#include "boot/picoboot_constants.h"
#include "hardware/regs/otp_data.h"
#include "hardware/regs/m33.h"
#include "hardware/regs/otp.h"
#include "hardening.h"
#include "varm_to_riscv_hints.h"

.cpu cortex-m23
// note using near (.n) for branches as GCC still seems to do things like bcs.w for m23!
.thumb
.syntax unified

.section .text.s_from_nsboot_varm_reboot, "ax"

fail_reboot:
    movs r0, #-BOOTROM_ERROR_NOT_PERMITTED
    negs r0, r0
reboot_return:
#if FEATURE_CANARIES
.cpu cortex-m33
    ldr r1, [sp, #4]
    rcp_canary_check_nodelay r1, CTAG_S_FROM_NS_VARM_API_REBOOT_ENTRY
.cpu cortex-m23
#endif
    // hardening: done
    pop {r1, r2, r4, pc}

// this is in assembly, as it passes an arg in r4
.global s_from_nsboot_varm_reboot
s_from_nsboot_varm_reboot:
    mov r3, r4
.global s_from_ns_varm_api_reboot
s_from_ns_varm_api_reboot:
    // this innocuous line of code does a myriad of things:
    //
    // 1. copy r0 to be the 5th argument to s_varm_hx_reboot
    // 2. don't care about saving r1, but we need space for the canary
    // 3. r4 is for stack alignment
    // 4. lr this one we'll return to later
    push {r0, r1, r4, lr}

#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_canary_get_nodelay r4, CTAG_S_FROM_NS_VARM_API_REBOOT_ENTRY
.cpu cortex-m23
    str r4, [sp, #4]
#endif
    // Redundant args are passed in r0/*sp, and we want them to mismatch when
    // bit 3 is set (set for all Secure-only reboot types).

    // first check that bit 3 isn't set (since that shouldn't be calling from NS)
    lsls r4, r0, #29
    bcs fail_reboot

    // now, try quite hard to clear bit 3 in r0, so that if bit3 were set in our
    // now-stacked 5th argument to s_varm_hx_reboot, the value in r0 won't match
    // and we'll get an rcp_ violation in the callee

    // 1. put r0 back together without bit 3
    lsrs r4, r4, #29
    lsrs r0, r0, #4
    lsls r0, r0, #4
    orrs r0, r4
    // 2. clear bit 3
    movs r4, #8
    bics r0, r4
    bl s_varm_hx_reboot
    b reboot_return

.global s_varm_api_reboot
.thumb_func
s_varm_api_reboot:
    push {r0, lr} // r0 is arg 4 to s_varm_hx_reboot
    bl s_varm_hx_reboot
    pop {r1, pc} // discard stacked value into r1
.p2align 2 // because we should flow into s_varm_hx_reboot which is word aligned (this will insert nop if we're not)
.global s_varm_api_reboot_end
s_varm_api_reboot_end:

#if BOOTROM_HARDENING
.section .text.s_varm_step_safe_hx_get_boot_flagx_impl
.global s_varm_step_safe_hx_get_boot_flagx_impl
.thumb_func
s_varm_step_safe_hx_get_boot_flagx_impl:
    // on RISC-V there is no need to do the XOR as we only look at the top bit, and by convention
    // our XOR patterns do not modify the top bit (so we can continue to use that to determine true/false)
    //
    // therefore immediately redirect into our existing special (lower security) implementation for RISC-V
    varm_hint HINT_s_native_step_safe_hx_get_boot_flag_impl
    push {r0, r2, lr}
.cpu cortex-m33
    rcp_canary_get r1, STEPTAG_S_VARM_STEP_SAFE_HX_GET_BOOT_FLAGX_IMPL
.cpu cortex-m23
    // r1 is preserved by this call
    bl varm_to_s_native_step_safe_hx_get_boot_flag_impl
    pop {r2}
    eors r0, r2
.cpu cortex-m33
    rcp_canary_check r1, STEPTAG_S_VARM_STEP_SAFE_HX_GET_BOOT_FLAGX_IMPL
.cpu cortex-m23
    // we trash r0, r1 only
    pop {r2, pc}

// s_native_step_safe_hx_get_boot_flag_impl is quite slow under varmulet, for little benefit;
// this a simplified version for use on RISC-V which is cheaper in code
// than reimplementing s_varm_step_safe_otp_read_rbit3_guarded in assembly
.pushsection .rodata.keep, "a"
// hardening: this is moved to a non-executable section as it is only executed
// under RISC-V, so it is unhardened.
.global s_varm_riscv_hx_get_boot_flag_impl
.thumb_func
s_varm_riscv_hx_get_boot_flag_impl:
    push {r0-r3, lr}
    movs r0, #OTP_DATA_BOOT_FLAGS0_ROW
    bl s_varm_step_safe_otp_read_rbit3_guarded
    pop {r1}
    // setting the top bit correctly 1 for a500a500 or 0 for 00c300c3 is good
    // enough for everything RISC-V cares about (namely is_true/false checks)
    // -- note relying on mod 32 behaviour of rors.
    rors r0, r1
    pop {r1-r3, pc}
.popsection

// hardened boot flag getting
// note r0 is input parameter (the bit index + 1) - but with bits 0-2 negated in bits 5-7
// flag is returned in r0, so can't the function
// we aim to return true rather than false if we don't crash

.global varm_to_s_native_step_safe_hx_get_boot_flag_impl
.thumb_func
varm_to_s_native_step_safe_hx_get_boot_flag_impl:
    varm_hint HINT_s_native_step_safe_hx_get_boot_flag_impl
s_native_step_safe_hx_get_boot_flag_impl:
    push {r0-r5, lr}
.cpu cortex-m33
    rcp_canary_get r5, CTAG_S_VARM_STEP_SAFE_HX2_GET_BOOT_FLAG_IMPL
.cpu cortex-m23
    movs r0, #OTP_DATA_BOOT_FLAGS0_ROW
    bl s_varm_step_safe_otp_read_rbit3_guarded
    mvns r4, r0
    movs r0, #OTP_DATA_BOOT_FLAGS0_ROW
    bl s_varm_step_safe_otp_read_rbit3_guarded
    mvns r0, r0
    // r0, r4 hold two reads of the same row (inverted)
.cpu cortex-m33
    rcp_iequal r0, r4
.cpu cortex-m23
    pop {r1}
    // if bits 5-7 aren't equal to ~bits 0-2, then
    // r1 will end up here with some bits set in 5-7.
    // bits 8+ will be the same bits 3+ negated,
    // but only 8 bits are used by the CPU for the shift though
    // bits in 5-7 will be a shift > 32
    mvns r2, r1
    lsls r2, #5
    eors r1, r2
    // inlined boolean making from two sources - will only give
    // a valid result if r0 >> r1 and r4 >> r1 are the same
    lsrs r0, r1
.cpu cortex-m33
    hx_bit_pattern_e100e1 r0
    hx_bit_pattern_1e001e r2
.cpu cortex-m23
    bcs 1f
    lsls r2, #1
1:
    subs r0, r2
    lsrs r4, r1
    bcs 1f
    lsls r0, #8
1:
.cpu cortex-m33
    rcp_bvalid r0
    rcp_canary_check_nodelay r5, CTAG_S_VARM_STEP_SAFE_HX2_GET_BOOT_FLAG_IMPL
.cpu cortex-m23
    pop {r1-r5, pc}
#endif

.global s_varm_swap_mpu_state
.thumb_func
// args: mpu, buf, mask
// write (buf & mask) to mpu, whilst saving current value of mpu to buf.
// return number of bytes copied, xor'd with mask.
s_varm_swap_mpu_state:
    push {r1, r4, r5, lr}
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_canary_get ip, CTAG_S_SAVE_CLEAR_AND_DISABLE_MPU
.cpu cortex-m23
#endif
    movs r4, #BOOTROM_MPU_REGION_COUNT - 1
1:
    // RNR
    str r4, [r0, #M33_MPU_RNR_OFFSET - M33_MPU_TYPE_OFFSET]
    // get old RLAR
    ldr r3, [r0, #M33_MPU_RLAR_OFFSET - M33_MPU_TYPE_OFFSET]
    ldr r5, [r1, #0]
    ands r5, r2
    // store saved RLR & mask
    str r5, [r0, #M33_MPU_RLAR_OFFSET - M33_MPU_TYPE_OFFSET]
    // save old RLAR
    stmia r1!, {r3}
    subs r4, r4, #1
    bpl 1b
2:
    ldr r0, [sp]
    subs r1, r0
    lsrs r0, r1, #2
    eors r0, r2
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_canary_check ip, CTAG_S_SAVE_CLEAR_AND_DISABLE_MPU
.cpu cortex-m23
#endif
    pop {r1, r4, r5, pc}

// Default XIP setup code. This code is copied into boot RAM by the bootrom
// before entering user code, and then copied into SRAM before executing. It
// may be overwritten by user code to install a better XIP setup function.
//
// When copied into boot RAM, the bootrom writes the current XIP mode
// (bootrom_xip_mode_t enum) and clock divisor immediately after this code.
// This code just takes those values and passes them to the
// s_varm_flash_select_xip_read_mode function.
//
// This means user apps which do not include an XIP setup function of their
// own can still call the saved XIP setup in bootram after flash programming,
// and have the XIP mode found by the bootrom automatically restored.

// Note this is in a .rodata section, not a .text section, as it should never
// be directly executed by the bootrom.
.section .rodata.keep.s_native_default_xip_setup, "a"
.global s_native_default_xip_setup

// Do not change this code without updating DEFAULT_ARM_XIP_SETUP_SIZE_BYTES in bootrom.h

.p2align 2
s_native_default_xip_setup:
    adr r2, 1f                                      // 2 bytes
    // Load arguments
    ldr r0,  [r2, #4]                               // 2 bytes
    ldr r1,  [r2, #8]                               // 2 bytes
    // Load and tail-call function pointer
    ldrh r2, [r2, #2]                               // 2 bytes
1:
    bx r2                                           // 2 bytes
// Absolute address of bootrom function:
#if BOOTROM_32BIT_FUNC_POINTERS
    // TODO it's annoying to support both here, and presently 32-bit funcptrs are only used for dev builds:
#warning "32-bit pointer builds will break binaries that call the default XIP setup (i.e. do flash programming, and do not have a boot2)"
    .hword -1
#else
    .hword s_varm_api_crit_flash_select_xip_read_mode+1 // 2 bytes, total 12 bytes
#endif
s_native_default_xip_setup_end:
.if DEFAULT_ARM_XIP_SETUP_SIZE_BYTES != s_native_default_xip_setup_end - s_native_default_xip_setup
.error "s_native_default_xip_setup is wrong size"
.endif
// Two argument words follow, set by bootrom after copying this code to
// boot RAM.

// -----------------------------------------------------------------------
// we pick this function to overlap 6 hwords of core0_boot_path_prolog as
// it is only used in secure code, and doesn't have any relocations
/*
 fe15 c736 	rcp_canary_get	ip, 0x56 (86), nodelay
 b504      	push	{r2, lr}
 f04f 121e 	mov.w	r2, #1966110	; 0x1e001e
 4082      	lsls	r2, r0
 f04f 10e1 	mov.w	r0, #14745825	; 0xe100e1
 00c9      	lsls	r1, r1, #3
 1a80      	subs	r0, r0, r2
 // ---- these 6 hwords go over the beginning of core0_boot_path_prolog
 4088      	lsls	r0, r1
 ee20 0710 	rcp_bvalid r0, delay
 fe05 c736 	rcp_canary_check	ip, 0x56 (86), nodelay
 bd04      	pop	{r2, pc}
*/
.section .text.sonly_varm_make_hx_bool_impl
.p2align 2
.global sonly_varm_make_hx_bool_impl
.thumb_func
sonly_varm_make_hx_bool_impl:
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_canary_get_nodelay ip, CTAG_S_VARM_MAKE_HX2_BOOL_IMPL
.cpu cortex-m23
#endif
    push {r2, r3, lr}
.cpu cortex-m33
    hx_bit_pattern_1e001e r2
.cpu cortex-m23
    lsls r2, r0
    orrs r0, r1
    lsrs r3, r0, #1
.cpu cortex-m33
    hx_bit_pattern_e100e1 r0
.cpu cortex-m23
    lsls r1, #3
    subs r0, r2
    lsls r0, r1
#if 0 // the rest of this is copied into core0_boot_path_prolog which follows immediately after
    eors r0, r3
.cpu cortex-m33
    rcp_bvalid r0 // i think delay is good here
.cpu cortex-m23
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_canary_check_nodelay ip, CTAG_S_VARM_MAKE_HX2_BOOL_IMPL
.cpu cortex-m23
#endif
    pop {r2, r3, pc}
#endif

.section .text.s_varm_crit_cache_maintenance, "ax"

// XIP cache maintenance: this family of functions preserves r1, r2, which
// helps keep caller values live in registers instead of spilling to the
// stack (assuming we annotate correctly)

#define XIP_CACHE_MAINTENANCE_OP_INVALIDATE_BY_SET_WAY 0
#define XIP_CACHE_MAINTENANCE_OP_CLEAN_BY_SET_WAY 1
#define XIP_CACHE_MAINTENANCE_OP_INVALIDATE_BY_ADDRESS 2
#define XIP_CACHE_MAINTENANCE_OP_CLEAN_BY_ADDRESS 3
#define XIP_CACHE_MAINTENANCE_OP_PIN_AT_ADDRESS 7

.global s_varm_api_crit_flash_flush_cache_impl
.thumb_func
s_varm_api_crit_flash_flush_cache_impl:
.cpu cortex-m33
    rcp_canary_get_nodelay ip, CTAG_S_NATIVE_CRIT_XIP_CACHE_MAINTENANCE
.cpu cortex-m23
    movs r0, #XIP_CACHE_MAINTENANCE_OP_INVALIDATE_BY_SET_WAY << 2
    b 1f
.global s_varm_crit_pin_xip_ram_impl
.thumb_func
s_varm_crit_pin_xip_ram_impl:
.cpu cortex-m33
    rcp_canary_get_nodelay ip, CTAG_S_NATIVE_CRIT_XIP_CACHE_MAINTENANCE
.cpu cortex-m23
    movs r0, #XIP_CACHE_MAINTENANCE_OP_PIN_AT_ADDRESS << 2
1:
    // fall through to shared body
_varm_to_native_cache_maintenance:
    // Set up base pointer -- maintenance on the upper 16k of the cached
    // space, which is suitable for flushing or pinning the entre cache.
#if (XIP_SRAM_BASE + (XIP_MAINTENANCE_BASE - XIP_BASE)) & ~0x3fffc000
#error "uh oh"
#endif
    // And I bet you thought movt was useless all this time!
    movt r0, (XIP_SRAM_BASE + (XIP_MAINTENANCE_BASE - XIP_BASE)) >> 14
    lsrs r0, #2
    // dispatch to native version of loop on RISC_V. Note there is no
    // varm_to_native symbol because the only valid entry points are the ones
    // where we set a known-good maintenance op value in r0.
    movs r3, #MULTIPLEX_s_native_crit_xip_cache_maintenance
    varm_hint HINT_MULTIPLEX
_native_cache_maintenance:
    movw r3, (XIP_SRAM_END - XIP_SRAM_BASE) - 8
1:
    strb r3, [r0, r3]
    subs r3, #8
    bcs  1b

.cpu cortex-m33
    rcp_canary_check_nodelay ip, CTAG_S_NATIVE_CRIT_XIP_CACHE_MAINTENANCE
.cpu cortex-m23
    bx  lr

.section .text.s_varm_flash_put_get_nodata
.global s_varm_flash_put_get_nodata
.p2align 2
.thumb_func
s_varm_flash_put_get_nodata:
   // Note tx/rx are ignored if len is 0, so they can be left as garbage
#if !GENERAL_SIZE_HACKS
   movs r1, #0
   movs r2, #0
#endif
   movs r3, #0
.global varm_to_s_native_crit_flash_put_get
.thumb_func
varm_to_s_native_crit_flash_put_get:
   varm_hint HINT_s_native_crit_flash_put_get
   // fall thru to s_native_crit_flash_put_get

// first ignored param just gives the caller a default return code if the function is skipped
// this function reads the LOCK1 row for the given OTP page, which is a 3-way majority vote
// with the 3 lowest bytes having:
// 0 :0:bl_write_disabled:bl_read_disabled:nsboot_write_disabled:nsboot_read_disabled:secure_write_disabled:secure_read_disabled
//
// this function takes the majority vote, and returns
// 1:1:maj3vote(bl_write_disable)|maj3vote(secure_write_disabled):maj3vote(bl_read_disable)|maj3vote(secure_read_disabled)
//
// which is the value to write to the runtime OTP locks to advance the secure locks according to the bootloader locks,
// and disable NS access completely.

.section .text.s_otp_advance_bl_to_s_value // (uint32_t ignored, uint32_t page)
.global s_otp_advance_bl_to_s_value
.thumb_func
#if OTP_SW_LOCK0_SEC_LSB != 0
// we are shifting the BL 2 bits from the OTP format into the SW secure setting format
#error
#endif
s_otp_advance_bl_to_s_value:
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_count_set STEPTAG_S_OTP_ADVANCE_BL_TO_S_VALUE
.cpu cortex-m23
#endif
    ldr r2, =otp_data_raw_guarded + OTP_DATA_PAGE0_LOCK1_ROW * 4
    lsls r1, #3
    ldr r0, [r2, r1]
    // r0 = AaBbCc (A is a nibble with 4 bits dont_care:bl_perms, a is a nibble with ns_perms:s_perms)
    lsrs r1, r0, #8 + OTP_DATA_PAGE0_LOCK1_LOCK_BL_LSB
    // r1 = 00AaB
    lsls r2, r0, #16 - OTP_DATA_PAGE0_LOCK1_LOCK_BL_LSB
    // r2 = aBbCc000
    orrs r1, r2
    // r1 = aBbCcAaB
    lsrs r0, #OTP_DATA_PAGE0_LOCK1_LOCK_BL_LSB
    // r0 = 000AaBbC
    ands r1, r0
    // r1 = 000(A&C)(a&c)(A&B)(a&b)(BC)
    movs r0, #OTP_SW_LOCK0_NSEC_BITS
1:
    orrs r0, r1
    lsrs r1, #8
    bne 1b
    // loop0, r0 = 000(A&C)x(A&B)X(0b1100 | B&C)
    // loop1, r0 = 000(A&C)x(0b1100 | (B&C | A&B))
    // loop2, r0 = 000000x(0b1100 | B&C | A&B | A&C)
    // loop3, r0 = 000000x(0b1100 | B&C | A&B | A&C)
    lsls r0, #28
    lsrs r0, #28
    // r0 = 0b1100 | B&C | A&B | A&C)
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_count_check STEPTAG_S_OTP_ADVANCE_BL_TO_S_VALUE
.cpu cortex-m23
#endif
    bx lr
//    static_assert(OTP_SW_LOCK0_SEC_LSB == 0, "");
    // ... and disabling NS access completely (we'll go through a NSC for all OTP access)
//    uint32_t sw_lock = (otp_locks >> OTP_DATA_PAGE0_LOCK1_LOCK_BL_LSB) | OTP_SW_LOCK0_NSEC_BITS;
//            printf(" sw_lock was %08x\n",(int) otp_hw->sw_lock[page]);
//            printf(" sw_lock write %08x\n", (int)sw_lock);

.section .text.s_varm_decode_item_size_impl
.global s_varm_decode_item_size_impl
s_varm_decode_item_size_impl:
//  if (item_header & 0x80) {
//      size = (uint16_t)(item_header >> 8);
//  } else {
//      size = (uint8_t)(item_header >> 8);
//  }
.cpu cortex-m33
    rcp_canary_get_nodelay ip, STEPTAG_S_VARM_DECODE_ITEM_SIZE_IMPL
.cpu cortex-m23
    lsrs r0, r0, #8
    bcs  1f
    uxtb r0, r0
1:
// move to caller as GCC insists on doing it anyway even if ASM writes a uint16_t
//    uxth r0, r0
.cpu cortex-m33
    rcp_canary_check_nodelay ip, STEPTAG_S_VARM_DECODE_ITEM_SIZE_IMPL
.cpu cortex-m23
    bx lr

.global varm_to_s_native_busy_wait_at_least_cycles
.thumb_func
varm_to_s_native_busy_wait_at_least_cycles:
    RISCV_REDIRECT_HINT(s_native_busy_wait_at_least_cycles)
s_native_busy_wait_at_least_cycles:
1:
    subs r0, #3
    bcs 1b
    bx lr

// preserves r3; if arg (r0) is non zero we return both the set alias of boot_diagnostic in r0, but the regular version in r1
// since we have the value in the reg and it can space in the caller
.global s_varm_init_diagnostic32_impl
s_varm_init_diagnostic32_impl:
//    if (real) {
//        uint32_t *rc = &bootram->always.boot_diagnostic;
//        // clear diangostics
//        *rc  = 0;
//        return hw_set_alias(rc);
//    }
//    return (uint32_t*)0;//get_fake_mpu();
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_canary_get_nodelay ip, STEPTAG_S_VARM_INIT_DIAGNOSTIC32_IMPL
.cpu cortex-m23
#endif
    // if false we'll actually return 0, which is a perfectly safe pointer to write
    // diagnostics we don't care about to
    cbz r0, 1f
    ldr r1, = BOOTRAM_BASE + BOOTRAM_ALWAYS_BOOT_DIAGNOSTIC_OFFSET
    movw r0, #REG_ALIAS_SET_BITS
    adds r0, r1
    movs r2, #0
    str r2, [r1]
1:
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_canary_check_nodelay ip, STEPTAG_S_VARM_INIT_DIAGNOSTIC32_IMPL
.cpu cortex-m23
#endif
    bx lr
