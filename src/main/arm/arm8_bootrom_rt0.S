/**
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

// ----------------------------------------------------------------------------
// Bootrom Runtime 0
// ----------------------------------------------------------------------------
// This is not a full crt0 -- in particular, no .bss or .data initialisation
// (use of .data/.bss is disallowed via linker script assertions).
// The bootrom is not permitted to use statically-allocated memory, as parts of
// it are called into by user code.
// The purpose of this file is:
// - Provide initial entry point for both cores
// - Provide holding pen and launch code for core 1
// - Provide direct-boot entry for core 0, mainly intended for running
//   ARM code during ATE
// - Pass core 0 control over to the main flash boot sequence
// - Thunks and other ARM only assembly functions

#include "bootram.h"
#include "bootrom.h"
#include "bootrom_layout.h"
#include "hardware/regs/accessctrl.h"
#include "hardware/regs/addressmap.h"
#include "hardware/regs/bootram.h"
#include "hardware/regs/clocks.h"
#include "hardware/regs/m33.h"
#include "hardware/regs/m33.h"
#include "hardware/regs/m33_eppb.h"
#include "hardware/regs/otp.h"
#include "hardware/regs/pads_bank0.h"
#include "hardware/regs/powman.h"
#include "hardware/regs/resets.h"
#include "hardware/regs/sio.h"
#include "hardware/regs/sysinfo.h"
#include "hardware/regs/trng.h"
#include "hardware/regs/watchdog.h"
#include "nsboot_secure_calls.h"

.cpu cortex-m33
.thumb
.syntax unified

.section .vectors, "ax"
.balign 2

.global __vectors
__vectors:
.word INVALID_STACK_PTR // Invalid stack; neither core should use any before setting their own SP
.word s_arm8_entry_point // Reset
// NMI goes to varm_dead which does an rcp hang which will now stall forever
.word varm_dead     // NMI
.word varm_dead     // HardFault

.global _magic
_magic:
// magic
.byte 'M', 'u'
_major_version:
.byte 2
_minor_version:
.byte 2

_arm_well_known_rom_table_base:
.hword BOOTROM_ROMTABLE_START
_arm_well_known_func_table_lookup_val:
.hword arm8_table_lookup_val + 1
_arm_well_known_func_table_lookup_entry:
.hword arm8_table_lookup_entry + 1

copyright:
.string "(C) 2024 Raspberry Pi Ltd"

// Args: 2-char symbol in r0, flag query in r1.
// Each table entry is a 2-char symbol, an hword of flags, and then 1 hword of
// data for each bit set in flags.
// Search the table for a symbol and a flag mask, and if *any* of those flags
// are found under the correct symbol, return a pointer to the first
// corresponding table data.
.global arm8_table_lookup_entry
.thumb_func
arm8_table_lookup_entry:
#if FEATURE_CANARIES
    rcp_count_set_nodelay STEPTAG_ARM_TABLE_LOOKUP_ENTRY
#endif
    ldr r3, =BOOTROM_ROMTABLE_START
    mov ip, r0
    b _lookup_next_symbol
#if USE_TINY_ROM_TABLE_LOOKUP || BOOTROM_32BIT_FUNC_POINTERS
1:
    adds r3, #2
_lookup_skip_to_next:
    lsrs r2, #1
    bcs 1b
    bne _lookup_skip_to_next
    adds r3, #4
#else
_lookup_skip_to_next:
    // Assume DATA and ARM_NONSEC entries never share a symbol.
    // Assume no long DATA or ARM_NONSEC entries.
    cmp r2, #0x10
    blo 1f
    adds r3, #2
1:
    // Assume no long ARM_SEC entries. (bit 3)
    ldr r0, =0x4a886866
    lsls r2, #2
    rors r0, r2
    lsrs r0, #28
    adds r3, r0
#endif
_lookup_next_symbol:
    ldrh r0, [r3]
    ldrh r2, [r3, #2]
    cbz r0, _lookup_return_ptr_r0
    cmp ip, r0
    bne _lookup_skip_to_next
    tst r2, r1
    beq _lookup_skip_to_next
_lookup_seek_result:
    ands r1, r2
1:
    lsrs r1, #1
    bcs _lookup_found
    lsrs r2, #1
    bcc 1b
    adds r3, #2
    b 1b
_lookup_found:
    adds r0, r3, #4
_lookup_return_ptr_r0:
#if FEATURE_CANARIES
    rcp_count_check_nodelay STEPTAG_ARM_TABLE_LOOKUP_ENTRY
#endif
    // fall thru
.global _noop, varm_noop
.thumb_func
varm_noop:
    // hardening: skip (previous instruction above is canary)
    bx lr

.global arm8_table_lookup_val
.thumb_func
arm8_table_lookup_val:
#if !FEATURE_CANARIES
    push {lr}
#else
    rcp_canary_get_nodelay r3, CTAG_ARM8_TABLE_LOOKUP_VAL
    push {r3, lr}
#endif
    bl arm8_table_lookup_entry
#if BOOTROM_32BIT_FUNC_POINTERS
    cbz r0, 1f
    ldr r0, [r0]
1:
#else
    // Note the first halfword of ROM is 0, so NULLs propagate naturally:
    ldrh r0, [r0]
#endif
#if !FEATURE_CANARIES
    pop {pc}
#else
    pop {r2, r3}
    rcp_canary_check_nodelay r2, CTAG_ARM8_TABLE_LOOKUP_VAL
    // hardening: done
    bx r3
#endif

// ----------------------------------------------------------------------------
// Entry point for both cores
// ----------------------------------------------------------------------------

.section .vectors, "ax"

.global s_arm8_entry_point
.type s_arm8_entry_point,%function
.thumb_func
s_arm8_entry_point:
    // Note on constants: we have
    //   ed08 VTOR
    //   ed94 MPU_CTRL
    //   ed88 CPACR
    //   edd0 SAU_CTRL
    // So to avoid near-misses in the literal pool, we always start by
    // materialising VTOR and then add an 8-bit offset if necessary.

    // enable canary processor
    // CPACR = M33_CPACR_CP7_BITS
    ldr r0, =PPB_BASE + M33_VTOR_OFFSET
    adds r0, #M33_CPACR_OFFSET - M33_VTOR_OFFSET
    movs r1, #M33_CPACR_CP7_BITS
    str r1, [r0]
    // good a place as any to enable it for NS too
    movs r2, #M33_NSACR_CP7_BITS
    str r2, [r0, #M33_NSACR_OFFSET - M33_CPACR_OFFSET]
    // NSACR = M33_NSACR_CP7_BITS
    add r0, #PPB_NONSEC_BASE - PPB_BASE
    str r1, [r0]
    // NS.CPACR = M33_CPACR_CP7_BITS

enable_sau:

    // Enable SAU region 7, which will remain "reserved by us" through and
    // post boot. This sets everything past the end of the Secure-only text
    // to SAU-NS. When combined with the IDAU, the final attribute map is:
    //
    //   Start             End               Attribute (I)  Attribute (D)  Contents
    //   0000           -> 42ff              Exempt         Exempt         Shared .text
    //   4300           -> sonly_text_end-1  Secure         Exempt         Not-NonSecure .text
    //   sonly_text_end -> 7dff              NonSecure      Exempt         .rodata, RISC-V code
    //   7e00           -> 7fff              Secure NSC     Secure NSC     SGs and SG->S wrappers
    //
    // Notes:
    //
    // - The 4300 here is actually 9300 for 64k ROM development FPGA builds
    //
    // - We intended for the 4300 to be tie-cell-programmable, it's a bit of a
    //   funny story (got case-analysed during STA)
    //
    // - The "Not-NonSecure .text" has no security requirement to be
    //   Secure-only, it's just that we can't make all of our text shared due
    //   to lack of IDAU Exempt->S watermark flexibility, so we have to keep
    //   shared text (such as ROM table lookup func) out of this region
    //
    // - The difference between fetch and load/store was a late-in-the-day
    //   synthesis hack, and isn't supposed to exist in v8-M (sorry Joseph).
    //   Having all of ROM be Exempt for load/stores is fine, we just don't
    //   want all of it to all be Secure-executable, since this would mean a
    //   larger ROP surface.

    ldr r0, =PPB_BASE + M33_VTOR_OFFSET
    adds r0, #M33_SAU_CTRL_OFFSET - M33_VTOR_OFFSET
    // we will do an stmia to set all 5 registers (not we write garbage to SAU_TYPE which is read-only)
#if M33_SAU_TYPE_OFFSET-M33_SAU_CTRL_OFFSET != 4 || M33_SAU_RNR_OFFSET-M33_SAU_CTRL_OFFSET != 8 || \
    M33_SAU_RBAR_OFFSET-M33_SAU_CTRL_OFFSET != 12 || M33_SAU_RLAR_OFFSET-M33_SAU_CTRL_OFFSET != 16
#error expected 5 registers in order
#endif
    movs r1, #M33_SAU_CTRL_ENABLE_BITS; // ALLNS=0 ENABLE=1
    movs r3, #7
    ldr  r4, =P16(sonly_text_end)
    // note `+` because this is a linker relocation:
    ldr  r5, =BOOTROM_SG_END - 32 + M33_SAU_RLAR_ENABLE_BITS
    stmia r0!, {r1-r5}

#if HACK_RAM_BOOTROM_AT
    ldr r0, =PPB_BASE + M33_VTOR_OFFSET
    adds r0, #M33_SAU_CTRL_OFFSET - M33_VTOR_OFFSET
    // Second region is required to get SGs to be NSC, as there are no IDAU
    // entries over SRAM.
    movs r1, #6
    str  r1, [r0, #M33_SAU_RNR_OFFSET-M33_SAU_CTRL_OFFSET]
    // Note overlap is always SAU-NSC (which, if IDAU is NS, is NSC overall)
    ldr  r1, =BOOTROM_SG_START
    ldr  r2, =BOOTROM_SG_END - 32 + M33_SAU_RLAR_ENABLE_BITS + M33_SAU_RLAR_NSC_BITS
    str  r1, [r0, #M33_SAU_RBAR_OFFSET-M33_SAU_CTRL_OFFSET]
    str  r2, [r0, #M33_SAU_RLAR_OFFSET-M33_SAU_CTRL_OFFSET]
#endif

    // Check if this is core 0, and go to holding pen if not enter main booth path
check_core:
    // NOTE: We DO NOT use any stack prior to possible watchdog entry
    ldr r0, =SIO_BASE
    ldr r1, [r0, #SIO_CPUID_OFFSET]
    cbnz r1, core1_boot_path

set_secure_stack:
    ldr r1, =BOOTRAM_PREBOOT_STACK_TOP
    sub r0, r1, #BOOTRAM_PREBOOT_STACK_SIZE
    msr msplim, r0
#if !(BOOTRAM_PREBOOT_STACK_TOP & 4)
#error expect un-aligned stack top for now to keep stack alignment once we enter C code
#endif

zero_most_of_bootram:
    // zero bootram up to preboot stack top (i.e. everything except core1 and always)
    movs r2, #0
1:
    stmia r0!, {r2}
    cmp r0, r1
    bne 1b
    mov sp, r1

    // continue in C code (note the weird call is because we skip the callee-saving which wastes
    // our limited stack space for a function that will never return
    b s_varm_crit_core0_boot_path_entry_p2 - 2

.global native_wait_rescue, varm_wait_rescue
.type native_wait_rescue,%function
.type varm_wait_rescue,%function
.thumb_func
native_wait_rescue:
varm_wait_rescue:
    cpsid i // disable IRQs
    wfi
    b.n varm_wait_rescue

// ----------------------------------------------------------------------------
// Core 1 boot path
// ----------------------------------------------------------------------------

// This code does not use any stack, and runs with the invalid stack pointer
// from the vector table, to ensure that not even faults cause RAM writes,
// until we have been given a valid stack by core 0. A fault before that point
// will fail to write its exception frame, and be promoted to a lockup.

// This code also runs with eXecute-Never (XN) permissions on all of memory
// except for the small part of the ROM containing this code. The restriction
// is lifted at the point we commit to launching core 1 into user code.

// takes r4 = SIOB_BASE
// returns r0 = word received
.thumb_func
receive_and_check_zero:
#if FEATURE_CANARIES
    rcp_canary_get_nodelay ip, CTAG_RECEIVE_AND_CHECK_ZERO
#endif
receive_and_check_zero_lp:
    wfe
    ldr r0, [r4, #SIO_FIFO_ST_OFFSET]
    lsrs r0, #SIO_FIFO_ST_VLD_LSB + 1
    bcc receive_and_check_zero_lp

    ldr r0, [r4, #SIO_FIFO_RD_OFFSET]
    // if we received 0, we reset back to main loop
    cbz r0, core_0_handshake_loop
#if FEATURE_CANARIES
    rcp_canary_check_nodelay ip, CTAG_RECEIVE_AND_CHECK_ZERO
#endif
    // hardening: done
    bx  lr

send_and_then_again:
    // in case of multiple core 1 resets, we can keep pushing and fill the FIFO
    // we should wait for an event if the FIFO is full to avoid busy wait
    wfe
// takes r0 = word to send, r4 = SIOB_BASE, r5 link register
send_and_then:
#if FEATURE_CANARIES
    // note nodelay as we loop over it, and we could easily expose a lot of delay timings
    rcp_canary_get_nodelay ip, CTAG_SEND_AND_THEN
#endif
    ldr r1, [r4, #SIO_FIFO_ST_OFFSET]
    lsrs r1, #SIO_FIFO_ST_RDY_LSB + 1
    bcc send_and_then_again
    str r0, [r4, #SIO_FIFO_WR_OFFSET]
    sev
#if FEATURE_CANARIES
    rcp_canary_check_nodelay ip, CTAG_SEND_AND_THEN
#endif
    // hardening: done
    bx  r5

// First step: block until core 0 initialises this core's RCP salt value.
// (Note if core 0 is RISC-V then core 1's RCP salt will be unconditionally
// marked as valid, since RISC-V cores can't access the coprocessors.)

wait_for_rcp_salt:
    wfe
core1_boot_path:
    // Keep SCB pointer in r7, MPU pointer in r6:
    ldr r7, =(PPB_BASE + M33_VTOR_OFFSET)
    adds r6, r7, #(M33_MPU_CTRL_OFFSET - M33_VTOR_OFFSET)
#if M33_MPU_RNR_OFFSET != (M33_MPU_CTRL_OFFSET + 4) || M33_MPU_RBAR_OFFSET != (M33_MPU_CTRL_OFFSET + 8) || \
    M33_MPU_RLAR_OFFSET != (M33_MPU_CTRL_OFFSET + 12)
#error ??
#endif
    // Set memory outside of core 1 boot path to execute-never, until we
    // receive a valid vector. It is harmless to do this multiple times:
    movs r0, #(M33_MPU_CTRL_PRIVDEFENA_BITS | M33_MPU_CTRL_ENABLE_BITS)
    movs r1, #0
#if M33_MPU_RBAR_XN_BITS != 1
#error M33_MPU_RBAR_XN_BITS != 1
#endif
    ldr r2, =P16(_end_of_core1_boot_path_roundup_32_plus_1)
    // -32 is end-of-memory, due to inclusive MPU bounds:
    subs r3, r1, #(32 - M33_MPU_RLAR_EN_BITS)
    stmia r6!, {r0-r3}
    // The rcp.canarystatus instruction returns hx_true (0xa500a500) if the
    // salt has been loaded, and hx_false (0x00c300c3) if it has not:
    mrc p7, #1, APSR_nzcv, c0, c0, #0
    bpl wait_for_rcp_salt
    subs r6, #16
    // Note RCP instructions after this point will fault if the RCP is not
    // initialised, so the branch above is just a friendly check.

// Wait for core 0 to provide an entry point.
wait_for_vector:
    ldr r4, =SIO_BASE
    // Enable SCR.SLEEPDEEP before WFE -- this allows NVIC to be fully gated
    // during sleep, as well as releasing the system-level clock request.
    movs r1, #M33_SCR_SLEEPDEEP_BITS
    str r1, [r7, #(M33_SCR_OFFSET - M33_VTOR_OFFSET)]
    // note core_0_handshake_loop is the intended next instruction, but the read is harmless
    // as we're about to drain, so don't waste an instruction branching
1:
    ldr r1, [r4, #SIO_FIFO_RD_OFFSET]
core_0_handshake_loop:
    rcp_count_set STEPTAG_ASM_C1_BOOTPATH + 0
    // Sanity check MPU limit which should have been set earlier
    ldr r2, [r6, #(M33_MPU_RLAR_OFFSET - M33_MPU_CTRL_OFFSET)]
    // recreate the constant in case r3 (which already had the value from above
    // is comprimized)
    movs r3, #-(32 - M33_MPU_RLAR_EN_BITS)
    rcp_iequal r2, r3

    // drain the FIFO before sending 0
    ldr r1, [r4, #SIO_FIFO_ST_OFFSET]
    lsrs r1, #SIO_FIFO_ST_VLD_LSB + 1
    bcs 1b

    // ...and_then = receive_and_check_zero (which jmps to core_0_handshake_loop on 0)
    adr r5, receive_and_check_zero
    // send 0
    movs r0, #0
    bl send_and_then
    rcp_count_check STEPTAG_ASM_C1_BOOTPATH + 0
    // check for cmd 1
    cmp r0, #1
    bne core_0_handshake_loop
    // ack and receive VTOR
    bl send_and_then
    rcp_count_check STEPTAG_ASM_C1_BOOTPATH + 1
    str r0, [r7, #(M33_VTOR_OFFSET - M33_VTOR_OFFSET)]
    // ack and receive SP
    bl send_and_then
    rcp_count_check STEPTAG_ASM_C1_BOOTPATH + 2
    // initialize
    mov sp, r0
    bl send_and_then
    rcp_count_check STEPTAG_ASM_C1_BOOTPATH + 3
    adr r5, core1_launch
    // receive IP (0 sends us back into handshake loop)
    bl send_and_then
.thumb_func
core1_launch:
    // Disable SLEEPDEEP before exiting, as it affects wake latency
    movs r1, #0
    str r1, [r7, #(M33_SCR_OFFSET - M33_VTOR_OFFSET)]
    // Disable MPU to remove XN region
    str r1, [r6, #(M33_MPU_CTRL_OFFSET - M33_MPU_CTRL_OFFSET)]
    // Also clear the RLAR (contains region enable) as it's a bit rude to leave the region behind
    str r1, [r6, #(M33_MPU_RLAR_OFFSET - M33_MPU_CTRL_OFFSET)]
    // Enter user-supplied vector
    rcp_count_check STEPTAG_ASM_C1_BOOTPATH + 4
    // hardening: done
    blx r0

// Low power hang on return. Reset the core if you want to provide another entry point
// (There is no need to return though)
//
// alternatively you could return directly to wait_for_vector (available in the function table)
// if you know core 1 is still in a good state
    b.n varm_dead_quiet

// ----------------------------------------------------------------------------
// Past this point is not executable by core 1 until it receives a vector.
.global _end_of_core1_boot_path
_end_of_core1_boot_path:

// ----------------------------------------------------------------------------
// Trampolines and trampoline-shaped objects
// ----------------------------------------------------------------------------

// note we do the copy here in assembly, so we don't need to set aside space for stage2 during the preboot stage (and
// so have more stack then), and here we reset the stack now we're comitted to entering the flash code without
// returning to bootrom C code

.section .text.s_native_crit_init_default_xip_setup_and_enter_image_thunk
.global s_native_crit_init_default_xip_setup_and_enter_image_thunk
s_native_crit_init_default_xip_setup_and_enter_image_thunk:
    ldrd r9, r10, [sp, #0]
    // r0 - XIP mode enum
    // r1 - XIP clkdiv
    // r2 = pc
    // r3 = sp
    // r9 = sp_lim
    // r10 = vector_table

    // Note this wipes our stack, which is ok since we aren't returning. Don't
    // call memset, because it may save the callee saves on the stack and then
    // trash them. (Environmental storytelling in code comments!)
    ldr r4, =BOOTRAM_BASE
    add r5, r4, #BOOTRAM_SIZE - BOOTRAM_ALWAYS_SIZE
    movs r6, #0
1:
    stmia r4!, {r6}
    cmp r4, r5
    blo 1b

    // ---------------- DO NOT CALL ANY FUNCTIONS USING STACK BELOW THIS POINT  ----------------
    // We have just erased the stack, and are about to copy XIP setup into former stack space.

    // Clear USB RAM -- anything left here by nsboot will not have been verified or cleared. Skip
    // clearing when secure boot is disabled, as a courtesy to core 1 running as USB debug probe
    // (the upper ~3k is already trashed, but 1k is enough to use the peripheral)
#if BOOTRAM_ALWAYS_OFFSET != BOOTRAM_SIZE - BOOTRAM_ALWAYS_SIZE
#error
#endif
    ldr r7, [r5, #BOOTRAM_ALWAYS_SECURE_OFFSET - BOOTRAM_ALWAYS_OFFSET]
    // need to set flags, and take the opportunity to XOR out the "secure" XOR
    eors r7, #HX_XOR_SECURE
    // branch if secure (top bit set)
    bmi 1f
    // if we're skipping the clear, assert this is actually the secure "false" value
    rcp_bfalse r7
    b 2f
1:
    ldr r4, =USBCTRL_DPRAM_BASE
    adds r5, r4, #USBCTRL_DPRAM_SIZE
    // r6 is still 0 at this point
1:
    stmia r4!, {r6}
    cmp r4, r5
    blo 1b
2:

    ldr r6, =(PPB_BASE + M33_VTOR_OFFSET)
    str r10, [r6]

    // Copy default xip setup code into boot ram -- this code just restores the XIP mode found by try_flash_boot.
    ldr r7, =BOOTRAM_BASE + BOOTRAM_XIP_SETUP_CODE_OFFSET
    ldr r6, =P16(s_native_default_xip_setup)
#if DEFAULT_ARM_XIP_SETUP_SIZE_BYTES == 12
    ldmia r6, {r4-r6}
    stmia r7!, {r4-r6}
    stmia r7!, {r0, r1}
#else
#warning "You should probably update the specialised version"
    adds r5, r7, #DEFAULT_ARM_XIP_SETUP_SIZE_BYTES
1:
    ldmia r6!, {r4}
    stmia r7!, {r4}
    cmp r7, r5
    blo 1b
    // Write arguments for s_varm_flash_select_xip_read_mode after the default XIP code
    stmia r7!, {r0, r1}
#endif

    // enter binary
    msr msplim, r9
    msr msp, r3
#if FEATURE_CANARIES
    rcp_count_check STEPTAG_S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_THUNK_BASE
#endif
    blx r2 // we don't expect the binary to return, but safe for us to hang (slightly better than no link register)

// Die without taking out the opposite core:
.global varm_dead_quiet
.thumb_func
varm_dead_quiet:
1:
    wfi
    b 1b
    // Fall through if branch fails

.global native_dead, varm_dead
.type native_dead,%function
.type varm_dead,%function
.thumb_func
native_dead:
varm_dead:
#if BREAKPOINT_AT_DEAD
    bkpt #0
#endif
    rcp_panic
#if BOOTROM_HARDENING
    rcp_panic
#endif

// This entry point is called from the secure gateway under ARM
.global s_from_ns_nsboot_service_call
.thumb_func
s_from_ns_nsboot_service_call:
#if FEATURE_CANARIES
    rcp_count_set_nodelay STEPTAG_S_FROM_NS_NSBOOT_SERVICE_CALL
#endif
    // under ARM we need to make sure we have not taken a boot path other than NSBOOT (at which point this API is not allowed)
    push {r0, r1}
    ldr r0, =BOOTRAM_BASE
    ldr r0, [r0, #BOOTRAM_WRITE_ONCE0_OFFSET]
    movs r1, #0
#if BOOT_ONCE_NSBOOT_API_DISABLED == 0
    lsls r0, #31 // 16-bit encoding
#else
    ands r0, r0, #(1u << BOOT_ONCE_NSBOOT_API_DISABLED)
#endif
    rcp_iequal r0, r1 // boot_once_disabled bit == false
    asrs r0, r3, #31
    rcp_iequal r0, r1 // call_number >= 0
    rsbs r0, r3, #SC_max_secure_call_num
    asrs r0, r0, #31
    rcp_iequal r0, r1 // call_number <= SC_max_secure_call_num
    pop {r0, r1}

// RISC-V code enters here under varmulet; we use .cpu to make sure everything other than RCP instructions are v8-M baseline
.cpu cortex-m23
.global s_from_nsboot_varm_service_call_no_boot_once_check
.thumb_func
s_from_nsboot_varm_service_call_no_boot_once_check:
#if BOOTROM_32BIT_FUNC_POINTERS
    lsls r3, #2
#else
    lsls r3, #1
#endif
    cmp r3, #varm_from_nsboot_func_table_end - varm_from_nsboot_func_table
    mov ip, r3
    bhs.n varm_dead // note we checked this before in the ARM case
    // we don't need to preserve r3, but we maintain stack alignment, and provide a place for our canary
#if FEATURE_CANARIES
.cpu cortex-m33
    rcp_canary_get_nodelay r3, CTAG_S_FROM_NS_NSBOOT_SERVICE_CALL
.cpu cortex-m23
#endif
    push {r3, lr}
    adr r3, varm_from_nsboot_func_table
    add r3, ip
#if BOOTROM_32BIT_FUNC_POINTERS
    ldr r3, [r3]
#else
    ldrh r3, [r3]
#endif
#if FEATURE_CANARIES
    // Assert that we ran the boot-once check on Arm
.cpu cortex-m33
    rcp_count_check_nodelay STEPTAG_S_FROM_NS_NSBOOT_SERVICE_CALL
.cpu cortex-m23
#endif
    // hardening: done
    blx r3
#if FEATURE_CANARIES
    pop {r3}
.cpu cortex-m33
    rcp_canary_check_nodelay r3, CTAG_S_FROM_NS_NSBOOT_SERVICE_CALL
    // note under ARM our SG caller takes care of clearing r1-r3
.cpu cortex-m23
    // hardening: done
    pop {pc}
#else
    pop {r3, pc}
#endif


.cpu cortex-m33
// Single function table, shared by Arm nsboot SG, and RISC-V SG hint.
// The order of this table is determined by the SC_xxx constants in nsboot_secure_calls.h.
// note: where these have from from_nsboot, or from_ns, the raw secure function performs
//       parameter checking or passes some context about the caller to the internal method
#if BOOTROM_32BIT_FUNC_POINTERS
.macro .varm_funcptr x
.word \x
.endm
.p2align 2
#else
.macro .varm_funcptr x
// note: +1 for thumb bit as we are using 16-bit pointers
.hword \x + 1
.endm
#endif
.p2align 2
varm_from_nsboot_func_table:
    .varm_funcptr s_varm_flash_abort_clear// s_varm_api_crit_connect_internal_flash
    .varm_funcptr s_from_nsboot_varm_flash_page_program
    .varm_funcptr s_from_nsboot_varm_flash_sector_erase
    .varm_funcptr s_from_nsboot_varm_flash_read_data
    .varm_funcptr s_varm_flash_abort
    .varm_funcptr s_from_nsboot_varm_reboot
    .varm_funcptr s_from_nsboot_varm_otp_access
    .varm_funcptr s_from_nsboot_varm_ram_trash_get_uf2_target_partition
    .varm_funcptr s_from_ns_varm_api_get_partition_table_info
    .varm_funcptr s_from_ns_varm_api_get_sys_info
#if FEATURE_EXEC2
    .varm_funcptr s_from_ns_varm_picoboot_exec2
#endif
varm_from_nsboot_func_table_end:

// put this in ASM, since i saw the GCC wasted a bunch of space formulating the table address
// int s_varm_api_set_ns_api_permission(uint api_num, bool enabled)
// r0: api index
// r1: allowed (bool)
.global s_varm_api_set_ns_api_permission
s_varm_api_set_ns_api_permission:
#if FEATURE_CANARIES
    rcp_count_set_nodelay STEPTAG_S_VARM_API_SET_NS_API_PERMISSION
#endif
    cmp r0, #BOOTROM_NS_API_COUNT
    bhs 1f
#if HX_BIT_PATTERN_TRUE != 0xa500a500 || HX_BIT_PATTERN_FALSE != 0x00c300c3
#error
#endif
    movs   r3, #0xc3
    cbz r1, 3f
    movs   r3, #0xa5
3:
    ldr  r2, =BOOTRAM_BASE + BOOTRAM_NS_API_PERMISSIONS_OFFSET
    strb r3, [r0, r2]
    movs r0, #0
    b 2f
1:
    movs r0, #BOOTROM_ERROR_INVALID_ARG
2:
#if FEATURE_CANARIES
    rcp_count_check_nodelay STEPTAG_S_VARM_API_SET_NS_API_PERMISSION
#endif
    // hardening: done
    bx lr

.global s_from_ns_arm8_api_secure_call
// call number passed in r4 (can't use IP as it is used by SG)
s_from_ns_arm8_api_secure_call:
#if FEATURE_CANARIES
    rcp_count_set_nodelay STEPTAG_S_FROM_NS_ARM8_API_SECURE_CALL
#endif
    push {r0, lr}
    ldr r0, =BOOTRAM_BASE
    ldr r0, [r0, #BOOTRAM_ALWAYS_CALLBACKS_OFFSET + BOOTROM_API_CALLBACK_secure_call * 4]
    cbz r0, 1f
    // tail call into secure function (we overwrite lr on the stack)
    str r0, [sp, #4]
    b 2f
1:
    // or return error and jump through original lr
    subs r0, #-BOOTROM_ERROR_INVALID_STATE
    str r0, [sp, #0]
2:
#if FEATURE_CANARIES
    rcp_count_check_nodelay STEPTAG_S_FROM_NS_ARM8_API_SECURE_CALL
#endif
    // hardening: done
    pop {r0, pc}

.global s_varm_step_safe_reset_unreset_block_wait_noinline
.type s_varm_step_safe_reset_unreset_block_wait_noinline,%function
.thumb_func
s_varm_step_safe_reset_unreset_block_wait_noinline:
#if FEATURE_CANARIES
    // use regular canary as we are called from boot path
    rcp_canary_get ip, CTAG_S_VARM_UNRESET_BLOCK_WAIT_NOINLINE
#endif
    ldr r1, =RESETS_BASE + REG_ALIAS_SET_BITS
    str r0, [r1, #RESETS_RESET_OFFSET]
    // fall thru

// seems unused -- move above canary_get down if this entry point is reinstated.
// .global s_varm_step_safe_unreset_block_wait_noinline
// .type s_varm_step_safe_unreset_block_wait_noinline,%function
// .thumb_func
// s_varm_step_safe_unreset_block_wait_noinline:
    ldr r1, =RESETS_BASE + REG_ALIAS_CLR_BITS
    str r0, [r1, #RESETS_RESET_OFFSET]
    // Remove alias bits (note we're avoiding v8-M Main instructions here)
    lsrs r1, #14
    lsls r1, #14
1:
    ldr r2, [r1, #RESETS_RESET_DONE_OFFSET]
    bics r0, r2
    bne 1b
#if FEATURE_CANARIES
    rcp_canary_check ip, CTAG_S_VARM_UNRESET_BLOCK_WAIT_NOINLINE
#endif
    // hardening: done
    bx lr

// DON'T FORGET TO UPDATE THE LINKER SCRIPT TOO!
VARM_TO_PREAMBLE(s_native_crit_init_default_xip_setup_and_enter_image_thunk)
VARM_TO_PREAMBLE(s_native_api_validate_ns_buffer)
VARM_TO_MULTIPLEX_PREAMBLE(s_native_crit_launch_nsboot)
VARM_TO_MULTIPLEX_PREAMBLE(s_native_crit_xip_cache_maintenance)

#if !USE_64K_BOOTROM
.section .sg_fillers
#else
.section .vectors, "ax"
#endif

// we clear USB SRAM (aka .bss and stack), and switch stack
.global varm_to_s_native_secure_call_pc_sp
.thumb_func
varm_to_s_native_secure_call_pc_sp: // (pc, sp or 0)
    movs r3, #MULTIPLEX_s_native_secure_call_pc_sp
    varm_hint HINT_MULTIPLEX
.global s_varm_secure_call // same function but called directly under varmulet
.thumb_func
s_varm_secure_call:
    push {r4, r5, r6, lr} // maintain stack align to call into user code
#if FEATURE_CANARIES
    rcp_canary_get_nodelay r6, CTAG_S_VARM_SECURE_CALL // used to check after call returns
    push {r6, r7} // maintain stack align to call into user code
    // canary value is now at [sp, #0]
#endif
    mov r4, sp
    mrs r5, msplim
    cbz r1, 1f // 0 sp means use current
    // Clear splim before setting sp, since our splim is likely higher than their sp
    movs r6, #0
    msr msplim, r6
    mov sp, r1
1:
#if FEATURE_CANARIES
    rcp_count_check_nodelay STEPTAG_S_VARM_SECURE_CALL
#endif
    // This will trap if you didn't set the Thumb bit! (Deliberate safeguard
    // against accidentally entering a RISC-V function pointer under Arm)

    // hardening: done
    blx r0

    msr msplim, r5
    mov sp, r4
#if !FEATURE_CANARIES
    pop {r4, r5, r6, pc}
#else
    // canary is popped into r2, r3 is trashed, r4-r6 & lr get their values
    pop {r2, r3, r4, r5, r6, lr}
    rcp_count_set STEPTAG_STEP8_TRY_VECTOR // used in the boot path
    rcp_canary_check_nodelay r2, CTAG_S_VARM_SECURE_CALL
    // hardening: ok
    bx lr
#endif

.global s_arm8_usb_client_ns_call_thunk // (secure_stack_base, secure_stack_size)
.thumb_func
s_arm8_usb_client_ns_call_thunk:
    rcp_count_check STEPTAG_NSBOOT_OTP_ADVANCE // otp should have been advcance
    add r1, r0
    // Set secure stack limit. Note setting SPLIM to a value greater than SP
    // does not trigger a fault -- the fault is always on an SP-setting
    // instruction that sets SP < SPLIM.
    msr msplim, r0
    // Secure SP, presumed MSP as we do not set SPSEL. (mov sp is smaller than msr msp)
    mov sp, r1
    // Set NonSecure stack
    ldr r2, =USBCTRL_DPRAM_BASE + USBCTRL_DPRAM_SIZE
    msr msp_ns, r2

    // does not return
    ldr r0, =NSBOOT_ENTRY_POINT & ~1
    ldr r1, =PPB_BASE + M33_VTOR_OFFSET
    adds r1, #M33_MPU_CTRL_OFFSET - M33_VTOR_OFFSET
    movs r2, #0
    // clear all other regs
    ldmia r0, {r3-r12}
    // disable MPU at the last minute
    str r2, [r1, #0]
    rcp_count_check STEPTAG_NSBOOT_OTP_ADVANCE + 1
    // hardening: done
    bxns  r0

.section .rodata.keep
.p2align 2
.global partition_table_ptr
partition_table_ptr:
.word BOOTRAM_BASE + BOOTRAM_ALWAYS_PARTITION_TABLE_OFFSET

.global flash_devinfo16_ptr
flash_devinfo16_ptr:
.word BOOTRAM_BASE + BOOTRAM_ALWAYS_FLASH_DEVINFO_OFFSET

xip_setup_func_ptr:
.word BOOTRAM_BASE + BOOTRAM_XIP_SETUP_CODE_OFFSET

