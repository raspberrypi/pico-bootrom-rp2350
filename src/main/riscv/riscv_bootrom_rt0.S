/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bootrom.h"
#include "bootram.h"
#include "bootrom_layout.h"
#include "bootrom_riscv_asm_macros.inc.S"
#include "arm_imports.h"
#include "git_info.h"

// ----------------------------------------------------------------------------
// Bootrom Runtime 0
// ----------------------------------------------------------------------------
// This is not a full crt0 -- in particular, no .bss or .data initialisation
// (use of .data is disallowed via linker script assertions). The bootrom is
// not permitted to use statically-allocated memory, as parts of it are called
// into by user code.
// The purpose of this file is:
// - Provide initial entry point for both cores
// - Provide holding pen and launch code for core 1
// - Pass core 0 control over to the main boot sequence

#include "hardware/regs/accessctrl.h"
#include "hardware/regs/addressmap.h"
#include "hardware/regs/clocks.h"
#include "hardware/regs/intctrl.h"
#include "hardware/regs/pads_bank0.h"
#include "hardware/regs/powman.h"
#include "hardware/regs/resets.h"
#include "hardware/regs/rvcsr.h"
#include "hardware/regs/rvcsr.h"
#include "hardware/regs/sio.h"
#include "hardware/regs/sysinfo.h"
#include "hardware/regs/watchdog.h"

#if !SILICON_BUILD
#define USE_BOOT_TIMER 1
#endif

// ----------------------------------------------------------------------------
// Vectors and tables

// Hardware entry point is at very end of RISC-V ROM image (so that the
// beginning of the ROM image can be moved). This section also contains the
// well-known table, again to keep it in a fixed position.

.section .entry, "ax"
.option push
.option norelax
.option norvc

.global actual_software_git_revision
actual_software_git_revision:
.word GIT_REV

// 2 byte alignment needed, so store main_decode_table as it might be useful to people (dp table follows)
.hword varmulet_main_decode_table - __opaque_zero_symbol
_riscv_well_known_rom_table_base:
.hword BOOTROM_ROMTABLE_START
_riscv_well_known_func_table_lookup_val:
.hword riscv_table_lookup_val - __opaque_zero_symbol
_riscv_well_known_func_table_lookup_entry:
.hword riscv_table_lookup_entry - __opaque_zero_symbol
#if AXE_RISCV
.global __reset_vector
__reset_vector:
    j native_dead

.option pop

.section .vectors, "ax"
.p2align 2
.global native_dead
native_dead:
entry_table:
    j native_dead
riscv_table_lookup_val:
riscv_table_lookup_entry:
    .word 0
#else
.global __reset_vector
__reset_vector:
    // reset vector
    j riscv_entry_point

.option pop

.section .vectors, "ax"

// Vectoring is disabled in bootrom -- only a single trap handler.
// Traps will be either USB IRQs or exceptions.

.p2align 2
.global __mtvec
__mtvec:
    // Check exception before touching stack, to avoid exception loop when
    // stack pointer is invalid. (also take this opportunity to save ra)
    csrw mscratch, ra
    csrr ra, mcause
    bgez ra, native_dead

    // ISR runs with IRQs disabled, so only the caller saves need to be saved
    // (assuming the ISR doesn't take any exceptions!)
    addi sp, sp, -8
    sw t6,  4(sp)
    jal_force_rvc varmulet_save_a0_a7_t0_t5 // reuse this handy function to save space

    jal_force_rvc riscv_usb_irq_handler

    jal_force_rvc varmulet_restore_a0_a7_t0_t5 // reuse this handy function to save space
    lw t6,  4(sp)
    addi sp, sp, 8

    csrr ra, mscratch
    mret

// Args: 2-char symbol in a0, flag query in a1.
// Each table entry is a 2-char symbol, an hword of flags, and then 1 hword of
// data for each bit set in flags.
// Search the table for a symbol and a flag mask, and if *any* of those flags
// are found under the correct symbol, return a pointer to the first
// corresponding table data.
.global riscv_table_lookup_entry
riscv_table_lookup_entry:
    la_romaddr a3, BOOTROM_ROMTABLE_START
    mv a5, a0
    j _lookup_next_symbol
_lookup_skip_to_next:
    cpop a2, a2
    sh1add a3, a2, a3
_lookup_next_symbol:
    lhu a0, (a3)
    beqz a0, _lookup_return_ptr_a0
    lhu a2, 2(a3)
    addi a3, a3, 4
    bne a5, a0, _lookup_skip_to_next
    and a4, a1, a2
    beqz a4, _lookup_skip_to_next
_lookup_seek_result:
    ctz a4, a4
    not a4, a4
    sll a2, a2, a4
    slli a2, a2, 1
    cpop a2, a2
    sh1add a0, a2, a3
_lookup_return_ptr_a0:
    ret

riscv_table_lookup_val:
    mv t0, ra
    jal riscv_table_lookup_entry
#if BOOTROM_32BIT_FUNC_POINTERS
    beqz a0, 1f
    lw a0, (a0)
1:
#else
    // Note the first halfword of ROM is 0, so NULLs propagate naturally:
    lhu a0, (a0)
#endif
    jr t0

// Unfortunately `li label_b - label_a` is illegal (even though we can use it
// with .hword), so do not change the code without updating this define:
#if DEFAULT_RISCV_XIP_SETUP_SIZE_BYTES & 0x3
#error "Constant island for XIP setup stub must be word-aligned"
#endif

// This stub is relocated along with its following constant island:
s_native_default_xip_setup:
    auipc a2, 0                                            // 32-bit
    // Load args from second and third constant
    c.lw a0, 12 + 4(a2)                                    // 16-bit
    c.lw a1, 12 + 8(a2)                                    // 16-bit
    // Load and tail-call function pointer
    c.lw a2, 12 + 0(a2)                                    // 16-bit
    c.jr a2                                                // 16-bit
1:
// Absolute address of bootrom function:
    .word _rt_entry_s_varm_api_crit_flash_select_xip_read_mode + 4
s_native_default_xip_setup_end:
.if DEFAULT_RISCV_XIP_SETUP_SIZE_BYTES != s_native_default_xip_setup_end - s_native_default_xip_setup
.error "s_native_default_xip_setup is wrong size"
.endif
// Two argument words follow, set by bootrom after copying this code to
// boot RAM.

.global s_native_crit_init_default_xip_setup_and_enter_image_thunk
s_native_crit_init_default_xip_setup_and_enter_image_thunk:
    // a0 - XIP mode enum
    // a1 - XIP clkdiv
    // a2 = pc
    // a3 = sp
    // [on varm stack] = sp_lim       (ignored on RISC-V, used by Arm version of this function)
    // [on_varm_stack] = vector_table (ignored on RISC-V, used by Arm version of this function)
    cm.mvsa01 s0, s1
    mv s2, a2
    mv sp, a3

    // Note this wipes our stack, but we aren't returning. Memset is fine in
    // because the RISC-V bootrom memset is size-optimised, and does not use
    // any stack.
    li a0, BOOTRAM_BASE
    li a1, BOOTRAM_SIZE - BOOTRAM_ALWAYS_SIZE
    jal_force_rvc native_memset0

    // Copy default xip setup code into boot ram -- this code just restores
    // the XIP mode found by try_flash_boot. Note memset preserves a0.
#if BOOTRAM_XIP_SETUP_CODE_OFFSET != 0
    addi a0, a0, BOOTRAM_XIP_SETUP_CODE_OFFSET
#endif
    la_romaddr a1, s_native_default_xip_setup
    li a2, DEFAULT_RISCV_XIP_SETUP_SIZE_BYTES
    jal_force_rvc __memcpy_44
    // Write arguments for s_varm_flash_select_xip_read_mode after the default
    // XIP code. Note memcpy returns its dst in a0.
    sw s0, DEFAULT_RISCV_XIP_SETUP_SIZE_BYTES+0(a0)
    sw s1, DEFAULT_RISCV_XIP_SETUP_SIZE_BYTES+4(a0)

#if USE_BOOT_TIMER
    // Leaving the bootrom at this point, so stop measuring
    csrsi mcountinhibit, RVCSR_MCOUNTINHIBIT_CY_BITS
#endif

    jalr s2

    j native_dead

// __noreturn riscv_nsboot_launch_thunk(armulet_cpu_t *cpu, const varmulet_asm_hooks_t *hooks, uintptr_t bootram_stack_top);
.global riscv_nsboot_launch_thunk
riscv_nsboot_launch_thunk:
#if !SWAP_RISCV_NSBOOT_STACKS
    li sp, USBCTRL_DPRAM_BASE + USBCTRL_DPRAM_SIZE
#else
    // passed as arg since the caller has it
    mv sp, a2
#endif
    jal_force_rvc varmulet_run_adapter
// fall thru to dead

// Send USB symbols to _dead if USB not linked (hack)
.global isr_usbctrl
.weak isr_usbctrl
isr_usbctrl:

.global async_task_worker
.weak async_task_worker
async_task_worker:

// ^^ make sure fall thrus from above are not disturbed
.global native_dead, native_wait_rescue
_wait_rescue:
native_dead:
#if BREAKPOINT_AT_DEAD
    ebreak
#endif
    wfi
    j native_dead

// ----------------------------------------------------------------------------
// Entry point for both cores
// ----------------------------------------------------------------------------

.global riscv_entry_point
riscv_entry_point:

#if HACK_RAM_BOOT && !HACK_RAM_BOOTROM_AT
//    we should not do this - the user who is booting into RAM should not turn them off when doing so
//    // make sure RAM is accessible

    // we jmp to powman_scratch[6] if top half of powman_scratch[5] = 0x27eb
    li a0, POWMAN_BASE + POWMAN_SCRATCH4_OFFSET
    li a1, 0x27eb
    lh a2, 6(a0)
    bne a1, a2, 1f
    lw a1, 8(a0)
    jr a1
1:
#endif
    // Set misaligned gp to trap most accidental gp usage (bootrom should only
    // use gp for nsboot .allowed_bss relaxation)
    li gp, -31
    // Invalid stack (bad alignment and pointing into address hole); neither
    // core should use any stack until a valid one is provided later
    li sp, -31
    la_romaddr a0, __mtvec
    csrw mtvec, a0

    // Clear varmulet_enclosing_cpu pointer for this core -- needed for some
    // IRQ reentrancy stuff with auto-emulated ROM calls from user code.
    li a0, BOOTROM_STATE_RESET_CURRENT_CORE
    jal s_native_api_bootrom_state_reset

// Check if this is core 0, and go to holding pen if not
check_core:
    // NOTE: We DO NOT use any stack prior to possible watchdog entry
    csrr a0, mhartid
    bnez a0, wait_for_vector

#if USE_BOOT_TIMER
    // Start cycle counter on core 0, for measuring boot time
    csrw mcycle, zero
    csrci mcountinhibit, RVCSR_MCOUNTINHIBIT_CY_BITS
#endif

    // -----------------------------------------------------------------
    // we now enter the ARM8-baseline boot path under varmulet, and do not return
    // -----------------------------------------------------------------
clear_varmulet_state:
    // 1. We want as much ARM6 stack as possible, and do not ever need to return.
    // 2. We need to be able to call into RISC-V code via HINT instructions, however do not want to use a separate stack
    //    as we don't have much space (127 words) to divvy up into two separate stacks
    //
    // So
    // i.  We set the ARM6 SP to the top of our own current RISC-V stack!!! this is OK as the ARM6 stack won't be used for a bit
    // ii. We set the ARM6 PC to a HINT 0xf instruction, which will set the RISC-V SP to INVALID_STACK_PTR after varmulet has
    //     been initialized (we don't need any of the saved context as we aren't returning)
    // iii. We set LR to the varm_core0_boot_path, as the "HINT 0xf" will execute an ARM6 "bx lr"

    // Clear the Arm registers' initial location, which is in our stack redzone at the bottom of our
    // allocated stack space (a little frisky but we don't use much stack until later in the arm6
    // boot path, and by that point we've relocated)
    #if !(BOOTRAM_PREBOOT_STACK_TOP & 4)
    #error expect un-aligned stack top for now
    #endif
    li a0, BOOTRAM_BASE + BOOTRAM_RISCV_PREBOOT_VARMULET_CPU_STATE_OFFSET
    addi sp, a0, BOOTRAM_PREBOOT_STACK_TOP - \
        (BOOTRAM_BASE + BOOTRAM_RISCV_PREBOOT_VARMULET_CPU_STATE_OFFSET)
    li a1, VARMULET_CPU_STATE_SIZE + BOOTRAM_PREBOOT_WORKAREA_SIZE // we want to clear the preboot workarea too (don't clear all of RAM to save time)
    jal_force_rvc native_memset0 // stackless function, preserves a0

#if ARMULET_FEATURE_ARMV8M_BASELINE_MSPLIM
    addi a1, sp, -BOOTRAM_PREBOOT_STACK_SIZE
    sw   a1, 72(a0)
#endif
    sw sp, (13*4)(a0) // arm6 sp
    // note the weird address is because we skip the callee-saving which wastes
    // our limited stack space for a function that will never return
    la_romaddr a1, __armexport_s_varm_crit_core0_boot_path_entry_p2 - 2
    sw a1, (14*4)(a0) // arm6 lr
    la_romaddr a2, hint0xf_instruction
    sw a2, (15*4)(a0) // arm6 pc
    la_romaddr a1, varmulet_preboot_asm_hooks
    j_force_rvc varmulet_run_adapter

hint0xf_instruction:
    .hword 0xbf00 + HINT_INVALIDATE_NATIVE_SP * 16


// ----------------------------------------------------------------------------
// Hold/launch code for Core 1
// ----------------------------------------------------------------------------
// Core 0 will bring core 1 up once it has gone through the sequence of setting
// up flash etc.
//

send_and_then_again:
    // in case of multiple core 1 resets, we can keep pushing and fill the FIFO
    // we should wait for an event if the FIFO is full to avoid busy wait
    h3.block
// takes a0 = word to send, a4 = SIOB_BASE, a5 link register
send_and_then:
    lw a1, SIO_FIFO_ST_OFFSET(a4)
    slli a1, a1, 31 - SIO_FIFO_ST_RDY_LSB
    bgez a1, send_and_then_again
    sw a0, SIO_FIFO_WR_OFFSET(a4)
    h3.unblock
    jr a5

wait_for_vector:
    li a4, SIO_BASE
    // Allow the h3.block instruction to release system wake request, but don't gate the processor
    // clock (msleep.deepsleep) because this blocks System Bus Access when asleep (Hazard3 v1.0 rc1
    // erratum). The power difference should be minimal, as the hierarchical clock gating should
    // still trim most of the processor clock tree during a pipeline stall, and if SBA is not
    // required then core 1 can be woken and sent into a full deep sleep state.
    csrwi RVCSR_MSLEEP_OFFSET, ( \
        RVCSR_MSLEEP_SLEEPONBLOCK_BITS | \
        RVCSR_MSLEEP_POWERDOWN_BITS \
    )

    // note core_0_handshake_loop is the intended next instruction, but the read is harmless
    // as we're about to drain, so don't waste an instruction branching
1:
    lw a1, SIO_FIFO_RD_OFFSET(a4)
core_0_handshake_loop:
    // drain the FIFO before sending 0
    lw a1, SIO_FIFO_ST_OFFSET(a4)
    slli a1, a1, 31 - SIO_FIFO_ST_VLD_LSB
    bltz a1, 1b

    // ...and_then = receive_and_check-zero (which jmps to core_0_handshake_loop on 0)
    la_romaddr a5, receive_and_check_zero
    // send 0
    li a0, 0
    jal send_and_then
    // check for cmd 1
    addi a1, a0, -1
    bnez a1, core_0_handshake_loop
    // ack and receive VTOR
    jal send_and_then
    csrw mtvec, a0
    // ack and receive SP
    jal send_and_then
    // initialize
    mv sp, a0
    jal send_and_then
    la_romaddr a5, core1_launch
    // receive IP (0 sends us back into handshake loop)
    jal send_and_then
core1_launch:
    // size: we could rework a0 to s0 above to save an instruction
    mv  s0, a0

    csrwi RVCSR_MSLEEP_OFFSET, 0
    jalr s0

// Low power hang on return. Reset the core if you want to provide another entry point
// (There is no need to return though)
//
// alternatively you could return directly to wait_for_vector (available in the function table)
// if you know core 1 is still in a good state
    j native_dead

// takes a4 = SIO_BASE
// returns a0 = word received
receive_and_check_zero:
    h3.block
    lw a0, SIO_FIFO_ST_OFFSET(a4)
    slli a0, a0, 31 - SIO_FIFO_ST_VLD_LSB
    bgez a0, receive_and_check_zero

    lw a0, SIO_FIFO_RD_OFFSET(a4)
    // if we received 0, we reset back to main loop
    beqz a0, core_0_handshake_loop
.global native_noop
native_noop:
    ret

// ----------------------------------------------------------------------------
// Trampolines
// ----------------------------------------------------------------------------

// a0: function pointer
// a1: stack pointer (or 0 to use caller's stack)
.global s_native_secure_call_pc_sp
s_native_secure_call_pc_sp:
    cm.push	{ra,s0}, -16
    mv s0, sp
    beqz a1, 1f
    mv sp, a1
1:
    // Assert that the LSB is clear (i.e. the Thumb bit on Arm) -- safeguard
    // against accidentally passing Arm function pointer to RISC-V startup
    andi a2, a0, 0x1
    bnez a2, native_dead

#if USE_BOOT_TIMER
    // Leaving the bootrom at this point, so stop measuring
    csrsi mcountinhibit, RVCSR_MCOUNTINHIBIT_CY_BITS
#endif
    jalr ra, a0
    mv sp, s0
    cm.popret {ra,s0}, +16

// Branch predictor doesn't reliably kick in for a loop containing only a
// single 16-bit, word-aligned instruction (doesn't misexecute, you just
// don't win the prediction cycle) so make the body 32-bit, and align the
// function to ensure we don't pay a fetch align penalty:
.global s_native_busy_wait_at_least_cycles
.p2align 2
s_native_busy_wait_at_least_cycles:
1:
#ifdef __riscv_zca
    // Workaround for assembler bug (this is the same as below)
    .insn i 0x13, 0, a0, a0, -2
#else
.option push
.option norvc
    addi a0, a0, -2
.option pop
#endif
    bgez a0, 1b
    ret

// This is mostly a shared varm function, but there is a native RISC-V prelude
// to it which can't be executed under varmulet because it is resetting
// actual varmulet state, which is saved/restored in varm_wrapper:
.global s_native_api_bootrom_state_reset
s_native_api_bootrom_state_reset:
    li a5, BOOTROM_STATE_RESET_CURRENT_CORE
    and a4, a0, a5
    beqz a4, 2f
    // Clear current CPU varmulet state (the caller must be RISC-V as this is RISC-V code!)
    li a3, BOOTRAM_BASE + BOOTRAM_RUNTIME_CORE0_VARMULET_USER_STACK_SIZE_OFFSET
    csrr a4, mhartid
    beqz a4, 1f
    addi a3, a3, BOOTRAM_RUNTIME_CORE1_VARMULET_USER_STACK_SIZE_OFFSET - BOOTRAM_RUNTIME_CORE0_VARMULET_USER_STACK_SIZE_OFFSET
1:
    li a4, 0
    sw a4, (a3)
    sw a4, (BOOTRAM_RUNTIME_CORE1_VARMULET_ENCLOSING_CPU_OFFSET - BOOTRAM_RUNTIME_CORE1_VARMULET_USER_STACK_SIZE_OFFSET)(a3)
    // Return if there was nothing else to do -- ensures we don't use stack
    // when called during core 1 launch
    bne a0, a5, 2f
    ret
2:
    // Tail into the remainder of this function, in shared code.
    jal a4, load_a4_goto_varm_wrapper
.hword __armexport_s_varm_step_safe_api_crit_bootrom_state_reset_addr

_:

#endif
