/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if PICO_RP2350
#include "pico.h"
#endif

#include "varmulet_macros.inc.S"
#include "bootrom.h"
#include "nsboot_secure_calls.h"
#include "arm_imports.h"
#include "bootrom_riscv_asm_macros.inc.S"
#include "hardware/regs/intctrl.h"
#include "hardware/regs/sha256.h"

#if !FEATURE_HWORD_ASM_HOOKS && !FEATURE_BYTE_ASM_HOOKS
#define ASM_HOOK(x) .word x
#elif FEATURE_HWORD_ASM_HOOKS
#define ASM_HOOK(x) .hword x - __opaque_zero_symbol
#else
#include "asm_hook_ordinals.h"
#define ASM_HOOK(x) .byte ASM_HOOK_ ## x
#endif

.macro next_instr_shared_if_smaller
#if VARMULET_USE_EARLY_INSTR_READ
// Hooks are less hot than emulator internals, so if `next_instruction` is
// more than a simple `jr`, share it across all hooks.
    j next_instruction_label
#else
    next_instruction
#endif
.endm

.global varmulet_nsboot_asm_hooks
// NOTE this is a copy of the default table with modifications, so we don't have to waste
// RAM at runtime, taking a copy and updating a few pointers
.section .rodata.varmulet_nsboot_asm_hooks
#if !FEATURE_HWORD_ASM_HOOKS && !FEATURE_BYTE_ASM_HOOKS
.p2align 2
#else
.p2align 1
#endif
varmulet_nsboot_asm_hooks:
    ASM_HOOK(varmulet_hook_default_enter_fn)
    ASM_HOOK(varmulet_hook_default_exit_fn)
    ASM_HOOK(varmulet_hook_default_save_regs_fn)
    ASM_HOOK(varmulet_hook_default_restore_regs_fn)
#if !VARMULET_USE_ENTER_HOOK_TO_OVERRIDE_REGISTER_STORED_HOOKS
    ASM_HOOK(varmulet_hook_default_execute_instruction)
    ASM_HOOK(varmulet_main_decode_table)
    ASM_HOOK(varmulet_dp_decode_table)
#endif
    ASM_HOOK(varmulet_halt)            // (undefined16)
    ASM_HOOK(bootrom_undefined32_sg_and_rcp_check)      // we allow some armv8m instructions
    ASM_HOOK(varmulet_hook_default_bkpt_instr)
    ASM_HOOK(bootrom_hint_instr)
    ASM_HOOK(varmulet_halt)            // we don't use SVC
    ASM_HOOK(varmulet_hook_default_cps_instr)
    ASM_HOOK(varmulet_hook_default_mrs_instr)
    ASM_HOOK(varmulet_hook_default_msr_instr)
    ASM_HOOK(varmulet_hook_default_misc_control_instr)
    ASM_HOOK(bootrom_update_primask_fn) // we respect PRIMASK settings
.global varmulet_hooks_default_exc_and_call_return
varmulet_hooks_default_exc_and_call_return:
    ASM_HOOK(varmulet_hook_default_exc_return)
    ASM_HOOK(varmulet_hook_default_call_return)

// back to back so easy to find
//.section .rodata.varmulet_preboot_asm_hooks
//.p2align 2
.global varmulet_preboot_asm_hooks
varmulet_preboot_asm_hooks:
    ASM_HOOK(varmulet_hook_default_enter_fn)
    ASM_HOOK(varmulet_hook_default_exit_fn)
    ASM_HOOK(varmulet_hook_default_save_regs_fn)
    ASM_HOOK(varmulet_hook_default_restore_regs_fn)
#if !VARMULET_USE_ENTER_HOOK_TO_OVERRIDE_REGISTER_STORED_HOOKS
    ASM_HOOK(varmulet_hook_default_execute_instruction)
    ASM_HOOK(varmulet_main_decode_table)
    ASM_HOOK(varmulet_dp_decode_table)
#endif
    ASM_HOOK(varmulet_halt)            // (undefined16)
    ASM_HOOK(bootrom_undefined32_rcp_check) // allow canary instrutions
    ASM_HOOK(varmulet_hook_default_bkpt_instr)
    ASM_HOOK(bootrom_hint_instr)
    ASM_HOOK(varmulet_halt)            // we don't use SVC
    ASM_HOOK(varmulet_halt) // cps
    ASM_HOOK(varmulet_halt) // mrs
    ASM_HOOK(varmulet_halt) // msr
    ASM_HOOK(varmulet_hook_default_misc_control_instr)
    ASM_HOOK(varmulet_halt) // primask
    ASM_HOOK(varmulet_halt) // no exec return
    ASM_HOOK(varmulet_halt) // no call return

.section .text.bootrom_asm_hooks

bootrom_undefined32_sg_and_rcp_check:
    pack        r_tmp0, r_work2, r_inst
    li          r_tmp1, 0b11101001011111111110100101111111
    bne         r_tmp0, r_tmp1, bootrom_undefined32_rcp_check

    // fall thru to SG
bootrom_sg_instr:
    // for SG we're just going to return execution at a new PC via arm6 code
    la_romaddr  r_pc, __armexport_s_from_nsboot_varm_service_call_no_boot_once_check
    next_instr_shared_if_smaller

// Coprocessor encodings:
// p = opc1
// P = opc2
// n = coprocessor number
// . = named field continues in this bit
//           31               16 15                0
// bit%16 -> fedc ba98 7654 3210 fedc ba98 7654 3210
// mcr       1110 1110 ppp0 CRn. rrrr nnnn PPP1 CRm.
// mcr2      1111 1110 ppp0 CRn. rrrr nnnn PPP1 CRm.
// mrc       1110 1110 ppp1 CRn. rrrr nnnn PPP1 CRm.
// mrc2      1111 1110 ppp1 CRn. rrrr nnnn PPP1 CRm.
// mcrr      1110 1100 0100 Rt2. Rt.. nnnn pppp CRm.
// mcrr2     1111 1100 0100 Rt2. Rt.. nnnn pppp CRm.
// mrrc      1110 1100 0101 Rt2. Rt.. nnnn pppp CRm. (not used by RCP)
// mrrc2     1110 1100 0101 Rt2. Rt.. nnnn pppp CRm. (not used by RCP)
// cdp       1110 1110 pppp CRn. CRd. nnnn PPP0 CRm.
// cdp2      1111 1110 pppp CRn. CRd. nnnn PPP0 CRm.
//
// This decode is only for use in the bootrom, and we are just mocking the interface so that v6 code
// with v8 coproc instructions embedded in it will still run (not trying to actually implement the
// coprocessor), so we make some assumptions:
//
// - All coprocessor instructions address cp7, the redundancy coprocessor aka RCP -- the other
//   options are the GPIO coprocessor and the two instances of the double float coprocessor, none
//   of which are used in the bootrom
//
// - Everything other than canary status check into APSR_nzcv can be a NOP(so canary reads will not
//   actually set the destination register, which is ok, because we don't check the canary value)
//
// - All parity bits are correct (CRm[3] or opc2[0])
//
// - All other instructions prefixed with 111x11xx (floating-point: register moves, load/stores,
//   data-processing; some unallocated opcode space) are not used in the bootrom and so we can
//   decode with just this prefix

.global bootrom_undefined32_rcp_check
bootrom_undefined32_rcp_check:
    pack        r_tmp0, r_work2, r_inst
    // Anything starting with 111x11xx is definitely a coprocessor instruction if we're at a valid
    // bootrom address. Anything else might be an RCP constant mov
    srli        r_tmp1, r_tmp0, 24
    andi        r_tmp1, r_tmp1, 0xec
    xori        r_tmp1, r_tmp1, 0xec
    bnez        r_tmp1, rcp_const_check
    // If bits 24:20 are 00011 then this is a canary status check (mrc/mrc2 with opc1 == 001) and we
    // assume it is writing to APSR_nzcv. For other bit patterns we just NOP.
    h3.bextmi   r_tmp1, r_tmp0, 20, 5
    addi        r_tmp1, r_tmp1, -3
    // (keep this branch short so it's 16-bit)
    bnez        r_tmp1, 1f
    // For canary status check, set N & V to indicate that we are varmulet and not real RCP
    li          r_lazy_nz, -1
    mv          r_topbit_v, r_lazy_nz
1:
    next_instr_shared_if_smaller

rcp_const_check:
    li          r_tmp2, 0xf04f0000
    sub         r_tmp0, r_tmp0, r_tmp2
    srli        r_tmp0, r_tmp0, 16
    bnez        r_tmp0, hang
    // this implementation makes us just too big for 8 bit asm_hook offsets, so move it to the bootrom
    // (it is pretty rare)
    j rcp_const_impl

hang:
#if MINI_PRINTF
    j_force_rvc hang_printf // branch because debug code makes the hooks > 512 bytes (too big for 8 bit offset table)
#else
    j_force_rvc varmulet_halt
#endif

// overriden to actually disable/enable IRQs
bootrom_update_primask_fn:
    sb          r_work0, CPU_OFFSET_PRIMASK(r_cpu)
    // Assume it's harmless to toggle IRQs off for a cycle (save a j instruction)
    csrci       mstatus, 0x8
    bnez        r_work0, 1f
    // Shared with native_usb_irq_enable -- every CSR instruction is precious!
shared_enable_irqs_and_return:
    csrsi       mstatus, 0x8
1:
    ret

// Hint instructions (bfx0 encoding space): NOP, YIELD etc. We overload "spare" hint numbers to inject native
// RISC-V code into the varm context.
.global bootrom_hint_instr
bootrom_hint_instr:
    // Get table address in ra
    jal bootrom_hint_instr_impl
// Note __opaque_zero_symbol is used to make these relative rather than absolute relocs, to work
// around RISC-V linker limitations
hint_table:
    .hword /*0*/ next_instruction_label                                     - __opaque_zero_symbol // NOP
    .hword /*1*/ next_instruction_label                                     - __opaque_zero_symbol // YIELD
    .hword /*2*/ bootrom_wfe                                                - __opaque_zero_symbol
    .hword /*3*/ bootrom_wfi                                                - __opaque_zero_symbol
    .hword /*4*/ bootrom_sev                                                - __opaque_zero_symbol
    .hword /*5*/ s_native_relocate_varm_registers                           - __opaque_zero_symbol
    .hword /*6*/ hint_multiplex                                             - __opaque_zero_symbol
    .hword /*7*/ hint_invalidate_native_sp                                  - __opaque_zero_symbol
    .hword /*8*/ hint_trng_shovelling                                       - __opaque_zero_symbol
    .hword /*9*/ hint_hx_get_boot_flag_impl                                 - __opaque_zero_symbol
    .hword /*a*/ s_native_crit_flash_put_get                                - __opaque_zero_symbol
    .hword /*b*/ s_native_busy_wait_at_least_cycles                         - __opaque_zero_symbol
    .hword /*c*/ s_native_crit_init_default_xip_setup_and_enter_image_thunk - __opaque_zero_symbol
    .hword /*d*/ s_native_api_validate_ns_buffer                            - __opaque_zero_symbol
    .hword /*e*/ native_memcpy                                              - __opaque_zero_symbol
    .hword /*f*/ native_memset                                              - __opaque_zero_symbol
multiplex_table:
    .hword       native_nsboot_init                                         - __opaque_zero_symbol // 0
    .hword       native_usb_irq_enable                                      - __opaque_zero_symbol // 1
#if FEATURE_RISCV_USB_BOOT
    .hword       native_usb_packet_done                                     - __opaque_zero_symbol // 2
#else
    .hword       native_dead                                                - __opaque_zero_symbol // 2
#endif
    .hword       s_native_crit_xip_cache_maintenance                        - __opaque_zero_symbol // 3
    .hword       s_native_secure_call_pc_sp                                 - __opaque_zero_symbol // 4
    .hword       stack_reset_then_s_native_launch_nsboot                    - __opaque_zero_symbol // 5
multiplex_table_end:
.if multiplex_table_end - multiplex_table != NUM_MULTIPLEX * 2
.error multiplex table size wrong
.endif

.p2align 2
bootrom_hint_instr_impl:
    h3.bextmi   r_tmp0, r_inst, 4, 4
    andi        r_inst, r_inst, 0xf
    // this should really be vexecute_undefined, but for bootrom purposes we
    // know there are no bfxy instructions for y != 0, so use hang instead,
    // which is within range of a 16-bit branch:
    bnez        r_inst, hang
_shared_hint_lookup_tail:
    // No bounds checking as this is a full 4-bit LUT
    sh1add      r_tmp1, r_tmp0, ra
    // unsigned because this is an absolute 16-bit address
    // note a5 is r_inst, which is no longer needed.
    lhu         a5, (r_tmp1)

    // Higher-numbered hints call native code, and then execute a "jr lr" -
    // i.e. we can replace a function by starting the Arm code with such a
    // hint instruction. Check:
#if HINT_FIRST_TO_REQUIRE_MARSHALLING == 8
    // (smaller special case)
    srli        r_tmp0, r_tmp0, 3
    bnez        r_tmp0, bootrom_call_native_and_bx_lr
#else
    addi        r_tmp0, r_tmp0, -HINT_FIRST_TO_REQUIRE_MARSHALLING
    bgez        r_tmp0, bootrom_call_native_and_bx_lr
#endif
    // Lower-numbered hints are just extensions of the emulator, which we
    // enter directly before tailing into the next instruction
    jr          a5

// hoisted to get hint_multiplex word-aligned
bootrom_wfe:
    h3.block
    next_instr_shared_if_smaller

// Multiplexed hints go first through the shared hint table entry, and are then folded back for a
// second lookup in the extended part of the table, indexed by varm register r3
hint_multiplex:
    lw          r_tmp0, CPU_OFFSET_R3(r_cpu)
#if !BOOTROM_ASSERT_DISABLED
    li          r_tmp1, NUM_MULTIPLEX
    bgeu        r_tmp0, r_tmp1, hang
#endif
    addi        r_tmp0, r_tmp0, 16
    // Multiplex hints are an extension to the main table, so offset by the number of base hints:
    j           _shared_hint_lookup_tail

bootrom_wfi:
    wfi
    next_instr_shared_if_smaller
bootrom_sev:
    h3.unblock
    next_instr_shared_if_smaller

#if MINI_PRINTF
hang_printf:
    mv          a2, r_pc
    mv          a1, r_tmp0
    la_romaddr  a0, formato
    li sp,      SRAM_END
    jal         mini_printf
    j           varmulet_halt

#endif
rcp_const_impl:
    r_ptr32_11_8 r_tmp2
    // note we only handle a few constant types
    zext.b      r_tmp0, r_work2
    pack        r_tmp0, r_tmp0, r_tmp0
    bexti       r_tmp1, r_work2, 12
    bexti       r_work2, r_work2, 13
    packh       r_tmp1, r_tmp1, r_work2
    mul         r_tmp0, r_tmp0, r_tmp1
    sw          r_tmp0, (r_tmp2)
    next_instr_shared_if_smaller

s_native_relocate_varm_registers:
    // This hint is used to relocate the varmulet register file store to a location defined by the
    // Arm code. We use this to move the registers from Arm stack redzone in bootram (!) to USB
    // RAM, early in the arm6 boot path. This allows full use of the stack at later points, and
    // also improves the performance of emulated code since USB RAM is faster. We don't start off
    // with the registers in USB RAM as we don't want to trash it.

    // Destination is passed in Arm r0, so copy the register file contents over there:
    lw r_tmp0, CPU_OFFSET_R0(r_cpu)
    mv r_tmp1, r_cpu
    // Point r_cpu at target immediately (assuming we are not being
    // interrupted when relocating -- otherwise do a lw r_cpu,(r_cpu) after
    // the copy, at a cost of 2 extra bytes)
    mv r_cpu, r_tmp0

    li r_tmp2, VARMULET_CPU_STATE_SIZE / 4
1:
    lw r_work0, (r_tmp1)
    sw r_work0, (r_tmp0)
    addi r_tmp1, r_tmp1, 4
    addi r_tmp0, r_tmp0, 4
    // Note counting in r_tmp2 is slower than bound checking r_tmp0, but lets
    // us use a 16-bit li for loop count, so saves 2 bytes
    addi r_tmp2, r_tmp2, -1
    bnez r_tmp2, 1b

    // That's it -- this is not a function call, we just augmented the arm6 context with a hint
    // instruction that relocates its register file.
    next_instr_shared_if_smaller

hint_invalidate_native_sp:
    // note this isn't a regular hint_trampoline function as calling such a function uses the stack
#if INVALID_STACK_PTR == 0xf0000000
    mv          sp, r_f0000000
#else
    li          sp, INVALID_STACK_PTR
#endif
    // we are a custom hint instruction that expects a target address in lr -- this is used for a
    // tricky manoeuvre when we first enter varm code from the RISC-V reset handler
    j            do_bx_lr

// r0: TRNG EHR pointer (must increment with reads)
// copy 8 words from r0 to SHA256_WDATA
hint_trng_shovelling:
    // The sequence of code we're replacing is of known size, so skip it
    // (this is a 16-bit instruction, so put it at the entry point)
    addi r_pc, r_pc, 12
    lw r_tmp0, CPU_OFFSET_R0(r_cpu)
    li r_tmp1, SHA256_BASE
    addi r_tmp2, r_tmp0, 32
1:
    lw r_work0, (r_tmp0)
    sw r_work0, SHA256_WDATA_OFFSET(r_tmp1)
    addi r_tmp0, r_tmp0, 4
    bltu r_tmp0, r_tmp2, 1b
    next_instruction

hint_hx_get_boot_flag_impl:
    // we just redirect to our simplified RISC-V version
    // symbol happens to be pretty low
    li r_pc,     __armexport_s_varm_riscv_hx_get_boot_flag_impl_addr
    next_instr_shared_if_smaller

stack_reset_then_s_native_launch_nsboot:
    li          sp, BOOTRAM_PREBOOT_STACK_TOP_DWORD_ALIGNED
    // Need to init gp for .allowed_bss references -- not done earlier to
    // guard against gp being trashed by scratch vectors (and to avoid
    // accidental use)
#if 1
    // EXEC2 may enter an image, and set gp, whilst still taking USB IRQs that
    // access .allowed_bss. Note when toggling this off, you need to also
    // comment out the __global_pointer$ assignment in the linker script
#if FEATURE_EXEC2
#error "Need to disable gp relaxation if EXEC2 is available -- change the if here, and edit the linker script"
#endif
.option push
.option norelax
    la_romaddr gp, __global_pointer$
.option pop
#endif
    // note s_native_launch_nsboot does not return
    j_force_rvc s_native_launch_nsboot

#if INVALID_STACK_PTR  != 0xf0000000
#error
#endif

bootrom_call_native_and_bx_lr: // function to call is in r_inst (register a5)
    mv          r_tmp1, r_asm_hooks // 16-bit instruction hoisted to entry point
    // if sp is INVALID_STACK_PTR (also 0xf0000000) then we are not using native stack for native code, and should use
    // the arm6 stack instead. we will then see r_f0000000 is 0 on return, and set native sp back to INVALID_STACK_PTR
    bne         r_f0000000, sp, 1f
    li          r_f0000000, 0
    lw          sp, CPU_OFFSET_SP(r_cpu)
1:
    // variant of call_hook_save_regs_fn -- we save r_asm_hooks in an s reg
    // (r_tmp0/r_tmp1 are s0/s1, so can be used to save over the native call)
    call_asm_hook_fn_trash_tmp2_work1 VASM_HOOKS_INDEX_SAVE_REGS_FN
    // mv          r_tmp1, r_asm_hooks (hoisted to entry point to avoid misaligned entry)
    mv          r_tmp0, r_cpu
    // load arguments into native registers before call
    lw          a0, CPU_OFFSET_R0(r_tmp0)
    lw          a1, CPU_OFFSET_R1(r_tmp0)
    lw          a2, CPU_OFFSET_R2(r_tmp0)
    lw          a3, CPU_OFFSET_R3(r_tmp0)
    jalr        a5 // r_inst
    // write back result to varm register file
    sw          a0, CPU_OFFSET_R0(r_tmp0)
    // variant of call_hook_restore_regs_fn0
    mv          r_asm_hooks, r_tmp1
    call_asm_hook_fn_trash_tmp2_work1 VASM_HOOKS_INDEX_RESTORE_REGS_FN
    bnez        r_f0000000, 1f
    li          r_f0000000, 0xf0000000
#if INVALID_STACK_PTR == 0xf0000000
    // (avoid duplicating literal)
    mv          sp, r_f0000000
#else
    li          sp, INVALID_STACK_PTR
#endif
1:
    // fall through
do_bx_lr:
    // now do a forced a branch to LR
    lw          r_tmp0, CPU_OFFSET_LR(r_cpu)
    // note: this is necessary, as check_exc_return also checks for returning into native code
    check_exc_return_to_tmp0_trash_tmp2_work1
    andi        r_pc, r_tmp0, ~1

    // fall through
next_instruction_label:
    next_instruction

#if ARMULET_FEATURE_ASM_HOOKS_IS_FUNCTION
varmulet_asm_hooks_fn:
    // r_tmp2 is index
    // we are allowed to trash work1
    lw r_work1, CPU_OFFSET_ASM_HOOK_PARAM(r_cpu)
#if FEATURE_BYTE_ASM_HOOKS
    add r_tmp2, r_tmp2, r_work1
    la_romaddr r_work1, first_hook_addr
    lbu r_tmp2, (r_tmp2)
    sh1add r_tmp2, r_tmp2, r_work1
#elif FEATURE_HWORD_ASM_HOOKS
    sh1add r_tmp2, r_tmp2, r_work1
    lhu  r_tmp2, (r_tmp2)
#else
    sh2add r_tmp2, r_tmp2, r_work1
    lw  r_tmp2, (r_tmp2)
#endif
    jr r_tmp2
#endif

#if MINI_PRINTF
formato:
    .string "GOT INVALID INSTRUCTION %p @ pc=%p\n"
#endif

.global native_usb_irq_enable
native_usb_irq_enable:
    // We assume, since nsboot should only be entered either from a cold reset
    // or via reboot-to-USB, that IRQ registers are in their reset states.
    // This means that mie is all zeroes, mstatus.mie is zero, and all
    // external IRQ force/enable array registers (Hazard3 IRQs) are zeroes.
    li a0, (1 << ((USBCTRL_IRQ % 16) + 16)) + (USBCTRL_IRQ / 16)
    csrw RVCSR_MEIEA_OFFSET, a0
    // set mie.meie, plus some RES0 bits which save an lui. I can do this
    // because I'm the implementer :)
#if USBCTRL_IRQ < 16
    // Actually this is smaller still
    srli a0, a0, USBCTRL_IRQ + 16 - RVCSR_MIE_MEIE_LSB
#else
    li a0, -RVCSR_MIE_MEIE_BITS
#endif
    csrw mie, a0

    // Global interrupt enable (share the CSR instruction)
    j shared_enable_irqs_and_return

.section .text.varmulet_run_adapter
.global varmulet_run_adapter
varmulet_run_adapter:
#if ARMULET_FEATURE_ASM_HOOKS_IS_FUNCTION
    // when using this feature, we store the hook table ptr in the CPU,
    // and pass our asm_hooks_fn as second arg instead
    sw a1, CPU_OFFSET_ASM_HOOK_PARAM(a0)
    la_romaddr a1, varmulet_asm_hooks_fn
#endif
    // fall thru into varmulet_run
.global varmulet_run_adapter_end
varmulet_run_adapter_end:

