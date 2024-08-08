/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pico.h"
#include "varmulet.h"
#include "bootrom.h"
#include "bootrom_layout.h"
#include "bootram.h"
#include "varmulet_hooks_bootrom.h"
#include "mini_printf.h"

static_assert(VARMULET_CPU_STATE_SIZE == sizeof(armulet_cpu_t), "");

// this is a wrapper used for autovarmed RISC-V bootrom APIs.
// Marked explicitly as used, as it's usually entered via fallthrough from an asm fragment.
int __used varm_wrapper(uint32_t p0, uint32_t p1, uint32_t p2, uint32_t p3, uintptr_t func_address) {
    uint c = riscv_read_csr(mhartid);
    if (!(c || bootram->always.zero_init.allow_core0_autovarm)) {
        printf("BLOCKING VARM WRAPPER as not allowed on core %d\n", c);
        return BOOTROM_ERROR_INVALID_STATE;
    }
    armulet_cpu_t *enclosing = bootram->runtime.core[c].riscv.varmulet_enclosing_cpu;
    // special value 1 means varmulet is not yet allowed
    armulet_cpu_t cpu; // use on stack CPU since we expect to return

#if !GENERAL_SIZE_HACKS
    // This turns into a memset, which is assumed to trash our args, and leads
    // to this function having an enormous prolog. We still initialise those
    // registers that are used by called varm code: r0-r3, pc, lr.
    armulet_reset_cpu(&cpu);
#endif

    if (enclosing) {
        // we continue below our small existing ARM stack; we could have used the native stack via additional shared stack support in varmulet,
        // however realistically we don't expect to use too much (most things we call use a handful of words), and the only time we're re-entrant (i.e. in this code path)
        // is if we are already were executing an ARM bootrom function, so must have taken a RISC-V IRQ, and then called another such
        // varm_wrapped API function (nested multiple times).
        // note also we now also provie a function to set the ARM stack to something bigger
        cpu.regs[ARM_REG_SP] = enclosing->regs[ARM_REG_SP];
    } else if (bootram->runtime.core[c].riscv.varmulet_user_stack_base) {
        cpu.splim = bootram->runtime.core[c].riscv.varmulet_user_stack_base;
        cpu.regs[ARM_REG_SP] = bootram->runtime.core[c].riscv.varmulet_user_stack_base + bootram->runtime.core[c].riscv.varmulet_user_stack_size;
    } else {
        cpu.splim = (uintptr_t)bootram->runtime.core[c].riscv.varmulet_stack;
        cpu.regs[ARM_REG_SP] = ((uintptr_t) bootram->runtime.core[c].riscv.varmulet_stack) +
                               sizeof(bootram->runtime.core[c].riscv.varmulet_stack);
    }
    cpu.regs[ARM_REG_R0] = p0;
    cpu.regs[ARM_REG_R1] = p1;
    cpu.regs[ARM_REG_R2] = p2;
    cpu.regs[ARM_REG_R3] = p3;
    cpu.regs[ARM_REG_PC] = func_address&~1u;
    cpu.regs[ARM_REG_LR] = ARMULET_CALL_RETURN_ADDRESS;
    bootram->runtime.core[c].riscv.varmulet_enclosing_cpu = &cpu;

    varmulet_asm_hooks_t hooks = varmulet_preboot_asm_hooks;

    // ok we need the HINT instructions
    //hooks.undefined32 = (uintptr_t)&bootrom_undefined32_canary_check;
    // bkpt causing ebreak is ok
    // hooks.bkpt_instr = (uintptr_t)&varmulet_halt;
    // already halt
    // hooks.svc_instr = (uintptr_t)&varmulet_halt;
   // hooks.hint_instr = (uintptr_t)&varmulet_hook_default_hint_instr;
    // we don't expect/support any such instructions in the wrapped functions
    //hooks.cps_instr = (uintptr_t)&varmulet_halt;
    //hooks.mrs_instr = (uintptr_t)&varmulet_halt;
    //hooks.msr_instr = (uintptr_t)&varmulet_halt;
    // hooks.update_primask_fn = (uintptr_t)&varmulet_halt;
    // misc control is ok as it just ignores dmb, dsb, isb
    // hooks.misc_control_instr = (uintptr_t)&varmulet_halt;
    // exc_return is ok, as all it does is implement the ARMULET_CALL_RETURN_ADDRESS support
    // hooks.exc_return = (uintptr_t)&varmulet_halt;

    // we need call return which also needs exc_return

#if !FEATURE_BYTE_ASM_HOOKS
    hooks.exc_return = (asm_hook_t)(uintptr_t)&varmulet_hook_default_exc_return;
    hooks.call_return = (asm_hook_t)(uintptr_t)&varmulet_hook_default_call_return;
#else
    static_assert(!(offsetof(varmulet_asm_hooks_t, exc_return) & 1), "");
    *(uint16_t *)__builtin_assume_aligned(&hooks.exc_return,2) = *(uint16_t *)__builtin_assume_aligned(varmulet_hooks_default_exc_and_call_return,2);
#endif

    int rc = varmulet_run_adapter(&cpu, &hooks);
    // restore enclosing ptr
    bootram->runtime.core[c].riscv.varmulet_enclosing_cpu = enclosing;
    return rc;
}
