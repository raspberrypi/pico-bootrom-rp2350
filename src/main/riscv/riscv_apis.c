/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pico.h"
#include "bootram.h"
#include "mini_printf.h"

void __attribute__((noreturn)) bootrom_assertion_failure(__unused const char *fn, __unused uint line) {
#if MINI_PRINTF
    printf("ASSERTION FAILURE %s:%d\n", fn, line);
#endif
    __breakpoint();
    __builtin_unreachable();
}

int __used s_native_set_varmulet_user_stack(uint32_pair_t *base_size) {
    int rc;
    // commented this out, as bootrom was built with older SDK for which restore_interrupts was a CSR write not set
    // uint32_t save = save_and_disable_interrupts();
    uint32_t save;
    pico_default_asm_volatile (
            "csrrci %0, mstatus, 0x8\n"
    : "=r" (save)
    );

    uint core_num = riscv_read_csr(mhartid);
    if (bootram->runtime.core[core_num].riscv.varmulet_enclosing_cpu) {
        rc = BOOTROM_ERROR_INVALID_STATE;
    } else {
        uint32_pair_t *current_base_size = &bootram->runtime.core[core_num].riscv.varmulet_user_stack_pair;
        uint32_pair_t tmp = *current_base_size;
        *current_base_size = *base_size;
        *base_size = tmp;
        rc = BOOTROM_OK;
    }
    // This flag may be clear if we left the bootrom through a PC/SP vector
    // which didn't return. Now that the user has called back and explicitly
    // given us a stack, it seems polite to let them use it.
    if (core_num == 0) {
        bootram->always.zero_init.allow_core0_autovarm = 1;
    }

    // commented this out, as bootrom was build with old code that just did read_csr/write_csr
    // restore_interrupts(save);
    riscv_write_csr(mstatus, save);
    return rc;
}
