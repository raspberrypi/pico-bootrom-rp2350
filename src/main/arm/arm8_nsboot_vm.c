/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bootrom.h"
#include "nsboot_secure_calls.h"
#include "bootram.h"
#include "varm_boot_path.h"
#include "hardware/regs/intctrl.h"
#include "hardware/structs/nvic.h"
#include "hardware/structs/scb.h"
#include "hardware/structs/accessctrl.h"
#include "hardware/gpio.h"
#include "bootrom_layout.h"
#include "hardware/structs/sau.h"
#include "hardware/sync.h"

// Careful when adding to this function: anything non-Arm-specific added here must also be added to
// the RISC-V version of this function in riscv_nsboot_vm.c. It's better to hoist things into the
// common preamble in varm_nsboot.c if possible.
void __attribute__((used, noreturn)) s_native_crit_launch_nsboot(void) {
    // this is cleared here rather than in common calling code as the varmulet regs are at the bottom of it on RISC-V
#if !HACK_RAM_BOOTROM_AT
    s_native_crit_step_safe_mem_erase_by_words(SRAM_BASE, SRAM_END - SRAM_BASE);
#endif
    // install the NS vector table
    // must be 0x80 - NSBOOT_VTOR_OFFSET aligned (chosen 32 byte boundary based on size of nsboot + riscv)
    // note it is a bit of a pain to move, as the usb_irq vector must be shifted down by this amount
    // NS VTOR is at the start of the NS code offset by the offset, so we don't have to have NSBOOT itself 0x80 aligned (it just has irq_usbctrl in it);
    static_assert(!((NSBOOT_START + NSBOOT_VTOR_OFFSET)&0x7f), ""); // vtor must be 0x80 aligned
    scb_ns_hw->vtor = (uintptr_t)(NSBOOT_START + NSBOOT_VTOR_OFFSET);

    // note we remove secure ability to write here, since we don't expect secure code to write to USB RAM which NS can see all of
    // BEWARE this makes it IMPOSSIBLE to stack an exception frame in NS mode, but we don't need to do that.
    uint32_t pass_core0_sp_nsp_dbg_bits = __get_opaque_value(ACCESSCTRL_PASSWORD_BITS | ACCESSCTRL_UART0_CORE0_BITS | ACCESSCTRL_UART0_SP_BITS |
                                                             ACCESSCTRL_UART0_NSP_BITS | ACCESSCTRL_USBCTRL_DBG_BITS);
    accessctrl_hw->usbctrl = pass_core0_sp_nsp_dbg_bits;
#if MINI_PRINTF
    accessctrl_hw->uart[0] = pass_core0_sp_nsp_dbg_bits;
#endif
    static_assert(!(BOOTROM_SG_START & 0x1fu), "");
    static_assert(!(BOOTROM_SG_END & 0x1fu), "");
    // SAU is enabled, and NSC is setup in arm8_bootrom_rt0.S (since we make whole bootrom NS exposing IDAU settings)
    // give NS access to all of SRAM and XIP SRAM
#if !ASM_SIZE_HACKS
    INIT_SAU_REGION(2, SRAM_BASE, SRAM_END, false, true);
    INIT_SAU_REGION(3, XIP_SRAM_BASE, XIP_SRAM_END, false, true);
#else
    register uintptr_t rnr = (uintptr_t) &sau_hw->rnr;
    pico_default_asm_volatile(
            "movs r0, #2\n"
            "lsls r1, r0, #28\n"
            "ldr r2, = %c[sram_rbar]\n"
            "stmia %[p]!, {r0-r2}\n"
            "subs %[p], #12\n"
            "movs r0, #3\n"
            "ldr r1, = %c[xip_sram_base]\n"
            "ldr r2, = %c[xip_sram_rbar]\n"
            "stmia %[p]!, {r0-r2}\n"
            : [p] "+&l" (rnr)
            : [sram_rbar] "i" (SRAM_END - 32 + 0 * M33_SAU_RLAR_NSC_BITS + 1 * M33_SAU_RLAR_ENABLE_BITS),
              [xip_sram_base] "i" (XIP_SRAM_BASE),
              [xip_sram_rbar] "i" (XIP_SRAM_END - 32 + 0 * M33_SAU_RLAR_NSC_BITS + 1 * M33_SAU_RLAR_ENABLE_BITS)
            : "r0", "r1", "r2", "cc"
            );
#endif

    // want USB IRQ to be non-secure
    nvic_hw->itns[USBCTRL_IRQ/32] = 1u << USBCTRL_IRQ;

    if (nsboot_config->usb_activity_pin >= 0) {
        accessctrl_hw->pads_bank0 = pass_core0_sp_nsp_dbg_bits;
        accessctrl_hw->io_bank[0] = pass_core0_sp_nsp_dbg_bits;
        gpio_assign_to_ns((uint)nsboot_config->usb_activity_pin, true);
    }
    s_arm8_usb_client_ns_call_thunk(bootram->nsboot.arm.secure_stack, sizeof(bootram->nsboot.arm.secure_stack));
}
