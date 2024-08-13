/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pico.h"
#include "native_generic_flash.h"
#include "bootrom.h"
#include "varmulet.h"
#include "varmulet_hooks_bootrom.h"
#include "hardware/hazard3.h"
#include "hardware/structs/usb.h"
#include "bootrom_layout.h"
#include "bootrom_otp.h"
#include "bootram.h"
#include "mini_printf.h"
#include "nsboot_secure_calls.h"
#include "hardware/irq.h"
#include "usb_device.h"
#include "usb_stream_helper.h"
#include "nsboot_arch_adapter.h"
#include "usb_device.h"
#if 0
//static int indent;
//#define in(...) ({ for(int f=0;f<indent;f++) printf("  "); printf("-->" __VA_ARGS__); indent++; })
//#define out(...) ({ indent--; for(int f=0;f<indent;f++) printf("  "); printf("<--" __VA_ARGS__); })
#define in(...) printf("-->" __VA_ARGS__)
#define out(...) printf("<--" __VA_ARGS__)
#else
#define in(...) ((void)0)
#define out(...) ((void)0)
#endif
#define __allowed_bss __attribute__((section(".allowed_bss")))
__allowed_bss struct armv6m_pointers armv6m_pointers;

//#define PROFILER 1
//static uint64_t total;

#define CPU_IDX_NORMAL 0 // used when executing outside the USB IRQ
#define CPU_IDX_IRQ    1 // used when executing in the USB IRQ
__allowed_bss armulet_cpu_t cpu[2];

// either 0 or sizeof(armulet_cpu_t) for cpu[1] - this saves code space vs doing multiply at runtime
static __allowed_bss volatile uint8_t current_cpu_offset;

static __force_inline armulet_cpu_t *get_current_cpu(void) {
    return (armulet_cpu_t *)((uintptr_t)&cpu[0] + current_cpu_offset);
}

uint32_t call_armv6m(armulet_cpu_t *current_cpu, uintptr_t address) {
#if FEATURE_RISCV_USB_BOOT
    if (address == (uintptr_t)armv6m_pointers.usb_stream_packet_handler) {
        // this is the only place we call back from RISC-V code into ARM code, where the function
        // pointed to may actually be implemented in RISC-V. We could use our usual varm_to_native_
        // mechanism to have us call back into the native implementation by always using the else
        // branch below, however that wastes a bunch of stack, and also time for something which
        // is called quite a lot.
        in("risc-v call usb_stream_packet_handler %08x\n", current_cpu->regs[ARM_REG_R0]);
        native_usb_stream_packet_handler((struct usb_endpoint *)current_cpu->regs[ARM_REG_R0]);
        out("risc-v call usb_stream_packet_handler %08x\n", current_cpu->regs[ARM_REG_R0]);
        return 0;
    } else
#endif
    {

        in("calling ARMv6m code %08x(%08x? %08x?) SP=%08x\n", address&~1, current_cpu->regs[ARM_REG_R0], current_cpu->regs[ARM_REG_R1], current_cpu->regs[ARM_REG_SP]);
        // we need to save restore PC/LR if we are nesting (cheapest to just do it anyway)
        // note that SP, R0, R1, R2, R3 do not need to be preserved as this is a regular function call
        uint32_t pc = current_cpu->regs[ARM_REG_PC];
        uint32_t lr = current_cpu->regs[ARM_REG_LR];
        current_cpu->regs[ARM_REG_PC] = address & ~1u;
        current_cpu->regs[ARM_REG_LR] = ARMULET_CALL_RETURN_ADDRESS;
        __unused uint32_t sp = current_cpu->regs[ARM_REG_SP];
        uint32_t rc = (uint32_t)varmulet_run_adapter(current_cpu, &varmulet_nsboot_asm_hooks);
        // restore trashed PC and LR
        current_cpu->regs[ARM_REG_PC] = pc;
        current_cpu->regs[ARM_REG_LR] = lr;
        bootrom_assert(NSBOOT, sp == current_cpu->regs[ARM_REG_SP]);
        out("return from ARMv6m code %08x %d SP=%08x\n", address&~1, rc, current_cpu->regs[ARM_REG_SP]);
        return rc;
    }
}

uint32_t call_armv6m_2(uintptr_t address, uint32_t p0, uint32_t p1) {
    armulet_cpu_t *current_cpu = get_current_cpu();
    current_cpu->regs[ARM_REG_R0] = p0;
    current_cpu->regs[ARM_REG_R1] = p1;
#if 0
    printf("CALL ARMV6M %08x(%08x, %08x) sp=%08x\n", (int)address, (int)p0, (int)p1, (int)get_sp());
    uint32_t rc = call_armv6m(current_cpu, address);
    printf("CALL ARMV6M %08x(%08x, %08x) returns %08x sp=%08x \n", (int)address, (int)p0, (int)p1, (int)rc, (int)get_sp());
    return rc;
#else
    return call_armv6m(current_cpu, address);
#endif
}

//#define TIME_TYPE 1
void riscv_usb_irq_handler(void) {
#if PROFILER
    static int fooble = 0;
    extern uint32_t address_profile[16384];
    if (!fooble) memset(address_profile, 0, 65536);
    if (fooble % 1000 == 0) {
        printf("%d\n", fooble);
    }
    if (++fooble == 3000) {
        for(int i=0;i<count_of(address_profile);i++) {
            printf("%08x: %d\n", 0x20010000 + i * 2, address_profile[i]);
        }
        __breakpoint();
        fooble = 0;
    }
#endif
#if TIME_TYPE
    static int weeble = 0;
#if TIME_TYPE == 1
    static uint64_t t0;
    if (weeble == 500) {
        t0 = time_us_64();
    } else if (weeble == 10500) {
        uint64_t delta = time_us_64() - t0;
        printf("elapsed %d\n", (int) delta);
    }
#elif TIME_TYPE == 2
    uint32_t t0 = time_us_32();
#endif
    weeble++;
#endif
    uint32_t status = usb_hw->ints;
//    if (in_irq) {
//        printf("NESTED IRQ!!\n");
//        __breakpoint();
//    }
    current_cpu_offset = sizeof(armulet_cpu_t);
    // IRQ stack just continues from regular CPU stack;
    // varmulet guarantees that even in the middle of an ARM instruction that uses that stack,
    // writing below current SP is safe.
    cpu[CPU_IDX_IRQ].regs[ARM_REG_SP] = cpu[CPU_IDX_NORMAL].regs[ARM_REG_SP];
#if FEATURE_RISCV_USB_BOOT
    if (status == USB_INTS_BUFF_STATUS_BITS) {
        in("RISC-V IRQ usb_handle_buffer\n");
        native_usb_handle_buffer();
        out("RISC-V IRQ usb_handle_buffer\n");
    } else
#endif
    {
        // read from the vector table (note 16 not VTABLE_FIRST_IRQ as we want the ARM constant not the RISC-V)
        uint32_t usb_irq_handler_address = *(uint32_t *)(NSBOOT_START + NSBOOT_VTOR_OFFSET + (16 + USBCTRL_IRQ) * 4);
        call_armv6m(&cpu[CPU_IDX_IRQ], usb_irq_handler_address);
    }
    current_cpu_offset = 0;
#if TIME_TYPE == 2
        if (weeble > 500) total += time_us_32() - t0;
    if (weeble == 10500) {
        printf("%d\n", (int)total);
    }
#endif
}

#if MINI_PRINTF
void __used native_nsboot_init(const struct armv6m_pointers *p) {
    printf("ARM pointers at %08x\n", (int)p);
    armv6m_pointers = *(const struct armv6m_pointers *)p;
}
#else
// Replaced by asm falling through into memcpy in riscv_misc.S
static_assert(sizeof(armv6m_pointers) == 12);
#endif

static __force_inline void s_native_crit_mem_erase_words(uintptr_t start, uint size_words) {
    // Just care about code size on the RISC-V side, so call existing function
    native_memset0((void*)start, size_words * 4);
}

void __attribute__((used, noreturn)) s_native_launch_nsboot(void) {
    // this is cleared here rather than in common calling code as the varmulet regs are at the bottom of it
#if !HACK_RAM_BOOTROM_AT
    s_native_crit_mem_erase_words(SRAM_BASE, (SRAM_END - SRAM_BASE)/4);
#endif
    // no need to reset teh CPU is it is in BSS which is cleared below; the only
    // thing that isn't reset correctly is lazy_nz_val and we don't care about flags
    // on entry to our code (note this comment out code was moved above the memset0,
    // so GCC wouldn't put static_data_shadow in a temporary
    //armulet_reset_cpu(&cpu[CPU_IDX_NORMAL]);
    // clear our bss data! (and make it clear that a0 is preserved.
    void *static_data_shadow = native_memset0(bootram->nsboot.riscv.static_data_shadow, sizeof(bootram->nsboot.riscv.static_data_shadow));
    printf("PC regs at %p\n", &cpu[CPU_IDX_NORMAL].regs);
    printf("launch_nsboot call sp=%08x\n", (int)get_sp());
    cpu[CPU_IDX_NORMAL].regs[ARM_REG_PC] = NSBOOT_ENTRY_POINT;
#if !SWAP_RISCV_NSBOOT_STACKS
    cpu[CPU_IDX_NORMAL].regs[ARM_REG_SP] = ((uintptr_t)&bootram->nsboot.riscv.varmulet_stack) + sizeof(bootram->nsboot.riscv.varmulet_stack);
    cpu[CPU_IDX_NORMAL].splim = cpu[CPU_IDX_IRQ].splim = (uintptr_t)&bootram->nsboot.riscv.varmulet_stack;
#else
    cpu[CPU_IDX_NORMAL].regs[ARM_REG_SP] = USBCTRL_DPRAM_BASE + USBCTRL_DPRAM_SIZE;
    cpu[CPU_IDX_NORMAL].splim = cpu[CPU_IDX_IRQ].splim = USBCTRL_DPRAM_BASE + USBCTRL_DPRAM_SIZE - NSBOOT_STACK_WORDS * 4;
#endif
    extern void __attribute__((noreturn)) riscv_nsboot_launch_thunk(armulet_cpu_t *cpu, const varmulet_asm_hooks_t *hooks, uintptr_t bootram_stack_top);
    static_assert((uintptr_t)bootram->nsboot.riscv.static_data_shadow ==
                          (uintptr_t)bootram->nsboot.riscv.varmulet_stack + sizeof(bootram->nsboot.riscv.varmulet_stack), "");
    riscv_nsboot_launch_thunk(&cpu[CPU_IDX_NORMAL], &varmulet_nsboot_asm_hooks, (uintptr_t)static_data_shadow);
}
