/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pico.h"
#include "hardware/structs/nvic.h"
#include "nsboot_async_task.h"
#include "nsboot_usb_client.h"
#include "usb_stream_helper.h"
#include "hardware/regs/intctrl.h"
#include "hardware/structs/scb.h"
#if USE_BOOTROM_GPIO
#include "hardware/structs/iobank0.h"
#include "hardware/structs/padsbank0.h"
#include "hardware/gpio.h"
#include "boot/picoboot.h"
#endif
#include "nsboot_secure_calls.h"
#include "nsboot_config.h"
#include "nsboot_arch_adapter.h"
#include "mini_printf.h"
#if MINI_PRINTF
#include "hardware/structs/resets.h"
#endif

#if defined(__ARM_ARCH_8M_MAIN__) || !defined(__ARM_ARCH_8M_BASE__)
//#error this must be compiled with armv8m-base
#endif

// note this is at address NSBOOT_RAM_START (and assumed to be!)
__attribute__((section(".bss.first"))) nsboot_config_t nsboot_config_inst;

#if FEATURE_UART_BOOT_SELECTABLE_INSTANCE
__attribute__((noreturn)) void nsboot_uart_client(uint inst);
#else
__attribute__((noreturn)) void nsboot_uart_client(void);
#endif

//__noinline __attribute__((noreturn)) void nsboot_i2c_client(uint inst);

static __noinline __attribute__((noreturn)) void _nsboot_usb_client(void) {
    nsboot_usb_device_init(nsboot_config->bootsel_flags);

#if 0
    // worker to run tasks on this thread (never returns); Note: USB code is IRQ driven
    // this thunk switches stack into USB DPRAM then calls async_task_worker
    gpio_init(4);
    gpio_set_dir(4, 1);
    while(true) {
        static int foo;
        foo = !foo;
        gpio_put(4, foo);
        printf("BIP %d\n", foo);
        busy_wait_ms(200);
    }
#else
    async_task_worker();
//    nsboot_client_stack_switch_thunk();
#endif
}

typedef void (*irq_handler_t)(void);
bool __used rebooting_flag;

static inline irq_handler_t *get_vtable(void) {
    return (irq_handler_t *) scb_hw->vtor;
}

static void native_interrupt_enable(uint32_t num, bool enabled) {
    if (enabled) {
#if !GENERAL_SIZE_HACKS
        // We should handle an initial spurious interrupt with no USB status
        // bits set, so don't bother to clear the pending latch
        nvic_hw->icpr[num / 32] = 1u << (num % 32);
#endif
        nvic_hw->iser[num / 32] = 1u << (num % 32);
    } else {
        nvic_hw->icer[num / 32] = 1u << (num % 32);
    }
}

void __attribute__((used)) native_usb_irq_enable(void) {
    native_interrupt_enable(USBCTRL_IRQ, true);
}

extern struct usb_endpoint control_endpoints[2];
extern struct usb_endpoint *non_control_endpoints[USB_MAX_ENDPOINTS];
// ARM pointers are the real compiled in versions (so no arch_)
const struct armv6m_pointers nsboot_init_armv6m_pointers = {
        // .endpoints = native_usb_get_endpoints(),
        .endpoints = non_control_endpoints,
        // .usb_control_endpoints = native_usb_get_control_endpoints(),
        .usb_control_endpoints = &control_endpoints[0],
        .usb_stream_packet_handler = native_usb_stream_packet_handler
};

void __attribute__((noreturn)) go(void) {
#if MINI_PRINTF
    //mini_printf_init();
#endif
    //if ((watchdog_hw->scratch[6] ^ SANDBOX_MAGIC) == watchdog_hw->scratch[7] && watchdog_hw->scratch[6] == 0x1) {
    varm_to_native_nsboot_init(P16_D(nsboot_init_armv6m_pointers));

#if FEATURE_UART_BOOT_SELECTABLE_INSTANCE
    uint inst = nsboot_config_inst.serial_mode_and_inst >> 4;
    uint mode = nsboot_config_inst.serial_mode_and_inst & 0xf;
#else
    __unused uint inst = 0;
    uint mode = nsboot_config_inst.serial_mode_and_inst;
#endif
    if (mode == BOOTSEL_MODE_UART) {
#if MINI_PRINTF
        printf("Resetting UART now for UART boot\n");
        mini_printf_flush();
        // UART would normally be reset during preamble in varm_nsboot.c, but
        // we deferred it to this point to keep printf as long as possible.
        uint32_t mask = RESETS_RESET_UART0_BITS << inst;
        hw_set_bits(&resets_hw->reset, mask);
        hw_clear_bits(&resets_hw->reset, mask);
        while (!(resets_hw->reset_done & mask))
            ;
#endif
#if FEATURE_UART_BOOT_SELECTABLE_INSTANCE
        nsboot_uart_client(inst);
#else
        nsboot_uart_client();
#endif
    }
    _nsboot_usb_client();
}

#if USE_BOOTROM_GPIO

void gpio_setup(void) {
    if (nsboot_config->usb_activity_pin >= 0) {
        uint gpio = (uint)nsboot_config->usb_activity_pin;

        gpio_set_dir(gpio, 1);
        // Set input enable on, output disable off
        hw_write_masked(&padsbank0_hw->io[gpio],
                        PADS_BANK0_GPIO0_IE_BITS,
                        PADS_BANK0_GPIO0_IE_BITS | PADS_BANK0_GPIO0_OD_BITS
        );
        // Zero all fields apart from fsel; we want this IO to do what the peripheral tells it.
        // This doesn't affect e.g. pullup/pulldown, as these are in pad controls.
        uint ctrl = GPIO_FUNC_SIO << IO_BANK0_GPIO0_CTRL_FUNCSEL_LSB;
        if (nsboot_config->bootsel_flags & BOOTSEL_FLAG_GPIO_PIN_ACTIVE_LOW) {
            ctrl |= IO_BANK0_GPIO0_CTRL_OUTOVER_VALUE_INVERT << IO_BANK0_GPIO0_CTRL_OUTOVER_LSB;
        }
        iobank0_hw->io[gpio].ctrl = ctrl;
        // Remove pad isolation now that the correct peripheral is in control of the pad
        hw_clear_bits(&padsbank0_hw->io[gpio], PADS_BANK0_GPIO0_ISO_BITS);
    }
#ifndef NDEBUG
    // Set to RIO for debug
    for (int i = 19; i < 23; i++) {
        gpio_init(i);
        gpio_set_dir_out_masked(1 << i);
    }
#endif
}

#endif

void __attribute__((noreturn)) bootrom_assertion_failure(__unused const char *fn, __unused uint line) {
#if MINI_PRINTF
    printf("ASSERTION FAILURE %s:%d\n", fn, line);
#endif
    __breakpoint();
    __builtin_unreachable();
}
