/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "pico.h"

struct armv6m_pointers {
    struct usb_endpoint **endpoints;
    struct usb_endpoint *usb_control_endpoints; // in followed by out
    void (* usb_stream_packet_handler)(struct usb_endpoint *ep);
};

void varm_callable(native_nsboot_init)(const struct armv6m_pointers *p);
void varm_callable(native_usb_irq_enable)(void); // when we want to turn on the IRQ
#if FEATURE_RISCV_USB_BOOT
void varm_callable(native_usb_packet_done)(struct usb_endpoint *ep);
#else
void native_usb_packet_done(struct usb_endpoint *ep);
#define varm_to_native_usb_packet_done native_usb_packet_done
#endif

struct usb_endpoint **native_usb_get_endpoints(void);
// array of in then out
struct usb_endpoint *native_usb_get_control_endpoints(void);
#define CONTROL_IN_ENDPOINT_INDEX 0
#define CONTROL_OUT_ENDPOINT_INDEX 1
#define native_usb_get_control_in_endpoint() (&native_usb_get_control_endpoints()[CONTROL_IN_ENDPOINT_INDEX])
#define native_usb_get_control_out_endpoint() (&native_usb_get_control_endpoints()[CONTROL_OUT_ENDPOINT_INDEX])

#ifdef __riscv
// as we don't care about the values passed in unused r0 or r1 to an ARM function,
// call_armv6m_0 and call_armv6m_1 are just aliases for call_armv6m_2
uint32_t call_armv6m_0(uintptr_t address);
uint32_t call_armv6m_1(uintptr_t address, uint32_t p1);
uint32_t call_armv6m_2(uintptr_t address, uint32_t p1, uint32_t p2);
#define call_arm_fp0(f) call_armv6m_0((uintptr_t) f)
#define call_arm_fp1(f, p) call_armv6m_1((uintptr_t) f, (uintptr_t) p)
#define call_arm_fp2(f, p1, p2) call_armv6m_2((uintptr_t) f, (uintptr_t) p1, (uintptr_t) p2)
extern struct armv6m_pointers armv6m_pointers;

static __force_inline struct usb_endpoint **arch_usb_get_endpoints(void) {
    return armv6m_pointers.endpoints;
}

static __force_inline struct usb_endpoint *arch_usb_get_control_endpoints(void) {
    return armv6m_pointers.usb_control_endpoints;
}

static __force_inline struct usb_endpoint *arch_usb_get_control_in_endpoint(void) {
    return &armv6m_pointers.usb_control_endpoints[0];
}

static __force_inline struct usb_endpoint *arch_usb_get_control_out_endpoint(void) {
    return &armv6m_pointers.usb_control_endpoints[0];
}
#else // arm
#define call_arm_fp0(f) f()
#define call_arm_fp1(f, p) f(p)
#define call_arm_fp2(f, p1, p2) f(p1, p2)

#define arch_usb_handle_buffer native_usb_handle_buffer
#define arch_usb_get_endpoints native_usb_get_endpoints
#define arch_usb_get_control_endpoints native_usb_get_control_endpoints
#define arch_usb_get_control_in_endpoint native_usb_get_control_in_endpoint
#define arch_usb_get_control_out_endpoint native_usb_get_control_out_endpoint
#endif

#ifdef __riscv
#define arm_or_riscv_impl(x) riscv_ ## x
#else
#define arm_or_riscv_impl(x) varm_ ## x
#endif
