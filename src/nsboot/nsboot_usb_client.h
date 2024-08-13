/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "usb_device.h"

#define VENDOR_ID   0x2e8au
#define PRODUCT_ID  0x000fu

void nsboot_usb_device_init(uint32_t bootsel_flags);

static inline bool is_address_flash(uint32_t addr) {
#if PICO_RP2350
    return (addr >= XIP_BASE && addr <= XIP_BASE + 32 * 1024 * 1024);
#else
    return (addr >= XIP_BASE && addr <= XIP_NOALLOC_BASE);
#endif
}
