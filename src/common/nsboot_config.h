/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "pico.h"
#include "bootrom_layout.h"

typedef enum {
    BOOTSEL_MODE_USB     = 0x0, // SD1 pulled low
    BOOTSEL_MODE_UART    = 0x1  // SD1 driven high
} bootsel_serialmode_t;

typedef struct {
    uint32_t public_rand_id[2];
} chip_id_t;

// NOTE THIS IS ALSO THE NS VECTOR TABLE!
typedef struct {
    // config settings
    int8_t usb_activity_pin;
    uint8_t bootsel_flags;
    uint8_t serial_mode_and_inst;
    chip_id_t chip_id;
} __aligned(4) nsboot_config_t;

#define nsboot_config ((nsboot_config_t *)NSBOOT_RAM_START)
