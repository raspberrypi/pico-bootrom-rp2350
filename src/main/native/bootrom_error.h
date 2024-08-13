/*
 * Copyright (c) 2024 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "pico/bootrom_constants.h"

static_assert(BOOTROM_OK == PICO_OK, "");
//static_assert(BOOTROM_ERROR_TIMEOUT == PICO_ERROR_TIMEOUT, "");
//static_assert(BOOTROM_ERROR_GENERIC == PICO_ERROR_GENERIC, "");
//static_assert(BOOTROM_ERROR_NO_DATA == PICO_ERROR_NO_DATA, "");
static_assert(BOOTROM_ERROR_NOT_PERMITTED == PICO_ERROR_NOT_PERMITTED, "");
static_assert(BOOTROM_ERROR_INVALID_ARG == PICO_ERROR_INVALID_ARG, "");
//static_assert(BOOTROM_ERROR_IO == PICO_ERROR_IO, "");
//static_assert(BOOTROM_ERROR_BADAUTH == PICO_ERROR_BADAUTH, "");
//static_assert(BOOTROM_ERROR_CONNECT_FAILED == PICO_ERROR_CONNECT_FAILED, "");
//static_assert(BOOTROM_ERROR_INSUFFICIENT_RESOURCES == PICO_ERROR_INSUFFICIENT_RESOURCES, "");
static_assert(BOOTROM_ERROR_INVALID_ADDRESS == PICO_ERROR_INVALID_ADDRESS , "");
static_assert(BOOTROM_ERROR_BAD_ALIGNMENT == PICO_ERROR_BAD_ALIGNMENT , "");
static_assert(BOOTROM_ERROR_INVALID_STATE == PICO_ERROR_INVALID_STATE , "");
static_assert(BOOTROM_ERROR_BUFFER_TOO_SMALL == PICO_ERROR_BUFFER_TOO_SMALL, "");
static_assert(BOOTROM_ERROR_PRECONDITION_NOT_MET == PICO_ERROR_PRECONDITION_NOT_MET, "");
static_assert(BOOTROM_ERROR_MODIFIED_DATA == PICO_ERROR_MODIFIED_DATA, "");
static_assert(BOOTROM_ERROR_INVALID_DATA == PICO_ERROR_INVALID_DATA, "");
static_assert(BOOTROM_ERROR_NOT_FOUND == PICO_ERROR_NOT_FOUND, "");
static_assert(BOOTROM_ERROR_UNSUPPORTED_MODIFICATION == PICO_ERROR_UNSUPPORTED_MODIFICATION, "");

// not allowed in bootrom
#define PICO_OK use_BOOTROM_variant_instead
#define PICO_ERROR_TIMEOUT use_BOOTROM_variant_instead
#define PICO_ERROR_GENERIC use_BOOTROM_variant_instead
#define PICO_ERROR_NO_DATA use_BOOTROM_variant_instead
#define PICO_ERROR_NOT_PERMITTED use_BOOTROM_variant_instead
#define PICO_ERROR_INVALID_ARG use_BOOTROM_variant_instead
#define PICO_ERROR_IO use_BOOTROM_variant_instead
#define PICO_ERROR_BADAUTH use_BOOTROM_variant_instead
#define PICO_ERROR_CONNECT_FAILED use_BOOTROM_variant_instead
#define PICO_ERROR_INSUFFICIENT_RESOURCES use_BOOTROM_variant_instead
#define PICO_ERROR_INVALID_ADDRESS use_BOOTROM_variant_instead
#define PICO_ERROR_BAD_ALIGNMENT use_BOOTROM_variant_instead
#define PICO_ERROR_INVALID_STATE use_BOOTROM_variant_instead
#define PICO_ERROR_BUFFER_TOO_SMALL use_BOOTROM_variant_instead
#define PICO_ERROR_PRECONDITION_NOT_MET use_BOOTROM_variant_instead
#define PICO_ERROR_MODIFIED_DATA use_BOOTROM_variant_instead
#define PICO_ERROR_INVALID_DATA use_BOOTROM_variant_instead
#define PICO_ERROR_NOT_FOUND use_BOOTROM_variant_instead
#define PICO_ERROR_UNSUPPORTED_MODIFICATION use_BOOTROM_variant_instead
