/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "bootrom.h"

// Validate a NonSecure buffer.
//
// Entire buffer must fit in range XIP_BASE -> SRAM_END, and must be
// accessible from NS caller according to SAU + NS MPU (privileged or not
// based on current processor IPSR and NS CONTROL flag). We also allow
// buffers in USB RAM if this is granted to NS via ACCESSCTRL -- note USB RAM
// is IDAU-Exempt so will fail tt* checks.
//
// Note this is a arm6-to-native call so that it can be stubbed on RISC-V,
// avoiding execution of Armv8-M instructions under emulation. This allows
// nsboot-to-secure shims (accessed via nsboot's service SG) to be shared.

void *varm_callable(s_native_api_validate_ns_buffer)(const void *addr, uint32_t size, hx_bool write, hx_bool *ok);
