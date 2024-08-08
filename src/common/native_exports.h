/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once
#include "bootrom_common.h"
#include <stdint.h>

void *varm_callable(native_memcpy)(void *a, const void *b, uint32_t len);
void *varm_callable(native_memset0)(void *a, uint32_t len);
void *varm_callable(native_memset)(void *a, uint v, uint32_t len);

#define varm_or_native_memcpy varm_callable(native_memcpy)
#define varm_or_native_memset0 varm_callable(native_memset0)

void varm_noop(void);
bool varm_is_sram_or_xip_ram(uint32_t addr);

