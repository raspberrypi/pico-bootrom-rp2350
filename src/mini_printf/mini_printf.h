/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#ifdef __cplusplus
extern "C" {
#endif

#if MINI_PRINTF

#include "hardware/structs/uart.h"
#include <stdio.h>
#include <hardware/structs/iobank0.h>
void mini_printf_init(void);
void mini_printf_flush(void);
#define printf mini_printf
#define puts mini_puts
void __noinline mini_printf(const char *fmt, ...);
int __noinline mini_puts(const char *str);

#else

#define mini_printf_init() ((void)0)
#define mini_printf_flush() ((void)0)
#define printf(fmt...) ((void)0)
#define puts(s) ((void)0)

#endif

#ifdef __cplusplus
}
#endif
