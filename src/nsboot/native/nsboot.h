/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "pico.h"
#include "bootrom_common.h"
#ifndef __riscv
#include "p16.h"
#endif

#ifndef __ASSEMBLER__
#include "pico/bootrom_constants.h"
#include "boot/picoboot.h"
#include "bootrom_assert.h"
#include "native_exports.h"

#if !USE_16BIT_POINTERS
#define RP2350_STRING "RP2350"
#define RPI_STRING "RPI"
#define ONE_STRING "1"
#else
#define RP2350_STRING P16_TYPED(const char *, _str_rp2350)
#define RPI_STRING P16_TYPED(const char *, _str_rpi_1)
#define ONE_STRING (P16_TYPED(const char *, _str_rpi_1) + 4)
#endif

#if USE_PICOBOOT
// allow nsboot to not include all interfaces
#define NSBOOT_WITH_SUBSET_OF_INTERFACES 1
// use a fixed number of interfaces to save code
#define USB_FIXED_INTERFACE_COUNT 2
#else
#define USB_FIXED_INTERFACE_COUNT 1
#endif

void poor_mans_text_decompress(const uint8_t *src_end, uint32_t size, uint8_t *dest);
// is a bool, but making it clear it isn't 1 or 0
uint rebooting(void);

#if USE_BOOTROM_GPIO
void gpio_setup(void);
void nsboot_set_gpio(bool on);
#endif

#include "mini_printf.h"

#if 1
#define usb_trace(format, ...) ((void)0)
#if MINI_PRINTF
//#define usb_debug printf
#define usb_debug(format, ...) ((void)0)
//#define usb_warn printf
#define usb_warn(format, ...) ((void)0)
//#define uf2_debug(format, ...) ((void)0)
#define uf2_debug printf
//#define uf2_info(format, ...) ((void)0)
#define uf2_info printf
#else
#define usb_debug(format, ...) ((void)0)
#define usb_warn(format, ...) ((void)0)
#define uf2_debug(format, ...) ((void)0)
#define uf2_info(format, ...) ((void)0)
#endif
#define usb_panic(format, ...) __breakpoint()
#else
#include "debug.h"
extern void uart_init(int i, int rate, int hwflow);
extern void panic(const char *fmt, ...);
extern int printf(const char *fmt, ...);
extern int puts(const char *str);
#define usb_panic(format,args...) panic(format, ## args)
#define usb_warn(format,args...) ({printf("WARNING: "); printf(format, ## args); })
#if false && !defined(NDEBUG)
#define usb_debug(format,args...) printf(format, ## args)
#else
#define usb_debug(format,...) ((void)0)
#endif
#if false && !defined(NDEBUG)
#define usb_trace(format,args...) printf(format, ## args)
#else
#define usb_trace(format,...) ((void)0)
#endif
#if true && !defined(NDEBUG)
#define uf2_debug(format,args...) printf(format, ## args)
#else
#define uf2_debug(format,...) ((void)0)
#endif
#define ctz32 __builtin_ctz
#endif

/**
 * will copy a possible overriden (white label) in OTP string into a buffer.
 *
 * Note that the buffer is always hword aligned, and that always an integer number of hwords is overwritten,
 * so if unicode_flag_and_buf_len_hwords is 11 (0:11 meaning 11 non unicode characters), up to 12 bytes will be overwritten, but
 * the return code will be no more than 11.
 *
 * @param buf hword aligned buffer
 * @param unicode_flag_and_buf_len_hwords 1:7 unicode_allowed:max_chars (size of char is 2 for unicode one for ASCII)
 * @param str_def_indext index of string descriptor from the white label structure
 * @param default_value the default value in ascii
 * @return 1:7 is_unicode:length in characters
 */
uint white_label_copy_string(aligned2_uint8_t *buf, uint unicode_flag_and_buf_len_hwords, uint str_def_index, const char *default_value);
uint white_label_copy_ascii(uint8_t *buf, uint max_len_bytes, uint str_def_index, const char *default_value);
#define wl_is_unicode(unicode_flags_and_char_count) ((unicode_flags_and_char_count) >= 128)

char * write_msb_hex_chars(char *dest, uint32_t val, int count);

static inline otp_cmd_t row_read_ecc_cmd(uint16_t row) {
    otp_cmd_t cmd = {.flags = ((uint) row << OTP_CMD_ROW_LSB) | OTP_CMD_ECC_BITS};
    return cmd;
}

#endif