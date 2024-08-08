/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "pico.h"
#include "hardware/structs/uart.h"
#include "hardware/structs/resets.h"

// Minimal UART support, for exposing PicoBoot interface over UART

static inline uart_hw_t *boot_uart_getinst(uint inst) {
    return (uart_hw_t *)(UART0_BASE + inst * (UART1_BASE - UART0_BASE));
}

static inline void boot_uart_init(uint inst) {
    // We should be able to access this RESETS bit as the peripheral itself
    // has been granted to NonSecure
    uint32_t mask = RESETS_WDSEL_UART0_BITS << inst;
    hw_set_bits(&resets_hw->reset, mask);
    hw_clear_bits(&resets_hw->reset, mask);
    while (!(resets_hw->reset_done & mask))
        ;

    uart_hw_t *uart = boot_uart_getinst(inst);
    // 1 Mbaud from an assumed 48 MHz: there is a fixed division of 16 due to
    // UART oversampling, so program an additional divide by 3.
    uart->ibrd = 3;
    uart->fbrd = 0;
    // Set 8n1 format, enable FIFOs, and latch baud divisor
    uart->lcr_h = UART_UARTLCR_H_FEN_BITS | (8u -  5u) << UART_UARTLCR_H_WLEN_LSB;
    // Enable the UART
    uart->cr = UART_UARTCR_UARTEN_BITS | UART_UARTCR_TXE_BITS | UART_UARTCR_RXE_BITS;
}

static inline bool boot_uart_is_writable(uint inst) {
    return !(boot_uart_getinst(inst)->fr & UART_UARTFR_TXFF_BITS);
}

static inline bool boot_uart_is_readable(uint inst) {
    return !(boot_uart_getinst(inst)->fr & UART_UARTFR_RXFE_BITS);
}

static inline void boot_uart_putc_blocking(uint inst, uint8_t wdata) {
    while (!boot_uart_is_writable(inst))
        ;
    boot_uart_getinst(inst)->dr = wdata;
}

static inline void boot_uart_write_blocking(uint inst, const uint8_t *wdata, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        boot_uart_putc_blocking(inst, wdata[i]);
    }
}

static inline uint8_t boot_uart_getc_blocking(uint inst) {
    while (!(boot_uart_is_readable(inst)))
        ;
    return (uint8_t)boot_uart_getinst(inst)->dr;
}

static inline void boot_uart_read_blocking(uint inst, uint8_t *rdata, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        rdata[i] = boot_uart_getc_blocking(inst);
    }
}

static inline void boot_uart_wait_tx_idle(uint inst) {
    while (boot_uart_getinst(inst)->fr & UART_UARTFR_BUSY_BITS);
}
