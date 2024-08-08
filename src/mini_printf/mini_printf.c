/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if MINI_PRINTF
#if !defined(__riscv) && (defined(__ARM_ARCH_8M_MAIN__) || !defined(__ARM_ARCH_8M_BASE__))
#error this must be compiled with armv8m-base on ARM
#endif

#include "mini_printf.h"
#include "hardware/resets.h"
#include "hardware/structs/accessctrl.h"

#define TBMAN_PLATFORM_OFFSET         (TBMAN_BASE + 0x00)
#define TBMAN_PLATFORM_HDLSIM_BITS    0x00000004
#define TBMAN_SIMUART_OFFSET          (TBMAN_BASE + 0x14)
#define TBMAN_PRINTTO_OFFSET          (TBMAN_BASE + 0x10)
#define TBMAN_PRINTTO_SIMCONSOLE_BITS 0x00000001

typedef struct uart_inst uart_inst_t;

#define uart0 ((uart_inst_t *)uart0_hw) ///< Identifier for UART instance 0
#define uart1 ((uart_inst_t *)uart1_hw) ///< Identifier for UART instance 1

static inline uint uart_get_index(uart_inst_t *uart) {
    return uart == uart1 ? 1 : 0;
}

static inline void uart_reset(uart_inst_t *uart) {
    reset_block(uart_get_index(uart) ? RESETS_RESET_UART1_BITS : RESETS_RESET_UART0_BITS);
}

static inline void uart_unreset(uart_inst_t *uart) {
    unreset_block_wait(uart_get_index(uart) ? RESETS_RESET_UART1_BITS : RESETS_RESET_UART0_BITS);
}

static inline uart_hw_t *uart_get_hw(uart_inst_t *uart) {
    uart_get_index(uart); // check it is a hw uart
    return (uart_hw_t *)uart;
}

uint uart_set_baudrate(uart_inst_t *uart, uint baudrate) {
    const uint32_t clk_hz = 48000000;
    uint32_t baud_rate_div = (8 * clk_hz / baudrate);
    uint32_t baud_ibrd = baud_rate_div >> 7;
    uint32_t baud_fbrd;

    if (baud_ibrd == 0) {
        baud_ibrd = 1;
        baud_fbrd = 0;
    } else if (baud_ibrd >= 65535) {
        baud_ibrd = 65535;
        baud_fbrd = 0;
    }  else {
        baud_fbrd = ((baud_rate_div & 0x7f) + 1) / 2;
    }

    // Load PL011's baud divisor registers
    uart_get_hw(uart)->ibrd = baud_ibrd;
    uart_get_hw(uart)->fbrd = baud_fbrd;

    // PL011 needs a (dummy) line control register write to latch in the
    // divisors. We don't want to actually change LCR contents here.
    hw_set_bits(&uart_get_hw(uart)->lcr_h, 0);

    // See datasheet
    return (4 * clk_hz) / (64 * baud_ibrd + baud_fbrd);
}

typedef enum {
    UART_PARITY_NONE,
    UART_PARITY_EVEN,
    UART_PARITY_ODD
} uart_parity_t;

static inline void uart_set_format(uart_inst_t *uart, uint data_bits, uint stop_bits, uart_parity_t parity) {
    hw_write_masked(&uart_get_hw(uart)->lcr_h,
                    ((data_bits - 5u) << UART_UARTLCR_H_WLEN_LSB) |
                    ((stop_bits - 1u) << UART_UARTLCR_H_STP2_LSB) |
                    (bool_to_bit(parity != UART_PARITY_NONE) << UART_UARTLCR_H_PEN_LSB) |
                    (bool_to_bit(parity == UART_PARITY_EVEN) << UART_UARTLCR_H_EPS_LSB),
                    UART_UARTLCR_H_WLEN_BITS |
                    UART_UARTLCR_H_STP2_BITS |
                    UART_UARTLCR_H_PEN_BITS |
                    UART_UARTLCR_H_EPS_BITS);
}

uint uart_init(uart_inst_t *uart, uint baudrate) {
    uart_reset(uart);
    uart_unreset(uart);

#if PICO_UART_ENABLE_CRLF_SUPPORT
    uart_set_translate_crlf(uart, PICO_UART_DEFAULT_CRLF);
#endif

    // Any LCR writes need to take place before enabling the UART
    uint baud = uart_set_baudrate(uart, baudrate);
    uart_set_format(uart, 8, 1, UART_PARITY_NONE);

    // Enable the UART, both TX and RX
    uart_get_hw(uart)->cr = UART_UARTCR_UARTEN_BITS | UART_UARTCR_TXE_BITS | UART_UARTCR_RXE_BITS;
    // Enable FIFOs
    hw_set_bits(&uart_get_hw(uart)->lcr_h, UART_UARTLCR_H_FEN_BITS);
    // Always enable DREQ signals -- no harm in this if DMA is not listening
    uart_get_hw(uart)->dmacr = UART_UARTDMACR_TXDMAE_BITS | UART_UARTDMACR_RXDMAE_BITS;

    return baud;
}

// note __force_inline wasting space, but saving stack
static __force_inline bool uart_is_writable(uart_inst_t *uart) {
    return !(uart_get_hw(uart)->fr & UART_UARTFR_TXFF_BITS);
}

#define stdio_uart __CONCAT(uart,PICO_DEFAULT_UART)

static __force_inline void uart_write_blocking(const uint8_t *src, size_t len) {
    for (size_t i = 0; i < len; ++i) {
        // Skip UART if TB output is specifically requested, to speed up sims.
#if !PRINTF_TO_TB
        // Also skip it if TBMAN says we're running in sim -- getting bored of
        // watching the processor blocked on UART
        if (!(*(io_ro_32*)TBMAN_PLATFORM_OFFSET & TBMAN_PLATFORM_HDLSIM_BITS)) {
            while (!uart_is_writable(stdio_uart))
                tight_loop_contents();
            uart_get_hw(stdio_uart)->dr = *src;
        }
#endif
        *(io_rw_32*)TBMAN_SIMUART_OFFSET = *src++;
    }
}

static __force_inline void uart_putc_raw(char c) {
    uart_write_blocking((const uint8_t *) &c, 1);
}

static __noinline void uart_putc(char c) {
    if (c == '\n')
        uart_putc_raw('\r');
    uart_putc_raw( c);
}

#include <stdarg.h>
void __noinline mini_printf(const char *fmt, ...)
{
    va_list va;
    va_start(va, fmt);

    while (*fmt) {
        char c = *fmt++;
        if (c == '%') {
            char c2 = *fmt++;
            switch (c2) {
                case '%':
                    uart_putc(c);
                    break;
                case 's': {
                    const char *v = va_arg(va, const char *);
                    while (*v) {
                        uart_putc(*v++);
                    }
                    break;
                }
                case 'd': {
                    int v = va_arg(va, int);
                    if (v < 0) {
                        v = -v;
                        uart_putc('-');
                    }
                    static const int tens[] = {
                            1000000000,
                            100000000,
                            1000000,
                            100000,
                            10000,
                            1000,
                            100,
                            10,
                            1,
                            };
                    if (!v) {
                        uart_putc('0');
                    } else {
                        bool had = false;
                        for(uint i=0;i<count_of(tens);i++) {
                            int d = 0;
                            while (tens[i] <= v) {
                                v -= tens[i];
                                d++;
                            }
                            if (d || had) {
                                uart_putc((char)('0'+d));
                                had = true;
                            }
                        }
                    }
                    break;
                }
                case 'p': {
                    uint32_t v = va_arg(va, uint32_t);
                    for(int pos=7;pos>=0;pos--) {
                        int d = (v >> (pos * 4)) & 0xf;
                        if (d < 10) uart_putc((char)('0'+d));
                        else uart_putc((char)('a'+d - 10));
                    }
                    break;
                }
                case '0': {
                    uint32_t v = va_arg(va, uint32_t);
                    if (fmt[0] > '0' && fmt[0] < '9' && fmt[1] == 'x') {
                        int zeros = fmt[0]-'1';
                        bool had_digit=false;
                        for(int pos=7;pos>=0;pos--) {
                            int d = (v >> (pos * 4)) & 0xf;
                            if (!d && pos > zeros && !had_digit) continue;
                            had_digit = true;
                            if (d < 10) uart_putc((char)('0'+d));
                            else uart_putc((char)('a'+d - 10));
                        }
                        fmt+=2;
                        break;
                    }
                    __attribute__((fallthrough));
                }
                default:
                    uart_putc('%');
                    uart_putc(c2);
                    uart_putc('?');
                    uart_putc('?');
            }
        } else {
            uart_putc(c);
        }
    }
    va_end(va);
}

int __noinline mini_puts(const char *str) {
    while (*str) {
        uart_putc(*str++);
    }
    uart_putc('\n');
    return 0;
}

void mini_printf_init(void) {
    unreset_block(RESETS_RESET_TBMAN_BITS);
    // Make tbman accessible to NS, as this printf is liable to end up in Exempt code
    // (note this accessctrl write has no effect, but is harmless, when performed by NSP)
    accessctrl_hw->tbman = ACCESSCTRL_PASSWORD_BITS | ACCESSCTRL_TBMAN_BITS;
    // Always enable TB printer (it's harmless to just write to it on FPGA too)
    *(io_rw_32*)TBMAN_PRINTTO_OFFSET = TBMAN_PRINTTO_SIMCONSOLE_BITS;
    // Disable UART if TB print is specifically requested, to reduce sim time
#if !PRINTF_TO_TB
    uart_init(stdio_uart, MINI_PRINTF_BAUD);
#endif
}

void mini_printf_flush(void) {
#if PRINTF_TO_TB
    return;
#else
    while (!(uart_get_hw(stdio_uart)->fr & UART_UARTFR_TXFE_BITS))
        ;
#endif
}

#endif
