// ----------------------------------------------------------------------------
// UART boot shell
// Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
// SPDX-License-Identifier: BSD-3-Clause
// ----------------------------------------------------------------------------
//
// Commands sent to the device consist of one ASCII character, optionally
// followed by 32 bytes of raw data.
//
// n  nop
// w  write 32 bytes to SRAM, increment read/write pointer by 32
// r  read 32 bytes from SRAM, increment read/write pointer by 32
// c  clear read/write pointer
// x  execute image at start of SRAM
//
// The command byte is echoed back upon the completion of each command. You
// should wait for the echo before sending the next command. If the device
// seems to be stuck, issue NOP commands until you start getting echos back,
// then wait for UART RX to go idle again, then issue a clear command and
// retry from the beginning.
//
// (Note the size of 32 is chosen for the depth of the FIFOs -- it's
// conceivable under emulation on RISC-V that we struggle to keep up with the
// UART.)
//
// An invalid command will be echoed back, with no other effect.
//
// The device starts by printing the splash string, "RP2350". It then remains
// silent until the correct knock sequence has been entered. The required
// knock sequence is the bytes 0x56, 0xff, 0x8b, 0xe4.
//
// The loaded data is expected to be a valid RP2350 executable with an
// appropriate IMAGE_DEF. If secure boot is enabled, the image must be signed
// and have an appropriate rollback version. This is checked after reboot --
// the UART bootloader does not verify the image for you, though it does
// allow you to read back for your own verification.

// varmulet dialect: v6-M plus movw, movt, cbz, cbnz, b.w, msplim
// -> reminiscent of v8-M baseline
.cpu cortex-m23
.syntax unified

.section .text.nsboot_uart_client, "ax"
#include "hardware/regs/addressmap.h"
#include "hardware/regs/uart.h"
#include "boot/picoboot_constants.h"
#include "nsboot.h"

// Note this happens to be the RP2040 UF2 family ID (expected to be sent in
// little-endian byte order) -- not particularly meaningful, we just need
// some well-known magic number to avoid responding to random GPIO toggles.
// The binary type (including Arm vs RISC-V etc) is determined from the
// binary's IMAGE_DEF, upon reboot after the `x` command is invoked.
#define MAGIC_KNOCK_PATTERN 0xe48bff56

// Note this code does not return, so we are free to trash all GPRs without
// stacking them. r7 always contains a pointer to the UART hardware. r5, r6
// always hold putc, getc (so we can call with just a 16-bit `blx`)

.macro blx_putc
    blx r5
.endm
.macro blx_getc
    blx r6
.endm

#if FEATURE_UART_BOOT_SELECTABLE_INSTANCE
#error not supported
#endif
.global nsboot_uart_client
.p2align 2
nsboot_uart_client:
    // The UART is assumed to have already been reset in the varm_nsboot
    // Secure preamble, or (for dev builds with printf) in early nsboot code.

    // r7 always holds the UART regs pointer.
    ldr r7, =UART0_BASE
    ldr r5, =P16(nsboot_uart_putc)
    ldr r6, =P16(nsboot_uart_getc)

    // Assuming a 48 MHz nsboot clock, and given the PL011's oversampling by
    // 16, we want an integer baud divisor of 3 to achieve a 1 Mbaud
    // signalling rate.
    movs r0, #3
    str r0, [r7, #UART_UARTIBRD_OFFSET]
    // (FBRD should already be 0 from reset)

    // Set 8n1 format, enable FIFOs, and latch baud divisor (triggered on LCR write):
    movs r0, #UART_UARTLCR_H_FEN_BITS | (8 - 5) << UART_UARTLCR_H_WLEN_LSB
    str r0, [r7, #UART_UARTLCR_H_OFFSET]

    // Enable the UART
    movw r0, #UART_UARTCR_UARTEN_BITS | UART_UARTCR_TXE_BITS | UART_UARTCR_RXE_BITS
    str r0, [r7, UART_UARTCR_OFFSET]
    // Fall through

    // Print out string so the host knows we're ready
nsboot_uart_splash:
    ldr r3, =P16(_str_rp2350)
1:
    ldrb r0, [r3]
    adds r3, #1
    cbz r0, 2f
    blx_putc
    b 1b
2:
    // Fall through

    // Remain silent until we receive the magic word
nsboot_uart_await_knock:
    // Byte-swap the constant to save an instruction: we expect little-endian
    ldr r3, =(\
        ((MAGIC_KNOCK_PATTERN & 0xff000000) >> 24) | \
        ((MAGIC_KNOCK_PATTERN & 0x00ff0000) >> 8 ) | \
        ((MAGIC_KNOCK_PATTERN & 0x0000ff00) << 8 ) | \
        ((MAGIC_KNOCK_PATTERN & 0x000000ff) << 24))
    movs r2, #0
1:
    blx_getc
    // Implement 4-byte shift register to test for knock pattern:
    lsls r2, #8
    add r2, r0
    cmp r2, r3
    bne 1b
    // Fall through

nsboot_uart_start_cmd_loop:
    // From now on:
    // r0/r1/r2 are trashable
    // r3 contains ram read/write pointer
    // r4 contains saved command (for echo-back)
    // r5-r7 are preserved, as before
    ldr r3, =SRAM_BASE

nsboot_uart_get_cmd:
    blx_getc
    // Save r0 for echo after completion
    movs r4, r0
    cmp r0, #'w'
    beq nsboot_uart_do_write_cmd
    cmp r0, #'r'
    beq nsboot_uart_do_read_cmd
    // Remaining commands perform echo immediately
    blx_putc
    cmp r0, #'c'
    beq nsboot_uart_start_cmd_loop
    cmp r0, #'x'
    bne nsboot_uart_get_cmd // unrecognised (including nop)
    // fall through
nsboot_uart_do_exec_cmd:
    // flags
    movw r0, #REBOOT2_FLAG_REBOOT_TYPE_RAM_IMAGE | REBOOT2_FLAG_NO_RETURN_ON_SUCCESS
    // delay_ms
    movs r1, #1
    // ram_image_start
    ldr r2, =SRAM_BASE
    // ram_image_size
#if (((SRAM_END - SRAM_BASE) >> 13) << 13) != (SRAM_END - SRAM_BASE) || \
      ((SRAM_END - SRAM_BASE) >> 13) > 255
#error "Fix this"
#endif
    movs r3, #(SRAM_END - SRAM_BASE) >> 13
    lsls r3, #13
    b sc_or_varm_reboot

nsboot_uart_do_read_cmd:
1:
    ldrb r0, [r3]
    adds r3, #1
    blx_putc
    // 32 bytes per chunk, pointer always starts 32-byte-aligned
    lsls r0, r3, #27
    bne 1b
    b nsboot_uart_echo_cmd
nsboot_uart_do_write_cmd:
1:
    blx_getc
    strb r0, [r3]
    adds r3, #1
    // 32 bytes per chunk, pointer always starts 32-byte-aligned
    lsls r0, r3, #27
    bne 1b
    // Fall through
nsboot_uart_echo_cmd:
    movs r0, r4
    blx_putc
    b nsboot_uart_get_cmd

// Args: character in r0
// Clobbers: r1
// Returns: character in r0 (preserved)
.global nsboot_uart_putc
nsboot_uart_putc:
    ldr r1, [r7, #UART_UARTFR_OFFSET]
    lsrs r1, #(UART_UARTFR_TXFF_LSB + 1)
    bcs nsboot_uart_putc
    strb r0, [r7, #UART_UARTDR_OFFSET]
    bx lr

// Args: none
// Clobbers: none
// Returns: character in r0
.global nsboot_uart_getc
nsboot_uart_getc:
    ldr r0, [r7, #UART_UARTFR_OFFSET]
    lsrs r0, #(UART_UARTFR_RXFE_LSB + 1)
    bcs nsboot_uart_getc
    ldrb r0, [r7, #UART_UARTDR_OFFSET]
    bx lr

nsboot_uart_literals:
.ltorg
