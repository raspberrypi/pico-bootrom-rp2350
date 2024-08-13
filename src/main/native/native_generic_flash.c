/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "hardware/regs/io_qspi.h"
#include "hardware/structs/pads_qspi.h"
#include "hardware/structs/qmi.h"
#include "native_generic_flash.h"
#include "bootrom.h"

// Sanity check
#undef static_assert
#define static_assert(cond, x) extern int __CONCAT(static_assert,__LINE__)[(cond)?1:-1]
check_hw_layout(qmi_hw_t, direct_csr, QMI_DIRECT_CSR_OFFSET);
check_hw_layout(qmi_hw_t, direct_tx, QMI_DIRECT_TX_OFFSET);

static_assert(IO_QSPI_GPIO_QSPI_SCLK_CTRL_OFFSET == 0x14, "QSPI IOs have moved");
static_assert(IO_QSPI_GPIO_QSPI_SD3_CTRL_OFFSET == 0x3c, "QSPI IOs have moved");

static_assert(PADS_QSPI_GPIO_QSPI_SCLK_OFFSET == 0x00000004, "QSPI PAD has moved");
static_assert(PADS_QSPI_GPIO_QSPI_SD0_OFFSET  == 0x00000008, "QSPI PAD has moved");
static_assert(PADS_QSPI_GPIO_QSPI_SD1_OFFSET  == 0x0000000c, "QSPI PAD has moved");
static_assert(PADS_QSPI_GPIO_QSPI_SD2_OFFSET  == 0x00000010, "QSPI PAD has moved");
static_assert(PADS_QSPI_GPIO_QSPI_SD3_OFFSET  == 0x00000014, "QSPI PAD has moved");
static_assert(PADS_QSPI_GPIO_QSPI_SS_OFFSET   == 0x00000018, "QSPI PAD has moved");

// Put bytes from one buffer, and get bytes into another buffer.
// These can be the same buffer.
// If tx is NULL then send zeroes.
// If rx is NULL then all read data will be dropped.
// Returns cs (first arg), so that it can be preserved over calls without
// using a callee save.
uint __noinline __attribute__((used)) s_native_crit_flash_put_get(uint cs, const uint8_t *tx, uint8_t *rx, size_t count) {
    canary_entry(S_NATIVE_CRIT_FLASH_PUT_GET);

    // Assert chip select, and enable direct mode. Anything queued in TX FIFO will start now.
#if !GENERAL_SIZE_HACKS
    uint32_t csr_toggle_mask = (QMI_DIRECT_CSR_ASSERT_CS0N_BITS << cs) | QMI_DIRECT_CSR_EN_BITS;
#else
    // Slightly smaller, works for 0/1 only
    bootrom_assert(FLASH, cs == 0 || cs == 1);
    uint32_t csr_toggle_mask = (QMI_DIRECT_CSR_ASSERT_CS0N_BITS | QMI_DIRECT_CSR_EN_BITS) + (cs << QMI_DIRECT_CSR_ASSERT_CS0N_LSB);
#endif
    hw_xor_bits(&qmi_hw->direct_csr, csr_toggle_mask);

    size_t tx_count = count;
    size_t rx_count = count;
    while (tx_count || rx_count) {
        uint32_t status = qmi_hw->direct_csr;
        if (tx_count && !(status & QMI_DIRECT_CSR_TXFULL_BITS)) {
            qmi_hw->direct_tx = (uint32_t) (tx ? *tx++ : 0);
            --tx_count;
        }
        if (rx_count && !(status & QMI_DIRECT_CSR_RXEMPTY_BITS)) {
            uint8_t rxbyte = (uint8_t) qmi_hw->direct_rx;
            if (rx)
                *rx++ = rxbyte;
            --rx_count;
        }
    }

    // Wait for BUSY as there may be no RX data at all, e.g. for single-byte SPI commands
    while (qmi_hw->direct_csr & QMI_DIRECT_CSR_BUSY_BITS)
        ;

    // Disable direct-mode interface and deassert chip select
    hw_xor_bits(&qmi_hw->direct_csr, csr_toggle_mask);
    canary_exit_return(S_NATIVE_CRIT_FLASH_PUT_GET, cs);
}
