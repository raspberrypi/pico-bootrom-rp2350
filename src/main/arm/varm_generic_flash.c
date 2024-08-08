/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

// Raw flash API for generic 25-series NOR flash devices

// This API uses "flash offsets", i.e. addresses starting from 0 at the beginning of the first flash
// device. These can be translated from flash storage addresses by subtracting XIP_BASE.

#if defined(__ARM_ARCH_8M_MAIN__) || !defined(__ARM_ARCH_8M_BASE__)
#error this must be compiled with armv8m-base
#endif

#include "hardware/structs/iobank0.h"
#include "hardware/structs/ioqspi.h"
#include "hardware/structs/padsbank0.h"
#include "hardware/structs/pads_qspi.h"
#include "hardware/structs/qmi.h"
#include "hardware/structs/xip_ctrl.h"
#include "hardware/resets.h"
#include "hardware/gpio.h"
#include "native_generic_flash.h"
#include "varm_resets.h"
#include "bootrom.h"
#include "bootrom_otp.h"

// These are supported by almost any SPI flash
#define FLASHCMD_PAGE_PROGRAM     0x02
#define FLASHCMD_READ_DATA        0x03
#define FLASHCMD_READ_STATUS      0x05
#define FLASHCMD_WRITE_ENABLE     0x06
#define FLASHCMD_SECTOR_ERASE     0x20
#define FLASHCMD_READ_SFDP        0x5a
#define FLASHCMD_READ_JEDEC_ID    0x9f

// Sanity check
check_hw_layout(qmi_hw_t, direct_csr, QMI_DIRECT_CSR_OFFSET);
check_hw_layout(qmi_hw_t, direct_tx, QMI_DIRECT_TX_OFFSET);

// ----------------------------------------------------------------------------
// Setup and generic access functions

static_assert(IO_QSPI_GPIO_QSPI_SCLK_CTRL_OFFSET == 0x14, "QSPI IOs have moved");
static_assert(IO_QSPI_GPIO_QSPI_SD3_CTRL_OFFSET == 0x3c, "QSPI IOs have moved");

static_assert(PADS_QSPI_GPIO_QSPI_SCLK_OFFSET == 0x00000004, "QSPI PAD has moved");
static_assert(PADS_QSPI_GPIO_QSPI_SD0_OFFSET  == 0x00000008, "QSPI PAD has moved");
static_assert(PADS_QSPI_GPIO_QSPI_SD1_OFFSET  == 0x0000000c, "QSPI PAD has moved");
static_assert(PADS_QSPI_GPIO_QSPI_SD2_OFFSET  == 0x00000010, "QSPI PAD has moved");
static_assert(PADS_QSPI_GPIO_QSPI_SD3_OFFSET  == 0x00000014, "QSPI PAD has moved");
static_assert(PADS_QSPI_GPIO_QSPI_SS_OFFSET   == 0x00000018, "QSPI PAD has moved");

// Connect the XIP controller to the flash pads (note the name is slightly
// historic -- this refers to original plans on RP2040 to always have flash
// in-package. We don't change the name because it's in the ROM table.)
void __exported_from_arm s_varm_api_crit_connect_internal_flash(void) {
    canary_set_step(STEPTAG_S_VARM_API_CRIT_CONNECT_INTERNAL_FLASH);

    // Use hard reset to force IO and pad controls to known state (don't touch
    // IO_BANK0 as that does not affect XIP signals)
    s_varm_step_safe_reset_unreset_block_wait_noinline(RESETS_RESET_IO_QSPI_BITS | RESETS_RESET_PADS_QSPI_BITS);

    pads_qspi_hw->voltage_select = hx_is_true(hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_FLASH_IO_VOLTAGE_1V8_LSB));

    // Then mux XIP block onto internal QSPI flash pads
    io_rw_32 *iobank1 = (io_rw_32 *)IO_QSPI_BASE;
#if !GENERAL_SIZE_HACKS
    for (int i = 0; i < 6; ++i) {
        iobank1[2 * i + 5] = 0;
    }
#else
    __asm volatile (
        "str %1, [%0, #20];" \
        "str %1, [%0, #28];" \
        "str %1, [%0, #36];" \
        "str %1, [%0, #44];" \
        "str %1, [%0, #52];" \
        "str %1, [%0, #60];"
    ::"r" (iobank1), "r" (0));
#endif

    // Finally, remove latching pad isolation
    io_rw_32 *clear_pads_qspi_io = __get_opaque_ptr(hw_clear_alias(&pads_qspi_hw->io[0]));
    for (uint i = 0; i < NUM_QSPI_GPIOS; ++i) {
        clear_pads_qspi_io[i] = PADS_QSPI_GPIO_QSPI_SCLK_ISO_BITS;
    }

    // If there is an auxiliary chip select configured in OTP, now is the time
    // to patch that through to the pads as well.
    int cs1_gpio = inline_s_varm_flash_devinfo_get_cs1_gpio();
    if (cs1_gpio >= 0) {
        padsbank0_hw->io[0] = PADS_BANK0_GPIO0_RESET;
        iobank0_hw->io[cs1_gpio].ctrl = GPIO_FUNC_XIP_CS1;
        padsbank0_hw->io[0] = PADS_BANK0_GPIO0_RESET & ~PADS_BANK0_GPIO0_ISO_BITS;
    }
    canary_check_step(STEPTAG_S_VARM_API_CRIT_CONNECT_INTERNAL_FLASH);
}

// Setup one of a small number of XIP read modes for use by the bootrom in
// e.g. flash_read_data. These modes all leave the flash in a state where it
// will continue to accept normal serial commands between reads.
#define USE_COMPACT_XIP_MODE_CFG 1

#if !USE_COMPACT_XIP_MODE_CFG
#define XIP_MODE_CFG(rfmt,rcmd) rfmt, ((rcmd) << QMI_M0_RCMD_PREFIX_LSB)
#else
// note bizarre / use to cause compile time (divide by zero) error if unexpected bits are set
#define XIP_MODE_CFG(rfmt,rcmd) ((rfmt / (((rfmt)>>24)==0)) | ((rcmd / (((rcmd) >> 8)==0) << 24u)))
#endif
const uint32_t bootrom_xip_mode_cfgs[] = {
// Mode 0: BOOTROM_XIP_MODE_03H_SERIAL (Generic run-on-a-potato serial read)
    XIP_MODE_CFG(
        QMI_M0_RFMT_PREFIX_WIDTH_VALUE_S << QMI_M0_RFMT_PREFIX_WIDTH_LSB |
        QMI_M0_RFMT_ADDR_WIDTH_VALUE_S   << QMI_M0_RFMT_ADDR_WIDTH_LSB |
        QMI_M0_RFMT_SUFFIX_WIDTH_VALUE_S << QMI_M0_RFMT_SUFFIX_WIDTH_LSB |
        QMI_M0_RFMT_DUMMY_WIDTH_VALUE_S  << QMI_M0_RFMT_DUMMY_WIDTH_LSB |
        QMI_M0_RFMT_DATA_WIDTH_VALUE_S   << QMI_M0_RFMT_DATA_WIDTH_LSB |
        QMI_M0_RFMT_PREFIX_LEN_VALUE_8   << QMI_M0_RFMT_PREFIX_LEN_LSB,
        0x03
    ),
// Mode 1: BOOTROM_XIP_MODE_0BH_SERIAL (0Bh, same as 03h but with a dummy byte
// after the address, may permit higher SCK fmax)
    XIP_MODE_CFG(
        QMI_M0_RFMT_PREFIX_WIDTH_VALUE_S << QMI_M0_RFMT_PREFIX_WIDTH_LSB |
        QMI_M0_RFMT_ADDR_WIDTH_VALUE_S   << QMI_M0_RFMT_ADDR_WIDTH_LSB |
        QMI_M0_RFMT_SUFFIX_WIDTH_VALUE_S << QMI_M0_RFMT_SUFFIX_WIDTH_LSB |
        QMI_M0_RFMT_DUMMY_WIDTH_VALUE_S  << QMI_M0_RFMT_DUMMY_WIDTH_LSB |
        QMI_M0_RFMT_DATA_WIDTH_VALUE_S   << QMI_M0_RFMT_DATA_WIDTH_LSB |
        QMI_M0_RFMT_PREFIX_LEN_VALUE_8   << QMI_M0_RFMT_PREFIX_LEN_LSB |
        2u                               << QMI_M0_RFMT_DUMMY_LEN_LSB,
        0x0bu
    ),
// Mode 2: BOOTROM_XIP_MODE_BBH_DUAL (BBh dual I/O read with MODE=00h -- no
// continuous read)
    XIP_MODE_CFG(
        QMI_M0_RFMT_PREFIX_WIDTH_VALUE_S << QMI_M0_RFMT_PREFIX_WIDTH_LSB |
        QMI_M0_RFMT_ADDR_WIDTH_VALUE_D   << QMI_M0_RFMT_ADDR_WIDTH_LSB |
        QMI_M0_RFMT_SUFFIX_WIDTH_VALUE_D << QMI_M0_RFMT_SUFFIX_WIDTH_LSB |
        QMI_M0_RFMT_DUMMY_WIDTH_VALUE_D  << QMI_M0_RFMT_DUMMY_WIDTH_LSB |
        QMI_M0_RFMT_DATA_WIDTH_VALUE_D   << QMI_M0_RFMT_DATA_WIDTH_LSB |
        QMI_M0_RFMT_PREFIX_LEN_VALUE_8   << QMI_M0_RFMT_PREFIX_LEN_LSB |
        QMI_M0_RFMT_SUFFIX_LEN_VALUE_8   << QMI_M0_RFMT_SUFFIX_LEN_LSB,
        0xbbu
    ),
// Mode 3: BOOTROM_XIP_MODE_EBH_QUAD (EBh quad I/O read with MODE=00h -- no
// continuous read)
    XIP_MODE_CFG(
        QMI_M0_RFMT_PREFIX_WIDTH_VALUE_S << QMI_M0_RFMT_PREFIX_WIDTH_LSB |
        QMI_M0_RFMT_ADDR_WIDTH_VALUE_Q   << QMI_M0_RFMT_ADDR_WIDTH_LSB |
        QMI_M0_RFMT_SUFFIX_WIDTH_VALUE_Q << QMI_M0_RFMT_SUFFIX_WIDTH_LSB |
        QMI_M0_RFMT_DUMMY_WIDTH_VALUE_Q  << QMI_M0_RFMT_DUMMY_WIDTH_LSB |
        QMI_M0_RFMT_DATA_WIDTH_VALUE_Q   << QMI_M0_RFMT_DATA_WIDTH_LSB |
        QMI_M0_RFMT_PREFIX_LEN_VALUE_8   << QMI_M0_RFMT_PREFIX_LEN_LSB |
        QMI_M0_RFMT_SUFFIX_LEN_VALUE_8   << QMI_M0_RFMT_SUFFIX_LEN_LSB |
        4u                               << QMI_M0_RFMT_DUMMY_LEN_LSB,
        0xebu
    )
};
#if !USE_COMPACT_XIP_MODE_CFG
static_assert(sizeof(bootrom_xip_mode_cfgs) == 8 * BOOTROM_XIP_MODE_N_MODES, "Bad XIP mode table size");
#else
static_assert(sizeof(bootrom_xip_mode_cfgs) == 4 * BOOTROM_XIP_MODE_N_MODES, "Bad XIP mode table size");
#endif

void __exported_from_arm s_varm_api_crit_flash_select_xip_read_mode(bootrom_xip_mode_t mode, uint8_t clkdiv) {
    canary_set_step(STEPTAG_S_VARM_API_CRIT_FLASH_SELECT_XIP_READ_MODE);
    // Note this also disables direct mode and clears the chip selects

    qmi_hw_t *qmi = __get_opaque_ptr(qmi_hw);
    qmi->direct_csr = clkdiv << QMI_DIRECT_CSR_CLKDIV_LSB;

    // note: haven't used P16_ here, because for no apparently good reason
    //      it makes GCC completely shit the bed on optimizations
#if !USE_COMPACT_XIP_MODE_CFG
    const uint32_t *mode_vals = &bootrom_xip_mode_cfgs[(int)mode * 2];
#else
    // note using P16 here doesn't make the function smaller (due to alignment/GCC),
    // and moves the bootrom_xip_mode_cfg actually causing more alignment issues
    const uint32_t *mode_vals= &bootrom_xip_mode_cfgs[(int)mode];
#endif
    register uint32_t timing asm ("r0") =
        (uint32_t)clkdiv << QMI_M0_TIMING_CLKDIV_LSB |
        // COOLDOWN is enabled for increased performance (allows chaining of
        // sequentially addressed QSPI transfers):
        1u << QMI_M1_TIMING_COOLDOWN_LSB |
        // PAGEBREAK is useful in case the attached device is a PSRAM, which
        // may wrap addresses on 1k boundaries.
        QMI_M1_TIMING_PAGEBREAK_VALUE_1024 << QMI_M1_TIMING_PAGEBREAK_LSB |
        // Likewise the MIN_DESELECT value here is chosen for a >= 50 ns
        // deassertion at 150 MHz, meeting most PSRAM devices' requirements.
        // (Note we will briefly violate the tCEM max select timing for a
        // PSRAM whilst loading user startup code, because no MAX_SELECT is
        // configured, but the impact on the whole-array refresh time should
        // be small as long as this is promptly reconfigured by user code.)
        7u << QMI_M1_TIMING_MIN_DESELECT_LSB |
        // A full cycle of RXDELAY helps with SDx input timing at fast SCK
        // divisors, and should never be harmful except for divide-by-1 at
        // low clk_sys speeds (which the bootrom will not use by default)
        2u << QMI_M0_TIMING_RXDELAY_LSB;

    register uint32_t rfmt asm ("r1");
    register uint32_t rcmd asm ("r2");
#if !USE_COMPACT_XIP_MODE_CFG
    rfmt = mode_vals[0];
    rcmd = mode_vals[1];
#else
    rfmt = mode_vals[0] & 0xffffffu;
    rcmd = mode_vals[0] >> 24u;
#endif
#if !ASM_SIZE_HACKS
    for (int i = 0; i < 2; ++i) {
        qmi->m[i].timing = timing;
        qmi->m[i].rfmt = rfmt;
        qmi->m[i].rfmt = rcmd;
    }
#else
    static_assert(offsetof(qmi_hw_t, m[0].rfmt) == offsetof(qmi_hw_t, m[0].timing) + 4, "");
    static_assert(offsetof(qmi_hw_t, m[0].rcmd) == offsetof(qmi_hw_t, m[0].timing) + 8, "");
    io_rw_32 *qmi_timing = &qmi->m[0].timing;
    pico_default_asm_volatile(
            "stmia %[qmi_timing]!, {r0-r2}\n"
            "adds %[qmi_timing], %[delta]\n"
            "stmia %[qmi_timing]!, {r0-r2}\n"
            : [qmi_timing] "+&l" (qmi_timing)
            : "l" (timing), "l" (rfmt), "l" (rcmd),
              [delta] "i" (offsetof(qmi_hw_t, m[1]) - offsetof(qmi_hw_t, m[0]) - 12)
            : "cc"
            );
#endif
    canary_check_step(STEPTAG_S_VARM_API_CRIT_FLASH_SELECT_XIP_READ_MODE);
}

static void s_varm_crit_flash_init_spi(void) {
    // This function clears the DIRECT_CSR (disables direct mode and clears
    // chip selects), sets clock dividers to BOOTROM_SPI_CLKDIV_DEFAULT, and
    // also sets up the XIP windows for a simple 03h serial read mode.
    s_varm_api_flash_enter_cmd_xip(); // should be equivalent to below
    // s_varm_api_crit_flash_select_xip_read_mode(BOOTROM_XIP_MODE_03H_SERIAL, BOOTROM_SPI_CLKDIV_DEFAULT);

    // Drain QMI FIFOs, without asserting chip selects. When starting from the
    // debugger there can be FIFO entries left behind from a previous boot
    // that was interrupted, as we don't reset the QMI on a warm boot.
    hw_xor_bits(&qmi_hw->direct_csr, QMI_DIRECT_CSR_EN_BITS);
    uint32_t status;
    do {
        status = qmi_hw->direct_csr;
        if (!(status & QMI_DIRECT_CSR_RXEMPTY_BITS)) {
            (void)qmi_hw->direct_rx;
        }
    } while (status & QMI_DIRECT_CSR_BUSY_BITS || !(status & QMI_DIRECT_CSR_RXEMPTY_BITS));
    hw_xor_bits(&qmi_hw->direct_csr, QMI_DIRECT_CSR_EN_BITS);
}

// returns its first argument to allow it to be preserved across calls without
// a callee save register
uint s_varm_flash_do_cmd(uint cs, uint8_t cmd, const uint8_t *tx, uint8_t *rx, size_t count) {
    qmi_hw->direct_tx = cmd | QMI_DIRECT_TX_NOPUSH_BITS;
    return varm_to_s_native_crit_flash_put_get(cs, tx, rx, count);
}

#if !TAIL_CALL_HACKS
uint __noinline s_varm_flash_put_get_nodata(uint cs) {
    // Common arguments -- use flash_put_get's ability to perform a command
    // already preloaded into the FIFO
    return varm_to_s_native_crit_flash_put_get(cs, NULL, NULL, 0);
}
#else
// handled in asm
uint s_varm_flash_put_get_nodata(uint cs);
#endif

// Queue up an 8-bit command, followed by 24 LSBs of a flash offset, in the TX FIFO
static inline void s_varm_flash_put_cmd_addr(uint8_t cmd, flash_offset_t offset) {
    offset = __builtin_bswap32(offset & ((1u << 24) - 1)); // `lsls; lsrs; rev` in v6-M
    offset |= cmd;
    qmi_hw->direct_tx = ((offset << 16) >> 16) | QMI_DIRECT_TX_NOPUSH_BITS | QMI_DIRECT_TX_DWIDTH_BITS;
    qmi_hw->direct_tx = ( offset        >> 16) | QMI_DIRECT_TX_NOPUSH_BITS | QMI_DIRECT_TX_DWIDTH_BITS;
    // Command and address are loaded into FIFO, but won't run until direct
    // mode is enabled by flash_put_get().
}

// GCC produces some heinous code if we try to loop over the pad controls,
// so structs it is
struct sd_padctrl {
    io_rw_32 sd0;
    io_rw_32 sd1;
    io_rw_32 sd2;
    io_rw_32 sd3;
};

// Sequence:
// 1. CSn = 1, IO = 4'h0 (via pulldown to avoid contention), x32 clocks
// 2. CSn = 0, IO = 4'hf (via pullup to avoid contention), x32 clocks
// 3. CSn = 1
// 4. CSn = 0, IO = 4'hf, 4'h5 at quad width (x2 clocks)
// 5. CSn = 1
// 6. CSn = 0, MOSI = 1'b1 driven, x16 clocks
// 7. CSn = 1
// 8. CSn = 0, IO = 4'hf, 4'hf at quad width (x2 clocks)
// 9. CSn = 1
//
// Parts 1 and 2 are to improve compatibility with Micron parts.
// Part 4 is to exit QPI mode on e.g. LY68L, IS66WV. (F5h)
// Part 6 is the sequence suggested in the W25Q16 datasheet for exiting
// continuous read mode. Note FFh is a NOP on most devices.
// Part 8 is an additional QPI exit for devices which don't respond to the F5h exit command.

void __exported_from_arm s_varm_api_crit_flash_exit_xip(void) {
    canary_entry(S_VARM_API_CRIT_FLASH_EXIT_XIP);
    struct sd_padctrl *qspi_sd_padctrl = (struct sd_padctrl *) (PADS_QSPI_BASE + PADS_QSPI_GPIO_QSPI_SD0_OFFSET);

    // First two 32-clock sequences. CSn is held high for the first 32 clocks,
    // then asserted low for next 32. No need to initially set it high as this
    // is done by clearing CS0N_ASSERT in flash_init_spi.
    s_varm_crit_flash_init_spi();

    const uint32_t qmi_cmd_16_ones = 0xffffu | QMI_DIRECT_TX_NOPUSH_BITS | QMI_DIRECT_TX_DWIDTH_BITS;
    const uint32_t qmi_cmd_qpi_f5 = 0xf5u | QMI_DIRECT_TX_NOPUSH_BITS | QMI_DIRECT_TX_OE_BITS |
        (QMI_DIRECT_TX_IWIDTH_VALUE_Q << QMI_DIRECT_TX_IWIDTH_LSB);

    // If there are two QSPI devices, we need to issue the exit sequence to both of them.
    uint n_chip_selects = 1 + (s_varm_flash_devinfo_get_size(1) > 0);
    for (uint cs = 0; cs < n_chip_selects; ++cs) {

        uint32_t padctrl_tmp = (qspi_sd_padctrl->sd0 & ~PADS_QSPI_GPIO_QSPI_SD0_PUE_BITS) |
                               (PADS_QSPI_GPIO_QSPI_SD0_OD_BITS | PADS_QSPI_GPIO_QSPI_SD0_PDE_BITS);

        for (int i = 0; i < 2; ++i) {
            qspi_sd_padctrl->sd0 = padctrl_tmp;
            qspi_sd_padctrl->sd1 = padctrl_tmp;
            qspi_sd_padctrl->sd2 = padctrl_tmp;
            qspi_sd_padctrl->sd3 = padctrl_tmp;

            // Brief delay for pulls to take effect: 50 us at max expected ROSC (23 MHz)
            varm_to_s_native_busy_wait_at_least_cycles(50 * ROSC_MHZ_MAX);

            // Issue 32 SCK cycles
            uint32_t toggle = QMI_DIRECT_CSR_EN_BITS | ((uint)i << (QMI_DIRECT_CSR_ASSERT_CS0N_LSB + cs));
            hw_xor_bits(&qmi_hw->direct_csr, toggle);
            qmi_hw->direct_tx = qmi_cmd_16_ones;
            qmi_hw->direct_tx = qmi_cmd_16_ones;
            while (qmi_hw->direct_csr & QMI_DIRECT_CSR_BUSY_BITS);
            hw_xor_bits(&qmi_hw->direct_csr, toggle);

            padctrl_tmp ^= PADS_QSPI_GPIO_QSPI_SD0_PUE_BITS | PADS_QSPI_GPIO_QSPI_SD0_PDE_BITS;
        }

        // Restore IO/pad controls. Put pullup on IO2/IO3 as these may be used as
        // WPn/HOLDn at this point, and we are starting to issue serial commands.
        padctrl_tmp ^= PADS_QSPI_GPIO_QSPI_SD0_OD_BITS;
        qspi_sd_padctrl->sd0 = padctrl_tmp;
        qspi_sd_padctrl->sd1 = padctrl_tmp;
        padctrl_tmp ^= PADS_QSPI_GPIO_QSPI_SD0_PUE_BITS | PADS_QSPI_GPIO_QSPI_SD0_PDE_BITS;
        qspi_sd_padctrl->sd2 = padctrl_tmp;
        qspi_sd_padctrl->sd3 = padctrl_tmp;

        // F5h QPI exit (2 SCK cycles, so should be ignored by devices already in SPI mode)
        qmi_hw->direct_tx = qmi_cmd_qpi_f5;
        cs = s_varm_flash_put_get_nodata(cs);

        // 16x one bits on SD1, should be interpreted as a NOP by most devices
        qmi_hw->direct_tx = qmi_cmd_16_ones;
        cs = s_varm_flash_put_get_nodata(cs);

        // FFh QPI exit (2 SCK cycles, so should be ignored by devices already in
        // SPI mode) Issued after the continuous read mode exit as it's a QPI
        // command which will be ignored when in continuous read mode.
        qmi_hw->direct_tx = __get_opaque_value(qmi_cmd_qpi_f5) + (0xff - 0xf5);
        cs = s_varm_flash_put_get_nodata(cs);
    }
    canary_exit_void(S_VARM_API_CRIT_FLASH_EXIT_XIP);
}

// Initialise QMI address translation to an identity mapping, with a 16 MiB
// downstream window on each chip select, and offset 0 in each window mapped
// to a QSPI address of 0 on that chip select.
void __exported_from_arm s_varm_api_crit_flash_reset_address_trans(void) {
    canary_set_step(STEPTAG_S_VARM_API_CRIT_FLASH_RESET_ADDRESS_TRANS);
    for (int i = 0; i < 8; ++i) {
        const uint32_t size = QMI_ATRANS0_RESET & QMI_ATRANS0_SIZE_BITS;
        qmi_hw->atrans[i] = size | ((i & 3) << ((QMI_ATRANS0_BASE_MSB + 1) - 2));
    }
    canary_check_step(STEPTAG_S_VARM_API_CRIT_FLASH_RESET_ADDRESS_TRANS);
}

// ----------------------------------------------------------------------------
// Programming

// Poll the flash status register until the busy bit (LSB) clears
static __force_inline uint s_varm_flash_wait_ready(uint cs) {
    uint8_t stat;
    do {
        cs = s_varm_flash_do_cmd(cs, FLASHCMD_READ_STATUS, NULL, &stat, 1);
    } while (stat & 0x1 && !s_varm_flash_was_aborted());
    return cs;
}

// Set the WEL bit (needed before any program/erase operation)
static __force_inline uint s_varm_flash_enable_write(uint cs) {
    qmi_hw->direct_tx = FLASHCMD_WRITE_ENABLE | QMI_DIRECT_TX_NOPUSH_BITS;
    return s_varm_flash_put_get_nodata(cs);
}

// Program a 256 byte page at some 256-byte-aligned flash address,
// from some buffer in memory. Blocks until completion.
#if !TAIL_CALL_HACKS
void __exported_from_arm s_varm_flash_page_program(flash_offset_t offset, const uint8_t *data) {
    canary_entry(S_VARM_FLASH_PAGE_PROGRAM);
    bootrom_assert(GENERIC_FLASH, offset < MAX_FLASH_ADDR_OFFSET);
    bootrom_assert(GENERIC_FLASH, !(offset & 0xffu));
    uint cs = inline_s_varm_flash_cs_from_offset(offset);
    cs = s_varm_flash_enable_write(cs);
    s_varm_flash_put_cmd_addr(FLASHCMD_PAGE_PROGRAM, offset);
    cs = varm_to_s_native_crit_flash_put_get(cs, data, NULL, 256);
    (void)s_varm_flash_wait_ready(cs);
    canary_exit_void(S_VARM_FLASH_PAGE_PROGRAM);
}
#endif

// Program a range of flash with some data from memory.
// Size is rounded up to nearest 256 bytes.
void __exported_from_arm s_varm_api_flash_range_program(flash_offset_t offset, const uint8_t *data, size_t count) {
    canary_entry(S_VARM_API_FLASH_RANGE_PROGRAM);
    bootrom_assert(GENERIC_FLASH, !(offset & 0xffu));
    bootrom_assert(GENERIC_FLASH, !(count & 0xffu));
    uint32_t goal = offset + count;
    while (offset < goal && !s_varm_flash_was_aborted()) {
        s_varm_flash_page_program(offset, data);
        offset += 256;
        data += 256;
    }
    canary_exit_void(S_VARM_API_FLASH_RANGE_PROGRAM);
}

// Force MISO input to QMI low so that an in-progress SR polling loop will
// fall through. This is needed when a flash programming task in async task
// context is locked up (e.g. if there is no flash device, and a hard pullup
// on MISO pin -> SR read gives 0xff) and the host issues an abort in IRQ
// context. Bit of a hack
void __exported_from_arm s_varm_flash_abort(void) {
    canary_set_step(STEPTAG_S_VARM_FLASH_ABORT);
    hw_set_bits(
            (io_rw_32 *) (IO_QSPI_BASE + IO_QSPI_GPIO_QSPI_SD1_CTRL_OFFSET),
            IO_QSPI_GPIO_QSPI_SD1_CTRL_INOVER_VALUE_LOW << IO_QSPI_GPIO_QSPI_SD1_CTRL_INOVER_LSB
    );
    canary_check_step(STEPTAG_S_VARM_FLASH_ABORT);
}

// Restore original pin function following an abort. On RP2040 an abort was
// cleared by re-calling connect_internal_flash() to re-init the pads -- on
// RP2350 we only set up the flash once before entering nsboot (which is the
// only user of the abort function) and then don't expose an interface for it
// to be re-inited.
void __exported_from_arm s_varm_flash_abort_clear(void) {
    canary_set_step(STEPTAG_S_VARM_FLASH_ABORT_CLEAR);
    hw_clear_bits(
        (io_rw_32 *) (IO_QSPI_BASE + IO_QSPI_GPIO_QSPI_SD1_CTRL_OFFSET),
        IO_QSPI_GPIO_QSPI_SD1_CTRL_INOVER_BITS
    );
    canary_check_step(STEPTAG_S_VARM_FLASH_ABORT_CLEAR);
}

// Also allow any unbounded loops to check whether the above abort condition
// was asserted, and terminate early
int s_varm_flash_was_aborted(void) {
    return *(io_rw_32 *) (IO_QSPI_BASE + IO_QSPI_GPIO_QSPI_SD1_CTRL_OFFSET)
           & IO_QSPI_GPIO_QSPI_SD1_CTRL_INOVER_BITS;
}

// ----------------------------------------------------------------------------
// Erase

// Setting correct address alignment is the caller's responsibility

// Erase at some address, with a user-supplied erase command, e.g. block erase
// or a chip erase. The address should already be aligned to the requirements
// of the specified command (e.g. 64k for a 64k block erase)

#if !TAIL_CALL_HACKS

void s_varm_flash_user_erase(flash_offset_t offset, uint8_t cmd) {
    canary_entry(S_VARM_FLASH_USER_ERASE);
    bootrom_assert(GENERIC_FLASH, offset < MAX_FLASH_ADDR_OFFSET);
    bootrom_assert(GENERIC_FLASH, !(offset & 0xfffu));
    uint cs = inline_s_varm_flash_cs_from_offset(offset);
    cs = s_varm_flash_enable_write(cs);
    s_varm_flash_put_cmd_addr(cmd, offset);
    cs = s_varm_flash_put_get_nodata(cs);
    (void)s_varm_flash_wait_ready(cs);
    canary_exit_void(S_VARM_FLASH_USER_ERASE);
}

// Erase one 4k sector of flash, using a standard 20h 4k erase command. The
// address should be 4k-aligned.
void __exported_from_arm s_varm_flash_sector_erase(flash_offset_t offset) {
    bootrom_assert(GENERIC_FLASH, !(offset & 0xfffu));
    s_varm_flash_user_erase(offset, FLASHCMD_SECTOR_ERASE);
}

#else // TAIL_CALL_HACKS

// Shared-tail implementation of s_varm_flash_sector_erase,
// s_varm_flash_user_erase, and s_varm_flash_page_program
void __used __attribute__((naked)) s_varm_flash_sector_erase(__unused flash_offset_t offset) {
    pico_default_asm_volatile(
        "movs r1, " __XSTRING(FLASHCMD_SECTOR_ERASE) "\n"
        // fall through
    ".global s_varm_flash_user_erase\n"
    ".thumb_func\n"
    "s_varm_flash_user_erase:\n"
    );
    {canary_entry_reg(ip, S_VARM_FLASH_USER_ERASE); __dataflow_barrier(__stack_canary_value);}
    pico_default_asm_volatile(
        "movs r3, #0\n"
        "b.n 1f\n"
    ".global s_varm_flash_page_program\n"
    ".thumb_func\n"
    "s_varm_flash_page_program:\n"
    );
    {canary_entry_reg(ip, S_VARM_FLASH_USER_ERASE); __dataflow_barrier(__stack_canary_value);}
    static_assert(FLASHCMD_PAGE_PROGRAM == 0x02, "");
    pico_default_asm_volatile(
        "movs r2, r1\n"
        "movs r1, #0x02\n"
        "lsls r3, r1, #7\n" // 256 bytes
    "1:\n"
        // fall through into s_varm_flash_erase_or_program via linker script fettling
    );
}
// Don't try to call this as a function -- you'll get RCP checked. The valid
// entry points are the ones in the asm prelude above.
static void __used s_varm_flash_erase_or_program(flash_offset_t offset, uint8_t cmd, const uint8_t *tx, size_t count) {
    // Need to plumb the prelude canary value into this function's dataflow so that the compiler
    // will keep it live for us (probably in a callee save) -- ip will get trashed by calls.
    // Note __stack_canary_value is the magic variable consumed by canary_exit_*() macros.
    register uint32_t __prelude_canary_value asm("ip");
    __dataflow_barrier(__prelude_canary_value);
    uint32_t __stack_canary_value = __prelude_canary_value;
    __dataflow_barrier(__stack_canary_value);

    bootrom_assert(GENERIC_FLASH, offset < MAX_FLASH_ADDR_OFFSET);
    if (cmd == FLASHCMD_PAGE_PROGRAM) {
        bootrom_assert(GENERIC_FLASH, !(offset & 0xffu));
    } else {
        bootrom_assert(GENERIC_FLASH, !(offset & 0xfffu));
    }
    uint cs = inline_s_varm_flash_cs_from_offset(offset);
    cs = s_varm_flash_enable_write(cs);
    s_varm_flash_put_cmd_addr(cmd, offset);
    cs = varm_to_s_native_crit_flash_put_get(cs, tx, NULL, count);
    (void)s_varm_flash_wait_ready(cs);
    canary_exit_void(S_VARM_FLASH_USER_ERASE);
}
#endif

// Erase a specified range of flash, using a mixture of sector erase and block
// erase commands. Sector erase commands have the best compatibility across
// 25-series flash devices, but most devices also expose a block erase
// command which erases a larger naturally aligned region of flash in one
// operation, and makes bulk erase operations faster. In particular a D8h
// erase command with a block size of 64k is very common, but not quite
// universal.
//
// block_size must be a power of 2. Generally block_size > 4k, and block_cmd
// is some command which erases a block of this size.
//
// The start and end of the specified address range have a minimum alignment
// of whichever is smaller out of 4k and block_size (usually 4k).
//
// To use sector-erase only, set block_size to 4k and block_cmd to 20h.
void __exported_from_arm s_varm_api_flash_range_erase(flash_offset_t offset, size_t count, uint32_t block_size, uint8_t block_cmd) {
    canary_entry(S_VARM_API_FLASH_RANGE_ERASE);
    uint32_t goal = offset + count;
    while (offset < goal && !s_varm_flash_was_aborted()) {
        if (!(offset & (block_size - 1)) && goal - offset >= block_size) {
            s_varm_flash_user_erase(offset, block_cmd);
            offset += block_size;
        } else {
            s_varm_flash_sector_erase(offset);
            offset += FLASH_SECTOR_SIZE;
        }
    }
    canary_exit_void(S_VARM_API_FLASH_RANGE_ERASE);
}

// ----------------------------------------------------------------------------
// Read

// Put the QMI into a mode where XIP accesses translate to standard
// serial 03h read commands. The flash remains in its default serial command
// state, so will still respond to other commands.
//
// Note the RP2350 bootrom leaves the QMI in the same 03h XIP configuration between
// programming commands, so it's no longer necessary to call this after flash
// programming, but it doesn't do any harm either.
#if !TAIL_CALL_HACKS
void __exported_from_arm s_varm_api_flash_enter_cmd_xip(void) {
    s_varm_api_crit_flash_select_xip_read_mode(BOOTROM_XIP_MODE_03H_SERIAL, BOOTROM_SPI_CLKDIV_DEFAULT);
}
#else
// Do sibling call to avoid return code which would need to be hardened.
// (also reduce stack usage by 8 bytes). We have sibling call optimisation
// enabled, so GCC ought to be doing this (and clang can do it) but...
static_assert((int)BOOTROM_XIP_MODE_03H_SERIAL == 0, "");
void __attribute__((naked)) __exported_from_arm s_varm_api_flash_enter_cmd_xip(void) {
    pico_default_asm_volatile (
        ".p2align 2\n"
        "movs r0, #0\n"
        "movs r1, #" __XSTRING(BOOTROM_SPI_CLKDIV_DEFAULT) "\n"
        // handled by linker script
        //"b.w s_varm_api_crit_flash_select_xip_read_mode\n"
    );
}
#endif

#if !TAIL_CALL_HACKS
void __exported_from_arm s_varm_crit_flash_read_data(uint8_t *rx, flash_offset_t offset, size_t count) {
    bootrom_assert(GENERIC_FLASH, offset < MAX_FLASH_ADDR_OFFSET);
    offset &= MAX_FLASH_ADDR_OFFSET - 1;
    varm_to_native_memcpy(rx, (const void*)(XIP_NOCACHE_NOALLOC_NOTRANSLATE_BASE + offset), count);
}
#else
void __attribute__((naked)) __exported_from_arm s_varm_crit_flash_read_data(__unused uint8_t *rx, __unused flash_offset_t offset, __unused size_t count) {
    static_assert(MAX_FLASH_ADDR_OFFSET == (1u << 25), "");
    static_assert((XIP_NOCACHE_NOALLOC_NOTRANSLATE_BASE >> 25) == 0xe, "");
    pico_default_asm_volatile (
        "lsls r1, r1, #7\n"
        "adds r1, #0xe\n"
        "movs r3, #7\n"
        "rors r1, r3\n"
        "b.w varm_to_native_memcpy\n"
    );
}
#endif

// ----------------------------------------------------------------------------
// Bounds checking

bool __noinline s_varm_flash_check_in_bounds_single_addr(flash_offset_t offset) {
    canary_set_step(STEPTAG_S_VARM_CRIT_FLASH_CHECK_IN_BOUNDS_SINGLE_ADDR);
    bool rc;
    if (offset >= MAX_FLASH_ADDR_OFFSET) {
        rc = false;
        goto single_addr_done;
    }
    uint cs = inline_s_varm_flash_cs_from_offset(offset);
    if (offset - cs * (1u << 24) >= s_varm_flash_devinfo_get_size(cs)) {
        rc = false;
        goto single_addr_done;
    }
    rc = true;
    single_addr_done:
    canary_check_step(STEPTAG_S_VARM_CRIT_FLASH_CHECK_IN_BOUNDS_SINGLE_ADDR);
    return rc;
}

bool __noinline s_varm_crit_flash_check_in_bounds_addr_span(flash_offset_t start_addr, uint32_t size) {
    canary_entry_reg(r4, S_VARM_CRIT_FLASH_CHECK_IN_BOUNDS_ADDR_SPAN);
    bool ok = false;

    if (!s_varm_flash_check_in_bounds_single_addr(start_addr)) {
        goto done;
    }
    if (size == 0) {
        ok = true;
        goto done;
    }

    // Minus one as we are checking the end address inclusively
    flash_offset_t end_addr = start_addr + size - 1u;
    // Anything which causes unsigned wrapping, with the exception of size-0 spans, is invalid
    if (end_addr < start_addr) {
        goto done;
    }
    if (!s_varm_flash_check_in_bounds_single_addr(end_addr)) {
        goto done;
    }
    // Spanning two chip selects is (conservatively) not permitted. When calling the checked flash
    // API with translation enabled, we break the transfer across ATRANS chunk boundaries, so this
    // check is avoided. When calling with raw storage addresses, you will have to manually split
    // transfers across chip selects.
    if (inline_s_varm_flash_cs_from_offset(start_addr) != inline_s_varm_flash_cs_from_offset(end_addr)) {
        goto done;
    }
    ok = true;
done:
    canary_exit_return(S_VARM_CRIT_FLASH_CHECK_IN_BOUNDS_ADDR_SPAN, ok);
}
