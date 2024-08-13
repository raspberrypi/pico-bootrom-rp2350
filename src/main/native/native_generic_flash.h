/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "bootrom.h"
#include "bootrom_otp.h"
#include "bootram.h"
#include "hardware/structs/qmi.h"

#include <stdint.h>
#include <stddef.h>

#define FLASH_PAGE_SHIFT 8u
#define FLASH_PAGE_SIZE (1ul << FLASH_PAGE_SHIFT)
#define FLASH_PAGE_REMAINDER_MASK (FLASH_PAGE_SIZE - 1u)

// Get non-sector parts of a flash storage address, assuming 2x16MiB windows:
#define FLASH_SECTOR_NUM_MASK ((1ul << 25) - (1ul << FLASH_SECTOR_SHIFT))

// The SCK divisor set by flash_init_spi, is the default used for programming,
// reads from the debugger post-programming, etc: (1 MHz @ 12 MHz clk_sys)
// Quite conservative as clk_sys may be rather high when this is used, and
// 03h reads may support quite low maximum SCK frequency.
#define BOOTROM_SPI_CLKDIV_DEFAULT 12u
// The SCK divisor used by nsboot (the USB/UART bootloader), which runs at a
// fixed 48 MHz clk_sys -> 8 MHz SCK, the same as RP2040 in BOOTSEL mode.
#define BOOTROM_SPI_CLKDIV_NSBOOT 6u
// The first divisor to attempt to use to read flash during flash boot:
// (-> 50 MHz at max clk_sys of 150 MHz, ~4 MHz at expected ROSC freq)
#define BOOTROM_SPI_CLKDIV_FLASH_BOOT_MIN 3u
// After trying all modes, flash boot will fall back to progressively slower
// divisors (doubling each time) up to this maximum:
// (->  6.25 MHz at max clk_sys, snail's pace at expected ROSC boot freq)
#define BOOTROM_SPI_CLKDIV_FLASH_BOOT_MAX 24u

#define NUM_FLASH_BOOT_CLOCK_DIVS 4

typedef uint32_t flash_offset_t;

static_assert(BOOTROM_SPI_CLKDIV_FLASH_BOOT_MAX == BOOTROM_SPI_CLKDIV_FLASH_BOOT_MIN << (NUM_FLASH_BOOT_CLOCK_DIVS-1), "");
// Try each clock divisor in each mode before giving up.
#define FLASH_SETTING_COMBINATION_COUNT (BOOTROM_XIP_MODE_N_MODES * NUM_FLASH_BOOT_CLOCK_DIVS)

void s_varm_api_crit_connect_internal_flash(void);
void s_varm_api_crit_flash_reset_address_trans(void);
void s_varm_api_crit_flash_select_xip_read_mode(bootrom_xip_mode_t mode, uint8_t clkdiv);
uint varm_callable(s_native_crit_flash_put_get)(uint cs, const uint8_t *tx, uint8_t *rx, size_t count);
uint s_varm_flash_do_cmd(uint cs, uint8_t cmd, const uint8_t *tx, uint8_t *rx, size_t count);
void s_varm_api_crit_flash_exit_xip(void);
void s_varm_flash_page_program(flash_offset_t offset, const uint8_t *data);
void s_varm_api_flash_range_program(flash_offset_t offset, const uint8_t *data, size_t count);
void s_varm_flash_sector_erase(flash_offset_t offset);
void s_varm_flash_user_erase(flash_offset_t offset, uint8_t cmd);
void s_varm_api_flash_range_erase(flash_offset_t offset, size_t count, uint32_t block_size, uint8_t block_cmd);
void s_varm_crit_flash_read_data(uint8_t *rx, uint32_t offset, size_t count);
void s_varm_api_flash_enter_cmd_xip(void);
void s_varm_flash_abort(void);
void s_varm_flash_abort_clear(void);
int s_varm_flash_was_aborted(void);

#if 0
void s_varm_api_crit_flash_flush_cache(void);
void s_varm_crit_pin_xip_ram(void);
#else
// Annotated with correct (minimal) clobbers to save spill/fill at call site
static __force_inline void s_varm_api_crit_flash_flush_cache(void) {
	pico_default_asm_volatile (
		"bl s_varm_api_crit_flash_flush_cache_impl\n"
		: : : "r0", "r3", "ip", "lr", "cc"
	);
}
static __force_inline void s_varm_crit_pin_xip_ram(void) {
	pico_default_asm_volatile (
		"bl s_varm_crit_pin_xip_ram_impl\n"
		: : : "r0", "r3", "ip", "lr", "cc"
	);
}
#endif

static __force_inline uint inline_s_varm_flash_cs_from_offset(flash_offset_t offset) {
    bootrom_assert(GENERIC_FLASH, offset < MAX_FLASH_ADDR_OFFSET);
    return (offset >> 24) & 0x1u;
}

#ifndef __riscv
// OTP-related getters are not used in the RISC-V parts of the bootrom
// (they should be in shared arm6 code)

// Default flash device info used if OTP is not marked as valid:
#define FLASH_DEFAULT_DEVINFO ( \
	OTP_DATA_FLASH_DEVINFO_CS0_SIZE_VALUE_16M  << OTP_DATA_FLASH_DEVINFO_CS0_SIZE_LSB | \
	OTP_DATA_FLASH_DEVINFO_CS1_SIZE_VALUE_NONE << OTP_DATA_FLASH_DEVINFO_CS1_SIZE_LSB \
)

static __force_inline uint32_t s_varm_flash_devinfo_get_size(uint cs) {
	uint shamt = OTP_DATA_FLASH_DEVINFO_CS0_SIZE_LSB + cs * (
		OTP_DATA_FLASH_DEVINFO_CS1_SIZE_LSB - OTP_DATA_FLASH_DEVINFO_CS0_SIZE_LSB
	);
	uint32_t mask = OTP_DATA_FLASH_DEVINFO_CS0_SIZE_BITS >> OTP_DATA_FLASH_DEVINFO_CS0_SIZE_LSB;
	// Calculate based on the cached devinfo which was read out during early boot
	uint size_bits = (bootram->always.zero_init.flash_devinfo >> shamt) & mask;
	// Encoded as log2(4k sector count):
	return size_bits == 0u ? 0u : (0x1000u << size_bits);
}

static __force_inline bool s_varm_flash_devinfo_get_d8h_supported(void) {
	return bootram->always.zero_init.flash_devinfo & OTP_DATA_FLASH_DEVINFO_D8H_ERASE_SUPPORTED_BITS;
}

// Return -1 if no CS1 device, otherwise return GPIO number
static __force_inline int inline_s_varm_flash_devinfo_get_cs1_gpio(void) {
	uint16_t devinfo = bootram->always.zero_init.flash_devinfo;
	if ((devinfo & OTP_DATA_FLASH_DEVINFO_CS1_SIZE_BITS) == 0) {
		return -1;
	} else {
		return (devinfo & OTP_DATA_FLASH_DEVINFO_CS1_GPIO_BITS) >> OTP_DATA_FLASH_DEVINFO_CS1_GPIO_LSB;
	}
}

// Return true if the given flash offset is within the bounds of known flash devices
bool s_varm_flash_check_in_bounds_single_addr(flash_offset_t offset);

// Return true if all flash offsets within a range are within the bounds of known flash devices
bool s_varm_crit_flash_check_in_bounds_addr_span(flash_offset_t start_addr, uint32_t size);

#endif
