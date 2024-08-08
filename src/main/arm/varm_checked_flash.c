/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bootrom.h"
#include "varm_checked_flash.h"
#include "varm_flash_permissions.h"
#include "native_generic_flash.h"
#include "mini_printf.h"

// #define VERBOSE_CFLASH_PRINTF 1

storage_addr_t __exported_from_arm s_varm_api_flash_runtime_to_storage_addr(uintptr_t flash_runtime_addr) {
	canary_set_step(STEPTAG_S_VARM_FLASH_TRANSLATE_RUNTIME_TO_STORAGE_ADDR);
	storage_addr_t rv = (storage_addr_t) BOOTROM_ERROR_INVALID_ADDRESS;
	if (flash_runtime_addr < XIP_BASE || flash_runtime_addr >= XIP_BASE + MAX_FLASH_ADDR_OFFSET) {
		goto return_invalid;
	}
	// Emulate the hardware operation: address modulo 4 MiB is added to a 4k-aligned base address
	// ranging 0 <= base < 16MiB, which is then taken modulo 16 MiB and added to the chip select's base
	// address. In other words, only bits 23:12 of the address are actually translated.
	const storage_addr_t translated_bit_mask = __get_opaque_value(0x00fff000u);
    const storage_addr_t inverted_translated_bit_mask = ~translated_bit_mask;
    const storage_addr_t window_index_mask   = 0x01c00000u;
#if 0
	const storage_addr_t window_offset_mask  = 0x003ff000;

	uint atrans_index = ((storage_addr_t)flash_runtime_addr & window_index_mask) >> 22;
	uint32_t atrans = qmi_hw->atrans[atrans_index];
	storage_addr_t window_base = ((atrans & QMI_ATRANS0_BASE_BITS) >> QMI_ATRANS0_BASE_LSB) << FLASH_SECTOR_SHIFT;
	storage_addr_t window_size = ((atrans & QMI_ATRANS0_SIZE_BITS) >> QMI_ATRANS0_SIZE_LSB) << FLASH_SECTOR_SHIFT;
#else
    static_assert(((QMI_ATRANS0_SIZE_BITS >> QMI_ATRANS0_SIZE_LSB) << FLASH_SECTOR_SHIFT) == ((0x00fff000u >> 1) & 0x00fff000u), "");
    const storage_addr_t qmi_atrans0_size_bits_shifted = (translated_bit_mask >> 1) & translated_bit_mask;
    static_assert(0x003ff000 == ((0x00fff000u >> 2) & 0x00fff000u), "");
    const storage_addr_t window_offset_mask  = (translated_bit_mask >> 2) & translated_bit_mask;

    uint atrans_index = ((storage_addr_t)flash_runtime_addr & window_index_mask) >> 22;
    uint32_t atrans = qmi_hw->atrans[atrans_index];
    storage_addr_t window_base = ((atrans & QMI_ATRANS0_BASE_BITS) >> QMI_ATRANS0_BASE_LSB) << FLASH_SECTOR_SHIFT;
    storage_addr_t window_size = (atrans >> (QMI_ATRANS0_SIZE_LSB - FLASH_SECTOR_SHIFT)) & qmi_atrans0_size_bits_shifted;
#endif
	if (((storage_addr_t)flash_runtime_addr & window_offset_mask) >= window_size) {
		goto return_invalid;
	}
	storage_addr_t translated_bits_unmasked = window_base + ((storage_addr_t)flash_runtime_addr & window_offset_mask);
	rv = ((storage_addr_t)flash_runtime_addr & inverted_translated_bit_mask) | (translated_bits_unmasked & translated_bit_mask);
return_invalid:
	canary_check_step(STEPTAG_S_VARM_FLASH_TRANSLATE_RUNTIME_TO_STORAGE_ADDR);
	return rv;
}

// Core implementation of a checked flash command. Pulled out into a separate function as it may be
// invoked multiple times when address translation is in play.
static int __noinline s_varm_checked_flash_op_notranslate(cflash_flags_t flags, uintptr_t addr, uint32_t size_bytes, uint8_t *buf) {
    canary_entry(S_VARM_CHECKED_FLASH_OP_NOTRANSLATE);
    int rc = inline_s_lock_check(BOOTROM_LOCK_FLASH_OP);
    if (rc) goto op_notranslate_done;

    // Get and validate flags
#if MINI_PRINTF && VERBOSE_CFLASH_PRINTF
    printf("Checked flash cmd, flags=%08x, addr=%08x, size=%08x, buf=%08x\n", flags.flags, addr, size_bytes, (uintptr_t)buf);
#endif
    uint32_t uflags = flags.flags;
    if (uflags & ~CFLASH_FLAGS_BITS) {
        rc = BOOTROM_ERROR_INVALID_ARG;
        goto op_notranslate_done;
    }
    uint seclevel = (uflags & CFLASH_SECLEVEL_BITS) >> CFLASH_SECLEVEL_LSB;
    if (seclevel == 0) {
        rc = BOOTROM_ERROR_INVALID_ARG;
        goto op_notranslate_done;
    }
    uint op = (uflags & CFLASH_OP_BITS) >> CFLASH_OP_LSB;
    if (op > CFLASH_OP_MAX) {
        rc = BOOTROM_ERROR_INVALID_ARG;
        goto op_notranslate_done;
    }

    // We assume the buffer has already been validated for NS access in a gateway function if the
    // caller is NS. Note this code may be run under emulation on RISC-V, so it's best to avoid
    // calling the v8-M buffer validation routine.

    static_assert((PICOBIN_PARTITION_PERMISSION_S_R_BITS << 1) == PICOBIN_PARTITION_PERMISSION_S_W_BITS, "");
    static_assert((PICOBIN_PARTITION_PERMISSION_S_R_BITS << 2) == PICOBIN_PARTITION_PERMISSION_NS_R_BITS, "");
    static_assert((PICOBIN_PARTITION_PERMISSION_S_R_BITS << 4) == PICOBIN_PARTITION_PERMISSION_NSBOOT_R_BITS, "");
    static_assert(CFLASH_SECLEVEL_VALUE_BOOTLOADER == 2 + CFLASH_SECLEVEL_VALUE_SECURE, "");

    bool permission_w = op == CFLASH_OP_VALUE_ERASE || op == CFLASH_OP_VALUE_PROGRAM;
    uint32_t permission_mask = PICOBIN_PARTITION_PERMISSION_S_R_BITS << ((uint) permission_w + 2 * (
            seclevel - CFLASH_SECLEVEL_VALUE_SECURE
    ));

    if (!s_varm_flashperm_storage_addr_span_has_permissions(addr, size_bytes, permission_mask)) {
        printf("OP %d %p + %08x permission failure\n", op, addr, size_bytes);
        rc = BOOTROM_ERROR_NOT_PERMITTED;
        goto op_notranslate_done;
    }

    // Alignment check is done after address validation, to ensure we propagate failed translations
    // in caller into NOT_PERMITTED (by virtue of error rc of the translation API itself being OOB)
    // instead of reporting them as BAD_ALIGNMENT
    uint alignment_lsb =
            op == CFLASH_OP_VALUE_ERASE ? FLASH_SECTOR_SHIFT :
            op == CFLASH_OP_VALUE_PROGRAM ? FLASH_PAGE_SHIFT : 0;

    uint32_t alignment_mask = ~(-1u << alignment_lsb);
    if ((addr & alignment_mask) || (size_bytes & alignment_mask)) {
        rc = BOOTROM_ERROR_BAD_ALIGNMENT;
        goto op_notranslate_done;
    }

    switch (op) {
        case CFLASH_OP_VALUE_PROGRAM:
            s_varm_api_flash_range_program(addr - XIP_BASE, buf, size_bytes);
            break;
        case CFLASH_OP_VALUE_ERASE:
            // D8h block erase command is used only if it is marked as supported by flash device info
            // read from OTP during boot, or later set by Secure code writing to bootram cached device info
            s_varm_api_flash_range_erase(addr - XIP_BASE, size_bytes,
                                         s_varm_flash_devinfo_get_d8h_supported() ? 1u << 16 : -1u, 0xd8);
            break;
        case CFLASH_OP_VALUE_READ:
            s_varm_crit_flash_read_data(buf, addr - XIP_BASE, size_bytes);
            break;
    }

    rc = BOOTROM_OK;
    op_notranslate_done:
    canary_exit_return(S_VARM_CHECKED_FLASH_OP_NOTRANSLATE, rc);
}

int __exported_from_arm s_varm_api_checked_flash_op(cflash_flags_t flags, uintptr_t addr, uint32_t size_bytes, uint8_t *buf) {
    canary_entry(S_VARM_API_CHECKED_FLASH_OP);
    int rc;
	// The ATRANS address mapping may split a contiguous span into multiple, smaller spans, if the
	// runtime addresses cross between 4 MiB runtime address boundaries, i.e. upstream translation
	// windows. It's difficult to reason about this on this side, so we split crossing spans before
	// translating, and then check each chunk after translation.
	uint aspace = (flags.flags & CFLASH_ASPACE_BITS) >> CFLASH_ASPACE_LSB;
	if (aspace == CFLASH_ASPACE_VALUE_STORAGE) {
		// No translation required in this case
		rc = s_varm_checked_flash_op_notranslate(flags, addr, size_bytes, buf);
        goto checked_flash_op_done;
	} else { // CFLASH_ASPACE_VALUE_RUNTIME
		uintptr_t span_start = addr;
		uintptr_t span_end = addr + size_bytes;
		if ((span_end < span_start) || (span_start < XIP_BASE) || (span_end > XIP_BASE + MAX_FLASH_ADDR_OFFSET)) {
			rc = BOOTROM_ERROR_INVALID_ADDRESS;
            goto checked_flash_op_done;
		}
		// Iterate over windows, clip span to each window and translate it if the clipped size is nonzero
		const uintptr_t window_size = 1u << 22;
		for (uintptr_t window_base = XIP_BASE; window_base < XIP_BASE + MAX_FLASH_ADDR_OFFSET; window_base += window_size) {
			uintptr_t window_end = window_base + window_size;
			uintptr_t clipped_start = span_start < window_base ? window_base : span_start > window_end ? window_end : span_start;
			uintptr_t clipped_end   = span_end   < window_base ? window_base : span_end   > window_end ? window_end : span_end;
			// If clipped to nothing, there is no overlap between the span and this window, so go check the next one.
			if (clipped_start >= clipped_end) {
				continue;
			}
			// Nonempty intersection between upstream span and this window, so translate the clipped
			// span to get a contiguous downstream span. Note -1 + 1 to avoid off-by-one when
			// access ends at ATRANS boundary; we have already checked span size is nonzero.
			uintptr_t storage_start = s_varm_api_flash_runtime_to_storage_addr(clipped_start);
			uintptr_t storage_end = s_varm_api_flash_runtime_to_storage_addr(clipped_end - 1) + 1;
			// This span will be validated inside s_varm_checked_flash_op_notranslate, so don't
			// duplicate those checks here. (Note the result of a failed translation is not a valid
			// flash storage address, so will fail bounds checking)
			rc = s_varm_checked_flash_op_notranslate(
				flags,
				storage_start,
				storage_end - storage_start,
				buf + (clipped_start - span_start)
			);
			if (rc != BOOTROM_OK) {
                goto checked_flash_op_done;
			}
		}
        rc = BOOTROM_OK;
        checked_flash_op_done:
        canary_exit_return(S_VARM_API_CHECKED_FLASH_OP, rc);
	}
}
