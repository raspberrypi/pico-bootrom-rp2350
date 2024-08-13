/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "bootrom.h"
#include "bootram.h"
#include "native_generic_flash.h"
#include "boot/picobin.h"
#include "hardware/regs/addressmap.h"
#include "hardware/sync.h"

// Helper functions for checking the permissions of flash storage addresses, based on the resident
// partition table.
//
// Note: A flash storage address is the QSPI bus address, plus the XIP hardware base address at
// which that QSPI device is first mapped in memory. Equivalently, it is the result of applying the
// XIP address translation configured by the QMI_ATRANSx registers to a system bus address. When
// the XIP address translation is disabled (or rather, configured to an identity mapping), the
// flash storage address is the same as the system bus address that a processor will perform a
// load/store on.
//
// This is different from the raw QSPI addresses ("flash offsets") used by the low-level flash
// programming code. A flash storage address is converted to a flash offset by subtracting
// XIP_BASE. For example a flash offset of 0x100, 256 bytes into the first QSPI device, has a flash
// storage address of 0x10000100. A flash offset of 0x01001234, which is 0x1234 bytes into
// the *second* chip select, has a flash storage address of 0x11001234.
//
// A program linked to run at address 0x10000000 may not actually be stored at that address in
// flash. For example, when A/B images are in play (for phased upgrades), there are two possible
// flash locations where the first sector of the currently running program may actually be stored,
// and neither of them will be at flash storage address 0x10000000, since in this example there is
// necessarily a partition table (to identify the two A/B image partitions) which occupies the
// first sector(s) of flash. In this case, *you must translate your flash addresses* using
// s_varm_flash_translate_physaddr_to_storage_addr().

typedef uint32_t flash_permission_mask_t;

typedef uintptr_t storage_addr_t;

static inline flash_offset_t s_varm_flash_translate_storage_addr_to_offset(storage_addr_t addr) {
	return (flash_offset_t)(addr - XIP_BASE);
}

// Walk the resident partition table and return the index of the first partition which matches a
// query address. Return PARTITION_TABLE_MAX_PARTITIONS if no matching partition was found, and
// return -1 if the query address is invalid.
int s_varm_flashperm_get_partition_num_from_storage_address(storage_addr_t addr);

// Default partition entry when nothing was found, defines the permissions of unpartitioned space
static __force_inline resident_partition_t s_varm_flashperm_get_default_partition(void) {
    // we expect it to have been loaded when this is called
    bootrom_assert(MISC, bootram->always.partition_table.loaded);
    const resident_partition_table_t *pt = &bootram->always.partition_table;
    return (resident_partition_t) {
		// Default partition is always max possible size -- don't worry about chip select address
		// hole as that is checked separately when validating address spans
		.permissions_and_location = (
				pt->unpartitioned_space_permissions_and_flags & PICOBIN_PARTITION_PERMISSIONS_BITS
			) | PICOBIN_PARTITION_LOCATION_LAST_SECTOR_BITS,
		.permissions_and_flags    = pt->unpartitioned_space_permissions_and_flags
	};
}

//// Walk the resident partition table and return, by value, the first partition which matches a query
//// address. Return an all-zeroes entry if no matching partition was found.
//static __force_inline resident_partition_t s_varm_flashperm_get_partition_from_storage_address(storage_addr_t addr) {
//	int partition_num = s_varm_flashperm_get_partition_num_from_storage_address(addr);
//	if (partition_num < 0) {
//		return (resident_partition_t) {
//			.location_and_permissions = 0,
//			.flags_and_permissions = 0
//		};
//	} else if (partition_num == PARTITION_TABLE_NO_PARTITION_INDEX) {
//		return s_varm_flashperm_get_default_partition();
//	} else {
//		return bootram->always.partition_table.partitions[partition_num];
//	}
//}

// Check that a given partition has ALL the specified permission flags
static __force_inline bool s_varm_flashperm_partition_has_permissions(resident_partition_t partition, flash_permission_mask_t required_permissions) {
	// The permissions are stored redundantly in the two halves of the entry, and when a bit
	// differs, we take the less-permissive value (bitwise AND)
	uint32_t actual_permissions = (
            partition.permissions_and_location &
            partition.permissions_and_flags &
            PICOBIN_PARTITION_PERMISSIONS_BITS
	);
	bool permissions_lacking = required_permissions & ~actual_permissions;
	return !permissions_lacking;
}

#if BOOTROM_ASSERT_FLASH_PERMISSIONS_ENABLE
#include "varm_boot_path.h"
#endif

// Check that a given partition number in the resident table has ALL the specified permission flags
static __force_inline bool s_varm_flashperm_partition_num_has_permissions(int partition_num, flash_permission_mask_t required_permissions) {
	if (partition_num == PARTITION_TABLE_NO_PARTITION_INDEX) {
		return s_varm_flashperm_partition_has_permissions(s_varm_flashperm_get_default_partition(), required_permissions);
	} else {
#if BOOTROM_ASSERT_FLASH_PERMISSIONS_ENABLE // because of need for include
        bootrom_assert(FLASH_PERMISSIONS, inline_s_is_resident_partition_table_loaded());
#endif
        if (partition_num >= 0 && partition_num < bootram->always.partition_table.permission_partition_count) {
            return s_varm_flashperm_partition_has_permissions(bootram->always.partition_table.partitions[partition_num],
                                                              required_permissions);
        } else {
            return false;
        }
	}
}

//// Check that a given single flash storage address has ALL the specified permission flags
//static __force_inline bool s_varm_flashperm_storage_addr_has_permissions(uint32_t addr, flash_permission_mask_t required_permissions) {
//	return s_varm_flashperm_partition_num_has_permissions(
//		s_varm_flashperm_get_partition_num_from_storage_address(addr),
//		required_permissions
//	);
//}

// Check that a given span of flash storage addresses has ALL the specified permission flags, and
// does not start/end in different partitions.
static __force_inline bool s_varm_flashperm_storage_addr_span_has_permissions(storage_addr_t start_addr, uint32_t size, flash_permission_mask_t required_permissions) {
	// The span itself must be valid, e.g. no crossing of an address hole between two flash devices.
	if (!s_varm_crit_flash_check_in_bounds_addr_span(start_addr - XIP_BASE, size)) {
		return false;
	}
	// Assumption: if a span's endpoints are in the same partition, all addresses in between have at
	// least the permissions of that partition. This assumption is violated if you embed a
	// Secure-RW partitition inside of a NonSecure-RW partition (for example), so don't do that
	int pnum_at_start = s_varm_flashperm_get_partition_num_from_storage_address(start_addr);
	int pnum_at_end   = s_varm_flashperm_get_partition_num_from_storage_address(start_addr + size - 1);

	// Bridging between two different partitions: not valid
	if (pnum_at_start != pnum_at_end) {
		return false;
	}

	// Permissions of the span are the permissions of the startpoint
	return s_varm_flashperm_partition_num_has_permissions(pnum_at_start, required_permissions);
}
