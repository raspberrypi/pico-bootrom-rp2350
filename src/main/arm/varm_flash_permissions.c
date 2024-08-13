/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "varm_flash_permissions.h"
#include "mini_printf.h"
#include "varm_boot_path.h"

// Walk the resident partition table and return the index of the first partition which matches a
// query address. Return PARTITION_TABLE_MAX_PARTITIONS if no matching partition was found, and
// return -1 if the query address is invalid or if the table is not yet loaded.
int __noinline s_varm_flashperm_get_partition_num_from_storage_address(storage_addr_t addr) {
    canary_entry(S_VARM_FLASHPERM_GET_PARTITION_NUM_FROM_STORAGE_ADDRESS);
	// We are dealing with flash storage addresses, i.e., the SPI wire-level address plus the XIP
	// hardware base address for that chip select. So, subtract the XIP hardware base address.
	addr -= XIP_BASE;
    int rc;

	// If the address is outside the bounds of known flash hardware (as configured by
	// OTP_DATA_FLASH_DEVINFO) then don't even bother to walk the table. The default if the
	// FLASH_DEVINFO_ENABLE flag is not set is 16 MiB for the first chip select, and nothing on the
	// second chip select.
	if (!s_varm_flash_check_in_bounds_single_addr(addr)) {
        rc = -1;
        goto from_storage_address_done;
	}

    // If we don't know anything then we can't give permission for anything
    if (!inline_s_is_resident_partition_table_loaded()) {
        rc = -1;
        goto from_storage_address_done;
    }

    // Read the partition count only once, and order the partition reads against it, to avoid
    // reading partially populated entries when the table is being appended. Assume that, on
    // append, entries are populated before incrementing the count. (A compiler memory barrier is
    // sufficient here because bootram should be strongly-ordered)
    const resident_partition_table_t *table = &bootram->always.partition_table;
    uint8_t partition_count = table->permission_partition_count;
    __compiler_memory_barrier();

    uint32_t addr_sector_num = (addr & FLASH_SECTOR_NUM_MASK) >> FLASH_SECTOR_SHIFT;

    bootrom_assert(PARTITION_TABLE, partition_count <= PARTITION_TABLE_MAX_PARTITIONS);
    for (uint i = 0; i < partition_count; ++i) {
        uint start_sector_num = (
                table->partitions[i].permissions_and_location & PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_BITS
        ) >> PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_LSB;
        uint end_sector_num = (
                table->partitions[i].permissions_and_location & PICOBIN_PARTITION_LOCATION_LAST_SECTOR_BITS
        ) >> PICOBIN_PARTITION_LOCATION_LAST_SECTOR_LSB;

        // Return first partition which matches the test address
        if (addr_sector_num >= start_sector_num && addr_sector_num <= end_sector_num) {
            rc = (int)i;
            goto from_storage_address_done;
        }
    }

	// Loop fell through: no partition was found, so apply the default permissions
	rc = PARTITION_TABLE_NO_PARTITION_INDEX;
    from_storage_address_done:
    canary_exit_return(S_VARM_FLASHPERM_GET_PARTITION_NUM_FROM_STORAGE_ADDRESS, rc);
}
