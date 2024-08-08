/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "bootrom.h"
#include "varm_flash_permissions.h"

static_assert(CFLASH_FLAGS_BITS == (CFLASH_ASPACE_BITS | CFLASH_SECLEVEL_BITS | CFLASH_OP_BITS), "");

// Apply the address translation currently specified in QMI_ATRANSx ("rolling window" hardware
// translation). Need to take care using this on the boot path, as the QMI may not yet have been
// set up, but this should be suitable for translating system bus addresses into flash storage
// addresses in user callbacks. Returns all-ones for an invalid address, which is also an invalid
// flash storage address, so invalidity is propagated.
storage_addr_t s_varm_api_flash_runtime_to_storage_addr(uintptr_t flash_runtime_addr);

// Perform the specified erase/program/read operation, translating addresses according to
// QMI_ATRANSx if necessary, and checking flash permissions based on the resident partition table
// and the specified effective security level. `addr` may be either a flash runtime address or a
// flash storage address, depending on the ASPACE given in `flags`.
//
// NOTE: This function does not validate the buffer for NS access. This must be validated before
// calling if the caller is reachable from a Secure Gateway.
int s_varm_api_checked_flash_op(cflash_flags_t flags, uintptr_t addr, uint32_t size_bytes, uint8_t *buf);
