/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bootrom.h"
#include "hardening.h"
#include "varm_checked_flash.h"

// The functions in this file are ARM8 because they are only used by SG on
// ARM. If the API is available on RISC-V under varmulet, these wrappers are
// bypassed and the varm_ function is called directly

#include "arm8_validate_ns_buffer.h"

// There is no functional difference between an SG implementation in main text
// vs in NSC text, since the actual SG instruction is separated from the
// implementation due to shared permission/return code. So, push them to
// whichever section to satisfy code layout constraints.
#define __sg_impl_exempt
#define __sg_impl_nsc __attribute__((noinline, section(".secure_gateways")))

int __sg_impl_nsc s_from_ns_arm8_api_checked_flash_op(cflash_flags_t flags, uintptr_t addr, uint32_t size_bytes, uint8_t *buf) {
    int rc;
    canary_entry(S_FROM_NS_ARM8_API_CHECKED_FLASH_OP);
    hx_bool buffer_ok = hx_bool_invalid();
    // Call from NonSecure: effective security level of the flash access must also be NS. This is
    // checked against the permissions in the resident partition table.
    uint seclevel = (flags.flags & CFLASH_SECLEVEL_BITS) >> CFLASH_SECLEVEL_LSB;
    uint op = (flags.flags & CFLASH_OP_BITS) >> CFLASH_OP_LSB;
    if (seclevel != CFLASH_SECLEVEL_VALUE_NONSECURE) {
        rc = BOOTROM_ERROR_INVALID_ARG;
        goto checked_flash_op_done;
    }
    if ((op == CFLASH_OP_VALUE_ERASE) != (buf == NULL)) {
        rc = BOOTROM_ERROR_INVALID_ARG;
        goto checked_flash_op_done;
    }
    // NS flash operations with RAM buffers must point to NS-accessible RAM
    hx_bool write = make_hx_bool(op != CFLASH_OP_VALUE_READ);
    if (buf != NULL) {
        buf = s_native_api_validate_ns_buffer(buf, size_bytes, write, &buffer_ok);
        if (hx_is_false(buffer_ok)) {
            rc = (int)buf; // will be BOOTROM_ERROR_INVALID_ADDRESS;
            goto checked_flash_op_done;
        }
    }
    hx_assert_true(buffer_ok);
    rc = s_varm_api_checked_flash_op(flags, addr, size_bytes, buf);
    checked_flash_op_done:
    canary_exit_return(S_FROM_NS_ARM8_API_CHECKED_FLASH_OP, rc);
}

int __sg_impl_nsc s_from_ns_arm8_api_flash_runtime_to_storage_addr(uintptr_t addr) {
    canary_entry(S_FROM_NS_ARM8_API_FLASH_RUNTIME_TO_STORAGE_ADDR);
    // Only allow SAU-NonSecure addresses to be translated via this gateway
    hx_bool addr_ok = hx_bool_invalid();
    addr = (uintptr_t)s_native_api_validate_ns_buffer((const void *) addr, 1, hx_false(), &addr_ok);
    if (hx_is_false(addr_ok)) {
        // already the case
        // addr = (uintptr_t)BOOTROM_ERROR_INVALID_ADDRESS;
        goto runtime_to_storage_addr_done;
    }
    hx_assert_true(addr_ok);
    addr = s_varm_api_flash_runtime_to_storage_addr(addr);
    if ((int32_t)addr < 0) {
        addr = (uintptr_t)BOOTROM_ERROR_INVALID_ADDRESS;
    }
    runtime_to_storage_addr_done:
    canary_exit_return(S_FROM_NS_ARM8_API_FLASH_RUNTIME_TO_STORAGE_ADDR, (int)addr);
}
