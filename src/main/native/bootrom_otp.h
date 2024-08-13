/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#ifndef __riscv
#include "bootrom.h"
#include "hardware/address_mapped.h"
#include "hardware/regs/otp_data.h"
#include "hardware/structs/otp.h"
#include "hardening.h"

// Offsets are all scaled so that OTP rows are 2 bytes apart (so that the same
// offset is passed into all functions). This means the _raw functions will
// scale the offset by 2 internally.

#define NUM_OTP_ROWS_LOG2 12u
#define NUM_OTP_PAGE_ROWS_LOG2 6u
#define OTP_ROW_MASK (NUM_OTP_ROWS - 1u)
static_assert((1u << NUM_OTP_ROWS_LOG2) == NUM_OTP_ROWS, "");
static_assert((1u << NUM_OTP_PAGE_ROWS_LOG2) == NUM_OTP_PAGE_ROWS, "");
static_assert(NUM_OTP_PAGES == NUM_OTP_ROWS / NUM_OTP_PAGE_ROWS, "");

#define OTP_CMD_BITS (OTP_CMD_ROW_BITS | OTP_CMD_WRITE_BITS | OTP_CMD_ECC_BITS)

// these are defined in the linker script as it makes GCC slightly less dumb
typedef const uint16_t otp_ecc_row_value_t;
typedef const uint32_t otp_ecc_row_value2_t;
typedef const uint32_t otp_raw_row_value_t;
extern otp_ecc_row_value_t otp_data[NUM_OTP_ROWS];
extern otp_ecc_row_value_t otp_data_guarded[NUM_OTP_ROWS];
extern otp_raw_row_value_t otp_data_raw[NUM_OTP_ROWS];
extern otp_raw_row_value_t otp_data_raw_guarded[NUM_OTP_ROWS];

// ----------------------------------------------------------------------------
// SBPI register constants

#define OTP_TARGET_DAP      0x02u
#define OTP_TARGET_PMC      0x3au

#define OTP_REG_READ        0x80u // 10nn_nnnn: read register n
#define OTP_REG_WRITE       0xc0u // 11nn_nnnn:

#define OTP_DAP_DR0         0x00u // Data 7:0
#define OTP_DAP_DR1         0x01u // Data 15:8
#define OTP_DAP_ECC         0x20u // Data 23:16
#define OTP_DAP_RQ0_RFMR    0x30u // Read Mode Control, Charge Pump Control
#define OTP_DAP_RQ1_VRMR    0x31u // Read Voltage Control (VRR), CP enable
#define OTP_DAP_RQ2_OVLR    0x32u // IPS VQQ and VPP Control
#define OTP_DAP_RQ3_IPCR    0x33u // VDD detect, Ext. Ref. enable, ISP enable, OSC. Output Mode, Ext Ck enable, Ref Bias Disable
#define OTP_DAP_RQ4_OSCR    0x34u // Reserved for Test
#define OTP_DAP_RQ5_ORCR    0x35u // OTP ROM control, Test Mode Controls
#define OTP_DAP_RQ6_ODCR    0x36u // Read Timer Control
#define OTP_DAP_RQ7_IPCR2   0x37u // IPS CP sync. Input Control, IPS reserved Control
#define OTP_DAP_RQ8_OCER    0x38u // OTP Bank Selection, PD control
#define OTP_DAP_RQ9_RES0    0x39u // Reserved
#define OTP_DAP_RQ10_DPCR   0x3au // DATAPATH Control: (msb - lsb) {MUXQ[1:0], PASS, brpGEN. brpDIS, eccTST, eccGEN, eccDIS}
#define OTP_DAP_RQ11_DPCR_2 0x3bu // DATAPATH Control 2 – multi-bit prog. control {5’b00000, MBPC[2:0]}
#define OTP_DAP_CQ0         0x3cu // OTP address LSBs
#define OTP_DAP_CQ1         0x3du // OTP address MSBs

#define OTP_PMC_MODE_0      0x30u // Bytes: 2 ; Default Read Conditions 0
#define OTP_PMC_MODE_1      0x32u // Bytes: 2 ; Read Conditions 1
#define OTP_PMC_MODE_2      0x34u // Bytes: 2 ; Read Conditions 2
#define OTP_PMC_MODE_3      0x36u // Bytes: 2 ; Specific Function Usage
#define OTP_PMC_TIMING_0    0x38u // Bytes: 1 ; Timing Control 0
#define OTP_PMC_TIMING_1    0x39u // Bytes: 1 ; Timing Control 1
#define OTP_PMC_TIMING_2    0x3au // Bytes: 1 ; Timing Control 2
#define OTP_PMC_DAP_ADDR    0x3bu // Bytes: 1 ; DAP ID Address
#define OTP_PMC_CQ          0x3cu // Bytes: 2 ; Function Control
#define OTP_PMC_DFSR        0x3eu // Bytes: 1 ; Flag Selection (Read Only)
#define OTP_PMC_CTRL_STATUS 0x3fu // Bytes: 1 ; Control Register (Write Only), STATUS (Read Only)

// ----------------------------------------------------------------------------
// Read functions

#define bootrom_otp_inline static inline

// Read 16-bit ECC-protected value from OTP
bootrom_otp_inline uint16_t inline_s_otp_read_ecc(uint row) {
    return otp_data[row & OTP_ROW_MASK];
}

// Read 16-bit ECC-protected value from OTP, and fault if instability detected
bootrom_otp_inline uint32_t inline_s_otp_read_ecc_guarded(uint row) {
#if ASM_SIZE_HACKS
    if (__builtin_constant_p(row)) {
        uint32_t rc;
        row = (row & OTP_ROW_MASK) * 2 - 0xa0;
        pico_default_asm(
                "ldrh %0, [%1, %2]"
                : "=l" (rc)
                : "l" (otp_data_guarded + 0x50), "i" (row)
        );
        return rc;
    }
#endif
    return otp_data_guarded[row & OTP_ROW_MASK];
}

// Read 2 aligned 16-bit ECC-protected values from OTP, and fault if instability detected
bootrom_otp_inline uint32_t inline_s_otp_read_ecc2_guarded(uint row) {
#if ASM_SIZE_HACKS
    if (__builtin_constant_p(row)) {
        uint32_t rc;
        row = (row & OTP_ROW_MASK) * 2 - 0xa0;
        pico_default_asm(
                "ldr %0, [%1, %2]"
        : "=l" (rc)
        : "l" (otp_data_guarded + 0x50), "i" (row)
        );
        return rc;
    }
#endif
    return *(otp_ecc_row_value2_t *)__builtin_assume_aligned(&otp_data_guarded[row & OTP_ROW_MASK], 4);
}

// Read raw 24-bit value from OTP
bootrom_otp_inline uint32_t inline_s_otp_read_raw(uint row) {
    return otp_data_raw[row & OTP_ROW_MASK];
}

// Read raw 24-bit value from OTP
bootrom_otp_inline uint32_t inline_s_otp_read_raw_guarded(uint row) {
    return otp_data_raw_guarded[row & OTP_ROW_MASK];
}

// Read a 24-bit raw value with bitwise majority vote across 3 rows:
//uint32_t otp_read_rbit3(uint offset);
// 3-way bitwise majority vote across 3 rows:
uint32_t s_varm_step_safe_otp_read_rbit3_guarded(uint row);

// ----------------------------------------------------------------------------
// Write functions

// note only two byte alignment is actually required for ECC reads
int s_varm_api_otp_access(aligned4_uint8_t *buf, uint32_t buf_len, otp_cmd_t cmd);
int s_varm_api_hx_otp_access(aligned4_uint8_t *buf, uint32_t buf_len, otp_cmd_t cmd, hx_xbool secure);

uint32_t s_otp_advance_bl_to_s_value(uint32_t ignored, uint32_t page);
#endif
