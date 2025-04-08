/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bootrom.h"
#define BOOTROM_OTP_C 1 // hack-o-rooney
#include "bootrom_otp.h"
#include "mini_printf.h"
#include "hardware/sync.h"
#include "hardware/structs/otp.h"
#include "nsboot_secure_calls.h"

#if defined(__ARM_ARCH_8M_MAIN__) || !defined(__ARM_ARCH_8M_BASE__)
#error this must be compiled with armv8m-base
#endif

// ----------------------------------------------------------------------------
// Programming configuration constants

// Note these values are dumped from Synopsys testbench waveforms as the docs
// are utterly inscrutable.

// Big Dumb Table (TM) is cheaper than the instructions required to think
// about it. Single table to avoid unnecessary pointer literals on Arm.

// Note we do not use ECC programming, since we already have to generate ECC +
// BRP in software to check that a programming operation is possible based on
// already-set bits before telling the hardware to perform it, so it's simpler
// to only implement raw programming at the SBPI level.

#define N_RQ_CQ_REGS (12 + 2)
typedef enum {
    RQ_CQ_DAP_INIT     = 0 * N_RQ_CQ_REGS,
    RQ_CQ_DAP_PROG_RAW = 1 * N_RQ_CQ_REGS,
    RQ_CQ_PMC_PROG_RAW = 2 * N_RQ_CQ_REGS,
    N_RQ_CQ_SEQ        = 3
} rq_cq_seq_t;

const uint8_t rq_cq_seq_table[N_RQ_CQ_REGS * N_RQ_CQ_SEQ] = {
// RQ_CQ_DAP_INIT:
    0x01, // RQ[ 7: 0], RFMR    : IREF=1, REDUND=0, LD_CP_EN=0
    0x6e, // RQ[15: 8], VRMR    : VRR=e, VRRTS=2, VRR_EN=1, CP_EN=0
    0x09, // RQ[23:16], OVLR    : VQQ=1, VPP=1, IPSOSCV*=0
    0x04, // RQ[31:24], IPCR    : VDD_DET_DIS=0, EXT_REF_EN=0, IPS_EN=1, OSC_OUT=0, EXT_CK_EN=0, REF_BIAS_DIS=0, VRRSWC=0
    0x00, // RQ[39:32], OSCR    : (reserved for test)
    0x00, // RQ[47:40], ORCR    : ROMEN=0, AROM=0, OTP_RTST=0
    0x1f, // RQ[55:48], ODCR    : CLKDEL=1f, (max
    0x01, // RQ[63:56], IPCR2   : WE_CK=1, VREFLVL=0
    0x08, // RQ[71:64], OCER    : PD=0, reserved test signal is 1?
    0x00, // RQ[79:72], RES0    :
    0x00, // RQ[87:80], DPCR    : ECCDIS=0, ECCGEN=0, ECCTST=0, BRPDIS=0, BRPGEN=0, PASS=0, MUXQ=0
    0x00, // RQ[95:88], DPCR_2  : MBPC=0
    0x00, // CQ[ 7: 0], A[7:0]  : Don't care
    0x00, // CQ[15: 8], A[15:8] : Don't care

/* Kept for the curious reader:
// RQ_CQ_DAP_PROG_ECC
    0x01,
    0x48, // RQ[15: 8], VRMR    : VRR=8, VRRTS=0, VRR_EN=1,CP_EN=0
    0x29, // RQ[23:16], OVLR    : VQQ=1, VPP=5, IPSOSCV*=0
    0x04, 0x00, 0x00, 0x1f, 0x01, 0x08, 0x00, 0x00, 0x00, 0x00, 0x00,*/

// RQ_CQ_DAP_PROG_RAW:
    0x01, 0x48, 0x29, 0x04, 0x00, 0x00, 0x1f, 0x01, 0x08, 0x00,
    0x01, // RQ[87:80], DPCR    : ECCDIS=1, ECCGEN=0
    0x00, 0x00, 0x00,

/* Kept for the curious reader:
// RQ_CQ_PMC_PROG_ECC:
    0x01, 0x48, 0x13, 0xdb, 0x8f, 0x47, 0x81, 0x4b, 0x12, 0x0e, 0x5d, 0x02,
    0x00, // CQ: max soak limit, do not skip any stages
    0x00,*/

// RQ_CQ_PMC_PROG_RAW:
    0x01, 0x48, 0x13, 0xdb, 0x8f, 0x47, 0x81, 0x4b, 0x12, 0x0e, 0x5d, 0x02,
    0x0a, // CQ: max soak limit, skip ECC and BRP
    0x00,
};

// ----------------------------------------------------------------------------
// SBPI bridge access functions

static void __noinline __sg_filler s_varm_otp_wait_sbpi_done(void) {
    canary_set_step(STEPTAG_S_VARM_OTP_WAIT_SBPI_DONE);
    uint32_t status_mask = OTP_SBPI_STATUS_INSTR_MISS_BITS | OTP_SBPI_STATUS_INSTR_DONE_BITS;
    while (!(otp_hw->sbpi_status & status_mask))
        ;
    otp_hw->sbpi_status = status_mask;
    canary_check_step(STEPTAG_S_VARM_OTP_WAIT_SBPI_DONE);
}

#if !ASM_SIZE_HACKS
static void __noinline s_varm_otp_sbpi_write_byte(uint32_t target, uint32_t addr, uint32_t wdata) {
    // note wdata is u32, and gets masked here, to avoid redundant uxtbs at
    // call sites. target/addr are not masked anywhere, should take a small
    // range of predefined values. These ought all really be u8.
    wdata &= 0xff;
    canary_entry(S_VARM_OTP_SBPI_WRITE_BYTE);
    uint32_t cmd = OTP_REG_WRITE | addr;
    otp_hw->sbpi_instr =
        (1u     << OTP_SBPI_INSTR_IS_WR_LSB          ) |
        (1u     << OTP_SBPI_INSTR_HAS_PAYLOAD_LSB    ) |
        (0u     << OTP_SBPI_INSTR_PAYLOAD_SIZE_M1_LSB) |
        (target << OTP_SBPI_INSTR_TARGET_LSB         ) |
        (cmd    << OTP_SBPI_INSTR_CMD_LSB            ) |
        (wdata  << OTP_SBPI_INSTR_SHORT_WDATA_LSB    ) |
        (1u     << OTP_SBPI_INSTR_EXEC_LSB           );
    s_varm_otp_wait_sbpi_done();
    canary_exit_void(S_VARM_OTP_SBPI_WRITE_BYTE);
}
#else
static_assert(OTP_SBPI_INSTR_SHORT_WDATA_LSB == 0, "");
static void __noinline __attribute__((naked)) s_varm_otp_sbpi_write_byte(__unused uint32_t target, __unused uint32_t addr, __unused uint32_t wdata) {
    pico_default_asm_volatile(
#if FEATURE_CANARIES
            ".cpu cortex-m33\n"
            "mrc2 p7, #0, ip, c%c[tag_h], c%c[tag_l], #1\n" // canary_entry
            ".cpu cortex-m23\n"
#endif
            "ldr r3, =%[sbpi_instr]\n"
            "uxtb r2, r2\n"
            "lsls r0, r0, %[target_shift]\n"
            "orrs r0, r2\n" // no shift as WDATA_LSB == 0
            "ldr r2, =%[flags]\n"
            "lsls r1, r1, %[cmd_shift]\n"
            "orrs r1, r2\n"
            "orrs r0, r1\n"
            "str r0, [r3]\n"
#if FEATURE_CANARIES
            ".cpu cortex-m33\n"
            "mcr2 p7, #0, ip, c%c[tag_h], c%c[tag_l], #1\n" // canary_check
            ".cpu cortex-m23\n"
#endif
            // size: this could be b.n if we moved wait_sbpi_done out of SG region
            // (worth 4 bytes due to literal pool alignment)
            "b s_varm_otp_wait_sbpi_done\n"
            :
            : [flags] "i" ((1u     << OTP_SBPI_INSTR_IS_WR_LSB          ) |
                           (1u     << OTP_SBPI_INSTR_HAS_PAYLOAD_LSB    ) |
                           (0u     << OTP_SBPI_INSTR_PAYLOAD_SIZE_M1_LSB) |
                           (OTP_REG_WRITE << OTP_SBPI_INSTR_CMD_LSB     ) |
                           (1u     << OTP_SBPI_INSTR_EXEC_LSB           )),
              [target_shift] "i" (OTP_SBPI_INSTR_TARGET_LSB),
              [cmd_shift] "i" (OTP_SBPI_INSTR_CMD_LSB),
              [reg_write] "i" (OTP_REG_WRITE),
              [sbpi_instr] "i" ((uintptr_t)&otp_hw->sbpi_instr),
              [tag_h]     "i" (CTAG_S_VARM_OTP_SBPI_WRITE_BYTE >> 4),
              [tag_l]     "i" (CTAG_S_VARM_OTP_SBPI_WRITE_BYTE & 0xf)
          : "r0", "r1", "r2", "r3"
    );
}
#endif

static inline uint8_t inline_s_otp_sbpi_read_byte(uint8_t target, uint8_t addr) {
    uint8_t cmd = OTP_REG_READ | addr;
    otp_hw->sbpi_instr =
        (0u     << OTP_SBPI_INSTR_IS_WR_LSB          ) |
        (1u     << OTP_SBPI_INSTR_HAS_PAYLOAD_LSB    ) |
        (0u     << OTP_SBPI_INSTR_PAYLOAD_SIZE_M1_LSB) |
        (target << OTP_SBPI_INSTR_TARGET_LSB         ) |
        (cmd    << OTP_SBPI_INSTR_CMD_LSB            ) |
        (1u     << OTP_SBPI_INSTR_EXEC_LSB           );
    s_varm_otp_wait_sbpi_done();
    return (uint8_t)otp_hw->sbpi_rdata[0];
}

static inline void inline_s_otp_sbpi_cmd(uint8_t target, uint8_t cmd) {
    otp_hw->sbpi_instr =
        (1u     << OTP_SBPI_INSTR_IS_WR_LSB          ) |
        (0u     << OTP_SBPI_INSTR_HAS_PAYLOAD_LSB    ) |
        (target << OTP_SBPI_INSTR_TARGET_LSB         ) |
        (cmd    << OTP_SBPI_INSTR_CMD_LSB            ) |
        (1u     << OTP_SBPI_INSTR_EXEC_LSB           );
    s_varm_otp_wait_sbpi_done();
}

// ----------------------------------------------------------------------------
// OTP programming

static void s_otp_configure_rq_cq(uint8_t target, rq_cq_seq_t seq) {
    // regalloc: use r7 (saved in prolog `push`) to avoid separate stack spill
    canary_entry_reg(r4, S_OTP_CONFIGURE_RQ_CQ);
    const uint8_t *rq_cq_vals = P16_A(rq_cq_seq_table) + (uint)seq;
    for (uint i = 0; i < N_RQ_CQ_REGS; ++i) {
        s_varm_otp_sbpi_write_byte(target, (uint8_t) (OTP_DAP_RQ0_RFMR + i), rq_cq_vals[i]);
    }
    canary_exit_void(S_OTP_CONFIGURE_RQ_CQ);
}

// Low-level programming functions: note these functions are static force-inline since they should
// only be called once each from s_varm_api_otp_access, so we prefer inlining for reduced stack usage
// and no extra canary instructions.

// Configure OTP controller for programming. The DATA port will become inaccessible (bus error)
// until cleanup() is called. Multiple programming operations can be performed back-to-back before
// calling cleanup().
static __force_inline void s_varm_otp_program_prepare(void) {
    // Clear DCTRL to permit SBPI access (and clear PD bit)
    otp_hw->usr = 0;
    // Fully initialise RQ registers
    s_otp_configure_rq_cq(OTP_TARGET_DAP, RQ_CQ_DAP_PROG_RAW);
    s_otp_configure_rq_cq(OTP_TARGET_PMC, RQ_CQ_PMC_PROG_RAW);
    s_varm_otp_sbpi_write_byte(OTP_TARGET_PMC, OTP_PMC_CTRL_STATUS, 0xa);
}

// Restore OTP controller to a clean initial configuration and re-enable DATA
// port access.
static __force_inline void s_varm_otp_program_cleanup(void) {
    // Return DAP to its post-BOOT configuration. Leave the PMC in its current
    // configuration, as reads do not care about PMC configuration.
    s_otp_configure_rq_cq(OTP_TARGET_DAP, RQ_CQ_DAP_INIT);
    // Re-enable data read access
    otp_hw->usr = OTP_USR_DCTRL_BITS;
}

// Program one OTP row, in between a call to otp_program_prepare() and otp_program_cleanup()
static __force_inline void s_varm_otp_program_blocking(uint row, uint32_t data) {
    // Note sbpi_write_byte write data is masked to 8 bits inside the function (minor size savings)
    s_varm_otp_sbpi_write_byte(OTP_TARGET_DAP, OTP_DAP_CQ0, row);
    s_varm_otp_sbpi_write_byte(OTP_TARGET_DAP, OTP_DAP_CQ1, row >> 8);

    s_varm_otp_sbpi_write_byte(OTP_TARGET_DAP, OTP_DAP_DR0, data);
    s_varm_otp_sbpi_write_byte(OTP_TARGET_DAP, OTP_DAP_DR1, data >> 8);
    s_varm_otp_sbpi_write_byte(OTP_TARGET_DAP, OTP_DAP_ECC, data >> 16);

    inline_s_otp_sbpi_cmd(OTP_TARGET_PMC, 0x01u); // START
    while (inline_s_otp_sbpi_read_byte(OTP_TARGET_PMC, OTP_PMC_CTRL_STATUS) & 0x80u)
        ;
    inline_s_otp_sbpi_cmd(OTP_TARGET_PMC, 0x02u); // STOP
}

// We have a popcount instruction on both Cortex-M33 and Hazard3, but this
// loop is cheaper than hooking things up in varmulet:
static inline uint32_t inline_s_even_parity(uint32_t input) {
#if ASM_SIZE_HACKS && !defined(__riscv)
    // smaller, unfortunately
    uint32_t scratch;
    pico_default_asm (
        "movs %1, #0\n"
    "1:"
        "eors %1, %0\n"
        "lsls %0, #1\n"
        "bne 1b\n"
        "lsrs %0, %1, 31\n"
        : "+l" (input), "=l" (scratch)
        :
        : "cc"
    );
    return input;
#else
    uint32_t rc = 0;
    while (input) {
        rc ^= input & 1;
        input >>= 1;
    }
    return rc;
#endif
}

// Magic numbers, source: magic
const uint32_t otp_ecc_parity_table[6] = {
    0b0000001010110101011011,
    0b0000000011011001101101,
    0b0000001100011110001110,
    0b0000000000011111110000,
    0b0000001111100000000000,
    0b0111111111111111111111
};

// In: 16-bit unsigned integer. Out: 22-bit unsigned integer.
static __force_inline uint32_t s_otp_calculate_ecc(uint16_t x) {
    uint32_t p = x;
    const uint32_t *table = P16_A(otp_ecc_parity_table);
    for (uint i = 0; i < count_of(otp_ecc_parity_table); ++i) {
        // P16 here seems to hurt actually
        p |= inline_s_even_parity(p & table[i]) << (16 + i);
    }
    return p;
}

static __force_inline uint32_t s_inline_otp_calculate_brp(uint32_t ecc, uint32_t pre_read) {
    if (pre_read & ~ecc) {
//      return 0xc00000u | (ecc ^ 0x3fffffu); (produces a 32-bit constant)
        return (~((ecc << 10) >> 2)) >> 8;
    } else {
        return ecc;
    }
}

// Note this is not under TAIL_CALL_HACKS because we require this sibling call
// optimisation to avoid an unprotected return
int __exported_from_arm __attribute__((naked)) s_varm_api_otp_access(__unused aligned4_uint8_t *buf, __unused uint32_t buf_len, __unused otp_cmd_t cmd) {
    __unused register hx_xbool r3 asm("r3") = hx_otp_secure_true();
    // placed *under* s_varm_api_hx_otp_access in the linker script
    // (nervous about having the above mov.w directly above the entry point)
    pico_default_asm_volatile("b.n s_varm_api_hx_otp_access");
}

// secure is xtrue for either secure or nsboot calls (since in the latter, we have advanced S locks to match BL locks already)
// note; that some callers expect to be able to pass invalid values for "false", so we only assert on true values
int __used s_varm_api_hx_otp_access(aligned4_uint8_t *buf, uint32_t buf_len, otp_cmd_t cmd, hx_xbool secure) {
    // regalloc: best to let the compiler do its thing, this *does* create a
    // late spill but the compiler needs lots of regs here so leave it.
    canary_entry(S_VARM_OTP_ACCESS);

    int rc = inline_s_lock_check(BOOTROM_LOCK_OTP);
    if (rc) goto done;

    uint base_row = (cmd.flags & OTP_CMD_ROW_BITS) >> OTP_CMD_ROW_LSB;
    bool is_write = cmd.flags & OTP_CMD_WRITE_BITS;
    bool is_ecc = cmd.flags & OTP_CMD_ECC_BITS;
    uint num_rows = buf_len >> (is_ecc ? 1 : 2);

    printf("OTP %s 0x%04x ecc=%d buf=%p len=%d\n", is_write ? "WRITE" : "READ ",
           base_row, is_ecc, buf, (int)buf_len);

    if (cmd.flags & ~OTP_CMD_BITS || base_row + num_rows > NUM_OTP_ROWS) {
        rc = BOOTROM_ERROR_INVALID_ARG;
    } else if (((uintptr_t)buf | buf_len) & (is_ecc ? 0x1 : 0x3)) {
        rc = BOOTROM_ERROR_BAD_ALIGNMENT;
    } else {
        // Shared read/write path (permission checks etc are common)
        if (is_write) {
            s_varm_otp_program_prepare();
        }
        // note: if the buffer belongs to a NS caller, then it remains accessible to NS IRQs
        // throughout this call, however, this seems reasonable, as the worst they can do is corrupt
        // they data that THEY are reading and writing anyway.
        uint row;
        for (row = base_row; row < base_row + num_rows; row++) {
            // Check each row as we go -- simplifies checks, at the cost of allowing tearing of
            // commands across permission boundaries. For our permission check, always start with a
            // base of S permissions so that we don't try to do something we aren't able to
            // (in practice NS and NSBOOT oughtn't be more permissive than S, but it's possible)
            uint page = row >> NUM_OTP_PAGE_ROWS_LOG2;
            uint32_t lockreg = otp_hw->sw_lock[page];
            uint page_locks = (lockreg & OTP_SW_LOCK0_SEC_BITS) >> OTP_SW_LOCK0_SEC_LSB;
            uint page2 = __get_opaque_value(row) >> NUM_OTP_PAGE_ROWS_LOG2;
            uint32_t lockreg2 = otp_hw->sw_lock[page2];
            uint page_locks2 = (lockreg2 & OTP_SW_LOCK0_SEC_BITS) >> OTP_SW_LOCK0_SEC_LSB;

            // Regress effective soft locks further according to effective security level
            if (hx_is_xfalse(secure)) {
                page_locks |= (lockreg & OTP_SW_LOCK0_NSEC_BITS) >> OTP_SW_LOCK0_NSEC_LSB;
            } else {
                // Nothing to do here because the secure softlocks are already promoted to the
                // NSBOOT level during nsboot secure preamble in varm_nsboot.c
                hx_assert_xtrue(secure, hx_otp_secure_xor());
            }
            if (hx_is_xfalse(__get_opaque_xbool(secure))) {
                page_locks2 |= (lockreg2 & OTP_SW_LOCK0_NSEC_BITS) >> OTP_SW_LOCK0_NSEC_LSB;
            }

            // In addition to the page lock check, check MSB of a raw read to detect a failed key
            // check. Need to flip fuse access from DAP to DATA if a write is in progress, else the
            // read will always fail. (We are likely to need this raw read result later anyway)
            hw_xor_bits(&otp_hw->usr, (uint)is_write << OTP_USR_DCTRL_LSB);
            uint32_t current_val = inline_s_otp_read_raw(row);
            hw_xor_bits(&otp_hw->usr, (uint)is_write << OTP_USR_DCTRL_LSB);

            uint lock_fail = page_locks & (is_write ? 0x3 : 0x2);
            uint read_fail = current_val & (1u << 31);
            if (lock_fail | read_fail) {
                rc = BOOTROM_ERROR_NOT_PERMITTED;
                goto abort;
            }
            uint lock_fail2 = page_locks2 & (__get_opaque_value(is_write) ? 0x3 : 0x2);
            hx_assert_equal2i(lock_fail2, 0);

            if (is_write) {
                uint32_t full_val;
                if (is_ecc) {
                    full_val = s_otp_calculate_ecc(*(uint16_t*)buf);
                    // BRP allows us to clear at least one set bit *for ECC reads only* by setting
                    // both bits 23:22 to flip the remainder of the row. This may be insufficient
                    // depending on the already-set bits and the target bit pattern.
                    full_val = s_inline_otp_calculate_brp(full_val, current_val);
                    //printf("W-ECC EXPECT %04x=%04x %06x\n", row, *(uint16_t *)buf, (int)full_val);
                } else {
                    full_val = *(uint32_t *)buf;
                }
                //printf("W-RAW %04x (currently %06x) <- %06x\n", row, current_val, full_val);
                if (current_val & ~full_val) {
                    rc = BOOTROM_ERROR_UNSUPPORTED_MODIFICATION;
                    goto abort;
                }
                s_varm_otp_program_blocking(row, full_val);
                // note: we expect user to verify the data was written correctly
            } else {
                if (is_ecc) {
                    // current_val holds the raw value
                    *(uint16_t *)buf = inline_s_otp_read_ecc(row);
                    // when reading using bootrom, validate the ECC read corresponds
                    // to the raw value read above.  Otherwise, the data is corrupted.
                    uint32_t re_encoded = s_otp_calculate_ecc(*(uint16_t *)buf);
                    uint32_t current_wo_brp = (current_value & 0x3FFFFFu);
                    if ((current_val & 0xC00000u) == 0x0) &&
                        (__builtin_popcount(current_wo_brp ^ re_encoded) >= 1)) {
                        // If neither BRP bit is set, then if there is more than
                        // a single-bit error, the data from the ECC read is corrupted.
                        rc = BOOTROM_ERROR_INVALID_DATA;
                        goto abort;
                    } else if ((current_val & 0xC00000u) == 0xC00000u) &&
                        (__builtin_popcount(((~current_wo_brp) & 0x3FFFFFu) ^ re_encoded) >= 1)) {
                        // If both BRP bits are set, then if there is more than
                        // a single-bit error, the data from the ECC read is corrupted.
                        rc = BOOTROM_ERROR_INVALID_DATA;
                        goto abort;
                    } else {
                        // When only one BRP bit is set, allow up to a single-bit error
                        // vs. either inverted or original current raw value (w/o BRP).
                        if ((__builtin_popcount(current_wo_brp ^ re_encoded) >= 1) &&
                            (__builtin_popcount(((~current_wo_brp) & 0x3FFFFFu)^ re_encoded) >= 1)) {
                            rc = BOOTROM_ERROR_INVALID_DATA;
                            goto abort;
                        }
                    }
                    // if did not abort from above checks, then value already stored in buf.
                } else {
                    *(uint32_t *)buf = current_val;
                }
            }
            buf += is_ecc ? 2 : 4;
        }
        hx_assert_equal2i(row, ((cmd.flags & OTP_CMD_ROW_BITS) >> OTP_CMD_ROW_LSB) + num_rows);
        abort:
        if (is_write) {
            s_varm_otp_program_cleanup();
        }
    }
    done:
    canary_exit_return(S_VARM_OTP_ACCESS, rc);
}

#if !ASM_SIZE_HACKS
uint32_t s_varm_step_safe_otp_read_rbit3_guarded(uint row) {
    canary_entry_reg(ip, S_VARM_STEP_SAFE_OTP_READ_RBIT3_GUARDED);
    uint32_t a = inline_s_otp_read_raw_guarded(row);
    uint32_t b = inline_s_otp_read_raw_guarded(row+1);
    uint32_t c = inline_s_otp_read_raw_guarded(row+2);
    canary_exit_return(S_VARM_STEP_SAFE_OTP_READ_RBIT3_GUARDED, (a & b) | (b & c) | (c & a));
}
#else
uint32_t __attribute__((naked)) s_varm_step_safe_otp_read_rbit3_guarded(__unused uint row) {
    // we also don't handle wrap around the end of the OTP like the C version, but that isn't really correct either
    pico_default_asm(
            ".cpu cortex-m33\n"
            // Note use of delay variant is deliberate, as this is early-boot only
            "mrc p7, #0, ip, c%c[tag_h], c%c[tag_l], #1\n" // canary_entry
            ".cpu cortex-m23\n"
            // (row & OTP_MASK) * 4
            "lsls r0, #32 - %c[otp_row_bits]\n"
            "lsrs r0, #30 - %c[otp_row_bits]\n"
            "ldr r3, =otp_data_raw_guarded\n"
            "adds r3, r0\n"
            "ldmia r3!, {r0-r2}\n"
            // (a & b) | (a & c) | (b & c)
            // (a & (b | c)) | (b & c)
            "movs r3, r1\n" // b' = b
            "orrs r1, r2\n" // b1 = b | c
            "ands r2, r3\n" // c1 = b' & c
            "ands r0, r1\n" // a1 = a & (b | c)
            "orrs r0, r2\n" // a2 = (a & (b | c)) | (b' & c)
            ".cpu cortex-m33\n"
            "mcr p7, #0, ip, c%c[tag_h], c%c[tag_l], #1\n" // canary_check
            ".cpu cortex-m23\n"
            "bx lr\n"
            :
            : [otp_row_bits] "i" (NUM_OTP_ROWS_LOG2),
              [tag_h]     "i" (CTAG_S_VARM_STEP_SAFE_OTP_READ_RBIT3_GUARDED >> 4),
              [tag_l]     "i" (CTAG_S_VARM_STEP_SAFE_OTP_READ_RBIT3_GUARDED & 0xf)
    );
}
#endif
