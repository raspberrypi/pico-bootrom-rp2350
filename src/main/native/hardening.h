/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "pico.h"
#include "hardware/rcp.h"
#include "bootrom_assert.h"
#include "bootrom_common.h"

#define HX_BIT_PATTERN_TRUE  RCP_MASK_TRUE
#define HX_BIT_PATTERN_FALSE RCP_MASK_FALSE
#define HX_UINT32_XOR        RCP_MASK_INTXOR

#define HX_XOR_SIG_VERIFIED 0x00130013u
#define HX_XOR_KEY_MATCH    0x00540054u
#define HX_XOR_SECURE       0x77u
#define HX_XOR_OTP_SECURE   0x2f002f00u

#ifdef __ASSEMBLER__
#if !BOOTROM_HARDENING
#ifdef __riscv
#define HX_LOAD_TRUE(reg) li reg, 1
#define HX_LOAD_FALSE(reg) li reg, 0
#else
#define HX_LOAD_TRUE(reg) movs reg, #1
#define HX_LOAD_FALSE(reg) movs reg, #0
#endif
#else // BOOTROM_HARDENING
#ifdef __riscv
#define HX_LOAD_TRUE(reg) li reg, HX_BIT_PATTERN_TRUE
#define HX_LOAD_FALSE(reg) li reg, HX_BIT_PATTERN_FALSE
#else
#define HX_LOAD_TRUE(reg) ldr reg, =#HX_BIT_PATTERN_TRUE
#define HX_LOAD_FALSE(reg) ldr reg, =#HX_BIT_PATTERN_FALSE
#endif
#endif // !BOOTROM_HARDENING
#ifndef __riscv
#define rcp_count_set_c0_c1(c0, c1) mcr p7, #4, r0, c##c0, c##c1, #0
#define rcp_count_check_c0_c1(c0, c1) mcr p7, #5, r0, c##c0, c##c1, #1
#endif

#if __ARM_ARCH_8M_MAIN__
.macro hx_bit_pattern_true reg
    ldr \reg, =HX_BIT_PATTERN_TRUE
.endm
.macro hx_bit_pattern_false reg
    ldr \reg, =HX_BIT_PATTERN_FALSE
.endm
.macro hx_bit_pattern_e100e1 reg
    ldr \reg, =0xe100e1
.endm
.macro hx_bit_pattern_1e001e reg
    ldr \reg, =0x1e001e
.endm
#else
// Note mrc p7, #7 is not a valid RCP instruction (mrc only goes up to 1); we
// use this as a placeholder to insert mov.w during post-processing.
.macro hx_bit_pattern_true reg
mrc p7, #7, \reg, c0, c0, #0
.endm
.macro hx_bit_pattern_false reg
mrc p7, #7, \reg, c0, c1, #0
.endm
.macro hx_bit_pattern_e100e1 reg
mrc p7, #7, \reg, c0, c3, #0
.endm
.macro hx_bit_pattern_1e001e reg
mrc p7, #7, \reg, c0, c4, #0
.endm
#endif
#else // __ASSEMBLER

#if !FEATURE_HARDENING_STEPS
static __force_inline void hx_set_step(__unused uint8_t step) { }
static __force_inline void hx_check_step(__unused uint8_t step) { }
static __force_inline void hx_set_step_nodelay(__unused uint8_t step) { }
static __force_inline void hx_check_step_nodelay(__unused uint8_t step) { }
#else
// Note step must be a constexpr as this is mangled into asm.
#define hx_set_step(step)   do {static_assert(step >= 0 && step < 256, ""); rcp_count_set(step);  } while (0)
#define hx_check_step(step) do {static_assert(step >= 0 && step < 256, ""); rcp_count_check(step);} while (0)
#define hx_set_step_nodelay(step)   do {static_assert(step >= 0 && step < 256, ""); rcp_count_set_nodelay(step);  } while (0)
#define hx_check_step_nodelay(step) do {static_assert(step >= 0 && step < 256, ""); rcp_count_check_nodelay(step);} while (0)
#endif
#if !BOOTROM_HARDENING
// just need stuff to be the right size (this is just
typedef uint32_t hx_bool; // note: keep stuff same size as I don't think this is much used by RISC-V any more
typedef uint32_t hx_xbool; // note: keep stuff same size as I don't think this is much used by RISC-V any more
typedef uint32_t hx_uint32_t;
#define hx_true() make_hx_bool(true)
#define hx_false() make_hx_bool(false)
#define hx_false_constant() hx_false()

#ifndef __riscv // no longer needed by riscv

#define __dataflow_barrier(val) ((void)0)
#define __dataflow_barrier_hxu32(val) ((void)0)
#define boot_flag_selector(f) f

#define HX2_UINT32_T_INVALID 0xaa561031 // let's hope this number isn't important!
static __force_inline hx_bool hx_bool_null(void) { return 2; }
static __force_inline bool hx_is_null(hx_bool v) { return v == 2; }
static __force_inline hx_bool hx_bool_invalid(void) { return hx_bool_null(); }
static __force_inline hx_bool hx_xbool_invalid(void) { return hx_bool_null(); }
static __force_inline bool hx_is_false(hx_bool v) { return !v; }
static __force_inline bool hx_is_false_checked(hx_bool v) { return !v; }
static __force_inline bool hx_is_true(hx_bool v) { return v; }
static __force_inline hx_bool make_hx_bool(bool v) { return v; }
static __force_inline hx_bool make_hx_bool2(bool v, __unused bool v2) { return v; }
static __force_inline hx_bool make_hx_xbool(bool value, __unused uint32_t xor) { return value; }
static __force_inline hx_xbool make_hx_xbool2(bool value, __unused bool value2, __unused uint32_t xor) { return value; }
static __force_inline hx_xbool make_hx_bool2_u(hx_uint32_t value, __unused hx_uint32_t value2) { return value; }
static __force_inline void hx_check_bool(__unused hx_bool v) {}
static __force_inline void hx_check_bools(__unused hx_bool a, __unused hx_bool b) {}
static __force_inline void hx_check_uint32(__unused hx_uint32_t v) {}
static __force_inline void hx_assert_false(__unused hx_bool v) {}
static __force_inline void hx_assert_true(__unused hx_bool v) {}
static __force_inline void hx_assert_notx_orx_true(__unused hx_bool a, __unused uint32_t xor_a, __unused hx_bool b, __unused uint32_t xor_b) {}
static __force_inline void hx_assert_null(__unused hx_bool v) {}
static __force_inline void hx_assert_equal2i(__unused uint32_t a, __unused uint32_t b) {}
static __force_inline hx_bool hx_or(hx_bool a, hx_bool b) { return a || b; }
static __force_inline hx_bool hx_and_checked(hx_bool a, hx_bool b) { return a && b; }
static __force_inline hx_bool hx_or_checked(hx_bool a, hx_bool b) { return a || b; }
static __force_inline hx_bool hx_not(hx_bool v) { return !v; }
static __force_inline hx_bool hx_not_checked(hx_bool v) { return !v; }
static __force_inline hx_bool hx_notx(hx_bool v, __unused uint32_t xor) { return !v; }
static __force_inline hx_bool hx_and_not_checked(hx_bool a, hx_bool b) { return a & !b; }
static __force_inline hx_bool hx_and_notb(hx_bool a, bool b) { return a & !b; }
static __force_inline bool hx_is_xfalse(hx_xbool v) { return !v; }
static __force_inline bool hx_is_xtrue(hx_xbool v) { return v; }
static __force_inline void hx_assert_or(__unused hx_bool a, __unused hx_bool b) {}
static __force_inline void hx_assert_xfalse(__unused hx_xbool v, __unused uint32_t xor) {}
static __force_inline void hx_assert_bequal(__unused hx_bool a, __unused hx_bool b) {}
static __force_inline void hx_check_xbool(__unused hx_xbool v, __unused uint32_t xor) {}
static __force_inline hx_bool hx_b_from_xored_checked(hx_bool v, __unused uint32_t xor) { return v; }
static __force_inline hx_bool hx_b_from_unsigned_is_less(hx_uint32_t a, hx_uint32_t b) { return a < b; }
static __force_inline bool hx_signed_is_greater(hx_uint32_t a, hx_uint32_t b) { return (int32_t)a > (int32_t)b; }
static __force_inline bool hx_signed_is_greateri(hx_uint32_t a, int32_t b) { return (int32_t)a > b; }
static __force_inline bool hx_unsigned_is_greater(hx_uint32_t a, hx_uint32_t b) { return a > b; }
static __force_inline hx_uint32_t make_hx_uint32(uint32_t value) { return value; }
static __force_inline hx_uint32_t make_hx_uint32_2(uint32_t value, __unused uint32_t value2) { return value; }
static __force_inline uint32_t hx_value(hx_uint32_t v) { return v; }
static __force_inline hx_bool hx_xbool_to_bool(hx_xbool b, __unused uint32_t xor) { return b; }
static __force_inline hx_bool hx_xbool_to_bool_checked(hx_xbool b, __unused uint32_t xor) { return b; }
static __force_inline bool hx_is_equal(hx_uint32_t a, hx_uint32_t b) {return a == b; }
static __force_inline hx_bool hx_uint32_to_bool_checked(hx_uint32_t v) { return v; }
#define hx_sig_verified_true() hx_true()
#define hx_sig_verified_false() hx_false()
#define hx_key_match_false() hx_false()
#define hx_bit_pattern_xor_secure() 0
#define hx_bit_pattern_xor_sig_verified() 0
#define hx_bit_pattern_xor_key_match() 0
#include "bootrom_otp.h"
static __force_inline hx_xbool hx_step_safe_get_boot_flagx(uint8_t bit) {
    return s_varm_step_safe_otp_read_rbit3_guarded(OTP_DATA_BOOT_FLAGS0_ROW) & (1u << bit);
}

static __force_inline hx_xbool hx_step_safe_get_boot_flag(uint8_t bit) {
    return s_varm_step_safe_otp_read_rbit3_guarded(OTP_DATA_BOOT_FLAGS0_ROW) & (1u << bit);
}

#endif
#else
typedef struct { uint32_t v; } hx_bool;
typedef struct { uint32_t v; } hx_xbool;
typedef struct { uint32_t v, p; } hx_uint32_t;
#define hx_false_constant() make_hx_bool(false)

#ifndef __riscv
// Dataflow barrier: do nothing to some variable, but tell the compiler we
// *may* have done something, and that it's dependent on its previous value.
#define __dataflow_barrier(val) asm volatile ("" : "+r"(val))

// Note mrc p7, #7 is not a valid RCP instruction (mrc only goes up to 1); we
// use this as a placeholder to insert mov.w during post-processing.
static __force_inline uint32_t hx_bit_pattern_true(void) {
    uint32_t rc;
#if __ARM_ARCH_8M_MAIN__
    // note on ARMv8-m main; we want to expose the real value so that it can be used in immediate operands
    rc = HX_BIT_PATTERN_TRUE;
#else
    rcp_asm ("mrc p7, #7, %0, c0, c0, #0\n" : "=r" (rc));
#endif
    return rc;
}

static __force_inline uint32_t hx_bit_pattern_false(void) {
    uint32_t rc;
#if __ARM_ARCH_8M_MAIN__
    // note on ARMv8-m main; we want to expose the real value so that it can be used in immediate operands
    rc = HX_BIT_PATTERN_FALSE;
#else
    rcp_asm ("mrc p7, #7, %0, c0, c1, #0\n" : "=r" (rc));
#endif
    return rc;
}

static __force_inline uint32_t hx_bit_pattern_xor(void) {
    uint32_t rc;
#if __ARM_ARCH_8M_MAIN__
    // note on ARMv8-m main; we want to expose the real value so that it can be used in immediate operands
    rc = HX_UINT32_XOR;
#else
    rcp_asm ("mrc p7, #7, %0, c0, c2, #0\n" : "=r" (rc));
#endif
    return rc;
}

static __force_inline uint32_t hx_bit_pattern_e100e1(void) {
    uint32_t rc;
#if __ARM_ARCH_8M_MAIN__
    // note on ARMv8-m main; we want to expose the real value so that it can be used in immediate operands
    rc = 0xe100e1;
#else
    rcp_asm ("mrc p7, #7, %0, c0, c3, #0\n" : "=r" (rc));
#endif
    return rc;
}

static __force_inline uint32_t hx_bit_pattern_1e001e(void) {
    uint32_t rc;
#if __ARM_ARCH_8M_MAIN__
    // note on ARMv8-m main; we want to expose the real value so that it can be used in immediate operands
    rc = 0x1e001e;
#else
    rcp_asm ("mrc p7, #7, %0, c0, c4, #0\n" : "=r" (rc));
#endif
    return rc;
}

static __force_inline uint32_t hx_bit_pattern_xor_sig_verified(void) {
    uint32_t rc;
#if __ARM_ARCH_8M_MAIN__
    // note on ARMv8-m main; we want to expose the real value so that it can be used in immediate operands
    rc = HX_XOR_SIG_VERIFIED;
#else
    rcp_asm ("mrc p7, #7, %0, c0, c5, #0\n" : "=r" (rc));
#endif
    return rc;
}

static __force_inline hx_xbool hx_sig_verified_false(void) {
    hx_xbool rc;
#if __ARM_ARCH_8M_MAIN__
    // note on ARMv8-m main; we want to expose the real value so that it can be used in immediate operands
    rc.v = HX_BIT_PATTERN_FALSE ^ HX_XOR_SIG_VERIFIED;
#else
    rcp_asm ("mrc p7, #7, %0, c0, c6, #0\n" : "=r" (rc.v));
#endif
    return rc;
}

static __force_inline uint32_t hx_bit_pattern_xor_key_match(void) {
    uint32_t rc;
#if __ARM_ARCH_8M_MAIN__
    // note on ARMv8-m main; we want to expose the real value so that it can be used in immediate operands
    rc = HX_XOR_KEY_MATCH;
#else
    rcp_asm ("mrc p7, #7, %0, c0, c7, #0\n" : "=r" (rc));
#endif
    return rc;
}

static __force_inline hx_xbool hx_key_match_false(void) {
    hx_xbool rc;
#if __ARM_ARCH_8M_MAIN__
    // note on ARMv8-m main; we want to expose the real value so that it can be used in immediate operands
    rc.v = HX_BIT_PATTERN_FALSE ^ HX_XOR_KEY_MATCH;
#else
    rcp_asm ("mrc p7, #7, %0, c0, c8, #0\n" : "=r" (rc.v));
#endif
    return rc;
}

static __force_inline uint32_t hx_bit_pattern_xor_secure(void) {
    uint32_t rc;
    rc = HX_XOR_SECURE;
//#if __ARM_ARCH_8M_MAIN__
//    // note on ARMv8-m main; we want to expose the real value so that it can be used in immediate operands
//    rc = HX_XOR_SECURE;
//#else
//    rcp_asm ("mrc p7, #7, %0, c0, c6, #0\n" : "=r" (rc));
//#endif
    return rc;
}

static __force_inline hx_xbool hx_sig_verified_true(void) {
    hx_xbool rc;
#if __ARM_ARCH_8M_MAIN__
    // the constant is not available via mov.w, so lets fabricate it (we shouldn't store it in the binary)
    rcp_asm ("mrc p7, #7, %0, c0, c0, #0\n" : "=r" (rc.v));
    rc.v ^= HX_XOR_SIG_VERIFIED;
#else
    rcp_asm ("mrc p7, #7, %0, c0, c6, #0\n" : "=r" (rc.v));
#endif
    return rc;
}

static __force_inline hx_xbool hx_otp_secure_true(void) {
    hx_xbool rc;
#if __ARM_ARCH_8M_MAIN__
    // note on ARMv8-m main; we want to expose the real value so that it can be used in immediate operands
    rc.v = HX_BIT_PATTERN_TRUE ^ HX_XOR_OTP_SECURE;
#else
    rcp_asm ("mrc p7, #7, %0, c0, c9, #0\n" : "=r" (rc.v));
#endif
    return rc;
}

static __force_inline uint32_t hx_otp_secure_xor(void) {
    uint32_t rc;
#if __ARM_ARCH_8M_MAIN__
    // note on ARMv8-m main; we want to expose the real value so that it can be used in immediate operands
    rc = HX_XOR_OTP_SECURE;
#else
    rcp_asm ("mrc p7, #7, %0, c0, c10, #0\n" : "=r" (rc));
#endif
    return rc;
}

static __force_inline uint32_t hx_bit_pattern_c3c3c3c3(void) {
    uint32_t rc;
#if __ARM_ARCH_8M_MAIN__
    // note on ARMv8-m main; we want to expose the real value so that it can be used in immediate operands
    rc = 0xc3c3c3c3;
#else
    rcp_asm ("mrc p7, #7, %0, c0, c11, #0\n" : "=r" (rc));
#endif
    return rc;
}


static __force_inline uint32_t hx_bit_pattern_not(void) {
    // not much we can do here (unless we decide to store it at a known location
    uint32_t rc;
    rc = HX_BIT_PATTERN_TRUE ^ HX_BIT_PATTERN_FALSE;
    return rc;
}


static __force_inline hx_bool hx_false(void) {
    hx_bool rc = { .v = hx_bit_pattern_false() };
    return rc;
}


static __force_inline hx_bool hx_true(void) {
    hx_bool rc = { .v = hx_bit_pattern_true() };
    return rc;
}

static __force_inline hx_bool make_hx_bool2(bool value1, bool value2) {
    register uint32_t r0 asm ("r0") = value1;
    register uint32_t r1 asm ("r1") = value2;
    pico_default_asm(
            "bl sonly_varm_make_hx_bool_impl"
            : "+l" (r0)
            : "l" (r1)
            : "ip", "lr", "cc"
            );
    hx_bool rc = { r0 };
    return rc;
}

static __force_inline hx_bool make_hx_bool2_u(uint32_t value1, uint32_t value2) {
    register uint32_t r0 asm ("r0") = value1;
    register uint32_t r1 asm ("r1") = value2;
    pico_default_asm(
    "bl sonly_varm_make_hx_bool_impl"
    : "+l" (r0)
    : "l" (r1)
    : "ip", "lr", "cc"
    );
    hx_bool rc = { r0 };
    return rc;
}

static __force_inline hx_bool make_hx_bool(bool value) {
    register uint32_t r0 asm ("r0") = value;
    register uint32_t r1 asm ("r1") = value;
    pico_default_asm(
            "bl sonly_varm_make_hx_bool_impl"
    : "+l" (r0)
    : "l" (r1)
    : "ip", "lr", "cc"
    );
    hx_bool rc = { r0 };
    return rc;
}

static __force_inline hx_xbool make_hx_xbool2(bool value1, bool value2, uint32_t xor) {
    register uint32_t r0 asm ("r0") = value1;
    register uint32_t r1 asm ("r1") = value2;
    pico_default_asm(
            "bl sonly_varm_make_hx_bool_impl"
    : "+l" (r0)
    : "l" (r1)
    : "ip", "lr", "cc"
    );
    hx_xbool rc = { r0 ^ xor };
    return rc;
}

static __force_inline hx_xbool make_hx_xbool(bool value, uint32_t xor) {
    return make_hx_xbool2(value, value, xor);
}

static __force_inline void hx_check_xbool(hx_xbool v, uint32_t xor) {
    rcp_bxorvalid(v.v, xor);
}

static __force_inline hx_bool hx_bool_invalid(void) { hx_bool rc = {0}; return rc; }
static __force_inline hx_xbool hx_xbool_invalid(void) { hx_xbool rc = {0}; return rc; }
static __force_inline hx_bool hx_bool_null(void) { return hx_bool_invalid(); }
static __force_inline bool hx_is_null(hx_bool v) { return !v.v; }
static __force_inline bool hx_is_true(hx_bool v) {
    return (int32_t)v.v < 0;
}
static __force_inline bool hx_is_xtrue(hx_xbool v) {
    // because we never XOR with a value with the top bit set, the comparison holds
    return (int32_t)v.v < 0;
}
static __force_inline bool hx_is_xfalse(hx_xbool v) {
    // because we never XOR with a value with the top bit set, the comparison holds
    return (int32_t)v.v >= 0;
}

static_assert((int32_t)HX_BIT_PATTERN_TRUE < 0, "");
static_assert((int32_t)HX_BIT_PATTERN_FALSE >= 0, "");

static __force_inline bool hx_is_false(hx_bool v) {
    return (int32_t)v.v >= 0;
}

static __force_inline bool hx_is_false_checked(hx_bool v) {
    rcp_bvalid(v.v);
    return (int32_t)v.v >= 0;
}

static __force_inline void hx_check_bool(hx_bool v) {
    rcp_bvalid(v.v);
}

static __force_inline void hx_check_bools(hx_bool a, hx_bool b) {
    rcp_b2valid(a.v, b.v);
}

static __force_inline void hx_assert_false(hx_bool v) {
    // we don't form real constants on RISC-V necessarily, so relax the check
    //bootrom_assert(MISC, v.v == HX_BIT_PATTERN_FALSE);
    bootrom_assert(MISC, hx_is_false(v));
    rcp_bfalse(v.v);
}

static __force_inline void hx_assert_true(hx_bool v) {
    // we don't form real constants on RISC-V necessarily, so relax the check
//    bootrom_assert(MISC, v.v == HX_BIT_PATTERN_TRUE);
    bootrom_assert(MISC, hx_is_true(v));
    rcp_btrue(v.v);
}

static __force_inline void hx_assert_null(hx_bool v) {
    bootrom_assert(MISC, !v.v);
    rcp_iequal(v.v, 0);
}

static __force_inline void hx_assert_or(hx_bool a, hx_bool b) {
    rcp_b2or(a.v, b.v);
}

static __force_inline void hx_assert_and(hx_bool a, hx_bool b) {
    rcp_b2and(a.v, b.v);
}

static __force_inline void hx_assert_bequal(hx_bool a, hx_bool b) {
    bootrom_assert(MISC, (a.v ^ b.v) == 0 && (a.v == HX_BIT_PATTERN_TRUE || a.v == HX_BIT_PATTERN_FALSE));
    hx_check_bools(a, b);
    rcp_iequal(a.v, b.v);
}

static __force_inline hx_bool hx_not(hx_bool v) {
    hx_bool rc = { v.v ^ (hx_bit_pattern_not()) };
    return rc;
}

static __force_inline hx_bool hx_notx(hx_xbool v, uint32_t xor) {
    hx_bool rc = { v.v ^ (HX_BIT_PATTERN_TRUE ^ HX_BIT_PATTERN_FALSE ^ xor) };
    return rc;
}

// same as hx_notx but useful to save code space if xor and base_xor result in close (-128 -> +127) NOT constantw
static __force_inline hx_bool hx_notx_constant_diff(hx_xbool v, uint32_t xor, uint32_t base_xor) {
    hx_bool rc = { v.v ^ (__get_opaque_value(HX_BIT_PATTERN_TRUE ^ HX_BIT_PATTERN_FALSE ^ base_xor) +
                    ((HX_BIT_PATTERN_TRUE ^ HX_BIT_PATTERN_FALSE ^ xor) -
                     (HX_BIT_PATTERN_TRUE ^ HX_BIT_PATTERN_FALSE ^ base_xor)))
    };
    return rc;
}


static __force_inline hx_bool hx_not_checked(hx_bool v) {
    hx_check_bool(v);
    hx_bool rc = { v.v ^ (hx_bit_pattern_not()) };
    return rc;
}

static __force_inline hx_bool hx_and_notb(hx_bool a, bool b) {
     if (b) a = hx_false();
     return a;
}

static __force_inline void hx_assert_notx_orx_true(hx_xbool a, uint32_t a_xor, hx_xbool b, uint32_t b_xor) {
    a.v ^= a_xor ^ HX_BIT_PATTERN_FALSE ^ HX_BIT_PATTERN_TRUE;
    b.v ^= b_xor;
    rcp_b2or(a.v, b.v);
}

static __force_inline hx_bool hx_and(hx_bool a, hx_bool b) {
    hx_bool rc;
    rc.v = a.v & b.v;
    // little extra check
    if (rc.v) rc.v |= a.v | b.v;
    return rc;
}

static __force_inline hx_bool hx_or(hx_bool a, hx_bool b) {
    // assume we check this later... if it was invalid before, it is invalid after
    // deliberate | to cause check off both
    hx_bool rc = make_hx_bool(hx_is_true(a) || hx_is_true(b));
    return rc;
}

static __force_inline hx_bool hx_or_checked(hx_bool a, hx_bool b) {
    hx_check_bools(a, b);
    // assume we check this later... if it was invalid before, it is invalid after
    // deliberate | to cause check off both
    hx_bool rc = make_hx_bool(hx_is_true(a) || hx_is_true(b));
    return rc;
}

static __force_inline hx_bool hx_and_checked(hx_bool a, hx_bool b) {
    hx_check_bools(a, b);
    hx_bool rc = { a.v & b.v };
    if (!rc.v) rc.v = hx_bit_pattern_false();
    return rc;
}

static __force_inline hx_bool hx_and_not_checked(hx_bool a, hx_bool b) {
    // assume we check this later... if it was invalid before, it is invalid after
    // deliberate & to cause check off both
    //hx_bool rc = make_hx_bool(hx_is_true(a) & hx_is_true(b));
    hx_check_bools(a, b);
    hx_bool rc = { a.v & (b.v ^ hx_bit_pattern_not()) };
    if (!rc.v) rc.v = hx_bit_pattern_false();
    return rc;
}

static __force_inline void hx_assert_xfalse(hx_xbool v, uint32_t xor) {
    bootrom_assert(MISC, (v.v ^ xor) == HX_BIT_PATTERN_FALSE);
    rcp_bxorfalse(v.v, xor);
}

static __force_inline void hx_assert_xtrue(hx_xbool v, uint32_t xor) {
    bootrom_assert(MISC, (v.v ^ xor) == HX_BIT_PATTERN_TRUE);
    rcp_bxortrue(v.v, xor);
}

static __force_inline void hx_assert_equal2i(uint32_t a, uint32_t b) {
    rcp_iequal(a, b);
}

static __force_inline hx_uint32_t make_hx_uint32(uint32_t value) { hx_uint32_t rc = { value, value ^ hx_bit_pattern_xor()}; return rc; }
static __force_inline hx_uint32_t make_hx_uint32_2(uint32_t value1, uint32_t value2) { hx_uint32_t rc = { value1, value2 ^ hx_bit_pattern_xor()}; return rc; }
static __force_inline void hx_check_uint32(hx_uint32_t v) {
    rcp_ivalid(v.v, v.p);
}

static __force_inline uint32_t hx_value(hx_uint32_t v) {
    return v.v;
}

static __force_inline uint32_t hx_value_other(hx_uint32_t v) {
    return v.p ^ hx_bit_pattern_xor();
}

static __force_inline bool hx_signed_is_greater(hx_uint32_t a, hx_uint32_t b) {
    return (int32_t)a.v > (int32_t)b.v;
}

static __force_inline bool hx_signed_is_greater_equali(hx_uint32_t a, int32_t b) {
    return (int32_t)a.v >= b;
}

static __force_inline bool hx_unsigned_is_greater(hx_uint32_t a, hx_uint32_t b) {
    return a.v > b.v;
}

static __force_inline hx_bool hx_b_from_unsigned_is_less(hx_uint32_t a, hx_uint32_t b) {
    uint32_t xor = hx_bit_pattern_xor();
    return make_hx_bool2(a.v < b.v, (a.p ^ xor) < (b.p ^ xor));
}

static __force_inline bool hx_is_equal(hx_uint32_t a, hx_uint32_t b) {
    return a.v == b.v;
}

static __force_inline hx_bool hx_xbool_to_bool(hx_xbool b, uint32_t xor) {
    hx_bool rc = { b.v ^ xor};
    return rc;
}

static __force_inline hx_bool hx_xbool_to_bool_checked(hx_xbool b, uint32_t xor) {
    rcp_bxorvalid(b.v, xor);
    hx_bool rc = { b.v ^ xor};
    return rc;
}

static __force_inline hx_bool hx_uint32_to_bool_checked(hx_uint32_t v) {
    hx_check_uint32(v);
    return make_hx_bool2(v.v != 0, (v.p ^ hx_bit_pattern_xor()) != 0);
}

static __force_inline uint32_t boot_flag_selector(uint8_t bit) {
    uint32_t bit32 = bit+1; // we know that bit <= 23
    return bit32 + (((~bit32) & 7) << 5);
}

// to save space, we preserve all registers across this call, and take the hit in s_varm_step_safe_hx_get_boot_flag_impl
// (added benefit the argument to this r0 is not a valid result hx_bool, so skipping the call won't help you
static __force_inline hx_xbool hx_step_safe_get_boot_flagx(uint8_t bit) {
    // we include the bit pattern
    register hx_xbool r0 asm("r0") = { .v = boot_flag_selector(bit) };
    pico_default_asm_volatile(
            "bl s_varm_step_safe_hx_get_boot_flagx_impl\n"
            : "+r" (r0)
            :
            : "r1", "ip", "lr", "cc"
    );
    return r0;
}

static __force_inline hx_bool hx_step_safe_get_boot_flag(uint8_t bit) {
    // we include the bit pattern
    register hx_bool r0 asm("r0") = { .v = boot_flag_selector(bit) };
    pico_default_asm_volatile(
    "bl varm_to_s_native_step_safe_hx_get_boot_flag_impl\n"
    : "+r" (r0)
    :
    : "ip", "lr", "cc"
    );
    return r0;
}

static __force_inline hx_xbool __get_opaque_xbool(hx_xbool b) {
    hx_xbool rc = {__get_opaque_value(b.v) };
    return rc;
}

#endif
#endif

uint32_t varm_callable(s_native_step_safe_crit_mem_erase_by_words_impl)(uintptr_t start, uint MUST_be_zero, uint32_t byte_count);
uint32_t varm_callable(s_native_crit_mem_copy_by_words_impl)(uint32_t *dest, const uint32_t *src, uint32_t byte_count);
#if !defined(__riscv) && !defined(__ARM_ARCH_8M_MAIN__)
static __force_inline uint s_varm_step_safe_crit_mem_erase_by_words(uintptr_t start, uint32_t byte_count) {
    uint bytes4 = varm_to_s_native_step_safe_crit_mem_erase_by_words_impl(start, 0, byte_count);
    hx_assert_equal2i(bytes4, byte_count);
    return bytes4;
}

static __force_inline uint s_varm_crit_mem_copy_by_words(uint32_t *dest, const uint32_t *src, uint32_t byte_count) {
    uint bytes4 = varm_to_s_native_crit_mem_copy_by_words_impl(dest, src, byte_count);
    hx_assert_equal2i(bytes4, byte_count);
    return bytes4;
}
#else
#if !defined(__riscv)
static __force_inline uint s_native_crit_step_safe_mem_erase_by_words(uintptr_t start, uint32_t byte_count) {
    uint bytes4 = s_native_step_safe_crit_mem_erase_by_words_impl(start, 0, byte_count);
    hx_assert_equal2i(bytes4, byte_count);
    return bytes4;
}

static __force_inline uint s_native_crit_mem_copy_by_words(uint32_t *dest, const uint32_t *src, uint32_t byte_count) {
    uint bytes4 = s_native_crit_mem_copy_by_words_impl(dest, src, byte_count);
    hx_assert_equal2i(bytes4, byte_count);
    return bytes4;
}
#endif
#endif // !defined(__riscv) && !defined(__ARM_ARCH_8M_MAIN__)

#endif // __ASSEMBLER__
