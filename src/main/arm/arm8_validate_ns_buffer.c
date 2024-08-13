/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bootrom.h"
#include "arm8_validate_ns_buffer.h"
#include "hardware/structs/accessctrl.h"

#undef  __ARM_FEATURE_CMSE
#define __ARM_FEATURE_CMSE 3

#include "arm_cmse.h"

#if 0
/*
 * ; ah MPSR NS
 * bool inPrivMode = (__get_IPSR()>0) || ((__get_CONTROL() & CONTROL_nPRIV_Msk) == 0);
 */
void *
__attribute__ ((warn_unused_result))
cmse_check_address_range (void *p, size_t size, int flags)
{
    cmse_address_info_t permb, perme;
    char *pb = (char *) p, *pe;

    /* Check if the range wraps around.  */
    if (__UINTPTR_MAX__ - (__UINTPTR_TYPE__) p < size)
        return NULL;

    /* Check if an unknown flag is present.  */
    int known = CMSE_MPU_UNPRIV | CMSE_MPU_READWRITE | CMSE_MPU_READ;
    int known_secure_level = CMSE_MPU_UNPRIV;
#if __ARM_FEATURE_CMSE & 2
    known |= CMSE_AU_NONSECURE | CMSE_MPU_NONSECURE;
  known_secure_level |= CMSE_MPU_NONSECURE;
#endif
    if (flags & (~known))
        return NULL;

    /* Execute the right variant of the TT instructions.  */
    pe = pb + size - 1;
    const int singleCheck
            = (((__UINTPTR_TYPE__) pb ^ (__UINTPTR_TYPE__) pe) < 32);
    switch (flags & known_secure_level)
    {
        case 0:
            permb = cmse_TT (pb);
            perme = singleCheck ? permb : cmse_TT (pe);
            break;
        case CMSE_MPU_UNPRIV:
            permb = cmse_TTT (pb);
            perme = singleCheck ? permb : cmse_TTT (pe);
            break;
#if __ARM_FEATURE_CMSE & 2
            case CMSE_MPU_NONSECURE:
      permb = cmse_TTA (pb);
      perme = singleCheck ? permb : cmse_TTA (pe);
      break;
    case CMSE_MPU_UNPRIV | CMSE_MPU_NONSECURE:
      permb = cmse_TTAT (pb);
      perme = singleCheck ? permb : cmse_TTAT (pe);
      break;
#endif
        default:
            /* Invalid flag, eg.  CMSE_MPU_NONSECURE specified but
           __ARM_FEATURE_CMSE & 2 == 0.  */
            return NULL;
    }

    /* Check that the range does not cross MPU, SAU, or IDAU boundaries.  */
    if (permb.value != perme.value)
        return NULL;

    /* Check the permissions on the range.  */
    switch (flags & (~known_secure_level))
    {
#if __ARM_FEATURE_CMSE & 2
        case CMSE_MPU_READ | CMSE_MPU_READWRITE | CMSE_AU_NONSECURE:
    case         CMSE_MPU_READWRITE | CMSE_AU_NONSECURE:
      return permb.flags.nonsecure_readwrite_ok ? p : NULL;
    case CMSE_MPU_READ | CMSE_AU_NONSECURE:
      return permb.flags.nonsecure_read_ok  ? p : NULL;
    case CMSE_AU_NONSECURE:
      return permb.flags.secure         ? NULL : p;
#endif
        case CMSE_MPU_READ | CMSE_MPU_READWRITE:
        case         CMSE_MPU_READWRITE:
            return permb.flags.readwrite_ok     ? p : NULL;
        case CMSE_MPU_READ:
            return permb.flags.read_ok      ? p : NULL;
        default:
            return NULL;
    }
}
#endif

static inline __force_inline uint32_t s_arm8_get_ipsr(void) {
    // No need to zero-extend the Exception field of IPSR, as we know
    // for *this version* of v8-M that all other bits are RES0.
    uint32_t ipsr;
    pico_default_asm_volatile(
        "mrs %0, ipsr\n"
        : "=r" (ipsr)
    );
    return ipsr;
}

// seems smaller if force-inlined: lots of unnecessary arg-saving in
// validate_ns_buffer if we permit an outline call.

static __force_inline bool s_arm8_is_ns_privileged(void) {
    if (s_arm8_get_ipsr()) return true;
    uint priv;
    pico_default_asm_volatile (
            "mrs %0, control_ns\n"
            : "=l" (priv)
            );
    return !(priv & 1);
}

static __force_inline bool s_arm8_is_ns_unprivileged(void) {
    if (s_arm8_get_ipsr()) return false;
    uint priv;
    pico_default_asm_volatile (
            "mrs %0, control_ns\n"
            : "=l" (priv)
            );
    return (priv & 1);
}

#define TT_RESP_NSR_LSB 20
#define TT_RESP_NSRW_LSB 21

// Validate a NonSecure buffer.
//
// Entire buffer must fit in range XIP_BASE -> SRAM_END, and must be
// accessible from NS caller according to SAU + NS MPU (privileged or not
// based on current processor IPSR and NS CONTROL flag). We also allow
// buffers in USB RAM if this is granted to NS via ACCESSCTRL -- note USB RAM
// is IDAU-Exempt so will fail tt* checks.
//
// sets *ok = hx_false() on failure, and returns BOOTROM_ERROR_INVALID_ADDRESS
void __exported_from_arm *s_native_api_validate_ns_buffer(const void *addr, uint32_t size, hx_bool write, hx_bool *_ok) {
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    // Diagnostic: CMSE header uses the wrong type signature for TT intrinsics. We cast away the
    // const but do not write through the resulting pointer. (Our signature is const* because we
    // may validate read-only buffers!) We also cast away the constness on return, because we may
    // assign back to a non-const buffer when a non-const buffer was passed in.
    volatile hx_bool *ok = (volatile hx_bool*)_ok;
    hx_set_step_nodelay(STEPTAG_S_NATIVE_API_VALIDATE_NS_BUFFER_BASE);
    *ok = hx_bool_invalid();
    __compiler_memory_barrier();

    uintptr_t pstart = (uintptr_t)addr;
    // Note -1 because bounds are inclusive: we test the byte at each end. 0-byte buffers are tested
    // as though they are 1-byte.
    uintptr_t pend = (uintptr_t)addr + size - (size != 0);

    // Initialisation values are interpreted as 4 different MPU regions, with no permissions set.
    // The defaults here will cause tests below to fall through. Without the barriers, the compiler
    // likes to eliminate the initial values:
    uint32_t flags_start  = 0; __dataflow_barrier(flags_start);
    uint32_t flags_end    = 1; __dataflow_barrier(flags_end);
    uint32_t flags_start2 = 2; __dataflow_barrier(flags_start2);
    uint32_t flags_end2   = 3; __dataflow_barrier(flags_end2);

    bool ns_is_privileged = s_arm8_is_ns_privileged();
    if (ns_is_privileged) {
        flags_start  = cmse_TTA((void*)pstart).value;
        flags_end    = cmse_TTA((void*)pend).value;
        flags_start2 = cmse_TTA((void*)pstart).value;
        flags_end2   = cmse_TTA((void*)pend).value;
        // Step check: we go through exactly one of these branches.
        hx_check_step(STEPTAG_S_NATIVE_API_VALIDATE_NS_BUFFER_BASE);
    }
    bool ns_is_unprivileged = s_arm8_is_ns_unprivileged();
    if (ns_is_unprivileged) {
        flags_start  = cmse_TTAT((void*)pstart).value;
        flags_end    = cmse_TTAT((void*)pend).value;
        flags_start2 = cmse_TTAT((void*)pstart).value;
        flags_end2   = cmse_TTAT((void*)pend).value;
        // Step check: we go through exactly one of these branches.
        hx_check_step(STEPTAG_S_NATIVE_API_VALIDATE_NS_BUFFER_BASE);
    }
    // Valid spans do not wrap the address space, and do not start/end in different IDAU, SAU, or
    // MPU regions.
    // Note __get_opaque_value to stop compiler from assuming they are equal
    // under the branch, in particular when we want to do an rcp_iequal.
    if (pstart <= pend && __get_opaque_value(flags_end) == flags_start) {
        hx_assert_equal2i(flags_end2, flags_start2);
        // XIP and SRAM are the valid spaces for buffers in non-Exempt regions.
        if (pstart >= XIP_BASE && pend < SRAM_END) {
            static_assert(TT_RESP_NSR_LSB + 1 == TT_RESP_NSRW_LSB);
            hx_check_step(STEPTAG_S_NATIVE_API_VALIDATE_NS_BUFFER_BASE + 1);
            __dataflow_barrier(write);
            uint32_t rw_r_ok_1 = ((flags_start >> TT_RESP_NSR_LSB) >> hx_is_true(write)) & 0x1;
            __dataflow_barrier(write);
            uint32_t rw_r_ok_2 = ((flags_end2 >> TT_RESP_NSR_LSB) >> hx_is_true(write)) & 0x1;
            hx_check_bool(write);
            *ok = make_hx_bool2_u(rw_r_ok_1, rw_r_ok_2);
            if (hx_is_true(*ok)) {
                hx_assert_equal2i(flags_end, flags_start);
                hx_check_step(STEPTAG_S_NATIVE_API_VALIDATE_NS_BUFFER_BASE + 2);
                return (void*)addr;
            }
        } else if (pstart >= USBCTRL_DPRAM_BASE && pend < USBCTRL_DPRAM_BASE + USBCTRL_DPRAM_SIZE) {
            // USB RAM is the only valid space for a buffer in an Exempt region. Exempt regions will
            // always fail TTA checks, so we allow NS buffers in USB RAM if and only if the USB
            // peripheral is granted to NS at the caller's privilege level via ACCESSCTRL.
            // (Note: this means we ignore NS MPU regions in USB RAM)
            static_assert(ACCESSCTRL_USBCTRL_NSU_BITS == 1, "");
            uint32_t ok1 = (accessctrl_hw->usbctrl >> ns_is_privileged) & ACCESSCTRL_USBCTRL_NSU_BITS;
            uint32_t ok2 = ((accessctrl_hw->usbctrl << ns_is_unprivileged) >> 1) & ACCESSCTRL_USBCTRL_NSU_BITS;
            *ok = make_hx_bool2_u(ok1, ok2);
            hx_check_step(STEPTAG_S_NATIVE_API_VALIDATE_NS_BUFFER_BASE + 1);
            if (hx_is_true(*ok)) {
                hx_assert_equal2i(flags_end, flags_start);
                hx_check_step(STEPTAG_S_NATIVE_API_VALIDATE_NS_BUFFER_BASE + 2);
                return (void*)addr;
            }
        } else {
            hx_check_step(STEPTAG_S_NATIVE_API_VALIDATE_NS_BUFFER_BASE + 1);
        }
    } else {
        hx_check_step(STEPTAG_S_NATIVE_API_VALIDATE_NS_BUFFER_BASE + 1);
    }

    *ok = hx_false();
    hx_assert_false(*ok);
    hx_check_step(STEPTAG_S_NATIVE_API_VALIDATE_NS_BUFFER_BASE + 2);
    return (void *)BOOTROM_ERROR_INVALID_ADDRESS;
#pragma GCC diagnostic pop
}
