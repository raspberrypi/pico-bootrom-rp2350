/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bootrom.h"
#include "arm8_sig.h"
#include "sb_sw_lib.h"

hx_xbool s_arm8_verify_signature_secp256k1(
        uint32_t context_buffer[SIG_CONTEXT_SIZE/4],
        const sb_sw_public_t public_key[1],
        const sb_sw_message_digest_t digest[1],
        const sb_sw_signature_t signature[1]) {
    canary_entry(S_ARM8_VERIFY_SIGNATURE_SECP256K1);
    // note we pass a buffer, as this is too big to go on the stack
    // note: could be < but may as well be exact, so we don't waste space
    static_assert(sizeof(sb_sw_context_t) == SIG_CONTEXT_SIZE, "");
    sb_sw_context_t *context = (sb_sw_context_t *)context_buffer;
    sb_verify_result_t res = sb_sw_verify_signature(context,
                                              signature,
                                              public_key,
                                              digest,
                                              NULL,
                               SB_SW_CURVE_SECP256K1);
#if !BOOTROM_HARDENING
    // sweet-b by default has zero for SUCCESS
    res = !res;
#endif
    canary_exit_return(S_ARM8_VERIFY_SIGNATURE_SECP256K1, res);
}
