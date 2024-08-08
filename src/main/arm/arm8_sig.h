/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "pico.h"
#include "hardware/structs/sha256.h"
#include "hardening.h"
#include "sb_types.h"

typedef sb_double_t sb_sw_public_t;
typedef sb_double_t sb_sw_signature_t;
typedef sb_single_t sb_sw_message_digest_t;

#define SIG_CONTEXT_SIZE 0x200
static_assert(0 == (SIG_CONTEXT_SIZE & 3), "");
// note this returns an XORed hx_bool with HX_XOR_SIG_VERIFIED
hx_xbool s_arm8_verify_signature_secp256k1(uint32_t context_buffer[SIG_CONTEXT_SIZE/4],
                                          const sb_sw_public_t public_key[1],
                                          const sb_sw_message_digest_t digest[1],
                                          const sb_sw_signature_t signature[1]);

