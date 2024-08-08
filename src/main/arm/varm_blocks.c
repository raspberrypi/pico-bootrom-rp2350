/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "varm_boot_path.h"
#include "native_generic_flash.h"
#include "arm8_sig.h"
#include "sb_sw_lib.h"
#include "hardware/structs/rosc.h"
#include "hardware/structs/clocks.h"

#if defined(__ARM_ARCH_8M_MAIN__) || !defined(__ARM_ARCH_8M_BASE__)
#error this must be compiled with armv8m-base
#endif

#if MINI_PRINTF
static __noinline uint debug_real_addr(const block_scan_t *bs, uint32_t buf_word_pos) {
//    return hx_value(hx_add(bs->base_addr, hx_add(bs->buf_offset, buf_pos)));
    return bs->ctx->current_search_window.base + (bs->window_rel_buf_start_word_offset + buf_word_pos) * 4;
}
#endif
#if 0
#define next_block_printf printf
#else
#define next_block_printf(...) ((void)0)
#endif

#define to_block_word_index_t(v) ({ bootrom_assert(BLOCK_SCAN, (v) < 256); (block_word_index_t)(v); })

#if MINI_PRINTF
__noinline void print_bytes(const uint8_t *bytes, uint count) {
    for (uint i = 0; i < count; i++) {
        printf("%02x", bytes[i]);
    }
    printf(" \n");
}
#else
#define print_bytes(b,c) ((void)0)
#endif

#if MINI_PRINTF
#define unsupported_block_printf(s, ...) ({ printf("MALFORMED block found around %08x : ", \
            debug_real_addr(bs, bs->buf_word_pos)); printf(s, ## __VA_ARGS__); printf("\n"); })
#else
#define unsupported_block_printf(s, ...) ((void)0)
#endif

#define unsupported_block_error(n, s, ...) ({ unsupported_block_printf(s, ## __VA_ARGS__); return -1; })
//#define unsupported_block_error(n, s, ...) ({ unsupported_block_printf(s, ## __VA_ARGS__); return -(n); })
//#define unsupported_block_error(n, s, ...) ({ unsupported_block_printf(s, ## __VA_ARGS__); end_marker_buf_pos = (uint32_t)-(n); goto error_man; })

static __force_inline bool first_block_found(const block_scan_t *bs) {
    return bs->window_rel_first_block_word_offset >= 0;
}

int s_varm_crit_next_block(block_scan_t *bs) {
    uint32_t *buffer = (uint32_t *)bs->ctx->scan_workarea->block_buffer_or_signature_workspace.block_buffer;
    static_assert(sizeof(bs->ctx->scan_workarea->block_buffer_or_signature_workspace.block_buffer) == PICOBIN_MAX_BLOCK_SIZE, "");

    // note: there is absolutely no need to copy data into a buffer, except when using flash, however
    // we do so to keep the code paths largely identical, and thus save code size

    do {
        next_block_printf("FIND BLOCK LOOP buf_word_pos=%08x, buf_word_count=%08x\n", (uint)bs->buf_word_pos, (uint)bs->buf_word_count);
        // refill buffer as much as we can
        if (bs->buf_word_pos == bs->buf_word_count) {
            bs->buf_word_pos = bs->buf_word_count = 0;
            bs->window_rel_buf_start_word_offset = bs->window_rel_next_read_word_offset;
        }
        if (bs->window_rel_buf_start_word_offset + bs->buf_word_pos == (uint32_t)bs->window_rel_first_block_word_offset) {
            next_block_printf("  looped back to first block at %08x\n", debug_real_addr(bs, 0));
            return 0;
        }
        uint32_t max_read_word_count = bs->ctx->current_search_window.size/4 - bs ->window_rel_next_read_word_offset;
//        printf("maxrwc 0x%08x bwc %d\n", max_read_word_count, bs->buf_word_count);
        if (max_read_word_count && max_read_word_count <= bs->ctx->current_search_window.size/4) {
            int32_t to_read_word_count = (PICOBIN_MAX_BLOCK_SIZE / 4 - bs->buf_word_count);
            to_read_word_count = MIN(to_read_word_count, (int)max_read_word_count);
            to_read_word_count = MIN(to_read_word_count, 0x200 / 4); // limit read to 0x200 so we don't overshoot 0x1000 (performance)
            if (to_read_word_count > 0) {
                next_block_printf("READ %08x(%08x) + %08x -> %p - %p\n",
                                  (uint) bs->ctx->current_search_window.base + bs->window_rel_next_read_word_offset*4,
                                  resolve_ram_or_absolute_flash_addr(bs->ctx->current_search_window.base) + bs->window_rel_next_read_word_offset,
                                  (uint) to_read_word_count * 4,
                                  buffer + bs->buf_word_count,
                                  buffer + bs->buf_word_count + to_read_word_count);
                // note: this was an inlines flash_read_data; however we now support reading from RAM too, and flash-read_data is just assert + memcpy
                // hx_assert_equal2i(addr & -(1u << 24), 0);
                s_varm_crit_mem_copy_by_words(buffer + bs->buf_word_count,
                                           resolve_ram_or_absolute_flash_addr(bs->ctx->current_search_window.base) + bs->window_rel_next_read_word_offset, (uint32_t)to_read_word_count*4);
                bs->window_rel_next_read_word_offset += (uint32_t)to_read_word_count;
                bs->buf_word_count += (block_word_index_t)to_read_word_count;
            }
        } else {
            // no more, but leaving around just in case
            // pico_default_asm_volatile("nop"); // for whatever reason, the code is smaller with this NOP ;-)
            unsupported_block_error(128, "attempt to read outside of window at %08x(%08x)\n",
                                    (uint) bs->ctx->current_search_window.base +
                                    bs->window_rel_next_read_word_offset * 4,
                                    resolve_ram_or_absolute_flash_addr(bs->ctx->current_search_window.base) +
                                    bs->window_rel_next_read_word_offset);
        }
        if (!first_block_found(bs)) {
            next_block_printf("searching for first block\n");
            // we must look for the first block
            while (bs->buf_word_pos < bs->buf_word_count) {
                uint32_t value = buffer[bs->buf_word_pos];
                if (value == PICOBIN_BLOCK_MARKER_START) {
                    next_block_printf("possible first block start at buffer offset %08x = %08x\n", (uint) bs->buf_word_pos*4, debug_real_addr(bs, bs->buf_word_pos));
                    break;
                }
                bs->buf_word_pos++;
            }
            if (bs->buf_word_pos >= bs->buf_word_count) {
                if (bs->window_rel_next_read_word_offset >= bs->window_rel_first_block_max_word_offset) {
                    next_block_printf("first block scan exhausted with no marker found\n");
                    return 0;
                }
                // we will keep reading
                next_block_printf("no block start found in current buffer, need to read more\n");
                continue;
            }
        } else {
            uint32_t value = buffer[bs->buf_word_pos];
            if (value != PICOBIN_BLOCK_MARKER_START) {
                unsupported_block_error(1, "no block marker at next expected pos %p\n", debug_real_addr(bs, bs->buf_word_pos));
                // if we've found the first block, then we expect to immediately find a block where we're looking
            }
        }
        next_block_printf("block is at buffer offset %08x = %08x\n", (uint) bs->buf_word_pos*4, debug_real_addr(bs, bs->buf_word_pos));
        // so at this point there is a block start marker at buf_pos
        if (bs->buf_word_pos) {
            next_block_printf("copying %d words from %08x to start of buffer\n", bs->buf_word_count - bs->buf_word_pos, buffer + bs->buf_word_pos);
            // buf_pos is not at start of buffer, so we will move everything down
            bootrom_assert(BLOCK_SCAN, bs->buf_word_pos != bs->buf_word_count);
            s_varm_crit_mem_copy_by_words(buffer, buffer + bs->buf_word_pos, (bs->buf_word_count - bs->buf_word_pos)*4u);
            bs->buf_word_count -= bs->buf_word_pos;
            bs->window_rel_buf_start_word_offset += bs->buf_word_pos;
            bs->buf_word_pos = 0;
            // we continue to complete filling of buffer
            continue;
        }
        // we now have a full buffer with PICOBIN_BLOCK_MARKER_START at the beginning.
        // note that the entire block is in our buffer
//        uint32_t size = 0;
        uint32_t item_pos = 1;
        uint32_t end_marker_buf_pos = 0;
        while (item_pos < bs->buf_word_count) {
            const aligned4_uint8_t *ptr = (const aligned4_uint8_t *)(buffer + item_pos);
            next_block_printf("ITEM AT %08x (off %d) %08x\n", (int)item_pos*4, (int)item_pos, ((const uint32_t*)ptr)[0]);
            uint8_t type = ptr[0];
            uint32_t item_size = inline_decode_item_size(*(const uint32_t *)ptr);
            if (!item_size) {
                unsupported_block_error(2, "invalid zero sized item");
            }
            if (type == PICOBIN_BLOCK_ITEM_2BS_LAST) {
                // block size in words is always item_pos - 1 since we start at 1
                if (item_pos - 1 == item_size) {
                    if (item_pos < bs->buf_word_count && buffer[item_pos + 2] == PICOBIN_BLOCK_MARKER_END) {
                        end_marker_buf_pos = item_pos;
                    } else {
                        unsupported_block_error(4, "no end marker in range");
                    }
                } else {
                    unsupported_block_error(8, "size mismatch %d != %d\n", (uint)(item_pos - 1), (uint)item_size);
                }
                break;
            }
//            size += item_size;
            item_pos += item_size;
        }
        if (end_marker_buf_pos) {
            // this is a valid block
            next_block_printf("WOOT BLOCK IS GOOD!!\n");
            uint32_t next_block_buf_pos = (uint32_t)(((int32_t)buffer[end_marker_buf_pos + 1])/4);
            if (!first_block_found(bs)) {
                bs->window_rel_first_block_word_offset = (int32_t)bs->window_rel_buf_start_word_offset;
            } else if (!next_block_buf_pos) {
                unsupported_block_error(16, "non-first block loops to itself");
            }

            // offset is in bytes from start of our buffer (which happens to be at buf pos 0 (the block is at the start of the buffer)
            next_block_printf("next block buf_offset %08x = %08x\n", (uint)next_block_buf_pos, debug_real_addr(bs, next_block_buf_pos));
            if (next_block_buf_pos < bs->buf_word_count) {
                next_block_printf("  ... which is in the buffer\n");
                // if it is in the current buffer, then it can't be a link to before the first block
                bs->buf_word_pos = to_block_word_index_t(next_block_buf_pos);
            } else {
                next_block_printf("  ... which is not in the buffer, so setting up for new read\n");
                bs->window_rel_next_read_word_offset += (next_block_buf_pos - bs->buf_word_count);
                if (bs->window_rel_next_read_word_offset < (uint32_t)bs->window_rel_first_block_word_offset) {
                    unsupported_block_error(32, "the block link goes to lower address than first block");
                }
                bs->buf_word_pos = bs->buf_word_count; // need whole new buffer
            }
            // size of block (well the bit that matters)
            return (int)end_marker_buf_pos;
        }
        if (first_block_found(bs)) {
            unsupported_block_error(64, "(non first) block was not valid, done");
        }
        bs->buf_word_pos++;
        next_block_printf("block was not valid, continue searching from buffer offset %08x = %08x\n", (uint) bs->buf_word_pos * 4, debug_real_addr(bs, bs->buf_word_pos));
    } while (true);
}

static __force_inline uint32_t inline_arm8_highest_bit(uint32_t v) {
    rcp_asm("clz %0, %0\n"
            "rsb %0, #32\n"
            : "+r" (v));
    return v;
}

static inline hx_xbool s_varm_crit_is_signing_key_match(const sb_sw_public_t *public_key) {
    sb_sha256_state_t sha;
    // Check signature key against expected key fingerprint in OTP
    sb_sha256_init(&sha);
    sb_sha256_update_32(&sha, public_key->words, sizeof(public_key->words));
    sb_single_t digest_buffer;
    sb_sha256_finish(&sha, digest_buffer.bytes);
//    printf("checkmatch sigkey: ");
//    print_bytes(public_key->bytes, sizeof(public_key->bytes));
//    printf("sigkey hash:       ");
//    print_bytes(digest_buffer->bytes, sizeof(digest_buffer->bytes));
//    printf("otphash:           ");
    uint match;
    static_assert(OTP_DATA_BOOTKEY1_0_ROW == OTP_DATA_BOOTKEY0_0_ROW + 16, "");
    static_assert(OTP_DATA_BOOTKEY2_0_ROW == OTP_DATA_BOOTKEY0_0_ROW + 32, "");
    static_assert(OTP_DATA_BOOTKEY3_0_ROW == OTP_DATA_BOOTKEY0_0_ROW + 48, "");
    hx_xbool image_key_matches_otp_key;
    uint32_t flags_a = s_varm_step_safe_otp_read_rbit3_guarded(OTP_DATA_BOOT_FLAGS1_ROW);
    uint32_t flags_b = s_varm_step_safe_otp_read_rbit3_guarded(OTP_DATA_BOOT_FLAGS1_ROW);
    static_assert(OTP_DATA_BOOT_FLAGS1_KEY_INVALID_LSB == OTP_DATA_BOOT_FLAGS1_KEY_VALID_LSB + 8, "");
    uint32_t valid_a = flags_a & ~(flags_a >> 8);
    uint32_t valid_b = flags_b & ~(flags_b >> 8);
    for(uint k=0;k<4;k++) {
        uint i = 0;
        match = 0;
        hx_assert_equal2i(valid_a, valid_b);
        if (valid_a & 1) {
            printf("KEY %d is marked valid (and not invalid)\n", k);
            for (; i < SB_SHA256_SIZE; i += 2) {
                uint32_t otp_key_hword = inline_s_otp_read_ecc_guarded(OTP_DATA_BOOTKEY0_0_ROW + k * 16 + i / 2);
                //        printf("%04x", __builtin_bswap16(otp_key_hword));
                // Actual bitwise & -- we want to branchlessly accumulate failures
                match += (digest_buffer.bytes[i] == (uint8_t) otp_key_hword) &
                         (digest_buffer.bytes[i + 1] == (otp_key_hword >> 8));
                __dataflow_barrier(match);
                __dataflow_barrier(i);
            }
            hx_assert_equal2i(i, SB_SHA256_SIZE);
            // double check not disabled
            hx_assert_equal2i(0, flags_a & (1u << (k + 8)));
            image_key_matches_otp_key = make_hx_xbool(match == SB_SHA256_SIZE / 2, hx_bit_pattern_xor_key_match());
            if (hx_is_xtrue(image_key_matches_otp_key)) goto done;
        }
        valid_a >>= 1;
        valid_b >>= 1;
    }
    return hx_key_match_false();
    done:
    __dataflow_barrier(image_key_matches_otp_key);
    __dataflow_barrier(match);
    hx_assert_equal2i(match,  SB_SHA256_SIZE/2);
    return image_key_matches_otp_key;
}


/**
 * The idea here is to extract as much information as possible, and fill in defaults...
 * @param block_offset the offest of the the block_data pointer block within the partition
 * @param block_data pointer to the block data in memory
 * @param block_size_words size in word of the block
 * @param image_def the output
 * @return
 */
// __noinline to prevent partial inlining

#define init_image_def_printf(...) ((void)0)
//#define init_image_def_printf printf

// back of envelope block sizes

//  1 : IMAGE_DEF
//  2 : HASH_DEF
// 34 : SIG
//  2 : VTABLE
//  3 : ENTRY
//  2 : ROLL
//  2 : ORIGIN
//  1 + 3n : LOAD_MAP
//  6 : HASH_VALUE
//  ? : version
// = 53 + LME * 3 - so maxed out with BS 0x180 gives us 14 load map entries which seems plenty .. well minues a couple for the version
// (note having a hash_value and sig would also be a bit weird)
//
//  2-3 : PARTITION_TABLE
//  2 : HASH_DEF
// 34 : SIG
//  2 : ORIGIN
//  6 : HASH_VALUE
//  ? : version
// = 50ish at 0x200, that leave 110 words for 16 partitions... = 6.875 per... minimum is 2 per (flags * 2)... if you add 64 bit ids, thats
// think another way; lets say you wanted 6 minimum per, that is 50 + 6 * 16
#undef unsupported_block_printf
#if MINI_PRINTF
#define unsupported_block_printf(s, ...) ({ printf("unsupported %s found at %08x, marking as unverified : ", parsed_block_size_words == PARSED_IMAGE_DEF_WORD_SIZE ? "IMAGE_DEF" : "PARTITION_TABLE", \
            bs->ctx->current_search_window.base + parsed_block->window_rel_block_offset); printf(s, ## __VA_ARGS__); printf("\n"); })
#else
#define unsupported_block_printf(s, ...) ((void)0)
#endif
#define unsupported_block_if(b, s, ...) ({ if (b) { unsupported_block_printf(s, ## __VA_ARGS__); goto bad_item; }})

bool s_varm_crit_parse_block(block_scan_t *bs, uint32_t block_size_words, parsed_block_t *parsed_block,
                                uint32_t parsed_block_size_words, uint32_t max_block_size_words) {
    canary_entry(S_VARM_CRIT_PARSE_BLOCK);
//    printf("parseb SP=%08x\n", get_sp());
    s_varm_step_safe_crit_mem_erase_by_words((uintptr_t) parsed_block, parsed_block_size_words * 4);
#if !BOOTROM_HARDENING
    parsed_block->verified = hx_bool_null(); // 0 is the NULL value for hardening, but it is something else for no HARDENING (since 0 == false)
#endif

    if (block_size_words < 2 || block_size_words > max_block_size_words) {
        if (block_size_words) init_image_def_printf("Invalid block size words: %d\n", (int) block_size_words);
        // block is actually unparse-able for us
        goto parse_block_done_error;
        // for a bad item, we mark it as unverified (so it won't be used), but return a block still
        // so the caller can note the presence of a block (even if we didn't understand it or want it)
        //
        // e.g. a RP2040 IMAGE_DEF's presence is still interesting to note (e.g. along-side a partition table)
        // even if it can't be used. we will always prefer other blocks to blocks which are unverified during scan
        bad_item:
#if !BOOTROM_ASSERT_DISABLED
        parsed_block->parser_rejected = true;
#endif
        parsed_block->verified = hx_false();
        goto accept_block;
    }

    // block is at start of our buffer
    uint32_t *block_data = bs->ctx->scan_workarea->block_buffer_or_signature_workspace.block_buffer;
    hx_xbool sig_otp_key_match; // note we keep a local copy so it isn't set in the block until we check that the whole block is signed
    sig_otp_key_match = parsed_block->sig_otp_key_match_and_block_hashed = hx_key_match_false();
#if FEATURE_EXEC2
    parsed_block->salt_included = hx_false();
#endif
    parsed_block->signature_verified = hx_sig_verified_false();
    parsed_block->enclosing_window = bs->ctx->current_search_window;
    parsed_block->window_rel_block_offset = bs->window_rel_buf_start_word_offset * 4;
    parsed_block->block_size_words = to_block_word_index_t(block_size_words);
    parsed_block->rollback_version = make_hx_uint32(0);
    uint32_t word_index;
    if (parsed_block_size_words == PARSED_IMAGE_DEF_WORD_SIZE) {
        // should really just check for IMAGE_DEF (and handle wrong size spearately), but this saves code space
        if ((0x100 | PICOBIN_BLOCK_ITEM_1BS_IMAGE_TYPE) != (uint16_t) block_data[1]) {
            goto parse_block_done_error;
        }
        uint32_t image_type_flags = (uint16_t) (block_data[1] >> 16u);
        ((parsed_image_def_t *)parsed_block)->image_type_flags = (uint16_t)image_type_flags;
        if ((image_type_flags & PICOBIN_IMAGE_TYPE_IMAGE_TYPE_BITS) == PICOBIN_IMAGE_TYPE_IMAGE_TYPE_AS_BITS(EXE)) {
            // clear tbyb flag so we don't break sig check
            block_data[1] &= ~(PICOBIN_IMAGE_TYPE_EXE_TBYB_BITS << 16);
            parsed_block->tbyb_flagged = image_type_flags & PICOBIN_IMAGE_TYPE_EXE_TBYB_BITS;
            unsupported_block_if((image_type_flags & PICOBIN_IMAGE_TYPE_EXE_CHIP_BITS) != PICOBIN_IMAGE_TYPE_EXE_CHIP_AS_BITS(RP2350),
                                 "executable image_def is not for RP2350");
        }
        word_index = 2;
    } else if (parsed_block_size_words == PARSED_PARTITION_TABLE_WORD_SIZE) {
        if (PICOBIN_BLOCK_ITEM_PARTITION_TABLE != (uint8_t) (block_data[1] & 0X7f))  {
            goto parse_block_done_error;
        }
        uint8_t singleton_and_partition_count = (uint8_t) (block_data[1] >> 24u);
        if (singleton_and_partition_count & 0x80) {
            ((parsed_partition_table_t *)parsed_block)->singleton = true;
            singleton_and_partition_count &= 0x7f;
        }
        uint16_t size = inline_decode_item_size(block_data[1]);
        unsupported_block_if(size < 2 || singleton_and_partition_count > PARTITION_TABLE_MAX_PARTITIONS, "expected PARTITION_TABLE of size at least 2, and max %d partitions", PARTITION_TABLE_MAX_PARTITIONS);
        ((parsed_partition_table_t *)parsed_block)->partition_count = singleton_and_partition_count;
        // skip all contents for now
        word_index = size + 1;
    } else {
        rcp_panic();
    }
    uint sig_needed_word_index = 0; // number of words in the block that need to be in the signature
    const uint32_t *block_data_word_index_plus_1 = __get_opaque_ptr(block_data) + word_index + 1;
    for(; word_index < block_size_words; ) {
        uint32_t header = block_data[word_index++];
        hx_assert_equal2i((uintptr_t)&block_data[word_index], (uintptr_t)block_data_word_index_plus_1);
        uint32_t size = inline_decode_item_size(header);
        if (!size || (header & 0x7f) == 0x7f) {
            break;
        }
        uint32_t item_type = header & 0x7f;
        if (item_type == PICOBIN_BLOCK_ITEM_1BS_HASH_DEF) {
            unsupported_block_if(size != 2, "HASH_DEF item has wrong size");
            // ignore HASH_DEF with unsupported hash type
            if ((uint8_t)(header >> 24u) == PICOBIN_HASH_SHA256) {
                parsed_block->hash_type = (uint8_t) (header >> 24u);
                parsed_block->hash_def_block_words_included = to_block_word_index_t(__get_opaque_value(block_data[word_index]));
            }
        } else if (item_type == PICOBIN_BLOCK_ITEM_HASH_VALUE) {
            unsupported_block_if(size < 2 || size > 9, "HASH_VALUE has wrong size");
            parsed_block->hash_value_word_index = to_block_word_index_t(word_index);
            parsed_block->hash_value_word_count = (uint8_t)(size-1);
            goto skip_sig_needed;
        } else if (item_type == PICOBIN_BLOCK_ITEM_SIGNATURE) {
            unsupported_block_if(size != 33, "ITEM_SIGNATURE item has wrong size");
            uint8_t sig_type = (uint8_t)(header >> 24u);
            if (sig_type == PICOBIN_SIGNATURE_SECP256K1) {
                parsed_block->public_key_word_index = to_block_word_index_t(word_index);
//                            image_def->public_key_word_size = 16;
                parsed_block->signature_word_index = to_block_word_index_t(word_index + 16);
//                            image_def->signature_word_size = 16;
#if MINI_PRINTF
                parsed_block->sig_type = sig_type;
#endif
                sig_otp_key_match = s_varm_crit_is_signing_key_match(
                        (sb_sw_public_t *) (block_data + parsed_block->public_key_word_index));
            }
            goto skip_sig_needed;
        } else if (item_type == PICOBIN_BLOCK_ITEM_1BS_VERSION) {
            int otp_row_count = (uint8_t)(header >> 24u);
            unsupported_block_if((int)size != 2 + ((otp_row_count != 0) + otp_row_count + 1) / 2,
                                 "VERSION_ITEM size %d doesn't match expected: 2 + (otp_row_count?(%d) + otp_row_count(%d) + 1) / 2\n", size, otp_row_count!=0, otp_row_count);
            parsed_block->major_minor_version = block_data[word_index];
            // Rollback is only of interest in secure mode (and currently only applies to IMAGE_DEF
            if (otp_row_count) {
                unsupported_block_if(parsed_block_size_words != PARSED_IMAGE_DEF_WORD_SIZE, "Rollback version is only supported on IMAGE_DEF");
                const uint16_t *extra = (const uint16_t*)(block_data + word_index + 1);
                hx_uint32_t rollback_version = make_hx_uint32_2(*extra++, *(const uint16_t *)(block_data_word_index_plus_1+1));
                printf("image_def rollback version is %d\n", hx_value(rollback_version));
                // save the address so we can update it later
                unsupported_block_if(hx_signed_is_greater_equali(rollback_version, otp_row_count * 24),
                                     "rollback version %d is too big for OTP row definition (%d rows = max %d)\n", hx_value(rollback_version), otp_row_count, otp_row_count * 24 - 1);
                if (hx_is_xtrue(bootram->always.secure)) {
                    uint32_t loops = __get_opaque_value(0u);
                    int otp_row_index = otp_row_count;
                    hx_uint32_t otp_rollback_version = make_hx_uint32(0);
                    do {
                        otp_row_index--;
                        loops++;
                        printf("CHECKING OTP ROW %04x\n", extra[otp_row_index]);
                        uint32_t row_a = extra[otp_row_index];
                        uint32_t row_b = ((const uint16_t *)block_data_word_index_plus_1)[otp_row_index+3];
                        // check we can read row_a & row_a + 2 (if we can, we can read row_a + 1) ... note that
                        // s_varm_step_safe_otp_read_rbit3_guarded will fault if unreadable
                        io_ro_32 *otp_check = otp_data_raw + row_a;
                        unsupported_block_if((int32_t)(otp_check[0]|otp_check[2]) < 0, "couldn't read OTP version row %d\n",
                                             extra[otp_row_index]);
                        hx_assert_equal2i(row_a, row_b);
                        uint32_t bits_a = s_varm_step_safe_otp_read_rbit3_guarded(row_a);
                        uint32_t bits_b = s_varm_step_safe_otp_read_rbit3_guarded(row_b);
                        printf("  value = %08x\n", bits_a);
                        hx_assert_equal2i(bits_a, bits_b);
                        int ri24 = otp_row_index * 24;
                        if (bits_a) {
                            if (!hx_value(otp_rollback_version)) {
                                // we are still looking for the otp_rollback_version
                                otp_rollback_version = make_hx_uint32_2(
                                        inline_arm8_highest_bit(bits_a) + (uint) ri24,
                                        inline_arm8_highest_bit(bits_b) + (uint) ri24
                                );
                                printf("  determined that OTP rollback version is %d\n",
                                        hx_value(otp_rollback_version));
                            } else {
                                hx_check_uint32(otp_rollback_version);
                                hx_assert_equal2i((bool) hx_value_other(otp_rollback_version), 1);
                            }
                        } else {
                            hx_assert_equal2i(bits_b, 0);
                        }
                        if (ri24 + 24 < (int)hx_value(rollback_version)) {
                            if (((int32_t)(bits_a<<8) >= 0)) {
                                // top bit not set, so will we mark it for setting, and force a reboot (so we can check again)
                                printf("  OTP update row is now 0x%04x bit %d because row does not have top bit set\n", row_a, 23);
                                ((parsed_image_def_t *) parsed_block)->rollback_version_otp_info.row = (uint16_t)row_a;
                                ((parsed_image_def_t *) parsed_block)->rollback_version_otp_info.bit = 23;
                                ((parsed_image_def_t *) parsed_block)->rollback_version_otp_info.reboot = 1;
                            }
                        }
                    } while (otp_row_index);
                    hx_check_uint32(otp_rollback_version);
                    hx_bool bad_version = hx_b_from_unsigned_is_less(rollback_version, otp_rollback_version);
                    unsupported_block_if(hx_is_true(bad_version),
                                         "rollback version %d is lower than otp rollback version %d, so invalid block",
                                         hx_value(rollback_version), hx_value(otp_rollback_version));
                    bootrom_assert(MISC, parsed_block_size_words == PARSED_IMAGE_DEF_WORD_SIZE);
                    uint32_t rv = hx_value(rollback_version);
                    if (!((parsed_image_def_t *) parsed_block)->rollback_version_otp_info.row && rv > hx_value(otp_rollback_version)) {
                        bootrom_assert(MISC, (int32_t)rv > 0); // unsigned compare above should make this so!
                        // bit to set
                        int bit = (int32_t)rv - 1;
                        printf("  OTP update row is now 0x%04x bit %d to make new version %d \n",
                               extra[bit / 24], bit % 24, rv);
                        ((parsed_image_def_t *) parsed_block)->rollback_version_otp_info.row = extra[bit / 24];
                        ((parsed_image_def_t *) parsed_block)->rollback_version_otp_info.hbit = (uint8_t) (
                                bit % 24);
                    }
                    hx_assert_false(bad_version);
                    // if rv was 24, then we would need two rows
                    hx_assert_equal2i((__get_opaque_value(header)>>24u) * 24u <= __get_opaque_value(hx_value(rollback_version)), 0);
                    parsed_block->rollback_version = rollback_version;
                    hx_assert_equal2i(hx_value(parsed_block->rollback_version), extra[-1]);
                    hx_assert_equal2i(loops, block_data[word_index-1] >> 24);
                } else {
                    hx_assert_xfalse(bootram->always.secure, hx_bit_pattern_xor_secure());
                }
                hx_check_uint32(parsed_block->rollback_version);
                parsed_block->rollback_version = rollback_version;
            }
#if FEATURE_EXEC2
        } else if (item_type == PICOBIN_BLOCK_ITEM_SALT) {
            unsupported_block_if(size != 7, "SALT has wrong size");
            // we overwrite the in memory data with the real values, thus if they were wrong in the block, hash/sig check will fail laterx
            *(uint32_sext_t *)(block_data + word_index) = bootram->always.six_words;
            parsed_block->salt_included = hx_true();
#endif
        } else if (parsed_block_size_words == PARSED_IMAGE_DEF_WORD_SIZE) {
            parsed_image_def_t *parsed_image_def = (parsed_image_def_t *)parsed_block;
            if (item_type == PICOBIN_BLOCK_ITEM_1BS_VECTOR_TABLE) {
                unsupported_block_if(size != 2, "VECTOR_TABLE item has wrong size");
                parsed_image_def->rolled_vector_table_addr = block_data[word_index];
            } else if (item_type == PICOBIN_BLOCK_ITEM_1BS_ENTRY_POINT) {
                unsupported_block_if(size != 3 && size != 4, "ENTRY_POINT item has wrong size");
                parsed_image_def->rolled_entry_point_addr = block_data[word_index];
                parsed_image_def->initial_sp = block_data[word_index + 1];
                parsed_image_def->initial_sp_limit = size == 4 ? block_data[word_index + 2] : 0;
            } else if (item_type == PICOBIN_BLOCK_ITEM_1BS_ROLLING_WINDOW_DELTA) {
                unsupported_block_if(size != 2, "ROLLING_WINDOW_DELTA item has wrong size");
                parsed_image_def->rolling_window_delta = block_data[word_index];
            } else if (item_type == PICOBIN_BLOCK_ITEM_LOAD_MAP) {
                unsupported_block_if(size != 1 + ((header << 1) >> 25) * 3, "LOAD_MAP item has wrong size");
                parsed_block->load_map_word_index = to_block_word_index_t(word_index - 1);
            }
        }
        sig_needed_word_index = word_index + (uint)(size - 1);
        skip_sig_needed:
        block_data_word_index_plus_1 += (uint16_t)size;
        word_index += (uint16_t)(size -1);
    }
    uint32_t _block_size_words = __clone_value(block_size_words);
    unsupported_block_if(word_index != block_size_words, "block size mismatch");
    hx_assert_equal2i(word_index, _block_size_words);
    unsupported_block_if(parsed_block_size_words == PARSED_IMAGE_DEF_WORD_SIZE && !hx_value(parsed_block->rollback_version) && hx_is_xtrue(bs->ctx->rollback_version_required), "no rollback version, but OTP says rollback version required");
    if (hx_is_xtrue(sig_otp_key_match)) {
        hx_set_step_nodelay(STEPTAG_S_VARM_CRIT_PARSE_BLOCK1);
        unsupported_block_if(parsed_block->hash_def_block_words_included < sig_needed_word_index, "not everything is signed");
        if (parsed_block_size_words == PARSED_IMAGE_DEF_WORD_SIZE) {
            hx_bool has_rollback_version = hx_uint32_to_bool_checked(parsed_block->rollback_version);
            hx_bool not_rollback_version_required = hx_notx(bs->ctx->rollback_version_required, boot_flag_selector(OTP_DATA_BOOT_FLAGS0_ROLLBACK_REQUIRED_LSB));
            hx_assert_or(has_rollback_version, not_rollback_version_required);
        } else {
            hx_assert_equal2i(parsed_block_size_words, PARSED_PARTITION_TABLE_WORD_SIZE);
        }
        parsed_block->sig_otp_key_match_and_block_hashed = sig_otp_key_match;
        hx_check_step_nodelay(STEPTAG_S_VARM_CRIT_PARSE_BLOCK1);
    }

    printf("Valid ");
    printf(parsed_block_size_words == PARSED_IMAGE_DEF_WORD_SIZE ? "IMAGE_DEF" : "PARTITION_TABLE");
    printf(" found at %08x\n", parsed_block->enclosing_window.base + parsed_block->window_rel_block_offset);
    hx_assert_null(parsed_block->verified);
accept_block:
    parsed_block->block_data = block_data;
    hx_assert_xfalse(parsed_block->signature_verified, hx_bit_pattern_xor_sig_verified());
    bool rc = true;
    goto parse_block_done;
    parse_block_done_error:
    rc = false;
    parse_block_done:
    canary_exit_return(S_VARM_CRIT_PARSE_BLOCK, rc);
}

static __force_inline bool inline_s_is_xip(uint32_t addr) {
    // Two 24-bit chip select windows.
    return (addr >> (24 + 1)) == (XIP_BASE >> 25);
}

static inline bool inline_s_is_valid_runtime_or_storage_address(uint32_t addr) {
    return varm_is_sram_or_xip_ram(addr) || inline_s_is_xip(addr);
}

// If this is an image_def it will load the load map
hx_bool s_varm_crit_ram_trash_verify_block(boot_scan_context_t *ctx, hx_bool sig_required, hx_bool hash_required,
                                           parsed_block_t *parsed_block, parsed_block_t *cosign_contents_block) {
    hx_bool cosign_covered = hx_false();
    // 1. the first time through a block should have a verified value of 0 which is invalid.
    // 2. if the block isn't populated then noone should check the verified value, so leaving it invalid is fine
    // 3. we only want to verify once
    hx_check_bools(sig_required, hash_required);
    if (is_block_populated(parsed_block) && hx_is_null(parsed_block->verified)) {
        printf("verify block @%p, sig_req=%d hash_req=%d\n", parsed_block->enclosing_window.base + parsed_block->window_rel_block_offset,
               hx_is_true(sig_required), hx_is_true(hash_required));
        // 4. all code paths here should set verifed to a valid value, so we don't need to pre-init
        const uint32_t *block_data = parsed_block->block_data;
        sb_sha256_state_t sha;
        bool do_hash = parsed_block->hash_value_word_index || hx_is_true(sig_required) || hx_is_true(hash_required);
        if (do_hash) {
            if (!parsed_block->hash_type) {
                printf("Block needs hashing, but no hash type\n");
                goto verify_fail;
            }
        }
        // we will calculate at least an empty SHA256 if not hashing
        sb_sha256_init(&sha);
        // load_map may load into XIP cache, so now is the time to flush the cache (as late as
        // possible without reverting any cache pinning performed by load_map) -- also it's
        // important this is done for every IMAGE_DEF, to avoid garbage from previous attempt.
        // Need write access for maintenance operations:
        inline_s_set_flash_rw_xn(ctx->mpu_on_arm);
        hx_check_bool(ctx->booting);
        if (hx_is_true(ctx->booting)) {
            printf("Flushing XIP cache\n");
            s_varm_api_crit_flash_flush_cache();
        } else {
            hx_assert_false(ctx->booting);
        }
        // note only IMAGEs have load maps
        if (parsed_block->load_map_word_index) {
            // need RAM access for load map
            inline_s_set_ram_rw_xn(ctx->mpu_on_arm);
            const picobin_load_map *load_map = (const picobin_load_map *)(block_data + parsed_block->load_map_word_index);
            for(uint i=0;i<picobin_load_map_entry_count(load_map);i++) {
                const picobin_load_map_entry *entry = load_map->entries + i;
                uint32_t map_vma = entry->runtime_address;
                uint32_t map_storage_address_value = entry->storage_address_rel;
                uint32_t map_size_value = entry->size;

                // this is the runtime address, but un-rolled and offset by enclosing_window in the flash case;
                // i.e. for a runtime_address in the load map of 0x10000010, but in a partition starting at 0x10040000,
                // the value will be 0x10040010
                uint32_t to_storage_addr = map_vma;
                // we are looking for flash targets, however exotic binaries may have a runtime physical address that starts outside
                // the flash range, and then rolls into it, so we check for (not) RAM/XIP RAM here.
                uint32_t lma_to_storage = parsed_block->enclosing_window.base + parsed_block->slot_roll - XIP_BASE + ((const parsed_image_def_t *)parsed_block)->rolling_window_delta;
                // we don't want to roll anything in the second XIP cs; and nor do we want to roll RAM or XIP RAM.
                // note: the VMA may be < XIP_BASE in the case of a positive roll (there is data that gets clipped from the beginning of the window)
                // however there should not be vmas above the 1K region (note a roll across two chip selects does not make any sense)

                if (map_vma < XIP_BASE + 16*1024*1024) {
                    // note we assume this is an image_def (this code path is not taken for partition tables)
                    to_storage_addr += lma_to_storage;
                } else {
                    // xip/sram/cs1 targets are unrolled
                }

                uint32_t size = map_size_value;
                if (!picobin_load_map_is_relative(load_map)) {
                    size -= map_vma;
                }
                uint32_t to_storage_addr_end = to_storage_addr + size;

                bool valid_to_address_span =
                        !(to_storage_addr & 3u) &&
                        inline_s_is_valid_runtime_or_storage_address(to_storage_addr) &&
                        inline_s_is_valid_runtime_or_storage_address(to_storage_addr_end - !!size) &&
                        // check to_storage_addr_end >= store_addr, but also that they are not
                        // more than 0x08000000 apart (so don't cross regions)
                        !((to_storage_addr_end - to_storage_addr) >> 27u);

                // use opaque value here so compiler can't figure out it is 1 below
                if (!__get_opaque_value(valid_to_address_span)) {
                    printf("LOAD MAP ENTRY has invalid runtime_address range %08x->%08x\n", to_storage_addr, to_storage_addr + size);
                    goto verify_fail;
                }

                // note: only need to do this for RAM (which is why i moved it into the loop) - we probably are fine
                //       with it outside the loop, and non RAM specific (thus causing a load_image_counter mismatch
                //       when it wasn't strictly necessary - i.e. nothing loading into RAM - if they only
                //       time this happens is in TBYB
                // we are loading a load map, so make sure we know any previously verified image's in memory representation is bad.
                ctx->load_image_counter++;

                // This pins the entire cache starting at XIP_SRAM_BASE, and is idempotent.
                if (hx_is_true(ctx->booting)) {
                    if (inline_s_is_xip_ram(to_storage_addr)) {
                        printf("  XIP_RAM == true, so pinning XIP RAM\n");
                        s_varm_crit_pin_xip_ram();
                    }
                }

                hx_assert_equal2i(valid_to_address_span, 1);
                uint32_t from_storage_addr;
                if (!map_storage_address_value) {
                    // 0 in the storage_address means zero it
                    size = (size + 3u) & ~3u;
                    if (hx_is_true(ctx->booting)) {
                        printf("  LOADER zero %08x + %08x ", (uint) to_storage_addr, (uint) size);
                        to_storage_addr = (uintptr_t)resolve_ram_or_absolute_flash_addr(to_storage_addr);
                        printf("  i.e. %08x + %08x\n", (uint) to_storage_addr, (uint) size);
                        size = s_varm_step_safe_crit_mem_erase_by_words(to_storage_addr, size);
                    } else {
                        hx_assert_false(ctx->booting);
                    }
                    s_varm_sha256_put_word_inc(size, &sha);
                    continue;
                } else {
                    from_storage_addr = map_storage_address_value;
                    if (!picobin_load_map_is_relative(load_map)) {
                        // address is LMA; we need to offset by window base (i.e. partition base)
                        // note; once again we check for !RAM/XIP RAM because the from address may roll from outside XIP into it
                        if (!varm_is_sram_or_xip_ram(from_storage_addr)) {
                            from_storage_addr += lma_to_storage;
                        }
                    } else {
                        from_storage_addr = map_storage_address_value + parsed_block->enclosing_window.base +
                                            parsed_block->window_rel_block_offset +
                                            parsed_block->load_map_word_index * 4;
                    }

                    uint32_t window_end = parsed_block->enclosing_window.base + parsed_block->enclosing_window.size;
                    if ((from_storage_addr & 3) ||
                        from_storage_addr < parsed_block->enclosing_window.base ||
                        from_storage_addr + size >= window_end ||
                        from_storage_addr + size < from_storage_addr) {
                        printf("LOAD MAP ENTRY has invalid (or out of window) storage_address range %08x->%08x\n", from_storage_addr, from_storage_addr + size);
                        goto verify_fail;
                    }
                }
                if (hx_is_false(ctx->booting)) {
                    // we don't load image when not booting, and just verify it in place
                    to_storage_addr = from_storage_addr;
                    hx_assert_false(ctx->booting);
                } else if (to_storage_addr != from_storage_addr) {
                    *ctx->diagnostic = BOOT_DIAGNOSTIC_LOAD_MAP_ENTRIES_LOADED;
                    printf("  LOADER copy %08x + %08x -> %08x\n", (uint) from_storage_addr, (uint) size,
                           (uint) to_storage_addr);
                    hx_assert_equal2i(to_storage_addr >> 30, 0);
                    s_varm_crit_mem_copy_by_words((uint32_t *) to_storage_addr,
                                                  resolve_ram_or_absolute_flash_addr(from_storage_addr), (size + 3u)&~3u);
                }
                if (do_hash) {
                    if (cosign_contents_block) {
                        // note: not too worried about hardening this, as if you can subvert it you just get to say the partition table is signed
                        // when it isn't, you still won't be able to boot an unsigned/bad-rollback-version image (though you might be able to boot the wrong one
                        // if you pass those constraints)
                        uint32_t cosign_storage_address = parsed_block->enclosing_window.base + cosign_contents_block->window_rel_block_offset;
                        uint32_t cosign_size = cosign_contents_block->block_size_words * 4;
                        if (cosign_storage_address >= from_storage_addr && cosign_storage_address + cosign_size <= from_storage_addr + size) {
                            cosign_covered = hx_true();
                        }
                    }
                    uint32_t *src = resolve_ram_or_absolute_flash_addr(to_storage_addr);
                    printf("  hash %08x + %08x (orig %08x + %08x)\n", (uint)src, size, (uint) from_storage_addr, (uint) size);
                    sb_sha256_update_32(&sha, src, size&~3u);
                    // pad with zero bytes because we can't mix 32 byte and 8 byte writes in the same block
                    if (size & 3) {
                        uint32_t last_word = src[size/4];
                        last_word &= (1u << (size * 8u)) - 1;
                        s_varm_sha256_put_word_inc(last_word, &sha);
                    }
                }
            }
        }

        signature_workspace_t *signature_workspace = &ctx->scan_workarea->block_buffer_or_signature_workspace.signature_workspace;
        inline_s_set_ram_ro_xn(ctx->mpu_on_arm);
        uint32_t hash_count1 = sha.total_bytes;
        if (do_hash) {
            printf("  hash block offsets %08x -> %08x\n", 0, parsed_block->hash_def_block_words_included * 4);
            sb_sha256_update_32(&sha, block_data, parsed_block->hash_def_block_words_included * 4);
            sb_sha256_finish(&sha, signature_workspace->hash.bytes);
        }
        uint32_t hash_count2 = sha.total_bytes;
        if (do_hash) {
            printf("resulting hash: ");
            print_bytes(signature_workspace->hash.bytes, count_of(signature_workspace->hash.bytes));
        }
        if (hx_is_true(sig_required)) {
#if FEATURE_EXEC2
            if (hx_is_true(parsed_block->sig_otp_key_match_and_block_hashed) &&
                hx_is_false(hx_and_not(inline_s_require_salt_if_secure(ctx), parsed_block->salt_included))) {
#else
            if (hx_is_xtrue(parsed_block->sig_otp_key_match_and_block_hashed)) {
#endif
                hx_bool hashed_some = make_hx_bool(parsed_block->hash_def_block_words_included != 0);
                hx_assert_true(hashed_some);
                hx_assert_equal2i(hash_count2-hash_count1, parsed_block->hash_def_block_words_included * 4);
                parsed_block->verify_diagnostic = BOOT_PARSED_BLOCK_DIAGNOSTIC_MATCHING_KEY_FOR_VERIFY | BOOT_PARSED_BLOCK_DIAGNOSTIC_HASH_FOR_VERIFY;
                hx_xbool sig_matches_image_keyx;
                *(volatile hx_xbool *)&sig_matches_image_keyx = hx_xbool_invalid();
#if !NO_SWEETB
                // This code should be unreachable on RISC-V when secure boot is enabled
                // (commented this out as hx_assert_equal2i is a no-op on RISC-V)
                //hx_assert_equal2i(ctx->boot_cpu, PICOBIN_IMAGE_TYPE_EXE_CPU_ARM);


                // Increase ROSC speed if clock state looks untouched, because the elliptic curve
                // code is quite lengthy. Note non-short-circuiting OR is used to avoid unnecessary
                // branches over volatile loads

                hx_bool disable_clock_config = hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_FAST_SIGCHECK_ROSC_DIV_LSB);
#if !ASM_SIZE_HACKS || !BOOTROM_HARDENING
                bool dirty_clock_cfg =
                        hx_is_true(disable_clock_config) |
                        (rosc_hw->div != (ROSC_DIV_VALUE_PASS | 0x8)) |
                        (rosc_hw->ctrl != (ROSC_CTRL_RESET | (ROSC_CTRL_ENABLE_VALUE_ENABLE << ROSC_CTRL_ENABLE_LSB))) |
                        (clocks_hw->clk[clk_ref].ctrl != CLOCKS_CLK_REF_CTRL_RESET) |
                        (clocks_hw->clk[clk_ref].div  != CLOCKS_CLK_REF_DIV_RESET ) |
                        (clocks_hw->clk[clk_sys].ctrl != CLOCKS_CLK_SYS_CTRL_RESET) |
                        (clocks_hw->clk[clk_sys].div  != CLOCKS_CLK_SYS_DIV_RESET );
                bool not_dirty_clock_cfg = !dirty_clock_cfg;
                if (not_dirty_clock_cfg) {
                    // Initial ROSC divisor is 8, so set divisor to 2 for expected f(clk_sys) ~48
                    // MHz. Need to unhook clk_sys from clk_ref, and increase clk_ref div so that it
                    // has the same expected frequency as with the reset clock configuration.
                    clocks_hw->clk[clk_ref].div = 4 << CLOCKS_CLK_REF_DIV_INT_LSB;
                    (void)clocks_hw->clk[clk_ref].div;
                    clocks_hw->clk[clk_sys].ctrl =
                            CLOCKS_CLK_SYS_CTRL_AUXSRC_VALUE_ROSC_CLKSRC << CLOCKS_CLK_SYS_CTRL_AUXSRC_LSB;
                    (void)clocks_hw->clk[clk_sys].ctrl;
                    rosc_hw->div = ROSC_DIV_VALUE_PASS | 0x2;
                    hw_set_bits(&clocks_hw->clk[clk_sys].ctrl, CLOCKS_CLK_SYS_CTRL_SRC_BITS);
                }
#else
                static_assert(&clocks_hw->clk[clk_ref].div == &clocks_hw->clk[clk_ref].ctrl + 1, "");
                static_assert(&clocks_hw->clk[clk_sys].ctrl == &clocks_hw->clk[clk_ref].ctrl + 3, "");
                static_assert(&clocks_hw->clk[clk_sys].div == &clocks_hw->clk[clk_ref].ctrl + 4, "");
                static_assert(CLOCKS_CLK_REF_CTRL_RESET == 0, "");
                static_assert(CLOCKS_CLK_SYS_CTRL_RESET == 0, "");
                static_assert(CLOCKS_CLK_REF_DIV_RESET == CLOCKS_CLK_SYS_DIV_RESET, "");
                static_assert(CLOCKS_CLK_REF_DIV_RESET == 0x10000, "");
                register uint32_t not_dirty_clock_cfg_out asm ("r0") = disable_clock_config.v;
                uintptr_t clocks_ptr = (uintptr_t)&clocks_hw->clk[clk_ref].ctrl;
                static_assert((4u << CLOCKS_CLK_REF_DIV_INT_LSB) == 0x40000, "");
                static_assert(REG_ALIAS_SET_BITS == 0x2000, "");
                static_assert(CLOCKS_CLK_SYS_CTRL_SRC_BITS == 1, "");
                pico_default_asm(
                        "cmp r0, #0\n"
                        "blt.n 1f\n"
                        "ldmia %[clocks_ptr]!, {r0-r4}\n"
                        "subs %[clocks_ptr], #20\n"
                        "cbnz r0, 1f\n" // clocks_hw->clk[clk_ref].ctrl != CLOCKS_CLK_REF_CTRL_RESET
                        "cbnz r3, 1f\n" // clocks_hw->clk[clk_sys].ctrl != CLOCKS_CLK_SYS_CTRL_RESET
                        "movs r2, #1\n"
                        "lsls r2, #16\n"
                        "cmp r1, r2\n"
                        "bne 1f\n"      // clocks_hw->clk[clk_ref].div  != CLOCKS_CLK_REF_DIV_RESET
                        "cmp r4, r2\n"
                        "bne 1f\n"      // clocks_hw->clk[clk_sys].div  != CLOCKS_CLK_SYS_DIV_RESET
                        "ldr r4, =%[rosc_ctrl_reset_enabled]\n"
                        "ldr r3, [%[rosc_ctrl]]\n"
                        "cmp r3, r4\n"
                        "bne 1f\n"      // rosc_hw->ctrl != (ROSC_CTRL_RESET | (ROSC_CTRL_ENABLE_VALUE_ENABLE << ROSC_CTRL_ENABLE_LSB))
                        "ldr r3, [%[rosc_ctrl], %[rosc_div_minus_rosc_ctrl]]\n"
                        "movw r4, %[rosc_div_value_pass_plus_8]\n"
                        "cmp r3, r4\n"
                        "bne 1f\n"      // rosc_hw->div != (ROSC_DIV_VALUE_PASS | 0x8)
                        "lsls r2, #2\n" // r2 = 0x40000
                        "str r2, [%[clocks_ptr], #4]\n" // clocks_hw->clk[clk_ref].div = 4 << CLOCKS_CLK_REF_DIV_INT_LSB;
                        "ldr r3, [%[clocks_ptr], #4]\n"
                        "movs r3, %[clk_sys_auxsrc_rosc]\n"
                        "str r3, [%[clocks_ptr], #12]\n" // clocks_hw->clk[clk_sys].ctrl = CLOCKS_CLK_SYS_CTRL_AUXSRC_VALUE_ROSC_CLKSRC << CLOCKS_CLK_SYS_CTRL_AUXSRC_LSB;
                        "ldr r3, [%[clocks_ptr], #12]\n"
                        "subs r4, #6\n"
                        "str r4, [%[rosc_ctrl], %[rosc_div_minus_rosc_ctrl]]\n" // rosc_hw->div = ROSC_DIV_VALUE_PASS | 0x2;
                        "movs r2, %[clk_sys_auxsrc_rosc] | %c[clk_sys_src_aux]\n"
                        "movs r0, #1\n" // set true for not_dirty_clock_cfg
                        "str r2, [%[clocks_ptr], #12]\n" // hw_set_bits(&clocks_hw->clk[clk_sys].ctrl, CLOCKS_CLK_SYS_CTRL_SRC_BITS)
                        "b 2f\n"
                    "1:\n"
                        "movs r0, #0\n"
                    "2:\n"
                        : [r0] "+&l" (not_dirty_clock_cfg_out),
                          [clocks_ptr] "+&l" (clocks_ptr)
                        : [rosc_ctrl] "l" (&rosc_hw->ctrl),
                          [rosc_div_minus_rosc_ctrl] "i" (ROSC_DIV_OFFSET - ROSC_CTRL_OFFSET),
                          [rosc_div_value_pass_plus_8] "i" (ROSC_DIV_VALUE_PASS + 8),
                          [rosc_ctrl_reset_enabled] "i" (ROSC_CTRL_RESET | (ROSC_CTRL_ENABLE_VALUE_ENABLE << ROSC_CTRL_ENABLE_LSB)),
                          [clk_sys_auxsrc_rosc] "i" (CLOCKS_CLK_SYS_CTRL_AUXSRC_VALUE_ROSC_CLKSRC << CLOCKS_CLK_SYS_CTRL_AUXSRC_LSB),
                          [clk_sys_src_aux] "i" (CLOCKS_CLK_SYS_CTRL_SRC_VALUE_CLKSRC_CLK_SYS_AUX << CLOCKS_CLK_SYS_CTRL_SRC_LSB)
                        : "r1", "r2", "r3", "r4", "cc"
                );
                bool not_dirty_clock_cfg = not_dirty_clock_cfg_out;
#endif

                // Decrypt signature hash using signature key, and check against actual observed image hash
                const sb_sw_public_t *public_key = (const sb_sw_public_t *)(block_data + parsed_block->public_key_word_index);
                const sb_sw_signature_t *signature = (const sb_sw_signature_t *)(block_data + parsed_block->signature_word_index);

                sig_matches_image_keyx = s_arm8_verify_signature_secp256k1(signature_workspace->sig_context_buffer,
                                                                          &public_key[0],
                                                                          &signature_workspace->hash,
                                                                          &signature[0]);
                printf("  sig check ok=%d %08x %08x\n", hx_is_xtrue(sig_matches_image_keyx), (int)signature->words[0], (int)signature->words[15]);

                // Restore original ROSC divider, to avoid changing flash SCK frequency
                if (not_dirty_clock_cfg) {
                    rosc_hw->div = ROSC_DIV_VALUE_PASS | 0x8;
                    (void)rosc_hw->div;
                    clocks_hw->clk[clk_ref].div = 1 << CLOCKS_CLK_REF_DIV_INT_LSB;
                }
#else
                printf("ignoring sig check as no sweetb\n");
                sig_matches_image_keyx = make_hx_xbool_xor(true, HX_XOR_SIG_VERIFIED);
#endif
                parsed_block->signature_verified = sig_matches_image_keyx;
                parsed_block->verified = hx_and_checked(hx_xbool_to_bool(sig_matches_image_keyx,
                                                                           hx_bit_pattern_xor_sig_verified()),
                                                         hx_xbool_to_bool(parsed_block->sig_otp_key_match_and_block_hashed,
                                                                           hx_bit_pattern_xor_key_match()));
            } else {
#if MINI_PRINTF
                if (!(parsed_block->sig_type && do_hash)) {
                    printf("  no hash-def/signature found; block is not verified for sig_required=true\n");
                } else if (hx_is_xfalse(parsed_block->sig_otp_key_match_and_block_hashed)) {
                    printf("  wrong signature key; block is not verified for sig_required=true\n");
                } else {
                    printf("  salt is missing when required; block is not verified for sig_required=true\n");
                }
#endif
                goto verify_fail;
            }
        } else if (do_hash) {
            if (parsed_block->hash_value_word_count < 1 || parsed_block->hash_value_word_count > count_of(signature_workspace->hash.words)) {
                printf("Block has been hashed, but no hash value to compare to\n");
                goto verify_fail;
            }
            parsed_block->verify_diagnostic = BOOT_PARSED_BLOCK_DIAGNOSTIC_HASH_FOR_VERIFY;
            for(uint i=0; i < parsed_block->hash_value_word_count ; i++) {
                if (signature_workspace->hash.words[i] != block_data[parsed_block->hash_value_word_index + i]) {
                    printf("  HASH mismatch:\n");
                    printf("    got: ");
                    print_bytes((const uint8_t *)&block_data[parsed_block->hash_value_word_index], parsed_block->hash_value_word_count  * 4);
                    printf("    expected ");
                    print_bytes(signature_workspace->hash.bytes, parsed_block->hash_value_word_count  * 4);
                    goto verify_fail;
                }
            }
            parsed_block->verified = hx_not_checked(sig_required); // note, we shouldn't be down this code path anyway when sig is required, but this is a safety check
        } else {
            parsed_block->verified = hx_not(hx_or_checked(sig_required, hash_required));
        }
        goto verify_done;
    verify_fail:
        // Note the default is hx_bool_invalid(), so not concerned about this being skipped
        parsed_block->verified = hx_false();
    verify_done:
        // Ensure memory is returned to RO on all paths (some may do this earlier)
        inline_s_set_flash_ro_xn(ctx->mpu_on_arm);
        inline_s_set_ram_ro_xn(ctx->mpu_on_arm);
        parsed_block->verify_diagnostic |= hx_is_true(parsed_block->verified) ? BOOT_PARSED_BLOCK_DIAGNOSTIC_VERIFIED_OK : 0;
#if MINI_PRINTF
        printf("  block verified ok? %d\n", hx_is_true(parsed_block->verified));
#endif
    }
    // we expect a side effect of verifying an image with a LOAD_MAP, to be to actually load the image
    // into RAM as necessary. This means that a subsequent verify could trash pre-existing RAM contents.
    // whilst we try to avoid such scenarios in the caller.
    // note: really, this should be impossible, but we keep this around as paranoia
    parsed_block->load_image_counter = ctx->load_image_counter;
    return cosign_covered;
}

void s_varm_crit_init_block_scan(block_scan_t *bs, const boot_scan_context_t *ctx, uint32_t window_rel_search_start_offset, uint32_t first_block_search_size) {
    static_assert(sizeof(block_scan_t) % 4 == 0, "");
    s_varm_step_safe_crit_mem_erase_by_words((uintptr_t)bs, sizeof(block_scan_t));
    bs->ctx = ctx;
    bs->window_rel_next_read_word_offset = window_rel_search_start_offset / 4;
    bs->window_rel_first_block_word_offset = -1;
    bs->window_rel_first_block_max_word_offset = MIN(bs->ctx->current_search_window.size / 4, bs->window_rel_next_read_word_offset + first_block_search_size /4);
}

#if MINI_PRINTF
static const char * const image_type_flags[] = {"<invalid>", "EXE", "Data"};
static const char * const cpu_flags[] = { "ARM", "RISC-V", "Varmulet" };
static const char * const chip_flags[] = { "RP2040", "RP2350" };
static const char * const security_flags[] = { "Unspecified", "Non-secure", "Secure" };
static const char * const hash_type_flags[] = { "<invalid>", "SHA256" };
static const char * const sig_type_flags[] = { "<invalid>", "SECP256K1" };

static void print_bit_field(const char *name, uint value, uint mask, const char * const names[], uint names_count) {
    value &= mask;
    while (mask && !(mask&1)) {
        mask >>=1;
        value >>= 1;
    }
    const char *value_string;
    if (value >= names_count) value_string = "<invalid>";
    else value_string = names[value];
    printf("  %s: %d %s\n", name, value, value_string);
}

void dump_load_map(const parsed_block_t *parsed_block) {
    printf("  load map:\n");
    const picobin_load_map *load_map = (const picobin_load_map *)(parsed_block->block_data + parsed_block->load_map_word_index);
    for(uint i=0;i<picobin_load_map_entry_count(load_map);i++) {
        const picobin_load_map_entry *entry = load_map->entries + i;
        uint32_t map_runtime_physical_address = entry->runtime_address;
        uint32_t map_storage_address_value = entry->storage_address_rel;
        uint32_t map_size_value = entry->size;

        // we are looking for flash targets, however exotic binaries may have a runtime physical address that starts outside
        // the flash range, and then rolls into it, so we check for (not) RAM/XIP RAM here.
        uint32_t physical_to_storage = 0;
        if (!varm_is_sram_or_xip_ram(map_runtime_physical_address)) {
            // note we assume this is an image_def (this code path is not taken for partition tables)
            physical_to_storage = parsed_block->enclosing_window.base + parsed_block->slot_roll - XIP_BASE + ((const parsed_image_def_t *)parsed_block)->rolling_window_delta;
        } else {
            // xip/sram is unrolled/partitioned
        }
        // this is the runtime address, but un-rolled and offset by enclosing_window in the flash case;
        // i.e. for a runtime_address in the load map of 0x10000010, but in a partition starting at 0x10040000,
        // the value will be 0x10040010
        uint32_t to_storage_addr = map_runtime_physical_address + physical_to_storage;
        uint32_t size = map_size_value;
        if (!picobin_load_map_is_relative(load_map)) {
            size -= map_runtime_physical_address;
        }
        uint32_t to_storage_addr_end = to_storage_addr + size;

        if (!map_storage_address_value) {
            printf("    (clear %08x -> %08x)\n", to_storage_addr, to_storage_addr_end);
        } else {
            uint32_t from_storage_addr;
            if (!picobin_load_map_is_relative(load_map)) {
                from_storage_addr = map_storage_address_value + physical_to_storage;
            } else {
                from_storage_addr = map_storage_address_value +
                                    parsed_block->enclosing_window.base +
                                    parsed_block->window_rel_block_offset +
                                    parsed_block->load_map_word_index * 4;
            }
            if (to_storage_addr == from_storage_addr) {
                printf("    (hash %08x -> %08x)\n", to_storage_addr, to_storage_addr_end);
            } else {
                printf("    load %08x -> %08x to %08x -> %08x\n", from_storage_addr, from_storage_addr + size, to_storage_addr, to_storage_addr_end);
            }
        }
    }
}

void dump_block_common(const parsed_block_t *block, const uint32_t *block_data) {
    if (block->hash_type) {
        print_bit_field("hash type:", block->hash_type, 0xff, hash_type_flags, count_of(hash_type_flags));
        if (block->load_map_word_index) {
            printf("   includes load map\n");
        }
        printf("   includes %d block words\n", block->hash_def_block_words_included);
    } else {
        printf("  hash: none\n");
    }
    if (block->hash_value_word_index) {
        printf("  hash_value: ");
        print_bytes((const uint8_t *)&block_data[block->hash_value_word_index], block->hash_value_word_count * 4);
    } else {
        printf("  hash_value: none\n");
    }
    if (block->sig_type) {
        print_bit_field("sig type", block->sig_type, 0xff, sig_type_flags, count_of(sig_type_flags));
        printf("  pub key: ");
        print_bytes((const uint8_t *)&block_data[block->public_key_word_index], 64);
        printf("  sig: ");
        print_bytes((const uint8_t *)&block_data[block->signature_word_index], 64);
        printf("  sig-key-match: %s\n", hx_is_xtrue(block->sig_otp_key_match_and_block_hashed) ? "true" : "false");
    } else {
        printf("  sig: none\n");
    }
    printf("  version: %04x.%04x.%04x\n", hx_value(block->rollback_version), block->major_minor_version>>16, (uint16_t)block->major_minor_version);
    printf("  verified: %s\n", hx_is_null(block->verified) ? "not yet" : hx_is_true(is_block_verified(block)) ? "true" : "false");
    printf("  sig-verified: %s\n", hx_is_xtrue(is_block_signature_verifiedx(block)) ? "true" : "false");
}

void dump_partition_table(const parsed_partition_table_t *partition_table, const uint32_t *block_data) {
    if (!partition_table->core.block_data) {
        bootrom_assert(MISC, false);
        printf("  not present?\n");
        return;
    }
#if !BOOTROM_ASSERT_DISABLED
    if (partition_table->core.parser_rejected) {
        printf("  not parsed\n");
        return;
    }
#endif
    printf("  partition count: %d\n", partition_table->partition_count);
    printf("  singleton: %s\n", partition_table->singleton ? "true" : "false");
    printf("  at %08x; data copy at=%p+%04x\n", partition_table->core.enclosing_window.base + (uint)partition_table->core.window_rel_block_offset, partition_table->core.block_data, partition_table->core.block_size_words*4);
    dump_block_common(&partition_table->core, block_data);
}

void dump_image_def(const parsed_image_def_t *image_def, const uint32_t *block_data) {
    if (!image_def->core.block_data) {
        bootrom_assert(MISC, false);
        printf("  not present?\n");
        return;
    }
#if !BOOTROM_ASSERT_DISABLED
    if (image_def->core.parser_rejected) {
        printf("  not parsed\n");
        return;
    }
#endif

    printf("  at %08x; data copy at=%p+%04x\n", image_def->core.enclosing_window.base + (uint)image_def->core.window_rel_block_offset, image_def->core.block_data, image_def->core.block_size_words*4);
    print_bit_field("image type", image_def->image_type_flags, PICOBIN_IMAGE_TYPE_IMAGE_TYPE_BITS, image_type_flags,
                    count_of(image_type_flags));
    if (inline_s_is_executable(image_def)) {
        print_bit_field("chip", image_def->image_type_flags, PICOBIN_IMAGE_TYPE_EXE_CHIP_BITS, chip_flags, count_of(chip_flags));
        print_bit_field("cpu", image_def->image_type_flags, PICOBIN_IMAGE_TYPE_EXE_CPU_BITS, cpu_flags,
                        count_of(cpu_flags));
        print_bit_field("security", image_def->image_type_flags, PICOBIN_IMAGE_TYPE_EXE_SECURITY_BITS, security_flags,
                        count_of(security_flags));
        if (image_def->rolled_vector_table_addr) {
            printf("  vtor: %08x\n", (uint)image_def->rolled_vector_table_addr);
        } else {
            printf("  vtor: (default)\n");
        }
        if (image_def->rolled_entry_point_addr) {
            printf("  entry: PC %08x, SP %08x SP-Lim %08x\n", (uint)image_def->rolled_entry_point_addr, (uint)image_def->initial_sp, (uint)image_def->initial_sp_limit);
        } else {
            printf("  entry: (default)\n");
        }
        if (image_def->core.load_map_word_index) {
            dump_load_map(&image_def->core);
        } else {
            printf("  load map: none\n");
        }
        printf("  tbyb: %d\n", image_def->core.tbyb_flagged);
    }

    dump_block_common(&image_def->core, block_data);
}
#endif

