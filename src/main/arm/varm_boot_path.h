/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "pico.h"
#include "boot/picobin.h"
#include "bootrom.h"
#include "bootram.h"
#include "bootrom_otp.h"
#include "mini_printf.h"
#include "arm8_sig.h"
#include "hardware/structs/otp.h"
#include "hardware/structs/mpu.h"
#include "hardware/regs/otp_data.h"

static_assert(CMAKE_PICOBIN_MAX_BLOCK_SIZE == PICOBIN_MAX_BLOCK_SIZE, "");
static_assert(CMAKE_PICOBIN_MAX_IMAGE_DEF_BLOCK_SIZE == PICOBIN_MAX_IMAGE_DEF_BLOCK_SIZE, "");
static_assert(CMAKE_PICOBIN_MAX_PARTITION_TABLE_BLOCK_SIZE == PICOBIN_MAX_PARTITION_TABLE_BLOCK_SIZE, "");
static_assert(PICOBIN_MAX_BLOCK_SIZE >= PICOBIN_MAX_IMAGE_DEF_BLOCK_SIZE, "");
static_assert(PICOBIN_MAX_BLOCK_SIZE >= PICOBIN_MAX_PARTITION_TABLE_BLOCK_SIZE, "");

// During flash boot we want to load a buffer worth of data from flash into RAM (so it can't
// change externally - esp. for secure boot (and we use a fixed buffer size of MAX_PICOBIN_BLOCK_SIZE in USB RAM)
//
// We also need to look for blocks later e.g.
//    * reading partition table in non-flash binary
//    * reading partition table in flash binary, but not having gone through boot path?
//    * RAM binary boot
// We call those BUFFERED, and LINEAR

typedef struct block_buffer_or_signature_workspace block_buffer_or_signature_workspace_t;
typedef struct scan_workarea scan_workarea_t;

typedef struct {
    uint32_t base;
    uint32_t size;
} boot_window_t;

typedef struct {
    // these three are not hardened as subverting them at worst would make you load the
    // wrong (but still signed) image, or none at all
    bool executable_image_def_only;
    bool verify_image_defs_without_signatures;
    uint8_t boot_cpu;
    uint8_t load_image_counter;
    // these are here, not in flash_boot_scan_context_t as we set up flash
    // with some values even in the non-flash IMAGE_DEF boot paths
    int8_t flash_mode;
    uint8_t flash_clkdiv;
    // either the real MPU during ARM boot, or a fake bit dumpster on RISC-V or when we're using boot
    // scan functions form outside the boot path
    mpu_hw_t *mpu_on_arm;
    hx_bool booting;
    hx_bool signed_partition_table_required; // only true if secure is true
    hx_xbool hashed_partition_table_required;
    hx_xbool rollback_version_required; // for images
    hx_bool dont_scan_for_partition_tables;
    uint16_t *diagnostic;
    scan_workarea_t *scan_workarea;
    boot_window_t current_search_window;
    uint32_t flash_update_boot_offset; // initialized to 1 (meaning invalid)
#if FEATURE_EXEC2
    hx_bool exec2;
#else
    uint32_t _pad;
#endif
    uint32_t _pad2;
} boot_scan_context_t;

#if FEATURE_EXEC2
static __force_inline hx_bool inline_s_allow_varmulet(boot_scan_context_t *ctx) {
    return ctx->exec2;
}

static __force_inline hx_bool inline_s_require_salt_if_secure(boot_scan_context_t *ctx) {
    return ctx->exec2;
}

static  __force_inline hx_bool inline_s_is_exec2(boot_scan_context_t *ctx) {
    return ctx->exec2;
}
#define has_feature_exec2 true
#else
#define has_feature_exec2 false
//static __force_inline hx_bool xinline_s_allow_varmulet(__unused boot_scan_context_t *ctx) {
//    bootrom_assert(MISC, false); // should not be called
//    return hx_false();
//}
//
//static __force_inline hx_bool xinline_s_require_salt_if_secure(__unused boot_scan_context_t *ctx) {
//    bootrom_assert(MISC, false); // should not be called
//    return hx_false();
//}
//
static  __force_inline hx_bool inline_s_is_exec2(__unused boot_scan_context_t *ctx) {
    bootrom_assert(MISC, false); // should not be called
    return hx_false_constant();
}
#endif

static_assert(PICOBIN_MAX_BLOCK_SIZE / 4 < 256, "");
// since blocks are less than 256 words, use uint8_t to save space
typedef uint8_t block_word_index_t;

typedef struct {
    const boot_scan_context_t *ctx;
    uint32_t window_rel_next_read_word_offset;
    uint32_t window_rel_first_block_max_word_offset;
    uint32_t window_rel_buf_start_word_offset; // start of current buffer relative to base
    int32_t window_rel_first_block_word_offset; // -1 if not found
    block_word_index_t buf_word_pos; // current pos within buffer
    block_word_index_t buf_word_count; // current number of valid bytes in buffer
} block_scan_t;

// common (partial) in memory representation of a parsed block (either image_def or partition_table)
// it retains a pointer (block_data) to an in (USB) RAM COPY of the original data
typedef struct {
    block_word_index_t block_size_words; // the size of the block in 32bit words

    // HASH_DEF
    uint8_t hash_type;
    block_word_index_t hash_def_block_words_included;

    block_word_index_t hash_value_word_index;
    uint8_t            hash_value_word_count;

    block_word_index_t public_key_word_index;
//    uint16_t public_key_word_size;
    block_word_index_t signature_word_index;

    block_word_index_t load_map_word_index;
    bool     tbyb_flagged; // only ever set for IMAGE_DEF but stored here, so it can be checked in common code
#if MINI_PRINTF
    uint8_t sig_type;
#endif
    uint8_t load_image_counter;
#if !BOOTROM_ASSERT_DISABLED
    bool parser_rejected;
#endif
    const uint32_t *block_data; // pointer to raw buffer (copy of original block)
    boot_window_t enclosing_window;
    uint32_t window_rel_block_offset; // offset of the start of this block from the window base
    hx_xbool sig_otp_key_match_and_block_hashed; // signature matches otp key hash and the hash included the pertinent parts of tblock (minus the signature)
    hx_bool verified;
    hx_xbool signature_verified; // verified covers this, but this is an extra sanity check
#if FEATURE_EXEC2
    hx_bool salt_included;
#else
#endif
    // this field is a low risk workaround for a late discovered bug, where an IMAGE_DEF in a block loop with a PT
    // in slot 1 is not rolled by the size of the slot. parsed_block_loop->flash_start_offset
    // cannot be changed because we use that to check against flash_update_offset, and
    // enclosing_window also has a bunch of dependencies.
    // this field will be zero EXCEPT if this is an IMAGE_DEF embedded in slot 1 in which
    // case it will be the roll amount to move slot 1 to slot 0 (positive).
    // it is used to:
    //   1. correct the load_map to_address calculations
    //   2. shrink the window_size when setting up ATRANS (the roll WAS applied here to the base
    //      but not to these size)
    uint32_t slot_roll;
    // note this is checked (and only initialized) at parse time, to avoid having to store
    // the value... if it is 0,0 then there is no version
    hx_uint32_t rollback_version;
#if !BOOTROM_HARDENING
    // note: to continue to support un-hardened builds for now, leaving hx_uint32_t in unhardened builds
    //       as uint32_t, but that means we need to pad up the size to match the real build
    uint32_t _rollback_version_pad;
#endif
    uint32_t major_minor_version;
    uint32_t verify_diagnostic;
} parsed_block_t;

// this is parsed from the raw IMAGE_DEF block, however the original block data is still
// required in order to make sense of variable items such as load_map, otp_version, hash data
// and signatures
typedef struct {
    parsed_block_t core; // must be at beginning
    // ROLLING_WINDOW_DELTA
    uint32_t rolling_window_delta;
    // VECTOR_TABLE
    uint32_t rolled_vector_table_addr; // note this is in rolled address space
    uint32_t initial_sp;
    // ENTRY_POINT
    uint32_t rolled_entry_point_addr;  // note this is in rolled address space
    uint32_t initial_sp_limit;

    otp_row_and_bit_t rollback_version_otp_info;
//    uint16_t signature_word_size;
    // IMAGE_TYPE
    uint16_t image_type_flags;
} parsed_image_def_t;

#define PARSED_IMAGE_DEF_WORD_SIZE (sizeof(parsed_image_def_t ) / 4)
static_assert(PARSED_IMAGE_DEF_WORD_SIZE * 4 == sizeof(parsed_image_def_t), "");

typedef struct {
    parsed_block_t core; // must be at beginning
    bool singleton;
    uint8_t partition_count;
} parsed_partition_table_t;

#define PARSED_PARTITION_TABLE_WORD_SIZE (sizeof(parsed_partition_table_t ) / 4)
static_assert(PARSED_PARTITION_TABLE_WORD_SIZE * 4 == sizeof(parsed_partition_table_t ), "");

// A parsed_block list holds the best image and/or partition table found by parsing a single block list.
// neither, either image_def, partition_table or both can be unpopulated, and this same structure
// is used for convenience even if it could never contain a partition_table (e.g. in a block list found in a partition)
typedef struct {
    // if the parsed_block_loop came from flash, this is the offset from the start of flash to the
    // partition or slot the block list started in. for non-flash sources it is 0
    uint32_t flash_start_offset;
    parsed_image_def_t image_def;
    parsed_partition_table_t partition_table;
    uint32_t image_def_data[PICOBIN_MAX_IMAGE_DEF_BLOCK_SIZE / 4];
    uint32_t partition_table_data[PICOBIN_MAX_PARTITION_TABLE_BLOCK_SIZE / 4];
} parsed_block_loop_t;

static_assert(sizeof(parsed_image_def_t ) == 88, "");
static_assert(sizeof(parsed_partition_table_t ) == 64, "");
static_assert(sizeof(parsed_block_loop_t) == 1180, "");
static_assert(sizeof(parsed_block_loop_t) == PARSED_BLOCK_LOOP_SIZE, "");

// use to check signature of blocks stored in image_def_copies/partition_table_copies below
typedef struct {
    sb_sw_message_digest_t hash;
    sb_sw_message_digest_t key_hash;
    uint32_t sig_context_buffer[SIG_CONTEXT_SIZE / 4];
} signature_workspace_t;

static_assert(sizeof(signature_workspace_t) == 0x240, "");
struct block_buffer_or_signature_workspace {
    // used while we are searching for blocks
    union {
        uint32_t block_buffer[PICOBIN_MAX_BLOCK_SIZE / 4];
        // use to check signature of blocks stored in image_def_copies/partition_table_copies below
        signature_workspace_t signature_workspace;
    };
};
static_assert(sizeof(block_buffer_or_signature_workspace_t) == BLOCK_BUFFER_OR_SIGNATURE_WORKSPACE_SIZE, ""); // just so we know

typedef struct {
    boot_scan_context_t boot_context;
    int8_t flash_combinations_remaining; // <0 means try no more
} flash_boot_scan_context_t;

typedef union {
    boot_scan_context_t ctx;
    flash_boot_scan_context_t flash_ctx;
} largest_boot_scan_context_t;
static_assert(sizeof(largest_boot_scan_context_t) == LARGEST_BOOTSCAN_CONTEXT_SIZE, "");

typedef struct scan_workarea {
    // we have the parsed_xxx_t types, however:
    // 1. these only keep a subset of the data (they are on the stack)
    // 2. the data in parsed_xxx_t is in a different form (so we can use it when we hash)
    //
    // therefore we need a copy (outside of flash, so it can't be changed under us) of up to two (slot 0/1) of
    // both and image_def and a partition_table. the parsed_xxx_t instances point to the buffer containing the full
    // block
    largest_boot_scan_context_t ctx_holder;
    parsed_block_loop_t parsed_block_loops[2];
    block_buffer_or_signature_workspace_t block_buffer_or_signature_workspace;
} scan_workarea_t;

// layout of RAM we steal during find_uf2_target_partition
struct uf2_target_workarea {
    uint32_t family_id_buffer[1 + PARTITION_TABLE_MAX_PARTITIONS * PICOBIN_PARTITION_MAX_EXTRA_FAMILIES];
    uint32_t accepting_partition_mask; // based on family id
    scan_workarea_t scan_workarea;
};

typedef struct {
    uint32_t rlar[BOOTROM_MPU_REGION_COUNT];
} mpu_save_state_t;


static __force_inline bool inline_s_is_executable(const parsed_image_def_t *image_def) {
    return (image_def->image_type_flags & PICOBIN_IMAGE_TYPE_IMAGE_TYPE_BITS) == PICOBIN_IMAGE_TYPE_IMAGE_TYPE_AS_BITS(EXE);
}

static __force_inline uint8_t inline_s_executable_image_def_cpu_type(const parsed_image_def_t *image_def) {
    bootrom_assert(BLOCK_SCAN, inline_s_is_executable(image_def));
    return (image_def->image_type_flags & PICOBIN_IMAGE_TYPE_EXE_CPU_BITS) >> PICOBIN_IMAGE_TYPE_EXE_CPU_LSB;
}

static __force_inline uint16_t inline_decode_item_size(uint32_t item_header) {
//    uint16_t size;
//    if (item_header & 0x80) {
//        size = (uint16_t)(item_header >> 8);
//    } else {
//        size = (uint8_t)(item_header >> 8);
//    }
//    return size;
#if 0
    uint16_t rc;
    pico_default_asm_volatile(
        "lsrs %1, %0, #8\n"
        "bcs  1f\n"
        "uxtb %1, %1\n"
        "1:\n"
        "uxth %1, %1\n"
        : "=l" (rc)
        : "l" (item_header)
        : "cc");
    return rc;
#else
    register uint32_t r0 asm ("r0") = item_header;
    pico_default_asm_volatile(
            "bl s_varm_decode_item_size_impl"
            : "+l" (r0)
            :
            : "ip", "cc"
            );
    return (uint16_t)r0;
#endif
}

void s_varm_crit_init_block_scan(block_scan_t *bs, const boot_scan_context_t *ctx, uint32_t window_rel_search_start_offset, uint32_t first_block_search_size);

/**
 *
 * @param bs
 * @param workspace32
 * @return >0 : block size
 *          0 : no more blocks
 *         <0 : invalid block list
 */
int s_varm_crit_next_block(block_scan_t *bs);

uint32_t *resolve_ram_or_absolute_flash_addr(uint32_t addr);

// note anything less than 0, really
#define FLASH_MODE_STATE_SEARCH_ENDED ((int8_t)-1)
/**
 * @param sig_required true if a signature is required
 * @param hash_required if no signature, then a hash value is required
 * @param mpu_on_arm
 * @param flash_origin
 * @param parsed_block
 * @param signature_workspace
 * @param cosign_contents_block
 * @return
 */
hx_bool s_varm_crit_ram_trash_verify_block(boot_scan_context_t *ctx, hx_bool sig_required, hx_bool hash_required,
                                           parsed_block_t *parsed_block, parsed_block_t *cosign_contents_block);
bool s_varm_crit_parse_block(block_scan_t *bs, uint32_t block_size_words, parsed_block_t *parsed_block,
                                uint32_t parsed_block_size_words, uint32_t max_block_size_words);
void s_varm_crit_ram_trash_try_flash_boot(flash_boot_scan_context_t *flash_ctx);
int s_varm_crit_ram_trash_checked_ram_or_flash_window_launch(boot_scan_context_t *ctx);
void s_varm_crit_ram_trash_try_otp_boot(mpu_hw_t *mpu_on_arm, boot_scan_context_t *ctx);
void s_varm_crit_nsboot(mpu_hw_t *mpu_on_arm, uint32_t usb_activity_pin, uint32_t bootselFlags, uint serial_mode);
bool s_varm_crit_search_window(const boot_scan_context_t *ctx, uint32_t range_base, uint32_t range_size, parsed_block_loop_t *parsed_block_loop);
void s_varm_crit_get_non_booting_boot_scan_context(scan_workarea_t *scan_workarea, bool executable_image_def_only, bool verify_image_defs_without_signatures);
// note this should not be called for flash images; call the flash specific version which does wome work prior to calling this
int s_varm_crit_ram_trash_verify_and_launch_image(boot_scan_context_t *ctx, parsed_block_loop_t *parsed_block_loop);
int s_varm_crit_ram_trash_verify_and_launch_flash_image(boot_scan_context_t *ctx, parsed_block_loop_t *parsed_block_loop);
void s_varm_crit_ram_trash_pick_ab_image_part1(boot_scan_context_t *ctx, uint pi);
int s_varm_api_crit_get_b_partition(uint pi_a);
void s_varm_crit_ram_trash_perform_flash_scan_and_maybe_run_image(flash_boot_scan_context_t *flash_ctx);
bool s_varm_crit_load_init_context_and_prepare_for_resident_partition_table_load(scan_workarea_t *scan_workarea, bool force_reload);
void s_varm_crit_ram_trash_verify_parsed_blocks(boot_scan_context_t *ctx, parsed_block_loop_t *parsed_block_loop);
int s_varm_crit_choose_by_tbyb_flash_update_boot_and_version(boot_scan_context_t *ctx, uint block_loop_struct_offset);
static __force_inline bool s_varm_crit_parse_image_def(block_scan_t *bs, uint32_t block_size_words, parsed_image_def_t *image_def) {
    return s_varm_crit_parse_block(bs, block_size_words, &image_def->core, PARSED_IMAGE_DEF_WORD_SIZE,PICOBIN_MAX_IMAGE_DEF_BLOCK_SIZE);
}
// clear and return the set alias to bootram->always.boot_diagnoistc if real = true
// otherwise return a NULL Pointer (which is fine for writing to when we just
// want to lose the results
static __force_inline uint32_t *s_varm_init_diagnostic32(bool real) {
    register uintptr_t r0 asm ("r0") = real;
    pico_default_asm_volatile(
            "bl s_varm_init_diagnostic32_impl\n"
            : "+l" (r0) : : "r1", "r2", "ip", "lr", "cc"
            );
    return (uint32_t *)r0;
}

static __force_inline bool s_varm_crit_parse_partition_table(block_scan_t *bs, uint32_t block_size_words, parsed_partition_table_t *partition_table) {
    return s_varm_crit_parse_block(bs, block_size_words, &partition_table->core,
                                   PARSED_PARTITION_TABLE_WORD_SIZE, PICOBIN_MAX_PARTITION_TABLE_BLOCK_SIZE);
}


/**
 * Non RAM trashing version used post boot - note this will initialize the flash_boot_scan_context in the workspace
 *
 * can be called at any time to load the redisdent partition table if not already loaded
 *
 * Note this method is split into two parts and made inline to avoid using extra stack
 * space before calling s_varm_crit_ram_trash_perform_flash_scan_and_maybe_run_image which can otherwise
 * run out of stack when called from nsboot initialization
 *
 * @param workspace
 * @param force_reload
 */
void s_varm_crit_load_resident_partition_table(scan_workarea_t *workspace, bool force_reload);

static __force_inline int s_varm_crit_ram_trash_pick_ab_image(boot_scan_context_t *ctx, uint pi) {
    s_varm_crit_ram_trash_pick_ab_image_part1(ctx, pi);
    return s_varm_crit_choose_by_tbyb_flash_update_boot_and_version(ctx, offsetof(parsed_block_loop_t, image_def));
}

static __force_inline uint32_t inline_s_xip_window_base_from_offset(uint32_t offset) {
    return XIP_BASE + offset;
}

static __force_inline bool inline_s_is_xip_ram(uint32_t addr) {
    static_assert((XIP_SRAM_END - XIP_SRAM_BASE) == 1u << 14, "");
    return (addr >> 14) == (XIP_SRAM_BASE >> 14);
}

static __force_inline bool inline_s_is_resident_partition_table_loaded_pt(resident_partition_table_t *pt) {
    return pt->loaded;
}

static __force_inline bool inline_s_is_resident_partition_table_loaded(void) {
    return inline_s_is_resident_partition_table_loaded_pt(&bootram->always.partition_table);
}

static __force_inline bool inline_s_partition_is_nsboot_writable(const resident_partition_t *partition) {
    return PICOBIN_PARTITION_PERMISSION_NSBOOT_W_BITS & (partition->permissions_and_location & partition->permissions_and_flags);
}

static __force_inline uint32_t inline_s_partition_start_offset(const resident_partition_t *partition) {
    return ((partition->permissions_and_location >> PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_LSB) & PICOBIN_PARTITION_LOCATION_SECTOR_BIT_MASK) * 4096;
}

static __force_inline uint32_t inline_s_partition_end_offset(const resident_partition_t *partition) {
    // note: +1 since the end_offset is at the end of (after) the last sector
    return (((partition->permissions_and_location >> PICOBIN_PARTITION_LOCATION_LAST_SECTOR_LSB) & PICOBIN_PARTITION_LOCATION_SECTOR_BIT_MASK) + 1) * 4096;
}

static __force_inline uint32_t inline_s_partition_link_type(const resident_partition_t *partition) {
    return (partition->permissions_and_flags & PICOBIN_PARTITION_FLAGS_LINK_TYPE_BITS) >> PICOBIN_PARTITION_FLAGS_LINK_TYPE_LSB;
}

static __force_inline uint32_t inline_s_partition_link_value(const resident_partition_t *partition) {
    return (partition->permissions_and_flags & PICOBIN_PARTITION_FLAGS_LINK_VALUE_BITS) >> PICOBIN_PARTITION_FLAGS_LINK_VALUE_LSB;
}

static __force_inline bool inline_s_is_b_partition(const resident_partition_t *partition) {
#if GENERAL_SIZE_HACKS
    return (partition->permissions_and_flags & PICOBIN_PARTITION_FLAGS_LINK_TYPE_BITS) == PICOBIN_PARTITION_FLAGS_LINK_TYPE_AS_BITS(A_PARTITION);
#else
    return inline_s_partition_link_type(partition) == PICOBIN_PARTITION_LINK_TYPE_A_PARTITION;
#endif
}

static __force_inline uint32_t inline_s_partition_accepts_num_extra_families(const resident_partition_t *partition) {
    return (partition->permissions_and_flags & PICOBIN_PARTITION_FLAGS_ACCEPTS_NUM_EXTRA_FAMILIES_BITS) >> PICOBIN_PARTITION_FLAGS_ACCEPTS_NUM_EXTRA_FAMILIES_LSB;
}

// Note only an A partition can be owned (and should point at the A owner), since the B partition has the A partition number in the link value
static __force_inline bool inline_s_is_owned_partition(const resident_partition_t *partition) {
#if GENERAL_SIZE_HACKS
    return (partition->permissions_and_flags & PICOBIN_PARTITION_FLAGS_LINK_TYPE_BITS) == PICOBIN_PARTITION_FLAGS_LINK_TYPE_AS_BITS(OWNER_PARTITION);
#else
    return inline_s_partition_link_type(partition) == PICOBIN_PARTITION_LINK_TYPE_A_PARTITION;
#endif
}

static __force_inline bool inline_s_partition_is_marked_bootable(const resident_partition_t *partition, uint16_t cpu_type) {
    static_assert(PICOBIN_PARTITION_FLAGS_IGNORED_DURING_ARM_BOOT_BITS << PICOBIN_IMAGE_TYPE_EXE_CPU_ARM == PICOBIN_PARTITION_FLAGS_IGNORED_DURING_ARM_BOOT_BITS, "");
    static_assert(PICOBIN_PARTITION_FLAGS_IGNORED_DURING_ARM_BOOT_BITS << PICOBIN_IMAGE_TYPE_EXE_CPU_RISCV == PICOBIN_PARTITION_FLAGS_IGNORED_DURING_RISCV_BOOT_BITS, "");
    return !(partition->permissions_and_flags & (PICOBIN_PARTITION_FLAGS_IGNORED_DURING_ARM_BOOT_BITS << cpu_type));
}

static __force_inline void inline_s_set_romdata_ro_xn(mpu_hw_t *mpu_on_arm) {
    // Symbols from linker script:
    __unused extern char __start_of_secure_xn_plus_5;
    mpu_on_arm->rnr = BOOTROM_MPU_REGION_SECURE_XN;
    static_assert(((2u << M33_MPU_RBAR_AP_LSB) | M33_MPU_RBAR_XN_BITS) == 5, "");
//    mpu_on_arm->rbar = (uintptr_t)P16_D(__start_of_secure_xn) | (2u << M33_MPU_RBAR_AP_LSB) | M33_MPU_RBAR_XN_BITS;
    mpu_on_arm->rbar = (uintptr_t)P16_D(__start_of_secure_xn_plus_5);
    mpu_on_arm->rlar = (uintptr_t)BOOTROM_SG_START | M33_MPU_RLAR_EN_BITS;
}

// Disable writes to the core 1 stack region of boot RAM, which is between
// core 0 stack and "always" (also disable X permission, but this doesn't matter
// since bootram is physically impossible to execute from due to bus architecture)
static __force_inline void inline_s_set_core1_ro_xn(mpu_hw_t *mpu_on_arm) {
    mpu_on_arm->rnr = BOOTROM_MPU_REGION_BOOTRAM_CORE1;
    static_assert(((2u << M33_MPU_RBAR_AP_LSB) | M33_MPU_RBAR_XN_BITS) == 5, "");
    // note this range isn't exact due to alignment (we round inwards) but it is still between the core 0 stack and our always data
    uint32_t rbar = (((uintptr_t) &bootram->runtime.core[1] + HACK_STACK_WORDS * 4 + 0x1fu) & ~0x1fu) +
                    ((2u << M33_MPU_RBAR_AP_LSB) | M33_MPU_RBAR_XN_BITS);
    mpu_on_arm->rbar = rbar;
    mpu_on_arm->rlar = __get_opaque_value(rbar) +
                       (((uintptr_t) &bootram->always - 0x1fu) & ~0x1fu) + M33_MPU_RLAR_EN_BITS -
                       ((((uintptr_t) &bootram->runtime.core[1] + HACK_STACK_WORDS * 4 + 0x1fu) & ~0x1fu) +
                        ((2u << M33_MPU_RBAR_AP_LSB) | M33_MPU_RBAR_XN_BITS));
}

static_assert(BOOTROM_MPU_REGION_RAM == 0, "");
static_assert(BOOTROM_MPU_REGION_FLASH == 1, "");

static __force_inline void inline_s_update_mpu(mpu_hw_t *mpu_on_arm, bool flash, bool write) {
    mpu_on_arm->rnr = flash;
    // note 0u is r/w privileged only
    //      2u is r/o privlleged only
    mpu_on_arm->rbar = (flash ? 0x10000000 : 0x20000000) | ((write?0u:2u) << M33_MPU_RBAR_AP_LSB) | (M33_MPU_RBAR_XN_BITS);
}

static __force_inline void inline_s_enable_mpu(mpu_hw_t *mpu_on_arm) {
    // Enable MPU (and leave default attributes applied even for privileged software)
    mpu_on_arm->ctrl = M33_MPU_CTRL_PRIVDEFENA_BITS | M33_MPU_CTRL_ENABLE_BITS;
}

static __force_inline void inline_s_disable_mpu(mpu_hw_t *mpu_on_arm) {
    mpu_on_arm->ctrl = 0;
}

extern uint32_t s_varm_swap_mpu_state(mpu_hw_t *mpu_on_arm, mpu_save_state_t *save_state, uint32_t and);

static __force_inline void s_save_clear_and_disable_mpu(mpu_hw_t *mpu_on_arm, mpu_save_state_t *save_state) {
    hx_assert_equal2i(s_varm_swap_mpu_state(mpu_on_arm, save_state, 0), BOOTROM_MPU_REGION_COUNT);
    inline_s_disable_mpu(mpu_on_arm);
}

static __force_inline void s_restore_and_enable_mpu(mpu_hw_t *mpu_on_arm, mpu_save_state_t *save_state) {
    hx_assert_equal2i(s_varm_swap_mpu_state(mpu_on_arm, save_state, 0xffffffffu) ^ 0xffffffffu, BOOTROM_MPU_REGION_COUNT);
    inline_s_enable_mpu(mpu_on_arm);
}

#define inline_s_set_flash_ro_xn(mpu_on_arm) inline_s_update_mpu(mpu_on_arm, true, false)
#define inline_s_set_flash_rw_xn(mpu_on_arm) inline_s_update_mpu(mpu_on_arm, true, true)
#define inline_s_set_ram_ro_xn(mpu_on_arm) inline_s_update_mpu(mpu_on_arm, false, false)
#define inline_s_set_ram_rw_xn(mpu_on_arm) inline_s_update_mpu(mpu_on_arm, false, true)

static __force_inline void mark_block_unpopulated(parsed_block_t *block) {
    block->block_data = 0;
}

static __force_inline bool is_block_populated(const parsed_block_t *block) {
    return block->block_data != NULL;
}

static __force_inline hx_bool is_block_verified(const parsed_block_t *block) {
    return block->verified;
}

// note x, as this returns an xor-ed hx_bool with HX_XOR_SIG_VERIFIED
static __force_inline hx_xbool is_block_signature_verifiedx(const parsed_block_t *block) {
    return block->signature_verified;
}

static __force_inline bool is_block_signature_verified(const parsed_block_t *block) {
    return hx_is_xfalse(block->signature_verified);
}

#define is_partition_table_populated(pt) is_block_populated(&(pt)->core)
#define is_partition_table_verified(pt) is_block_verified(&(pt)->core)
// note x, as this returns an xor-ed hx_bool with HX_XOR_SIG_VERIFIED
#define is_partition_table_signature_verifiedx(pt) is_block_signature_verifiedx(&(pt)->core)
#define mark_partition_table_unpopulated(pt) mark_block_unpopulated(&(pt)->core)
static __force_inline bool is_partition_table_singleton(const parsed_partition_table_t *pt) {
    return pt->singleton;
}

#define is_image_def_populated(image_def) is_block_populated(&(image_def)->core)
#define is_image_def_verified(image_def) is_block_verified(&(image_def)->core)
// note x, as this returns an xor-ed hx_bool with HX_XOR_SIG_VERIFIED
#define is_image_def_signature_verifiedx(image_def) is_block_signature_verifiedx(&(image_def)->core)
#define mark_image_def_unpopulated(image_def) mark_block_unpopulated(&(image_def)->core)


extern scan_workarea_t core0_boot_usbram_workspace;
static_assert(sizeof(core0_boot_usbram_workspace) == CORE0_BOOT_USBRAM_WORKSPACE_SIZE, "");

// needs to be an invalid value 1 is smaller than -1 in terms of arm6 insn space
#define INVALID_FLASH_UPDATE_BOOT_OFFSET 1
void s_varm_crit_init_boot_scan_context(scan_workarea_t *scan_workarea, mpu_hw_t *mpu_on_arm,
                                               bool executable_image_def_only);

static inline bool is_version_greater(parsed_block_t *a, parsed_block_t *b) {
    return hx_signed_is_greater(a->rollback_version, b->rollback_version) |
            (hx_is_equal(a->rollback_version, b->rollback_version) && a->major_minor_version > b->major_minor_version);
}

#if MINI_PRINTF
void print_partition_default_families(uint32_t flags_and_permissions);
void print_partition_permissions(uint p);
void dump_image_def(const parsed_image_def_t *image_def, const uint32_t *block_data);
void dump_partition_table(const parsed_partition_table_t *partition_table, const uint32_t *block_data);
#endif

// make sure diagnostic is pointing at the beginning of the two hwords (and is either zero - which is where we now
// dump data we don't care about as it is ROm or is the set alias of always.boot_diagnostic. note we also allow
// 0xf0000000 which is allowed when assertions enabled (and is used as a canary value to catch writes when
// we didn't expect them)
#define check_diagnostic_is_aligned(d) bootrom_assert(MISC, !((uintptr_t)(d) & 3) && (!(d) || 0xf0000000u == (uintptr_t)(d) || ((uintptr_t)(d) - BOOTRAM_BASE - REG_ALIAS_SET_BITS) == offsetof(bootram_t, always.boot_diagnostic)))

#ifndef __riscv
void __attribute__((noreturn)) s_arm8_usb_client_ns_call_thunk(uint32_t *secure_stack_bottom, uint32_t secure_stack_size);
#define INIT_SAU_REGION(num, base, end, nsc, enable) ({ static_assert(~((base)&0x1f), ""); static_assert(~((end)&0x1f), ""); sau_hw->rnr = (num); sau_hw->rbar = (base); sau_hw->rlar = \
        ((uintptr_t)(end)-32) | ((nsc)?M33_SAU_RLAR_NSC_BITS:0) | ((enable)?M33_SAU_RLAR_ENABLE_BITS:0); })
// init with non-static addresses
#define INIT_SAU_REGION_D(num, base, end, nsc, enable) ({ bootrom_assert(MISC, ~((base)&0x1f)); bootrom_assert(MISC, ~((end)&0x1f)); sau_hw->rnr = (num); sau_hw->rbar = (base); sau_hw->rlar = \
        ((uintptr_t)(end)-32) | ((nsc)?M33_SAU_RLAR_NSC_BITS:0) | ((enable)?M33_SAU_RLAR_ENABLE_BITS:0); })
#define DISABLE_SAU_REGION(num) ({ sau_hw->rnr = (num); sau_hw->rlar = 0; })
#endif

#define FAKE_MPU_SAU_SIZE 20
// bit dumpster for RISC-V to avoid PPB accesses: some reserved regs that
// we know will ignore writes and read back as zero
// note this is also used on ARM when using parts of the boot path code
// outside the boot path.
static __force_inline mpu_hw_t *get_fake_mpu_sau(void) {
    static_assert(offsetof(mpu_hw_t, ctrl) < FAKE_MPU_SAU_SIZE, "");
    static_assert(offsetof(mpu_hw_t, rbar) < FAKE_MPU_SAU_SIZE, "");
    static_assert(offsetof(mpu_hw_t, rlar) < FAKE_MPU_SAU_SIZE, "");

    static_assert(offsetof(armv8m_sau_hw_t, ctrl) < FAKE_MPU_SAU_SIZE, "");
    static_assert(offsetof(armv8m_sau_hw_t, rnr) < FAKE_MPU_SAU_SIZE, "");
    static_assert(offsetof(armv8m_sau_hw_t, rbar) < FAKE_MPU_SAU_SIZE, "");
    static_assert(offsetof(armv8m_sau_hw_t, rlar) < FAKE_MPU_SAU_SIZE, "");

    // save space by using 0; we check on ARM that we're not using the fake_mpu
    // which checks that the first two words are 0x800, and 0x5; which
    // they certainly aren't in the bootrom since that is our initial SP and entry-point
    //    return ((mpu_hw_t *) (PWM_BASE + 8 * 4096 - 128));
    return (mpu_hw_t *) __get_opaque_ptr(0);
}
