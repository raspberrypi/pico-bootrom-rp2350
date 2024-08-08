/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pico.h"
#include "boot/uf2.h"
#include "boot/picobin.h"
#include "nsboot_usb_client.h"
#include "usb_virtual_disk.h"
#include "scsi.h"
#include "usb_msc.h"
#include "nsboot_async_task.h"
#include "nsboot_secure_calls.h"
#include "fat_dir_entries.h"
#include "index_html.h"
#include "info_uf2_txt.h"
#include "hardware/regs/sysinfo.h"
#include "hardware/regs/otp_data.h"
#define INCLUDE_index_html_template_z
#define INCLUDE_info_uf2_txt_template_z
#define INCLUDE_fat_dir_entries_z
#include "generated.h"

#define BOOTROM_UF2_REBOOT_MS   500

// Fri, 05 Sep 2008 16:20:51
#define RASPBERRY_PI_TIME_FRAC 100
#define RASPBERRY_PI_TIME ((16u << 11u) | (20u << 5u) | (51u >> 1u))
#define RASPBERRY_PI_DATE ((28u << 9u) | (9u << 5u) | (5u))
//#define NO_PARTITION_TABLE 1

#define CLUSTER_SIZE (4096u * CLUSTER_UP_MUL)
#define CLUSTER_SHIFT (3u + CLUSTER_UP_SHIFT)
static_assert(CLUSTER_SIZE == SECTOR_SIZE << CLUSTER_SHIFT, "");

#define CLUSTER_COUNT (VOLUME_SIZE / CLUSTER_SIZE)

static_assert(CLUSTER_COUNT <= 65526, "FAT16 limit");

#if NO_PARTITION_TABLE
#define VOLUME_SECTOR_COUNT SECTOR_COUNT
#else
#define VOLUME_SECTOR_COUNT (SECTOR_COUNT-1)
#endif

#define FAT_COUNT 2u
#define MAX_ROOT_DIRECTORY_ENTRIES 512
#define ROOT_DIRECTORY_SECTORS (MAX_ROOT_DIRECTORY_ENTRIES * 32u / SECTOR_SIZE)

#define SECTORS_PER_FAT (2 * (CLUSTER_COUNT + SECTOR_SIZE - 1) / SECTOR_SIZE)
static_assert(SECTORS_PER_FAT < 65536, "");

static_assert(VOLUME_SIZE >= 16 * 1024 * 1024, "volume too small for fat16");

// we are a hard drive - SCSI inquiry defines removability
#define IS_REMOVABLE_MEDIA false
#define MEDIA_TYPE (IS_REMOVABLE_MEDIA ? 0xf0u : 0xf8u)

#define MAX_RAM_UF2_BLOCKS 2144
static_assert(MAX_RAM_UF2_BLOCKS == ((SRAM_END - SRAM_BASE) + (XIP_SRAM_END - XIP_SRAM_BASE)) / 256, "");
static uint32_t uf2_valid_ram_blocks[(MAX_RAM_UF2_BLOCKS + 31) / 32];

#define DEFAULT_VOLUME_LABEL RP2350_STRING

#if !USE_16BIT_POINTERS
struct mail_merge {
    const char * const *defaults;
    const uint8_t *str_defs;
    const uint8_t *metadata;
};
#define mail_merge_default(mm,n) ((mm)->defaults[n])
#define mail_merge_str_defs(mm) ((mm)->str_defs)
#define mail_merge_metadata(mm) ((mm)->metadata)
#else
struct mail_merge {
    uint16_t defaults;
    uint16_t str_defs;
    uint16_t metadata;
};

typedef struct __packed {
    uint32_t val;
} unaligned_uint32_t;

// mm->defaults is a 16 bit pointer to an array of 16 bit values which are pointers to strings
#define mail_merge_default(mm,n) ((const char *)(uintptr_t)(((uint16_t *)(uintptr_t)((mm)->defaults))[n]))
#define mail_merge_str_defs(mm) ((const uint8_t *)(uintptr_t)((mm)->str_defs))
#define mail_merge_metadata(mm) ((const uint8_t *)(uintptr_t)((mm)->metadata))

#endif

// note these are in reverse order
const uint8_t index_html_str_defs[INDEX_HTML_INSERT_COUNT] = {
        OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_INDEX_HTM_REDIRECT_NAME_STRDEF,
        OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_INDEX_HTM_REDIRECT_URL_STRDEF,
        OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_INDEX_HTM_REDIRECT_URL_STRDEF,
};

#if !USE_16BIT_POINTERS
// note these are in reverse order
static const char * const index_html_defaults[INDEX_HTML_INSERT_COUNT]  = {
        "raspberrypi.com",
        "https://raspberrypi.com/device/RP2?version=\01xxxxxxxxxxx", // 01 is marker for serial number
        "https://raspberrypi.com/device/RP2?version=\01xxxxxxxxxxx",
};

static const struct mail_merge index_html_mail_merge = {
        .defaults = index_html_defaults,
        .str_defs = index_html_str_defs,
        .metadata = tadata,
};
#else
extern const struct mail_merge index_html_mail_merge;
#endif

// note these are in reverse order
const uint8_t info_uf2_txt_str_defs[INFO_UF2_TXT_INSERT_COUNT] = {
        OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_INFO_UF2_TXT_BOARD_ID_STRDEF,
        OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_INFO_UF2_TXT_MODEL_STRDEF,
};

#if !USE_16BIT_POINTERS
// note these are in reverse order
const char * const info_uf2_txt_defaults[INFO_UF2_TXT_INSERT_COUNT]  = {
        "RP2350",
        "Raspberry Pi RP2350",
};

const struct mail_merge info_uf2_txt_mail_merge = {
        .defaults = info_uf2_txt_defaults,
        .str_defs = info_uf2_txt_str_defs,
        .metadata = info_uf2_txt_metadata,
};
#else
extern const struct mail_merge info_uf2_txt_mail_merge;
#endif

enum partition_type {
    PT_FAT12 = 1,
    PT_FAT16 = 4,
    PT_FAT16_LBA = 0xe,
};

const uint8_t boot_sector[] = {
        // 00 here should mean not bootable (according to spec) -- still windows unhappy without it
        0xeb, 0x3c, 0x90,
        // 03 id
        'M', 'S', 'W', 'I', 'N', '4', '.', '1',
//        'U', 'F', '2', ' ', 'U', 'F', '2', ' ',
        // 0b bytes per sector
        lsb_hword(512),
        // 0d sectors per cluster
        (CLUSTER_SIZE / SECTOR_SIZE),
        // 0e reserved sectors
        lsb_hword(1),
        // 10 fat count
        FAT_COUNT,
        // 11 max number root entries
        lsb_hword(MAX_ROOT_DIRECTORY_ENTRIES),
        // 13 number of sectors, if < 32768
#if VOLUME_SECTOR_COUNT < 65536
        lsb_hword(VOLUME_SECTOR_COUNT),
#else
        lsb_hword(0),
#endif
        // 15 media descriptor
        MEDIA_TYPE,
        // 16 sectors per FAT
        lsb_hword(SECTORS_PER_FAT),
        // 18 sectors per track (non LBA)
        lsb_hword(1),
        // 1a heads (non LBA)
        lsb_hword(1),
        // 1c hidden sectors 1 for MBR
        lsb_word(SECTOR_COUNT - VOLUME_SECTOR_COUNT),
// 20 sectors if >32K
#if VOLUME_SECTOR_COUNT >= 65536
        lsb_word(VOLUME_SECTOR_COUNT),
#else
        lsb_word(0),
#endif
        // 24 drive number
        0,
        // 25 reserved (seems to be chkdsk flag for clean unmount - linux writes 1)
        0,
        // 26 extended boot sig
        0x29,

        // 27 serial number
        0, 0, 0, 0,
        // 2b label
        ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', ' ', // it is cheaper to have this here than to try and compress (we will overwrite with a possibly shorter volume label)
         // 36
        'F', 'A', 'T', '1', '6', ' ', ' ', ' ',
        0xeb, 0xfe // while(1);
};
static_assert(sizeof(boot_sector) == 0x40, "");

#define BOOT_SECTOR_OFFSET_SERIAL_NUMBER 0x27
#define BOOT_SECTOR_OFFSET_LABEL 0x2b

#define ATTR_READONLY       0x01u
#define ATTR_HIDDEN         0x02u
#define ATTR_SYSTEM         0x04u
#define ATTR_VOLUME_LABEL   0x08u
#define ATTR_DIR            0x10u
#define ATTR_ARCHIVE        0x20u

#define MBR_OFFSET_SERIAL_NUMBER 0x1b8

static struct uf2_info {
    uint32_t *valid_blocks;
    uint32_t max_valid_blocks;
    uint32_t *erased_sectors;
    uint32_t max_erased_sectors;
    union {
        // note this structure is exposed directly to PICOBOOT so don't reorder it
        struct {
            uint16_t uf2_status;
            bool ram;
            bool no_reboot;
            uint32_t family_id;
            uint32_t valid_block_count;
            uint32_t num_blocks;
        };
        uint32_quad_t uf2_status_quad;
    };
    uint32_t token;
    uint32_t lowest_addr;
    uint32_t offset; // offset when downloading into a partition (takes 0x10000000 to start of partition)
    uint32_t max_addr; // limit on the address
    uint32_t block_no;
    struct async_task next_task;
} _uf2_info;

// --- start non IRQ code ---

void write_uf2_page_complete(struct async_task *task) {
    if (task->token == _uf2_info.token) {
        if (!task->result) {
            if (_uf2_info.valid_block_count == _uf2_info.num_blocks && !_uf2_info.no_reboot) {
                // if we're rebooting into RAM we provide a window to search for an IMAGE_DEF
                uint32_t flags, p0, p1;
                // for some reason suppressing unitialized warnings doesn't work, so we use a mallet.
                pico_default_asm("" : "=l"(p0), "=l"(p1));
                if (_uf2_info.ram) {
                    flags = REBOOT2_FLAG_REBOOT_TYPE_RAM_IMAGE;
                    p0 = _uf2_info.lowest_addr;
                    p1 = (_uf2_info.lowest_addr >= SRAM_BASE ? SRAM_END : XIP_SRAM_END) - p0;
                } else {
                    flags = REBOOT2_FLAG_REBOOT_TYPE_FLASH_UPDATE;
                    p0 = XIP_BASE + _uf2_info.offset;
                }
                // explicitly boot into the right architecture (resetting both cores)
                static_assert(RP2350_RISCV_FAMILY_ID == RP2350_ARM_S_FAMILY_ID + 1, "");
                uint32_t arm_s_family_id;
                pico_default_asm_volatile(
                    "ldr %0, =%1\n" :
                    "=l" (arm_s_family_id) :
                    "i" (RP2350_ARM_S_FAMILY_ID)
                );
                if (_uf2_info.family_id == arm_s_family_id) {
                    flags |= REBOOT2_FLAG_REBOOT_TO_ARM;
                } else if (_uf2_info.family_id == arm_s_family_id + 1) {
                    flags |= REBOOT2_FLAG_REBOOT_TO_RISCV;
                }
                if (sc_or_varm_reboot(flags, BOOTROM_UF2_REBOOT_MS, p0, p1)) {
                    _uf2_info.uf2_status |= UF2_STATUS_ABORT_REBOOT_FAILED;
                }
            }
        } else {
            _uf2_info.uf2_status |= UF2_STATUS_ABORT_WRITE_ERROR;
        }
    }
    vd_async_complete(task->token, task->result);
}

// return true for async
static bool _write_uf2_page(void) {
    // If we need to write a page (i.e. it hasn't been written before, then we queue a task to do that asynchronously
    //
    // Note that in an ideal world, given that we aren't synchronizing with the task in any way from here on,
    // we'd hand that task an immutable work item so that we don't step on the task's toes later.
    //
    // In the constrained bootrom (no RAM use) environment we don't have space to do that, so instead we pass
    // it a work item which is immutable except for the data buffer to be written.
    //
    // Note that we also pre-update all _uf2_info state in anticipation of the write being completed. This saves us
    // doing some extra figuring in _write_uf2_page_complete later, and there are only two cases we care about
    //
    // 1) that the task fails, in which case we'll notice in _write_uf2_page_complete anyway, and we can reset.
    // 2) that we superseded what the task was doing with a new UF2 download, in which case the old state is irrelevant.
    //
    // So basically the rule is, that this method (and _write_uf2_page_complete) which are both called under our
    // pseudo-lock (i.e. during IRQ or with IRQs disabled) are the onlu things that touch UF2 tracking state...
    // the task just takes an immutable command (with possibly mutable data), and takes care of writing that data to FLASH or RAM
    // along with erase etc.
    uf2_debug("_write_uf2_page tok %d block %d / %d\n", (int) _uf2_info.token, _uf2_info.block_no,
              (int) _uf2_info.num_blocks);
    uint block_offset = _uf2_info.block_no / 32;
    uint32_t block_mask = 1u << (_uf2_info.block_no & 31u);
    if (!(_uf2_info.valid_blocks[block_offset] & block_mask)) {
        // note we don't want to pick XIP_CACHE over RAM even though it has a lower address
        bool xip_cache_next = _uf2_info.next_task.transfer_addr < SRAM_BASE;
        bool xip_cache_lowest = _uf2_info.lowest_addr < SRAM_BASE;
        if ((_uf2_info.next_task.transfer_addr < _uf2_info.lowest_addr && xip_cache_next == xip_cache_lowest) ||
            (xip_cache_lowest && !xip_cache_next)) {
            _uf2_info.lowest_addr = _uf2_info.next_task.transfer_addr;
        }
        if (_uf2_info.ram) {
            bootrom_assert(UF2, _uf2_info.next_task.transfer_addr);
        } else {
            bootrom_assert(UF2, _uf2_info.next_task.transfer_addr >= XIP_BASE && _uf2_info.next_task.transfer_addr < XIP_END);
            uint sector_num = (_uf2_info.next_task.transfer_addr - XIP_BASE) / FLASH_SECTOR_ERASE_SIZE;
            bootrom_assert(UF2, _uf2_info.erased_sectors);
            bootrom_assert(UF2, sector_num < _uf2_info.max_erased_sectors);
            uint word_offset = sector_num / 32;
            uint32_t word_mask = 1u << (sector_num & 31u);
            bootrom_assert(UF2, word_offset <= _uf2_info.max_erased_sectors);
            if (!(_uf2_info.erased_sectors[word_offset] & word_mask)) {
                _uf2_info.next_task.erase_addr = _uf2_info.next_task.transfer_addr & ~(FLASH_SECTOR_ERASE_SIZE - 1u);
                _uf2_info.next_task.erase_size = FLASH_SECTOR_ERASE_SIZE; // always erase a single sector
                _uf2_info.erased_sectors[word_offset] |= word_mask;
                _uf2_info.next_task.type |= AT_MASKABLE_FLASH_ERASE;
            }
            uf2_debug("Have flash destined page %08x (%08x %08x)\n", (uint) _uf2_info.next_task.transfer_addr,
                      (uint) *(uint32_t *) _uf2_info.next_task.data,
                      (uint) *(uint32_t *) (_uf2_info.next_task.data + 4));
            bootrom_assert(UF2, !(_uf2_info.next_task.transfer_addr & 0xffu));
        }
        _uf2_info.valid_block_count++;
        _uf2_info.valid_blocks[block_offset] |= block_mask;
        uf2_info("Queuing 0x%08x->0x%08x valid %d/%d checked %d/%d\n", (uint)
                (uint) _uf2_info.next_task.transfer_addr, (uint) (_uf2_info.next_task.transfer_addr + FLASH_PAGE_SIZE),
                 (uint) _uf2_info.block_no + 1u, (uint) _uf2_info.num_blocks, (uint) _uf2_info.valid_block_count,
                 (uint) _uf2_info.num_blocks);
        queue_task(QUEUE_VIRTUAL_DISK, &_uf2_info.next_task, P16_F(write_uf2_page_complete));
        // after the first write (i.e. next time, we want to check the source)
        _uf2_info.next_task.check_last_mutation_source = true;
        // note that queue_task may actually be handled sychronously based on #define, however that is OK
        // because it still calls _write_uf2_page_complete which still calls vd_async_complete which is allowed even in non async.
        return true;
    } else {
        bootrom_assert(UF2, _uf2_info.next_task.type); // we should not have had any valid blocks after reset... we must take the above path so that the task gets executed
        uf2_debug("Ignore duplicate write to 0x%08x->0x%08x\n",
                  (uint) _uf2_info.next_task.transfer_addr,
                  (uint) (_uf2_info.next_task.transfer_addr + FLASH_PAGE_SIZE));
    }
    return false; // not async
}

void vd_init(void) {
}

void vd_reset(void) {
    usb_debug("Resetting virtual disk\n");
    _uf2_info.num_blocks = 0; // marker that uf2_info is invalid
}

// note caller must pass SECTOR_SIZE buffer
void init_dir_entry(struct dir_entry *entry, uint len) {
//    entry->creation_time_frac = RASPBERRY_PI_TIME_FRAC;
    entry->creation_time = RASPBERRY_PI_TIME;
//    entry->creation_date = RASPBERRY_PI_DATE;
    entry->last_modified_time = RASPBERRY_PI_TIME;
//    entry->last_modified_date = RASPBERRY_PI_DATE;
//    varm_to_native_memcpy(entry->name, fn, 11);
//    entry->attr = ATTR_READONLY | ATTR_ARCHIVE;
//    entry->cluster_lo = cluster;
    entry->size = len;
}

#if !FEATURE_TWO_ARG_MAIL_MERGE
uint mail_merge(uint8_t *buf, const uint8_t *template_z, uint template_z_len, const struct mail_merge *merge) {
#else
uint mail_merge(uint8_t *buf, const uint8_t *template_z, uint template_z_len) {
    const struct mail_merge *merge = (const struct mail_merge *)__builtin_assume_aligned(template_z - sizeof(struct mail_merge), 4);
#endif
    uint insert_len[mail_merge_metadata(merge)[0]];
    uint total_len = mail_merge_metadata(merge)[1];
    uint run_start = total_len;
    for(uint i=0;i<mail_merge_metadata(merge)[0];i++) {
        insert_len[i] = white_label_copy_ascii(buf, MAIL_MERGE_MAX_ITEM_LENGTH, mail_merge_str_defs(merge)[i], mail_merge_default(merge,i));
        total_len += insert_len[i];
    }
    poor_mans_text_decompress(template_z, template_z_len, buf);
    uint pos = total_len;
    for(uint i=0;i<mail_merge_metadata(merge)[0];i++) {
        uint run_length = mail_merge_metadata(merge)[2+i];
        pos -= run_length;
        run_start -= run_length;
        varm_to_native_memcpy(buf + pos, buf + run_start, run_length);
        pos -= insert_len[i];
        white_label_copy_ascii(buf + pos, MAIL_MERGE_MAX_ITEM_LENGTH, mail_merge_str_defs(merge)[i], mail_merge_default(merge,i));
    }
    return total_len;
}

uint fill_index_html(uint8_t *buf) {
#if FEATURE_TWO_ARG_MAIL_MERGE
    bootrom_assert(NSBOOT, (uintptr_t)&index_html_mail_merge == (uintptr_t)index_html_template_z - sizeof(struct mail_merge));
#endif
    return mail_merge(buf,
                      P16_A(index_html_template_z),
                      sizeof(index_html_template_z)
#if !FEATURE_TWO_ARG_MAIL_MERGE
                      ,&index_html_mail_merge
#endif
    );
}

uint fill_info_uf2_txt(uint8_t *buf) {
#if FEATURE_TWO_ARG_MAIL_MERGE
    bootrom_assert(NSBOOT, (uintptr_t)&info_uf2_txt_mail_merge == (uintptr_t)info_uf2_txt_template_z - sizeof(struct mail_merge));
#endif
    return mail_merge(buf,
                      P16_A(info_uf2_txt_template_z),
                      sizeof(info_uf2_txt_template_z)
#if !FEATURE_TWO_ARG_MAIL_MERGE
                      ,&info_uf2_txt_mail_merge
#endif
                      );
}


bool vd_read_block(__unused uint32_t token, uint32_t lba, aligned4_uint8_t *buf __comma_removed_for_space(uint32_t buf_size)) {
#ifndef NDEBUG
    bootrom_assert(UF2, buf_size >= SECTOR_SIZE);
#endif
    varm_to_native_memset0(buf, SECTOR_SIZE);
#if !NO_PARTITION_TABLE
    if (!lba) {
        uint8_t *ptable = buf + SECTOR_SIZE - 2 - 64;

#if 0
        // simple LBA partition at sector 1
        ptable[4] = PT_FAT16_LBA;
        // 08 LSB start sector
        ptable[8] = 1;
        // 12 LSB sector count
        ptable[12] = (SECTOR_COUNT-1) & 0xffu;
        ptable[13] = ((SECTOR_COUNT-1)>>8u) & 0xffu;
        ptable[14] = ((SECTOR_COUNT-1)>>16u) & 0xffu;
        static_assert(!(SECTOR_COUNT>>24u), "");
#else
//        static_assert(!((SECTOR_COUNT - 1u) >> 24), "");
//        static const uint8_t _ptable_data4[] = {
//                PT_FAT16_LBA, 0, 0, 0,
//                lsb_word(1), // sector 1
//                // sector count, but we know the MS byte is zero
//                (SECTOR_COUNT - 1u) & 0xffu,
//                ((SECTOR_COUNT - 1u) >> 8u) & 0xffu,
//                ((SECTOR_COUNT - 1u) >> 16u) & 0xffu,
//        };
//        varm_to_native_memcpy(ptable + 4, _ptable_data4, sizeof(_ptable_data4));
        aligned2_uint8_t *ptable_p4 = __get_opaque_ptr(ptable + 4);
        // simple LBA partition at sector 1
        ptable_p4[0] = PT_FAT16_LBA;
        // 08 LSB start sector
        ptable_p4[4] = 1;
        // 12 LSB sector count
        static_assert(((SECTOR_COUNT-1)&0xffff) == 0xffff, "");
        *(int16_t *)(ptable_p4 + 8)  = -1;
        static_assert(((SECTOR_COUNT-1)>>16) == 0x3, "");
        static_assert(!(SECTOR_COUNT>>24u), "");
        ptable_p4[10] = (SECTOR_COUNT-1)>>16u;
        bootrom_assert(NSBOOT, ((unaligned_uint32_t *)(ptable + 4))->val == PT_FAT16_LBA);
        bootrom_assert(NSBOOT, ((unaligned_uint32_t *)(ptable + 8))->val == 1);
        bootrom_assert(NSBOOT, ((unaligned_uint32_t *)(ptable + 12))->val == SECTOR_COUNT-1);
#endif
        uint32_t sn = msc_get_serial_number32();
        varm_to_native_memcpy(buf + MBR_OFFSET_SERIAL_NUMBER, &sn, 4);

set_55_aa_and_return:
        buf[SECTOR_SIZE-2] = 0x55;
        buf[SECTOR_SIZE-1] = 0xaa;
        return false;
    }
    lba--;
#endif
    if (!lba) {
        uint32_t sn = msc_get_serial_number32();
        varm_to_native_memcpy(buf, P16_A(boot_sector), sizeof(boot_sector));
        varm_to_native_memcpy(buf + BOOT_SECTOR_OFFSET_SERIAL_NUMBER, &sn, 4);
        white_label_copy_ascii(buf + BOOT_SECTOR_OFFSET_LABEL, 11, OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_VOLUME_LABEL_STRDEF, DEFAULT_VOLUME_LABEL);
        goto set_55_aa_and_return;
    } else {
        lba--;
        if (lba < SECTORS_PER_FAT * FAT_COUNT) {
            // mirror
            while (lba >= SECTORS_PER_FAT) lba -= SECTORS_PER_FAT;
            if (!lba) {
#if GENERAL_SIZE_HACKS && USE_INFO_UF2
                static_assert((0xffffff00u | MEDIA_TYPE) == (uint32_t)-8, "");
                uint tmp = lba - 8;
                ((uint32_t *)buf)[0] = tmp;
                ((uint32_t *)buf)[1] = tmp + 7;
#else
                uint16_t *p = (uint16_t *) buf;
                p[0] = 0xff00u | MEDIA_TYPE;
                p[1] = 0xffff;
                p[2] = 0xffff; // cluster2 is index.htm
#if USE_INFO_UF2
                p[3] = 0xffff; // cluster3 is info_uf2.txt
#endif
#endif
            }
        } else {
            lba -= SECTORS_PER_FAT * FAT_COUNT;
            if (lba < ROOT_DIRECTORY_SECTORS) {
                // we don't support that many directory entries actually
                if (!lba) {
                    // root directory

                    // best way to find out how big these are, are to re-use code that fills the sector
                    uint index_html_len = fill_index_html(buf);
                    uint info_uf2_txt_len = fill_info_uf2_txt(buf);

                    // now we must clear the buffer, since we trashed it
                    varm_to_native_memset0(buf, SECTOR_SIZE);

                    struct dir_entry *entries = (struct dir_entry *) buf;
                    poor_mans_text_decompress(P16_A(fat_dir_entries_z), fat_dir_entries_z_len, buf);
                    white_label_copy_ascii(entries[0].name, 11, OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_VOLUME_LABEL_STRDEF, DEFAULT_VOLUME_LABEL);

                    init_dir_entry(&entries[0], 0);
                    init_dir_entry(&entries[1], index_html_len);
#if USE_INFO_UF2
                    init_dir_entry(&entries[2], info_uf2_txt_len);
#else
#error expect USE_INFO_UF2 now dir entries are hardcoded
#endif
                }
            } else {
                lba -= ROOT_DIRECTORY_SECTORS;
                uint cluster = lba >> CLUSTER_SHIFT;
                uint cluster_offset = lba - (cluster << CLUSTER_SHIFT);
                if (!cluster_offset) {
                    if (cluster == 0) {
#if !COMPRESS_TEXT
#error no longer supported
#else
                        uint len = fill_index_html(buf);
                        // we use embedded 0x01 in our URL to indicate where the serial_number goes;
                        // it may not be present (or may move) if the user has overriden the URL
                        for(uint i=0;i<len;i++) {
                            if (buf[i] == 1) {
                                // insert chip/rom version serial number which we use on server to redirect to the right place
                                extern uint32_t software_git_revision;
                                char *buf_i_p_6 = write_msb_hex_chars((char *) buf + i,
                                                    *(uint32_t *) (SYSINFO_BASE + SYSINFO_GITREF_RP2350_OFFSET), 6);
                                write_msb_hex_chars(buf_i_p_6, *P16_D(software_git_revision), 6);
                            }
                        }
#endif
                    }
#if USE_INFO_UF2
                    else if (cluster == 1) {
                        // spec suggests we have this as raw text in the binary, although it doesn't much matter if no CURRENT.UF2 file
                        // and we can't do that now we built it dynamically
                        fill_info_uf2_txt(buf);
                    }
#endif
                }
            }
        }
    }
    return false;
}

#define FLASH_MAX_VALID_BLOCKS (FLASH_BITMAPS_SIZE * 8)
#define FLASH_MAX_ERASED_SECTORS (32*1024*1024/4096)

static_assert(FLASH_MAX_VALID_BLOCKS * 256 == 32*1024*1024, ""); // should cover entire flash region
// put erase sectors at the top of RAM
#define FLASH_ERASED_SECTORS_BASE (SRAM_END - FLASH_MAX_ERASED_SECTORS/8)
static_assert(FLASH_ERASED_SECTORS_BASE == 0x20081c00, "");
static_assert(!(FLASH_ERASED_SECTORS_BASE & 0x3), "");

static void _clear_bitset(uint32_t *mask, uint32_t count) {
    varm_to_native_memset0(mask, count / 8);
}

static bool _update_current_uf2_info(struct uf2_block *uf2, uint32_t family_id, uint32_t token) {
    bool ram = varm_is_sram_or_xip_ram(uf2->target_addr) && varm_is_sram_or_xip_ram(uf2->target_addr + (FLASH_PAGE_MASK));
    bool flash = is_address_flash(uf2->target_addr) && is_address_flash(uf2->target_addr + (FLASH_PAGE_MASK));
    bootrom_assert(MISC, !(ram && flash));
    uint32_t status;
    if (deref_queue(QUEUE_VIRTUAL_DISK)->disable) {
        status = UF2_STATUS_ABORT_EXCLUSIVELY_LOCKED;
    } else {
        // note (test above) if virtual disk queue is disabled (and note since we're in IRQ that cannot change whilst we are executing),
        // then we don't want to do any of this even if the task will be ignored later (doing this would modify our state)
        uint8_t type = AT_MASKABLE_WRITE; // we always write
        if (_uf2_info.num_blocks != uf2->num_blocks || _uf2_info.family_id != family_id) {
            // if we have a different number of blocks, or a different family_id, then this is a different logical set of blocks
            // than we were dealing with before. if this is a family id we can download, then we want to reset the transfer (we don't
            // support two downloadable family IDs in the same UF2 (unless they come 100% in order).

            resident_partition_t partition;
            if (ram) {
                static_assert(DATA_FAMILY_ID == ABSOLUTE_FAMILY_ID + 1, "");
                static_assert(RP2350_ARM_S_FAMILY_ID == ABSOLUTE_FAMILY_ID + 2, "");
                static_assert(RP2350_RISCV_FAMILY_ID == ABSOLUTE_FAMILY_ID + 3, "");
                if (family_id < ABSOLUTE_FAMILY_ID || family_id > RP2350_RISCV_FAMILY_ID) {
                    printf("  RAM downloads only accept ARM_S and RISC-V, DATA, ABSOLUTE\n");
                    status = UF2_STATUS_IGNORED_FAMILY;
                    goto ignore;
                }
            } else {
                int pi = sc_or_varm_ram_trash_get_uf2_target_partition(&partition, family_id);
                if (pi < 0) {
                    printf("  family_id %08x is not accepted according to pt\n", family_id);
                    status = UF2_STATUS_IGNORED_FAMILY;
                    goto ignore;
                }
            }
            printf("Resetting active UF2 transfer because have new binary size %d->%d or family_id %08x->%08x\n", (int) _uf2_info.num_blocks,
                   (int) uf2->num_blocks, _uf2_info.family_id, family_id);
            varm_to_native_memset0(&_uf2_info, sizeof(_uf2_info));
            _uf2_info.family_id = family_id;
            _uf2_info.ram = ram;
            if (ram) {
                _uf2_info.max_addr = 0xffffffff;
                _uf2_info.valid_blocks = uf2_valid_ram_blocks;
                _uf2_info.max_valid_blocks = count_of(uf2_valid_ram_blocks) * 32;
                uf2_debug("  ram, so valid_blocks (max %d) %p->%p for %dK\n", (int) _uf2_info.max_valid_blocks,
                          _uf2_info.valid_blocks, _uf2_info.valid_blocks + ((_uf2_info.max_valid_blocks + 31) / 32),
                          (uint) _uf2_info.max_valid_blocks / 4);
            } else {
                _uf2_info.offset = ((partition.permissions_and_location >> PICOBIN_PARTITION_LOCATION_FIRST_SECTOR_LSB) & PICOBIN_PARTITION_LOCATION_SECTOR_BIT_MASK) * 4096;
                _uf2_info.max_addr = XIP_BASE + (((partition.permissions_and_location >> PICOBIN_PARTITION_LOCATION_LAST_SECTOR_LSB) & PICOBIN_PARTITION_LOCATION_SECTOR_BIT_MASK) + 1) * 4096;
                _uf2_info.no_reboot = partition.permissions_and_flags & PICOBIN_PARTITION_FLAGS_UF2_DOWNLOAD_NO_REBOOT_BITS;
                printf("  flash offset = +%08x, max_addr=%08x\n", _uf2_info.offset, _uf2_info.max_addr);
                _uf2_info.erased_sectors = (uint32_t *) FLASH_ERASED_SECTORS_BASE;
                _uf2_info.max_erased_sectors = FLASH_MAX_ERASED_SECTORS;
                _clear_bitset(_uf2_info.erased_sectors, _uf2_info.max_erased_sectors);
                type |= AT_MASKABLE_EXIT_XIP;
                _uf2_info.valid_blocks = (uint32_t *) FLASH_VALID_BLOCKS_BASE;
                _uf2_info.max_valid_blocks = FLASH_MAX_VALID_BLOCKS;
                uf2_debug("  flash, so valid_blocks (max %d) %p->%p for %dK\n", (int) _uf2_info.max_valid_blocks,
                          _uf2_info.valid_blocks, _uf2_info.valid_blocks + ((_uf2_info.max_valid_blocks + 31) / 32),
                          (uint) _uf2_info.max_valid_blocks / 4);
                uf2_debug("    cleared_sectors %p->%p\n", _uf2_info.erased_sectors,
                          _uf2_info.erased_sectors + ((_uf2_info.max_erased_sectors + 31) / 32));
            }
            _clear_bitset(_uf2_info.valid_blocks, _uf2_info.max_valid_blocks);
            uf2_debug("    cleared_blocks %p->%p\n", _uf2_info.valid_blocks,
                      _uf2_info.valid_blocks + ((_uf2_info.max_valid_blocks + 31) / 32));

            if (uf2->num_blocks > _uf2_info.max_valid_blocks) {
                uf2_debug("Oops image requires %d blocks and won't fit", (uint) uf2->num_blocks);
                goto bad_address;
            }
            uf2_info("New UF2 transfer\n");
            _uf2_info.num_blocks = uf2->num_blocks;
            _uf2_info.valid_block_count = 0;
            // use 0x1400000 not 0xfffffff, so for flash it is above the max address,
            // and for RAM it is above xip_cache addresses, but sorts above RAM in our sort ordder
            _uf2_info.lowest_addr = XIP_END;
        }
        if (ram != _uf2_info.ram) {
            uf2_debug("Abort write due to out of range address 0x%08x->0x%08x\n",
                      (uint) uf2->target_addr, (uint) (uf2->target_addr + uf2->payload_size));
        } else if (ram || flash) {
            bootrom_assert(UF2, uf2->num_blocks <= _uf2_info.max_valid_blocks);
            if (uf2->block_no < uf2->num_blocks) {
                // set up next task state (also serves as a holder for state scoped to this block write to avoid copying data around)
                reset_task(&_uf2_info.next_task);
                _uf2_info.block_no = uf2->block_no;
                _uf2_info.token = _uf2_info.next_task.token = token;
                _uf2_info.next_task.transfer_addr = uf2->target_addr + _uf2_info.offset;
                if (flash && (uint8_t)_uf2_info.next_task.transfer_addr) goto bad_address;
                _uf2_info.next_task.type = type;
                _uf2_info.next_task.data = uf2->data;
                _uf2_info.next_task.callback = P16_F(write_uf2_page_complete);
                _uf2_info.next_task.data_length = FLASH_PAGE_SIZE; // always a full page
                _uf2_info.next_task.source = TASK_SOURCE_VIRTUAL_DISK;
                if (_uf2_info.next_task.transfer_addr < _uf2_info.max_addr) {
                    return true;
                }
                uf2_debug("Attempt to write off end of flash partition (%p > %p\n", _uf2_info.next_task.transfer_addr, _uf2_info.max_addr);
            } else {
                uf2_debug("Abort write due to out of range block %d >= %d\n", (int) uf2->block_no,
                          (int) uf2->num_blocks);
            }
        }
        bad_address:
        status = UF2_STATUS_ABORT_BAD_ADDRESS;
        // in the case we have a partially written UF2, it is possible that restarting a new "transfer" with the subequent blocks
        // might pick a different partition (if the IMAGE_DEF in the partially written UF2 is valid)... this would split the transfer
        // into two partitions, which would be bad.
        goto ignore;
    }
    //abort:
    _uf2_info.num_blocks = 0; // invalid
    ignore:
    _uf2_info.uf2_status |= (uint16_t)status;
    return false;
}

// note caller must pass SECTOR_SIZE buffer
bool vd_write_block(uint32_t token, __unused uint32_t lba, aligned4_uint8_t *buf __comma_removed_for_space(uint32_t buf_size)) {
    struct uf2_block *uf2 = (struct uf2_block *) buf;
    if (uf2->magic_start0 == UF2_MAGIC_START0 && uf2->magic_start1 == UF2_MAGIC_START1 &&
        uf2->magic_end == UF2_MAGIC_END) {
        if (uf2->flags & UF2_FLAG_FAMILY_ID_PRESENT &&
            !(uf2->flags & UF2_FLAG_NOT_MAIN_FLASH) && uf2->payload_size == 256) {
            if (_update_current_uf2_info(uf2, uf2->file_size, token)) {
                // if we have a valid uf2 page, write it
                return _write_uf2_page();
            }
        } else {
            uf2_debug("Sector %d: ignoring write of no family or non 256 bytes sector\n", (uint) lba);
        }
    } else {
        uf2_debug("Sector %d: ignoring write of non UF2 sector\n", (uint) lba);
    }
    return false;
}

uint32_quad_t *get_uf2_status(void) {
    return &_uf2_info.uf2_status_quad;
}
