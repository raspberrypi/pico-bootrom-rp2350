/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

// NOTE THIS IS IN A SEPARATE HEADER AS IT IS COMPRESSED WHEN USING COMPRESS_TEXT
#include <stdint.h>
#include <assert.h>

// Fri, 05 Sep 2008 16:20:51
#define RASPBERRY_PI_TIME_FRAC 100
#define RASPBERRY_PI_TIME ((16u << 11u) | (20u << 5u) | (51u >> 1u))
static_assert(RASPBERRY_PI_TIME == 0x8299, "");
#define RASPBERRY_PI_DATE ((28u << 9u) | (9u << 5u) | (5u))
static_assert(RASPBERRY_PI_DATE == 0x3925, "");

#define ATTR_READONLY       0x01u
#define ATTR_HIDDEN         0x02u
#define ATTR_SYSTEM         0x04u
#define ATTR_VOLUME_LABEL   0x08u
#define ATTR_DIR            0x10u
#define ATTR_ARCHIVE        0x20u


struct dir_entry {
    uint8_t name[11];
    uint8_t attr;
    uint8_t reserved;
    uint8_t creation_time_frac;
    uint16_t creation_time;
    uint16_t creation_date;
    uint16_t last_access_date;
    uint16_t cluster_hi;
    uint16_t last_modified_time;
    uint16_t last_modified_date;
    uint16_t cluster_lo;
    uint32_t size;
};
static_assert(sizeof(struct dir_entry) == 32, "");

#if !COMPRESS_TEXT
// note we fill in values whose individual bytes are all <0x80 (for poor_mans_text_decompress)
static struct dir_entry fat_dir_entries[3] = {
            {
                    .name = "           ", // note this is blanked with spaces so we can overwrite it with possibly shorter volume label
                    .creation_time_frac = RASPBERRY_PI_TIME_FRAC,
                    .creation_date = RASPBERRY_PI_DATE,
                    .last_modified_date = RASPBERRY_PI_DATE,
                    .attr = ATTR_VOLUME_LABEL | ATTR_ARCHIVE,
            },
            {
                    .name = "INDEX   HTM",
                    .creation_time_frac = RASPBERRY_PI_TIME_FRAC,
                    .creation_date = RASPBERRY_PI_DATE,
                    .last_modified_date = RASPBERRY_PI_DATE,
                    .cluster_lo = 2,
                    .attr = ATTR_READONLY | ATTR_ARCHIVE,
            },
            {
                    .name = "INFO_UF2TXT",
                    .creation_time_frac = RASPBERRY_PI_TIME_FRAC,
                    .creation_date = RASPBERRY_PI_DATE,
                    .last_modified_date = RASPBERRY_PI_DATE,
                    .cluster_lo = 3,
                    .attr = ATTR_READONLY | ATTR_ARCHIVE,
            },
    };
#endif
