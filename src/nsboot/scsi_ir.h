/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

// NOTE THIS IS IN A SEPARATE HEADER AS IT IS COMPRESSED WHEN USING COMPRESS_TEXT
typedef unsigned char uint8_t;

struct scsi_inquiry_response {
    uint8_t pdt;
    uint8_t rmb;
    uint8_t spc_version;
    uint8_t rdf;
    uint8_t additional_length;
    uint8_t inquiry5;
    uint8_t inquiry6;
    uint8_t inquiry7;
    char vendor[8];
    char product[16];
    char version[4];
} __packed;

#if !COMPRESS_TEXT
static const struct scsi_inquiry_response scsi_ir = {
        .rmb = 0x80,
        .spc_version = 2,
        .rdf = 2,
        .additional_length = sizeof(struct scsi_inquiry_response) - 5,
        // note these are now spaces because they compress well, and this allows to not
        // need to fill with spaces later if the strings are shorter
        .vendor  = "        ",
        .product = "                ",
        .version = "    ",
};
#endif
