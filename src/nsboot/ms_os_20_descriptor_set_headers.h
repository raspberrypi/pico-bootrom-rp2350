/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

// NOTE THIS IS IN A SEPARATE HEADER AS IT IS COMPRESSED WHEN USING COMPRESS_TEXT
#include <stdint.h>

#define LE32(a,b,c,d) ((a)|((b)<<8)|((c)<<16)|((d)<<24))
struct five_words {
    uint32_t a, b, c, d, e;
};
#if !COMPRESS_TEXT
static const struct five_words ms_os_20_descriptor_set_headers = {
        LE32(0x0A, 0x00, // Descriptor size (10 bytes)
             0x00, 0x00), // MS OS 2.0 descriptor set header
        LE32(0x00, 0x00, 0x03, 0x06), // Windows version (8.1) (0x06030000)
        LE32(0x00, 0x00, //lsb_hword(MS_OS_20_DESCRIPTOR_SIZE), // Size, MS OS 2.0 descriptor set (158 bytes)

        // Function subset descriptor
             0x08, 0x00), // Descriptor size (8 bytes)
        LE32(0x02, 0x00, // Function subset header
             0x01, 0x00), // itf_num, reserved
        LE32(0x9c, 0x00, // size
             0x00, 0x00), // padding
};
#endif
