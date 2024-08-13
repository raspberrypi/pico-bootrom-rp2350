/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

// NOTE THIS IS IN A SEPARATE HEADER AS IT IS COMPRESSED WHEN USING COMPRESS_TEXT
#include <stdint.h>
#include <assert.h>

#if !COMPRESS_TEXT
// because of mail merge we no longer have raw source for INDEX.HTM
static const char *info_uf2_txt_template = 
        "UF2 Bootloader v1.0\n"
        "Model: \n"
        "Board-ID: \n";
#endif

#define INFO_UF2_TXT_INSERT_COUNT 2

// count, length of template, reverse order list of run lengths between before inserts
const uint8_t info_uf2_txt_metadata[INFO_UF2_TXT_INSERT_COUNT + 2] = {INFO_UF2_TXT_INSERT_COUNT, 39, 1, 11} ;
