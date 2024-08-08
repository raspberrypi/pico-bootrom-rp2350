/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

// NOTE THIS IS IN A SEPARATE HEADER AS IT IS COMPRESSED WHEN USING COMPRESS_TEXT
#include <stdint.h>
#include <assert.h>

// top bit is "unicode" flag, so max length is 127
#define MAIL_MERGE_MAX_ITEM_LENGTH 127

#if !COMPRESS_TEXT
// because of mail merge we no longer have raw source for INDEX.HTM
static const char *index_html_template = "<html><head><meta http-equiv=\"refresh\" content=\"0;URL=''\"/></head><body>Redirecting to <a href=''></a></body></html>";
#endif

#define INDEX_HTML_INSERT_COUNT 3

// count, length of template, reverse order list of run lengths between before inserts
const uint8_t index_html_metadata[INDEX_HTML_INSERT_COUNT + 2] = {INDEX_HTML_INSERT_COUNT, 116, 18, 2, 41} ;
