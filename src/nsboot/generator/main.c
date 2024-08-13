/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <stdlib.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <string.h>
#include <assert.h>
#include <sys/stat.h>

#include "../scsi_ir.h"
#include "../fat_dir_entries.h"
#include "../index_html.h"
#include "../info_uf2_txt.h"
#include "../ms_os_20_descriptor_set_headers.h"

#ifndef MIN
#define MIN(a,b) ((a)<(b)?(a):(b))
#endif

#ifndef MAX
#define MAX(a,b) ((a)>(b)?(a):(b))
#endif

typedef unsigned int uint;

static int decompress(const uint8_t *data, int data_size, uint8_t *buf, int buf_size);
static void dump(const char *name, char *suffix, const uint8_t *buf, size_t n);

// NOTE: This is a VERY simple and HIGHLY specialized compression format.
// It can compress a string of bytes (which contain only 0 <= c <= 127)...
//
// The goals were simplicity/size of decode function and the ability to
// handle repeated strings in the index.html
int compress(const uint8_t *src, int len, const char *name) {
    static uint8_t buf[4096];
    int cost = len;
    int n = 0;
    for (int i = 0; i < len; i++) {
        if (src[i] >= 0x80) {
            fprintf(stderr, "Input data may not have top bit set");
            return 1;
        }
    }
    for (int to = 0; to < len; to++) {
        bool found = false;
        for (int match_len = MIN(127, len - to); match_len >= 3 && !found; match_len--) {
            for (int from = MAX(0, to - 255); from < to && !found; from++) {
                if (!memcmp(src + to, src + from, match_len)) {
                    assert(from < to);
//                    printf("Match %d from %d+%d\n", i, k, match_len);
                    // todo look for other matches?
                    cost += 2;
                    cost -= match_len;
                    buf[n++] = 0x100 - match_len;
                    buf[n++] = to - from;
                    to += match_len;
                    found = true;
                }
            }
        }
        if (to != len)
            buf[n++] = src[to];
    }
    static uint8_t check_buf[4096];
    int check_n = decompress(buf, n, check_buf, sizeof(check_buf));
    if (check_n != len || memcmp(src, check_buf, len)) {
        fprintf(stderr, "Decompress check failed\n");
        dump("expected", "", src, len);
        dump("actual", "", check_buf, check_n);
        return 1;
    }

    printf("#ifdef COMPRESS_TEXT\n");
    printf("// %s:\n", name);
    printf("// %d/%d %d %d\n", cost, len, len - cost, n);
    dump(name, "_z", buf, n);
    printf("#define %s_len %d\n", name, len);
    printf("#endif\n\n");
    return 0;
}

int decompress(const uint8_t *data, int data_size, uint8_t *buf, int buf_size) {
    int n = 0;
    for (int i = 0; i < data_size && n < buf_size; i++) {
        uint8_t b = data[i];
        if (b < 0x80u) {
            buf[n++] = b;
        } else {
            int len = 0x100 - b;
            int off = n - data[++i];
            while (len--) {
                buf[n++] = buf[off++];
            }
        }
    }
    if (n == buf_size) n = 0;
    return n;
}

void dump(const char *name, char *suffix, const uint8_t *buf, size_t n) {
    printf("#ifdef INCLUDE_%s%s\n", name, suffix);
    printf("const uint8_t __used __attribute__((section(\".rodata.%s%s\"))) %s%s[] = {\n", name, suffix, name, suffix);
    for (size_t i = 0; i < n; i += 12) {
        printf("    ");
        for (size_t j = i; j < MIN(n, i + 12); j++) {
            printf("0x%02x, ", buf[j]);
        }
        printf("\n");
    }
    printf("};\n");
    printf("#define %s%s_len %d\n", name, suffix, (int)n);
    printf("#endif\n");
}

static char filename[FILENAME_MAX];

#if defined(WIN32) || defined(_WIN32)
#define PATH_SEPARATOR "\\"
#else
#define PATH_SEPARATOR "/"
#endif

void replace(char *str, char from, char to) {
    for (char *p = strchr(str, from); p; p = strchr(p, from)) *p = to;
}

void check_byte(const char *text, int offset, char expected) {
    if (text[offset] != expected) {
        fprintf(stderr, "Expected \"%c\" at char %d\n", expected, offset);
        for(int i=0;i<offset;i++) fputc(text[i] < 32 ? '$' : text[i], stderr);
        fputc('\n', stderr);
        for(int i=0;i<offset;i++) fputc(i%10?' ':'0'+(i/10), stderr);
        fputs("^", stderr);
        fputc('\n', stderr);
        exit(1);
    }
}

int main(int argc, char **argv) {
    int rc = 0;
    struct stat sb;
    if (argc != 2 || stat(argv[1], &sb) || !(sb.st_mode & S_IFDIR)) {
        fprintf(stderr, "expected valid source path argument.");
        rc = 1;
    }

    static uint8_t buf[4096];

    if (!rc) {
        rc = compress((const uint8_t *)index_html_template, strlen(index_html_template), "index_html_template");

        if (strlen(index_html_template) != index_html_metadata[1]) {
            fprintf(stderr, "length mismatch %lu != %d\n", strlen(index_html_template), index_html_metadata[1]);
            return 1;
        }

        const int INDEX_HTML_OFFSET_URL0 = index_html_metadata[1] - index_html_metadata[2] - index_html_metadata[3] - index_html_metadata[4];
        const int INDEX_HTML_OFFSET_URL1 = index_html_metadata[1] - index_html_metadata[2] - index_html_metadata[3];
        const int INDEX_HTML_OFFSET_SITE_NAME = index_html_metadata[1] - index_html_metadata[2];
        check_byte(index_html_template, INDEX_HTML_OFFSET_URL0-1, '\'');
        check_byte(index_html_template, INDEX_HTML_OFFSET_URL0, '\'');
        check_byte(index_html_template, INDEX_HTML_OFFSET_URL1-1, '\'');
        check_byte(index_html_template, INDEX_HTML_OFFSET_URL1, '\'');
        check_byte(index_html_template, INDEX_HTML_OFFSET_SITE_NAME-1, '>');
        check_byte(index_html_template, INDEX_HTML_OFFSET_SITE_NAME, '<');
        check_byte(index_html_template, INDEX_HTML_OFFSET_SITE_NAME+1, '/');
        check_byte(index_html_template, INDEX_HTML_OFFSET_SITE_NAME+2, 'a');
        if (strlen(index_html_template) + MAIL_MERGE_MAX_ITEM_LENGTH * 3 > 512) {
            fprintf(stderr, "index_html is bigger than a sector\n");
            return 1;
        }
    }

    if (!rc) {
        rc = compress((const uint8_t *)info_uf2_txt_template, strlen(info_uf2_txt_template), "info_uf2_txt_template");

        if (strlen(info_uf2_txt_template) != info_uf2_txt_metadata[1]) {
            fprintf(stderr, "length mismatch %lu != %d\n", strlen(info_uf2_txt_template), info_uf2_txt_metadata[1]);
            return 1;
        }
        const int INFO_UF2_TXT_OFFSET_MODEL = info_uf2_txt_metadata[1] - info_uf2_txt_metadata[2] - info_uf2_txt_metadata[3];
        const int INFO_UF2_TXT_OFFSET_BOARD_ID = info_uf2_txt_metadata[1] - info_uf2_txt_metadata[2];
        check_byte(info_uf2_txt_template, INFO_UF2_TXT_OFFSET_MODEL-2, ':');
        check_byte(info_uf2_txt_template, INFO_UF2_TXT_OFFSET_MODEL-1, ' ');
        check_byte(info_uf2_txt_template, INFO_UF2_TXT_OFFSET_BOARD_ID-2, ':');
        check_byte(info_uf2_txt_template, INFO_UF2_TXT_OFFSET_BOARD_ID-1, ' ');
        if (strlen(info_uf2_txt_template) + MAIL_MERGE_MAX_ITEM_LENGTH * 3 > 512) {
            fprintf(stderr, "info_uf2_txt is bigger than a sector\n");
            return 1;
        }
    }

    if (!rc) {
        struct scsi_inquiry_response copy = scsi_ir;
        copy.rmb = 0x00, // should be 0x80 but we can't compress that so we use 0 and fill it later
        rc = compress((uint8_t *) &copy, sizeof(copy), "scsi_ir");
    }

    if (!rc) {
        rc = compress((uint8_t *)fat_dir_entries, sizeof(fat_dir_entries), "fat_dir_entries");
    }

    static_assert(sizeof(ms_os_20_descriptor_set_headers) == 20, "");
    const uint8_t *ms_os_20_descriptor_set_headers_bytes = (const uint8_t *)&ms_os_20_descriptor_set_headers.a;
    assert(ms_os_20_descriptor_set_headers_bytes[15] == 0);
    // this is stored by code later
    assert(ms_os_20_descriptor_set_headers_bytes[16] == 0x9c);
    assert(ms_os_20_descriptor_set_headers_bytes[17] == 0);
    assert(ms_os_20_descriptor_set_headers_bytes[18] == 0);
    assert(ms_os_20_descriptor_set_headers_bytes[19] == 0);
    if (!rc) {
        rc = compress(ms_os_20_descriptor_set_headers_bytes, 15, "ms_os_20_descriptor_set_headers");
    }

    return rc;
}