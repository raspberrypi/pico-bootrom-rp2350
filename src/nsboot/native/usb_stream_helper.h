/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "usb_device.h"

struct usb_stream_transfer {
    struct usb_transfer core;
    uint32_t offset; // offset within the stream
    uint32_t transfer_length;
    uint32_t chunk_size;
    uint8_t *chunk_buffer;
    struct usb_endpoint *ep;
    const struct usb_stream_transfer_funcs *funcs;
#ifndef NDEBUG
    bool packet_handler_complete_expected;
#endif
};

typedef void (*stream_on_packet_complete_function)(__removed_for_space_only(struct usb_stream_transfer *transfer));
typedef bool (*stream_on_chunk_function)(uint32_t chunk_len
                                         __comma_removed_for_space(struct usb_stream_transfer *transfer));

#if !USB_USE_TINY_STREAM_TRANSFER_FUNCS
struct usb_stream_transfer_funcs {
    stream_on_packet_complete_function on_packet_complete;
    // returns whether processing async
    stream_on_chunk_function on_chunk;
};
#define usb_stream_transfer_on_packet_complete(tf) ((tf)->on_packet_complete)
#define usb_stream_transfer_on_chunk(tf) ((tf)->on_chunk)
#else
struct usb_stream_transfer_funcs {
    uint16_t on_packet_complete;
    // returns whether processing async
    uint16_t on_chunk;
};
#define usb_stream_transfer_on_packet_complete(tf) ((stream_on_packet_complete_function)(uintptr_t)((tf)->on_packet_complete))
#define usb_stream_transfer_on_chunk(tf) ((stream_on_chunk_function)(uintptr_t)((tf)->on_chunk))
#endif

void usb_stream_setup_transfer(struct usb_stream_transfer *transfer, const struct usb_stream_transfer_funcs *funcs,
                               uint8_t *chunk_buffer, uint32_t chunk_size, uint32_t transfer_length,
                               usb_transfer_completed_func on_complete);

void usb_stream_chunk_done(struct usb_stream_transfer *transfer);

void native_usb_stream_packet_handler(struct usb_endpoint *ep); // public so we can call it directly in RISC-V mode

#define usb_stream_noop_on_packet_complete ((stream_on_packet_complete_function)varm_noop)
#define usb_stream_noop_on_chunk needs_work
