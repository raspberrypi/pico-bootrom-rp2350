/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "pico.h"
#include "usb_common.h"

#if 1
#define STRUCT_CHECK(x) static_assert(x, "")
#endif
struct usb_transfer {
#if GENERAL_SIZE_HACKS
    union {
        struct {
#endif
            // number of packets which require usb_packet_done()
            bool outstanding_packet;
            // received a packet which we couldn't deliver because there was one outstanding
            bool packet_queued;
            bool started;
            bool completed;
#if GENERAL_SIZE_HACKS
        };
        uint32_t all_flags;
    };
#endif
    // prototype
    usb_transfer_type_ref_t type;
    usb_transfer_completed_func on_complete;
    // total number of buffers (packets) that still need to be handed over to the hardware
    // during the remaining course of the transfer (with data for IN, empty for data for out)
    uint32_t remaining_packets_to_submit;
    // total number of buffers when we will expect to receive IRQ/handle_buffer for during
    // the remaining course of the transfer
    uint32_t remaining_packets_to_handle;
};

struct usb_interface {
    const struct usb_interface_descriptor *descriptor;
#if !USB_NO_INTERFACE_ENDPOINTS_MEMBER
    struct usb_endpoint *const *endpoints;
    uint8_t endpoint_count;
#endif
    bool (*setup_request_handler)(struct usb_interface *interface, struct usb_setup_packet *setup);
#if !USB_NO_INTERFACE_ALTERNATES
    bool (*set_alternate_handler)(struct usb_interface *interface, uint alt);
    uint8_t alt;
#endif
};

struct usb_configuration {
    const struct usb_configuration_descriptor *descriptor;
    struct usb_interface *const *interfaces;
#ifndef USB_FIXED_INTERFACE_COUNT
    uint8_t interface_count;
#endif
};
#ifdef USB_FIXED_INTERFACE_COUNT
#define _usb_interface_count(config) USB_FIXED_INTERFACE_COUNT
#else
#define _usb_interface_count(config) config->interface_count
#endif

struct usb_device {
#if !GENERAL_SIZE_HACKS
    uint8_t current_address; // 0 if unaddressed
#endif
    uint8_t current_config_num; // 0 if unconfigured
    uint8_t pending_address; // address to set on completion of SET_ADDRESS CSW
    uint16_t next_buffer_offset;
    const struct usb_device_descriptor *descriptor;
#if !USB_NO_DEVICE_SETUP_HANDLER
    bool (*setup_request_handler)(struct usb_device *dev, struct usb_setup_packet *setup);
#endif
#if !USB_USE_GLOBAL_DEVICE_ON_CONFIGURE_CB
    void (*on_configure)(struct usb_device *dev, bool configured);
#endif
#if !USB_USE_GLOBAL_DEVICE_GET_DESCRIPTOR_STRING_CB
    const char *(*get_descriptor_string)(uint index);
#endif
    // only support one config for now
    struct usb_configuration config;
//    bool started;
};

enum usb_halt_state {
    HS_NONE = 0,
    HS_NON_HALT_STALL = 1, // just stalled
    HS_HALTED = 2, // halted or command halted
    HS_HALTED_ON_CONDITION = 3 // halted that cannot be simply cleared by CLEAR_FEATURE
};

struct usb_endpoint {
    union {
        struct {
            uint8_t num;
            bool double_buffered;
            bool in;
            uint8_t buffer_bit_index;
        };
        uint32_t init_word;
    };
    uint8_t next_pid;
    uint8_t owned_buffer_count;
    union {
        struct {
            uint8_t current_take_buffer;
            uint8_t current_give_buffer;
        };
        uint8_t current_buffers[2];
    };
    uint8_t halt_state;
    bool first_buffer_after_reset;
    const struct usb_endpoint_descriptor *descriptor;
    struct usb_transfer *default_transfer;
    struct usb_transfer *current_transfer;
    struct usb_transfer *chain_transfer;
    void (*on_stall_change)(struct usb_endpoint *ep);
#if !USB_NO_ENDPOINT_SETUP_HANDLER
    bool (*setup_request_handler)(struct usb_endpoint *ep, struct usb_setup_packet *setup);
#endif
    uint16_t dpram_buffer_offset;
#if !USB_ALL_ENDPOINTS_MAX_PACKET_SIZE
    uint16_t buffer_size; // for an individual buffer
#endif
    struct usb_buffer current_hw_buffer;
#if !USB_BULK_ONLY_EP1_THRU_16
    uint16_t buffer_stride;
#endif
};
STRUCT_CHECK(sizeof(struct usb_endpoint) == 44);
STRUCT_CHECK(offsetof(struct usb_endpoint, next_pid) == 4);
static inline uint usb_endpoint_buffer_size(struct usb_endpoint *ep) {
#if USB_ALL_ENDPOINTS_MAX_PACKET_SIZE
    (void)ep;
    return USB_ALL_ENDPOINTS_MAX_PACKET_SIZE;
#else
    return ep->buffer_size;
#endif
}
static inline uint usb_endpoint_number(struct usb_endpoint *ep) {
   bootrom_assert(USB, ep);
    return ep->descriptor ? ep->descriptor->bEndpointAddress & 0xfu : 0;
}

static inline bool usb_is_endpoint_stalled(struct usb_endpoint *endpoint) {
    return endpoint->halt_state != HS_NONE;
}

const char *usb_endpoint_dir_string(struct usb_endpoint *ep);

void usb_transfer_current_packet_only(struct usb_endpoint *ep);

#if !USB_ALL_ENDPOINTS_MAX_PACKET_SIZE
#define ep_buffer_size(ep) ((ep)->buffer_size)
#else
#define ep_buffer_size(ep) USB_ALL_ENDPOINTS_MAX_PACKET_SIZE
#endif
