/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "nsboot.h"

// ------------------------------------------------------------------------------------
// In order to save space in bootrom, remove unused features, or simplify some
// abstractions that are not required, whilst leaving the code intent intact
// ------------------------------------------------------------------------------------

// GENERAL_SIZE_HACKS (set in build) size hacks (e.g. asm) that are valid in bootrom and usb_device_test
// BOOTROM_ONLY_SIZE_HACK (set in build) size hacks that require this to be actual bootrom (e.g. 16 bit pointers)

#define USB_ASSUME_ZERO_INIT 1

// number of our one configuration = 1
#define USB_FIXED_CONFIGURATION_NUMBER 1

// space-saving
#define USB_USE_TWO_ENDPOINT_INTERFACES 1
#define USB_USE_TINY_ENDPOINT_INIT 1
#if USE_16BIT_POINTERS
#define USB_USE_TINY_TRANSFER_TYPE 1
#define USB_USE_TINY_STREAM_TRANSFER_FUNCS 1
#endif
#if !NSBOOT_WITH_SUBSET_OF_INTERFACES
#define USB_ASSUME_ENDPOINTS_ARRAY_FULL 1
#endif
#define USB_NO_ENDPOINT_CALLBACK_DATA 1

// no custom per device setup packet handler
#define USB_NO_DEVICE_SETUP_HANDLER 1

#define USB_ALL_ENDPOINTS_MAX_PACKET_SIZE 64

// since our device has on_configure, require it so save a null test
//#define USB_MUST_HAVE_DEVICE_ON_CONFIGURE 1
#define USB_USE_GLOBAL_DEVICE_ON_CONFIGURE_CB 1
#define USB_USE_GLOBAL_DEVICE_GET_DESCRIPTOR_STRING_CB 1

#define USB_SUPPORT_MS_OS_20_DESCRIPTOR_SET 1
#define USB_USE_GLOBAL_DEVICE_MS_OS_20_DESCRIPTOR_SET_TRANSFER 1

// since all our non 0 endpoints are bulk, require that to allow compile-time constants
#define USB_BULK_ONLY_EP1_THRU_16 1

// our interfaces are zero based number in the order they appear on the device - require that
#define USB_ZERO_BASED_INTERFACES 1

// no custom per endpoint setup packet handlers
#define USB_NO_ENDPOINT_SETUP_HANDLER 1

// do on_init method for transfer
#define USB_NO_TRANSFER_ON_INIT 1

// do on_cancel method for transfer
#define USB_NO_TRANSFER_ON_CANCEL 1

// don't store the endpoints on the interface, and as a result
// just do some endpoint level init during the endpoint initializers
#define USB_NO_INTERFACE_ENDPOINTS_MEMBER 1

#define USB_NO_INTERFACE_ALTERNATES 1

#ifndef USB_ISOCHRONOUS_BUFFER_STRIDE_TYPE
#define USB_ISOCHRONOUS_BUFFER_STRIDE_TYPE 0
#endif

#if USB_USE_TINY_TRANSFER_TYPE
#define USB_DEVICE_TRANSFER_TYPE_ms_os_20_descriptor_set_transfer_type 0
#define USB_DEVICE_TRANSFER_TYPE_usb_current_packet_only_transfer_type 1
#define USB_DEVICE_TRANSFER_TYPE__usb_stream_transfer_type 2
#define USB_DEVICE_TRANSFER_TYPE__picoboot_cmd_transfer_type 3
#define USB_DEVICE_TRANSFER_TYPE__msc_cmd_transfer_type 4
#define USB_DEVICE_TRANSFER_TYPE_COUNT 5

// need to know the exact number in ASM
#define GLOBAL_MS_OS_20_DESCRIPTOR_SET_PACKET_COUNT 3
#endif
#ifndef __ASSEMBLER__

static_assert(USB_ISOCHRONOUS_BUFFER_STRIDE_TYPE >= 0 && USB_ISOCHRONOUS_BUFFER_STRIDE_TYPE < 4, "");

#define lsb_hword(x) (((uint)(x)) & 0xffu), ((((uint)(x))>>8u)&0xffu)
#define lsb_word(x) (((uint)(x)) & 0xffu), ((((uint)(x))>>8u)&0xffu),  ((((uint)(x))>>16u)&0xffu),  ((((uint)(x))>>24u)&0xffu)

extern uint8_t ms_os_20_descriptor_size;

// don't zero out most structures (since we do so globablly for BSS)
#define USB_SKIP_COMMON_INIT 1

// only 16 bytes saved to not set a sense code
//#define USB_SILENT_FAIL_ON_EXCLUSIVE 1

#ifndef NDEBUG
#define __removed_for_space(x) x
#define __removed_for_space_only(x) x
#define __comma_removed_for_space(x) ,x
#else
#define __removed_for_space(x)
#define __removed_for_space_only(x) void
#define __comma_removed_for_space(x)
#endif
struct usb_transfer;
struct usb_endpoint;

typedef void (*usb_transfer_func)(struct usb_endpoint *ep);
typedef void (*usb_transfer_completed_func)(struct usb_endpoint *ep, struct usb_transfer *transfer);

typedef uint8_t constrained_usb_buffer_size_t; // large enough to hold the size of biggest packets used in bootrom

struct usb_buffer {
    aligned4_uint8_t *data;
    constrained_usb_buffer_size_t data_len;
#if !USB_ALL_ENDPOINTS_MAX_PACKET_SIZE
    constrained_usb_buffer_size_t bdata_max;
#endif
    // then...
    bool valid; // aka user owned
};

#if !USB_ALL_ENDPOINTS_MAX_PACKET_SIZE
#define usb_buffer_data_max(ub) ((ub)->data_max)
#else
#define usb_buffer_data_max(ub) USB_ALL_ENDPOINTS_MAX_PACKET_SIZE
#endif

struct usb_transfer_type {
    // for IN transfers this is called to setup new packet buffers
    // for OUT transfers this is called with packet data
    //
    // In any case usb_packet_done must be called if this function has handled the buffer
    usb_transfer_func on_packet;
#if !USB_NO_TRANSFER_ON_INIT
    usb_transfer_func on_init;
#endif
#if !USB_NO_TRANSFER_ON_CANCEL
    usb_transfer_func on_cancel;
#endif
    uint8_t initial_packet_count;
};

#if !USB_USE_TINY_TRANSFER_TYPE
#define MAKE_USB_TRANSFER_TYPE(name, _on_packet, _initial_packet_count ) \
    const struct usb_transfer_type name = { \
            .on_packet = _on_packet, \
            .initial_packet_count = _initial_packet_count, \
    };
#define USB_TRANSFER_TYPE_REF(tt) (&(tt))
typedef const struct usb_transfer_type *usb_transfer_type_ref_t;
#define usb_transfer_type_on_packet(tt) ((tt)->on_packet)
#define usb_transfer_type_initial_packet_count(tt) ((tt)->initial_packet_count)
#else
#if HACK_RAM_BOOTROM_AT
#error TINY_USB_TRANSFER_TYPE not supported with RAM bootrom
#endif
#define MAKE_USB_TRANSFER_TYPE(name, _on_packet, _initial_packet_count ) \
    static const uint8_t name = USB_DEVICE_TRANSFER_TYPE_ ## name;
#define USB_TRANSFER_TYPE_REF(tt) tt
typedef uint32_t usb_transfer_type_ref_t;

extern uint16_t usb_transfer_types[USB_DEVICE_TRANSFER_TYPE_COUNT * 2]; // not really tiems 2
#define usb_transfer_type_on_packet(tt) ((usb_transfer_func)(uintptr_t)P16_A(usb_transfer_types)[tt])
#define usb_transfer_type_initial_packet_count(tt) (((uint8_t*)P16_A(usb_transfer_types))[USB_DEVICE_TRANSFER_TYPE_COUNT * 2 + tt])
#endif

#include "usb_device_private.h"

struct usb_interface *usb_interface_init(struct usb_interface *interface, const struct usb_interface_descriptor *desc,
#if !USB_USE_TWO_ENDPOINT_INTERFACES
                                         struct usb_endpoint *const *endpoints, uint endpoint_count,
#else
                                         struct usb_endpoint *endpoint0,
#endif
                                         bool double_buffered);

struct usb_device *usb_device_init(const struct usb_device_descriptor *desc,
                                   const struct usb_configuration_descriptor *config_desc,
                                   struct usb_interface *const *interfaces, uint interface_count);

void usb_device_start(void);
void usb_device_stop(struct usb_device *device);

// these are now hardcoded as this library isn't used outside bootrom
void usb_device_on_configure_cb(struct usb_device *dev, bool configured);
int usb_device_get_descriptor_string_cb(uint index, aligned4_uint8_t *buf64);

// explicit stall
void usb_halt_endpoint_on_condition(struct usb_endpoint *ep);
void usb_halt_endpoint(struct usb_endpoint *endpoint);
void usb_clear_halt_condition(struct usb_endpoint *ep);
//static inline bool usb_is_endpoint_stalled(struct usb_endpoint *endpoint);
void usb_set_default_transfer(struct usb_endpoint *ep, struct usb_transfer *transfer);
// dummy is used to save space by simplifying register setup
void usb_reset_transfer(uint32_t dummy, struct usb_transfer *transfer, usb_transfer_type_ref_t type,
                        usb_transfer_completed_func on_complete);
void usb_start_transfer(struct usb_endpoint *ep, struct usb_transfer *transfer);
void usb_reset_and_start_transfer(struct usb_endpoint *ep, struct usb_transfer *transfer,
                                  usb_transfer_type_ref_t type, usb_transfer_completed_func on_complete);
void usb_chain_transfer(struct usb_endpoint *ep, struct usb_transfer *transfer);
void usb_grow_transfer(struct usb_transfer *transfer, uint packet_count);
void usb_start_default_transfer_if_not_already_running_or_halted(struct usb_endpoint *ep);

typedef void (*usb_transfer_func)(struct usb_endpoint *ep);

#ifndef NDEBUG
struct usb_buffer *usb_current_in_packet_buffer(struct usb_endpoint *ep);
struct usb_buffer *usb_current_out_packet_buffer(struct usb_endpoint *ep);
#else
struct usb_buffer *usb_current_packet_buffer(struct usb_endpoint *ep);
#define usb_current_in_packet_buffer usb_current_packet_buffer
#define usb_current_out_packet_buffer usb_current_packet_buffer
#endif
aligned4_uint8_t *usb_get_single_packet_response_buffer(struct usb_endpoint *ep, uint len);
void native_usb_handle_buffer(void);

// call during (or asynchronously after) on_packet to mark the packet as done
void native_usb_packet_done(struct usb_endpoint *ep);

#if !USB_USE_TINY_TRANSFER_TYPE
extern const struct usb_transfer_type usb_current_packet_only_transfer_type;
#if USB_USE_GLOBAL_DEVICE_MS_OS_20_DESCRIPTOR_SET_TRANSFER
extern const struct usb_transfer_type ms_os_20_descriptor_set_transfer_type;
#endif
#else
#if USB_USE_GLOBAL_DEVICE_MS_OS_20_DESCRIPTOR_SET_TRANSFER
void usb_device_ms_os_20_descriptor_set_on_packet_cb(struct usb_endpoint *ep);
#endif
#endif

void usb_start_empty_control_in_transfer(usb_transfer_completed_func on_complete);
void usb_start_empty_control_in_transfer_null_completion(void);
void usb_start_tiny_control_in_transfer(uint32_t data, uint8_t len);
void usb_start_single_buffer_control_in_transfer(void);
void usb_start_control_out_transfer(usb_transfer_type_ref_t type);
void usb_start_empty_transfer(struct usb_endpoint *endpoint, struct usb_transfer *transfer,
                              usb_transfer_completed_func on_complete);

void usb_soft_reset_endpoint(struct usb_endpoint *ep);
void usb_soft_reset_endpoint2(struct usb_endpoint ep[2]);
void usb_hard_reset_endpoint(struct usb_endpoint *ep);

#if ENABLE_DEBUG_TRACE
void usb_dump_trace(void);
void usb_reset_trace(void);
#else

static inline void usb_dump_trace(void) {}

static inline void usb_reset_trace(void) {}

#endif
#endif
