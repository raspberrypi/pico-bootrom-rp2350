/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "pico.h"
#include "boot/picoboot.h"
#include "nsboot_usb_client.h"
#include "usb_msc.h"
#include "usb_stream_helper.h"
#include "nsboot_async_task.h"
#include "nsboot_secure_calls.h"
#include "nsboot_arch_adapter.h"
#include "hardware/regs/otp_data.h"
#define INCLUDE_ms_os_20_descriptor_set_headers_z
#include "generated.h"

// mutable serial number string for us to initialize on startup
__aligned(4) char serial_number_string[17];
uint8_t ms_os_20_descriptor_size;

#define MS_OS_20_COMPOSITE_DESCRIPTOR_SIZE     0xa6
#define MS_OS_20_NON_COMPOSITE_DESCRIPTOR_SIZE 0x9e

char *const descriptor_strings[] =
        {
                "Raspberry Pi",
                "RP2350 Boot",
                serial_number_string
        };

struct usb_simple_interface_descriptor {
    struct usb_interface_descriptor desc;
    struct usb_endpoint_descriptor ep1_desc;
    struct usb_endpoint_descriptor ep2_desc;
} __packed;

#if USE_PICOBOOT
#define BOOT_DEVICE_NUM_INTERFACES 2
#else
#define BOOT_DEVICE_NUM_INTERFACES 1
#endif

struct boot_device_config {
    struct usb_configuration_descriptor config_desc;
    struct usb_simple_interface_descriptor interface_desc[BOOT_DEVICE_NUM_INTERFACES];
} __packed;

const struct boot_device_config boot_device_config = {
        .config_desc = {
                .bLength             = 0x09,    // Descriptor size is 9 bytes
                .bDescriptorType     = 0x02,   // CONFIGURATION Descriptor Type
                .wTotalLength        = sizeof(boot_device_config),
                .bNumInterfaces      = BOOT_DEVICE_NUM_INTERFACES,
                .bConfigurationValue = 0x01,   // The value 1 should be used to select this configuration
                .iConfiguration      = 0x00,   // The device doesn't have the string descriptor describing this configuration
                .bmAttributes        = 0x80,   // Configuration characteristics : Bit 7: Reserved (set to one) 1 Bit 6: Self-powered 0 Bit 5: Remote Wakeup 0
                .bMaxPower           = 0x19,   // Maximum power consumption of the device in this configuration is 50 mA
        },
        .interface_desc = {
                {
                        .desc = {
                                .bLength            = 0x09, // Descriptor size is 9 bytes
                                .bDescriptorType    = 0x04, // INTERFACE Descriptor Type
                                .bInterfaceNumber   = 0x00, // The number of this interface is 0.
                                .bAlternateSetting  = 0x00, // The value used to select the alternate setting for this interface is 0
                                .bNumEndpoints      = 0x02,
                                .bInterfaceClass    = 0x08, // The interface implements the Mass Storage class
                                .bInterfaceSubClass = 0x06, // The interface implements the SCSI Transparent Subclass
                                .bInterfaceProtocol = 0x50, // The interface uses the Bulk-Only Protocol
                                .iInterface         = 0x00, // The device doesn't have a string descriptor describing this iInterface
                        },
                        .ep1_desc = {
                                .bLength          = 0x07,   // Descriptor size is 7 bytes
                                .bDescriptorType  = 0x05,   // ENDPOINT Descriptor Type
                                .bEndpointAddress = 0x81,   // This is an IN endpoint with endpoint number 1
                                .bmAttributes     = 0x02,   // Types - BULK
                                // note this must equal USB_ALL_ENDPOINTS_MAX_PACKET_SIZE if that is defined
                                .wMaxPacketSize   = 0x0040, // Maximum packet size for this endpoint is 64 Bytes. If Hi-Speed, 0 additional transactions per frame
                                .bInterval        = 0x00,   // The polling interval value is every 0 Frames. Undefined for Hi-Speed
                        },
                        .ep2_desc = {
                                .bLength          = 0x07,   // Descriptor size is 7 bytes
                                .bDescriptorType  = 0x05,   // ENDPOINT Descriptor Type
                                .bEndpointAddress = 0x02,   // This is an OUT endpoint with endpoint number 2
                                .bmAttributes     = 0x02,   // Types - BULK
                                // note this must equal USB_ALL_ENDPOINTS_MAX_PACKET_SIZE if that is defined
                                .wMaxPacketSize   = 0x0040, // Maximum packet size for this endpoint is 64 Bytes. If Hi-Speed, 0 additional transactions per frame
                                .bInterval        = 0x00,   // The polling interval value is every 0 Frames. If Hi-Speed, 0 uFrames/NAK
                        },
                },
#if USE_PICOBOOT
                {
                        .desc = {
                                .bLength            = 0x09, // Descriptor size is 9 bytes
                                .bDescriptorType    = 0x04, // INTERFACE Descriptor Type
                                .bInterfaceNumber   = 0x01, // The number of this interface is 1.
                                .bAlternateSetting  = 0x00, // The value used to select the alternate setting for this interface is 0
                                .bNumEndpoints      = 0x02,
                                .bInterfaceClass    = 0xff, // The interface is vendor specific
                                .bInterfaceSubClass = 0x00, // no subclass
                                .bInterfaceProtocol = 0x00, // no protocol
                                .iInterface         = 0x00, // The device doesn't have a string descriptor describing this iInterface
                        },
                        .ep1_desc = {
                                .bLength          = 0x07,   // Descriptor size is 7 bytes
                                .bDescriptorType  = 0x05,   // ENDPOINT Descriptor Type
                                .bEndpointAddress = 0x03,   // This is an OUT endpoint with endpoint number 3
                                .bmAttributes     = 0x02,   // Types - BULK
                                // note this must equal USB_ALL_ENDPOINTS_MAX_PACKET_SIZE if that is defined
                                .wMaxPacketSize   = 0x0040, // Maximum packet size for this endpoint is 64 Bytes. If Hi-Speed, 0 additional transactions per frame
                                .bInterval        = 0x00,   // The polling interval value is every 0 Frames. If Hi-Speed, 0 uFrames/NAK
                        },
                        .ep2_desc = {
                                .bLength          = 0x07,   // Descriptor size is 7 bytes
                                .bDescriptorType  = 0x05,   // ENDPOINT Descriptor Type
                                .bEndpointAddress = 0x84,   // This is an IN endpoint with endpoint number 4
                                .bmAttributes     = 0x02,   // Types - BULK
                                // note this must equal USB_ALL_ENDPOINTS_MAX_PACKET_SIZE if that is defined
                                .wMaxPacketSize   = 0x0040, // Maximum packet size for this endpoint is 64 Bytes. If Hi-Speed, 0 additional transactions per frame
                                .bInterval        = 0x00,   // The polling interval value is every 0 Frames. Undefined for Hi-Speed
                        }
                }
#endif
        }
};

static_assert(sizeof(boot_device_config) == sizeof(struct usb_configuration_descriptor) +
                                            BOOT_DEVICE_NUM_INTERFACES * sizeof(struct usb_simple_interface_descriptor),
              "");

static struct usb_interface msd_interface;

#if USE_PICOBOOT
static struct usb_endpoint picoboot_endpoints[2];
#define PICOBOOT_OUT_INDEX 0
#define PICOBOOT_IN_INDEX 1
#define picoboot_out (picoboot_endpoints[PICOBOOT_OUT_INDEX])
#define picoboot_in (picoboot_endpoints[PICOBOOT_IN_INDEX])
static struct usb_interface picoboot_interface;
#endif

const struct usb_device_descriptor boot_device_descriptor = {
        .bLength            = 18, // Descriptor size is 18 bytes
        .bDescriptorType    = 0x01, // DEVICE Descriptor Type
        .bcdUSB             = 0x0210, // USB Specification version 2.1 for BOS
        .bDeviceClass       = 0x00, // Each interface specifies its own class information
        .bDeviceSubClass    = 0x00, // Each interface specifies its own Subclass information
        .bDeviceProtocol    = 0x00, // No protocols the device basis
        .bMaxPacketSize0    = 0x40, // Maximum packet size for endpoint zero is 64
        .idVendor           = VENDOR_ID,
        .idProduct          = PRODUCT_ID,
        .bcdDevice          = 0x0100, // The device release number is 1.00
        .iManufacturer      = 0x01, // The manufacturer string descriptor index is 1
        .iProduct           = 0x02, // The product string descriptor index is 2
        .iSerialNumber      = 3,//count_of(descriptor_strings) + 1, // The serial number string descriptor index is 3
        .bNumConfigurations = 0x01, // The device has 1 possible configurations
};

// we have two possible descriptors:
//
// MSD + picoboot : composite descriptor
// picoboot only  : non-composite descriptor (windows ignores composite descriptor in this case)
// MSD only       : composite descriptor (windows ignores composite descriptor in this case)
// neither        : not supported (we never do this)
//
// This is the composite descriptor of size 0xa6 (the non-composite has size of 0x9e and omits the
// "function subset descriptor")
//
//        0x0A, 0x00, // Descriptor size (10 bytes)
//        0x00, 0x00, // MS OS 2.0 descriptor set header
//        0x00, 0x00, 0x03, 0x06, // Windows version (8.1) (0x06030000)
//        **0xa6**, 0x00, // Size, MS OS 2.0 descriptor set (166 bytes)
//
//        // no Configuration subset descriptor (we only have one onfig)
//
//        // Function subset descriptor (omitted for non-composite descriptor)
//        0x08, 0x00, // Descriptor size (8 bytes)
//        0x02, 0x00, // Function subset header
//        0x01, 0x00, // itf_num, reserved
//        0x9c, 0x00, // Size
//
//        // Microsoft OS 2.0 compatible ID descriptor
//        0x14, 0x00, // Descriptor size (20 bytes)
//        0x03, 0x00, // MS OS 2.0 compatible ID descriptor
//        0x57, 0x49, 0x4E, 0x55, 0x53, 0x42, 0x00, 0x00, // WINUSB string
//        0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sub-compatible ID
//
//        // Registry property descriptor
//        0x80, 0x00, // Descriptor size (128 bytes))
//        0x04, 0x00, // Registry Property descriptor
//        0x01, 0x00, // String is  null-terminated Unicode
//        0x28, 0x00, // Size of Property Name (40 bytes)
//
//        //Property Name ("DeviceInterfaceGUID")
//        0x44, 0x00, 0x65, 0x00, 0x76, 0x00, 0x69, 0x00, 0x63, 0x00, 0x65, 0x00,
//        0x49, 0x00, 0x6E, 0x00, 0x74, 0x00, 0x65, 0x00, 0x72, 0x00, 0x66, 0x00,
//        0x61, 0x00, 0x63, 0x00, 0x65, 0x00, 0x47, 0x00, 0x55, 0x00, 0x49, 0x00,
//        0x44, 0x00, 0x00, 0x00,
//        0x4E, 0x00, // Size of Property Data (78 bytes)
//
//        // Vendor-defined Property Data: {ecceff35-146c-4ff3-acd9-8f992d09acdd}
//        0x7B, 0x00, 0x65, 0x00, 0x63, 0x00, 0x63, 0x00, 0x65, 0x00, 0x66, 0x00,
//        0x66, 0x00, 0x33, 0x00, 0x35, 0x00, 0x2D, 0x00, 0x31, 0x00, 0x34, 0x00,
//        0x36, 0x00, 0x33, 0x00, 0x2D, 0x00, 0x34, 0x00, 0x66, 0x00, 0x66, 0x00,
//        0x33, 0x00, 0x2D, 0x00, 0x61, 0x00, 0x63, 0x00, 0x64, 0x00, 0x39, 0x00,
//        0x2D, 0x00, 0x38, 0x00, 0x66, 0x00, 0x39, 0x00, 0x39, 0x00, 0x32, 0x00,
//        0x64, 0x00, 0x30, 0x00, 0x39, 0x00, 0x61, 0x00, 0x63, 0x00, 0x64, 0x00,
//        0x64, 0x00, 0x7D, 0x00, 0x00, 0x00

const uint8_t ms_os2_compatible_id_descriptor[10] = {
    // Microsoft OS 2.0 compatible ID descriptor
    0x14, 0x00, // Descriptor size (20 bytes)
    0x03, 0x00, // MS OS 2.0 compatible ID descriptor
    0x57, 0x49, 0x4E, 0x55, 0x53, 0x42, // 0x00, 0x00, // WINUSB string
    //0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, // Sub-compatible ID
};

// this is the common suffix
#define P(a, b) (a + b * 0x100) // "a" but generate a warning if "b" is non zero
#define MS_OS2_COMPATIBLE_ID_DESCRIPTOR_SIZE     0x14
#define MS_OS2_REGISTRY_PROPERTY_DESCRIPTOR_SIZE 0x80
const uint8_t ms_os2_registry_property_descriptor_even_bytes[] = {
    // Registry property descriptor
    P(MS_OS2_REGISTRY_PROPERTY_DESCRIPTOR_SIZE, 0x00), // Descriptor size (128 bytes)
    P(0x04, 0x00), // Registry Property descriptor
    P(0x01, 0x00), // String is  null-terminated Unicode
    P(0x28, 0x00), // Size of Property Name (40 bytes)

    //Property Name ("DeviceInterfaceGUID")
    P(0x44, 0x00), P(0x65, 0x00), P(0x76, 0x00), P(0x69, 0x00), P(0x63, 0x00), P(0x65, 0x00),
    P(0x49, 0x00), P(0x6E, 0x00), P(0x74, 0x00), P(0x65, 0x00), P(0x72, 0x00), P(0x66, 0x00),
    P(0x61, 0x00), P(0x63, 0x00), P(0x65, 0x00), P(0x47, 0x00), P(0x55, 0x00), P(0x49, 0x00),
    P(0x44, 0x00), P(0x00, 0x00),
    P(0x4E, 0x00), // Size of Property Data (78 bytes)

    // Vendor-defined Property Data: {bc7398c1-73cd-4cb7-98b8-913a8fca7bf6}
    P('{', 0),     P('b', 0),     P('c', 0),     P('7', 0),     P('3', 0),     P('9', 0),
    P('8', 0),     P('c', 0),     P('1', 0),     P('-', 0),     P('7', 0),     P('3', 0),
    P('c', 0),     P('d', 0),     P('-', 0),     P('4', 0),     P('c', 0),     P('b', 0),
    P('7', 0),     P('-', 0),     P('9', 0),     P('8', 0),     P('b', 0),     P('8', 0),
    P('-', 0),     P('9', 0),     P('1', 0),     P('3', 0),     P('a', 0),     P('8', 0),
    P('f', 0),     P('c', 0),     P('a', 0),     P('7', 0),     P('b', 0),     P('f', 0),
    P('6', 0),     P('}', 0),     P(  0, 0)
};
static_assert(sizeof(ms_os2_registry_property_descriptor_even_bytes) == 64, "");

void usb_device_ms_os_20_descriptor_set_on_packet_cb(struct usb_endpoint *ep);

#define MS_OS_20_DESCRIPTOR_SET_PACKET_COUNT ((MS_OS_20_COMPOSITE_DESCRIPTOR_SIZE + 63) / 64)
// we want the same number of packets for both types
static_assert( MS_OS_20_DESCRIPTOR_SET_PACKET_COUNT == (MS_OS_20_NON_COMPOSITE_DESCRIPTOR_SIZE + 63) / 64, "");
#if !USB_USE_TINY_TRANSFER_TYPE
//const struct usb_transfer_type ms_os_20_descriptor_set_transfer_type = {
//        .on_packet = usb_device_ms_os_20_descriptor_set_on_packet_cb,
//        .initial_packet_count = MS_OS_20_DESCRIPTOR_SET_PACKET_COUNT,
//};
MAKE_USB_TRANSFER_TYPE(ms_os_20_descriptor_set_transfer_type, usb_device_ms_os_20_descriptor_set_on_packet_cb, MS_OS_20_DESCRIPTOR_SET_PACKET_COUNT);
#else
static_assert(MS_OS_20_DESCRIPTOR_SET_PACKET_COUNT == GLOBAL_MS_OS_20_DESCRIPTOR_SET_PACKET_COUNT, "");
#endif

uint32_t msc_get_serial_number32(void) {
    return nsboot_config->chip_id.public_rand_id[1] * 31 + nsboot_config->chip_id.public_rand_id[0];
}

int usb_device_get_descriptor_string_cb(uint index, aligned4_uint8_t *buf64) {
    uint len = 0;
    if (--index < count_of(descriptor_strings)) {
        static_assert(OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_USB_DEVICE_PRODUCT_STRDEF == OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_USB_DEVICE_MANUFACTURER_STRDEF + 1, "");
        static_assert(OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_USB_DEVICE_SERIAL_NUMBER_STRDEF == OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_USB_DEVICE_MANUFACTURER_STRDEF + 2, "");
        // note we use 30 chars not 31 so that the max buffer size is 62 bytes not 64 (which doesn't fit in a single buffer control transfer - which must be <64 bytes to avoid another packet)
        len = white_label_copy_string(buf64 + 2, 0x80 | 30, OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_USB_DEVICE_MANUFACTURER_STRDEF + index , P16_A(descriptor_strings)[index]);
        if (wl_is_unicode(len)) {
            len = (uint8_t)(len << 1); // lop of unicode bit and double len at same time
        } else {
            len <<= 1;
            // ascii we need to copy
            for(uint i=len; i != 0; i-=2) {
                buf64[i] = buf64[i/2+1];
                buf64[i+1] = 0;
            }
        }
    }
//    for(uint i=0;i<len;i+=2) {
//        printf("%04x\n", *(uint16_t*)(buf64 + i + 2));
//    }
    len += 2;
    buf64[0] = (uint8_t)len;
    buf64[1] = 3;
    return (int)len;
}


#if USE_PICOBOOT

void _picoboot_cmd_packet(struct usb_endpoint *ep);

//static const struct usb_transfer_type _picoboot_cmd_transfer_type = {
//        .on_packet = _picoboot_cmd_packet,
//        .initial_packet_count = 1,
//};
MAKE_USB_TRANSFER_TYPE(_picoboot_cmd_transfer_type, _picoboot_cmd_packet, 1);

struct picoboot_cmd_status _picoboot_current_cmd_status;

static void _picoboot_reset(void) {
    usb_debug("PICOBOOT RESET\n");
    static_assert(PICOBOOT_OUT_INDEX == 0, "");
    static_assert(PICOBOOT_IN_INDEX == 1, "");
//    usb_soft_reset_endpoint(&picoboot_out);
//    usb_soft_reset_endpoint(&picoboot_in);
    usb_soft_reset_endpoint2(picoboot_endpoints);
    if (_picoboot_current_cmd_status.bInProgress) {
        printf("command in progress so aborting flash\n");
        sc_or_varm_flash_abort();
    }
    varm_to_native_memset0(&_picoboot_current_cmd_status, sizeof(_picoboot_current_cmd_status));
    // reset queue (note this also clears exclusive access)
    reset_queue(QUEUE_VIRTUAL_DISK);
    reset_queue(QUEUE_PICOBOOT);
}

#if !ASM_SIZE_HACKS
void tf_picoboot_wait_command(__unused struct usb_endpoint *ep, __unused struct usb_transfer *transfer) {
    usb_debug("_tf_picoboot_wait_command\n");
    // todo check this at the end of an OUT ACK
    usb_start_default_transfer_if_not_already_running_or_halted(&picoboot_out);
}
#else
static_assert(picoboot_endpoints == &picoboot_out, "");
void __attribute__((naked)) tf_picoboot_wait_command(__unused struct usb_endpoint *ep, __unused struct usb_transfer *transfer) {
    pico_default_asm_volatile(
            "ldr r0, =picoboot_endpoints\n"
            "b.n usb_start_default_transfer_if_not_already_running_or_halted\n"
            );
}
#endif

void picoboot_ack(void) {
    static struct usb_transfer _ack_transfer;
    _picoboot_current_cmd_status.bInProgress = false;
    usb_start_empty_transfer((_picoboot_current_cmd_status.bCmdId & 0x80u) ? &picoboot_out : &picoboot_in, &_ack_transfer,
                             P16_F(tf_picoboot_wait_command));
}

#define tf_ack ((usb_transfer_completed_func)P16_F(picoboot_ack))

bool picoboot_setup_request_handler(__unused struct usb_interface *interface, struct usb_setup_packet *setup) {
    setup = __builtin_assume_aligned(setup, 4);
    if (USB_REQ_TYPE_TYPE_VENDOR == (setup->bmRequestType & USB_REQ_TYPE_TYPE_MASK)) {
        if (setup->bmRequestType & USB_DIR_IN) {
            if (setup->bRequest == PICOBOOT_IF_CMD_STATUS && setup->wLength == sizeof(_picoboot_current_cmd_status)) {
                uint8_t *buffer = usb_get_single_packet_response_buffer(arch_usb_get_control_in_endpoint(),
                                                                        sizeof(_picoboot_current_cmd_status));
                varm_to_native_memcpy(buffer, &_picoboot_current_cmd_status, sizeof(_picoboot_current_cmd_status));
                usb_start_single_buffer_control_in_transfer();
                return true;
            }
        } else {
            if (setup->bRequest == PICOBOOT_IF_RESET) {
                _picoboot_reset();
                usb_start_empty_control_in_transfer_null_completion();
                return true;
            }
        }
    }
    return false;
}

static struct picoboot_stream_transfer {
    struct usb_stream_transfer stream;
    struct async_task task;
} _picoboot_stream_transfer;

static void _set_cmd_status(uint32_t status) {
    _picoboot_current_cmd_status.dStatusCode = status;
}

static __noinline bool _check_task_failure(struct async_task *task) {
    _set_cmd_status(task->result);
    if (task->result) {
        printf("SHOULD HALT ENDPOINT\n");
        usb_halt_endpoint(_picoboot_stream_transfer.stream.ep);
        // halt the ack transfer too
        if (_picoboot_stream_transfer.stream.ep == &picoboot_in) {
            usb_halt_endpoint(&picoboot_out);
        } else {
            usb_halt_endpoint(&picoboot_in);
        }
        _picoboot_current_cmd_status.bInProgress = false;
        return true;
    }
    return false;
}

void atc_ack(struct async_task *task) {
    if (task->picoboot_user_token == _picoboot_stream_transfer.task.picoboot_user_token) {
        usb_warn("atc_ack\n");
        if (!_check_task_failure(task)) {
            picoboot_ack();
        }
    } else {
        usb_warn("atc for wrong picoboot token %08x != %08x\n", (uint) task->picoboot_user_token,
                 (uint) _picoboot_stream_transfer.task.picoboot_user_token);
    }
}

void atc_chunk_task_done(struct async_task *task) {
    if (task->picoboot_user_token == _picoboot_stream_transfer.task.picoboot_user_token) {
        // save away result
        if (!_check_task_failure(task)) {
            // we update the position of the original task which will be submitted again in on_stream_chunk
            _picoboot_stream_transfer.task.transfer_addr += task->data_length;
        }
        usb_stream_chunk_done(&_picoboot_stream_transfer.stream);
    }
}

bool picoboot_on_stream_chunk(uint32_t chunk_len __comma_removed_for_space(
        struct usb_stream_transfer *transfer)) {
#ifndef NDEBUG
    bootrom_assert(PICOBOOT, transfer == &_picoboot_stream_transfer.stream);
#endif
    bootrom_assert(PICOBOOT, chunk_len <= FLASH_PAGE_SIZE);
    _picoboot_stream_transfer.task.data_length = chunk_len;
    queue_task(QUEUE_PICOBOOT, &_picoboot_stream_transfer.task, P16_F(atc_chunk_task_done));
    // for subsequent tasks, check the mutation source
    _picoboot_stream_transfer.task.check_last_mutation_source = true;
    return true;
}

// size_of_cmd, command to invoke
const uint8_t picoboot_cmd_mapping[]= {
        0, 0, 0,
        sizeof(struct picoboot_exclusive_cmd), 0x00, AT_EXCLUSIVE,
        sizeof(struct picoboot_reboot_cmd), 0x00, AT_EXEC, // note we don't support reboot cmd, so use AT_EXEC which already returns UNKNOWN_CMD
        sizeof(struct picoboot_range_cmd), 0x00, AT_MASKABLE_FLASH_ERASE,
        sizeof(struct picoboot_range_cmd), 0x80, AT_MASKABLE_READ,
        sizeof(struct picoboot_range_cmd), 0x80, AT_MASKABLE_WRITE,
        0, 0x00, AT_MASKABLE_EXIT_XIP,
        0, 0x00, AT_ENTER_CMD_XIP,
        sizeof(struct picoboot_address_only_cmd), 0x00, AT_EXEC,
        sizeof(struct picoboot_address_only_cmd), 0x00, AT_VECTORIZE_FLASH,
        sizeof(struct picoboot_reboot2_cmd), 0x00, 0, // reboot2 command handled directly, so no AT_ command
        sizeof(struct picoboot_get_info_cmd), 0x80 | 0x20 | 0x10, AT_GET_INFO,
        sizeof(struct picoboot_otp_cmd), 0x80 | 0x40 | 0x10, AT_OTP_READ,
        sizeof(struct picoboot_otp_cmd), 0x80 | 0x40 | 0x10, AT_OTP_WRITE,
#if FEATURE_EXEC2
        sizeof(struct picoboot_exec2_cmd), 0x10, AT_EXEC2,
#endif
};

static void _picoboot_cmd_packet_internal(struct usb_endpoint *ep) {
    struct usb_buffer *buffer = usb_current_out_packet_buffer(ep);
    uint len = buffer->data_len;

    struct picoboot_cmd *cmd = (struct picoboot_cmd *) buffer->data;
    if (len == sizeof(struct picoboot_cmd) && cmd->dMagic == PICOBOOT_MAGIC) {
        // pre-init even if we don't need it
        static uint32_t real_token;
        reset_task(&_picoboot_stream_transfer.task);
        _picoboot_stream_transfer.task.token = --real_token; // we go backwards to disambiguate with MSC tasks
        _picoboot_stream_transfer.task.picoboot_user_token = cmd->dToken;
        _picoboot_current_cmd_status.bCmdId = cmd->bCmdId;
        _picoboot_current_cmd_status.dToken = cmd->dToken;
        _picoboot_current_cmd_status.bInProgress = false;
        _set_cmd_status(PICOBOOT_UNKNOWN_CMD);
        _picoboot_stream_transfer.task.transfer_addr = _picoboot_stream_transfer.task.erase_addr = cmd->range_cmd.dAddr;
        _picoboot_stream_transfer.task.erase_size = cmd->range_cmd.dSize;
        _picoboot_stream_transfer.task.exclusive_param = cmd->exclusive_cmd.bExclusive;
        static_assert(
                offsetof(struct picoboot_cmd, range_cmd.dAddr) == offsetof(struct picoboot_cmd, address_only_cmd.dAddr),
                ""); // we want transfer_addr == exec_cmd.addr also
        uint8_t type = 0;
        static_assert(1u == (PC_EXCLUSIVE_ACCESS & 0xfu), "");
        static_assert(2u == (PC_REBOOT & 0xfu), "");
        static_assert(3u == (PC_FLASH_ERASE & 0xfu), "");
        static_assert(4u == (PC_READ & 0xfu), "");
        static_assert(5u == (PC_WRITE & 0xfu), "");
        static_assert(6u == (PC_EXIT_XIP & 0xfu), "");
        static_assert(7u == (PC_ENTER_CMD_XIP & 0xfu), "");
        static_assert(8u == (PC_EXEC & 0xfu), "");
        static_assert(9u == (PC_VECTORIZE_FLASH & 0xfu), "");
        static_assert(10u == (PC_REBOOT2 & 0xfu), "");
        static_assert(11u == (PC_GET_INFO & 0xfu), "");
        static_assert(12u == (PC_OTP_READ & 0xfu), "");
        static_assert(13u == (PC_OTP_WRITE & 0xfu), "");
#if FEATURE_EXEC2
        static_assert(14u == (PC_EXEC2 & 0xfu), "");
#endif
        uint id = cmd->bCmdId & 0x7fu;
        if (id && id < count_of(picoboot_cmd_mapping) / 3) {
            id *= 3;
            const uint8_t *cmd_mapping = P16_A(picoboot_cmd_mapping);
            if (cmd->bCmdSize == cmd_mapping[id]) {
                _set_cmd_status(PICOBOOT_OK);
                uint32_t l = cmd_mapping[id + 1];
                // copy raw command
                if (l & 0x10) {
                    static_assert((offsetof(struct picoboot_cmd, args) & 3) == 0, "");
                    _picoboot_stream_transfer.task.raw_cmd = *(uint32_quad_t *)__builtin_assume_aligned(&cmd->args,4);
                    l &= ~0x10u;
                }
                // includes transfer
                if (l & 0x80u) {
                    if (l & 0x40u) { // is_otp transfer
                        // for now just use a separate flag for OTP commands
                        _picoboot_stream_transfer.task.transfer_addr = 0;
                        l = cmd->otp_cmd.wRowCount * (cmd->otp_cmd.bEcc ? 2u : 4u);
                    } else if (l & 0x20) {
                        // use 0x20 for singe buffer transfer
                        if (cmd->dTransferLength <= 0x100) l = cmd->dTransferLength;
                    } else {
                        l = cmd->range_cmd.dSize;
                    }
                }
                if (l == cmd->dTransferLength) {
                    type = cmd_mapping[id + 2];
                }
                if (cmd->bCmdId == PC_REBOOT2) {
                    if (!sc_or_varm_reboot(cmd->reboot2_cmd.dFlags & ~(uint32_t)REBOOT2_FLAG_NO_RETURN_ON_SUCCESS,
                                           cmd->reboot2_cmd.dDelayMS,
                                           cmd->reboot2_cmd.dParam0,
                                           cmd->reboot2_cmd.dParam1)) {
                        return picoboot_ack();
                    }
                    _set_cmd_status(PICOBOOT_NOT_PERMITTED);
                    goto halt;
                } else if (type) {
                    _picoboot_stream_transfer.task.type = type;
                    _picoboot_stream_transfer.task.source = TASK_SOURCE_PICOBOOT;
                    _picoboot_current_cmd_status.bInProgress = true;
                    if (cmd->dTransferLength) {
                        static __aligned(4) uint8_t _buffer[FLASH_PAGE_SIZE];
#if !USB_USE_TINY_STREAM_TRANSFER_FUNCS
                        const struct usb_stream_transfer_funcs picoboot_stream_funcs = {
                                .on_packet_complete = usb_stream_noop_on_packet_complete,
                                .on_chunk = picoboot_on_stream_chunk
                        };
#else
                        extern const struct usb_stream_transfer_funcs picoboot_stream_funcs;
#endif

                        _picoboot_stream_transfer.task.data = _buffer;

                        // note we want the block size to be at least the size of an OTP page (* 4 for raw mode)
                        static_assert(FLASH_PAGE_SIZE >= NUM_OTP_PAGE_ROWS * 4, "");
                        usb_stream_setup_transfer(&_picoboot_stream_transfer.stream,
                                                  P16_D(picoboot_stream_funcs), _buffer, FLASH_PAGE_SIZE,
                                                  cmd->dTransferLength,
                                                  tf_ack);
                        //if (type & AT_MASKABLE_WRITE) {
                        if (cmd->bCmdId < 0x80) {
                            _picoboot_stream_transfer.stream.ep = &picoboot_out;
                            return usb_chain_transfer(&picoboot_out, &_picoboot_stream_transfer.stream.core);
                        } else {
                            _picoboot_stream_transfer.stream.ep = &picoboot_in;
                            return usb_start_transfer(&picoboot_in, &_picoboot_stream_transfer.stream.core);
                        }
                    }
                    return queue_task(QUEUE_PICOBOOT, &_picoboot_stream_transfer.task, P16_F(atc_ack));
                }
                _set_cmd_status(PICOBOOT_INVALID_TRANSFER_LENGTH);
            } else {
                _set_cmd_status(PICOBOOT_INVALID_CMD_LENGTH);
            }
        }
    }
    halt:
    usb_halt_endpoint(&picoboot_in);
    usb_halt_endpoint(&picoboot_out);
}

void _picoboot_cmd_packet(struct usb_endpoint *ep) {
    _picoboot_cmd_packet_internal(ep);
    varm_to_native_usb_packet_done(ep);
}

#endif

void usb_device_on_configure_cb(struct usb_device *device, bool configured) {
#if !NSBOOT_EXPANDED_RUNTIME || NO_FLASH // can't do this on a flash based nsboot_test build for obvious reasons!
    // kill any in process flash which might be stuck - this will leave flash in bad state
    usb_warn("FLASH ABORT\n");
    sc_or_varm_flash_abort();
#endif
    msc_on_configure(device, configured);
#if USE_PICOBOOT
    if (configured) _picoboot_reset();
#endif
}

#if NSBOOT_WITH_SUBSET_OF_INTERFACES
static struct single_interface_boot_device_config {
    struct usb_configuration_descriptor config_desc;
    struct usb_simple_interface_descriptor interface_desc[1];
} _single_interface_config;
#endif

struct usb_interface *const boot_device_interfaces[] = {
        &msd_interface,
#if USE_PICOBOOT
        &picoboot_interface,
#endif
};

void nsboot_usb_device_init(__unused uint32_t bootsel_flags) {
#if NSBOOT_WITH_SUBSET_OF_INTERFACES
    uint32_t usb_disable_interface_mask = bootsel_flags & 3;
    if (usb_disable_interface_mask == 3)
        usb_disable_interface_mask = 0; // bad things happen if we try to disable both
#else
    const uint32_t usb_disable_interface_mask = 0;
#endif
#if USE_BOOTROM_GPIO
    gpio_setup();
#endif

    // not sure whiy GCC ignores the align attribute on serial_number_string for warnings - it does align it
    char *next_serial = write_msb_hex_chars((char *) serial_number_string, nsboot_config->chip_id.public_rand_id[1], 8);
    write_msb_hex_chars(next_serial, nsboot_config->chip_id.public_rand_id[0], 8);
    const struct boot_device_config *config_desc = __get_opaque_ptr(P16_D(boot_device_config));
    uint picoboot_interface_num = 1;
#if NSBOOT_WITH_SUBSET_OF_INTERFACES
    ms_os_20_descriptor_size = MS_OS_20_COMPOSITE_DESCRIPTOR_SIZE;
    // if we are disabling interfaces
    if (usb_disable_interface_mask) {
        // copy descriptor and MSC descriptor
        varm_to_native_memcpy(&_single_interface_config, config_desc, sizeof(_single_interface_config));
        _single_interface_config.config_desc.wTotalLength = sizeof(_single_interface_config);
        static_assert(sizeof(_single_interface_config) ==
                      sizeof(struct usb_configuration_descriptor) + sizeof(struct usb_simple_interface_descriptor), "");
        if (usb_disable_interface_mask & 1u) {
            picoboot_interface_num = 0;
            ms_os_20_descriptor_size = MS_OS_20_NON_COMPOSITE_DESCRIPTOR_SIZE;
            varm_to_native_memcpy(&_single_interface_config.interface_desc[0], &config_desc->interface_desc[1],
                   sizeof(struct usb_simple_interface_descriptor));
        }
        _single_interface_config.config_desc.bNumInterfaces = 1u;
        _single_interface_config.interface_desc[0].desc.bInterfaceNumber = 0;
        config_desc = (const struct boot_device_config *) &_single_interface_config;
    }
#endif
    if (!(usb_disable_interface_mask & 1u)) {
#if !USB_USE_TWO_ENDPOINT_INTERFACES
        static struct usb_endpoint *const _msc_endpoints[] = {
                msc_endpoints,
                msc_endpoints + 1
        };
        usb_interface_init(&msd_interface, &config_desc->interface_desc[0].desc, _msc_endpoints,
                           count_of(msc_endpoints), true);
#else
        usb_interface_init(&msd_interface, &config_desc->interface_desc[0].desc, msc_endpoints, true);
#endif
        msd_interface.setup_request_handler = P16_F(msc_setup_request_handler);
    }
#if USE_PICOBOOT
    if (!(usb_disable_interface_mask & 2u)) {
#if !USB_USE_TWO_ENDPOINT_INTERFACES
        static struct usb_endpoint *const _picoboot_endpoints[] = {
                &picoboot_out,
                &picoboot_in,
        };
        usb_interface_init(&picoboot_interface, &config_desc->interface_desc[picoboot_interface_num].desc,
                           _picoboot_endpoints, count_of(_picoboot_endpoints), true);
#else
        usb_interface_init(&picoboot_interface, &config_desc->interface_desc[picoboot_interface_num].desc,
                           picoboot_endpoints, true);
#endif
        static struct usb_transfer _picoboot_cmd_transfer;
        _picoboot_cmd_transfer.type = USB_TRANSFER_TYPE_REF(_picoboot_cmd_transfer_type);
        usb_set_default_transfer(&picoboot_out, &_picoboot_cmd_transfer);
        picoboot_interface.setup_request_handler = P16_F(picoboot_setup_request_handler);
    }
#endif

    static_assert(count_of(boot_device_interfaces) == BOOT_DEVICE_NUM_INTERFACES, "");

    struct usb_interface *const * bdi = __get_opaque_ptr(P16_A(boot_device_interfaces));
    // this little gem saves us some net bytes byt stopping (idk!) GCC double-loading boot_device_descriptor and bdi
    pico_default_asm_volatile("nop");
    __unused struct usb_device *device = usb_device_init(P16_D(boot_device_descriptor), &config_desc->config_desc,
                                                         bdi + (usb_disable_interface_mask == 1),
                                                         usb_disable_interface_mask ? 1 : BOOT_DEVICE_NUM_INTERFACES);
    bootrom_assert(USB, device);
    usb_device_start();
}

#if !ASM_SIZE_HACKS
aligned4_uint8_t *usb_get_single_packet_response_buffer(struct usb_endpoint *ep, uint len) {
    struct usb_buffer *buffer = usb_current_in_packet_buffer(ep);
    buffer->data_len = (constrained_usb_buffer_size_t) len;
    bootrom_assert(USB, buffer->data_len == len);
    bootrom_assert(USB, len <= usb_buffer_data_max(buffer));
    return varm_to_native_memset0(buffer->data, len);
}
#else
static_assert(sizeof(((struct usb_buffer *)0)->data_len) == 1, "");
aligned4_uint8_t * __attribute__((naked)) usb_get_single_packet_response_buffer(__unused struct usb_endpoint *ep, __unused uint len) {

    pico_default_asm_volatile(
            "push {r1, lr}\n"
            "bl usb_current_packet_buffer\n"
            "pop {r1, r2}\n"
            "strb r1, [r0, %[buffer_data_len_offset]]\n"
            "ldr r0, [r0, %[buffer_data_offset]]\n"
            "mov lr, r2\n"
            "b.w varm_to_native_memset0\n"
            :
            : [buffer_data_offset] "i" (offsetof(struct usb_buffer, data)),
              [buffer_data_len_offset] "i" (offsetof(struct usb_buffer, data_len))
            );
}
#endif

void __noinline write_at_two_byte_intervals(uint8_t *out, const uint8_t *in, uint count) {
    for(uint i=0;i<count;i++) {
        out[i*2] = in[i];
    }
}

void usb_device_ms_os_20_descriptor_set_on_packet_cb(struct usb_endpoint *ep) {
    struct usb_buffer *buffer = usb_current_in_packet_buffer(ep);
    bootrom_assert(USB, buffer);
    bootrom_assert(USB, usb_buffer_data_max(buffer) == 64);
    // store in local variable, as GCC seems to be treating it as volatile for no good reason I can see.
    aligned4_uint8_t *data = buffer->data;
    struct usb_transfer *transfer = ep->current_transfer;
    bootrom_assert(USB, transfer);
    // note this rather ugly code, combined with the multiple arrays above, is about the same size
    // as the single composite descriptor. this code however also does all the hard work of copying the
    // descriptor, and indeed coping with the two descriptor types.
    varm_to_native_memset0(data, 64);
    uint header_size = ms_os_20_descriptor_size - MS_OS2_REGISTRY_PROPERTY_DESCRIPTOR_SIZE;
    uint src_offset;
    uint dest_offset;
    uint packet = (MS_OS_20_DESCRIPTOR_SET_PACKET_COUNT - transfer->remaining_packets_to_submit);
    if (!packet) {
        // should be handled via ldmia/stmia
#if !COMPRESS_TEXT
        *(struct five_words *)data = ms_os_20_descriptor_set_headers;
        __compiler_memory_barrier();
#else
        poor_mans_text_decompress(P16_A(ms_os_20_descriptor_set_headers_z), ms_os_20_descriptor_set_headers_z_len, data);
        data[16] = 0x9c;
#endif
        data[8] = ms_os_20_descriptor_size;
        // target is not aligned, so can't do anything faster in arm6
        // note MS_OS2_COMPATIBLE_ID_DESCRIPTOR_SIZE is actually bigger than sizeof(ms_os2_compatible_id_descriptor)
        // as the latter does not include trailing zeroes
        varm_to_native_memcpy(data + header_size - MS_OS2_COMPATIBLE_ID_DESCRIPTOR_SIZE, P16_A(ms_os2_compatible_id_descriptor), sizeof(ms_os2_compatible_id_descriptor));
        src_offset = 0;
        dest_offset = header_size;
    } else {
        src_offset = 64 * packet - header_size;
        dest_offset = 0;
    }
    uint copy_len = MIN(64 - dest_offset, MS_OS2_REGISTRY_PROPERTY_DESCRIPTOR_SIZE - src_offset);
    const uint8_t *even_bytes = P16_A(ms_os2_registry_property_descriptor_even_bytes);
    for(uint i = 0; i < copy_len; i += 2) {
        data[i+dest_offset] = even_bytes[(i+src_offset)/2];
    }
    buffer->data_len = (constrained_usb_buffer_size_t)(dest_offset + copy_len);
    varm_to_native_usb_packet_done(ep);
}

