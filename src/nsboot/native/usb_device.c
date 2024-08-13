/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if !defined(__riscv) || FEATURE_RISCV_USB_BOOT
#include "pico.h"
#include "hardware/sync.h"
#include "hardware/structs/usb.h"
#include "usb_device.h"
#include "nsboot_arch_adapter.h"
#include "nsboot_secure_calls.h"
#include "hardware/regs/otp_data.h"

#ifdef USB_LARGE_DESCRIPTOR_SIZE
#include "usb_stream_helper.h"
#endif

// -------------------------------------------------------------------------------------------------------------
// Note this is a small code size focused USB device abstraction, which also avoids using any mutable static
// data so it is easy to include in bootrom.
// -------------------------------------------------------------------------------------------------------------

// =====================================================================
// BEGIN CODE THAT IS COMPILED INTO BOTH ARMv6M AND RISC-V
//
// NOTE: THERE SHOULD BE NO USE OF STATIC DATA that doesn't hold a
// value which is the same in both builds (i.e. no function pointers
// or mutable state)
// =====================================================================


#ifndef USB_MAX_ENDPOINTS
#define USB_MAX_ENDPOINTS USB_NUM_ENDPOINTS
#endif

//#define USB_SINGLE_BUFFERED 1

#define usb_hw_set hw_set_alias(usb_hw)
#define usb_hw_clear hw_clear_alias(usb_hw)

#if !USB_NO_ENDPOINT_CALLBACK_DATA
#define __comma_endpoint_callback_decl(x) , __unused uint32_t x
#define __comma_endpoint_callback_val(x) , x
#else
#define __comma_endpoint_callback_decl(x)
#define __comma_endpoint_callback_val(x)
#endif
#ifndef __riscv
// these are only used by ARMv6M

#if USB_USE_TINY_TRANSFER_TYPE
// need to declare it locally as it is a const int
MAKE_USB_TRANSFER_TYPE(ms_os_20_descriptor_set_transfer_type, usb_device_ms_os_20_descriptor_set_on_packet_cb, GLOBAL_MS_OS_20_DESCRIPTOR_SET_PACKET_COUNT);
#endif

static struct {
    uint16_t otp_row; // otp location of WHITE_LABEL structure
    uint16_t valid_bits; // valid bits (note we only have 16, so beware if more white label entries are added)
} white_label;

// BOS descriptor with platform capability descriptor
const uint8_t bos_descriptor[0x21] = {
// BOS descriptor
        0x05, // Descriptor size (5 bytes)
        0x0F, // Descriptor type (BOS)
        0x21, 0x00, // Length of this + subordinate descriptors // (33 bytes)
        0x01, // Number of subordinate descriptors
// Microsoft OS 2.0 Platform Capability Descriptor
        0x1C, // Descriptor size (28 bytes)
        0x10, // Descriptor type (Device Capability)
        0x05, // Capability type (Platform)
        0x00, // Reserved
// MS OS 2.0 Platform Capability ID (D8DD60DF-4589-4CC7-9CD2-659D9E648A9F)
        0xDF, 0x60, 0xDD, 0xD8,
        0x89, 0x45,
        0xC7, 0x4C,
        0x9C, 0xD2,
        0x65, 0x9D, 0x9E, 0x64, 0x8A, 0x9F,
        0x00, 0x00, 0x03, 0x06, // Windows version (8.1) (0x06030000)
        // note: this is annoying; current windows is quite happy if we just use the bigger of our two values,
        //      which saves us a bit of code, but it is exactly the sort of thing that might break in the future!
        0x00, 0x00, // size of MS OS 2.0 descriptor (we will fill in later)
        0x01, // Vendor-assigned bMS_VendorCode
        0x00 // Doesn’t support alternate enumeration
};

/**
 * Public ep 0 IN/OUT
 */
struct usb_endpoint control_endpoints[2];
struct usb_endpoint *non_control_endpoints[USB_MAX_ENDPOINTS];

__force_inline struct usb_endpoint **native_usb_get_endpoints(void) {
    return non_control_endpoints;
}

__force_inline struct usb_endpoint *native_usb_get_control_endpoints(void) {
    return &control_endpoints[0];
}
#endif

#if ENABLE_DEBUG_TRACE
#ifdef __riscv
#error not supported
#endif
static uint32_t debug_trace[128][2];
static volatile uint32_t trace_i;
#endif

#if MINI_PRINTF
static inline const char *_in_out_string(bool in) {
    return in ? "IN" : "OUT";
}

const char *usb_endpoint_dir_string(struct usb_endpoint *ep) {
    return _in_out_string(ep->in);
}
#endif


/**
 * @param ep
 * @return a 32 bit pointer to both buffer control registers for an endpoint
 */
#if GENERAL_SIZE_HACKS && !defined(__riscv)
static io_rw_32 *_usb_buf_ctrl_wide(const struct usb_endpoint *ep) {
    uint32_t in = ep->in;
    uint32_t num = ep->num * 8;
    io_rw_32 *p = &usb_dpram->ep_buf_ctrl[0].out;
    pico_default_asm(
            "add %0, %2\n"
            "cbz %1, 1f\n"
            "subs %0, #4\n"
            "1:\n"
            : "+&l" (num) : "l" (in), "r" (p)
            : "cc"
    );
    return (io_rw_32 *)num; // keep using r0
}
#else
static io_rw_32 *_usb_buf_ctrl_wide(const struct usb_endpoint *ep) {
    return ep->in ? &usb_dpram->ep_buf_ctrl[ep->num].in : &usb_dpram->ep_buf_ctrl[ep->num].out;
}
#endif

/**
 * @param ep
 * #param which 0 or 1 double-buffer index
 * @return a 16 bit pointer to the specified (1 of 2) buffer control register for an endpoint
 */
static io_rw_16 *_usb_buf_ctrl_narrow(const struct usb_endpoint *ep, uint which) {
    return &((io_rw_16 *) _usb_buf_ctrl_wide(ep))[which];
}

#if !GENERAL_SIZE_HACKS || defined(__riscv) || !USB_USE_TINY_TRANSFER_TYPE
void usb_call_on_packet(struct usb_endpoint *ep) {
    struct usb_transfer *current_transfer = ep->current_transfer;
    bootrom_assert(USB, current_transfer);
    bootrom_assert(USB, !current_transfer->outstanding_packet);
//    printf(__XSTRING(arm_or_riscv_impl()) " XXX call on packet sets %08x(%d %d) %08x op to 1\n", ep, ep->num, ep->in, current_transfer);
    current_transfer->outstanding_packet = true;
    //__rom_function_deref(usb_transfer_func, current_transfer->type->on_packet)(ep);
    call_arm_fp1(usb_transfer_type_on_packet(current_transfer->type), ep);
}
#else
static_assert(sizeof(usb_transfer_type_ref_t) == 4, "");
void __attribute__((naked)) usb_call_on_packet(__unused struct usb_endpoint *ep) {
    pico_default_asm_volatile(
        "ldr r3, [r0, %[current_transfer]]\n"
        "movs r2, #1\n"
        "strb r2, [r3, %[outstanding_packet]]\n"
        "ldr r3, [r3, %[type]]\n"
        "lsls r3, r2\n"
#if !USE_16BIT_POINTERS
        "ldr r2, =usb_transfer_types\n"
#else
        "movw r2, %[p16_usb_transfer_types]\n"
#endif
        "ldrh r2, [r2, r3]\n"
        "bx r2\n"
        :
        : [current_transfer] "i" (offsetof(struct usb_endpoint, current_transfer)),
          [outstanding_packet] "i" (offsetof(struct usb_transfer, outstanding_packet)),
#if USE_16BIT_POINTERS
          [p16_usb_transfer_types] "i" (P16_CONSTANT(usb_transfer_types)),
#endif
          [type] "i" (offsetof(struct usb_transfer, type))
    );
#if 0
    struct usb_transfer *current_transfer = ep->current_transfer;
    bootrom_assert(USB, current_transfer);
    bootrom_assert(USB, !current_transfer->outstanding_packet);
//    printf(__XSTRING(arm_or_riscv_impl()) " XXX call on packet sets %08x(%d %d) %08x op to 1\n", ep, ep->num, ep->in, current_transfer);
    current_transfer->outstanding_packet = true;
    //__rom_function_deref(usb_transfer_func, current_transfer->type->on_packet)(ep);
    call_arm_fp1(usb_transfer_type_on_packet(current_transfer->type), ep);
#endif
}
#endif

static void _usb_give_buffer(struct usb_endpoint *ep, uint32_t len) {
    bootrom_assert(USB, ep->owned_buffer_count);
    bootrom_assert(USB, ep->current_transfer);
    bootrom_assert(USB, !ep->halt_state);
    ep->halt_state = HS_NONE; // best effort recovery

    bootrom_assert(USB, len < 1023);
    uint32_t val = len | USB_BUF_CTRL_AVAIL;

    if (ep->first_buffer_after_reset) {
        bootrom_assert(USB, !ep->current_give_buffer);
        val |= USB_BUF_CTRL_SEL;
        ep->first_buffer_after_reset = false;
    }

    bootrom_assert(USB, len <= usb_endpoint_buffer_size(ep));
    if (ep->in) val |= USB_BUF_CTRL_FULL;
    val |= ep->next_pid ? USB_BUF_CTRL_DATA1_PID : USB_BUF_CTRL_DATA0_PID;
    ep->next_pid ^= 1u;
#if ENABLE_DEBUG_TRACE
    debug_trace[trace_i][0] = (uint32_t) _usb_buf_ctrl_narrow(ep, ep->current_give_buffer);
    debug_trace[trace_i][1] = val;
    trace_i++;
    if (trace_i == 128) {
        trace_i = 0;
    }
#endif

#if !USB_BULK_ONLY_EP1_THRU_16
    if (ep->current_give_buffer)
    {
        val |= USB_ISOCHRONOUS_BUFFER_STRIDE_TYPE << 11u; // 11 + 16 = 27 - which is where stride bits go (and only relevant on buffer 1)
    }
#endif

    *_usb_buf_ctrl_narrow(ep, ep->current_give_buffer) = (uint16_t) val;
    if (ep->in) {
        // if there is a buffer len, then it must have been accessed to fill it with data
        bootrom_assert(USB, !len || ep->current_hw_buffer.valid);
    }

    ep->current_hw_buffer.valid = false;
    ep->owned_buffer_count--;
    ep->current_transfer->remaining_packets_to_submit--;
    if (ep->double_buffered) {
        ep->current_give_buffer ^= 1u;
//        usb_debug("toggle current give buffer %d %s to %d\n", ep->num, usb_endpoint_dir_string(ep), ep->current_give_buffer);
    }
}

// If we own buffers, we try and transfer them to the hardware (either by filling packets via on_packet for
// IN or by passing empty buffers for out)
void __used _usb_give_as_many_buffers_as_possible(struct usb_endpoint *ep) {
    usb_debug(__XSTRING(arm_or_riscv_impl(_usb_give_as_many_buffers_as_possible))"\n");
    while (ep->current_transfer && ep->current_transfer->remaining_packets_to_submit && ep->owned_buffer_count &&
           !ep->halt_state) {
        if (ep->in) {
            uint old = ep->owned_buffer_count;
            usb_call_on_packet(ep);
            if (old == ep->owned_buffer_count) {
                // on_packet did not yet submit anything
                break;
            }
        } else {
            if (ep->current_transfer->outstanding_packet) {
                usb_warn("untested? give buffer with outstanding packet %d %s owned %d\n", ep->num,
                         usb_endpoint_dir_string(ep), ep->owned_buffer_count);
            }
            _usb_give_buffer(ep, ep_buffer_size(ep));
        }
    }
}

#if !ASM_SIZE_HACKS || defined(__riscv)
#ifndef __riscv
__noinline // seems smaller this way on ARM
#endif
void usb_start_transfer(struct usb_endpoint *ep, struct usb_transfer *transfer) {
    bootrom_assert(USB, !ep->current_transfer);
    ep->current_transfer = transfer;
    ep->chain_transfer = NULL;
    bootrom_assert(USB, transfer);
    bootrom_assert(USB, !transfer->started);
    transfer->started = true;
    bootrom_assert(USB, usb_transfer_type_on_packet(transfer->type));
    // currently we explicity disallow these rather than ending immediately.
    bootrom_assert(USB, transfer->remaining_packets_to_submit);
    bootrom_assert(USB, transfer->remaining_packets_to_handle);
#if !USB_NO_TRANSFER_ON_INIT
    if (transfer->type->on_init) {
        transfer->type->on_init(transfer, ep);
    }
#endif
    _usb_give_as_many_buffers_as_possible(ep);
}
#else
static_assert(sizeof(((struct usb_endpoint *)0)->current_transfer) == 4, "");
static_assert(sizeof(((struct usb_endpoint *)0)->chain_transfer) == 4, "");
static_assert(sizeof(((struct usb_transfer *)0)->started) == 1, "");
void __attribute__((naked)) usb_start_transfer(__unused struct usb_endpoint *ep, __unused struct usb_transfer *transfer) {
    pico_default_asm_volatile(
            "str r1, [r0, %[current_transfer]]\n"
            "movs r2, #0\n"
            "str r2, [r0, %[chain_transfer]]\n"
            "movs r2, #1\n"
            "strb r2, [r1, %[started]]\n"
            // fall thru "b.n _usb_give_as_many_buffers_as_possible\n"
            ".global usb_start_transfer_end\n"
            "usb_start_transfer_end:\n"
            :
            : [current_transfer] "i" (offsetof(struct usb_endpoint, current_transfer)),
              [chain_transfer] "i" (offsetof(struct usb_endpoint, chain_transfer)),
              [started] "i" (offsetof(struct usb_transfer, started))
            );
}
#endif

static void __noinline _usb_check_for_transfer_completion(struct usb_endpoint *ep) {
    struct usb_transfer *transfer = ep->current_transfer;
    bootrom_assert(USB, transfer);
    if (ep->halt_state || !(transfer->remaining_packets_to_handle || transfer->outstanding_packet)) {
        bootrom_assert(USB, !transfer->completed);
        transfer->completed = true;
        // size: avoid sw zero, (xx) on RISC-V which is a 32-bit encoding (prefer li; sw)
        uintptr_t zero = __get_opaque_value((uintptr_t)0);
        ep->current_transfer = (void*)zero;
        if (ep->halt_state) {
            if (transfer->on_complete) {
                usb_warn("untested? stall of transfer with on_complete set %d %s %p\n", ep->num,
                         usb_endpoint_dir_string(ep), transfer->on_complete);
            }
            transfer->remaining_packets_to_submit = transfer->remaining_packets_to_handle = zero;
            return;
        }
        if (transfer->on_complete) {
            bootrom_assert(USB, !ep->chain_transfer);
            usb_debug("calling on complete\n");
            call_arm_fp2(transfer->on_complete, ep, transfer);
        } else if (ep->chain_transfer) {
            usb_debug("chaining transfer\n");
            usb_start_transfer(ep, ep->chain_transfer);
        }
    } else if (!transfer->remaining_packets_to_handle) {
        usb_debug("outstanding packet %d on %d %s\n", transfer->outstanding_packet, ep->num,
                  usb_endpoint_dir_string(ep));
    }
}

static uint16_t _usb_endpoint_stride(__unused struct usb_endpoint *ep) {
#if !USB_BULK_ONLY_EP1_THRU_16
    return ep->buffer_stride;
#else
    return 64;
#endif
}

struct usb_buffer *usb_current_packet_buffer(struct usb_endpoint *ep) {
    struct usb_buffer *packet = &ep->current_hw_buffer;
    if (!packet->valid) {
#if !USB_ALL_ENDPOINTS_MAX_PACKET_SIZE
        packet->data_max = (constrained_usb_buffer_size_t)ep_buffer_size(ep);
#endif
        bootrom_assert(USB, usb_buffer_data_max(packet) == usb_endpoint_buffer_size(ep));
        static_assert(offsetof(struct usb_endpoint, current_take_buffer) == offsetof(struct usb_endpoint, current_buffers), "");
        static_assert(offsetof(struct usb_endpoint, current_give_buffer) == offsetof(struct usb_endpoint, current_buffers) + 1, "");
        uint which = ep->current_buffers[ep->in];
        if (ep->in) {
            bootrom_assert(USB, !(USB_BUF_CTRL_FULL & *_usb_buf_ctrl_narrow(ep, which)));
            packet->data_len = 0;
        } else {
            bootrom_assert(USB, (USB_BUF_CTRL_FULL & *_usb_buf_ctrl_narrow(ep, which)));
            packet->data_len = (constrained_usb_buffer_size_t)(USB_BUF_CTRL_LEN_MASK & *_usb_buf_ctrl_narrow(ep, which));
        }
        packet->data = ((uint8_t *) (USBCTRL_DPRAM_BASE + ep->dpram_buffer_offset + which * _usb_endpoint_stride(ep)));
        packet->valid = true;
        //usb_debug("getting buffer for endpoint %02x %s %p: buf_ctrl %d -> %04x\n", usb_endpoint_number(ep), usb_endpoint_dir_string(ep), packet->data, which, *_usb_buf_ctrl_narrow(ep, which));
    }
    return packet;
}

/**
 * Stall the given endpoint
 *
 * @param ep
 */
void usb_stall_endpoint(struct usb_endpoint *ep, enum usb_halt_state hs) {
    bootrom_assert(USB, hs);
    __unused enum usb_halt_state old_hs = ep->halt_state;
    if (!ep->halt_state) {
        if (ep->num == 0) {
            // A stall on EP0 has to be armed so it can be cleared on the next setup packet
            usb_hw_set->ep_stall_arm = ep->in ? USB_EP_STALL_ARM_EP0_IN_BITS : USB_EP_STALL_ARM_EP0_OUT_BITS;
        }
        *_usb_buf_ctrl_wide(ep) |= USB_BUF_CTRL_STALL;
        ep->halt_state = hs;
        if (ep->on_stall_change) ep->on_stall_change(ep);
    } else {
        // we should be stalled
        bootrom_assert(USB, USB_BUF_CTRL_STALL & *_usb_buf_ctrl_wide(ep));
        if (hs > ep->halt_state) ep->halt_state = hs;
    }
    usb_debug("Stall %d %s %d->%d\n", ep->num, usb_endpoint_dir_string(ep), old_hs, hs);
}

#if !GENERAL_SIZE_HACKS || defined(__riscv)
void usb_halt_endpoint(struct usb_endpoint *ep) {
    usb_stall_endpoint(ep, HS_HALTED);
};
#else
static_assert(HS_HALTED == 2, "");
void __noinline __attribute__((naked)) usb_halt_endpoint(__unused struct usb_endpoint *ep) {
    pico_default_asm_volatile("movs r1, #2\n"
                              "nop\n");
    // fall thru to _usb_stall_endpoint();
}
#endif

static void _usb_handle_transfer(uint ep_num, bool in, uint which) {
    usb_debug(__XSTRING(arm_or_riscv_impl(_usb_handle_transfer))"\n");
    struct usb_endpoint *ep;
    bootrom_assert(USB, ep_num < USB_MAX_ENDPOINTS);
    if (ep_num) {
        ep = arch_usb_get_endpoints()[ep_num];
    } else {
        ep = in ? arch_usb_get_control_in_endpoint() : arch_usb_get_control_out_endpoint();
    }
    bootrom_assert(USB, ep); // "Received buffer IRQ for unknown EP");
    ep->owned_buffer_count++;
    struct usb_transfer *transfer = ep->current_transfer;
    if (!transfer) {
        usb_warn("received unexpected packet on %d %s\n", ep->num, usb_endpoint_dir_string(ep));
        return usb_halt_endpoint(ep);
    }
    bootrom_assert(USB, !ep->halt_state);
    bootrom_assert(USB, transfer->remaining_packets_to_handle);
    if (transfer->outstanding_packet) {
        usb_debug("re-enter %d %s which=%d\n", ep->num, usb_endpoint_dir_string(ep), which);
//        printf(__XSTRING(arm_or_riscv_impl()) " WTF ep=%08x trans=%08x rps %d rph %d op %d pq %d st %d cp %d\n", ep, ep->current_transfer, ep->current_transfer->remaining_packets_to_submit,
//                ep->current_transfer->remaining_packets_to_handle, ep->current_transfer->outstanding_packet, ep->current_transfer->packet_queued,
//                ep->current_transfer->started, ep->current_transfer->completed);
        bootrom_assert(USB, ep->double_buffered);
        bootrom_assert(USB, which != ep->current_take_buffer);
        transfer->packet_queued = true;
    } else {
        ep->current_take_buffer = (uint8_t)which;
        // we only called on_packet for submit-able packets for an in transfer
        if (!ep->in || transfer->remaining_packets_to_submit) {
            usb_call_on_packet(ep);
        }
        // transfer might already be completed during on_packet() if we stalled.
        if (!transfer->completed) {
            bootrom_assert(USB, transfer->remaining_packets_to_handle);
            --transfer->remaining_packets_to_handle;
            _usb_check_for_transfer_completion(ep);
        }
    }
}

// native ctz (we want to use m33 even on
static __force_inline uint native_ctz(uint32_t val) {
#ifdef __riscv
    return (uint)__builtin_ctz(val);
#else
    uint tmp;
    pico_default_asm(
            ".cpu cortex-m33\n"
            "rbit %0, %1\n"
            "clz %0, %0\n"
            : "=r" (tmp): "r" (val)
            );
    return tmp;
#endif
}

void native_usb_handle_buffer(void) {
    uint32_t remaining_buffers = usb_hw->buf_status;

    if (!remaining_buffers) {
        usb_debug("_usb_handle_buffer called without any buffers set\n");
    }

    // do this for now could be smarter
    while (remaining_buffers) {
        uint i = native_ctz(remaining_buffers);
        uint32_t bit = 1u << i;
        uint which = (usb_hw->buf_cpu_should_handle & bit) ? 1 : 0;
        // clear this in advance
        usb_hw_clear->buf_status = bit;
        // IN transfer for even i, OUT transfer for odd i
        _usb_handle_transfer(i >> 1u, !(i & 1u), which);
        remaining_buffers &= ~bit;
    }
    // note this is no longer possible; the only way it was possible for the old code which looped over the endpoints
    // was if there was a buffer for an endpoint >=USB_MAX_ENDPOINTS, so was pretty pointless
    if (remaining_buffers) {
        usb_debug("Ignoring buffer event for impossible mask %08x\n", (uint) remaining_buffers);
        usb_hw_clear->buf_status = remaining_buffers;
    }
}

void __attribute__((used)) native_usb_packet_done(struct usb_endpoint *ep) {
    usb_debug(__XSTRING(arm_or_riscv_impl(usb_packet_done)) " %08x\n", (uintptr_t)ep);
    struct usb_buffer *buffer = &ep->current_hw_buffer;
    bootrom_assert(USB, buffer == &ep->current_hw_buffer);
    struct usb_transfer *transfer = ep->current_transfer;
    // this can happen if the host goes away
    if (!transfer) return;
    //bootrom_assert(USB, transfer);
    bootrom_assert(USB, transfer->outstanding_packet);
    usb_debug(__XSTRING(arm_or_riscv_impl()) " XXX packet done %08x(%d %d) %08x op to 0\n", (int)ep, ep->num, ep->in, (uintptr_t)ep->current_transfer);
    transfer->outstanding_packet = false;
    _usb_check_for_transfer_completion(ep);
    if (!transfer->completed) {
        //    usb_debug("buffer done for endpoint %02x %s %d/%d\n", usb_endpoint_number(ep), usb_endpoint_dir_string(ep),
        //              buffer->data_len, buffer->data_max);
        if (ep->in) {
            bootrom_assert(USB, buffer->valid);
            bootrom_assert(USB, buffer->data_len <= usb_endpoint_buffer_size(ep));
            _usb_give_buffer(ep, buffer->data_len);
        }
        ep->current_hw_buffer.valid = false;

        if (transfer->packet_queued) {
            bootrom_assert(USB, ep->double_buffered);
            usb_debug("Toggling current take buffer to %d and sending deferred packet %d %s\n",
                      ep->current_take_buffer ^ 1u, ep->num,
                      usb_endpoint_dir_string(ep));
            transfer->packet_queued = false;
            ep->owned_buffer_count--; // todo this is a bit of a hack because the function increments it a second time - maybe pass a param
            _usb_handle_transfer(ep->num, ep->in, ep->current_take_buffer ^ 1u);
        } else {
            // we may now need to top up double buffer;
            // note this call may cause recursion back into this function
            _usb_give_as_many_buffers_as_possible(ep);
        }
    }
    usb_debug(__XSTRING(arm_or_riscv_impl(usb_packet_done)) "returns");
}

// =====================================================================
// BEGIN CODE/DATA THAT IS ARMv6M ONLY
// =====================================================================

#ifndef __riscv

// note we treat all errors the same (we just ignore)
#define USB_INTS_ERROR_BITS ( \
    USB_INTS_ERROR_DATA_SEQ_BITS      |  \
    USB_INTS_ERROR_BIT_STUFF_BITS     |  \
    USB_INTS_ERROR_CRC_BITS           |  \
    USB_INTS_ERROR_RX_OVERFLOW_BITS   |  \
    USB_INTS_ERROR_RX_TIMEOUT_BITS)

// define some macros so we implement different allocation schemes (right now we use bootrom which is no-alloc and assume zero)
#if !USB_ASSUME_ZERO_INIT
#define usb_init_clear_deref(x) varm_to_native_memset0(x, sizeof(*(x)))
#else
#define usb_init_clear_deref(x) ((void)0)
#endif
#define usb_common_init(x) ({ bootrom_assert(USB, x); usb_init_clear_deref(x);  x; })


//const struct usb_transfer_type usb_current_packet_only_transfer_type = {
//        .on_packet = _usb_transfer_current_packet_only,
//        .initial_packet_count = 1,
//};
MAKE_USB_TRANSFER_TYPE(usb_current_packet_only_transfer_type, usb_transfer_current_packet_only, 1);

#ifndef __riscv
#ifdef USB_LARGE_DESCRIPTOR_SIZE
static struct usb_stream_transfer _control_in_stream_transfer;
#define _control_in_transfer _control_in_stream_transfer.core
#else
static struct usb_transfer _control_in_transfer;
#endif
static __used struct usb_transfer _control_out_transfer;

static struct usb_device _device;

#endif
static uint8_t _ep_buffer_count(const struct usb_endpoint *ep) {
    return ep->double_buffered ? 2 : 1;
}

#ifndef NDEBUG
static void _usb_dump_eps(void)
{
    printf("\n");
    for (int num = 1; num < USB_MAX_ENDPOINTS; num++) {
        for(int b = 0; b < 2; b++)
        {
            struct usb_endpoint *ep = non_control_endpoints[num];
            uint16_t ctrl = (uint16_t) *_usb_buf_ctrl_narrow(ep, b);
            uint8_t pid = (ctrl & USB_BUF_CTRL_DATA1_PID) ? 1 : 0;
            printf("ep %d %s <= 0x%04x (DATA%d", ep->num,  usb_endpoint_dir_string(ep), ctrl, pid);
            if (ctrl & USB_BUF_CTRL_FULL)
            { printf(", FULL"); }
            if (ctrl & USB_BUF_CTRL_LAST)
            { printf(", LAST"); }
            if (ctrl & USB_BUF_CTRL_SEL)
            { printf(", SEL"); }
            printf(", LEN = %04x)\r\n", ctrl & USB_BUF_CTRL_LEN_MASK);
        }
    }
    usb_reset_trace();
}
#endif

/**
 * Reset the buffers for an endpoint to CPU ownership, aborting the buffers if necessary
 * @param ep
 */
void usb_reset_buffers(struct usb_endpoint *ep) {
    uint32_t mask = 1u << ep->buffer_bit_index;
    static_assert((USBCTRL_REGS_BASE & ((1<<12)-1)) == 0, "");
    uintptr_t usb_hw_hi = __get_opaque_value(USBCTRL_REGS_BASE >> 12);
    usb_hw_t *_usb_hw = (usb_hw_t *) (uintptr_t)(usb_hw_hi << 12);
    usb_hw_t *_usb_hw_clear = (usb_hw_t *) (uintptr_t)((usb_hw_hi + (REG_ALIAS_CLR_BITS>>12)) << 12);
    usb_hw_t *_usb_hw_set = (usb_hw_t *) (uintptr_t)((usb_hw_hi + (REG_ALIAS_SET_BITS>>12)) << 12);

    if ((USB_BUF_CTRL_AVAIL * 0x10001) & *_usb_buf_ctrl_wide((ep))) {
        usb_debug("Must abort buffers %d %s owned=%d %08x!!!\n", ep->num, usb_endpoint_dir_string(ep),
                  ep->owned_buffer_count, (uint) *_usb_buf_ctrl_wide(
                ep));
        // if the hardware owns 1 buffer, then when we reset we toggle the pid (in double-buffer mode it could own two)
        if (!ep->double_buffered || ep->owned_buffer_count == 1) {
            usb_debug("Toggling PID as buffers restored");
            ep->next_pid ^= 1u;
        }
        usb_dump_trace();
        // note we don't clear abort done here as there is no reason it should ever have been set
        // and doing so at this point doesn't actually help because it takes an unkown number of cycles
        // usb_hw_clr->abort = mask;
        _usb_hw_set->abort = mask;
        // being massively overly defensive here; we are not aware of any cases where abort done may not get
        // set, however in the spirit of not hanging the chip, we prefer a (comparatively in USB times, lengthy)
        // timeout.
        // This should leave us in a good state as the host has likely given up, and the buf ctrl clear below
        // will be done without any active state on the endpoint. What the host does if we were to timeout,
        // we don't know (it depends what it was doing when it chose to reset us), however we will
        // at least be back in a good state.
        int count = 1u<<16u; // approx 4800000/8*65536 = 10ms
        while (!(_usb_hw->abort_done & mask) && --count);
    }
    *_usb_buf_ctrl_wide(ep) = USB_BUF_CTRL_SEL; // 1u << 12;
    // HW requires us to clear abort before abort done
    _usb_hw_clear->abort = mask;
    _usb_hw_clear->abort_done = mask;
    ep->owned_buffer_count = _ep_buffer_count(ep);
    usb_debug("clear current buffer %d %s\n", ep->num, usb_endpoint_dir_string(ep));
    ep->current_give_buffer = ep->current_take_buffer = 0;
    ep->first_buffer_after_reset = true;
}

#ifndef __riscv
/**
 * Initialize any endpoint (0 or user defined)
 * @param ep
 * @param num
 * @param in
 * @param max_buffer_size
 * @param double_buffered
 * @return
 */
#if !USB_USE_TINY_ENDPOINT_INIT
static __noinline struct usb_endpoint *_usb_endpoint_init_internal(struct usb_endpoint *ep,
                                                                   uint num,
                                                                   bool in,
#if !USB_ALL_ENDPOINTS_MAX_PACKET_SIZE
                                                                   uint max_buffer_size,
#endif
                                                                   bool double_buffered) {
    // for some inling of memset reason, removing this makes the code larger!
    usb_common_init(ep);
    ep->num = (uint8_t)num;
    ep->in = in;
#if !USB_ALL_ENDPOINTS_MAX_PACKET_SIZE
    ep->buffer_size = (uint16_t)max_buffer_size;
#endif
#if !USB_SINGLE_BUFFERED
    ep->double_buffered = double_buffered;
#endif
#if !USB_BULK_ONLY_EP1_THRU_16
    ep->buffer_stride = 64;
#endif
    ep->buffer_bit_index = (uint8_t) ((num * 2u) + (in ? 0u : 1u));
    return ep;
}
#else
#if !USB_ALL_ENDPOINTS_MAX_PACKET_SIZE || !USB_ALL_ENDPOINTS_MAX_PACKET_SIZE || !USB_BULK_ONLY_EP1_THRU_16
#error camt use USB_USE_TINY_ENDPOINT_INIT because of other settings
#endif
static struct usb_endpoint *_usb_endpoint_init_internal(struct usb_endpoint *ep,
                                                                   uint num,
                                                                   bool in,
                                                                   bool double_buffered) {
    // for some inling of memset reason, removing this makes the code larger!
    usb_common_init(ep);
    static_assert(offsetof(struct usb_endpoint, num) == 0, "");
    static_assert(offsetof(struct usb_endpoint, double_buffered) == 1, "");
    static_assert(offsetof(struct usb_endpoint, in) == 2, "");
    static_assert(offsetof(struct usb_endpoint, buffer_bit_index) == 3, "");
    ep->init_word = ((uint32_t)(uint8_t)num) | ((uint32_t)double_buffered << 8u) | ((uint32_t)in << 16u) | (((num * 2u) + (in ? 0u : 1u)) << 24u);
    return ep;
}
#endif
#endif

#ifndef __riscv

void usb_endpoint_hw_init(struct usb_endpoint *ep __comma_endpoint_callback_decl(data))
{
    // ep->num should already be initialized (so no need to call usb_endpoint_number which gets it from the descriptor)
    uint ep_num = ep->num;
    bootrom_assert(NSBOOT, ep_num == usb_endpoint_number(ep));
    volatile uint32_t * const ep_buf_ctrl = &usb_dpram->ep_buf_ctrl[ep_num].in;
#if !GENERAL_SIZE_HACKS
    usb_dpram->ep_buf_ctrl[ep_num].in = 0;
    usb_dpram->ep_buf_ctrl[ep_num].out = 0;
#else
    static_assert(offsetof(struct usb_device_dpram_ep_buf_ctrl, in) == 0, "");
    static_assert(offsetof(struct usb_device_dpram_ep_buf_ctrl, out) == 4, "");
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align" // there is no 64 bit write in M33
    ep_buf_ctrl[0] = ep_buf_ctrl[1] = 0;
//    *(volatile uint64_t *) (&usb_dpram->ep_buf_ctrl[ep_num].in) = 0;
#pragma GCC diagnostic pop
#endif
    ep->dpram_buffer_offset = _device.next_buffer_offset;
    usb_debug("endpoint %d %s buf at %04x %04xx%d\n", ep_num, usb_endpoint_dir_string(ep), ep->dpram_buffer_offset,
              64, _ep_buffer_count(ep));
    uint16_t stride = _usb_endpoint_stride(ep);
#if !GENERAL_SIZE_HACKS
    _device.next_buffer_offset += stride * _ep_buffer_count(ep);
#else
    stride <<= ep->double_buffered;
    _device.next_buffer_offset += stride;
#endif
    bootrom_assert(USB, _device.next_buffer_offset <= USB_DPRAM_MAX);
    if (ep_num) {
#if !GENERAL_SIZE_HACKS || !USB_BULK_ONLY_EP1_THRU_16
        uint32_t reg = EP_CTRL_ENABLE_BITS
                       | (ep->double_buffered ? EP_CTRL_DOUBLE_BUFFERED_BITS : 0u)
                       | EP_CTRL_INTERRUPT_PER_BUFFER
                       //| EP_CTRL_INTERRUPT_ON_NAK
//                       | EP_CTRL_INTERRUPT_ON_STALL
                       | ep->dpram_buffer_offset
#if !USB_BULK_ONLY_EP1_THRU_16
                       | (ep->descriptor->bmAttributes << EP_CTRL_BUFFER_TYPE_LSB);
#else
                       | (USB_TRANSFER_TYPE_BULK << EP_CTRL_BUFFER_TYPE_LSB);
        bootrom_assert(USB, ep->descriptor->bmAttributes == USB_TRANSFER_TYPE_BULK);
#endif
#else
        static_assert(EP_CTRL_ENABLE_BITS >> 25u, "");
        static_assert(EP_CTRL_INTERRUPT_PER_BUFFER >> 25u, "");
        static_assert(EP_CTRL_DOUBLE_BUFFERED_BITS >> 25u, "");
        static_assert(EP_CTRL_BUFFER_TYPE_LSB >= 25u, "");
        bootrom_assert(USB, ep->descriptor->bmAttributes == USB_TRANSFER_TYPE_BULK);
        // weird... the compiler doesn't actually do this, but still produces better code than the above!
        uint32_t reg = (EP_CTRL_ENABLE_BITS | EP_CTRL_INTERRUPT_PER_BUFFER |
                        (USB_TRANSFER_TYPE_BULK << EP_CTRL_BUFFER_TYPE_LSB)) >> 25u;
        if (ep->double_buffered) reg += (EP_CTRL_DOUBLE_BUFFERED_BITS) >> 25u;
        reg = (reg << 25u) + ep->dpram_buffer_offset;
#endif
        // todo coordinate with buff control
#if !GENERAL_SIZE_HACKS
        if (ep->in) {
            usb_dpram->ep_ctrl[ep_num - 1].in = reg;
            usb_dpram->ep_ctrl[ep_num - 1].out = 0;
        } else {
            usb_dpram->ep_ctrl[ep_num - 1].in = 0;
            usb_dpram->ep_ctrl[ep_num - 1].out = reg;
        }
#else
        uint32_t reg0 = reg * ep->in;
        static_assert(offsetof(usb_device_dpram_t, ep_ctrl) == offsetof(usb_device_dpram_t, ep_buf_ctrl) - 8 * 15, "");
        static_assert(offsetof(usb_device_dpram_t, ep_ctrl[0].in) == offsetof(usb_device_dpram_t, ep_buf_ctrl[0].in) - 8 * 15, "");
        static_assert(offsetof(usb_device_dpram_t, ep_ctrl[0].out) == offsetof(usb_device_dpram_t, ep_buf_ctrl[0].out) - 8 * 15, "");
//        usb_dpram->ep_ctrl[ep_num - 1].in = reg;
//        usb_dpram->ep_ctrl[ep_num - 1].out = reg ^ reg0;
        volatile uint32_t *tmp = __get_opaque_ptr(&ep_buf_ctrl[-32]);
        tmp[0] = reg;
        tmp[1] = reg ^ reg0;
#endif
    }
}

typedef void (*endpoint_callback)(struct usb_endpoint *endpoint __comma_endpoint_callback_decl(data));

#if !ASM_SIZE_HACKS || !USB_NO_ENDPOINT_CALLBACK_DATA || USB_ASSUME_ENDPOINTS_ARRAY_FULL
static void _usb_for_each_non_control_endpoint(endpoint_callback callback __comma_endpoint_callback_decl(data)) {
    // note order is important here as the buffers are allocated in enumeration order
#if USB_ASSUME_ENDPOINTS_ARRAY_FULL
    for(uint i = 1; i < count_of(non_control_endpoints); i++) {
        bootrom_assert(USB, non_control_endpoints[i]);
    }
#endif
    for (uint i = 1; i < count_of(non_control_endpoints); i++) {
#if !USB_ASSUME_ENDPOINTS_ARRAY_FULL
        if (non_control_endpoints[i]) {
            callback(non_control_endpoints[i] __comma_endpoint_callback_val(data));
        }
#else
        callback(non_control_endpoints[i], data);
#endif
    }
}
#else
static_assert(count_of(non_control_endpoints) > 0, "");
static void __noinline __attribute((naked)) _usb_for_each_non_control_endpoint(__unused endpoint_callback callback) {
    pico_default_asm_volatile(
            "push {r4, r5, r6, lr}\n"
            "ldr r4, =non_control_endpoints\n"
            "mov r5, r4\n"
            "adds r5, r5, #%c[num_non_control_endpoints] * 4\n"
            "mov r6, r0\n"
            "1:\n"
            "ldmia r4!, {r0}\n"
            "cbz r0, 2f\n"
            "blx r6\n"
            "2:\n"
            "cmp r4, r5\n"
            "bne 1b\n"
            "pop {r4, r5, r6, pc}\n"
            :
            : [num_non_control_endpoints] "i" (count_of(non_control_endpoints))
            );
}
#endif

#endif

void usb_transfer_current_packet_only(struct usb_endpoint *ep) {
    // NOTE: IF YOU ADD ANY OTHER NON DEBUG CODE
    // than calling varm_to_native_usb_packet_done with the same args, then you need to
    // change the code in nsboot_asm.S which calls varm_to_native_usb_packet_done instead of this functions
//    printf("usb_transfer_current_packet_only %d %s\n", ep->num, usb_endpoint_dir_string(ep));
    if (ep->in) {
        bootrom_assert(USB, usb_current_in_packet_buffer(ep)->data_len <
               usb_endpoint_buffer_size(ep)); // must not be buffer_size or we'd need two
    }
    varm_to_native_usb_packet_done(ep);
}

#ifndef __riscv
// marked used as it may only be entered by fallthrough from the hard/soft-only sibling functions
void __used usb_reset_endpoint(struct usb_endpoint *ep, bool hard) {
    // ok we need to update the packet
#if !USB_NO_TRANSFER_ON_CANCEL
    if (ep->current_transfer && ep->current_transfer->type->on_cancel)
    {
        ep->current_transfer->type->on_cancel(ep->current_transfer, ep);
    }
#endif
    ep->current_transfer = NULL;
    usb_reset_buffers(ep); // hopefully a no-op
    if (hard) {
        // must be done after reset buffers above
        if (ep->next_pid) {
            usb_debug("Reset pid to 0 %d %s\n", ep->num, usb_endpoint_dir_string(ep));
        }
        ep->next_pid = 0;
    }
    ep->current_hw_buffer.valid = false;
    if (ep->halt_state) {
        ep->halt_state = HS_NONE;
        if (ep->on_stall_change) ep->on_stall_change(ep);
    }
    // note on_stall_change might have started a transfer
    if (_device.current_config_num && ep->default_transfer && !ep->current_transfer) {
        usb_debug("start default %d %s, nextpid = %d\n", ep->num, usb_endpoint_dir_string(ep), ep->next_pid);
        usb_reset_and_start_transfer(ep, ep->default_transfer, ep->default_transfer->type, 0);
    }
}

void usb_halt_endpoint_on_condition(struct usb_endpoint *ep) {
    usb_stall_endpoint(ep, HS_HALTED_ON_CONDITION);
};

void usb_hard_reset_endpoint_callback(struct usb_endpoint *ep __comma_endpoint_callback_decl(data));

static void _usb_handle_set_address(uint8_t addr) {
    bootrom_assert(USB, !_device.current_config_num); // we expect to be unconfigured
#if !GENERAL_SIZE_HACKS
    _device.current_address = addr;
#endif
    usb_hw->dev_addr_ctrl = addr;
}

static void _usb_handle_set_config(uint8_t config_num) {
    _device.current_config_num = config_num;
    _usb_for_each_non_control_endpoint(P16_F(usb_hard_reset_endpoint_callback) __comma_endpoint_callback_val(0));
#if USB_USE_GLOBAL_DEVICE_ON_CONFIGURE_CB
    usb_device_on_configure_cb(&_device, config_num != 0);
#else
#if !USB_MUST_HAVE_DEVICE_ON_CONFIGURE
    if (_device.on_configure) {
#endif
        _device.on_configure(&_device, config_num != 0);
#if !USB_MUST_HAVE_DEVICE_ON_CONFIGURE
    }
#endif
#endif
}

static void _usb_handle_bus_reset(void) {
#if ENABLE_DEBUG_TRACE
    usb_dump_trace();
    usb_reset_trace();
#endif

    // downgrade to unconfigured state
    _usb_handle_set_config(0);
    // downgrade to unaddressed state

    //_usb_handle_set_address(0);
    // ^ this is:
    //    bootrom_assert(USB, !_device.current_config_num); // we expect to be unconfigured
    //#if !GENERAL_SIZE_HACKS
    //    _device.current_address = addr;
    //#endif
    //    usb_hw->dev_addr_ctrl = addr;
    // so replacing it with a clear of dev_addr_ctrl:
    usb_hw_clear->dev_addr_ctrl = 0xffffffff;

    // Clear buf status + sie status
    usb_hw_clear->buf_status = 0xffffffff;
    usb_hw_clear->sie_status = 0xffffffff;
//    // todo?
//    //usb_hw->abort = 0xffffffff;
}

#define should_handle_setup_request(e, s) (!(e)->setup_request_handler || !(e)->setup_request_handler(e, s))

void usb_set_default_transfer(struct usb_endpoint *ep, struct usb_transfer *transfer) {
    bootrom_assert(USB, !ep->default_transfer);
    ep->default_transfer = transfer;
}

void usb_chain_transfer(struct usb_endpoint *ep, struct usb_transfer *transfer) {
    bootrom_assert(USB, ep->current_transfer);
    bootrom_assert(USB, !ep->current_transfer->completed);
    bootrom_assert(USB, !ep->current_transfer->on_complete);
    ep->chain_transfer = transfer;
}

#if !ASM_SIZE_HACKS || !GENERAL_SIZE_HACKS || !USB_USE_TINY_TRANSFER_TYPE
// note dummy arg because it actually helps with size reductions.
void __noinline __used usb_reset_transfer(uint32_t __unused dummy, struct usb_transfer *transfer, usb_transfer_type_ref_t type,
                                   usb_transfer_completed_func on_complete) {
#if !GENERAL_SIZE_HACKS
    varm_to_native_memset0(transfer, sizeof(struct usb_transfer));
#else
    static_assert(sizeof(struct usb_transfer) == 20, "");
    transfer->all_flags = 0;
#endif
    transfer->type = type;
    transfer->on_complete = on_complete;
    transfer->remaining_packets_to_submit = transfer->remaining_packets_to_handle = usb_transfer_type_initial_packet_count(type);
}
#else
static_assert(sizeof(struct usb_transfer) == 20, "");
static_assert(sizeof(((struct usb_transfer *)0)->all_flags) == 4, "");
static_assert(sizeof(((struct usb_transfer *)0)->type) == 4, "");
static_assert(sizeof(((struct usb_transfer *)0)->on_complete) == 4, "");
extern uint8_t usb_transfer_type_transfer_counts;
void __noinline __used __attribute__((naked)) usb_reset_transfer(__unused uint32_t __unused dummy,
                                                                 __unused struct usb_transfer *transfer,
                                                                 __unused usb_transfer_type_ref_t type,
                                                                 __unused usb_transfer_completed_func on_complete) {
    pico_default_asm_volatile(
        "movs r0, #0\n"
        "stmia r1!, {r0,r2,r3}\n"
        "movw r0, %[usb_transfer_type_transfer_counts]\n"
        "ldrb r0, [r0, r2]\n"
        // note -12 as we did stmia above
        "str r0, [r1, %[rpts] - 12]\n"
        "str r0, [r1, %[rpth] - 12]\n"
        "bx lr\n"
        :
        : [usb_transfer_type_transfer_counts] "i" (P16_CONSTANT(usb_transfer_type_transfer_counts)),
          [rpts] "i" (offsetof(struct usb_transfer, remaining_packets_to_submit)),
          [rpth] "i" (offsetof(struct usb_transfer, remaining_packets_to_handle))
    );
}
#endif

#if !ASM_SIZE_HACKS
void __used usb_reset_and_start_transfer(struct usb_endpoint *ep, struct usb_transfer *transfer,
                                  usb_transfer_type_ref_t type, usb_transfer_completed_func on_complete) {
    usb_reset_transfer((uintptr_t)ep, transfer, type, on_complete);
    usb_start_transfer(ep, transfer);
}
#else
void __used __attribute__((naked)) usb_reset_and_start_transfer(__unused struct usb_endpoint *ep, __unused struct usb_transfer *transfer,
                                                                __unused usb_transfer_type_ref_t type, __unused usb_transfer_completed_func on_complete) {
    pico_default_asm_volatile(
            "push {r0, r1, lr}\n"
            "bl usb_reset_transfer\n"
            "pop {r0, r1, r2}\n"
            "mov lr, r2\n"
            // fall thru "b.n usb_start_transfer\n"
            ".global usb_reset_and_start_transfer_end\n"
            "usb_reset_and_start_transfer_end:\n"
            );
}
#endif

#if GENERAL_SIZE_HACKS
// this is only used in one place in final compiler output, but it doesn't inline it, so force it
__force_inline
#endif
void
usb_stall_control_pipe(__unused struct usb_setup_packet *setup) {
    // NOTE: doing this inside of usb_stall_endpoint which might seem reasonable allows a RACE with the host
    //  whereby it may send a new SETUP packet in response to one STALL before we have gotten to clearing
    //  the second buffer (yes I see this with the USB 2 Command Verifier!)
    usb_reset_buffers(arch_usb_get_control_in_endpoint());
    usb_reset_buffers(arch_usb_get_control_out_endpoint());

    usb_stall_endpoint(arch_usb_get_control_in_endpoint(), HS_NON_HALT_STALL);
    usb_stall_endpoint(arch_usb_get_control_out_endpoint(), HS_NON_HALT_STALL);
}

#if !ASM_SIZE_HACKS
void tf_send_control_in_ack(__unused struct usb_endpoint *endpoint, __unused struct usb_transfer *transfer) {
    bootrom_assert(USB, endpoint == arch_usb_get_control_in_endpoint());
    bootrom_assert(USB, transfer == &_control_in_transfer);
    usb_debug("_tf_setup_control_ack\n");
    usb_start_empty_transfer(arch_usb_get_control_out_endpoint(), &_control_out_transfer, 0);
}
#else
static_assert(sizeof(struct usb_endpoint) == 44, "");
void __attribute__((naked)) tf_send_control_in_ack(__unused struct usb_endpoint *endpoint, __unused struct usb_transfer *transfer) {
    pico_default_asm_volatile(
            "ldr r0, =control_endpoints + 44\n"
            "ldr r1, =_control_out_transfer\n"
            "movs r2, #0\n"
            "b.n usb_start_empty_transfer\n"
            );
}
#endif

static void _tf_send_control_out_ack(__unused struct usb_endpoint *endpoint, __unused struct usb_transfer *transfer) {
    bootrom_assert(USB, endpoint == arch_usb_get_control_out_endpoint());
    bootrom_assert(USB, transfer == &_control_out_transfer);
    usb_debug("_tf_setup_control_ack\n");
    usb_start_empty_transfer(arch_usb_get_control_in_endpoint(), &_control_in_transfer, 0);
}

void tf_set_address(__unused struct usb_endpoint *endpoint, __unused struct usb_transfer *transfer) {
    bootrom_assert(USB, endpoint == arch_usb_get_control_in_endpoint());
    usb_debug("_tf_set_address %d\n", _device.pending_address);
    _usb_handle_set_address(_device.pending_address);
}

static struct usb_configuration *_usb_get_current_configuration(void) {
    if (_device.current_config_num) return &_device.config;
    return NULL;
}

static struct usb_configuration *_usb_find_configuration(uint num) {
#if USB_FIXED_CONFIGURATION_NUMBER
    if (USB_FIXED_CONFIGURATION_NUMBER == num) {
        return &_device.config;
    }
#else
    if (_device.config.descriptor->bConfigurationValue == num) {
        return &_device.config;
    }
#endif
    return NULL;
}

#if !USB_USE_GLOBAL_DEVICE_GET_DESCRIPTOR_STRING_CB
static int _usb_prepare_string_descriptor(aligned4_uint8_t *buf, __unused uint buf_len, const char *str) {
    int len = 2;
    uint8_t c;
    while (0 != (c = *str++)) {
        bootrom_assert(USB, len < buf_len);
        *(uint16_t *) (buf + len) = c;
        len += 2;
    }
    buf[0] = (uint8_t)len;
    buf[1] = 3; // bDescriptorType
    return len;
}
#endif

static bool update_hword_from_otp(uint16_t *buf, otp_cmd_t cmd) {
    // function specifies 4 byte alignment, but actually onlu needs 2 byte alignment for ECC
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
    return !sc_or_varm_otp_access((aligned4_uint8_t *)buf, 2, cmd);
#pragma GCC diagnostic push
}

// returns true if the last of the offsets were updated (basically if you care, you should do one offset at a time)
static bool white_label_update_hwords_if_valid(uint8_t *dest, uint wl_index, uint count) {
    bool rc = false;
    if (white_label.otp_row) {
        for (uint i = 0; i < count; i++) {
            if (white_label.valid_bits & (1u << (wl_index + i))) {
                // note use temp as dest is not always 2 byte aligned
                uint16_t tmp;
                // note the explicit cast to 16 bit means that we might wrap if white_label.otp_row was close to
                // 65536, however to save space, we assuem the user did not shoot themselves in the foot - since
                // this is a read, they will at worst crash themselves.
                rc = update_hword_from_otp(&tmp, row_read_ecc_cmd((uint16_t)(white_label.otp_row + wl_index + i)));
                if (rc) {
                    dest[i * 2] = (uint8_t)tmp;
                    dest[i * 2 + 1] = (uint8_t)(tmp >> 8);
                }
            }
        }
    }
    return rc;
}

#define wl_byte_len(unicode_flags_and_char_count) ((uint8_t)(unicode_flags_and_char_count << wl_is_unicode(unicode_flags_and_char_count)))
uint __used white_label_copy_string(aligned2_uint8_t *buf, uint buf_unicode_flag_and_char_count, uint str_def_index, const char *default_value) {
    union {
        struct {
            uint8_t unicode_flag_and_char_count;
            uint8_t row_offset;
        };
        uint16_t hword;
    } str_def;
    if (white_label_update_hwords_if_valid((uint8_t *) &str_def, str_def_index, 1) && str_def.hword && str_def.hword != 0xffff) {
        // we support writing ASCII into UNICODE buffer, but not vice-versa
        if (wl_is_unicode(buf_unicode_flag_and_char_count) || !wl_is_unicode(str_def.unicode_flag_and_char_count)) {
            if (wl_is_unicode(buf_unicode_flag_and_char_count) && !wl_is_unicode(str_def.unicode_flag_and_char_count)) {
                buf_unicode_flag_and_char_count &= 0x7f; // treat char limit as ASCII chars (number of chars remains the same as caller will convert to unicode)
            }
            uint8_t buf_max_bytes = wl_byte_len(buf_unicode_flag_and_char_count);
            uint8_t src_bytes = wl_byte_len(str_def.unicode_flag_and_char_count);
            src_bytes = MIN(buf_max_bytes, src_bytes);
            otp_cmd_t cmd = row_read_ecc_cmd(white_label.otp_row + str_def.row_offset);
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-align"
            // function specifies 4 byte alignment, but actually onlu needs 2 byte alignment for ECC
            if (!sc_or_varm_otp_access((aligned4_uint8_t *)buf, (src_bytes+1)&~1, cmd)) {
#pragma GCC diagnostic pop
                if ((int8_t)str_def.unicode_flag_and_char_count < 0) {
                    // convert length back into unicode
                    src_bytes = (src_bytes >> 1) | 0x80;
                }
                return src_bytes;
            }
        }
    }
    uint len = 0;
    while (default_value[len]) {
        ((uint8_t*)buf)[len] = default_value[len];
        len++;
    }
    return len;
}

#if !ASM_SIZE_HACKS
uint white_label_copy_ascii(uint8_t *buf, uint max_len_bytes, uint str_def_index, const char *default_value) {
    // use tmp buffer, because caller's buf is not always 2 byte aligned (stupid USB descriptors)
    // and also because we can write one byte off the end due to reading words
    uint16_t tmp[(max_len_bytes+1) / 2]; // really just rounded up, but 1 byte too big is fine
    uint len = white_label_copy_string((aligned2_uint8_t *)tmp, max_len_bytes, str_def_index, default_value);
    varm_to_native_memcpy(buf, tmp, len);
//    for(uint i=0; i < len; i++) buf[i] = ((uint8_t*)tmp)[i];
    return len;
}
#else
uint __attribute__((naked)) __noinline white_label_copy_ascii(__unused uint8_t *buf, __unused uint max_len_bytes, __unused uint str_def_index, __unused const char *default_value) {
    pico_default_asm_volatile(
            "push {r0, r4, r5, lr}\n"
            "mov r5, sp\n"
            "subs r4, r5, r1\n"
            "lsrs r4, #2\n"
            "lsls r0, r4, #2\n"
            "mov sp, r0\n"
            "bl white_label_copy_string\n"
            "lsls r1, r4, #2\n"
            "mov r2, r0\n"
            "ldr r0, [r5, #0]\n"
            "str r2, [r5, #0]\n"
            "bl varm_to_native_memcpy\n"
            "mov sp, r5\n"
            "pop {r0, r4, r5, pc}\n"
    );
}
#endif

static int _usb_handle_get_descriptor(aligned4_uint8_t *buf,
#if !USB_ALL_ENDPOINTS_MAX_PACKET_SIZE
                                      uint buf_len,
#endif
                                      struct usb_setup_packet *setup) {
    int len = -1;
    buf = __builtin_assume_aligned(buf, 4);
    switch (setup->wValue >> 8u) {
        case USB_DT_DEVICE: {
            usb_trace("GET DEVICE DESCRIPTOR\n");
            len = sizeof(*_device.descriptor);
            varm_or_native_memcpy(buf, (const uint8_t *) _device.descriptor, (uint)len);
            // white_label overrides idVendeor(VID), idProduct(PID), bcdDevice
            static_assert(offsetof(struct usb_device_descriptor, bcdDevice) + sizeof(_device.descriptor->bcdDevice) - offsetof(struct usb_device_descriptor, idVendor) == 6, "");
            static_assert(OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_USB_DEVICE_PID_VALUE == OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_USB_DEVICE_VID_VALUE + 1, "");
            static_assert(OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_USB_DEVICE_BCD_DEVICE_VALUE == OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_USB_DEVICE_VID_VALUE + 2, "");

            white_label_update_hwords_if_valid((buf + offsetof(struct usb_device_descriptor, idVendor)),
                                               OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_USB_DEVICE_VID_VALUE, 3);
            break;
        }
        case USB_DT_CONFIG: {
            usb_trace("GET CONFIG DESCRIPTOR %d\n", (uint8_t) setup->wValue);
            if (!(uint8_t) setup->wValue) {
                len = _device.config.descriptor->wTotalLength;
                varm_or_native_memcpy(buf, (const uint8_t *) _device.config.descriptor, (uint)len);
                // white_label overrides bmAttributes, bMaxPower
                static_assert(offsetof(struct usb_configuration_descriptor, bMaxPower) + sizeof(_device.config.descriptor->bMaxPower) - offsetof(struct usb_configuration_descriptor, bmAttributes) == 2, "");
                // argh; field is not hword aligned
                white_label_update_hwords_if_valid(
                        buf + offsetof(struct usb_configuration_descriptor, bmAttributes),
                        OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_USB_CONFIG_ATTRIBUTES_MAX_POWER_VALUES, 1);
            }
            break;
        }
        case USB_DT_STRING: {
            uint8_t index = (uint8_t)setup->wValue; // low part is index
            usb_trace("GET STRING DESCRIPTOR %d\n", index);
            if (index == 0) {
//                static const uint8_t lang_descriptor[] =
//                        {
//                                4, // bLength
//                                0x03, // bDescriptorType == String Descriptor
//                                0x09, 0x04 // language id = us english
//                        };
                *(uint32_t *)buf = 0x04090304;
                white_label_update_hwords_if_valid(buf + 2,
                                                   OTP_DATA_USB_WHITE_LABEL_ADDR_VALUE_INDEX_USB_DEVICE_LANG_ID_VALUE,
                                                   1);
                len = 4;
            } else {
#if USB_USE_GLOBAL_DEVICE_GET_DESCRIPTOR_STRING_CB
                len = usb_device_get_descriptor_string_cb(index, buf);
#else
                bootrom_assert(USB, _device.get_descriptor_string);
                const char *descriptor_string = _device.get_descriptor_string(index);
                bootrom_assert(USB, descriptor_string);
                len = _usb_prepare_string_descriptor(buf, buf_len, descriptor_string);
#endif
            }
            break;
        }
#if USB_SUPPORT_MS_OS_20_DESCRIPTOR_SET
        case USB_DT_BOS: {
            usb_trace("GET BOS DESCRIPTOR\n");
            static_assert(sizeof(bos_descriptor) <= 64, "");
            // note: this is annoying; current windows is quite happy if we just use the bigger of our two values,
            //      which saves us a bit of code, but it is exactly the sort of thing that might break in the future!
//            varm_or_native_memcpy(buf, src, (uint)len);
//            len = count_of(bos_descriptor);
//            src = bos_descriptor;
            varm_or_native_memcpy(buf, P16_D(bos_descriptor), sizeof(bos_descriptor));
            buf[sizeof(bos_descriptor)-4] = ms_os_20_descriptor_size;
            return sizeof(bos_descriptor);
        }
#endif
    }
    return len;
}

static void _usb_default_handle_device_setup_request(struct usb_setup_packet *setup) {
    setup = __builtin_assume_aligned(setup, 4);
    if (!(setup->bmRequestType & USB_REQ_TYPE_TYPE_MASK)) {
        if (setup->bmRequestType & USB_DIR_IN) {
            struct usb_buffer *in_packet = usb_current_in_packet_buffer(arch_usb_get_control_in_endpoint());
            aligned4_uint8_t *buf = in_packet->data;
            __unused uint buf_len = usb_buffer_data_max(in_packet);
            int len = -1;

            switch (setup->bRequest) {
                case USB_REQUEST_GET_STATUS: {
                    usb_debug("DEVICE GET_STATUS\n");
                    *((uint16_t *) in_packet->data) = 0;
                    len = 2;
                    break;
                }
                case USB_REQUEST_GET_DESCRIPTOR: {
                    usb_debug("DEVICE GET_DESCRIPTOR\n");
#ifdef USB_LARGE_DESCRIPTOR_SIZE
                    static __aligned(4) uint8_t descriptor_buf[USB_LARGE_DESCRIPTOR_SIZE];
                    static struct usb_stream_transfer_funcs control_stream_funcs = {
                            .on_chunk = usb_stream_noop_on_chunk,
                            .on_packet_complete = usb_stream_noop_on_packet_complete
                    };
                    len = _usb_handle_get_descriptor(descriptor_buf, sizeof(descriptor_buf), setup);
                    if (len != -1)
                    {
                        len = MIN(len, setup->wLength);
                        usb_stream_setup_transfer(&_control_in_stream_transfer, &control_stream_funcs, descriptor_buf,
                                                  sizeof(descriptor_buf), len, _tf_send_control_in_ack);

                        _control_in_stream_transfer.ep = usb_get_control_in_endpoint();
                        return usb_start_transfer(usb_get_control_in_endpoint(), &_control_in_stream_transfer.core);
                    } else {
                        //usb_warn("Didn't find requested device descriptor\n");
                    }
#elif USB_ALL_ENDPOINTS_MAX_PACKET_SIZE
                    len = _usb_handle_get_descriptor(buf, setup);
#else
                    len = _usb_handle_get_descriptor(buf, buf_len, setup);
#endif
                    break;
                }
                case USB_REQUEST_GET_CONFIGURATION: {
                    usb_debug("DEVICE GET_CONFIGURATION\n");
                    *((uint8_t *) buf) = _device.current_config_num;
                    len = 1;
                    break;
                }
            }
            if (len >= 0) {
                bootrom_assert(USB, buf_len <= 64);
                bootrom_assert(USB, (uint)len <= buf_len); // a bit late
                in_packet->data_len = (constrained_usb_buffer_size_t) MIN((uint)len, setup->wLength);
                usb_start_single_buffer_control_in_transfer();
                return;
            }
            usb_warn("Unhandled device IN setup request %02x\n", setup->bRequest);
        } else {
            switch (setup->bRequest) {
                case USB_REQUEST_SET_FEATURE: {
                    bootrom_assert(USB, false);
                    break;
                }
                case USB_REQUEST_SET_ADDRESS: {
                    uint addr = setup->wValue;
                    if (addr && addr <= 127) {
                        usb_debug("SET ADDRESS %02x\n", addr);
                        _device.pending_address = (uint8_t)addr;
                        return usb_start_empty_control_in_transfer(P16_F(tf_set_address));
                    }
                    break;
                }
                case USB_REQUEST_SET_DESCRIPTOR: {
                    bootrom_assert(USB, false);
                    break;
                }
                case USB_REQUEST_SET_CONFIGURATION: {
                    uint config_num = setup->wValue;
                    usb_debug("SET CONFIGURATION %02x\n", config_num);
                    if (!config_num || _usb_find_configuration(config_num)) {
                        // graham 1/3/20 removed this:
                        // USB 2.0 9.4.7: "If the specified configuration value matches the configuration value from a
                        // configuration descriptor, then that configuration is selected and the device remains in
                        // the Configured state"
                        // USB 2.0 9.4.5: "The Halt feature is reset to zero after either a SetConfiguration() or SetInterface() request even if the
                        // requested configuration or interface is the same as the current configuration or interface."
                        //
                        // Since there isn't a particularly clean way to unset a STALL, i'm taking this to mean that we should just do regular config setting tuff
                        //                    if (config_num != device.current_config_num)
                        //                    {
                        _usb_handle_set_config((uint8_t)config_num);
                        //                    }
                        return usb_start_empty_control_in_transfer_null_completion();
                    }
                    break;
                }
            }
            usb_warn("Unhandled device OUT setup request %02x\n", setup->bRequest);
        }
#if USB_SUPPORT_MS_OS_20_DESCRIPTOR_SET
    } else if (setup->bRequest == 1 && setup->wIndex == 7 && USB_REQ_TYPE_TYPE_VENDOR == (setup->bmRequestType & USB_REQ_TYPE_TYPE_MASK)) {
        static_assert(USB_USE_GLOBAL_DEVICE_MS_OS_20_DESCRIPTOR_SET_TRANSFER, "");
        return usb_reset_and_start_transfer(arch_usb_get_control_in_endpoint(), &_control_in_transfer,
                                            USB_TRANSFER_TYPE_REF(ms_os_20_descriptor_set_transfer_type), P16_F(tf_send_control_in_ack));
#endif
    }
    // default
    return usb_stall_control_pipe(setup);
}

static void _usb_default_handle_interface_setup_request(struct usb_setup_packet *setup,
                                                        __unused struct usb_interface *interface) {
    // check for valid class request
    if (!(setup->bmRequestType & USB_REQ_TYPE_TYPE_MASK) && !(setup->wIndex >> 8u)) {
        if (setup->bmRequestType & USB_DIR_IN) {
            switch (setup->bRequest) {
                case USB_REQUEST_GET_STATUS: {
                    usb_debug("DEVICE GET_STATUS\n");
                    return usb_start_tiny_control_in_transfer(0, 2);
                }
#if !USB_NO_INTERFACE_ALTERNATES
                case USB_REQUEST_GET_INTERFACE:
                {
                    if (!setup->wValue && setup->wLength == 1) {
                        return usb_start_tiny_control_in_transfer(interface->alt, 1);
                    }
                }
#endif
            }
        } else {
            switch (setup->bRequest) {
                case USB_REQUEST_SET_INTERFACE: {
#if !USB_NO_INTERFACE_ALTERNATES
                    if (interface->set_alternate_handler) {
                        if (interface->set_alternate_handler(interface, setup->wValue)) {
                            interface->alt = setup->wValue;
                            return usb_start_empty_control_in_transfer_null_completion();
                        }
                    }
#endif
                    // todo should we at least clear all HALT? - i guess given that we don't support this is fine
                    usb_warn("(ignored) set interface %d (alt %d)\n", setup->wIndex, setup->wValue);
                    break;
                }
            }
        }
    }
    usb_warn("Unhandled interface %02x setup request %02x bmRequestType %02x\n",
             interface->descriptor->bInterfaceNumber, setup->bRequest, setup->bmRequestType);
    // default
    return usb_stall_control_pipe(setup);
}

static void _usb_default_handle_endpoint_setup_request(struct usb_setup_packet *setup, struct usb_endpoint *ep) {
    if (!(setup->bmRequestType & USB_REQ_TYPE_TYPE_MASK)) {
        if (setup->bmRequestType & USB_DIR_IN) {
            switch (setup->bRequest) {
                case USB_REQUEST_GET_STATUS: {
                    if (!setup->wValue && setup->wLength == 2) {
                        // HALT FEATURE is not set for control stall
                        return usb_start_tiny_control_in_transfer(ep->halt_state > HS_NON_HALT_STALL ? 1 : 0, 2);
                    }
                    break;
                }
            }
            usb_warn("Unhandled ep %02x %s IN setup request %02x\n", ep->num, usb_endpoint_dir_string(ep),
                     setup->bRequest);
        } else {
            switch (setup->bRequest) {
                case USB_REQUEST_CLEAR_FEATURE: {
                    if (setup->wValue == USB_FEAT_ENDPOINT_HALT) {
                        if (ep->halt_state < HS_HALTED_ON_CONDITION) {
                            usb_debug("Request unhalt EP %d %s\n", ep->num, usb_endpoint_dir_string(ep));
                            usb_hard_reset_endpoint(ep);
                        } else {
                            ep->next_pid = 0; // must always reset data toggle
                            usb_debug("Skipped unhalt EP %d %s halt_state = %d\n", ep->num, usb_endpoint_dir_string(ep),
                                      ep->halt_state);
                        }
                        return usb_start_empty_control_in_transfer_null_completion();
                    }
                    break;
                }
                case USB_REQUEST_SET_FEATURE: {
                    if (setup->wValue == USB_FEAT_ENDPOINT_HALT) {
                        usb_debug("Request halt EP %d %s\n", ep->num, usb_endpoint_dir_string(ep));
                        usb_stall_endpoint(ep, HS_HALTED);
                        return usb_start_empty_control_in_transfer_null_completion();
                    }
                    break;
                }
            }
            usb_warn("Unhandled ep %02x %s OUT setup request %02x\n", ep->num, usb_endpoint_dir_string(ep),
                     setup->bRequest);
        }
    } else {
        usb_warn("Unhandled endpoint %d %s setup request %02x bmRequestType %02x\n", ep->num,
                 usb_endpoint_dir_string(ep), setup->bRequest, setup->bmRequestType);
    }
    // default
    return usb_stall_control_pipe(setup);
}

// returns null if device not configured
static struct usb_interface *_usb_find_interface(uint num) {
    struct usb_configuration *config = _usb_get_current_configuration();
    if (config) {
#if USB_ZERO_BASED_INTERFACES
        if (num < _usb_interface_count(config)) {
            return config->interfaces[num];
        }
#else
        for(uint i=0; i<_usb_interface_count(config); i++) {
            if (config->interfaces[i]->descriptor->bInterfaceNumber == num) {
                return config->interfaces[i];
            }
        }
#endif
    }
    return NULL;
}

// returns null if device not configured
static struct usb_endpoint *_usb_find_endpoint(uint num) {
    if (!num) {
        return arch_usb_get_control_out_endpoint();
    } else if (num == USB_DIR_IN) {
        return arch_usb_get_control_in_endpoint();
    }
    if (_usb_get_current_configuration()) {
        for (uint i = 1; i < count_of(non_control_endpoints); i++) {
            if (non_control_endpoints[i] && non_control_endpoints[i]->descriptor->bEndpointAddress == num) {
                return non_control_endpoints[i];
            }
        }
    }
    return NULL;
}

static void _usb_handle_setup_packet(struct usb_setup_packet *setup) {
    usb_debug("Setup packet\r\n");
    // a setup packet is always accepted, so reset anything in progress
//    usb_soft_reset_endpoint(arch_usb_get_control_in_endpoint());
//    usb_soft_reset_endpoint(arch_usb_get_control_out_endpoint());
    // make sure we reset in the same order
    static_assert(CONTROL_IN_ENDPOINT_INDEX == 0, "");
    static_assert(CONTROL_OUT_ENDPOINT_INDEX == 1, "");
    usb_soft_reset_endpoint2(arch_usb_get_control_in_endpoint());
    arch_usb_get_control_in_endpoint()->next_pid = arch_usb_get_control_out_endpoint()->next_pid = 1;
    switch (setup->bmRequestType & USB_REQ_TYPE_RECIPIENT_MASK) {
        case USB_REQ_TYPE_RECIPIENT_DEVICE: {
#if !USB_NO_DEVICE_SETUP_HANDLER
            if (!should_handle_setup_request(&_device, setup)) return;
#endif
            return _usb_default_handle_device_setup_request(setup);
        }
        case USB_REQ_TYPE_RECIPIENT_INTERFACE: {
            struct usb_interface *interface = _usb_find_interface(
                    setup->wIndex & 0xffu); // todo interface is only one byte; high byte seems to be used for entity
            usb_debug("Interface request %d %p\n", setup->wIndex, interface);
            if (interface) {
                if (!should_handle_setup_request(interface, setup)) return;
                return _usb_default_handle_interface_setup_request(setup, interface);
            }
            usb_warn("Setup request %04x for unknown interface %04x\n", setup->bRequest, setup->wIndex);
            break;
        }
        case USB_REQ_TYPE_RECIPIENT_ENDPOINT: {
            struct usb_endpoint *endpoint = _usb_find_endpoint(setup->wIndex);
            if (endpoint) {
#if !USB_NO_ENDPOINT_SETUP_HANDLER
                if (!should_handle_setup_request(endpoint, setup)) return;
#endif
                return _usb_default_handle_endpoint_setup_request(setup, endpoint);
            }
            usb_warn("Setup packet %04x for unknown endpoint %04x\n", setup->wValue, setup->wIndex);
            break;
        }
    }
    usb_warn("Unhandled setup packet - stalling contol pipe\r\n");
    // default
    usb_stall_control_pipe(setup);
}

void __used __isr usb_irq_handler(void) {
    uint32_t status = usb_hw->ints;
    uint32_t handled = 0;
    if (status & USB_INTS_SETUP_REQ_BITS) {
        handled |= USB_INTS_SETUP_REQ_BITS;
        _usb_handle_setup_packet(remove_volatile_cast(struct usb_setup_packet *, &usb_dpram->setup_packet));
        usb_hw_clear->sie_status = USB_SIE_STATUS_SETUP_REC_BITS;
    }

    // usb_handle_buffer is already called on RISC-V and contains some ARM8 code...
    // if an IRQ comes in after that has happened we could take this path under
    // varmulet which is no good, as it has CLZ and RBIS instructions in it
    branch_under_varmulet(skip_handler_buffer);
    if (status & USB_INTS_BUFF_STATUS_BITS) {
        handled |= USB_INTS_BUFF_STATUS_BITS;
        arch_usb_handle_buffer();
        // Interrupt is cleared when buff flag is cleared
    }
    skip_handler_buffer:

    if (status & USB_INTS_BUS_RESET_BITS) {
        handled |= USB_INTS_BUS_RESET_BITS;
        usb_debug("Bus Reset\r\n");
        _usb_handle_bus_reset();
        usb_hw_clear->sie_status = USB_SIE_STATUS_BUS_RESET_BITS;
    }

    if (status & USB_INTS_ERROR_BITS) {
        handled |= (status & USB_INTS_ERROR_BITS);
#ifndef NDEBUG
        _usb_dump_eps();
#endif
        //uint32_t errs = usb_hw->sie_status;
        usb_warn("Error 0x%lx (sie status 0x%lx)\n", (status & USB_INTS_ERROR_BITS), usb_hw->sie_status);
        if (usb_hw->sie_status & USB_SIE_STATUS_DATA_SEQ_ERROR_BITS) {
            usb_dump_trace();
            usb_warn("Data seq error\n");
            usb_hw_clear->sie_status = USB_SIE_STATUS_DATA_SEQ_ERROR_BITS;
        } else {
            // Assume we have been unplugged
            usb_debug("Assuming unplugged\n");
            _usb_handle_bus_reset();
        }
    }

    if (status ^ handled) {
        usb_warn("Unhandled IRQ 0x%x\r\n", (uint) (status ^ handled));
    }

}

#if ENABLE_DEBUG_TRACE
void usb_dump_trace(void)
{
    usb_debug("\r\n");
    for (int i = 0; i < trace_i; i++) {
        uint16_t ctrl = (uint16_t)debug_trace[i][1];
        uint8_t pid = (ctrl & USB_BUF_CTRL_DATA1_PID) ? 1 : 0;
        int ep = -1, b = -1, d = -1;
        for(int e=0;e<USB_NUM_ENDPOINTS;e++) {
            if (debug_trace[i][0] == (uintptr_t)&usb_dpram->ep_buf_ctrl[e].in)
            {
                ep = e;
                b = 0;
                d = 0;
            } else if (debug_trace[i][0] == 2 + (uintptr_t)&usb_dpram->ep_buf_ctrl[e].in) {
                ep = e;
                b = 1;
                d = 0;
            } else if (debug_trace[i][0] == (uintptr_t)&usb_dpram->ep_buf_ctrl[e].out) {
                ep = e;
                b = 0;
                d = 1;
            } else if (debug_trace[i][0] == 2 + (uintptr_t)&usb_dpram->ep_buf_ctrl[e].out) {
                ep = e;
                b = 1;
                d = 1;
            }
        }
        usb_debug("0x%lx (ep %d, b %d, d %d) <= 0x%x (DATA%d", debug_trace[i][0], ep, b, d, ctrl, pid);
        if (debug_trace[i][0] & 0b100) {
            usb_debug(", OUT");
        } else {
            usb_debug(", IN ");
        }
        if (ctrl & USB_BUF_CTRL_FULL) { usb_debug(", FULL"); }
        if (ctrl & USB_BUF_CTRL_LAST_BUF) { usb_debug(", LAST"); }
        if (ctrl & USB_BUF_CTRL_BUFF_SEL) { usb_debug(", SEL"); }
        usb_debug(", LEN = %d)\r\n", ctrl & USB_BUF_CTRL_LEN_MASK);
    }
    usb_reset_trace();
}

void usb_reset_trace(void)
{
    trace_i = 0;
}
#endif

static const void *usb_next_descriptor(const void *d, uint8_t type) {
    const struct usb_descriptor *desc = (const struct usb_descriptor *) d;
    do {
        desc = (const struct usb_descriptor *) (((const uint8_t *) desc) + desc->bLength);
    } while (desc->bDescriptorType != type);
    return desc;
}

/**
 * Initialize the runtime data structures for an interface, and all its endpoints
 * @param interface
 * @param desc
 * @param endpoints
 * @param endpoint_count
 * @param double_buffered
 * @return
 */
struct usb_interface *usb_interface_init(struct usb_interface *interface, const struct usb_interface_descriptor *desc,
#if !USB_USE_TWO_ENDPOINT_INTERFACES
                                         struct usb_endpoint *const *endpoints, uint endpoint_count,
#else
                                         struct usb_endpoint *endpoint0,
#endif
                                         bool double_buffered) {
    bootrom_assert(USB, desc->bLength == sizeof(struct usb_interface_descriptor));
#if !USB_USE_TWO_ENDPOINT_INTERFACES
    #define endpoint_arg(n) endpoints[n]
#else
    const int endpoint_count = 2;
    #define endpoint_arg(n) (&endpoint0[n])
#endif
    bootrom_assert(USB, desc->bNumEndpoints == endpoint_count);
    interface = usb_common_init(interface);
    interface->descriptor = desc;
#if !USB_NO_INTERFACE_ENDPOINTS_MEMBER
    interface->endpoints = endpoints;
    interface->endpoint_count = endpoint_count;
#endif
    const void *p = (const void *) desc;
    for (uint i = 0; i < endpoint_count; i++) {
        p = usb_next_descriptor(p, USB_DESCRIPTOR_TYPE_ENDPOINT);
        const struct usb_endpoint_descriptor *ep_desc = (const struct usb_endpoint_descriptor *) p;
        bootrom_assert(USB, ep_desc->bLength >= sizeof(struct usb_endpoint_descriptor));
        bootrom_assert(USB, ep_desc->bDescriptorType == USB_DESCRIPTOR_TYPE_ENDPOINT);
        uint8_t ep_num = ep_desc->bEndpointAddress & 0xfu;
        bootrom_assert(USB, ep_num && ep_num < USB_MAX_ENDPOINTS);
        _usb_endpoint_init_internal(endpoint_arg(i), ep_num, ep_desc->bEndpointAddress & USB_DIR_IN,
#if !USB_ALL_ENDPOINTS_MAX_PACKET_SIZE
                                    ep_desc->wMaxPacketSize,
#endif
                                    double_buffered);
        endpoint_arg(i)->descriptor = ep_desc;
#if !USB_BULK_ONLY_EP1_THRU_16
        if (USB_TRANSFER_TYPE_ISOCHRONOUS == (ep_desc->bmAttributes & USB_TRANSFER_TYPE_BITS)) {
            endpoint_arg(i)->buffer_stride = 128 << USB_ISOCHRONOUS_BUFFER_STRIDE_TYPE;
        } else {
            endpoint_arg(i)->buffer_stride = 64;
        }
        bootrom_assert(USB, ep_desc->wMaxPacketSize <= endpoint_arg(i)->buffer_stride);
#endif
#if USB_NO_INTERFACE_ENDPOINTS_MEMBER
        bootrom_assert(USB, ep_num && ep_num < count_of(non_control_endpoints));
        non_control_endpoints[ep_num] = endpoint_arg(i);
#endif
    }
#undef endpoint_arg
    return interface;
}

struct usb_device *usb_device_init(const struct usb_device_descriptor *desc,
                                   const struct usb_configuration_descriptor *config_desc,
                                   struct usb_interface *const *interfaces, uint interface_count
#if !USB_USE_GLOBAL_DEVICE_GET_DESCRIPTOR_STRING_CB
                                   ,const char *(*get_descriptor_string)(uint index)
#endif
                                   ) {
    usb_debug("-------------------------------------------------------------------------------\n");
    bootrom_assert(USB, desc->bLength == sizeof(struct usb_device_descriptor));
    bootrom_assert(USB, desc->bNumConfigurations ==
           1); // all that is supported right now (otherwise we must hanlde GET/SET_CONFIGURATION better
    bootrom_assert(USB, config_desc->bNumInterfaces == interface_count);
    _device.descriptor = desc;
    _device.config.descriptor = config_desc;
    _device.config.interfaces = interfaces;

    uint32_t values[3];
    otp_cmd_t cmd = { .flags = OTP_DATA_USB_BOOT_FLAGS_ROW << OTP_CMD_ROW_LSB };
    if (!sc_or_varm_otp_access((aligned4_uint8_t *)values, sizeof(values), cmd)) {
        uint32_t flags = (values[0] & values[1]) | (values[1] & values[2]) | (values[2] & values[0]);
        if (flags & OTP_DATA_USB_BOOT_FLAGS_WHITE_LABEL_ADDR_VALID_BITS) {
            white_label.valid_bits = (uint16_t) flags;
            update_hword_from_otp(&white_label.otp_row, row_read_ecc_cmd(OTP_DATA_USB_WHITE_LABEL_ADDR_ROW));
            // note to save space we don't validate white_label.otp_row... if the user sets it close enough
            // to 65536 to cause a wrap, that is their fault.
//            printf("HAVE WHITE_LABEL TABLE row=%04x, valid bits=%04x\n", white_label.otp_row, white_label.valid_bits);
        }
    }

#ifndef USB_FIXED_INTERFACE_COUNT
    _device.config.interface_count = interface_count;
#endif
#if !USB_USE_GLOBAL_DEVICE_GET_DESCRIPTOR_STRING_CB
    _device.get_descriptor_string = get_descriptor_string;
#endif

#if !USB_ALL_ENDPOINTS_MAX_PACKET_SIZE
    _usb_endpoint_init_internal(arch_usb_get_control_in_endpoint(), 0, true, 64, false);
    _usb_endpoint_init_internal(arch_usb_get_control_out_endpoint(), 0, false, 64, false);
#else
    static_assert(USB_ALL_ENDPOINTS_MAX_PACKET_SIZE == 64, "");
    _usb_endpoint_init_internal(arch_usb_get_control_in_endpoint(), 0, true, false);
    _usb_endpoint_init_internal(arch_usb_get_control_out_endpoint(), 0, false,false);
#endif

#if !USB_NO_INTERFACE_ENDPOINTS_MEMBER
    usb_init_clear_deref(&_endpoints);
    for(uint i=0; i < interface_count; i++) {
        for(uint e=0; e<interfaces[i]->endpoint_count; e++) {
            struct usb_endpoint *ep = interfaces[i]->endpoints[e];
            uint ep_num = usb_endpoint_number(ep);
            bootrom_assert(USB, ep_num && ep_num < count_of(_endpoints));
            non_control_endpoints[ep_num] = ep;
        }
    }
#endif
#if USB_ZERO_BASED_INTERFACES
    for (uint i = 0; i < interface_count; i++) {
        bootrom_assert(USB, interfaces[i]->descriptor->bInterfaceNumber == i);
    }
#endif

    _device.next_buffer_offset = 0x100;
    usb_endpoint_hw_init(arch_usb_get_control_in_endpoint() __comma_endpoint_callback_val(0));
    _device.next_buffer_offset = 0x100;
    usb_endpoint_hw_init(arch_usb_get_control_out_endpoint() __comma_endpoint_callback_val(0));
    _device.next_buffer_offset = 0x180;
    _usb_for_each_non_control_endpoint(P16_F(usb_endpoint_hw_init) __comma_endpoint_callback_val(0));
    return &_device;
}

void usb_grow_transfer(struct usb_transfer *transfer, uint packet_count) {
    transfer->remaining_packets_to_submit += packet_count;
    transfer->remaining_packets_to_handle += packet_count;
}

#if !GENERAL_SIZE_HACKS
void usb_soft_reset_endpoint(struct usb_endpoint *ep) {
    usb_reset_endpoint(ep, false);
}

void usb_hard_reset_endpoint(struct usb_endpoint *ep) {
    usb_reset_endpoint(ep, true);
}
#else
void __attribute__((naked, section(".text.usb_hard_reset_endpoint_callback"))) usb_soft_reset_endpoint(__unused struct usb_endpoint *ep) {
    pico_default_asm_volatile(
        "movs r1, #0\n"
        "b 1f\n"
        "nop\n"
        ".global usb_hard_reset_endpoint\n"
        ".thumb_func\n"
        "usb_hard_reset_endpoint:\n"
        ".global usb_hard_reset_endpoint_callback\n"
        ".thumb_func\n"
        "usb_hard_reset_endpoint_callback:\n"
        "movs r1, #1\n"
    "1:\n"
    );
    // now fall through (via linker script)
}
#endif

void __noinline usb_soft_reset_endpoint2(struct usb_endpoint ep[2]) {
    usb_soft_reset_endpoint(&ep[0]);
    usb_soft_reset_endpoint(&ep[1]);
}

void usb_clear_halt_condition(struct usb_endpoint *ep) {
    if (ep->halt_state == HS_HALTED_ON_CONDITION) {
        ep->halt_state = HS_HALTED; // can be reset by regular unstall
    }
}

void usb_device_start(void) {

    // At least on FPGA we don't know the previous state
    // so clean up registers. Should be fine not clearing DPSRAM
//    io_rw_32 *reg = &usb_hw->dev_addr_ctrl;
//    // Don't touch phy trim
//    while (reg != &usb_hw->phy_trim)
//        *reg++ = 0;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    varm_or_native_memset0((void *)&usb_hw->dev_addr_ctrl, &usb_hw->phy_trim - &usb_hw->dev_addr_ctrl);
#pragma GCC diagnostic pop

    // Start setup
#if ENABLE_DEBUG_TRACE
    trace_i = 0;
#endif

    usb_hw->muxing = USB_USB_MUXING_TO_PHY_BITS | USB_USB_MUXING_SOFTCON_BITS;
    usb_hw->pwr = USB_USB_PWR_VBUS_DETECT_BITS | USB_USB_PWR_VBUS_DETECT_OVERRIDE_EN_BITS;
    usb_hw->main_ctrl = USB_MAIN_CTRL_CONTROLLER_EN_BITS;

    // Reset various things to default state
    _usb_handle_bus_reset();

    // Pull up starts the show. Enable IRQ for EP0 buffer done
    usb_hw->sie_ctrl = USB_SIE_CTRL_PULLUP_EN_BITS | USB_SIE_CTRL_EP0_INT_1BUF_BITS;
    // Present pull up before enabling bus reset irq
    usb_hw->inte = USB_INTS_BUFF_STATUS_BITS | USB_INTS_BUS_RESET_BITS | USB_INTS_SETUP_REQ_BITS |
                   USB_INTS_ERROR_BITS;// | USB_INTS_EP_STALL_NAK_BITS;

    varm_to_native_usb_irq_enable();
}

void usb_device_stop(__unused struct usb_device *device) {
    bootrom_assert(USB, false);
}

void usb_start_tiny_control_in_transfer(uint32_t data, uint8_t len) {
    bootrom_assert(USB, len <= 4);
    struct usb_buffer *buffer = usb_current_in_packet_buffer(arch_usb_get_control_in_endpoint());
    // little endian so this works for any len
    *(uint32_t *) buffer->data = data;
    buffer->data_len = len;
    return usb_start_single_buffer_control_in_transfer();
}

void usb_start_single_buffer_control_in_transfer(void) {
    bootrom_assert(USB, usb_current_in_packet_buffer(arch_usb_get_control_in_endpoint())->data_len <
           64); // we don't want to have to send an extra packet
    usb_reset_and_start_transfer(arch_usb_get_control_in_endpoint(), &_control_in_transfer, USB_TRANSFER_TYPE_REF(usb_current_packet_only_transfer_type),
                                 P16_F(tf_send_control_in_ack));
}

void usb_start_control_out_transfer(usb_transfer_type_ref_t type) {
    usb_reset_and_start_transfer(arch_usb_get_control_out_endpoint(), &_control_out_transfer, type, _tf_send_control_out_ack);
}

#if !USB_USE_TINY_TRANSFER_TYPE
void usb_start_empty_transfer(struct usb_endpoint *endpoint, struct usb_transfer *transfer,
                              usb_transfer_completed_func on_complete) {
    if (endpoint->in) usb_current_in_packet_buffer(endpoint)->data_len = 0;
    usb_reset_and_start_transfer(endpoint, transfer, USB_TRANSFER_TYPE_REF(usb_current_packet_only_transfer_type), on_complete);
}
#else
static_assert(USB_DEVICE_TRANSFER_TYPE_usb_current_packet_only_transfer_type == 1, "");
static_assert(offsetof(struct usb_endpoint, in) == 2, "");
static_assert(sizeof(((struct usb_endpoint *)0)->in) == 1, "");
static_assert(offsetof(struct usb_buffer, data_len) == 4, "");
static_assert(sizeof(((struct usb_buffer *)0)->data_len) == 1, "");
void __attribute__((naked)) usb_start_empty_transfer(__unused struct usb_endpoint *endpoint, __unused struct usb_transfer *transfer,
                                                     __unused usb_transfer_completed_func on_complete) {
    pico_default_asm_volatile(
            "ldrb r3, [r0, #2]\n" // in
            "cbz r3, 1f\n"
            "push {r0-r2, lr}\n"
            "bl usb_current_packet_buffer\n"
            "movs r3, #0\n"
            "strb r3, [r0, #4]\n" // data_len
            "pop {r0-r3}\n"
            "mov lr, r3\n"
            "1:\n"
            "mov r3, r2\n"
            "movs r2, #1\n" // USB_TRANSFER_TYPE_REF(usb_current_packet_only_transfer_type)
            ".global usb_start_empty_transfer_end\n"
            "usb_start_empty_transfer_end:\n"
            // fall thru to usb_reset_and_start_transfer
            );
}
#endif

void usb_start_empty_control_in_transfer(usb_transfer_completed_func on_complete) {
    usb_start_empty_transfer(arch_usb_get_control_in_endpoint(), &_control_in_transfer, on_complete);
}

#if !ASM_SIZE_HACKS
void usb_start_empty_control_in_transfer_null_completion(void) {
    usb_start_empty_control_in_transfer(0);
}
#else
void __attribute__((naked)) usb_start_empty_control_in_transfer_null_completion(void) {
    pico_default_asm_volatile(
            "ldr r0, =control_endpoints\n"
            "ldr r1, =_control_in_transfer\n"
            "movs r2, #0\n"
            "b.n usb_start_empty_transfer\n"
    );
}
#endif

#ifndef NDEBUG
// this is provided as a wrapper to catch coding errors
struct usb_buffer *usb_current_in_packet_buffer(struct usb_endpoint *ep) {
    bootrom_assert(USB, ep->in);
    return usb_current_packet_buffer(ep);
}

// this is provided as a wrapper to catch coding errors
struct usb_buffer *usb_current_out_packet_buffer(struct usb_endpoint *ep) {
    bootrom_assert(USB, !ep->in);
    return usb_current_packet_buffer(ep);
}
#endif

#if !ASM_SIZE_HACKS
void usb_start_default_transfer_if_not_already_running_or_halted(struct usb_endpoint *ep) {
    // if we are in halt state we will do this again later; defensively check against current transfer already in place
    if (!ep->halt_state && ep->current_transfer != ep->default_transfer) {
        usb_reset_and_start_transfer(ep, ep->default_transfer, ep->default_transfer->type, 0);
    }
}
#else
static_assert(sizeof(control_endpoints[0].halt_state) == 1, "");
static_assert(sizeof(control_endpoints[0].default_transfer) == 4, "");
static_assert(sizeof(control_endpoints[0].current_transfer) == 4, "");
static_assert(sizeof(control_endpoints[0].current_transfer->type) == 4, "");
void __attribute__((naked)) usb_start_default_transfer_if_not_already_running_or_halted(__unused struct usb_endpoint *ep) {
    pico_default_asm_volatile(
            "ldrb r1, [r0, %[halt_state]]\n"
            "cbnz r1, 1f\n"
            "ldr r1, [r0, %[default_transfer]]\n"
            "ldr r3, [r0, %[current_transfer]]\n"
            "cmp r1, r3\n"
            "beq 1f\n"
            "ldr r2, [r1, %[type]]\n"
            "b usb_reset_and_start_transfer\n"
            "1:\n"
            "bx lr\n"
            :
            :
            [halt_state] "i" (offsetof(struct usb_endpoint, halt_state)),
            [default_transfer] "i" (offsetof(struct usb_endpoint, default_transfer)),
            [current_transfer] "i" (offsetof(struct usb_endpoint, current_transfer)),
            [type] "i" (offsetof(struct usb_transfer, type))
    );
}
#endif
#endif
#endif
#endif
