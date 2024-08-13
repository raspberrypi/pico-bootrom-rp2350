/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#if !defined(__riscv) || FEATURE_RISCV_USB_BOOT

#include "pico.h"
#include "usb_stream_helper.h"
#include "usb_device.h"
#include "nsboot_arch_adapter.h"
#include "nsboot_config.h"
#include "hardware/gpio.h"

static uint32_t _usb_stream_chunk_offset(struct usb_stream_transfer *transfer) {
    return transfer->offset & (transfer->chunk_size - 1);
}

void usb_stream_packet_handler_complete(struct usb_stream_transfer *transfer) {
    struct usb_buffer *buffer;
    struct usb_endpoint *ep = transfer->ep;
#ifndef NDEBUG
   bootrom_assert(USB, transfer->packet_handler_complete_expected);
    transfer->packet_handler_complete_expected = false;
#endif
   bootrom_assert(USB, ep);
    if (ep->in) {
        buffer = usb_current_in_packet_buffer(ep);
       bootrom_assert(USB, buffer);
//        if (buffer->data_max != 64) {
//            printf("BUFFER %p data_max %d %d/%d\n", buffer, buffer->data_max, transfer->offset, transfer->transfer_length);
//        if (transfer->offset >= 114000)
//            printf("%d %08x\n", transfer->offset, get_sp());
//        }
       bootrom_assert(USB, usb_buffer_data_max(buffer) == 64);
        uint chunk_offset = _usb_stream_chunk_offset(transfer);
        uint data_len = 64;
        if (transfer->offset + 64 > transfer->transfer_length) {
            data_len = transfer->transfer_length - transfer->offset;
        }
        buffer->data_len = (uint8_t)data_len;
        varm_or_native_memcpy(buffer->data, transfer->chunk_buffer + chunk_offset, data_len);
    } else {
        buffer = usb_current_out_packet_buffer(ep);
        bootrom_assert(USB, buffer);
        bootrom_assert(USB, buffer->data_len);
    }
    transfer->offset += buffer->data_len;
   bootrom_assert(USB, transfer->funcs && usb_stream_transfer_on_packet_complete(transfer->funcs));
#ifndef NDEBUG
    call_arm_fp1(transfer->funcs->on_packet_complete, transfer);
#else
    call_arm_fp0(usb_stream_transfer_on_packet_complete(transfer->funcs));
#endif
#if USE_BOOTROM_GPIO
    nsboot_set_gpio(0);
#endif
    /**
     *     usb_transfer_completed_func on_complete;
    // total number of buffers (packets) that still need to be handed over to the hardware
    // during the remaining course of the transfer (with data for IN, empty for data for out)
    uint32_t remaining_packets_to_submit;
    // total number of buffers when we will expect to receive IRQ/handle_buffer for during
    // the remaining course of the transfer
    uint32_t remaining_packets_to_handle;
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

     */
//    printf(__XSTRING(arm_or_riscv_impl()) " Streamer about to call packet done ep=%08x(%d %d) trans=%08x rps %d rph %d op %d pq %d st %d cp %d\n", ep, ep->num, ep->in, ep->current_transfer, ep->current_transfer->remaining_packets_to_submit,
//           ep->current_transfer->remaining_packets_to_handle, ep->current_transfer->outstanding_packet, ep->current_transfer->packet_queued,
//           ep->current_transfer->started, ep->current_transfer->completed);
#if defined(__riscv)
    native_usb_packet_done(ep);
#else
    varm_to_native_usb_packet_done(ep);
#endif
//    printf(__XSTRING(arm_or_riscv_impl()) " Called packet done rps ep=%08x(%d %d) trans=%08x %d rph %d op %d pq %d st %d cp %d\n", ep, ep->num, ep->in, ep->current_transfer, ep->current_transfer->remaining_packets_to_submit,
//           ep->current_transfer->remaining_packets_to_handle, ep->current_transfer->outstanding_packet, ep->current_transfer->packet_queued,
//           ep->current_transfer->started, ep->current_transfer->completed);
}

void native_usb_stream_packet_handler(struct usb_endpoint *ep) {
#if USE_BOOTROM_GPIO
    nsboot_set_gpio(1);
#endif
//    printf(__XSTRING(arm_or_riscv_impl()) " usb_stream_packet_handler ep=%08x(%d %d) trans=%08x  %d rph %d op %d pq %d st %d cp %d\n", ep, ep->num, ep->in, ep->current_transfer, ep->current_transfer->remaining_packets_to_submit,
//           ep->current_transfer->remaining_packets_to_handle, ep->current_transfer->outstanding_packet, ep->current_transfer->packet_queued,
//           ep->current_transfer->started, ep->current_transfer->completed);

    // todo assert type
    struct usb_stream_transfer *transfer = (struct usb_stream_transfer *) ep->current_transfer;
    uint chunk_offset = _usb_stream_chunk_offset(transfer);
    uint chunk_len = 0; // set to non zero to call on_chunk
    if (ep->in) {
        if (!chunk_offset) {
            // we are at the beginning of a chunk so want to call on_chunk
            chunk_len = (transfer->offset + transfer->chunk_size) > transfer->transfer_length ?
                        transfer->transfer_length - transfer->offset : transfer->chunk_size;
            if (ep->num > 2)
                usb_warn("chunko %d len %05x offset %08x size %04x transfer %08x\n", ep->num, chunk_len, chunk_offset,
                         (uint) transfer->chunk_size, (uint) transfer->transfer_length);
        }
    } else {
        //    usb_debug("write packet %04x %d\n", (uint)transfer->offset, ep->current_take_buffer);
        struct usb_buffer *buffer = usb_current_out_packet_buffer(ep);
       bootrom_assert(USB, buffer);
        // note we only set chunk_len if this is the end of a chunk
        if (transfer->offset + 64 >= transfer->transfer_length) {
            // we have ended the transfer (possibly mid-chunk)
            chunk_len = transfer->transfer_length & (transfer->chunk_size - 1);
            if (chunk_len) {
                usb_warn(">> Truncated %08x\n", chunk_len);
            } else {
                chunk_len = transfer->chunk_size;
            }
        } else if (chunk_offset + 64 >= transfer->chunk_size) {
            // end of regular chunk
            chunk_len = transfer->chunk_size;
        }
       bootrom_assert(USB, chunk_len || buffer->data_len == 64);
//        if (!(!chunk_len || buffer->data_len == ((chunk_len & 63u) ? (chunk_len & 63u) : 64u))) {
//            usb_warn("ooh off=%08x len=%08x chunk_off=%04x chunk_len=%04x data_len=%04x\n", (uint)transfer->offset, (uint)transfer->transfer_length, chunk_offset, chunk_len, buffer->data_len);
//        }
       bootrom_assert(USB, !chunk_len || buffer->data_len == ((chunk_len & 63u) ? (chunk_len & 63u) : 64u));
        // zero buffer when we start a new buffer, so that the chunk callback never sees data it shouldn't (for partial chunks)
        if (!chunk_offset) {
            varm_or_native_memset0(transfer->chunk_buffer, transfer->chunk_size);
        }
        varm_or_native_memcpy(transfer->chunk_buffer + chunk_offset, buffer->data, buffer->data_len); // always safe to copy all
    }
#ifndef NDEBUG
    transfer->packet_handler_complete_expected = true;
#endif

//    printf(__XSTRING(arm_or_riscv_impl(x))" STREAMER %d %d : cl %d\n", ep->num, ep->in, chunk_len);

    // todo i think this is reasonable since 0 length chunk does nothing
    if (chunk_len) {
       bootrom_assert(USB, transfer->funcs && usb_stream_transfer_on_chunk(transfer->funcs));
//        if (__rom_function_deref(stream_on_chunk_function, transfer->funcs->on_chunk)(chunk_len
//                                                                                      __comma_removed_for_space(
//                                                                                              transfer)))
#ifndef NDEBUG
        if (call_arm_fp2(transfer->funcs->on_chunk, chunk_len, transfer))
#else
        if (call_arm_fp1(usb_stream_transfer_on_chunk(transfer->funcs), chunk_len))
#endif
            return;
    }
    usb_stream_packet_handler_complete(transfer);
}

void nsboot_set_gpio(bool on) {
    if (nsboot_config->usb_activity_pin >= 0) {
        gpio_put((uint)nsboot_config->usb_activity_pin, on);
    }
}

#ifndef __riscv
void usb_stream_chunk_done(struct usb_stream_transfer *transfer) {
    usb_stream_packet_handler_complete(transfer);
}

//static const struct usb_transfer_type _usb_stream_transfer_type = {
//        .on_packet = native_usb_stream_packet_handler
//};
MAKE_USB_TRANSFER_TYPE(_usb_stream_transfer_type, native_usb_stream_packet_handler, 0);

void usb_stream_setup_transfer(struct usb_stream_transfer *transfer, const struct usb_stream_transfer_funcs *funcs,
                               uint8_t *chunk_buffer, uint32_t chunk_size, uint32_t transfer_length,
                               usb_transfer_completed_func on_complete) {
    transfer->funcs = funcs;
    transfer->chunk_buffer = chunk_buffer;
    bootrom_assert(USB, !(chunk_size & 63u)); // buffer should be a multiple of USB packet buffer size
    transfer->chunk_size = chunk_size;
    transfer->offset = 0;
    // todo combine with residue?
    transfer->transfer_length = transfer_length;
#if !ASM_SIZE_HACKS
    usb_reset_transfer(0, &transfer->core, USB_TRANSFER_TYPE_REF(_usb_stream_transfer_type), on_complete);
#else
    // same call as above, but we don't initialize r0
    register struct usb_transfer *r1 asm ("r1") = &transfer->core;
    register uintptr_t r2 asm ("r2") = USB_TRANSFER_TYPE_REF(_usb_stream_transfer_type);
    register usb_transfer_completed_func r3 asm ("r3") =  on_complete;
    pico_default_asm_volatile(
            "bl usb_reset_transfer\n"
            : "+l" (r1), "+l" (r2), "+l" (r3)
            :
            : "r0", "lr", "cc"
            );
#endif
    usb_grow_transfer(&transfer->core, (transfer_length + 63) / 64);
}
#endif
#endif