/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "bootrom_layout.h"
#include "varm_to_riscv_hints.h"
#include "nsboot_secure_calls.h"
#include "usb_device.h"

.syntax unified
.cpu cortex-m23
.thumb

.section .entry, "ax"

.global _start

_start:
    // note we dont use + 2 since go() actually overwrites its own stack !!
    b.w go // + 2 // skip first push instruction as it doesn't return

.macro sc_or_varm_impl name ord
.global \name
.thumb_func
\name:
    movs r3, #\ord
.endm

#define SC_OR_VARM_STUB(name) sc_or_varm_impl sc_or_varm_##name SC_##name

// inlined, as called once only:
// SC_OR_VARM_STUB(connect_internal_flash)
// SC_OR_VARM_STUB(get_partition_table_info)
// SC_OR_VARM_STUB(flash_page_program)
// SC_OR_VARM_STUB(flash_sector_erase)
// SC_OR_VARM_STUB(flash_read_data)
// SC_OR_VARM_STUB(get_sys_info)

SC_OR_VARM_STUB(ram_trash_get_uf2_target_partition)
// fall through
.global sc_or_varm_common
sc_or_varm_common:
    b.w BOOTROM_SG_START

// macro is "inlined" to allow hword alignment
.global varm_to_native_nsboot_init
.thumb_func
varm_to_native_nsboot_init:
    movs r3, #MULTIPLEX_native_nsboot_init
    varm_hint HINT_MULTIPLEX
.global native_nsboot_init
.thumb_func
native_nsboot_init:
    bx lr

#if COMPRESS_TEXT
.global poor_mans_text_decompress
.type poor_mans_text_decompress,%function
.thumb_func
poor_mans_text_decompress:
    push {r4, r5, lr}
    adds r0, r1
    negs r1, r1
1:
    // r3 = char
    ldrb r3, [r0, r1]
    adds r2, #1
    lsrs r4, r3, #8
    sbcs r5, r5
    // r5 is -1 for regular character
    bne 3f

    sxtb r5, r3
    adds r1, #1
    ldrb r4, [r0, r1]
    // note we expect clear carry (so this subtracts an extra 1), which is fine, because r1 is < 0 still
    sbcs r2, r5
    subs r4, r2, r4
    // do copy
2:
    ldrb r3, [r4, r5]
3:
    strb r3, [r2, r5]
    adds r5, #1
    bne 2b

    adds r1, #1
    bne 1b

    pop {r4, r5, pc}
#else
#error WHY NOT?
#endif

// this is where the USB IRQ is in the vector table
// (and must be at offset 0x78 from a 128 byte aligned boundary)
.p2align 2
.global __irq14_vector
__irq14_vector:
    .word usb_irq_handler

SC_OR_VARM_STUB(flash_abort)
b.n sc_or_varm_common
SC_OR_VARM_STUB(otp_access)
b.n sc_or_varm_common

// char *write_msb_hex_chars(__unused char *dest, __unused uint32_t val, __unused int count)
.global write_msb_hex_chars
.thumb_func
write_msb_hex_chars:
    adds r2, r0, r2
1:
    lsrs r3, r1, #28
    adds r3, r3, #55
    cmp  r3, #64
    bhi.n 2f
    subs r3, r3, #7
2:
    strb r3, [r0]
    adds r0, r0, #1
    lsls r1, r1, #4
    cmp r0, r2
    bne 1b
    bx lr

.thumb_func
.global rebooting
rebooting:
    ldr r0, =rebooting_flag
    ldrb r0, [r0]
    bx lr

// reboot is handled specially as it has 4 args (we pass the third in r4)
.global sc_or_varm_reboot
.thumb_func
sc_or_varm_reboot:
    push {r3, r4, r5, lr}
    movs r3, #SC_reboot
    ldr r5, =rebooting_flag
    strb r3, [r5]
    // note 3rd arg passed on R4
    pop {r4}
    bl sc_or_varm_common
    // clear rebooting flag on unsuccessful call
    cbz r0, 1f
    movs r1, #0
    strb r1, [r5]
1:
    pop {r4, r5, pc}


VARM_TO_MULTIPLEX_PREAMBLE(native_usb_irq_enable)
VARM_TO_MULTIPLEX_PREAMBLE(native_usb_packet_done)

.section .rodata.keep.packed_structs

#if USB_USE_TINY_STREAM_TRANSFER_FUNCS
.global msc_sector_funcs
msc_sector_funcs:
    .hword msc_on_sector_stream_packet_complete + 1
    .hword msc_on_sector_stream_chunk + 1

.global picoboot_stream_funcs
picoboot_stream_funcs:
    // note varm_noop comes from main bootrom imports, so already has thumb bit set
    .hword varm_noop  // usb_stream_noop_on_packet_complete + 1
    .hword picoboot_on_stream_chunk + 1
#endif

#if USB_USE_TINY_TRANSFER_TYPE
.global usb_transfer_types
usb_transfer_types:
//#define USB_DEVICE_TRANSFER_TYPE_ms_os_20_descriptor_set_transfer_type 0
.hword usb_device_ms_os_20_descriptor_set_on_packet_cb + 1
//#define USB_DEVICE_TRANSFER_TYPE_usb_current_packet_only_transfer_type 1
.hword varm_to_native_usb_packet_done + 1 //usb_transfer_current_packet_only + 1
//#define USB_DEVICE_TRANSFER_TYPE__usb_stream_transfer_type 2
.hword native_usb_stream_packet_handler + 1
//#define USB_DEVICE_TRANSFER_TYPE__picoboot_cmd_transfer_type 3
.hword _picoboot_cmd_packet + 1
//#define USB_DEVICE_TRANSFER_TYPE__msc_cmd_transfer_type 4
.hword _msc_cmd_packet + 1

.global usb_transfer_type_transfer_counts
usb_transfer_type_transfer_counts:
// initial transfer counts for the above
.byte GLOBAL_MS_OS_20_DESCRIPTOR_SET_PACKET_COUNT
.byte 1
.byte 0
.byte 1
.byte 1
#endif

#if USE_16BIT_POINTERS
// these come from sb_virtual_disk.c
_str_rpicom:
.asciz "raspberrypi.com"
_str_device_rp2:
.asciz "https://raspberrypi.com/device/RP2?version=\01xxxxxxxxxxx" // 01 is marker for serial number
_str_raspberry_pi_rp2350:
.ascii "Raspberry Pi "
// fall thru
.global _str_rp2350
_str_rp2350:
.asciz "RP2350"
.global _str_rpi_1
_str_rpi_1:
.asciz "RPI"
.asciz "1"
.byte 'c', 'r', 'i', 'v', 'e', 'n', 's', 0
#endif

.align 2
.global index_html_defaults
index_html_defaults:
// note these are in reverse order
    .hword _str_rpicom
    .hword _str_device_rp2
    .hword _str_device_rp2

// note these are in reverse order
.global info_uf2_txt_defaults
info_uf2_txt_defaults:
    .hword _str_rp2350
    .hword _str_raspberry_pi_rp2350

.section .rodata.index_html_mail_merge
.global index_html_mail_merge
index_html_mail_merge:
    .hword index_html_defaults
    .hword index_html_str_defs
    .hword index_html_metadata

.section .rodata.info_uf2_txt_mail_merge
.global info_uf2_txt_mail_merge
info_uf2_txt_mail_merge:
    .hword info_uf2_txt_defaults
    .hword info_uf2_txt_str_defs
    .hword info_uf2_txt_metadata

// just here to cause linker errors for now if we use too much BSS
.section .stack_space
.align 2
nsboot_stack:
.space NSBOOT_STACK_WORDS * 4
nsboot_stack_end:
