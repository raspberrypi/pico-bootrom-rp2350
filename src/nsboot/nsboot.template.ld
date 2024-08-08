MEMORY {
    ROM(rx) : ORIGIN = ${NSBOOT_START}, LENGTH = ${NSBOOT_SIZE}
    USBRAM(rw) : ORIGIN = ${NSBOOT_RAM_START}, LENGTH = ${NSBOOT_RAM_END} - ${NSBOOT_RAM_START}
}

INCLUDE "${ARM_SYMBOL_LINKER_SCRIPT}"

SECTIONS {
    ASSERT((${NSBOOT_RAM_START} & 0x7f) == 0, "USB RAM must be 0x80 aligned for VTOR")
    . = ORIGIN(ROM);
    ENTRY(_start)
    .text : {
        *(.entry)
        *(.text.varm_to_native_nsboot_init)
        KEEP(*(.text.native_nsboot_init))
        *(.text.varm_to_native_usb_packet_done)
        KEEP(*(.text.native_usb_packet_done))
        *(.text.varm_to_native_usb_irq_enable)
        KEEP(*(.text.native_usb_irq_enable))
        *(.text.usb_halt_endpoint) /* fall thru */
        *(.text.usb_stall_endpoint)
        *(.text.usb_hard_reset_endpoint_callback) /* fall thru */
        KEEP(*(.text.usb_reset_endpoint))
        /* following for for b.n closeness in tail calls */
        *(.text.tf_picoboot_wait_command)
        *(.text.usb_start_default_transfer_if_not_already_running_or_halted)
        *(.text.usb_start_empty_control_in_transfer_null_completion)
        *(.text.tf_send_control_in_ack)
        *(.text.usb_start_empty_transfer)
        *(.text.usb_reset_and_start_transfer)
        *(.text.usb_start_transfer)
        *(.text._usb_give_as_many_buffers_as_possible)

        *(SORT_BY_ALIGNMENT(.text*))
        /* merge & template_z must being contiguous */
        KEEP(*(.rodata.keep*))
        KEEP(*(.rodata.index_html_mail_merge))
        KEEP(*(.rodata.index_html_template_z))
        KEEP(*(.rodata.info_uf2_txt_mail_merge))
        KEEP(*(.rodata.info_uf2_txt_template_z))
        *(SORT_BY_ALIGNMENT(.rodata*))
        this_is_the_end_my_only_friend_the_end = .;
        . = ORIGIN(ROM) + LENGTH(ROM);
    } >ROM =0x00be

    ASSERT(native_nsboot_init == varm_to_native_nsboot_init + 4, "varm_to_native failure 1")
    ASSERT(native_usb_packet_done == varm_to_native_usb_packet_done + 4, "varm_to_native failure 2")
    ASSERT(native_usb_irq_enable == varm_to_native_usb_irq_enable + 4, "varm_to_native failure 3")
/*    ASSERT(usb_stall_endpoint == usb_halt_endpoint + 4, "fall thru failure 1")
    ASSERT(usb_reset_endpoint == usb_hard_reset_endpoint_callback + 4, "fall thru failure 2")*/
    ASSERT(usb_start_empty_transfer_end == usb_reset_and_start_transfer, "fall thru failure 3")
    ASSERT(usb_reset_and_start_transfer_end == usb_start_transfer, "fall thru failure 4")
    ASSERT(usb_start_transfer_end == _usb_give_as_many_buffers_as_possible, "fall thru failure 5")
    ASSERT(index_html_template_z == index_html_mail_merge + 6, "mail merge failure 1")
    ASSERT(info_uf2_txt_template_z == info_uf2_txt_mail_merge + 6, "mail merge failure 2")
    .data : {
        __usb_ram_begin = .;
        *(SORT_BY_ALIGNMENT(.data*))
    } >USBRAM

    .bss : {
        __bss_begin = .;
        *(.bss.first)
        *(SORT_BY_ALIGNMENT(SORT_BY_NAME(.bss*)))
        *(COMMON)
    } >USBRAM

    .stack : {
        . = ALIGN(4);
        KEEP(*(.stack_space))
        __usb_ram_end = .;
    } >USBRAM

    ASSERT(SIZEOF(.data) == 0,
        "ERROR: do not use static memory in nsboot! (.data)")

    ASSERT((${NSBOOT_START} & 0x1f) == 0, "NSBOOT must be 32 byte aligned")
/*    ASSERT(__irq14_vector - ((${NSBOOT_START} + ${NSBOOT_VTOR_OFFSET})&~0x7f) == (16 + 14) * 4, "USB irq vector entry is in the wrong place")*/
    ASSERT(__usb_ram_end - __usb_ram_begin <= LENGTH(USBRAM), "USB RAM overflow")
    ASSERT(__usb_ram_end - __usb_ram_begin == LENGTH(USBRAM), "Increase stack space to fill gap")
    INCLUDE "${P16_ASSERTS_LINKER_SCRIPT}"
}
