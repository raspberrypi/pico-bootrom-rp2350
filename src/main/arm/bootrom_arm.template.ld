MEMORY {
    ROM(rx) : ORIGIN = ${BOOTROM_ARM_START}, LENGTH = ${BOOTROM_ARM_SIZE}
    ROMSG(rx): ORIGIN = ${BOOTROM_SG_START}, LENGTH = ${BOOTROM_SG_SIZE}
    SRAM(rwx) : ORIGIN = 0x20000000, LENGTH = 520K
    USBRAM(rw) : ORIGIN = 0x50100000 + 0x1000 - ${CORE0_BOOT_USBRAM_WORKSPACE_SIZE}, LENGTH = ${CORE0_BOOT_USBRAM_WORKSPACE_SIZE}
    BOOTRAM(rw) : ORIGIN = ${BOOTRAM_ARM_STATIC_DATA_START}, LENGTH = ${BOOTRAM_ARM_STATIC_DATA_SIZE}
}

SECTIONS {
    . = ORIGIN(ROM);
    ENTRY(s_arm8_entry_point)
    .text : {
        exempt_start = .;
        KEEP(*(.vectors))
        /* functions with hint prefixes need to be glued together (hint prefix and body) because they are in C code */
        *(.text.s_varm_flash_put_get_nodata) /* falls thru */
        KEEP(*(.text.s_native_crit_flash_put_get))

        *(.text.varm_to_s_native_crit_launch_nsboot)
        KEEP(*(.text.s_native_crit_launch_nsboot))
        KEEP(*(.text.varm_to_s_native_crit_init_default_xip_setup_and_enter_image_thunk))
        KEEP(*(.text.s_native_crit_init_default_xip_setup_and_enter_image_thunk))
        *(.text.varm_to_s_native_api_validate_ns_buffer)
        KEEP(*(.text.s_native_api_validate_ns_buffer))
        *(.text.s_varm_api_flash_enter_cmd_xip) /* falls thru */
        *(.text.s_varm_api_crit_flash_select_xip_read_mode) /* falls thru */
        *(.text.s_varm_crit_redo_last_reboot) /* needs to be near s_varm_api_reboot */
        KEEP(*(.text.s_from_nsboot_varm_reboot)) /* needs to be near s_varm_api_reboot */
        KEEP(*(.text.s_varm_api_reboot)) /* falls thru */
        *(.text.s_varm_hx_reboot)
        KEEP(*(.text.s_varm_flash_sector_erase)) /* falls thru */
        KEEP(*(.text.s_varm_flash_erase_or_program))
        KEEP(*(.text.s_from_nsboot_varm_flash_sector_erase)) /* falls thru */
        KEEP(*(.text.s_varm_api_checked_flash_op))
        *(.text.s_varm_api_hx_otp_access)
        *(.text.s_varm_api_otp_access) /* does b.n to previous func */

        /* Mark APIs as KEEP because they may only be referred to by the ROM
           table, and those references are not visible to the Arm link step
           (since it's linked in the RISC-V binary using Arm post-link
           exports). Note __attribute__((used)) is only for the compiler. */
        KEEP(*(.text.s_varm_api_* .text.s_arm8_api_*))

        /* Main Secure/Exempt text entries */
        *(SORT_BY_ALIGNMENT(.text.s_*))

        /* ideally these should be inline (and they do now seem to be, so commented out): */
        /**(SORT_BY_ALIGNMENT(.text.rcp_*))*/

        /* These debug routines should only exist in development builds. We
           will know if we included them by accident, due to code size. */
        *(.text.mini_printf*)
        *(.text.mini_puts*)
        *(.text.dump_*)
        *(.text.print_*)
        *(.text.bootrom_assertion_failure)
        *(.text.uart_putc_raw)
        *(.text.printf)
        *(.text.debug_real_addr)
        *(.text.uart_putc)
        *(.text.puts)

        exempt_end = .;

        /* Exempt is followed by Secure-only text, which is used during the
           boot path but not called back into. (The sandwich goes Exempt ->
           Secure -> NonSecure -> NSC, with Exempt/Secure boundary fixed at
           0x4300, Secure/NonSecure boundary defined by the bootrom SAU
           region, and NonSecure/NSC fixed at 0x7e00 by the IDAU.) */
        sonly_text_start = .;
        *(.text.sonly_varm_make_hx_bool_impl)
        *(.text.sonly_varm_crit_core0_boot_path_prolog)
        *(SORT_BY_ALIGNMENT(.text.sb_*))
        *(SORT_BY_ALIGNMENT(.text.sonly_*))
        /* Must align the end symbol because the bootrom NS SAU region must
           start strictly after the end of Secure-executable text. There's no
           need to align the start. */
        . = ALIGN(32);
        sonly_text_end = .;

        ns_start = .;
        ns_text_start = .;
        /* (Note this should be empty, so the ALIGN costs nothing --
           however __start_of_secure_xn does need to be aligned) */
        *(SORT_BY_ALIGNMENT(.text.ns_*))
        . = ALIGN(32);
        ns_text_end = .;

        /* Text not marked by one of the known prefixes */
        unknown_text_start = .;
        /* (Note this should be empty, so the ALIGN costs nothing --
           however __start_of_secure_xn does need to be aligned) */
        *(SORT_BY_ALIGNMENT(.text*))
        . = ALIGN(32);
        unknown_text_end = .;

        PROVIDE(__start_of_secure_xn = .);
        KEEP(*(.rodata.keep*))
        *(.rodata*)
        this_is_the_end_my_only_friend_the_end = .;
        . = ${BOOTROM_ARM_SIZE}; /* ALIGN(LENGTH(ROM)); note hack to BOOTRAM_ARM_SIZE to allow RAM builds */
    } >ROM =0x00be
    ASSERT(ns_text_end == ns_text_start, "seem to have some ns text - possibly not bad, but havent had any yet")

    ASSERT(exempt_end <= ${BOOTROM_ARM_START} + ${BOOTROM_IDAU_EXEMPT_END}, "Exempt text beyond end of IDAU region, try marking more stuff as secure-only")

    ASSERT(unknown_text_end == unknown_text_start, "Found some text neither s nor ns.    This will crash if executed from Secure code, as it ends up past the SAU NS base. Mark it explicitly as the correct section. If it's inline_ then force its inlining.    To find out what code was caught, search for unknown_text_start in the .map file.")

    ASSERT((sonly_text_end & 0x1f) == 0, "End of secure-only text must be 32-byte-aligned for SAU")
    ASSERT((__start_of_secure_xn & 0x1f) == 0, "Start of Secure XN must be 32-byte-aligned for MPU")

    ASSERT(s_native_crit_flash_put_get == varm_to_s_native_crit_flash_put_get + 2, "varm_to_s_native failure 1")
    ASSERT(s_native_crit_launch_nsboot == varm_to_s_native_crit_launch_nsboot + 4, "varm_to_s_native failure 2")
    ASSERT(s_native_api_validate_ns_buffer == varm_to_s_native_api_validate_ns_buffer + 4, "varm_to_s_native failure 3")
    ASSERT(s_native_crit_init_default_xip_setup_and_enter_image_thunk == varm_to_s_native_crit_init_default_xip_setup_and_enter_image_thunk + 4, "varm_to_s_native failure 4")
    ASSERT(s_varm_api_crit_flash_select_xip_read_mode == s_varm_api_flash_enter_cmd_xip + 4, "fall thru failure 1")
    ASSERT(s_varm_hx_reboot == s_varm_api_reboot_end, "fall thru failure 2")
    ASSERT(varm_to_s_native_crit_flash_put_get == s_varm_flash_put_get_nodata + 2, "fall thru failure 4")
    ASSERT(s_varm_api_checked_flash_op == s_from_nsboot_varm_flash_sector_erase_end, "fall thru failure 5")
    ASSERT(sonly_varm_make_hx_bool_impl != sonly_varm_make_hx_bool_impl + 16, "prolog overlap error")
    ASSERT(boot_path_rnd_to_sha_end == boot_path_rnd_to_sha_start + 12, "boot path rnd to sha size != 12")

    .secure_gateways : {
        ASSERT((. & 31) == 0, "ERRROR secure_gateways not 32 byte aligned");
        PROVIDE(__start_of_secure_gateways = .);
        KEEP(*(.secure_gateways.first))
        *(.secure_gateways .secure_gateways.*)
        KEEP(*(.sg_fillers))
        . = ORIGIN(ROMSG) + LENGTH(ROMSG);
        PROVIDE(__end_of_secure_gateways = .);
    } >ROMSG =0x0000

    .data : {
        *(.data*)
    } >USBRAM

    .bss : {
        *(.bss*)
    } >USBRAM

    .fake (NOLOAD) : {
        PROVIDE(core0_boot_usbram_workspace = .);
    } >USBRAM
    .allowed_bss (COPY) : {
        *(.allowed_bss*)
    } >BOOTRAM

    _end_of_core1_boot_path_roundup_32_plus_1 = ((_end_of_core1_boot_path + 31) & ~31) + 1;

    ASSERT(SIZEOF(.data) == 0,
        "ERROR: do not use static memory in bootrom! (.data)")
    ASSERT(SIZEOF(.bss) == 0,
        "ERROR: do not use BSS memory in bootrom! (.bss)")
    ASSERT(SIZEOF(.allowed_bss) == ${BOOTRAM_ARM_STATIC_DATA_SIZE}, "allowed_bss size mismatch")

    INCLUDE "${P16_ASSERTS_LINKER_SCRIPT}"

     /* Leave room above the stack for stage 2 load, so that stage 2
       can image SRAM from its beginning */
    _stacktop = ORIGIN(SRAM) + LENGTH(SRAM) - 256;
    otp_data = 0x40130000;
    otp_data_raw = 0x40134000;
    otp_data_guarded = 0x40138000;
    otp_data_raw_guarded = 0x4013c000;
    sha256_hw_inst = 0x400f8000;
    software_git_revision = ${BOOTROM_RISCV_END} - ${BOOTROM_RISCV_END_SIZE};
    sb_fe_one = SB_CURVE_SECP256K1_P+0x22*4;
    __start_of_secure_xn_plus_5 = __start_of_secure_xn + 5;
    /* alias, as there is no difference in implementation */
    s_from_ns_varm_api_get_b_partition = s_varm_api_crit_get_b_partition;
}
