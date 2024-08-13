MEMORY {
    ROM(rx)    : ORIGIN = ${BOOTROM_RISCV_START}, LENGTH = ${BOOTROM_RISCV_END} - ${BOOTROM_RISCV_END_SIZE} - ${BOOTROM_ROMTABLE_SIZE}
    ROMTABLE(rx) : ORIGIN = ${BOOTROM_RISCV_END} - ${BOOTROM_RISCV_END_SIZE}  - ${BOOTROM_ROMTABLE_SIZE}, LENGTH = ${BOOTROM_ROMTABLE_SIZE}
    ROMEND(rx) : ORIGIN = ${BOOTROM_RISCV_END} - ${BOOTROM_RISCV_END_SIZE}, LENGTH = ${BOOTROM_RISCV_END_SIZE}
    SRAM(rwx)  : ORIGIN = 0x20000000, LENGTH = 520K
    BOOTRAM(rw) : ORIGIN = ${BOOTRAM_RISCV_STATIC_DATA_START}, LENGTH = ${BOOTRAM_RISCV_STATIC_DATA_SIZE}
    USBRAM(rw) : ORIGIN = 0x50100000 + 0x1000 - ${CORE0_BOOT_USBRAM_WORKSPACE_SIZE}, LENGTH = ${CORE0_BOOT_USBRAM_WORKSPACE_SIZE}
}

INCLUDE "${ARM_SYMBOL_LINKER_SCRIPT}"
INCLUDE "${NSBOOT_SYMBOL_LINKER_SCRIPT}"

SECTIONS {
    . = ORIGIN(ROM);
    ENTRY(__reset_vector)

    .text : {
        riscv_start = .;
        /* Start with varmulet, so that the decode table is at a known
           address (workaround for lack of 16-bit data relocs) */
        KEEP(*(.text.varmulet_armv6m_core))
        *(.rodata.varmulet_usbboot_asm_hooks)
        *(.text.varmulet_run_adapter)
        /* falls thru to */
        KEEP(*(.text.varmulet_run))

        /* keep these together so we can use an 8 bit offset asm_hook table */
        first_hook_addr = .;
        *(.text.varmulet_hook_default_enter_fn)
        *(.text.varmulet_hook_default_exit_fn)
        *(.text.varmulet_hook_default_save_regs_fn)
        *(.text.varmulet_hook_default_restore_regs_fn)
/*        #if !VARMULET_USE_ENTER_HOOK_TO_OVERRIDE_REGISTER_STORED_HOOKS
        *(.text.varmulet_hook_default_execute_instruction)
        *(.text.varmulet_main_decode_table)
        *(.text.varmulet_dp_decode_table)
        #endif*/
        *(.text.varmulet_halt)     
        *(.text.varmulet_hook_default_bkpt_instr)
        *(.text.varmulet_hook_default_cps_instr)
        *(.text.varmulet_hook_default_mrs_instr)
        *(.text.varmulet_hook_default_msr_instr)
        *(.text.varmulet_hook_default_misc_control_instr)
        *(.text.varmulet_hook_default_exc_return)
        *(.text.varmulet_hook_default_call_return)
        *(.text.bootrom_asm_hooks)

        KEEP(*(.text.load_a4_goto_varm_wrapper)) /* fall through: */
        KEEP(*(.text.varm_wrapper))

        last_hook_addr = bootrom_hint_instr;
        ASSERT( last_hook_addr - first_hook_addr < 0x200, "need hints to fit into 0x200 bytes for 8 bit table");

        KEEP(*(.vectors))
        *(SORT_BY_ALIGNMENT(.text*))
        KEEP(*(.rodata.keep*))

        *(.rodata*)
        *(.srodata*)
        riscv_end = .;
        this_is_the_end_my_only_friend_the_end = .;
    } >ROM =0x0290 /* c.ebreak */

    /* The entry point and ROM tables are in different sections because
       attempting to set the location counter to end-of-ROM can give a link
       error like:

       cannot move location counter backwards (from 000000000000880c to 0000000000007ffc)

       Which seems related to the fact that the code is oversize until linker
       relaxations are applied. */

    .romtable : {
        KEEP(*(.romtable))
    } > ROMTABLE =0x0290 /* c.ebreak */

    .entry : {
        KEEP(*(.entry))
    } > ROMEND

    ASSERT(varmulet_run == varmulet_run_adapter_end, "varmulet_run_adapter does not fall into varmulet_run")
    ASSERT(SIZEOF(.entry) == ${BOOTROM_RISCV_END_SIZE}, ".entry is the wrong size, should be 10 bytes")
    ASSERT(__reset_vector == ORIGIN(ROMEND) + LENGTH(ROMEND) - 4,
        "__reset_vector was not in the expected location")
    .data : {
        *(.data*)
        *(.sdata*)
    } >SRAM

    .bss : {
        *(.bss*)
		*(COMMON)
        *(.sbss*)
    } >SRAM

    .allowed_bss (COPY) : {
        PROVIDE(__global_pointer$ = . );
        *(.allowed_bss*)
        . = ALIGN(4);
    } >BOOTRAM

    .fake (NOLOAD) : {
        PROVIDE(core0_flash_boot_usbram_workspace = .);
    } >USBRAM

    ASSERT(SIZEOF(.data) == 0,
        "ERROR: do not use static memory in bootrom! (.data)")

    ASSERT(SIZEOF(.bss) == 0,
        "ERROR: do not use bss memory in bootrom! (.bss)")
    ASSERT(SIZEOF(.allowed_bss) == ${BOOTRAM_RISCV_STATIC_DATA_SIZE}, "allowed_bss size mismatch")

     /* Leave room above the stack for stage 2 load, so that stage 2
       can image SRAM from its beginning */
    _stacktop = ORIGIN(SRAM) + LENGTH(SRAM) - 256;

    /* aliases with garbage for unused parameters */
    call_armv6m_0 = call_armv6m_2;
    call_armv6m_1 = call_armv6m_2;

    /* For some reason, RISC-V gas/ld can't relocate .hword sym_x, but *can*
       relocate .hword sym_x - sym_y (relative), so use this magic zero to
       transform absolute relocations into relative ones: */
    PROVIDE(__opaque_zero_symbol = 0);
}

otp_data_raw_guarded = 0x4013c000;
