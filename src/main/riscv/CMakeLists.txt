add_executable(bootrom_raw)

# we want the binary in the root
set_target_properties(bootrom_raw
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
        )

set_bootrom_exe_flags(bootrom_raw)
add_dependencies(bootrom_raw
        make_arm_import_symbols
        make_arm_import_symbols_header
        make_nsboot_import_symbols
        make_nsboot_import_symbols_header)

set(ARM_IMPORTS
        # Set a prefix so we never accidentally use an arm symbol
        __armexport_

        native_memcpy
        native_memset
        s_from_nsboot_varm_service_call_no_boot_once_check/d
        s_native_api_validate_ns_buffer
        s_varm_api_chain_image
        s_varm_api_checked_flash_op
        s_varm_step_safe_api_crit_bootrom_state_reset
        s_varm_api_crit_connect_internal_flash
        s_varm_api_crit_flash_exit_xip
        s_varm_api_crit_flash_flush_cache_impl
        s_varm_api_crit_flash_reset_address_trans
        s_varm_api_crit_flash_select_xip_read_mode
        s_varm_api_explicit_buy
        s_varm_api_flash_enter_cmd_xip
        s_varm_api_flash_range_erase
        s_varm_api_flash_range_program
        s_varm_api_flash_runtime_to_storage_addr
        s_varm_api_crit_get_b_partition
        s_varm_api_get_partition_table_info
        s_varm_api_get_sys_info
        s_varm_api_get_uf2_target_partition
        s_varm_api_load_partition_table
        s_varm_api_otp_access
        s_varm_api_pick_ab_partition
        s_varm_api_reboot
        s_varm_api_set_ns_api_permission
        s_varm_api_set_rom_callback
        s_varm_crit_core0_boot_path_entry_p2
        s_varm_flash_abort
        s_varm_flash_abort_clear
        s_varm_flash_page_program
        s_varm_flash_sector_erase
        s_varm_riscv_hx_get_boot_flag_impl/d # we don't want thumb bit as we set PC directly
        sg_api_checked_flash_op
        sg_api_flash_runtime_to_storage_addr
        sg_api_get_b_partition
        sg_api_get_partition_table_info
        sg_api_get_sys_info
        sg_api_otp_access
        sg_api_secure_call
        sg_api_reboot
        varm_noop

        software_git_revision/d
        partition_table_ptr/d
        flash_devinfo16_ptr/d
        xip_setup_func_ptr/d
        )

set(NSBOOT_IMPORTS
        # No prefix as we want the symbol name to be used directly
        NO_PREFIX

        usb_transfer_types/od)

set(ASM_HOOKS
        varmulet_hook_default_enter_fn
        varmulet_hook_default_exit_fn
        varmulet_hook_default_save_regs_fn
        varmulet_hook_default_restore_regs_fn
        varmulet_halt
        varmulet_hook_default_bkpt_instr
        varmulet_hook_default_cps_instr
        varmulet_hook_default_mrs_instr
        varmulet_hook_default_msr_instr
        varmulet_hook_default_misc_control_instr
        varmulet_hook_default_exc_return
        varmulet_hook_default_call_return
        bootrom_undefined32_sg_and_rcp_check
        bootrom_hint_instr
        bootrom_update_primask_fn
        bootrom_undefined32_rcp_check
)

set(ASM_HOOKS_INCLUDE "#pragma once\n")
set(ASM_HOOK_INDEX "0")
foreach(ASM_HOOK IN LISTS ASM_HOOKS)
    target_link_options(bootrom_raw PRIVATE "LINKER:--undefined=${ASM_HOOK}")
    math(EXPR ASM_HOOK_HEX "${ASM_HOOK_INDEX}" OUTPUT_FORMAT HEXADECIMAL)
    string(CONCAT ASM_HOOK_INCLUDE "${ASM_HOOK_INCLUDE}" "#define ASM_HOOK_${ASM_HOOK} ${ASM_HOOK_HEX}\n")
    math(EXPR ASM_HOOK_INDEX "${ASM_HOOK_INDEX} + 1")
endforeach()

set(ASM_HOOK_INCLUDE_FILE ${CMAKE_BINARY_DIR}/asm_hook_ordinals.h)
file(GENERATE OUTPUT "${ASM_HOOK_INCLUDE_FILE}" CONTENT "${ASM_HOOK_INCLUDE}")

generate_arm_imports("${ARM_IMPORTS}")
generate_nsboot_imports("${NSBOOT_IMPORTS}")
configure_file(bootrom_riscv.template.ld ${CMAKE_BINARY_DIR}/bootrom_riscv.ld)

if (DEFINED ENV{PICO_BOOTROM_ARMULET_PATH})
    set(PICO_BOOTROM_ARMULET_PATH $ENV{PICO_BOOTROM_ARMULETPATH})
endif()
if (DEFINED PICO_BOOTROM_ARMULET_PATH)
    add_subdirectory(${PICO_BOOTROM_ARMULET_PATH}/armulet)
else()
    add_subdirectory(../../../lib/armulet armulet)
endif()

set(GIT_INFO_H ${CMAKE_CURRENT_BINARY_DIR}/git_info.h)

add_custom_target(update_git_info DEPENDS ${GIT_INFO_H})

add_custom_command(OUTPUT ${GIT_INFO_H}
        COMMENT "Generating ${GIT_INFO_H}"
        DEPENDS ${CMAKE_CURRENT_LIST_DIR}/../../../.git/index
        COMMAND ${CMAKE_COMMAND} -E echo_append " #define GIT_REV 0x" > ${GIT_INFO_H}
        COMMAND git rev-parse --short=8 HEAD >> ${GIT_INFO_H}
        WORKING_DIRECTORY ${CMAKE_CURRENT_LIST_DIR} # so git is definitely running from within repo
)

add_dependencies(bootrom_raw update_git_info)

target_sources(bootrom_raw PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}/riscv_apis.c
        ${CMAKE_CURRENT_LIST_DIR}/riscv_bootrom_rt0.S
        ${CMAKE_CURRENT_LIST_DIR}/rom_table.S
        ${CMAKE_CURRENT_LIST_DIR}/riscv_misc.S
        ${CMAKE_CURRENT_LIST_DIR}/riscv_nsboot_vm.c
        ${CMAKE_CURRENT_LIST_DIR}/riscv_varm_wrapper.c
        ${CMAKE_CURRENT_LIST_DIR}/varmulet_hooks_bootrom.S
        )

target_compile_definitions(bootrom_raw PRIVATE
        ARMULET_USE_ASM=1
        ARMULET_FEATURE_CALL=1
        ARMULET_USE_REAL_MEMORY=1
        ARMULET_USE_LAZY_NZ=1

        ARMULET_FEATURE_ARMV8M_BASELINE=1
        # don't think we need UDIV/SDIV (there is one in the bootrom, but it is related to secure rollback which is ARM only)
        ARMULET_FEATURE_ARMV8M_BASELINE_SDIV_UDIV=0

        FEATURE_BYTE_ASM_HOOKS=1
        VARMULET_ASM_HOOK_TYPE=uint8_t
        ARMULET_FEATURE_ASM_HOOKS_IS_FUNCTION=1

        # Disable to save space as it's not that profitable in the bootrom,
        # since you can't load and fetch from the bootrom on the same cycle:
        VARMULET_USE_EARLY_INSTR_READ=0
        VARMULET_USE_ENTER_HOOK_TO_OVERRIDE_REGISTER_STORED_HOOKS=1
        SWAP_RISCV_NSBOOT_STACKS=1
        )
if (NOT USE_64K_BOOTROM)
target_compile_definitions(bootrom_raw PRIVATE
        VARMULET_FORCE_SHORT_JUMPS_FROM_DEFAULT_HOOKS=1
        )
endif()
if (NOT BOOTROM_32BIT_FUNC_POINTERS)
    target_compile_definitions(bootrom_raw PRIVATE
        # Enable hack for using assembler arithmetic to generate a 16-bit function table without relocations:
        VARMULET_USE_HWORD_MAIN_DECODE=1
        VARMULET_HWORD_MAIN_DECODE_ABSOLUTE_ADDR_OFFSET=${BOOTROM_RISCV_START}
        )
endif()

# We need this define in the RISC-V bootrom too, because some layouts depend
# on it (particularly launch config passed on stack during multicore launch)
if (BOOTROM_HARDENING)
    target_compile_definitions(bootrom_raw PRIVATE BOOTROM_HARDENING=1)
endif()
if (RISCV_BOOTROM_ASSERT_DEFAULT_ENABLE)
    target_compile_definitions(bootrom_raw PRIVATE BOOTROM_ASSERT_DEFAULT_ENABLE=1)
endif()
if (NOT DEFINED PRINTF_IN_RISCV)
    set(PRINTF_IN_RISCV PRINTF_IN_NATIVE)
endif()
if (PRINTF_IN_RISCV)
    target_compile_definitions(bootrom_raw PRIVATE
            MINI_PRINTF=1
            )
endif()
if (AXE_RISCV)
    target_compile_definitions(bootrom_raw PRIVATE
            AXE_RISCV=1
            )
endif()

target_link_libraries(bootrom_raw PRIVATE
        bootrom_common
        armulet
        varmulet
        hardware_hazard3
        mini_printf
        nsboot_native)

target_include_directories(bootrom_raw SYSTEM PRIVATE /Users/graham/dev/riscv-gnu-toolchain/newlib/newlib/libc/include)
target_include_directories(bootrom_raw PRIVATE ${CMAKE_CURRENT_BINARY_DIR}) # for git_info
target_link_options(bootrom_raw PRIVATE "LINKER:--script=${CMAKE_BINARY_DIR}/bootrom_riscv.ld")
set_target_properties(bootrom_raw PROPERTIES LINK_DEPENDS ${CMAKE_BINARY_DIR}/bootrom_riscv.ld)
set_target_properties(bootrom_raw PROPERTIES LINK_DEPENDS ${ARM_SYMBOL_LINKER_SCRIPT})
set_target_properties(bootrom_raw PROPERTIES LINK_DEPENDS ${NSBOOT_SYMBOL_LINKER_SCRIPT})
add_custom_command(TARGET bootrom_raw POST_BUILD
        COMMAND ${CMAKE_NM} $<TARGET_FILE:bootrom_raw> >${CMAKE_BINARY_DIR}/bootrom.sym
)

pico_add_extra_outputs(bootrom_raw)

find_package (Python3 REQUIRED COMPONENTS Interpreter)
set(BOOTROM_ELF "${CMAKE_BINARY_DIR}/bootrom.elf")
add_custom_command(OUTPUT ${BOOTROM_ELF}
        DEPENDS $<TARGET_FILE:bootrom_raw>
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/fixup_asm_hooks $<TARGET_FILE:bootrom_raw> ${CMAKE_BINARY_DIR}/bootrom.sym ${BOOTROM_ELF} ${ASM_HOOKS}
        VERBATIM)

add_custom_target(bootrom ALL DEPENDS ${BOOTROM_ELF})
add_custom_command(TARGET bootrom POST_BUILD COMMAND ${CMAKE_OBJCOPY} -Obinary ${BOOTROM_ELF} ${CMAKE_BINARY_DIR}/bootrom.bin VERBATIM)
add_custom_command(TARGET bootrom POST_BUILD COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/bin2hex.py -32 ${CMAKE_BINARY_DIR}/bootrom.bin ${CMAKE_BINARY_DIR}/bootrom.h32)
add_custom_command(TARGET bootrom POST_BUILD
        COMMAND ${CMAKE_OBJDUMP} -h ${BOOTROM_ELF} > ${CMAKE_BINARY_DIR}/bootrom.dis
        COMMAND ${CMAKE_OBJDUMP} -d ${BOOTROM_ELF} >> ${CMAKE_BINARY_DIR}/bootrom.dis
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/xh3bextm_dis ${CMAKE_BINARY_DIR}/bootrom.dis ${CMAKE_BINARY_DIR}/bootrom.dis
        VERBATIM
)
add_custom_command(TARGET bootrom POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/bootrom_raw.elf.map ${CMAKE_BINARY_DIR}/bootrom.elf.map
)
