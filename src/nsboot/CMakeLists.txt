# note not all definitions are relevant to nsboot and RISC-V, but best to keep them all common to everything so they are definitely in sync
add_library(nsboot_config INTERFACE)
target_compile_definitions(nsboot_config INTERFACE
        USE_PICOBOOT=1
        USB_MAX_ENDPOINTS=5
        USE_BOOTROM_GPIO=${USE_BOOTROM_GPIO}
        COMPRESS_TEXT=1

        PICO_USE_GPIO_COPROCESSOR=0 # don't want copro instructions in varmuleted code
        FEATURE_TWO_ARG_MAIL_MERGE=1
        )

add_subdirectory(native)

if (NSBOOT_BUILD)
    # note we export memcpy as well in case it is used by C compiler (it is the same as varm_to_native_memcpy)
    set(ARM_IMPORTS
            # Empty export prefix -- we want to reference exported memset as just "memset"
            NO_PREFIX
#            memcpy
            varm_is_sram_or_xip_ram
            varm_to_native_memcpy
            varm_to_native_memset
            varm_to_native_memset0
#            memset
            varm_noop
            software_git_revision/d
    )

    # We want to generate headers from WELCOME.HTM etc.
    include(ExternalProject)
    ExternalProject_Add(generator
            PREFIX generator
            SOURCE_DIR ${CMAKE_CURRENT_LIST_DIR}/generator
            BINARY_DIR ${CMAKE_BINARY_DIR}/generator
            DOWNLOAD_COMMAND ""
            INSTALL_COMMAND ""
            )

    add_executable(generate IMPORTED)
    # todo is there a better way - this breaks on windows I presume
    set_property(TARGET generate PROPERTY IMPORTED_LOCATION ${CMAKE_BINARY_DIR}/generator/generate)
    add_dependencies(generate generator)

    add_executable(nsboot_raw
            ${CMAKE_CURRENT_LIST_DIR}/nsboot_usb_client.c
            ${CMAKE_CURRENT_LIST_DIR}/usb_virtual_disk.c
            ${CMAKE_CURRENT_LIST_DIR}/nsboot_async_task.c
            ${CMAKE_CURRENT_LIST_DIR}/usb_msc.c
            ${CMAKE_CURRENT_LIST_DIR}/nsboot_asm.S
            ${CMAKE_CURRENT_LIST_DIR}/nsboot.c
            ${CMAKE_CURRENT_LIST_DIR}/nsboot_uart_client.S
    )

    # we want the binary in the root
    set_target_properties(nsboot_raw
            PROPERTIES
            RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
            )

    set_bootrom_exe_flags(nsboot_raw)

    # these are the functions/data we want 16 bit pointers to
    # we will generate p16.h with P16_go == 0x00 P16_write_uf2_page_complete == 0x01 etc.
    # we will generate p16_asserts.ld which checks they are all included in the binary
    # we will use the ordering here along with the nsboot_raw.sym output to replace
    # 'movw rx, 0xbb00 + ord` with `movw rx, 16_bit_address_of(ord)`
    set(P16_TARGETS
            write_uf2_page_complete/2
            boot_sector/d1
            _str_rp2350/d4
            scsi_ir_z/d1
            index_html_template_z/d2
            info_uf2_txt_template_z/d2
            fat_dir_entries_z/d1
            ms_os_20_descriptor_set_headers_z/d1
            atc_chunk_task_done/1
            ms_os2_compatible_id_descriptor/d1
            ms_os2_registry_property_descriptor_even_bytes/d1
            vd_read_block/1
            vd_write_block/1
            usb_transfer_types/d1
            usb_transfer_type_transfer_counts/d1
            tf_wait_command/1
            msc_sector_funcs/d1
            msc_data_phase_complete/2
            nsboot_init_armv6m_pointers/d1
            nsboot_uart_putc/1
            nsboot_uart_getc/1
            _str_rpi_1/d1
            capacity_resp/d1
            format_capacity_resp/d1
            msc_in_on_stall_change/1
            usb_hard_reset_endpoint_callback/1
            msc_setup_request_handler/1
            picoboot_setup_request_handler/1
            boot_device_interfaces/d1
            boot_device_config/d1
            boot_device_descriptor/d1
            usb_endpoint_hw_init/1
            bootrom_error_to_picoboot_error/d1
            tf_send_control_in_ack/2
            tf_picoboot_wait_command/1
            picoboot_cmd_mapping/d1
            picoboot_stream_funcs/d1
            picoboot_ack/1
            atc_ack/1
            bos_descriptor/d1
            descriptor_strings/d1
            tf_set_address/1
            software_git_revision/d1
    )

    set(P16_ASSERTS "")
    set(P16_INCLUDE "#pragma once\n")
    set(P16_INDEX "0")
    foreach(P16_TARGET IN LISTS P16_TARGETS)
        string(FIND "${P16_TARGET}" "/" TARGET_LEN)
        string(SUBSTRING "${P16_TARGET}" 0 ${TARGET_LEN} P16_TARGET)
        target_link_options(nsboot_raw PRIVATE "LINKER:--undefined=${P16_TARGET}")
        string(CONCAT P16_ASSERTS "${P16_ASSERTS}" "ASSERT (${P16_TARGET} >= 0, \"${P16_TARGET} does not exist\")\n")
        math(EXPR P16_INDEX_HEX "${P16_INDEX}" OUTPUT_FORMAT HEXADECIMAL)
        string(CONCAT P16_INCLUDE "${P16_INCLUDE}" "#define P16_${P16_TARGET} ${P16_INDEX_HEX}\n")
        math(EXPR P16_INDEX "${P16_INDEX} + 1")
    endforeach()

    generate_arm_imports("${ARM_IMPORTS}")

    set(P16_ASSERTS_LINKER_SCRIPT ${CMAKE_BINARY_DIR}/p16_asserts.ld)
    set(P16_INCLUDE_FILE ${CMAKE_BINARY_DIR}/p16.h)
    file(GENERATE OUTPUT "${P16_ASSERTS_LINKER_SCRIPT}" CONTENT "${P16_ASSERTS}")
    file(GENERATE OUTPUT "${P16_INCLUDE_FILE}" CONTENT "${P16_INCLUDE}")
    configure_file(nsboot.template.ld ${CMAKE_BINARY_DIR}/nsboot.ld)

    set(GENERATED_H ${CMAKE_CURRENT_BINARY_DIR}/generated.h)
    add_custom_target(generate_header DEPENDS ${GENERATED_H})
    add_custom_command(OUTPUT ${GENERATED_H}
            COMMENT "Generating ${GENERATED_H}"
            DEPENDS scsi_ir.h index_html.h fat_dir_entries.h info_uf2_txt.h
            COMMAND generate ${CMAKE_CURRENT_LIST_DIR}/generator >${GENERATED_H}
            )

    target_include_directories(nsboot_raw PRIVATE
            ${CMAKE_CURRENT_BINARY_DIR}
            ${CMAKE_CURRENT_LIST_DIR}
            )
    target_link_libraries(nsboot_raw PRIVATE
            bootrom_shared_apis
            nsboot_native
            bootrom_layout
            mini_printf
            hardware_regs
            hardware_structs
            hardware_exception_headers
            hardware_gpio_headers
            hardware_resets_headers
            hardware_sync_headers
            pico_platform_headers
            pico_bootrom_headers
            boot_uf2_headers
            boot_picoboot_headers
            boot_picobin_headers
            )

    target_compile_definitions(nsboot_raw PRIVATE
            NSBOOT_APP=1
            )
    if (NSBOOT_ASSERT_DEFAULT_ENABLE)
        target_compile_definitions(nsboot_raw PRIVATE BOOTROM_ASSERT_DEFAULT_ENABLE=1)
    endif()
    if (PRINTF_IN_NSBOOT)
        target_compile_definitions(nsboot_raw PRIVATE
                MINI_PRINTF=1
                )
    endif()

    add_dependencies(nsboot_raw make_arm_import_symbols make_arm_import_symbols_header generate_header)

    target_link_libraries(nsboot_raw PRIVATE
            nsboot_native
    )

    # ugh we need these
    #set_bootrom_flags(nsboot)
    target_link_options(nsboot_raw PRIVATE "LINKER:--script=${CMAKE_BINARY_DIR}/nsboot.ld")
    # these are the functions followed by the number of times we expect them to be referenced
    # seems to save aobut 40 bytes for nsboot!??
    target_cl_options(nsboot_raw "-freorder-blocks-algorithm=stc")

    set_target_properties(nsboot_raw PROPERTIES LINK_DEPENDS ${ARM_SYMBOL_LINKER_SCRIPT})

    add_custom_command(TARGET nsboot_raw POST_BUILD
            COMMAND ${CMAKE_NM} $<TARGET_FILE:nsboot_raw> >${CMAKE_BINARY_DIR}/nsboot.sym
    )

    pico_add_extra_outputs(nsboot_raw)
    pico_add_map_output(nsboot_raw)
    target_link_options(nsboot_raw PRIVATE -save-temps -fverbose-asm)

    find_package (Python3 REQUIRED COMPONENTS Interpreter)

    set(NSBOOT_ELF "${CMAKE_BINARY_DIR}/nsboot.elf")
    add_custom_command(OUTPUT ${NSBOOT_ELF}
            DEPENDS $<TARGET_FILE:nsboot_raw>
            COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/inject_p16 $<TARGET_FILE:nsboot_raw> ${CMAKE_BINARY_DIR}/nsboot.sym ${NSBOOT_ELF} ${P16_TARGETS}
            VERBATIM)

    add_custom_target(nsboot ALL DEPENDS ${NSBOOT_ELF})
    add_custom_command(TARGET nsboot POST_BUILD COMMAND ${CMAKE_OBJCOPY} -Obinary ${NSBOOT_ELF} ${CMAKE_BINARY_DIR}/nsboot.bin VERBATIM)
    add_custom_command(TARGET nsboot POST_BUILD COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/bin2hex.py -32 ${CMAKE_BINARY_DIR}/nsboot.bin ${CMAKE_BINARY_DIR}/nsboot.h32)
    add_custom_command(TARGET nsboot POST_BUILD
            COMMAND ${CMAKE_OBJDUMP} -h ${NSBOOT_ELF} > ${CMAKE_BINARY_DIR}/nsboot.dis
            COMMAND ${CMAKE_OBJDUMP} -d ${NSBOOT_ELF} >> ${CMAKE_BINARY_DIR}/nsboot.dis
            COMMAND ${Python3_EXECUTABLE} ${PICO_TOOLS_DIR}/copro_dis.py ${CMAKE_BINARY_DIR}/nsboot.dis ${CMAKE_BINARY_DIR}/nsboot.dis
            VERBATIM
    )
    add_custom_command(TARGET nsboot POST_BUILD
            COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/nsboot_raw.elf.map ${CMAKE_BINARY_DIR}/nsboot.elf.map
    )
endif()

