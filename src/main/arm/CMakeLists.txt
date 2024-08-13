add_executable(bootrom_raw)

# we want the binary in the root
set_target_properties(bootrom_raw
        PROPERTIES
        RUNTIME_OUTPUT_DIRECTORY ${CMAKE_BINARY_DIR}
        )

set_bootrom_exe_flags(bootrom_raw)

set(VARM_SOURCE_FILES
        ${CMAKE_CURRENT_LIST_DIR}/varm_apis.c
        ${CMAKE_CURRENT_LIST_DIR}/varm_blocks.c
        ${CMAKE_CURRENT_LIST_DIR}/varm_boot_path.c
        ${CMAKE_CURRENT_LIST_DIR}/varm_flash_boot.c
        ${CMAKE_CURRENT_LIST_DIR}/varm_flash_permissions.c
        ${CMAKE_CURRENT_LIST_DIR}/varm_nsboot.c
        ${CMAKE_CURRENT_LIST_DIR}/varm_checked_flash.c
        ${CMAKE_CURRENT_LIST_DIR}/varm_generic_flash.c
        ${CMAKE_CURRENT_LIST_DIR}/varm_misc.S
        ${CMAKE_CURRENT_LIST_DIR}/varm_otp.c
        ${CMAKE_CURRENT_LIST_DIR}/varm_launch_image.c
        ${CMAKE_CURRENT_LIST_DIR}/varm_s_from_nsboot_wrappers.c
)
set(ARM8_SOURCE_FILES
        ${CMAKE_CURRENT_LIST_DIR}/arm8_bootrom_rt0.S
        ${CMAKE_CURRENT_LIST_DIR}/arm8_misc.S
        ${CMAKE_CURRENT_LIST_DIR}/arm8_s_from_ns_wrappers.c
        ${CMAKE_CURRENT_LIST_DIR}/arm8_secure_gateways.S
        ${CMAKE_CURRENT_LIST_DIR}/arm8_sig.c
        ${CMAKE_CURRENT_LIST_DIR}/arm8_nsboot_vm.c
        ${CMAKE_CURRENT_LIST_DIR}/arm8_validate_ns_buffer.c
        )
target_sources(bootrom_raw PRIVATE
        ${VARM_SOURCE_FILES}
        ${ARM8_SOURCE_FILES}
        )

list(APPEND VARM_SOURCE_FILES ${CMAKE_CURRENT_LIST_DIR}/../../mini_printf/mini_printf.c)
list(APPEND VARM_SOURCE_FILES ${CMAKE_CURRENT_LIST_DIR}/../../../lib/sweet-b/src/sb_sha256.c)
foreach(VARM_SOURCE IN LISTS VARM_SOURCE_FILES)
    if (NOT EXISTS ${VARM_SOURCE})
        message(FATAL_ERROR "${VARM_SOURCE} not found")
    endif()
    set_source_files_properties(${VARM_SOURCE} PROPERTIES COMPILE_FLAGS " -march=armv8-m.base -mcpu=cortex-m23")
endforeach ()

target_include_directories(bootrom_raw PRIVATE
        ${CMAKE_CURRENT_LIST_DIR}
        )

# these are the functions/data we want 16 bit pointers to
# we will generate p16.h with P16_go == 0x00 P16_write_uf2_page_complete == 0x01 etc.
# we will generate p16_asserts.ld which checks they are all included in the binary
# we will use the ordering here along with the nsboot_raw.sym output to replace
# 'movw rx, 0xbb00 + ord` with `movw rx, 16_bit_address_of(ord)`
set(P16_TARGETS
        __start_of_secure_xn_plus_5/d1
        sonly_text_end/d2
        s_native_default_xip_setup/d1
        _end_of_core1_boot_path_roundup_32_plus_1/d1
        #bootrom_xip_mode_cfgs/d1
        otp_ecc_parity_table/d1
        sg_api_table/d1
        rq_cq_seq_table/d1
        sb_fe_one/d1
)

set(P16_ASSERTS "")
set(P16_INCLUDE "#pragma once\n")
set(P16_INDEX "0")
foreach(P16_TARGET IN LISTS P16_TARGETS)
    string(FIND "${P16_TARGET}" "/" TARGET_LEN)
    string(SUBSTRING "${P16_TARGET}" 0 ${TARGET_LEN} P16_TARGET)
    target_link_options(bootrom_raw PRIVATE "LINKER:--undefined=${P16_TARGET}")
    string(CONCAT P16_ASSERTS "${P16_ASSERTS}" "ASSERT (${P16_TARGET} >= 0, \"${P16_TARGET} does not exist\")\n")
    math(EXPR P16_INDEX_HEX "${P16_INDEX}" OUTPUT_FORMAT HEXADECIMAL)
    string(CONCAT P16_INCLUDE "${P16_INCLUDE}" "#define P16_${P16_TARGET} ${P16_INDEX_HEX}\n")
    math(EXPR P16_INDEX "${P16_INDEX} + 1")
endforeach()
# provide these two from ARM as software_git_revision is needed by nsboot, and
# having them defined is easier for the rom_table
target_link_options(bootrom_raw PRIVATE "LINKER:--undefined=software_git_revision")
target_link_options(bootrom_raw PRIVATE "LINKER:--undefined=partition_table_ptr")

set(P16_ASSERTS_LINKER_SCRIPT ${CMAKE_BINARY_DIR}/p16_asserts.ld)
set(P16_INCLUDE_FILE ${CMAKE_BINARY_DIR}/p16.h)
file(GENERATE OUTPUT "${P16_ASSERTS_LINKER_SCRIPT}" CONTENT "${P16_ASSERTS}")
file(GENERATE OUTPUT "${P16_INCLUDE_FILE}" CONTENT "${P16_INCLUDE}")
configure_file(bootrom_arm.template.ld ${CMAKE_BINARY_DIR}/bootrom_arm.ld)

target_compile_definitions(bootrom_raw PRIVATE
        BREAKPOINT_AT_DEAD=1
        GENERAL_SIZE_HACKS=1
        ASM_SIZE_HACKS=1
        TAIL_CALL_HACKS=1
        PICO_SECURE=1
        PICO_NO_FPGA_CHECK=0
        )

if (BOOTROM_HARDENING)
    target_compile_definitions(bootrom_raw PRIVATE BOOTROM_HARDENING=1)
endif()
if (ARM_BOOTROM_ASSERT_DEFAULT_ENABLE)
    target_compile_definitions(bootrom_raw PRIVATE BOOTROM_ASSERT_DEFAULT_ENABLE=1)
endif()

if (NOT DEFINED PRINTF_IN_ARM)
    set(PRINTF_IN_ARM PRINTF_IN_NATIVE)
endif()
if (PRINTF_IN_ARM)
    target_compile_definitions(bootrom_raw PRIVATE
            MINI_PRINTF=1
            )
endif()
if (NO_SWEETB)
    target_compile_definitions(bootrom_raw PRIVATE
            NO_SWEETB=1
            )
endif()

set(SB_TEST_FEATURE_CANARIES 1)

add_subdirectory(../../../lib/sweet-b sweet-b)
target_link_libraries(bootrom_raw PRIVATE
        bootrom_common
        sweet_b)
target_compile_definitions(bootrom_raw PRIVATE
        SB_UNROLL=0
        SB_SW_P256_SUPPORT=0
        SB_USE_RP2350_SHA256=1
        )
if (HACK_STACK_WORDS)
    target_compile_definitions(bootrom_raw PRIVATE
            HACK_STACK_WORDS=${HACK_STACK_WORDS}
    )
endif()

target_link_options(bootrom_raw PRIVATE "LINKER:--script=${CMAKE_BINARY_DIR}/bootrom_arm.ld")
set_target_properties(bootrom_raw PROPERTIES LINK_DEPENDS ${CMAKE_BINARY_DIR}/bootrom_arm.ld)
add_custom_command(TARGET bootrom_raw POST_BUILD
        COMMAND ${CMAKE_NM} $<TARGET_FILE:bootrom_raw> >${CMAKE_BINARY_DIR}/bootrom.sym
        )

pico_add_extra_outputs(bootrom_raw)

target_link_options(bootrom_raw PRIVATE -save-temps -fverbose-asm)

find_package (Python3 REQUIRED COMPONENTS Interpreter)

set(BOOTROM_ELF "${CMAKE_BINARY_DIR}/bootrom.elf")
add_custom_command(OUTPUT ${BOOTROM_ELF}
        DEPENDS $<TARGET_FILE:bootrom_raw>
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/inject_p16 $<TARGET_FILE:bootrom_raw> ${CMAKE_BINARY_DIR}/bootrom.sym ${BOOTROM_ELF} ${P16_TARGETS}
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/inject_rcp_consts ${BOOTROM_ELF} ${BOOTROM_ELF}
        COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/overwrite_prolog ${BOOTROM_ELF} ${CMAKE_BINARY_DIR}/bootrom.sym ${BOOTROM_ELF}
        VERBATIM)

add_custom_target(bootrom ALL DEPENDS ${BOOTROM_ELF})
add_custom_command(TARGET bootrom POST_BUILD COMMAND ${CMAKE_OBJCOPY} -Obinary ${BOOTROM_ELF} ${CMAKE_BINARY_DIR}/bootrom.bin VERBATIM)
add_custom_command(TARGET bootrom POST_BUILD COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/bin2hex.py -32 ${CMAKE_BINARY_DIR}/bootrom.bin ${CMAKE_BINARY_DIR}/bootrom.h32)
add_custom_command(TARGET bootrom POST_BUILD
        COMMAND ${CMAKE_OBJDUMP} -h ${BOOTROM_ELF} > ${CMAKE_BINARY_DIR}/bootrom.dis
        COMMAND ${CMAKE_OBJDUMP} -d ${BOOTROM_ELF} >> ${CMAKE_BINARY_DIR}/bootrom.dis
        COMMAND ${Python3_EXECUTABLE} ${PICO_TOOLS_DIR}/copro_dis.py ${CMAKE_BINARY_DIR}/bootrom.dis ${CMAKE_BINARY_DIR}/bootrom.dis
        VERBATIM
)
add_custom_command(TARGET bootrom POST_BUILD
        COMMAND ${CMAKE_COMMAND} -E copy ${CMAKE_BINARY_DIR}/bootrom_raw.elf.map ${CMAKE_BINARY_DIR}/bootrom.elf.map
)
