cmake_minimum_required(VERSION 3.14)
set(USE_BOOTROM_GPIO 1)
#set(PRINTF_IN_NATIVE 1)
#set(PRINTF_IN_RISCV 1)
#set(PRINTF_IN_ARM 1)
#set(PRINTF_IN_NSBOOT 1)
if (NOT DEFINED MINI_PRINTF_BAUD)
    set(MINI_PRINTF_BAUD 1000000)
endif()

## define the bootrom layout
set(BOOTROM_SIZE         0x8000)
set(BOOTRAM_SIZE          0x400)
# does not need to be word aligned (though it feels less dirty this way)
SET(BOOTROM_ROMTABLE_SIZE 0x11c)

if (NOT DEFINED USE_64K_BOOTROM)
    # for a1-dev we currently use 64K by default
#    set(USE_64K_BOOTROM 1)
endif()

if (USE_64K_BOOTROM)
    set(PICO_REAL_LAYOUT 0)
endif()
if (NOT DEFINED PICO_REAL_LAYOUT)
    # unset to use a custom layout (defined below)
    set(PICO_REAL_LAYOUT 1)
endif()

# set to build a RAM bootrom
# set(HACK_RAM_BOOTROM_AT 0x20040000)

# global define of the VTOR_OFFSET as we have to keep the vector table correctly aligned
set(NSBOOT_VTOR_OFFSET "-0x40")
if (HACK_RAM_BOOTROM_AT)
    message("Building a huge RAM bootrom at ${HACK_RAM_BOOTROM_AT}")
    set(PRINTF_IN_ARM 1)
    set(PRINTF_IN_RISCV 1)
    set(PRINTF_IN_NSBOOT 1)
    set(BOOTROM_HARDENING 1)
    set(BOOTROM_IDAU_EXEMPT_END 0xffffffff)
    set(BOOTROM_ARM_SIZE        0xc000)
    set(NSBOOT_SIZE             0x4700)
    set(BOOTROM_RISCV_SIZE      0x3700)
    set(BOOTROM_SG_SIZE         0x200)
    set(BOOTROM_SG_STEAL        0x0)
    set(BOOTROM_ROMTABLE_SIZE   0x200)
    set(BOOTROM_SIZE            0x14000)
    set(HACK_STACK_WORDS 8)
    if (NOT DEFINED USE_ASSERTS)
       set(USE_ASSERTS 1)
    endif()
    if (NOT DEFINED ARM_BOOTROM_ASSERT_DEFAULT_ENABLE)
        set(ARM_BOOTROM_ASSERT_DEFAULT_ENABLE ${USE_ASSERTS})
    endif()
    if (NOT DEFINED RISCV_BOOTROM_ASSERT_DEFAULT_ENABLE)
        set(RISCV_BOOTROM_ASSERT_DEFAULT_ENABLE ${USE_ASSERTS})
    endif()
    if (NOT DEFINED NSBOOT_ASSERT_DEFAULT_ENABLE)
        set(NSBOOT_ASSERT_DEFAULT_ENABLE ${USE_ASSERTS})
    endif()
    set(BOOTROM_32BIT_FUNC_POINTERS 1)
    add_compile_definitions(BOOTROM_32BIT_FUNC_POINTERS=1)
    add_compile_definitions(HACK_RAM_BOOTROM_AT=1)
elseif (PICO_REAL_LAYOUT)
    message("Using real bootrom layout, so no printf")
    set(PRINTF_IN_NATIVE 0)
    set(PRINTF_IN_ARM 0)
    set(PRINTF_IN_RISCV 0)
    set(PRINTF_IN_NSBOOT 0)
    set(BOOTROM_ARM_SIZE   0x4940)
    set(BOOTROM_IDAU_EXEMPT_END 0x4300)
    set(NSBOOT_SIZE      0x20ec)
    set(BOOTROM_RISCV_SIZE 0x13d4)
    set(BOOTROM_SG_SIZE    0x200)
    set(BOOTROM_SG_STEAL   0x0)
    set(BOOTROM_HARDENING 1)
    set(SILICON_BUILD 1) # remove stuff to make sim happy (and RISC-V timer enable)
    set(BOOTROM_ASSERT_DISABLED 1)
elseif (USE_64K_BOOTROM)
    set(NO_SWEETB 0)
    set(BOOTROM_ARM_SIZE   0xa040)
    set(BOOTROM_IDAU_EXEMPT_END 0x9300)
    set(NSBOOT_SIZE      0x3680)
    set(BOOTROM_RISCV_SIZE 0x2740)
    set(BOOTROM_SG_SIZE    0x200)
    set(BOOTROM_SG_STEAL   0x0)
    set(BOOTROM_HARDENING  1)
    set(BOOTROM_ROMTABLE_SIZE 0x140)
    set(BOOTROM_SIZE       0x10000)
    if (1)
        message("Building 64K ROM")
        set(HACK_STACK_WORDS 8)
        if (NOT DEFINED USE_ASSERTS)
           set(USE_ASSERTS 1)
        endif()
        if (NOT DEFINED ARM_BOOTROM_ASSERT_DEFAULT_ENABLE)
            set(ARM_BOOTROM_ASSERT_DEFAULT_ENABLE ${USE_ASSERTS})
        endif()
        if (NOT DEFINED RISCV_BOOTROM_ASSERT_DEFAULT_ENABLE)
            set(RISCV_BOOTROM_ASSERT_DEFAULT_ENABLE ${USE_ASSERTS})
        endif()
        if (NOT DEFINED NSBOOT_ASSERT_DEFAULT_ENABLE)
            set(NSBOOT_ASSERT_DEFAULT_ENABLE ${USE_ASSERTS})
        endif()

        set(PRINTF_IN_ARM 1)
        set(PRINTF_IN_RISCV 1)
        set(PRINTF_IN_NSBOOT 1)
    else()
        message("Building 64K ROM. no asserts no printf")
        set(USE_ASSERTS 0)
        set(PRINTF_IN_ARM 0)
        set(PRINTF_IN_RISCV 0)
        set(PRINTF_IN_NSBOOT 0)
        #set(BOOTROM_HARDENING 0)
    endif()
endif()
if (HACK_RAM_BOOTROM_AT)
    set(BOOTROM_ARM_START ${HACK_RAM_BOOTROM_AT})
else()
    set(BOOTROM_ARM_START 0x0000)
endif()
# free space used for nsboot (must not overlap actual USB usage of RAM)
set(NSBOOT_RAM_START         0x50100480)
set(NSBOOT_RAM_END           0x50101000)
set(BOOTRAM_BASE               0x400e0000)
set(BOOTRAM_RUNTIME_PER_CORE_SIZE 0x114)
set(BOOTRAM_ALWAYS_SIZE        0xd8)
set(BOOTRAM_PREBOOT_STACK_SIZE 0x20c)
set(BOOTROM_RISCV_END_SIZE 16)
if (NOT DEFINED HACK_STACK_WORDS)
    set(HACK_STACK_WORDS 0)
endif()
math(EXPR BOOTRAM_PREBOOT_STACK_SIZE "${BOOTRAM_PREBOOT_STACK_SIZE} + ${HACK_STACK_WORDS}*4")
set(BOOTRAM_ARM_STATIC_DATA_SIZE 0x0) # no static data on ARM
set(BOOTRAM_RISCV_STATIC_DATA_SIZE 0xb0) # set aside for allowed static data
set(PICOBIN_MAX_BLOCK_SIZE 0x280) # we need 1 of these (and we should be able to hold partition table)
set(PICOBIN_MAX_IMAGE_DEF_BLOCK_SIZE 0x180)
set(PICOBIN_MAX_PARTITION_TABLE_BLOCK_SIZE 0x280)
set(PARSED_BLOCK_LOOP_SIZE 0x49c)
set(BLOCK_BUFFER_OR_SIGNATURE_WORKSPACE_SIZE 0x280)
set(MAX_XIP_SETUP_SIZE 0x100)
set(CORE0_BOOT_USBRAM_WORKSPACE_SIZE_PADDING_WORDS 0)
set(LARGEST_BOOTSCAN_CONTEXT_SIZE 0x40)
math(EXPR CORE0_BOOT_USBRAM_WORKSPACE_SIZE     "  ${BLOCK_BUFFER_OR_SIGNATURE_WORKSPACE_SIZE} + ${PARSED_BLOCK_LOOP_SIZE} * 2 + ${CORE0_BOOT_USBRAM_WORKSPACE_SIZE_PADDING_WORDS} * 4 + ${LARGEST_BOOTSCAN_CONTEXT_SIZE}" OUTPUT_FORMAT HEXADECIMAL)
set(CORE0_BOOT_USBRAM_MAX_WORKSPACE_SIZE 0xc00) # the limit we allow

math(EXPR BOOTROM_ARM_END      "${BOOTROM_ARM_START} + ${BOOTROM_ARM_SIZE}" OUTPUT_FORMAT HEXADECIMAL)

math(EXPR NSBOOT_START       "${BOOTROM_ARM_END}" OUTPUT_FORMAT HEXADECIMAL)
math(EXPR NSBOOT_END         "${NSBOOT_START} + ${NSBOOT_SIZE}" OUTPUT_FORMAT HEXADECIMAL)

math(EXPR BOOTROM_RISCV_START  "${NSBOOT_END}" OUTPUT_FORMAT HEXADECIMAL)
math(EXPR BOOTROM_RISCV_END    "${BOOTROM_RISCV_START} + ${BOOTROM_RISCV_SIZE}" OUTPUT_FORMAT HEXADECIMAL)

math(EXPR BOOTROM_SG_START     "${BOOTROM_RISCV_END}" OUTPUT_FORMAT HEXADECIMAL)
math(EXPR BOOTROM_SG_END       "${BOOTROM_SG_START} + ${BOOTROM_SG_SIZE} + ${BOOTROM_SG_STEAL}" OUTPUT_FORMAT HEXADECIMAL)

math(EXPR CALC_BOOTROM_SIZE     "${BOOTROM_ARM_SIZE} + ${NSBOOT_SIZE} + ${BOOTROM_RISCV_SIZE} + ${BOOTROM_SG_SIZE} + ${BOOTROM_SG_STEAL}" OUTPUT_FORMAT HEXADECIMAL)
# not going to bother with padding smaller sizes
if (NOT CALC_BOOTROM_SIZE STREQUAL BOOTROM_SIZE)
    if (HACK_RAM_BOOTROM_AT)
        set(BOOTROM_SIZE ${CALC_BOOTROM_SIZE})
    else()
        message(FATAL_ERROR "Total bootrom size ${CALC_BOOTROM_SIZE} is not ${BOOTROM_SIZE}")
    endif()
endif()

math(EXPR BOOTRAM_ARM_STATIC_DATA_START     "${BOOTRAM_BASE} + ${BOOTRAM_SIZE} - ${BOOTRAM_ALWAYS_SIZE} - ${BOOTRAM_ARM_STATIC_DATA_SIZE}" OUTPUT_FORMAT HEXADECIMAL)
math(EXPR BOOTRAM_RISCV_STATIC_DATA_START     "${BOOTRAM_BASE} + ${BOOTRAM_SIZE} - ${BOOTRAM_ALWAYS_SIZE} - ${BOOTRAM_RISCV_STATIC_DATA_SIZE}" OUTPUT_FORMAT HEXADECIMAL)


set(ARM_SYMBOL_LINKER_SCRIPT "${CMAKE_BINARY_DIR}/arm_imports.ld")
set(ARM_SYMBOL_HEADER "${CMAKE_BINARY_DIR}/arm_imports.h")
set(NSBOOT_SYMBOL_LINKER_SCRIPT "${CMAKE_BINARY_DIR}/nsboot_imports.ld")
set(NSBOOT_SYMBOL_HEADER "${CMAKE_BINARY_DIR}/nsboot_imports.h")

function(generate_arm_imports ARM_IMPORTS)
    # pull in addresses from the main arm ELF
    if (NOT DEFINED BOOTROM_ARM_SYM_FILE)
        message(FATAL_ERROR "Must define BOOTROM_ARM_SYM_FILE to path for current ARM bootrom symbols (bootrom.sym) in order to perform RISC-V or nsboot build")
    endif()
    if (NOT EXISTS ${BOOTROM_ARM_SYM_FILE})
        message(WARNING "${BOOTROM_ARM_SYM_FILE} not found; build may fail")
    endif()
    find_package (Python3 REQUIRED COMPONENTS Interpreter)

    # used in linker templates
    add_custom_target(make_arm_import_symbols DEPENDS ${ARM_SYMBOL_LINKER_SCRIPT})
    add_custom_command(OUTPUT ${ARM_SYMBOL_LINKER_SCRIPT} DEPENDS ${BOOTROM_ARM_SYM_FILE} ${PROJECT_SOURCE_DIR}/scripts/make_import_ld
            COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/make_import_ld ${BOOTROM_ARM_SYM_FILE} ${ARM_SYMBOL_LINKER_SCRIPT} ${ARM_IMPORTS}
            )
    add_custom_target(make_arm_import_symbols_header DEPENDS ${ARM_SYMBOL_HEADER})
    add_custom_command(OUTPUT ${ARM_SYMBOL_HEADER} DEPENDS ${BOOTROM_ARM_SYM_FILE} ${PROJECT_SOURCE_DIR}/scripts/make_import_header
            COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/make_import_header ${BOOTROM_ARM_SYM_FILE} ${ARM_SYMBOL_HEADER} ${ARM_IMPORTS}
            )
endfunction()

function(generate_nsboot_imports NSBOOT_IMPORTS)
    # pull in addresses from the main arm ELF
    if (NOT DEFINED NSBOOT_SYM_FILE)
        message(FATAL_ERROR "Must define NSBOOT_SYM_FILE to path for current nsboot (bootrom.sym) in order to perform RISC-V or nsboot build")
    endif()
    if (NOT EXISTS ${NSBOOT_SYM_FILE})
        message(WARNING "${NSBOOT_SYM_FILE} not found; build may fail")
    endif()
    find_package (Python3 REQUIRED COMPONENTS Interpreter)

    # used in linker templates
    add_custom_target(make_nsboot_import_symbols DEPENDS ${NSBOOT_SYMBOL_LINKER_SCRIPT})
    add_custom_command(OUTPUT ${NSBOOT_SYMBOL_LINKER_SCRIPT} DEPENDS ${NSBOOT_SYM_FILE} ${PROJECT_SOURCE_DIR}/scripts/make_import_ld
            COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/make_import_ld ${NSBOOT_SYM_FILE} ${NSBOOT_SYMBOL_LINKER_SCRIPT} ${NSBOOT_IMPORTS}
    )
    add_custom_target(make_nsboot_import_symbols_header DEPENDS ${NSBOOT_SYMBOL_HEADER})
    add_custom_command(OUTPUT ${NSBOOT_SYMBOL_HEADER} DEPENDS ${NSBOOT_SYM_FILE} ${PROJECT_SOURCE_DIR}/scripts/make_import_header
            COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/scripts/make_import_header ${NSBOOT_SYM_FILE} ${NSBOOT_SYMBOL_HEADER} ${NSBOOT_IMPORTS}
    )
endfunction()

# we need these for both compile and link due to flto
function(target_cl_options TARGET option)
    get_target_property(target_type ${TARGET} TYPE)
    if ("EXECUTABLE" STREQUAL "${target_type}")
        target_compile_options(${TARGET} PRIVATE ${option})
        target_link_options(${TARGET} PRIVATE ${option})
    else()
        target_compile_options(${TARGET} INTERFACE ${option})
        target_link_options(${TARGET} INTERFACE ${option})
    endif()
endfunction()

function(pico_add_h32_output TARGET)
    pico_get_runtime_output_directory(${TARGET} output_path)
    find_package (Python3 REQUIRED COMPONENTS Interpreter)
    add_custom_command(TARGET ${TARGET} POST_BUILD
            COMMAND ${Python3_EXECUTABLE} ${PROJECT_SOURCE_DIR}/bin2hex.py -32 ${output_path}${TARGET}.bin ${output_path}${TARGET}.h32)
endfunction()

configure_file(bootrom_layout.template.h ${CMAKE_BINARY_DIR}/bootrom_layout.h)
add_library(bootrom_layout INTERFACE)
target_include_directories(bootrom_layout INTERFACE ${CMAKE_BINARY_DIR})

function(set_bootrom_exe_flags TARGET)
    target_cl_options(${TARGET} "-g")
    target_cl_options(${TARGET} "-Os")
    target_cl_options(${TARGET} "-fno-jump-tables")
    target_cl_options(${TARGET} "-ftree-vrp") # added for -Warray-bounds
    target_cl_options(${TARGET} "-ffunction-sections")
    target_cl_options(${TARGET} "-fdata-sections")
    target_cl_options(${TARGET} "-flto")

    target_link_options(${TARGET} PRIVATE "LINKER:--build-id=none")
    target_link_options(${TARGET} PRIVATE "LINKER:--gc-sections")

    #    target_cl_options(${TARGET} PRIVATE "--save-temps")
    target_link_options(${TARGET} PRIVATE "--specs=nosys.specs")
    target_link_options(${TARGET} PRIVATE "-nostartfiles")

    target_cl_options(${TARGET} "-Wall")
    target_cl_options(${TARGET} "-Warray-bounds=2") # because we had an array subscript out of range that wasn't reported
    target_cl_options(${TARGET} "-Wextra")
#    target_cl_options(${TARGET} "-Werror")
    target_cl_options(${TARGET} "-Wnull-dereference")
    target_cl_options(${TARGET} "-Wuninitialized")
    target_cl_options(${TARGET} "-Wunused")
    target_cl_options(${TARGET} "-Wcast-align")
    target_cl_options(${TARGET} "-Wcast-qual")
    target_cl_options(${TARGET} "-Wconversion")
    target_cl_options(${TARGET} "-Wsign-compare")
    target_cl_options(${TARGET} "-Wstrict-prototypes")
    target_cl_options(${TARGET} "-Wno-inline")
#    target_cl_options(${TARGET} "-Wpacked") # avoided because of __packed in picoboot.h
#    target_cl_options(${TARGET} "-Wredundant-decls")

    target_cl_options(${TARGET} "-Wno-ignored-qualifiers")
    # note: we did have this at 4, however 0 seems to do no harm, and saves us 8 bytes
    # note: "SHELL:" allows passing two args as one, and solves deduplication problem
    #       with passing "--param" multiple times - if we add more params
    target_cl_options(${TARGET} "SHELL:--param max-completely-peel-times=0")

    if (USE_64K_BOOTROM)
        target_compile_definitions(${TARGET} PRIVATE
                USE_64K_BOOTROM=1
        )
    endif()
    target_compile_definitions(${TARGET} PRIVATE
            #FEATURE_EXEC2=1
            FEATURE_HARDENING_STEPS=1
            FEATURE_RISCV_USB_BOOT=1
            FEATURE_CANARIES=1
            FEATURE_UART_BOOT_SELECTABLE_INSTANCE=0
            GENERAL_SIZE_HACKS=1
            ASM_SIZE_HACKS=1
            USE_16BIT_POINTERS=1
            PICO_USE_SW_SPIN_LOCKS=0 # we don't use them, but if we did, we'd use the hardware
            NDEBUG)
    target_compile_definitions(${TARGET} PRIVATE
            MINI_PRINTF_BAUD=${MINI_PRINTF_BAUD})

    if (SILICON_BUILD)
        target_compile_definitions(${TARGET} PRIVATE SILICON_BUILD=1)
    endif()
    if (BOOTROM_ASSERT_DISABLED)
        target_compile_definitions(${TARGET} PRIVATE BOOTROM_ASSERT_DISABLED=1)
    endif()

    if (PICO_RISCV)
        # bit of a hack to decide whether we use save restore
        if ((CMAKE_C_FLAGS MATCHES ".*zcb.*") AND (CMAKE_C_FLAGS MATCHES ".*zcmp.*"))
            message("Have zcb/zcmp so turning off save-restore")
        else()
            message(WARNING "no zcb/zcmp in riscv compiler")
            target_cl_options(bootrom "-msave-restore")
        endif()
        target_cl_options(${TARGET} "-mtune=size")
        # Use lui+addi pairs instead of auipc+addi for global addresses, which
        # is smaller for us because ROM addresses all use 16-bit lui:
        target_cl_options(${TARGET} "-mcmodel=medlow")
    else()
        # We don't remove stdlib on RISC-V, as this prevents msave-restore from
        # working. Everything other than the save-restore routines should get
        # garbage-collected anyway.
        target_cl_options(${TARGET} "-nodefaultlibs")
        target_cl_options(${TARGET} "-nostdlib")
        target_cl_options(${TARGET} "-mno-unaligned-access")
        target_link_options(${TARGET} PRIVATE "LINKER:-z,max-page-size=1024")
    endif()
endfunction()

add_subdirectory(mini_printf)
add_subdirectory(common)
add_subdirectory(nsboot) # we do this anyway as it provides some common libraries (also must predate RISC-V)
if (NOT NSBOOT_BUILD)
    add_subdirectory(main)
endif()
