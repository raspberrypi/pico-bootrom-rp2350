cmake_minimum_required(VERSION 3.14)
set(CMAKE_C_STANDARD 11)

set(PICO_NO_UF2 1) # turn off SDK UF2 output
if (NSBOOT_BUILD AND NOT PICO_COMPILER)
    set(PICO_COMPILER "pico_arm_cortex_m23_gcc")
endif()

if (NOT INCLUDE_TESTS AND NOT SB_TEST)
    set(PICO_BARE_METAL 1)
else()
    # SDK versions conflict with code to be tested
    set(SKIP_PICO_BIT_OPS 1)
    if (NSBOOT_BUILD)
        set(SKIP_PICO_MEM_OPS 1)
    endif()
endif()
set(PICO_NO_CMSE 1) # override default RP2350 behavior

# PICO_SDK_PATH must be specified on CMake command line if overriden to make sure we don't pick up random environment
if (NOT PICO_SDK_PATH) # so we pick up SDK path set above on re-configure
    set(PICO_SDK_PATH ${CMAKE_CURRENT_LIST_DIR}/lib/pico-sdk)
endif()
include(${PICO_SDK_PATH}/pico_sdk_init.cmake)
project(amy-bootrom)

pico_sdk_init()

add_subdirectory(src)

