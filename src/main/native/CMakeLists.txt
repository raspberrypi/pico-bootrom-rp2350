add_library(bootrom_common INTERFACE)

target_sources(bootrom_common INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}/native_generic_flash.c
        )

target_compile_definitions(bootrom_common INTERFACE
        USE_BOOTROM_GPIO=${USE_BOOTROM_GPIO}
        BOOTROM_BUILD=1
        )

target_link_libraries(bootrom_common INTERFACE
        hardware_regs
        hardware_structs
        hardware_resets_headers
        hardware_sync_headers
        hardware_gpio_headers
        hardware_irq_headers
        hardware_exception_headers
        boot_uf2_headers
        boot_picoboot_headers
        boot_picobin_headers
        pico_bootrom_headers
        pico_platform_headers
        )

target_compile_definitions(bootrom_common INTERFACE
        NDEBUG)

target_include_directories(bootrom_common INTERFACE ${CMAKE_CURRENT_LIST_DIR})
target_link_libraries(bootrom_common INTERFACE
        bootrom_layout
        bootrom_shared_apis
        mini_printf)
