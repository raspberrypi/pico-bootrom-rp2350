add_library(nsboot_native INTERFACE)
target_sources(nsboot_native INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}/usb_device.c
        ${CMAKE_CURRENT_LIST_DIR}/usb_stream_helper.c
        )
target_include_directories(nsboot_native INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}
        )
target_link_libraries(nsboot_native INTERFACE
        nsboot_config)