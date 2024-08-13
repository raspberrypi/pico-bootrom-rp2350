add_library(mini_printf INTERFACE)

target_sources(mini_printf INTERFACE
        ${CMAKE_CURRENT_LIST_DIR}/mini_printf.c
)

if (PRINTF_TO_TB)
    target_compile_definitions(mini_printf INTERFACE PRINTF_TO_TB=1)
endif()

target_include_directories(mini_printf INTERFACE ${CMAKE_CURRENT_LIST_DIR})