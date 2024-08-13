# code that is compiled for both arm and riscv
add_subdirectory(native)

if (PICO_RISCV)
    add_subdirectory(riscv)
else()
    add_subdirectory(arm)
endif()
