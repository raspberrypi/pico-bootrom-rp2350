#!/bin/bash
set -ex

# Config

# Using prebuilt CORE-V toolchain for RISC-V bootrom development, as Zcb/Zcmp
# are not yet available in mainline GCC. The prebuilt toolchains have a
# slightly wonky multilib setup, so not suitable for general RISC-V software
# development (use mainline GCC12), but we need the better code density of
# Zcb/Zcmp in the bootrom, and don't care about stdlib.


if [ -z ${RISCV_PICO_COMPILER} ]; then
    RISCV_PICO_COMPILER=pico_riscv_gcc_zcb_zcmp
fi

if [[ "$ASIC_ENV" == 1 ]]; then
    echo "Building for ASIC"
    CMAKE=/opt/compilers/riscv/cmake/CMake/bin/cmake
    ARM_TOOLCHAIN_PATH=/opt/compilers/arm-gnu-toolchain-12.2.rel1-x86_64-arm-none-eabi/bin
    ARM_TOOLCHAIN="-DPICO_TOOLCHAIN_PATH=$ARM_TOOLCHAIN_PATH"
    if [ -z ${RISCV_TOOLCHAIN_PATH} ]; then
        RISCV_TOOLCHAIN_PATH="/opt/compilers/riscv/corev-openhw-gcc-centos7-20240114/bin"
    fi
    ARM_NONE_EABI_OBJCOPY="$ARM_TOOLCHAIN_PATH/arm-none-eabi-objcopy"
    ARM_NONE_EABI_OBJDUMP="$ARM_TOOLCHAIN_PATH/arm-none-eabi-objdump"
  if [ -z ${ROM_SRC_DIR} ]; then
    ROM_SRC_DIR="$PROJ_ROOT/software/amy-bootrom"
  fi
else
    CMAKE=cmake
    ARM_TOOLCHAIN_PATH=""
    ROM_BUILD_DIR=$(pwd)
    ROM_SRC_DIR=$(pwd)
    if [ -z ${RISCV_TOOLCHAIN_PATH} ]; then
        RISCV_TOOLCHAIN_PATH=/opt/compilers/riscv/riscv32-unknown-elf/bin
    fi
    ARM_NONE_EABI_OBJCOPY=arm-none-eabi-objcopy
    ARM_NONE_EABI_OBJDUMP=arm-none-eabi-objdump
fi

if [ -z ${BIN2HEX} ]; then
    BIN2HEX=${ROM_SRC_DIR}/scripts/bin2hex
fi

RISCV_OBJCOPY=$(ls $RISCV_TOOLCHAIN_PATH/*objcopy)
    
if [ -z ${ROM_BUILD_DIR} ]; then
    echo "Must define ROM_BUILD_DIR"
    exit 1
fi

if [ -z ${ROM_SRC_DIR} ]; then
    echo "Must define ROM_SRC_DIR"
    exit 1
fi

# Ensure build directories exist. Blow them away first if a clean build is requested.

BUILD_V8M_DIR="$ROM_BUILD_DIR/build-v8m"
BUILD_RISCV_DIR="$ROM_BUILD_DIR/build-riscv"
BUILD_V6M_DIR="$ROM_BUILD_DIR/build-v6m"
BUILD_COMBINED_DIR="$ROM_BUILD_DIR/build-combined"

if [[ "$CLEAN_BUILD" == 1 ]]; then
    rm -rf $BUILD_V8M_DIR || true
    rm -rf $BUILD_RISCV_DIR || true
    rm -rf $BUILD_V6M_DIR || true
    rm -rf $BUILD_COMBINED_DIR
fi

mkdir -p $BUILD_V8M_DIR
mkdir -p $BUILD_RISCV_DIR
mkdir -p $BUILD_V6M_DIR
mkdir -p $BUILD_COMBINED_DIR

# Build raw images for various architectures

cd $BUILD_V8M_DIR
$CMAKE -DPICO_PLATFORM=rp2350 -DPICO_BOARD=amethyst_fpga $ARM_TOOLCHAIN $ROM_SRC_DIR
make bootrom
cd ..

cd $BUILD_V6M_DIR
$CMAKE -DPICO_PLATFORM=rp2350 -DPICO_BOARD=amethyst_fpga $ARM_TOOLCHAIN -DNSBOOT_BUILD=1 -DBOOTROM_ARM_SYM_FILE="$BUILD_V8M_DIR/bootrom.sym" $ROM_SRC_DIR
make nsboot
cd ..

cd $BUILD_RISCV_DIR
$CMAKE -DPICO_PLATFORM=rp2350-riscv -DPICO_BOARD=amethyst_fpga -DPICO_TOOLCHAIN_PATH=${RISCV_TOOLCHAIN_PATH} -DPICO_COMPILER=${RISCV_PICO_COMPILER} -DBOOTROM_ARM_SYM_FILE="$BUILD_V8M_DIR/bootrom.sym" -DNSBOOT_SYM_FILE="$BUILD_V6M_DIR/nsboot.sym" $ROM_SRC_DIR
make bootrom
cd ..

# Extract the two bread slices from the v8-M bootrom. Note the SGs must go at
# one end of ROM because the IDAU NSC boundary is fixed, and putting them at
# the far end allows the v8-M vector table to remain at offset +0x0.

$ARM_NONE_EABI_OBJCOPY $BUILD_V8M_DIR/bootrom.elf -j .text -O binary $BUILD_COMBINED_DIR/v8m-text.bin
$ARM_NONE_EABI_OBJCOPY $BUILD_V8M_DIR/bootrom.elf -j .secure_gateways -O binary $BUILD_COMBINED_DIR/v8m-secure-gateways.bin
$BIN2HEX $BUILD_COMBINED_DIR/v8m-text.bin $BUILD_COMBINED_DIR/v8m-text.h32
$BIN2HEX $BUILD_COMBINED_DIR/v8m-secure-gateways.bin $BUILD_COMBINED_DIR/v8m-secure-gateways.h32

# Also need to split off the RISC-V size hack region from the main binary, as
# these straddle the hole that the SGs need to end up in, at 0x7e00
$RISCV_OBJCOPY -O binary -j .text -j .romtable -j .entry $BUILD_RISCV_DIR/bootrom.elf $BUILD_COMBINED_DIR/riscv-text.bin
$RISCV_OBJCOPY -O binary -j .riscv_space_saving_temp $BUILD_RISCV_DIR/bootrom.elf $BUILD_COMBINED_DIR/riscv-post-sg-hack.bin
$BIN2HEX $BUILD_COMBINED_DIR/riscv-text.bin $BUILD_COMBINED_DIR/riscv-text.h32
$BIN2HEX $BUILD_COMBINED_DIR/riscv-post-sg-hack.bin $BUILD_COMBINED_DIR/riscv-post-sg-hack.h32

# The v6-M and RISC-V images then form the bacon and tomatoes (respectively)
# of our sandwich.

cat $BUILD_COMBINED_DIR/v8m-text.bin $BUILD_V6M_DIR/nsboot.bin $BUILD_COMBINED_DIR/riscv-text.bin $BUILD_COMBINED_DIR/v8m-secure-gateways.bin $BUILD_COMBINED_DIR/riscv-post-sg-hack.bin > $BUILD_COMBINED_DIR/bootrom-combined.bin
cat $BUILD_COMBINED_DIR/v8m-text.h32 $BUILD_V6M_DIR/nsboot.h32 $BUILD_COMBINED_DIR/riscv-text.h32 $BUILD_COMBINED_DIR/v8m-secure-gateways.h32 $BUILD_COMBINED_DIR/riscv-post-sg-hack.h32 > $BUILD_COMBINED_DIR/bootrom-combined.h32

final_bin_size=$(du -b $BUILD_COMBINED_DIR/bootrom-combined.bin | awk '{print $1;}')
# Permitted sizes for: 32k chip ROM, 64k FPGA dev ROM, 80k RAM-ROM
if [[ ${final_bin_size} != 32768 && ${final_bin_size} != 65536 && ${final_bin_size} != 81920 ]]; then
    echo "Wrong final bootrom size! Check the .bin pasting" && false
fi

# Instruction scanning checks on final binary image
${ROM_SRC_DIR}/scripts/check_sg_symbols $BUILD_COMBINED_DIR/bootrom-combined.bin $BUILD_V8M_DIR/bootrom.elf $ARM_NONE_EABI_OBJDUMP

# Check for duplicate ROM table codes
${ROM_SRC_DIR}/scripts/check_rom_table_duplicates ${ROM_SRC_DIR}/lib/pico-sdk/src/rp2_common/pico_bootrom/include/pico/bootrom_constants.h

# Check for useless RCPs of a register with itself
${ROM_SRC_DIR}/scripts/check_useless_rcps $BUILD_V8M_DIR/bootrom.dis

# Check for RCP tags which have count_set without count_check, or only one of canary_get/canary_set
${ROM_SRC_DIR}/scripts/check_useless_canaries $BUILD_V8M_DIR/bootrom.dis

# Check for function returns where there isn't a canary function since the beginning of the function
${ROM_SRC_DIR}/scripts/check_function_returns $BUILD_V8M_DIR/bootrom.dis
