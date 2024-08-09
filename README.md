# Overview

This is the A2 version of the RP2350 bootrom.

The source is provided for reference purposes. Whilst you can build a matching binary if you use the exact right compilers, it may be simpler just to use the ELFs with debug info provided as part of the release artifacts. 

It is highly recommended that you read the "Bootrom Concepts" section in the [RP2350 Datasheet](https://datasheets.raspberrypi.com/rp2350/rp2350-datasheet.pdf) as a background, or indeed the whole Bootrom chapter!

# Building the bootrom

The bootrom breaks into four flat images, coming from three separate link steps: 

1. First is the main ARMv8-M Mainline (M33) boot image that holds the majority of the boot code and API functions.
2. Next is the NS boot; an ARMv8-M Baseline (M23) image which is run as a Non Secure application on the ARM processors or via emulation on the RISC-V processors. This binary contains the USB and UART bootloaders
3. Next is the main RISC-V boot image. This binary contains an emulator for ARMv8-M Baseline, and other RISC-V only code.
4. Finally, the Secure Gateway image, which is linked as part of the v8-M boot image

For more information on the separate bootrom parts see the Bootrom Details section below.

Why the hole between the main v8-M image and the Secure Gateway image? This is because the SG address range is fixed in the IDAU, which is a fixed hardware address decode network. Most of the ROM is IDAU-Exempt, but SG image is IDAU-NSC. If the SG image were somewhere in the middle of the ROM, rather than at one end, then it would partially fix the relative sizes of the other three images. If the SG image were at the _start_ of the ROM, it would push the main Arm vector table away from offset +0x0, which broke a surprising amount of software when we tried it. Therefore, the SGs are at the end of the mask ROM, with a hole between SGs and the ARMv8-M image to be filled with v6-M and RISC-V code.

## Build instructions for ARM M33 bootrom

NOTE: GCC 12.2 is required (you can download it here https://developer.arm.com/downloads/-/arm-gnu-toolchain-downloads and pass it to CMake via `-DPICO_TOOLCHAIN_PATH=/path/to/gcc-12`.

```
mkdir build
cd build
cmake -DPICO_PLATFORM=rp2350 ..
make bootrom
```

## Build instructions for NS boot
NOTE: GCC 12.2 is required

NOTE: That this build is dependent on some symbols from the ARM bootrom build. You need to pass the path to the generated symbol file from that build via `-DBOOTROM_ARM_SYM_FILE`

```
mkdir build-nsboot
cd build-nsboot
cmake -DPICO_PLATFORM=rp2350 -DPICO_COMPILER=pico_arm_cortex_m23_gcc -DBOOTROM_ARM_SYM_FILE=/path/to/arm-bootrom-build/bootrom.sym ..
make nsboot
```

## Build instructions for RISC-V bootrom

NOTE: That this build is dependent on some symbols from the ARM bootrom build. You need to pass the path to the generated symbol file from that build via `-DBOOTROM_ARM_SYM_FILE`

```
mkdir build-riscv
cd build-riscv
cmake -DPICO_PLATFORM=rp2350-riscv -DPICO_COMPILER=pico_riscv_gcc_zcb_zcmp -DBOOTROM_ARM_SYM_FILE=/path/to/arm-bootrom-build/bootrom.sym ..
make bootrom
```

## Building a Combined Image
NOTE: you need to set up the compilers first

```bash
export BIN2HEX=./bin2hex.py
export ARM_TOOLCHAIN="-DPICO_TOOLCHAIN_PATH=/opt/compilers/arm-gnu-toolchain-12.2.rel1-x86_64-arm-none-eabi"
export RISCV_TOOLCHAIN_PATH="/opt/compilers/riscv/centos-gcc12-rv32-corev-elf/bin"
./make-combined-bootrom.sh
```

## Getting a RISC-V compiler

Not all the fancy instructions supported by Hazard3 will be in the compilers in people's package managers right now (and we do want to use them here since the bitmanip instructions improve code density). At time of writing the master branch of `riscv-gnu-toolchain` is GCC 12, which does support the bit manipulation instructions.

The following compiler is known to be correct: `corev-openhw-gcc-ubuntu2204-20240114`. Others may or may not; because space is very tight, slight compiler variations can cause code not to fit.

Alernatively you can build a compatible one into `/opt/riscv` like this:

```bash
sudo apt install -y autoconf automake autotools-dev curl python3 libmpc-dev libmpfr-dev libgmp-dev gawk build-essential bison flex texinfo gperf libtool patchutils bc zlib1g-dev libexpat-dev
git clone --recursive https://github.com/riscv/riscv-gnu-toolchain
cd riscv-gnu-toolchain
./configure --prefix=/opt/riscv --with-arch=rv32imac_zicsr_zifencei_zba_zbb_zbc_zbs_zbkb --with-abi=ilp32
sudo mkdir /opt/riscv
sudo chown $(whoami) /opt/riscv
make -j $(nproc)
```

### OS X
```bash
brew install python3 gawk gnu-sed gmp mpfr libmpc isl zlib expat texinfo
brew tap discoteq/discoteq
brew install flock
```

# Bootrom Details

- 32K of ROM means we are very short on space. Not only code space, but also stack space. This has quite an effect on how the code is written.
- Because of limited space, we cannot duplicate a lot of code in RISC-V, so ARM code is emulated (varmulet) on RISC-V. We emulate (roughly) ARMv8-M Baseline not ARMv8-M Mainline as it has many fewer less complex instructions (ARM8-M Baseline adds a small number of, but very handy instructions over m0-plus)
    - 'a lot of' is perhaps an understatement... pretty much everything is emulated now, including the main boot path, and API functions.
    - there are a huge number of "asm hacks" where we drop into ass, and a bunch of other tricks we use to save instruction/data space.
    - Other than glue code, the only RISC-V code is really for RISC-V only APIs/setup, and stuff that needs to be optimized for speed.
    - Unused ARM hardware hint instructions (and/or RCP instructions) are used to make code behave differently under real ARM or emulation.
    - ARM only code is compiled for ARMv8-M Mainline (m33).
    - Emulatable code is compiled for ARMv8-M Baseline (m23), though emulation of UDIV and SDIV is not included in the bootrom, since they are unused by emulated code. The actual instructions included are (over ARM6M0-plus)
        1. b.w, cbz, cbnz, movw, movt from ARMv8-M Baseline.
        2. RCP instructions (they are NOPs).
        3. Special cases of mov.w. This is a ARMv8-M Mainline instruction, but we want efficient loads of constants 0xmm00mm00, 0x00nn00nn and 0xpppppppp which are used by the RCP
        4. MSPLIM (also ARMv8-M Mainline)
        5. SG (ARMv8-M Mainline) we can redirect ARM NS->S calls to different code on RISC-V.
    - We use function name prefixes to help clarify what code runs where.
      -  
- Sweet-B is used for elliptic curve signature verification for ARM only.
- NSBoot (which includes the UF2/USB bootloader) is a non-secure client _app_ under ARM. It is emulated under RISC-V. The intention is to allow this code to run on a secured chip, though it can be disabled via OTP.
    - There is some distinction in the code for code entering the secure side from NSBOOT versus user NS code; you'll see `s_from_nsboot_foo` vs `s_from_ns_foo` ... the NSBOOT code has its own pseudo security level, and its special APIs are/(should be) locked down when not in use.
    - Calls from NSBOOT into the secure mode go thru SG on ARM, and can do
- GCC does well for us, but:
  - It is impossible (it seems) to coerce it to use `mov.w` for constants for code originating in a ARMv8-M Baseline source file, so we post process the ELF to insert these (we assemble an unused coprocessor MRC instruction).
  - It has no "tiny" memory model on ARM. All our code/rodata pointers are known to be 16 bit, so we place `movw reg, 0xbbxx` in the code, where `xx` is an ordinal, and replace the contents in the ELF afterwards. This is all the P16_ macro stuff you see, to keep it vaguely clean in the source, and the build files provide the lists of symbols referenced in this way.
  - We want to directly use symbols from the ARM S binary in the NSBOOT and RISC-V binary, so we have some build support for taking symbols from the one, and inserting them via linker script into the others.
- You may also note that the bootrom specific use of the emulator (varmulet) is a runtime adaptation of the core code, so an intrepid user could re-use the emulation code from the bootrom themselves.
- This is the description from the code for the split of memory
  ```
  // Enable SAU region 7, which will remain "reserved by us" through and
  // post boot. This sets everything past the end of the Secure-only text
  // to SAU-NS. When combined with the IDAU, the final attribute map is:
  //
  //   Start             End               Attribute (I)  Attribute (D)  Contents
  //   0000           -> 42ff              Exempt         Exempt         Shared .text
  //   4300           -> sonly_text_end-1  Secure         Exempt         Not-NonSecure .text
  //   sonly_text_end -> 7dff              NonSecure      Exempt         .rodata, RISC-V code
  //   7e00           -> 7fff              Secure NSC     Secure NSC     SGs and SG->S wrappers
  //
  // Notes:
  //
  // - The 4300 here is actually 9300 for 64k ROM development FPGA builds
  //
  // - We intended for the 4300 to be tie-cell-programmable, it's a bit of a
  //   funny story (got case-analysed during STA)
  //
  // - The "Not-NonSecure .text" has no security requirement to be
  //   Secure-only, it's just that we can't make all of our text shared due
  //   to lack of IDAU Exempt->S watermark flexibility, so we have to keep
  //   shared text (such as ROM table lookup func) out of this region
  //
  // - The difference between fetch and load/store was a late-in-the-day
  //   synthesis hack, and isn't supposed to exist in v8-M (sorry Joseph).
  //   Having all of ROM be Exempt for load/stores is fine, we just don't
  //   want all of it to all be Secure-executable, since this would mean a
  //   larger ROP surface.
  ```

