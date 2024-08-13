# Serial Boot Modes

For RP2350 we want to add the following additional boot media over RP2040:

- UART
- I2C slave
- OTP

OTP is similar to flash: it is checked before dropping into BOOTSEL mode (unless the flash CSn pin is driven low), and if it is valid then we boot from it. UART and I2C boot are more similar to USB boot: they are interfaces for an external host to load code once we enter BOOTSEL mode. However, they are expected to be much simpler than USB boot, because they are for use with less sophisticated hosts.

This document is a first stab at defining the UART and I2C slave boot modes.

## Objectives

UART/I2C boot modes are used in two cases:

- First-time bootstrapping of unprogrammed boards, as an alternative to USB/SWD
- Chain-booting a flashless RP2350 from a host device on the same board, on a normal boot
	- E.g. if flash has been removed as a cost-saving measure
	- Host device may be another microcontroller, potentially less powerful than RP2350

So the goals are:

- UART and I2C boot allow code to be loaded and executed even on a device with blank OTP
- Must not require an external flash to be connected
- Must require the absolute minimum amount of software running on the host (the host may be another microcontroller)
- Must allow a flat image to be loaded and executed in SRAM (anything else can be bootstrapped from the first image)
- (Stretch goal) UART and I2C boot can be used with no external crystal
- (Stretch goal) allow the PicoBoot protocol to be tunneled through I2C/UART, e.g. for OTP programming

Some assumptions:

- There is no requirement to run UART/I2C boot concurrently with USB boot

## Hardware interfaces

UART and I2C boot will use the hardware UART/I2C blocks. In BOOTSEL mode, the system clock (and clk_peri) are assumed to run at 48 MHz, providing a stable frequency reference for I2C/UART baud rates.

I2C is fixed at 100 kHz, UART is fixed at 1 Mbaud.

By default, the QSPI SD2/SD3 pins are used:

- SD2: UART0 TX/I2C1 SDA
- SD3: UART0 RX/I2C1 SCL

(Note this uses the new F11 "UART AUX" function select.) These pins are chosen because they are are not required for serial/dual-SPI operation, so the bootrom can still access flash even when we borrow SD2/SD3.

To enable selection of boot mode, we overload the SD0/SD1 pins (driven low by default) as boot mode selectors, sampled upon entering BOOTSEL mode:

- `{SD1, SD0} = 0x0`: USB boot (the only option on previous devices)
- `{SD1, SD0} = 0x1`: UART boot
- `{SD1, SD0} = 0x2`: I2C boot
- `{SD1, SD0} = 0x3`: Reserved for future use

Once the bootrom has sampled the boot mode, it enables the relevant interface.

The default I2C slave address is `0x52` (an ASCII capital R, and a relatively uncommon address according to [this list](https://learn.adafruit.com/i2c-addresses/the-list))

TODOs:

- Do we allow pin assignment to be overridden by OTP? (We could just as well have people install their own UART/I2C bootloaders into OTP and boot those.)

## Security Model

BOOTSEL mode is a NonSecure application launched by the initial Secure bootrom code. Presently it contains a USB bootloader which is capable of loading contents into SRAM or flash (the latter via Secure calls), and then requesting that contents to be run. BOOTSEL mode is not trusted by the Secure bootrom code, because it runs a complex protocol stack that is assumed to be exploitable. When boot signing is enabled, the Secure code _verifies_ whatever was loaded by BOOTSEL code before running it.

UART and I2C slave boot will piggyback onto this model. They run in the BOOTSEL code, as alternatives to the USB bootloader. The Secure code largely does not care that they exist -- they are just another way for BOOTSEL mode to load untrusted code. Whatever is loaded by UART/I2C boot will be verified if necessary by the Secure code.

### GPIO Security

In USB boot, flash remains a Secure peripheral, and NS code can only access flash via Secure calls. This means the decision to connect NS-owned peripherals (UART, I2C) to the QSPI pins *must be made by Secure code.* Otherwise there is a risk of NS code interfering with Secure QSPI accesses at the wire level. So:

- The check of the boot mode pins (SD0/SD1) should be performed by Secure code before entering the NS application
- SD0/SD1 should not be set in NSMASK
- The NSMASK bits for SD2/SD3 should be set by Secure code if and only if the NS application requires them (i.e. UART or I2C boot has been selected)

## Protocol Alternative A: Absolutely Minimal

This is assuming we do *not* want the complexity of tunnelling PicoBoot through UART/I2C, for absolutely minimal code on the host. Consider this protocol a strawman for now. The byte-level protocol for UART and I2C boot is the same:

- Wake sequence: to initiate communications, send the UF2 family ID (a well-known entropy-dense constant)
- Then a 32-bit count of bytes to be loaded at the base of SRAM
- The bitwise complement of this count
- Then the payload
- Then a CRC32 of the entire transfer with the same CRC parameters as RP2040 boot2

For I2C, any departure from this sequence results in a NAK. Following a NAK, the host is free to restart the sequence from the very beginning. Success occurs when the CRC32 is ACK'd (which may follow a very long clock stretch).

For UART, any departure from this sequence results in an ASCII '!' character (0x21) being sent on UART TX. Following an error, the host waits for the UART FIFOs to drain and restarts the transfer. Once the CRC32 has been confirmed, the string `"OK"` is sent on UART TX.

Once the code has been loaded, the bootrom jumps directly to the base of SRAM (`0x20000000`).

## Protocol Alternative B: PicoBoot Tunnelling

Reusing the existing PicoBoot protocol slightly increases the minimum complexity of the host software for loading code. However, it allows reuse of existing bootrom code, and avoids a proliferation of bootloader interfaces on our microcontrollers.

### PicoBoot Recap

PicoBoot is an RPi-specific boot shell implemented on a single `IN` and `OUT` USB endpoint. 32-byte command packets are sent to the `OUT` endpoint, and these may be followed by variably-sized data transfers through either endpoint (depending on direction). The total size of the data transfer is given by the command packet, but the data transfer is broken into 64-byte (maximum) blocks to fit the maximum USB FS bulk packet size.

```c
struct __packed __aligned(4) picoboot_cmd {
    uint32_t dMagic;
    uint32_t dToken; // an identifier for this token to correlate with a status response
    uint8_t bCmdId; // top bit set for IN
    uint8_t bCmdSize; // bytes of actual data in the arg part of this structure
    uint16_t _unused;
    uint32_t dTransferLength; // length of IN/OUT transfer (or 0) if none
    union {
        uint8_t args[16];
        struct picoboot_reboot_cmd reboot_cmd;
        struct picoboot_range_cmd range_cmd;
        struct picoboot_address_only_cmd address_only_cmd;
        struct picoboot_exclusive_cmd exclusive_cmd;
        struct picoboot_reboot2_cmd reboot2_cmd;
        struct picoboot_otp_cmd otp_cmd;
    };
};
```

PicoBoot does not have any built-in checksums, since it is built on top of USB, which provides error detection at multiple levels. This means the PicoBoot-over-UART and PicoBoot-over-I2C protocols will have to add similar protection.

### PicoBoot-over-I2C protocol

We encapsulate USB IN/OUT packets in the following I2C line format:

* Read (PID=IN/GETSTAT):
	* Start
	* Write+Addr
	* Packet header byte
	* Packet header byte parity (complement)
	* Restart
	* Read+Addr
	* _n_ byte reads
	* 2 bytes for CRC16
	* Stop
* Write (PID=OUT):
	* Start
	* Write+Addr
	* Packet header byte
	* Packet header byte parity
	* _n_ byte writes
	* 2 bytes for CRC16
	* Stop

A packet header byte consists of a 2-bit PID and a 6-bit length (in the range 1-64 bytes, with _n_ bytes being encoded as the value _n_ - 1).

The PIDs are:

* `0x0` OUT
* `0x1` IN
* `0x2` GETSTAT
* `0x3` Reserved

OUT/IN encapsulate a single OUT/IN transfer to be passed to the PicoBoot code. For OUT this may be a command or a data transfer. For IN this is always a data transfer.

GETSTAT is a special single-byte read command for reading the status byte, a 1-byte value maintained by the bootrom I2C code. Its packet header the magic length `0x25`. The possible error values are:

* `0x0`: No error
* `0x1`: Packet header parity error
* `0x2`: Write data CRC error
* Other values: some other error not listed here

When the status byte is nonzero, any command except for GETSTAT gets a NAK response from the I2C slave. Reading the status via GETSTAT clears the status byte. Once the status byte becomes nonzero, its value does not change again until it is cleared via GETSTAT.

If the device is addressed whilst a previous command is still in progress, the clock is stretched until that command completes, so there is no need to poll for completion of a command.

### PicoBoot-over-UART protocol

Again, this is meant to be a lightweight encapsulation of the USB IN/OUT packets used by PicoBoot.

* Read (PID=IN/CHECKERR):
	* RX: Packet header byte
	* RX: Packet header byte parity (complement)
	* TX: _n_ bytes read
	* TX: 2-byte CRC16
* Write (PID=OUT):
	* RX: Packet header byte
	* RX: Packet header byte parity
	* RX: _n_ bytes write
	* RX: 2-byte CRC16
	* TX: *(once complete)* Current value of error status byte, without clearing it

The TX at the end of the write packet is to allow the host to check that RP2350's FIFOs are drained before it sends more data.

### Differences to PicoBoot between USB and non-USB transports

There is only one difference: the `EXCLUSIVE_ACCESS` command is a successful NOP on non-USB transports, since these don't have a mass storage interface to exclude.
