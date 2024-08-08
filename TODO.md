# TODO

## testing relevant

- make sure flash boot path ctx stuff checks booting (esp signing which should not load)

- ~~PT (block actually) has optional origin offset; needed for 0/1 and >4K~~
- ~~0054 make sure IMAGE_DEF scan checks version before sig...~~
- ~~select IMAGE_DEF with right signature (we do)~~
- ~~0031 otp to turn off PT stuff altogether~~
- ~~0055 need "try before you buy" (for flash) IMAGE_DEF watchdog reboot boot path~~
- ~~should secure boot failure (e.g. invalid sig) prevent fall thru to nsboot~~ i doo't think so; you can have secure boot and nsboot, or secure boot without nsboot (based on OTP)
- ~~oops we need bits for white label override~~
- ~~let's go thru OTP together (what is NSBOOT, what is USBBOOT - e.g. PLLs etc)~~
- ~~0056 partition table should support having HASH_VALUE~~
- ~~rename s_inline something else~~
- ~~make sure we erase USB RAM we use for boot up front (possibly leaving as much as we don't use - i.e. clear slot 1 
  later)~~
- ~~large streamed OTP via picoboot~~
- ~~check sig covers entry point? don't think we know it~~ user error!
- ~~make sure reboot after setting secure is deep enough to not cause OTP/hw mismatch on secure flags~~ luke says 
  its fine

## NEW SINCE DISCUSSED
- MCU boot - tim gover
- ~~LED flash codes for UF2 drag/drop~~
- ~~do we want people to be able to further refine flash permissions on top of PT...~~ yes
- ~~remove vectorize flash (issues with secure, but also starting to drag a flash UF2 can now trash RAM)~~ 
- extra secure launch core 1 (should this actually be in the bootrom) - previously thought it should be, but then again the user can do the same thing
  - it potentially saves code (the copying of SAU/MPU)
  - it IS necessary for a NS launch core 1 API
  - if you mix ARM/RISCV it should work fine (you don't get SAU/MPU sent if core 0 is RISC-V, it is ignored if core 1 is RISC-V)
  
--------------

- ~~what is issue with function calls in boot path vs branches~~ not much we just need to canary them
- ~~dont care about RAM-ness of partitions - users still fault if they download to RAM (ah this means if you have a 
  QSPI RAM)~~ correct
- ~~(I think you can sign a partition table, it just isn't necessary. benefit? if you want to allow picotool to 
  read/write and be
  sure that your permissions are respected)~~
- ~~do we still redirect thru boot path in flash binary (hopefully)~~ answer: yes

- Note everything with ~~strikethrough~~ should be revisited for testing

##

### Week 7/31
* ~~partition table should have UF2 family id list
  we have 4 built in (ARM secure, ARM non secure, RISC-V, data)~~
### Week 8/7
* ~~Any UF2 format updates (RP2350 family), but also do we support side-channel IMAGE_DEF for RAM binary~~
- UF2 downloads to non-physical addresses (downloading into partition)
  - what about 0x4000000 window - what does it mean to download to non 0x10->0x11
  - decision: windows is 32M and we should allow (which requires moving flash bitmap into RAM)
  - what about sparse binaries and partitions...
* RAM UF2 block tracking?
* Flash access during picoboot
* make sure we can support picotool use cases
  * multiple binaries
    * partitions
    * probably need boot search code equivalent (actually we ask device)
    * how to retrofit on RP2040 - well we can embed EXEDEFs there too
  * info on NS or S binaries
  * ~~how do we decide what is readable? do we rely on partition table, otherwise everything is?~~

## MAJOR MISSING FUNCTIONALITY

* ~~Secure picotool (bubble)~~
* NS APIs
* Permissioning for NS APIs
  * generic mechanism
* S/NS state comms
  * This was the use case of indicating things that need to be done between secure/non-secure (though manyu can be handled by looking whether you have access, but perhaps not - e.g. maybe secure uses UART, but leaves it open for NS - but NS runtime should not re-init it)
  * Maybe this is as simple as a couple of bits per device.
  * Question: how does this related to hardware claiming? if we support shared h/w blocks, then we should share claiming
 
#### not critical path
* signing tool

----

### Questions

- ~~Can we move to faster clock for flash launch? (signature check - is in A0)~~
  - also worried about RISC-V speed
    - note we can do a hint check possibly for clearing BOOTRAM (which is most of the instructions) - rcp check is valid before we init rcp which is good
- do we need to install handler mode stacks (esp for secure mode)
  - stack sealing - note my belief is not (if the secure user creates secure thread mode, then they should seal
    their stack, but we need to be sure)
  - luke thinks this is more general?
- who is responsible for setting SAU for secure binary (not thinking about it right now, can we default everything to secure which is fine)
  - do we need a PT api?
- should we use TRNG in sweet-b
  - luke should read too 
  - decision: may as well

### A0 ###

- ~~check NS watermark is correct and works as expected~~
- ~~hard float~~
. ~~powering up of RAMs... make sure this is done in all paths~~
- ~~look at USB RAM usage - allow use of 3K?~~
- ~~some way of deferring OTP decisions to RAM~~
- ~~some sort of secure boot (just with regular)~~
- ~~OTP boot~~
- ~~a rolling window trampoline~~
- ~~RAM boot~~
- ~~I2C/UART boot~~ UART only - needs to use PICOBOOT
- ~~image detect for UF2~~ only if EXE DEF is include
- ~~usb boot advance~~
- ~~boot into rAM?~~
- ~~more TRNG OTP settings~~
  - check TRNG defaults

## General

- call reset_state (with permissions and core 0) in main boot path
- ARM SC_ function pointers should be NSC versions (i.e. check flash accessibility etc.)
- ~~async_task check max read address of rom is 0x7e00 in NS at least~~ done
- ~~XIP_END used to mark the end of the flash XIP window, now it covers multiple~~ not used on RP2040
- ~~Get rid of `running_on_fpga()` checks~~
- updates based on otp characterization
- ~~. watchdog - we should ignore vectors if special flag is set~~ done
- ~~make sure core 1 launch doesn't break compatibility of RISC-V mixture (but remains secure)~~ fixed canary issue
- ~~OTP boot; we should have a RISC-V/ARM flag (could use LSB)~~
  - ~~if we require an EXEHDR then that is covered; however that is a minimum of 16 bytes~~
  - ~~yes, we now require IMAGE_DEF~~
- ~~decide whether we want IMAGE_DEF HASH check in risc-v - could probably save bootrom space without; IDK this is 
  now common code~~
- bootrom function to reset internal per execution state (so debug restart of program works)
  - this is separate from security setup for debugger
- Secure stuff
  - ~~secure RNG API - need to get in boot path; also used to assign per boot random value~~ none, sdk can do this, 
    we have no lock as it is only used in core 0 boot.
  - ~~lockdown RAM until usb boot (means turning on MPU); we do this now~~
- ~~auto varmulet use of varmuletable ones... no, but we need to implement some via varmulet at fixed address~~
  - ~~ordinal for varmulet (forgot about this)~~ not needed now
- ~~pre USB boot we should advance all NS OTP locks to fully-locked~~
- ~~pre USB boot we should erase all SRAM that will be NS-accessible~~
- ~~check secure boot flag for USB boot disabled~~
- ~~initialize canary; ignore in RISC-V (re-enable canary to check)~~
- ~~move mini_printf (on armv8m side) to be Armv6m so we don't break when calling under varmulet~~
- ~~move initial bootrom SP to top of BOOTRAM~~
- ~~starting via BOOTSEL/RUN seems to be broken on FPGA~~
- ~~flag bits in func tables; bump version;~~
- ~~(SP update option in varmulet)~~ - decided against this i think
- ~~why does a picotool error leave the device in a bad state? e.g. invalid cmd length~~
- ~~should we have a different VID/PID for RISC-V booted?~~ nope 
- ~~should we have different INFO_UF2.txt for different packages~~ answer per eben: no
- ~~allow an OTP setting for debug printf? (uh, no)~~
- ~~try clang?~~ no bueno
- ~~return code from _ns_boot (maybe cannot force mode etc)~~ we cant return because we are non-secure
- ~~watchdog code architecture - do we expect user to get it right; do we support varmulet?~~
- ~~Allow varmulation of boot2;~~ no.
- ~~can we use hardfault to make flash writing easier~~ fucking crazy
  - ~~who's hard fault handler?~~
- ~~make memset, memcpy in bootrom be ARMv8 - not much point , memset is faster than GCC one, and existing memcpy has
  the benefit that it works with peripheral memory (since it doesnt rely on unaligned accesses)~~
- ~~i notice that picotool times out when dealing with an error from PICOBOOT while streaming... the bootrom is
  HALTing the endpoint, so why does it not fail fast?~~ bootrom was not halting both IN and OUT endpoints
- ~~move submodules into lib subdirectory~~
- ~~only one boot key - what does this mean for stage2 - nothing - you just have to sign it - needs separate thermo~~
- why does USB activity led start on?
- ~~load stage2 into BOOTRAM~~
- ~~boot from OTP~~
- ~~stage2 from OTP?~~
- ~~stage2 from boot sector~~
- ~~How to find signatures?~~
- ~~we should reset accessctrl on bootrom entry~~
- ~~we need special watchdog/powman vector for going into USB boot~~
- ~~split lookup tables into secure/exempt/~~ - decided against this; uses flags instead
- ~~replace CTZ etc. with what you'd expect - to do bother to even keep?~~ not kept
- ~~Decide on the version numbers/magic numbers in the bootrom header~~ have changed
- ~~Update (VID)/PID~~ done: ours is now :000f
- ~~clean up build muck which was there to match old makefile builds~~
- ~~fix GPIO USB activity LED~~
- ~~varmulet integration~~
  - ~~Add WFE/SEV hint implemtations~~
  - ~~make sure flash stuff is SVC (well it has to be)~~
  - ~~possibly redirect the async_task done stuff via SVC (where it calls back into USB stack) - it uses functions we
    already have in RISC-V~~
  - ~~SG impl~~
  - ~~need to make VARMULET use consistent memory access registers (and also maybe make the regs a bit more sensible)~~
  - ~~canary instructions. **is ignoring all of these fine?**~~ yes (ignore)
- PICOBOOT
  - ~~RP2040 had no command to reset into USB boot; we should probably add one vs using current EXEC some code to
    call `reset_usb_boot` method ... update; indeed as that method is not NS (though we want an NS one anyway),
    however using EXEC in secure mode may not be supported~~
- ~~Disable FP etc in bootrom (if not using)~~
- ~~Consider re-adding FP trig functions~~ NO
- ~~Enable CMSE secure mode for ARMV8M for compiler~~ it sucks (bootrom)
- ~~Disable CMSE secure mode for ARMV6M for compiler~~ it sucks (bootrom)
- ~~__acle_se for~~ it sucks
- ~~secure Stack must be XN~~
- ~~remove "vectorize flash"~~
- canary
  - ~~should we just init it ourselves; not much use in the user doing it.~~ yes, since it is write once
  - ~~need to canary all secure area functions~~
- ~~0035 flash cache - should we allow binary to specify region of XIP to be left as RAM~~
- ~~0061 change block ids to be parity 1 (or 2)~~

# got to marker
### APIs

#### NSC & S

- are there other secure only (or likely secure only) that we should expose
- Set peripheral access
  - Processor ISTR (IRQ is secure/nonsecure) for an IRQ ought to be kept in sync with the corresponding peripheral's access manager permissions
- API for a secure binary to launch a nonsecure flash binary in a particular flash window, and set up its SAU-ness.

#### OTP related APIs

- done
- zero_bit_already_one
- key_already_set
- invalid param
- lock_sequence_error

secure: this is fine
non-secure: NSC wrapper which checks validty then call secure read/write code
RISCV: has them is secure

### Core1 related APIs

We need/want to basically take the pico_multicore core related functions and put them in the bootrom

####core1_launch()

## preboot

- ~~ability to tell a secure binary~~ signed binary is signed; a binary may be marked SECURE - todo decide how we 
  use the latter
- ~~clear RAM on entry to USB boot)~~

## nsboot

- respect and OTP store sub-device-type (to allow packaging multi-variants of a binary)
- ~~Move nsboot preamble (the part with mem erase etc) from native code into arm6_boot_path -- currently just the clock setup has been hoisted~~
- ~~safe eject (without complaining) can we send unit_attention, then respond to request sense with read/ready change 
  and media may have changed~~
- ~~optimization: read pages b4 flash erase in UF2? as per picotool (should probably be optional - can maybe use UF2 
  flags)~~ can't do it
- ~~how to tie the added block to the binary? - guarantee it is not on a sector boundary?~~ it has to be linked 
  explicitly; you always have a zero linke at end of chain
- ~~should OTP boot have an EXE HDR? (probably)~~ yes
- ~~salt in PICOBIN~~ not needed now we don't read off end of binary; this would have been hard anyway
- we should expose memcpy (for aligned only) - actually we already do
- ~~we should make CRC optional for XIP_SETUP based on IMAGE_DEF (could use IMAGE_DEF hash instead)~~
- ~~a BOS description for Windows~~
- ~~USB clock reference (different XTAL)~~

## BOOT SPEED

* maybe lazy fill reset of buffer, instead of moving to beginning - depends how complex that makes the code - this
  saves one read
* Locate Secp256k1 work variables in main SRAM for single-cycle load/store; save/restore the RAM region to USB RAM before/after running the Secp256k1 code
* ~~Use 32-bit IO for SHA updates~~
* ~~Use XIP stream to read SHA'd flash contents, so that flash interface can run in parallel with the processor 
  shuffling the data into the SHA block~~
* ~~Attempt QSPI read before falling back to SPI read~~
* ~~Attempt higher SCK before falling back to lower freq~~
* Hoist RISC-V check of scratch vectors back into pre-arm6 asm code, because we take a big hit to watchdog reboot time on RISC-V on A0. (Note if core 0 is RISC-V then canary salt and possibly TRNG in general are irrelevant)
  * note TRNG is needed because we generate per boot value, and there is a lot of code prior to watchdog; we should certainly identify where time is spent, and possibly skip some stuff if we can
  * go look at unicorn
  
## SECURITY

- fuzzing (Unicorn?)
- Make sure RCP instructions get inlined, even after LTO
- Make sure all s_ functions have canary
- ~~Make sure we are using random delay RCP instructions where appropriate~~ no-delay is opt in
- Unicorn flow (with map file) make sure there are no functions in secure boot path that aren't "crit" 
- ~~Now we have XIP enabled, we should disable executing from flash until the last minute (just needs to be NS i 
  guess)~~
- we should have rcp steps after every reset of accessctrl in the boot path
- ~~OTP flag for not allowing watchdog secure boot from external oscillator~~ not necesary because only way to get 
  here is from user secure code.
- dont forget about NS IRQ potentially modifying state that S is working on.
- maybe put some NS bombs in some exempt boot code that should not be run from NS (though bootram is a good one)

## SPACE SAVING

- i just tried using bootrom as an extern pointer (not known) and saved 128 bytes, so struct-ulating is good (as long ass GCC can't try to 'optimize it')
### RISC-V
- ~~60: we can call varmulet_hook_default_save_regs_fn (bit of a tight coupling though, but can prefix the function
  such that it saves all)~~
- 128: use 16 bit pointers for varmulet_main_decode_table
- use 16 bit pointers for anything called from arm6 (as it has the pointers as constants ... )
- ~~lots: move boot path into varmulet~~
  - ~~note we can use an unused ARM 16-bit hint instruction to cause different behavior~~
  - ~~it seems GCC is happy for us to change .cpu in inline asm (todo check if it resets it after)~~
- we need to add the "reset varm_wrapper" or "i've restarted my binary" field
- de genericize varmulet
- make main_decode_align a noop (32 bytes at cost of small amount of speed)
### ARM
- pointer struct for re-use of common constants
- degenericize usb device code more

## TESTS

### small

- check OTP lock forwarding on RISC-V (think this is OK, as we just forward from secure->picoboot, which is what we
  want)
- blocks
  - multiple block starts
  - multiple block ends (some invalid)
  - block spanning reads
- always test exes without any IMAGE_DEF/blocks
- make sure signature hash_def can't have hash_def omitted from hash
- sparse binaries!
- test picoboot read of all address space (including ROM)
- all white label functions
  - ASCII/UNICODE
  - unreadable permissions
  - overly long strings
- rolling window
  - binary in partition
  - rolled binary at start of flash
  - binary in slot 1
  - rolled binary in slot 1
  - rolled binary in partition
  
### larger/examples

- download alternate code EXE over wifi and reboot with hash check
- 
## OTP

- picoboot OTP write
- ~~we need to do correct write checking for ECC, 1 bit corrections and wotnot~~
- we should support "alloc" best practice, where zero page is not allocated? maybe put your "TAG" at the beginning
  - get page API
  - reserved page bitmap

## Debug

- flash functions will have canaries... we can add a function to init canaries if not init-ted

## Review

## Doc

- did a little test on 1/1/23, as i thought it was worth re-checking 
  - RISC-V build of usb_boot was 9.7K
  - RISC-V build of bootrom without varmulet or native USB funcs was 5.3K smaller
  - i.e. varmulet saves 4+K and will continue to save more as features are added.
  
## Partition Info (root sector)

## SDK

- macros for m33_hw->nvic_itns[0]

### BACK PORT

- failing picoboot command (streaming) does not HALT ack channel causing timeout. seems like picotool (pre-existing bug was not resetting when connecting)

## OTP LIST

* **Need to check everything is used**

# Documentation

- 2K (exact may now be 1.5K?) use of USBRAM by boot path. actually 2.5 now.

# out of scope

- compressed binary? (particularly for OTP boot) - although idk how much compression we might expect there - i guess we can test
  - ~~we may want to replace poor_mans_text_decompress... with commander keen~~ um commander is RLE which won't help much i think
