# A1 Bootrom TODOs

## Review

## Questions
*   * we have OTP (default for no PT) and PT permissions for unpartitioned space.
  * ~~you must mark each partition as "absolute family accepting" that you want to be able to directly address~~

* ~~Regarding 0017.. we did say RAM->OTP->FLASH fallback if there is no valid binary, currently we do RAM->NS 
  OTP->FLASH->NS~~
* ~~Regarding 0029.. we use 4K for A/B image we can save a loop if we just scan all 4K in each slot in one go, 
  proably should~~

## Doc

* Signature covers every item in block except for itself and ..?
* There is no NSC SAU region required at boot, and we put an NS region over all of ROM (region 7) - possibly minus a bit for watermark error
* We do not do any SAU setup for a core 0 secure binary, other than leaving region 7 in place for callbacks.
* All ECC boot params in OTP must have a non-ECC'd valid bit which can be checked first
* Boot signing tool should check that the entry point is covered by the signature
* Getting a free OTP page can be done by looking for an all-zeroes page -- when you allocate, you should put an eyecatcher so you can find your page again
* OTP binary cannot return (duh - i was thinking of vector)
* we steal top 0xc00 of USB RAM during boot on ARM, and 0xc4c on RISC-V 
* Document which lock we use for the SHA-256 and make sure we hold it for the duration of a checksum. these are boot locks with numbers the same as BOOTROM_ACCESS_LOCK_.. thease are only used by the bootrom default access_lock function, which returns BOOTROM_ERROR_AGAIN on concurrent use

## Decisions/Note-to-self

* We should just steal 3k of USB RAM: save pain and leave space for A2. Note USB RAM can't be executed and can't retained so it is the best thing to steal
* We should disallow images that straddle the chip select boundary (or clip them to the 16 MiB window your image starts in), with the sole possible exceptions of images that do not belong to a partition table (start at storage address 0) and have no extra roll
* BOOTDIS should not particularly interact with the TBYB try-boot, because this does not vector the boot path, it just twiddles the 0/1 or A/B slot selection
* ~~We need 4k of RAM space whenever we need to rewrite a flash sector (or flash space if we want to be slow)~~
  * ~~For the downgrade case we can actually just get away with erasing the opposite image~~
  * ~~For all other cases (partition TBYB, normal image TBYB) we do need to rewrite a sector to remove the TBYB flag~~
* XIP cache should not overlap flash ranges - i.e. should be top half 0x1200_0000 so as to not overlap flash 
* UF2 block target addresses starting with 0x1xxx_xxxx are relative to the start of the partition. When a flash image is linked at some address other than 0x1000_0000 (say 0x1040_0000), elf2uf2 (and friends) should find the lowest address and subtract it out. This means the bootrom knows where to put each UF2 block without having any additional metadata in the UF2 blocks e.g. "lowest programming address".
* `.uninitialized_data` does not work for binaries that we secure-boot into (you'll probably get zeroes)
* We do not use multiple flash parameters in NSBOOT mode, we just use 0/6 because searching will slow us down when flash is blank, and also the existing code goes down to 3/24 whcih is silly in NSBOOT with known clock
* We do not use multiple flash params in boot_to_ram binary load PT, because we expect them to have set XIP up.

### core 1 launch

* we will pass SAU on core 1 stack
* we can use bootram.core1 for secure stack if we haven't been given one (e.g. NS launch of S)
* we can have a saved secure function pointer to call on core 1 launch - will be called with a bool
  say whether it was a secure launch (it can do SPSEL and sealing of PSP stack if needed)
* we have 3 layers
  1. raw launch with SP
  2. mirrored launch with SAU (and SPLIM) which will cause secure func
  3. NS wrapper which will call 2, and then call a S-registered bootram function pointer, and then BLXNS into NS

### Flash API

There are three parts:

* Existing RP2040 API, which is secure only
* New "checked API", secure API, takes S/NS/NSBOOT as "caller security level" (Q: absolute? Partition-relative)
* NonSecure version of the checked API, appears the same in the SDK, just goes through gateways which force the security level to nonsecure
* NSBOOT uses the same nonsecure gateway, but based on the "disable nsboot" flag not having been set, we force the security level to nsboot instead of nonsecure
  
## Discussion

* Can we say that the XIP image we boot will always be mapped at an XIP runtime address of 0x1000_0000?
  * no we think (not least for prepending a block), but we want to make sure there aren't issues - actually there are issues; we can only support 4M increments

## Size

* (0007) Size: should we use saved boot flag hx uint32_t?
* (0011) Size: Don't overharden!
* (0020) Size: Make sure we assert everything that should be asserted
* (0128) space saving todos (some are marked with this, some are listed here)
  * ~~s_native_crit_flash_put_get(cs, NULL, NULL, 0) is used a lot - possibly inline (it doesn't need to be native) or
    at least make a variant that doesn't take all the args (perhaps that won't save space)~~ done
* (0464) Size: graham: perform some common table driven buffer validation in SG apparatus
* ~~(0186) Size: Make reboot magic sequential to save constant space - done ~~
* ~~(0210) Size: Remove exposed _44 etc memcpy/memset variants (save table space))~~ 
  * note we may want to split into crit_erase_words, crit_copy_words, and then just a simply loop version of the others
* (0198) Size: maybe remove sticking invalid values in window_base
* (0220) size: try to shrink otp_access function - it is a bit chunky
* ~~(0223) what? size/general: remove chip random from~~ not zure what this meant
* (0242) size: finalize otp_inline (we think function calls are fine with canary) - might need to be regular one even though leaf.
* (0250) size: dont keep two different varm hooks tables for boot and nsboot (the latter could be a modified former in RAM)
* (0272) size: removing enter_cmd_xip function altogether (backwards compatibility issue tho)
* (0288) size: do we need to not clear pt populated in slot search when just searching images?
* (0320) size: clearing PT/IMAGE_DEF already found in a block list which later turns out to be invalid may be unecessary, if we actually check the return code.
* (0332) size/security: do we need hx_bools for enter ns_boot or ram_image - can we just use boot_type now?
  actually do neeed for ram_image not ns_boot
* ~~(0342) size: sb_ stuff (section?) has 16 byte alignment~~
* (0346) size: s_arm6_crit_mem_copy_words produces horrible code with repeated stack loads
* (0352) size: probably make load map sizes have to be multiples of 4 - entries must already be word aligned - we
  should enforce
* (0364) size: remove branch from otp reading here by bit manip
* (0276) size: remove 2BS partition_table support? probably only minimal saving if at all
* (0294) size: maybe remove init of TBYB erase address if it is guarded by something else
* (0300) size: graham: now that block buffers are combined with what used to be parsed_slot_pair_t, we are copying the
  parsed_blocks and the buffers from slot1 to slot0 when choosing slots which is wasteful if we're not updating the block_data pointers
* (0386) size: use linker script hw objects to thwart GCC "optimization"
* (0390) size: can't seem to force use of mov.w for a500a500 or 00c300c3, but we could make fake rcp
  instructions and post process the ELF... both MOV and CMP with immediate would be useful, avoid having the constants around in the bootrom
* (0391) size: opportunities to use bit set/clr on BOOTRAM
* (1002) size: can we use just one MPU region to cover RAM and XIP? (Probably can't share ROM XN because that would cover SGs)
* (0468) size: remove antyhing which is NOT autovarm (so mainly NS helper APIs and put them behind a user supplied multiplex - perhaps extension of func lookup with code)
* ~~(0482) size: CORE0_USB_WORKSPACE_SIZE is currently 0xc28 can we make it 0xc00?~~
* ~~(0494) check recent MSR MSP -> MOV SP change to see if it opens us up to ordering issues (MOV SP checks MSPLIM, MSR doesnt)~~ we have moved MSPLIM setting before
* (0509) size: "RP2350" in UART duplicates string elsewhere
* (0512) size: check whether putting __builtin_unreachable() rather than noreturn makes code smaller
* (0520) size: gpio_put and gpio_set_dir can probably be samller with bit manip to find correct reg rather than branches
* (0522) size: make s_varm_reboot aliases with fewer args - nah, but just remove warnings
* (0525) size: vs hardening; pass garbage for TX/RX buffers for flash_put_get_nodata
* (1023) size: clean up pointer literals for bootram references in `s_varm_crit_ram_trash_perform_flash_scan_and_maybe_run_image`
* (0526) reorder bootram to allow efficient zeroing on boot? - also perhaps keeping smaller fields nearer the beginning helps
* ~~(0528) size: maybe don't pass otp_access struct to S from nsboot (we sholdnt be exposing PICOBOOT anyway),and see 
  why otp_access is so big~~ gone
* (0529) size: is bootram->always put in reg, and do we reference from it (we may want to move the byte/hword values up front)  
* (1020) size: SB_FE_ONE and SB_FE_ZERO can be found in some IO registers, e.g. starting from `PIO0_RSTSEQ_DONE` or `SHA256_RSTSEQ_DONE` (0x400f8034), to save 36 bytes
* (0538) size: do we need to save the IRQ state around nsboot_otp_access?
* (0540) in shrinking varmulet we can move a lot of the default hooks to the end of the table, and make their use hard coded, as they are only read i think by things like enter/exit (possibly anyway)... actually yes, some of these have been removed and are set directly by the enter hook
   ```
    public_hook varmulet_hook_default_save_regs_fn
    public_hook varmulet_hook_default_restore_regs_fn
    public_hook varmulet_hook_default_execute_instruction
    public_hook varmulet_main_decode_table
    public_hook varmulet_dp_decode_table
    .word       varmulet_halt                    // undefined16
    ```
* (0542) size: remove call to init cpu (since memset clears it)  
* size: DISCUSS: remove magic/ROM version from RISC-V (unless used by commonn code)
* (0550) size: DISCUSS: after rcp_valid, don't check actual hx_bool value
* size: would be nice to remove xxxxxxxx but would need to be done deep in the defaulting of strings
## cut?

* SYSCALL
  * core1 launch
  * (0152) bootram locations allocated for S->NS state sharing information:
    * hardware claim
    * NS binary RAM bounds (e.g. heap growth limited to dynamic size of S binary)
    * Initialisation state? Possibly not, sharing of hardware concunrrently with S/NS seems an unlikely use case
  * stdout/stdin
* EXEC2

## Hardening

Thoughts:

- we want to make sure we are doing all the pre-requisite steps etc... we don't necessarily care if people screw up the flash search etc, as long as the result image can't be booted

* ~~(0025) Make sure we stay dead in sudden death, also possibly replace cant_boot branches with die-in-place (and check other places where we call `_dead` and stuff)~~ JIRA
* ~~(0051) hardening of required sig_words - affects ability to modify signed image loadmap etc. although i guess it is hard to use this to subvert an existing hash.~~ JIRA
* ~~(0074) Add function canaries~~ JIRA
* (0091) Make critical hx_bools have unique XOR masks, and make use of the XOR'd bool RCP instructions
  * done for signature_verified
* ~~(0165) Pass canaries out through bootram to make sure that a path deep in the call stack was actually traversed.~~ not ure what this meant
* (0244) Review hx_ functions
* ~~(0239) add more panics to _dead~~ JIRA
* ~~(0240) verify ARM nsboot_vm func calls are all correctly permission wrapped~~
* (0274) move stuff around in bootram and enforce SPLIM on both processors, so stacks are generally at the end of bootram so they are bounded at both ends - worried about storing add positive offset to sp overwriting hx_bools etc.
* (0354) hardening of in place/in RAM SHA256 check.. you would execute all zeros if you failed to actually load to
  RAM, but still...
* ~~(0368) harden: s_from_ns_nsboot_service_call~~ JIRA
* ~~(0374) harden partition table parsing (links must be in range etc)~~ JIRA
* (0422) DISCUSS: hx_and_not etc look skippable
* ~~(0424) make SB_ASSERT rcp_panic~~ JIRA
* ~~(0442) DISCUSS: harden "buy" API~~ JIRA
* (0454) parsing of partition table should be able to return "invalid"
* ~~(0460) harden bootrom_state_reset parameter?~~ JIRA
* ~~(0474) make sure we can't reboot to PC/SP from NS~~ JIRA
* ~~(0496) worry about image_def loaded via verify overwrite by future (have't seen this happen yet) if nothing else assert on it.~~ JIRA
* ~~(0516) PICOBOOT reboot check to disallow PC_SP needs help maybe~~ JIRA
* (0534) DISCUSS: we currently clear BOOTRAM up to the bottom of the stack on entry; should we clear more? we should skip the things we have in always if we do (and maybe init to zero instead the value of r0 so we can skip some zeroing in boot_path.c)
* ~~(0536) Harden sweet-b returns~~ JIRA
* 
## Release

* ~~(0118) make sure we add BOOTROM_ASSERT_DISABLED for real build~~ AMYSW-89
* ~~(0124) Remove HACK_ defines (including the one about security holes!)~~ AMYSW-88
* ~~(0126) Add SILICON_BUILD define (to make sure all test code is dead)~~ AMYSW-56
* (0150) build-time python script which checks that bx lr or pop {pc} is preceded by a canary or some other kind of rcp instruction
  * ~~Make sure there are no functions called inline_xxx~~
* ~~(0155) Move hardware NS watermark based on final A1 bootrom layout~~ can't, so modify SAU region
*~~(0159) Reinstate the linker script assertion for ns text size being nonzero (and remove the pulling in of `inline_s_` into secure text)~~
* (0246) Check linker assertions (fix issues with inline functions etc) may want separate linker script for SILICON_BUILD
* ~~(0414) programatic check of rom table codes for duplicates (just got hit)~~ JIRA
* (0426) re-arrange SDK bootrom_constants to be bootrom_api or whatever and include bootrom_constants from that
* (1009) Grep code for every instance of `varm_to_s_native_validate_ns_buffer` and make sure bounds are correct, e.g. no copy/paste errors

## Post-release

* (0158) de-document psm_hw->frce_on as it doesn't do anything
* (1008) Validate OTP boot parameters in picotool: e.g. load destination should be in SRAM and should *not* have a Thumb bit set.
* (1010) When signing Secure binaries, add LOAD_MAP entries to zero uninitialised RAM
* (1011) For negative-rolled binaries, check that the binary is no larger than the available space (e.g. 4 MiB if the binary is rolled by `0xc00000`)

## Functionality

### graham

* Exposed error/status
  * ~~(0476) boot type for chain~~
  * ~~Add to PICOBOOT GET_SYS_INFO~~
  * ~~(0444) what to do if OTP version thermo is not writable (but readable) put it the boot failure 
    somewhere~~ DISUCSS it does now fail the boot, but we don't have a specific failure reason
* ~~(0478) ~~moving of bootram->always below stack (no help if bootram is mirrored)~~ maybe make core 1 area
  inaccessible under MPU~~ JIRA
* (0498) cleanup various launch_image variants. DISCUSS we don't check RAM window range except in EXEC2/RAM boot (so chain_image)
* (0535) DISCUSS: can we make FPGA more like h/w here
* ~~(0544) DISCUSS: callback should fail if thumb bit is wrong; also check r3 for secure_call (actually secure_call is probably ARM only?)~~ JIRA
* ~~(0545) check the over-read when loading garbage PT~~ JIRA
* ~~(0546) LAUNCH_CONDITION_FAILURE set if there is no IMAGE~~ 
* ~~(0547) DISCUSS: we may leave RAM contents from previous image when booting another (signed)~~ JIRA
* ~~(0549) need to doc spin lock stuff~~ (its in the databook - which may merge with doxygen)

  ~~* (0081) A secure getter API for whether the current boot is a "try", so the candidate image knows to perform the "buy" callback (possibly this is part of the bootram "reason register" status word) - cleanup the existing return code nonsense from explicit_buy~~ now handled get_sys_info
* ~~(0024) Some kind of feedback for dragging an invalid UF2 e.g. wrong family ID~~ nothing visual (it is hard because we support other data in the middle)... we now have `picotool uf2info`
* ~~(0082) Fixup rolling window for second XIP window and also check for overflows at the end (binary must not cross
  16 M in storage or runtime address) - note also a binary in the second flash window must be rolled there~~
  * do we support booting from second flash at all - ANSWER: no
* ~~(0017) What is the priority of OTP boot vs boot-to-RAM~~
  * ~~we think RAM goes first; OTP boot does not return; so RAM->OTP->FLASH in fact none can return (IMAGE_DEF boot
    does not return)~~
  * ~~we should still see if we can chain into a flash boot from some OTP code (i.e. make sure relevant functions are
    exposed)~~ API is exposed but untested
* ~~(0027) Clear USB RAM we might use on the flash boot path (easier now we have fixed 3K)~~
* ~~Locking: yes we use lock 7 to indicate required, and returns INVALID_STATE on lock N not-owned when set
  (returning error) - avoids arch affinity, and deadlocks.~~
* ~~(0031) Add an OTP chicken bit for disabling as much code as possible whilst being able to do a secure boot
  (removing partition tables & rollwing window)~~
* ~~(0036) Implement flash slot size OTP config~~
* ~~(lets limit to half of flash size so we don't have to worry about
  crossing) - actually the window sort of already does this? Answer: yes~~
* ~~(0048) Check we handle address wrapping at 16 MiB chip-select window correctly in *all* places, or disallow windows wrapping around (going past) the end of a chip-select window~~ it is disallowed
* ~~(0057) The EXEC-image call (e.g. picoboot EXEC callback) needs to make the verified range of RAM Secure so it can execute it (note it must secure the workarea and the image actually) - half done~~
* ~~(0064) Should we erase SRAM on a secure boot (including XIP RAM)?~~ it is up to load map (or binary) to clear
* ~~(0076) Need to check ARM boot binary is secure (the flag in the IMAGE_DEF should be marked secure for us to
  consider it)~~ Actually we check for NOT secure, and btw we don't prefer S over NS in the same block list as mixing them makes no sense (for code size)
* ~~(0085) allow OTP disable of PICOBOOT EXEC~~
* ~~(0089) Add partition names to ~~spec~~ and code~~
* ~~(0095) Choose correct target partition for UF2 download~~
  * ~~QUESTION: Does the UF2 partition chooser need to check signatures of the flash images, or should it just trust their versions?~~ it does no verification
  * ~~QUESTION: Should we avoid loading when checking signatures in the UF2 partition chooser?~~ YES
* ~~(0101) done? Check IMAGE_DEF is executable before we execute it (since we now have non-executable images)~~
* ~~(0182) we don't do any TBYB poisoning except in boot mode.~~
* ~~(0184) need flags in partition to indicate whether we reboot (and what TBYB window?) when we drop~~
* ~~(0106) Remember which partition we booted from, or the flash offset of the window we booted from, in bootram~~
* ~~(0107) More picoboot info:~~
  * ~~Which CPU arches are supported~~
  * ~~Number of pins in the package~~
  * ~~Once-per-boot random "nonce"~~
  * ~~flash dev_info (add to sys_info)~~
* ~~(0113) Check USB white label vs chip ID (structured ID from OTP) vs random ID (unstructured ID from OTP) -- make sure we are using the right IDs in the right places for serial numbers etc.  (also include USB drive serial number -- don't want random, and don't want time-since-boot)~~ Note, 32 bit id is hash of device/wafer.. default USB serial number is WAFER:DEVICE
* ~~(0122) otp flag for slot 0 only~~ not useful
* ~~(0137) done? Add a reboot reason to bootram->always so that code can query it. (particularly to detect reset from nsboot)~~
  * ~~add to get_sys_info so we don't need an accessor~~
* ~~(0163) Add a secure API to test and run an IMAGE_DEF, e.g. for a decryption stage calling back to verify and launch the blob that it decrypted. Make sure that a previous verification success is not cached!~~ chain_image
* ~~(0164) Add a recovery watchdog timer to try before you buy, on a non-automatic try phase~~
* ~~(0176) We need to make RAM/XIP writable during verify_image~~
* ~~(0180) the exposed bootrom API for loading partition table should deliberately NOT check flash types (the user should have set it up).~~
* ~~(0196) Implement inline_s_partition_is_marked_bootable~~
* ~~(0218) make sure we're happy with OTP locking for write only. (actually we do it for both as reads
  don't work)~~
* ~~(0219) otp_access we don't copy a NS buffer when writing... though the worst that happens is NS code
  doing a NS write pollutes its own data~~
* ~~(0254) need to generate new MS descriptor GUID?~~
* ~~(0258) fix nsboot gpio setting (don't use copro instructions for pin >= 32)~~
* ~~(0262) why was there gpio setup after xip~~ no idea; history doesn't relate, and it seems fine without it
* ~~(0310) do we need hash required for pt?~~ duplicate of (0402)
* ~~(0324) graham: Argh... we should be careful about reboot to PC/SP from picoboot, also reboot to RAM image. We
  should not allow PC/SP from PICOBOOT because why would you (we should reject it at least).. so yes, change the command~~
* ~~(0330) public reboot APIs - NS ... i think this means just clean this up (along with the PICOBOOT one)~~
* ~~(0338) what is the boot_type of a fallen thru PC_SP? either leave as PC_SP or set back to NORMAL.. set it
    back to normal, AND set it to PC_SP when entering~~
* ~~(0344) default UF2 families when no PT (e.g. we want to support RISC-V, ARM etc)... allow everything~~ dupe of (0428)
* ~~(0370) cleanup reboot API/picoboot do we need backward compatibility; gpio stuff should go in SP - goto (0330)~~
* ~~(0398) is it ok to copy 1-3 extra bytes for non word sized load map entry? OK~~
* ~~(0402) get rid of pt_hash_required altogether (reason it isn't gated by secure like pt_sig_required, we
  don't have ) one for images, and if you really cared you'd require signature (note it is broken anyway)). ANSWER:
  look at this again - i think i'd forgotten about the OTP flag~~ implemented
* ~~(0404) should skip PT with wrong sig key~~
* ~~(0412) parse partition names~~ dupe of (0089)
* ~~(0416) OTP access APIs which should we export?~~
* ~~(0418) add multiple boot keys? valid and invalid flag for each; DECISION: yes, lets move all into page 2~~
  * ~~actually add other boot keys~~
  * ~~respect boot key valid/invalid~~
  * ~~add picotool info read via OTP~~
* ~~(0420) opt - commented back in check of IMAGE_DEF in PT load;~~ this is fine as hash_req=false, sig_req=false is a noop unless booting (where we will hash if there is one)
* ~~(0428) what family IDs should we accept for RAM and no PT:~~ answer, (RISC-V, ARM-S, DATA<,ABSOLUTE)
* ~~(0432) picotool ability to reload PT? ANSWER: sure~~
* ~~(0434) double check exec2 allowed when entering image~~
* ~~(0438) expose s_varm_crit_ram_trash_checked_ram_or_flash_window_launch API as bootrom API~~ is chain_image
* ~~(0439) should OTP boot be varmable?~~ NO
* ~~(0440) did we really mean rollback version is completely ignored for non-secure (i.e. it is just zero)
  we actually do assume this in launch_image? should we move it to IMAGE_DEF and/or out of version~~ - ANSWER: please
  respect it (but it must have sufficient OTP rows) - it isn't supoprted for PT any more
* ~~(0446) set rollback version required bit (now exists in otp_data)~~
* ~~(0448) add error code when marking image as invalid to put into boot info~~ no, we just have no valid image* ~~(0458) Ugh; backwards roll has issues that you cannot mask off stuff before it... we should limit to rolling to 4M aligned addresses when rolling backwards (pain for say a boot-loader that wants to run at 0x10400000 to move itself on entry, as the entry point is all wrong too)~~
* ~~(0466) make sure you can't call SG/auto-varm particularly except past boot (auto-varm functions should fail)~~
* ~~(0467) RISC-V API to set core local varmulet (ARM) stack.~~
* ~~(0472) chain_image will not set the boot partition (though it could - perhaps it should take a boot partition instead of a window for flash)~~ does now
* ~~(0482) CORE0_BOOT_USBRAM_WORKSPACE_SIZE is currently 0xc28 can we make it 0xc00?~~ fixed
* ~~(0484) RISC-V s_native_secure_call seems to break unless there is a nop after the jalr.~~
* ~~(0486) how do we notice if rolling window cuts off the end (as rolling window always cuts off the end) I dont think it can unless you are negative rolling (at which point what is cut off would be >16M)~~ it is up to signing tool to check - a boot image may not cross 16M boundary either in storage_address or runtime_address
* ~~(0500) test stack overflow in load pt~~
* ~~(0502) Aato varm should set stack limit~~
* ~~(0504) conduit API~~
* ~~(0516) check that cpu switch is supported in watchdog_reboot~~ decided against this - you should check first via SYS_INFO
* ~~(0530) overscan - we should read in chunks ofr 0x200 not 0x280 so it divides 0x1000 (test that it loops correctly
  to fill the buffer)~~
* ~~(0532) expose validate_ns_buffer as API~~

### luke

* ~~(0140) NonSecure watchdog/powman reboot API, with callback to let Secure know we have reset and are about to 
  enter the NonSecure code (maybe cut)~~ this can be replaced by new custom API
* ~~(0160) Use non-delay version of RCP for functions that are exported to non-bootrom (possibly for leaf canaries too)~~  JIRA
* ~~(0162) Should we have a BOOT_FLAGS flag that must always be set, and program it during ATE? (Would have to be 
  checked after watchdog boot, as we use watchdog boot to program the chip during ATE)~~
* ~~(0178) xip setup API cannot use the bootram xip setup code in NSBOOT because that is stack, so we need to check for NSBOOT using the fancy not a flag~~ JIRA

### william 
* (0090) Expand Unicorn RISC-V support to Hazard3 dialect, so we can run regressions on it (RV32IMAZifenceiZicsrZbaZbbZbsZbkbZcaZcbZcmp)
* (0093) Find tide mark for stack occupation, both Arm and RISC-V, to make sure we have headroom
* ~~(0047) Make sure crit_next_block doesn't loop forever when the max read size is greater than the window size, or when your block spans the end of the window.~~
* (0492) prove what must be some broken code around which image was verified last - try putting RAM binaries which overlap and make sure the right code runs (probably without "singleton", and with/without secure/signed_pt)
 
### dominic?

* (0132) Harden sb_verify signature and friends, return e.g. unique hx_bool

### unassigned

* (0111) Add a UF2 meta for "largest erase span" (put it in every block) so that we can do some bulk erase up front, which can use larger commands if available. (Actually this could be a "this UF2 block is part of a 64k contiguous lump of blocks" flag, so we can do a 64k erase when we see such a block)
* ~~(0149) NonSecure API to get a random number? probably not given the characterization woes~~ in the "conduit" maybe
* (0284) ~~starting and ending in different partitions can be valid (for absolute writes)~~
  * worry about 64K erase
* (0286) ~~make sure we account for RISC-V varm state now stored in USB RAM~~ this bit me hard
  * actually still want to add SPLIM

### Code Verification / Test

* (0001) Will "core 1 as debug probe" ever break due to core 0 booth path, including clocks, ACCESSCTRL etc..
  * write a regression test for this
* ~~(0010) `graham` Avoid infinite loop when attempting to arch-switch to an architecture that is disabled~~
  * ~~DISCUSS/TEST: think this is good as long as SECURE sets boot flags to RISC-V disabled~~
* (0028) Make sure we don't trash main SRAM when we don't have to (particularly thinking of the core-1-as-debugger
  case)
  * we mentioned test case (0001)
* (0050) Launch a nonsecure image and see what code paths we need, to see what bootrom code paths might want to be exposed
* ~~(0054) Make sure IMAGE_DEF scan checks image version before checking sig, to avoid multiple signature checks (perf reasons)~~
* (0079) Lets do a quick (at least on paper) POC of an OTP boot which finds image_def, (decrypts
  image/copies/decompresses) into RAM, and runs it (hopefully with bootrom help)
* (0087) WHY: Why is float stacking not happening in e.g. DOOM?
  * Also check ASPEN flag for nsboot, to make sure we don't start stacking floating point
* (0098) Check msplim is set after returning from vectors
* (0099) Check varmulet exports if we haven't crippled the size
* (0100) Check preboot struct is only used in boot path
* (0102) Make sure RAM boot and nsboot do not load things into RAM whilst searching partitions
* (0108) Make sure we handle load map addresses for a rolled, signed binary ANSWER: we are happy to doc
  that runtime address in flash means don't load.
* (0109) When we start looking down a new block list (because the previous list, possibly on a different XIP mode attempt, was malformed) make sure we reset all of the necessary search state
* (0116) make sure boot_scan_context is zeroed
* (0135) test that resetting into nsboot when XOSC is off works
* (0138) Make sure we ignore family IDs that are not in our partition table ID list, and accept ones that are
  ** Sub-todo: if we get a UF2 download with a mix of ignored and non-ignored UF2 families ("fat UF2" targetting multiple boards each with a custom family) then does the non-ignored download proceed correctly without getting jammed up by the ignored one?
* (0143) Make sure RISC-V boot speed is comparable to Arm
* (0146) Hook up OTP LED config to nsboot LED parameter
* (0147) Make sure UF2 code can use all 32 MiB of flash - cant
* (0161) Unicorn flow: make sure all functions called on bootpath contain `_crit_`
* (0167) Make sure that calling s_arm6_crit_load_resident_partition_table does not look at images when it is called off of the flash boot path (e.g. when loading the table before entering nsboot)
* (0200) commented out code in launch_image needs looking at
* (0202) do we need image_counter in final product - hopefully testing should tell us.
* ~~(0214) UART boot GPIO config~~ axed, you can do this easily with OTP boot
* (0216) USB boot GPIO config (activity)
* (0260) check NSBOOT stack size - seems large - we may want to steal some for (i forget)
* (0266) review UF2 download complete RAM boot launch window
* (0268) sparse binaries remaining todos (I thought this was fixed)
* (0292) code read
* (0312) graham: currently we skip sig check of slot 0 when deciding whether to skip slot 1, but we don't skip hash
  check; should we (slightly painful)
* (0298) what if both slots have TBYB flag but no window (right now we boot first, but we could boot neither)
* (0336) I think i saw loading a RAM binary after NSBOOT fail with unable to write UART - i thought we cleared accessctrl (though this was core 1 - we may need to do reset anyway)
* (0348) ~~should load map use storage_rel address; actually it must because we dont know the roll yet
  necessarily, however it makes a load address of 0 (zero) encoding be different, but that is just a tool issue-
  make it 0 instead? the problem where the zero is tested in code~~ test zero fill
* (0360) TEST: we can't currently ignore blocks that are too big. ANSWER: these will fail the whole block loop, sorry.
* (0378) graham: can we skip signatures when loading PT other than during boot (saves a stack space issue))
* (0380) graham: major perf: rationalize when we do LOAD_MAP load and/hash - we want to avoid as much as possible in
  loading resident partition table where we currently verify the image in slot 0
* ~~(0384) correctly handle absolute family id in get_uf2_target_partition (what pi should we return?)~~
* (0464) verify exposed bootrom APIs are what we want
* (1005) Make sure every function exported to RISC-V via src/riscv/CMakeLists.txt is marked `__exported_from_arm` to avoid constpropping
* ~~(0406) hmm.. we need to check image is verified before trying to boot it? actually i think it is fine as is; if you have PT and an IMAGE_DEF but the IMAGE_DEF fails validation, you don't want to go back to the PT as if the image wasn't there at all, thouhg perhaps that means we're broke in the usual case (i.e. we shouldn't ignore completel all wrongly signed IMAGE_DEFs we should just not accept them - aka overwrite existing chosen image_def only IFF the image_def is signed by the right key) - we still won't boot with an unsigned IMAGE_DEF ... basically we need to firm up "not present" vs "unverified"~~
* ~~(0488) add partitions - kinda tricky as it will break scan (can just add second pt count though in same word) - just expose via PT add a DATA pointer~~ we make the start of the table format semi-public
* (0514) make sure reboot to RAM image checks range post boot
* ~~(0510) RISC-V bootrom stack API~~ the biggest offenders are already passed a buffer, we can also maek the SDK
  wrap them - lets see which APIs this affects... 
* (0529) worry about concurrent OTP access from NSBOOT and white label stuff (disable IRQ on nsboot code path, but worth checking)

### Documentation / Code Quality

* (0012) Document the boot scan context struct

### Done

* ~~(0002) Remove chicken bit for TRNG, use characterisation, consider turning off all the checks~~ code has been replaced with SHA256 and sampling
* ~~(0003) combine setting the is-CPU-Arm flag branch with the branch inside the RCP setup code~~
* ~~(0004) does clock enable need to be done before the first TRNG access?~~ yes
* ~~(0005) Can we set the once-per-boot random data before entering the watchdog path? Perf but also whether it is surprising for it to change on a watchdog~~
  * ~~we should set it after~~
* ~~(0006) Check the logic which asserts that the CRIT OTP readback matches the value read by hardware~~
* ~~(0008) Replace RISC-V watchdog-as-SPLIM hack with some PMP setup in RISC-V bootrom rt0?~~ No, we have msplim in varmulet now
* ~~(0009) Check we are resetting the correct pad registers -- possible typo (also make sure we apply/remove isolation correctly for both banks)~~
* ~~(0013) `graham` Flash origin and window base are a bit confused~~ window is either whole flash, or a partition. now `flash_start_offset` indicates where in flash the block list was searched from (i.e. the sector it started in)
* ~~(0015) Check that image boot address range is in RAM or upper half of XIP,~~ ~~and rename it to reboot-to-RAM~~
* ~~(0016) Respect BOOTDIS for reboot-to-RAM (image boot) and also add an OTP disable for it~~ already covered by the existing scratch disable OTP flags
* ~~(0018) Make double-tap-boot path ignore non-RUN resets~~
* ~~(0022) Make sure when we have both an enable and a disable in OTP, we check both~~ The only case we have both is OTP boot, and this does check DISABLE before ENABLE
* ~~(0029) Read max flash search size from OTP~~ we limit to 4K always (for flash)
* ~~(0030) Fix the flash mode-search FSM starting in the wrong state~~
* ~~(0032) Rename block_buffer_or_signature_workspace to tell you that it has a slot_pair inside it~~ it doesn't any 
  more
* ~~(0033) Make sure load map can't write to anything but RAM/XIP cache... (no PSRAM to PSRAM)~~
* ~~(0034) xxx_check_slots_01: asserts booting is true, but it is not true always as it gets called in e.g. 
  load_resident_partition_table (which performs a dry run too)~~
* ~~(0035) Need a EXE flag for "preserve XIP tag state" for people with stuff stashed in there~~ We always flush, but we pin if any LOAD_MAP entries have runtime addresses in XIP RAM
* ~~(0037) For partition try-before-you-buy, does the bootrom buy automatically (i.e. go and program some flash) or do we wait for a callback from the user image?~~
  * we say yes.
  * ~~**FLAG** where is the RAM workspace for programming~~
    * ~~(0038) For image downgrades, we should support a try before you buy variant which is 1. automatic, 2. automatically performs the buy once the image is found to be bootable, 3. poisons the opposite image to avoid the build number precedence stopping the downgrade image from running~~
  * Note see [tbyb spreadhseet](tbyb.xls]) for full/latest spec
* ~~(0039) Need to propagate watchdog boot type (e.g. boot-to-RAM) across arch-switch reboots~~
  * ~~we have the following scratch contents~~
    ```
                   ALLOWED W/     SUPPORT
                    BOOTDIS     ARCH SWITCH (via reboot)
    normal -           Y             Y
    pc/sp -            N             N
    nsboot -           Y             N
    ram boot           N             Y  (this is ok w.r.t. BOOTDIS, since to have got here BOOTDIS=N)
    ```
* ~~(0040) XIP mode for non-flash boots e.g. boot-to-RAM: probably just a slow mode 0~~ yes, we now use enter_flash_thunk for both paths, and the default mode is set up in bootrom in arm6_boot_path
* ~~(0041) Move temporary parsed_image_def off the stack in s_arm6_crit_search_window~~ didn't save anything - wasn't the deepest branch
* ~~(0042) Rename s_arm6_crit_search_slot for something more sensible~~
* ~~(0043) s_arm6_crit_search_window needs to support partitions being disabled via the OTP chicken flag~~
* ~~(0044) Need to pick the last matching image_def or partition table block in the block list.~~
* ~~(0045) Make sure we ignore block lists that have any internal inconsistencies -- e.g. partition tables must have an origin link back to address 0 (mandatory). The link is relative, and we figure out with storage address arithmetic that it points to zero in flash storage addresses. (actually we now require lists to form a loop.)~~
* ~~(0046) `luke` Support second chip select for flash programming~~
* ~~(0049) Consider always poisoning opposite being disabled via the OTP chicken flag image in the buy phase of a TBYB,
  if this saves code size~~ no
* ~~(0052) When do we update OTP rollback version to match image rollback version? Is this just in TBYB buy phase?~~
  * ~~Long/short - rollback versions are only checked/applied in OTP for a secure boot (implies signed image)~~
  * ~~rollback version is applied to OTP at buy (explicit or implicit)~~
    * ~~actually i guess it is also updated on super implicit buy i.e. booting an image without TBYB: ANSWER yes (post 
      signature check obviously)~~  
* ~~(0053) Enforce image-only, in slot 1 only, as invalid~~ this should be the case already
* ~~(0055) Need some mechanism for passing TBYB "try" information via watchdog reboot (possibly same as 0137)~~
* ~~(0056) Partition table should support having a HASH_VALUE entry. (Also usable on RISC-V)~~
* ~~(0058) Require that the signature is always the last item in a block. Otherwise the block is invalid. Also, only 
  permit a single HASH_DEF.. revised this since you might want NEXT_BLOCK_OFFSET not to be signed... it 
  basically needs to be after every other parsed item (which is actually how the code was and is about the same thing)~~
* ~~(0059) Picoboot EXEC2: Require a per-boot random number (salt) + nonce in the signed block, for preventing replays of EXEC-image calls~~
   * ~~Spec a NONCE item for this~~
* ~~(0060) Does nsboot override OTP boot? Do we have a flag for having OTP boot still enter when BOOTSEL is pressed?~~
* ~~(0061) Change block IDs to have more hamming distance~~
* ~~(0062) Is there a image exe type for varmuleted code? (E.g. for OTP boot or for picoboot)~~ yes
* ~~(0063) Should we use null values for major/minor version (i.e. not have to initialize them to valid hx_uint32_t(0)) and check later - code size issue vs some hardening~~
* ~~(0065) `luke` Decide whether to add additional FFh QPI exit command to XIP exit (branch: extra_qpi_exit_cmd)~~ yes, should be harmless as it's two clocks, so added it and we will see during flash field testing whether it had a negative effect
* ~~(0066) Implement API permissions using bootram flags~~
* ~~(0068) Hoist as much stuff as possible into SG and remove the RISC-V stuff so we don't have secure-executable RISC-V instructions~~
* ~~(0069) XIP cache is not actually mapped at boot time~~
  * done when entering nsboot, and we assume it is pinned before watchdog reboot that needs it
  * packaged RAM binary... we will pin as we write.
* ~~(0070) When shuld we clear partition table (after vectors?)~~
  * ~~do it before "real boot" i.e. RAM/OTP/FLASH/NS~~
* ~~(0071) Do we want anti-rollback on RISC-V (see 0073)...~~ no this is a terrible idea (we only support on 
  secure)
* ~~(0072) Do we need OTP for "require major_rollback_version"~~
  * ~~yws we need the bit~~
  * ~~we set it once we've seen a binary with a version (non zero number of OTP rows)~~
* ~~(0073) Use `clz` and varmulet for counting rollback bits - actually using clz so we have to decide 
  RISC-V~~ this is fine now as we only use on arm 
* ~~(0075) `luke` Remove BOOT2 by default from SDK (and VTOR entry) - at least for testing~~
* ~~(0077) Should we fail BLOCKs with bad parsing (e.g. mis-sized items) - we currently ignore invalid items (probably 
  fine with a goto (size wise))..~~ we fail now
* ~~(0078) need to be careful about permissions for writing OTP for anti-rollback - also when does this happen 
  (relates also to whether we support on RISC-V which is 0071)~~ this is now OK because the image must be signed for 
  us to update OTP
* ~~(0080) A secure chip should reset core 1~~ no, because reset of OTP implies reset of CORE 1, and doing it in the 
  bootorm is too late already 
* ~~(0083) `luke` configure GPIO for second chip select~~
* ~~(0084) `luke` permit reboot to NSBOOT when bootdis is set~~
* ~~(0086) WHY: Find out why picotool save is slow as balls~~ because the flash clkdiv was doubled, now fixed
* ~~(0088) WHY: Why is DOOM flash streaming borked?~~
* ~~(0092) Enable bootrom_assert on 64k version (i.e. development assertions) now we have enough space to swing a dog in~~
* ~~(0096) picoboot info should return device unique ID, so that subsequent picotool commands can target a particular device by its ID~~
* ~~(0097) done? Bounds check each UF2 flash block write, and fail the download if it goes off the end of the partition~~ yes, fixed by use of the checked_flash API
* ~~(0104) picoboot: expose a "where would I put this family ID" API~~
* ~~(0105) picoboot: expose a "get partition table"~~
* ~~(0110) OTP flag for using D8h 64k erase command to make programming faster (used for picoboot and checked flash API, can't be used by UF2 load unless we add more metadata for it)~~
* ~~(0112) Implement picoboot EXEC2 (signed/image_def exec), and don't support picoboot EXEC~~
* ~~(0114) `luke` rename CLOCKS_BANK_DEFAULT to CLOCKS in ACCESSCTRL~~
* ~~(0115) Should we split OTP_DATA_BOOT_FLAGS into two sets of rows, to reserve more space for additional flags? Depends on whether we want to cache this in an hxu32.~~ it is split
* ~~(0120) need to set window size for slot boot (do we know how big?)~~ set to size of CS 0
* ~~(0129) Use boot spinlock to protect partition table accessors? (E.g. races between adding an ephemeral partition and walking the resident table)~~ no, just fill out the entry before incrementing count when appending
* ~~(0130) Implement inline_s_partition_is_nsboot_writable~~
* ~~(0133) Add a setter for the cached flash_devinfo in bootram?~~ Probably SDK-side as it's secure-only and we already document the bootram layout
* ~~(0134) `luke` add enumvals for FLASH_DEVINFO flash sizes~~
* ~~(0139) Allocate space for the UF2 download bitmap for a 32 megabyte download~~ have mode erase flags into end of RAM
* ~~(0142) `luke` review address range validation code, particularly looking at region number checks~~ checked, found a couple of bugs
* ~~(0144) Expose a NS API to get partition table (make sure it works correctly when called from Secure -- can the gateway check the lr token?)~~
* ~~(0145) Make sure we zap registers before entering nsboot~~
* ~~(0148) Bounds check writes performed by load of OTP-boot code into SRAM~~
* ~~(0151) NS API to call the stdio function pointers stored in bootram~~
* ~~(0153) NS API to perform QMI ATRANS translation (flash runtime address to flash storage address)~~
* ~~(0154) done? Flash APIs need to return an error if the partition table is not loaded. Need an NS API to trigger loading of partition table (for RAM binaries doing flash stuff)~~ partition load check is implemented, NS API for partition load likely axed due to poor safety vs ergonomics trade (how does NS provide the necessary workspace) -- Secure RAM binaries should just do a partition load if NS is to be able to program flash.
* ~~(0156) done? NSBOOT OTP API needs to also be exposed as an NS API, and use the correct permissions based on caller~~
* ~~(0168) We need to load resident partition table on flash access from picoboot~~ done up front
* ~~(0169) Reclaim RISC-V stack space by relocating register file to USB RAM after watchdog check (regs can start off way down the bottom of bootram)~~
* ~~(0170) Block loop (lowest address (sector) must be first~~
* ~~(0190) some vector todos (we should remove thumb bit setting in ARM path, and hang in RISC-V native_secure_call or whatever)~~
* ~~(0192) Remove support for multiple hash items etc. (i.e. you use the one there is which must come before)~~
* ~~(0194) Implement inline_s_is_b_partition~~
* ~~(0204) SHA256 reset (we do it in the boot path)~~ is fine 
* ~~(0208) hx_assert should be bootrom_assert?~~ 
* ~~(0212) Move default_xip_setup function into NS areas as it is data not code~~ Moved it to .rodata instead
* ~~(0213) Make sure Secure image .rodata section is not executable (either via MPU or via watermark)~~ via MPU, though it ought to be close to watermark value anyway
* ~~(0222) handling of ECC read failures (e.g. chip random id)~~ - we ignore
* ~~(0224) bootrom_state_reset (we have core0, core1, permissions)...~~
  * core 0 boot will call state_reset(CURRENT_CORE|GLOBAL_STATE) in boot path
  * core 1 will call state_reset(CURRENT_CORE) in wait_for_vector
  * core 0 crt0 (actually runtime.c right now) will call state_reset(CURRENT_CORE|GLOBAL_STATE) in RAM binaries, to handle debugger launch
* ~~(0228) size: Remove exposure of wait_for_vector? (ooh is this a problem for debugger launch of core 1 into RAM 
  binary?)~~ Yes this is fine, core 1 can just enter through the reset vector instead of looking up a symbol
  of band (in USB RAM)
* ~~(0234) size: can we sometimes combine NS and S Apis (i.e. can bounds checks be safe and SG AOK?) - no, but we
  should try to save table space (two addresses for one symbol)~~
* ~~(0238) remove flash_noop from PICOBOOT~~
* ~~(0248) does clearing r4 in canary_entry provide value (it certainly increases size)~~ - no value
* ~~(0246) call state reset on core 1 launch for RISCV (arm doesnt have any core 1 state reset) - issue with stack, we could make the function ASM~~ function moved to varm, so solved by just clearing varmulet_enclosing_cpu directly in asm
* ~~(0252) luke; varmulet copro instruction check (is this correct/efficient decode)~~
* ~~(0264) return error codes from flash programming picoboot calls (need to fix shims to return error so we can) -~~ 
  ~~note these need to be translated to at least 1 PICOBOOT error code~~
* ~~(0270) gitref/ for JEDECID is this todo stale~~
* ~~(0278) should NS buffers be allowed to be in USB ram, or just for NSBOOT (currently the former)~~ good as is
* ~~(0280) reorder partition permissions bits to be S at top to match everything else~~ these are correct already
* ~~(0287) can we remove page lock checking in otp_access; it catches a case where we have read access but not write, 
  but we still have the "is key locked" cases to worry about. maybe caller should check anyway (as per disputed todo)~~ invalid: we need to check permissions for NS, duh!
* ~~(0296) TBYB short-circuit we just skip short circuit in secure mode (i.e. we don't NOT look for slot 1) - note i 
  also think that now you can TBYB slot 1 if there is a singleton in slot 0~~ ok says luke
* ~~(0302) what about invalid load map desitinations~~ 
* ~~(0304) Add "signature checked hx_bool" and re-check it on EXE launch in secure boot path~~
* ~~(0306) do we really want to leave FLAG in PT if there is only one (or should we fall thru) - i gess that 
  is OK because worst that happens is you don't find anything to boot, and will fall thru anyway~~ no flag in PT
* ~~(0308) ooh, harden core 1 launch - we don't want to be able to glitch it into executing code - so perhaps 
  hx_bool in register which is set once we are down the full handshake. we should certainly make RAM/XIP ro/non-exec until we start~~ added some RCP step checks, and made everything except core 1 launch code non-executable
* ~~(0314) do we need the 3 word NEXT_BLOCK_OFFSET (removed)~~
* ~~(0316) do we need concatenated (i.e. no NEXT_BLOCK_OFFSET) blocks (removed)~~
* ~~(0318) dropping a RAM binary of the wrong CPU doesn't switch now - we need the boot reason flag, so we can do a second reboot to RAM (when we reboot to perform the switch)~~
* ~~(0322) if we find an invalid block loop we treat that as garbage flash settings - I think this is correct 
  (you just get shitty speed (takes longer to boot) perhaps if you actually have bits of block list left around, or 
  you write a bad one)~~
* ~~(0326) should TBYB flash boot be disabled by BOOTDIS~~ no
* ~~(0328) special (!= NORMAL) boot types would cause us to always set ARCHSEL in watchdog_reboot 
  even if no explicit reboot ARCH selected which seems odd; we should just leave them alone~~
  * ~~note also, what happens if you are debugging on the other core (i guess your own silly fault?)~~ thats your 
    problem
* ~~(0334) ARM6 stack alignment in core0_boot_path - perhaps not important without printf? - actually this is 
  a bit of a mess and tangled with skipping of no_return stack frame; what is the alignment requirement for RISC-V~~ 
  (answer 16)
* ~~(0356) SRAM / XIP cache LOAD MAP entry writing should NOT cause a crash - can writing to second half
  cause a crash?... ANSWER: we need to pin all 16K of cache when we see a XIP target, and disallow anything outside
  of last 16K of address space (see 0035)~~
* ~~(0357) move XIP cache flushing earlier (before load map) - and pin during load map~~
* ~~(0362) should we allow SHA256 HASH < 8 words (e.g. just a number of words)~~ decided yes
* ~~(0366) slot size > flash size?~~ ANSWER: this should not be possible
* ~~(0372) need API to check flash has been setup (or what will happen?)~~
* ~~(0376) i thought we wanted different permissions for CS 0 and CS 1 without needing a PT (see 0382 also)~~ we 
  decided not
* ~~(0382) make accepting of absolute UF2 not a partition flag, but a PT flag... you are still bound by NSBOOT 
  permissions, it just indicates whether you can overwrite stuff which is in a partition (vs stuff not in a 
  partition - remind how default permissions work - should these be partition 16, 17 from a code point of view - see 
  376)~~ ~~ANSWER: yes we have flag in partition table for absolute download, and it overrides the default value of un 
  partitioned space too....~~
  * ~~there is no point in preventing unpartitioned downloads because they don't have any capabilities that partitioned 
    downloads don't other than writing to unpartitioned space~~
  * ~~we should let the partition table (overriding the defaults for no partition table) define permission for 
    unpartitioned space. (note the pt tool should possibly set the value to no writing to unpartitioned space)~~
* ~~(0388) switch to cortex-m23~~
* ~~(0392) graham: Fix hash size to be 8 words not 16~~
* ~~(0394) graham: Switch back to doing 4K searches (not multiple 1K)~~
* ~~(0396) ack: do we miss some cases where we pick 0/1 or a/b incorrectly.~~
* ~~(0400) currently we don't ignore signed blocks when not in secure mode (i.e. we take the latest) - i think this is 
  OK as you are expected to keep the normal data the same OK~~
* ~~(0403) Support launch of RISC-V core 1 via new multicore_launch API~~
* ~~(0405) Delegate all exceptions, coprocessors etc to NS in launch-core1-from-NS trampoline~~
* ~~(0407) Why does the secure core 1 boot hook have a garbage value when I check it in an SG? Should be 0.~~ Now cleared in bootrom_state_reset
* ~~(0408) why is arm_cmse.h here with #defines~~
* (~~0410) just 32 bit hash for PT? this is current - OK~~
* ~~(0430) what about empty PT vs no PT for UF2 download permissions? RTFM (yes there should be two words for 
  unpartition space)~~ with no PT you can write to any of flash, you can add a PT to prevent this
* ~~(0435) writing of rollback version from RAM binary~~ we do update, that's up to you
* ~~(0452) ok to rewrite ROLLBACK_REQUIRED bit~~ 
* ~~(0456) verify that IMAGE_DEF flash addresses are in 32M window (not in aliases) - we assume this means load_map sources~~ yes, all runtime and load addresses must be in either XIP 32M, XIP RAM, or main SRAM
* ~~(0518) refuse to reboot to an unavailable architecture, to avoid boot loop~~
* ~~(0014) Consider removing USB isolation at the point we remove reset from USB on the normal boot path (if there is no metal fix)~~ fixed in hardware
* ~~(0019) Make double tap reset time configurable e.g. in multiples of 50 ms~~
* ~~(0023) Prune OTP header and make sure there is no junk in there (possibly done)~~
* ~~(0026) Make sure OTP data names fit in 80 chars~~ mostly gone, just some USB crap, will fix header generation post-tapeout.
* ~~(0021) Simplify the boot strapping for UART/I2C now that we are UART only~~
* ~~(0067) Implement NS API wrappers (parameter-check wrappers around secure APIs)~~ these exist, dunno if we have absolutely everything we ever dreamed of
* ~~(0094) UART picoboot~~ axed, the purpose of UART boot is to be simpler than USB+picoboot. We also have SWD, if you want something bitbangable and fully featured.
  * Reset device (outside of picoboot cmds, embedded in UART framing, like a USB reset)
  * Cancel, i.e. the ability to abandon a command midway and resync without knowing how far through the command you were
* ~~(0141) Add new core 1 launch APIs with SAU mirroring, launch-NS-from-NS version~~
* ~~(0188) Use real OTP bit for dirty_config sigcheck rosc div clock stuff~~
* ~~(0462) what registers should be saved/restored in secure_call in RISC-V~~
  * ~~remove use of GP so we don't have to worry about it (EXEC2 calls user code which might do GP, and we have our IRQs)~~
* ~~(1000) Make sure UART boot works under RISC-V (possibly require UART-FIFO-sized framing to provide simple backpressure)~~
* ~~(1001) implement USB_BOOT_FLAGS_DP_DM_SWAP~~
* ~~(1003) size: remove OTP ROSC configuration for nsboot? Costs 128 bytes~~ yes, it's actually useless
* ~~(0157) Size: Should the RISC-V symbol walking walk the arm table for varmuleted calls, rather than duplicating the entries?~~
* ~~(0232) size (table entry): Do we want to expose verify sig in ROM table? - may not be possible if we store results out~~ inclined to say no, it is currently not in the table anyways.
* ~~(0230) size (table entry): Do we need to expose SHA256? one of those NS might want to do it things; answer no~~
* ~~(0340) size: remove support for REBOOT vs REBOOT2 cmd since old picotool no longer works anyway (see 0330)~~
* ~~(0282) size: remove __no_inline from s_arm6_crit_init_resident_partition_table_from_buffer (needed for debugging)~~ it is now used in two places
* ~~(0450) size: uninline erase_words & copy-words, and just check_step after (also hint for riscv versions)~~
* ~~(0508) size: magic -1 param to set callback~~ now < 0
  **  
* (0554)
