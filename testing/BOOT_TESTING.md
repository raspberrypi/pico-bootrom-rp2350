# Bootrom (ns)boot/UF2 testing

## Overview

This document discusses major areas of testing for the bootrom boot paths, and specifies the expected behavior and data formats involved. It should be updated to include detailed test plans later

Testing of the RP2350 boot-path/nsboot(formerly USB boot, but now includes UART and runs in NS(non-secure) mode) is much more involved than RP2040, because:

* We have persistent state in OTP which affects things
* We support ARM/RISC-V
* We support partitioning flash via "partition table" (and two possible copies of the PT)
* We now have security/signing of images/partition tables (note binaries are executable/bootable images)
* We support A/B images, "try before you buy", anti-rollback
* We support "rolling-windows"
* We support multiple UF2 families, and having them drop into different partitions (including doing A/B upgrades)
* We have flash and OTP permissions configured by the user

The upshot of all this, is that what happens during the flash boot path or UF2 download is dependent on the initial 
state of:

1. certain OTP registers
2. flash contents (including valid/invalid signed/unsigned hashed/unhashed partition tables/partitions, images etc).

Arguably RP2040 flash boot was dependent on the flash contents, but there were really no branches in the control flow - if the first 256 bytes of flash passed boot2 crc, then it was booted

NOTE: This document does not address our hardening testing which may use fuzzing/simulation, however the scenarios developed/test data generated here may be used as a basis for hardening tests, or equally we may choose to run some of these tests under simulation rather than on device (if it is more efficient for large scale), and there will likely  be some overlap with any fuzzing work we do for catching code paths hit by invalid data (see [FUZZING_SECURITY](FUZZING_SECURITY.md))

NOTE: simulation in the previous note, is not intended to refer to the ASIC sim, but rather something like "unicorn", though I guess the former could be possible. 

## Test harness required

1. Because of the large number of possible states of flash, we would like to be able to programatically generate flash contents based on what we're trying to test. this could be JSON or whatever based, but it is fine to do it in straight code.
  
   * An example generation might create a partition table, put a "signed" binary with version 1 in one of an A/B partition,
     and a binary with version 2 in the other.
   * Variants of the above, might have invalid binaries, wrongly signed binaries, invalid partition tables etc.
   * We can do some random perturbations of what we're specifically trying to test, but the test harness should be able to predict what is supposed to happen
1. The tests need to run on FPGA (since we're testing newer bootrom than A0)
1. We need to generate and load a fresh OTP image with each test.
1. We need to be able to reset the RP2350 regularly to ARM, RISC-V, or into BOOTSEL mode.
1. We would like to be able to send UF2 images, and check written flash contents, and also determine if we boot successfully
1. We need to test RAM UF2 as well as flash
1. Ability to detect possible outcomes (aka what is supposed to happen):
   * Image boots successfully
   * Falls thru to nsboot
   * We get a hard lock-up from RCP (i.e. we detected something bad) - note: the only time this should happen in this type of testing (vs hardware attack simulation) is if there is no valid boot path (i.e. all both paths - including nsboot - fail or are disabled).
   * That USB drive and/or PICOBOOT interface appear 


## Boot path

What happens at boot is dependent on OTP settings, the state of the flash, watchdog/powman scratch register values, whether BOOTSEL is pressed, and the UART bootstrap pins.

The main boot flow can be summarized as:

```
entering_ns_boot = BOOTSEL_PRESSED | specified in powman/watchdog
if (powman_vector) {
   // note these calls may return
   if (correct_arch) pownam_vector() else hang();
} 
if (watchdog_vector) {
   // note these calls may return
   if (correct_arch) pownam_vector() else hang();
}
if (!entering_nsboot) {
   // ram_image_window specified by powman/watchdog reboot
   if (ram_image_window) {
      // this only returns if there is no valid(signed if necessary) ram image to enter
      try_boot_ram_iaage(ram_image_window);
   } else {
      if (otp_boot_enabled()) {
         // this call may retun even if otp boot present
         try_otp_boot();
      }
      if (flash_boot_enabled()) {
         entering_nsboot = check_double_tap();
         // this only returns if there is no valid(signed if necessary) flash image to enter
         if (!entering_nsboot) try_flash_boot();
      }
   }
} 
if (entering_ns_boot) {
   if (bootstrap_select_uart && !nsboot_uart_disabled) {
      // never returns
      nsboot(uart);
   } else if (bootstrap_select_usb && !nsboot_usb_disabled) {
      nsboot(usb)
   }
}
hard_hang();
```

The OTP, RAM, and flash boot paths can only boot valid "images", but what is an image? Images are recognized by metadata blocks:

Note than if both architectures are enabled and the feature is not disabled in the OTP, then OTP, RAM and flash boot 
will switch reboot into the other architecture if they find an image for the other architecture and none for the 
current. 

Note that OTP boot may (TBD) support varmulet code (i.e. arm6 only subset that can be run on ARM and emulated on 
RISC-V)... this is the only thing that would (rational being OTP space is small)

## Metadata Blocks

Metadata blocks are self describing blocks that can be searched for inside of executables or data. We store metadata this way
to give end users the most flexibility about their image layout (people were unhappy with us tacking 256 bytes at the start of RP2040 binaries).

The only types of block we care about ar "partition table" and "image def", the latter which can be executable or other versioned image. Either of these types of blocks can be hashed for verification and/or signed. Note see the IMAGE_DEF and PARTITION_TABLE items below for mode details on images and partition tables.

Note you can see [BINARIES.md](../spec/BINARIES.md) for some more context on why things are the way they are, but it is a bit of a brain dump. At some point we can take this content here and make a better spec.

We search for blocks within a contiguous region (flash, flash partition, region of ram etc.) called a 'window'. In the case of flash we expect to find the first block within a certain distance of the start of the region (4K for flash boot)

A block always contains a relative link to the next block. The block links form a loop (the last block must contain a link **back to the first block**). No blocks are considered valid, unless the blocks form a valid loop. Note that by default the SDK puts a block near the start of an image, as an image_def block is required to boot an image (note we no longer have CRC-ed boot2 to determin a valid image). It has a next pointer of 0, however signing the EXE will change this to point to a new image_def which is signed which will point back to the original block. Note it is possible to null-ify an existing block by filling the contents up to PICOBIN_BLOCK_ITEM_2BS_LAST with a single PICOBIN_BLOCK_ITEM_2BS_IGNORED item (or indeed any other unknown item, but this is guaranteed never to be parsed)

### Metadata block format

Blocks have a header, a footer, and a variable number of items.

Note: due to RAM restrictions in the boot path, size of blocks is somewhat limited; currently (in bytes)

Note: all blocks are LSB first

```c
#define PICOBIN_MAX_IMAGE_DEF_BLOCK_SIZE       0x180
#define PICOBIN_MAX_PARTITION_TABLE_BLOCK_SIZE 0x200
```
```c
// Note little endian

WORD        : SIZE : VALUE
=========== : ==== : ===== 
          0 :  0x4 : 0xffffded3 (MAGIC HEADER)
        
            // item 0
          1 :  0x1 : size_flag:1 item type:7 (size_flag = 0 means 1 byte size, 1 means 2 byte size)  
            :  0x1 : size low byte
            :  0x1 : size hi byte/item type specific data
            :  0x1 : item type specific data
          
             // item 1 
     1 + s0 :  0x1 : size_flag:1 item type:7 (size_flag = 0 means 1 byte size, 1 means 2 byte size)  
            :  0x1 : size low byte
            :  0x1 : size hi byte/item type specific data
            :  0x1 : item type specific data
            
1 + s0 + s1 :  0x1 : 0xff (size_flag = 1, item type = BLOCK_ITEM_LAST)
            :  0x2 : other items' size (s1 + s2)
            :  0x1 : 0 // todo could change this for more sanity checking       

2 + s0 + s1 :  0x4 : relative position in bytes of next block MAGIC_HEADER relative to this block's MAGIC_HEADER 
               this forms a loop, so a single block loop has 0 here.

3 + s0 + s1 :  0x4 : 0xab123579 (MAGIC FOOTER) 
```

IMAGE_DEF and PARTITION_TABLE blocks are recognized by their first item being an IMAGE_DEF or PARTITION_TABLE item.

Note see https://asic-git.pitowers.org/amethyst/pico-sdk/-/blob/master/src/common/boot_picobin/include/boot/picobin.h for latest constants

#### IMAGE_DEF

An image def details a versioned blob (which may be bootable/executable). An IMAGE_DEF (block) starts with an 
IMAGE_DEF item.

```c
.byte PICOBIN_BLOCK_ITEM_1BS_IMAGE_TYPE  // item type with 1-byte size
.byte 0x1                                // word size of this item
.hword                                   // image type flags (see picobin.h)
```

To sign a binary, you must include these items in the IMAGE_DEF block

* BLOCK_ITEM_LOAD_MAP (was optional before, but now needed to define scope of hashed contents - actually it is only 
  now required if you have some data to sign outside of the block, which you always would you'd think in an 
  IMAGE_DEF but you generally won't in a PARTITION_TABLE)
* BLOCK_ITEM_HASH_DEF (defines the hash type/scope) - this must come after items that need to be hashed
* BLOCK_ITEM_SIGNATURE (the signature) - this comes after hash_def, so it isn't included in it!

Generally you'd also include unless you expect to just have a single binary with no anti-rollback (again these need 
to be covered by the signature):

* BLOCK_ITEM_VERSION (major/minor version, optional major rollback version with a list of OTP rows which determine device's minimum major rollback version (anti-rollback))

Note there is a TBYB flag for EXE image types, that indicates this is not the active image, but is a
candidate for a "try" operation which may subsequently be followed by a "buy". The bootrom will not attempt to boot an image normally (i.e. not as part of a try-buy sequence) if this flag is set. NOTE that a signing tool must sign the binary *WITHOUT* this flag set.

A "try" boot will see the `TBYB` flag and clear it before computing the hash in the
signature check, so it should compute the same hash as the signing tool and successfully verify the
binary. The "buy" phase (the binary calling back into the bootrom) will clear the flag by reprogramming the sector containing the block, to make the image normally bootable.

#### PARTITION_TABLE

A partition table defines up to 16 (bootram space limited) partitions. The partition table is used both for locating images during boot, deciding where dragged UF2 files are stored, and for providing runtime flash read/write permission

* The partition tables divides the 32M flash address space into (possibly named and/oridentified) partitions with attributes
* There can be one or two partition tables (to allow for flash partial write/failures). The (valid hash/opt sig) one with the latest version is "active"
* In the absence of a partition table, the bootrom will use (for permissions) a default partition a single partition 
  with offset/size & attributes from OTP (or just default to everything is writable if OTP not present)
   * we already said we had two flash sizes, so we should use those here

* Permissions are read/write for S, NS, PICOBOOT
   * anything not covered if there is a partition table is secure only (TODO didn't we say something else luke?)
* Partitions may be linked into A/B pairs, wherein which partition is "active" (e.g. would be the one used for boot) 
  is dependent on the IMAGE_DEFs of the binary in those partitions and their version information/validity.
* UF2 download is targeted based on UF2 family id.
   * Partitions indicate which family(es) they support storing from UF2. (Note this allows you to have more restrictive permissions for UF2 download for a partition than the actual PICOBOOT permissions)
   * In the case of A/B pairs, the download will target the version which would NOT boot (i.e. the inactive one)

A partition table has:
   * partition count
   * optional VERSION (generally containing only a simple major/minor version, since downgrading a pt doesn't really mean anything)
   * permission for partition spanning access
   * optional hash/signature
   * A list of partitions; the ordering is significant for boot priority, but does not necessarily match the actual 
     order of the locations of the partitions in flash

Each partion has:
   * 4K aligned start/end
   * Permissions (R/W) for S, NS, NSBOOT
   * Optional 64-bit id
   * Optional name
   * Not-bootable flags for ARM/RISC-V this is an optimization to mark something to be ignored during boot under ARM or RISC-V
   * A set of UF2 families that may be dropped into that partition (we will have RP2040, RP2350 ARM SECURE, RP2350 ARM 
     NON-SECURE, RP2350 RISC-V, ABSOLUTE_UF2 but the user can define their own).
   * "Absolute UF2" family. By default, when we download a UF2 whose family matches a partition, we will store the UF2 
     _into_ the partition. That means for data for an address of `0x10000000` in the UF2 may actually be stored at 
     the flash offset of the start of the partition.

     If the "Aboslute UF2" partition flag is set, then when we download a UF2 whose family matches this partiton; 
     any contents overlapping this partition are written to their specified address. Such an "absolute UF2" 
     partition may overlap other partitions, and allows for example dropping a UF2 to replace the entirety of flash. 
     We have a well-defined family id for this "ABSOLUTE_DATA" or something.  
   * Optional link from an A partition to its paired B partition
   * /or optional link to a partition this partition is "grouped with" (more on this later, which is only relevant 
     for more exotic use cases of donwloading UF2 files. 

A PARTITION_TABLE (block) starts with a PARTITION_TABLE item)
```c
.byte PICOBIN_BLOCK_ITEM_2BS_PARTITION_TABLE_TYPE // item type with 2-byte size
.hword                                      // word size of this item
.byte                                       // top bit set if singleton; low 4 is partition count
.word un_partitioned_space_permissions_flags
    31: nsboot_w
    30: nsboot_r
    29: ns_w
    28: ns_r
    27: s_w
    26: s_r
    ..
    17: accepts_family_rp2350_riscv
    16: accepts_family_rp2350_arm_ns
    15: accepts_family_rp2350_arm
    14: accepts_family_rp2040
    13: accepts_family_data
    12: accepts_family_absolute

[for each partition]
    .word permissions_location
        31: nsboot_w
        30: nsboot_r
        29: ns_w
        28: ns_r
        27: s_w
        26: s_r
        25-12: last_sector_number (4K)
        11-0:  first_sector_number (4K)
    .word permissions_flags
        31: nsboot_w
        30: nsboot_r
        29: ns_w
        28: ns_r
        27: s_w
        26: s_r
        ..
        17: accepts_family_rp2350_riscv
        16: accepts_family_rp2350_arm_ns
        15: accepts_family_rp2350_arm
        14: accepts_family_rp2040
        13: accepts_family_data
        12: accepts_family_absolute
        11: no_reboot_on_uf2_download
        10: has_name
        9: ab_non_bootable_owner_affinity
        8: not_bootable_on_riscv
        7: not_bootable_on_arm
        
        5-6: num_extra_familes
        3-4: link_value
        1-2: link_type
        0: has_id
    [if has_id]
        .word id_lo
        .word id_hi
    [for 0..num_extra_families]
        .word family_id
    [if has_name]
        .byte top_bit_reserved; lower_7)_bits: n_name_len_bytes
        [for 1..(n_name_len_bytes + 4) & ~3]
            .byte name_char

```

Note common in headings below mean they can occur in both `IMAGE_DEF` and `PARTITION_TABLE` blocks

#### HASH_DEF (common)

Optional item woth information about what and how to hash

```
.byte PICOBIN_BLOCK_ITEM_1BS_HASH_DEF // item type (with one byte size)
.byte 0x1                         // word size of this item
.byte 0                           // pad
.byte PICOBIN_HASH_SHA256         // hash type
.hword block_words_hashed         // number of words of block (not including START marker) hashed; must include this 
block if used for a signature 
.hwrd 0                           // pad
```

Note for Amy I removed the load_map link - if there is one it will ALWAYS be hashed (we could change this behavior in the future with a new flag). The load map used will be the last LOAD map in the block)

#### HASH_VALUE (common)

Optional item with hash result (for use when not using signature)

```
.byte PICOBIN_BLOCK_ITEM_1BS_HASH_VALUE // item type (with two byte size)
.hword 0x1 + n                    // word size of this item (note if the hash value is included, n > 0)
.byte 0                           // pad
.word [n]                         // hash value... which can be used for checking the binary is AOK           
```

Note whilst a SHA-256 is 16 words, you can include less (down to 1 word)

#### ITEM_SIGNATURE (common)

Optional item with cyrptographic signature

```
.byte PICOBIN_BLOCK_ITEM_SIGNATURE // item type 
.hword 0x22                        // word size of this item
.byte PICOBIN_SIGNATURE_SECP256K1  // signature type
.word [16]                          / public key
.word [16]                         // signature
```

Note: for Amy, I removed the reference to the HASH_DEF... it will pick the most recent

#### SALT (common)

Optional salt to be included in the cryptographic signature. Note that the bootrom expects 6 words
of salt, namely the 128 boot random, followed by the 64 bit nonce.

```
.byte PICOBIN_BLOCK_ITEM_SALT      // item type 
.hword 1+n                         // word size of this item
.byte 0                            // pad
[for i = 0..n]
    .word data
```

Note: for Amy, I removed the reference to the HASH_DEF... it will pick the most recent

#### VERSION (common)

A major/minor version number for the binary, 32 bits total, plus optionally a 16-bit major rollback
version and a list of OTP rows which can be read to determine the (thermometer-coded) minimum major
rollback version which this device will allow to be installed. The major and minor are always
present, whereas the major rollback version and OTP row list are generally only included if rollback
protection is required. The major rollback version is only valid in IMAGE_DEF blocks.

Each OTP row entry indicates the row number (1 through 4095 inclusive) of the first in a group of 3
OTP rows. The three OTP rows are read through the raw read alias, combined with a bitwise majority
vote, and then the index of the most-significant `1` bit determines the version number. So, a
single group of three rows can encode major rollback versions from 0 to 23 inclusive, or, when all
24 bits are set, an indeterminate version of at least 24. Each additional entry adds a further
group of 3 rows which increases the maximum version by 24.

There is no requirement for different OTP row entries to be contiguous in OTP. They should not
overlap, though the bootrom does not need to check this (the boot signing tool may).

For this entry to be considered valid, the number of available bits in the indicated OTP rows must
be *strictly greater than* the major rollback version. This means that it is always possible to
determine that the device's minimum major version is greater than the major version indicated in
this block, even if we don't know the full list of OTP rows used by later major versions.

If the number of OTP row entries is zero, there is no major rollback version for this block.

The major/minor version are used to disambiguate which is newer out of two binaries with the same
major rollback version. For example, to select which A/B image to boot from. when no major rollback
version is specified, A/B comparisons will treat the missing major version as zero, but no rollback
check will be performed.

```
.byte PICOBIN_BLOCK_ITEM_1BS_VERSION // item type
.byte 2 + ((num_row_entries != 0) + num_row_entries + 1) / 2
.byte 0
.byte num_otp_row_entries
.hword minor
.hword major
.hword rollback       // optional, present if num_otp_row_entries != 0
.hword otp_row        // optional
```

#### LOAD_MAP (common)

TODO: Note this is currently common to support easy signing/hashed of partition tables whose labels are stored outside the block (due to space constraints)... this feature may (probably will be) be removed in which case this will be IMAGE_DEF only.

Optional item with a similar representation to the ELF program header. This is used both to define content to hash, and 
also to "load" data before image execution (e.g. a secure flash binary can be loaded into RAM prior to both sig check and execution)

The load map is a collection of *runtime address*, *physical address*, *size* and flags.

Note on terms:

* *physical address* this is where the data is stored in the logical address space (e.g. the start of a flash image even if stored in a partition could have a physical address of `0x10000000`)  
* *runtime address* what the address of the data is at runtime
* *storage address* this is an absolute location where the data is stored (not necessarily the same as physical address for flash when partitions are in use)

Note we are using *physical address* here not *storage address* as this data is written by a tool working on the
ELF which will not know where the binary will finally be stored in flash.

This serves several purposes:

1. For a `packaged` binary, this tells the bootrom where to load the code
2. For a signed binary, the *runtime addresses* and *size*s indicate code/data that must be included in the hash
   to be verified.

NOTE: `picotool` will need to be updated to understand the EXE header so that it can translate addresses appropriately

NOTE: If the runtime_address is in flash or equal to the storage_addresss, then data is never copied, it is just hashed in place

```
.byte PICOBIN_BLOCK_ITEM_LOAD_MAP    // item type (1 or 2 byte size) 
.hword 1 + num_entries * 3                           // word size of this item
.byte absolute | num_entries                         // top bit == absolute flag
if (!absolute) {
    for each entry {
        .word storage_address_rel                            // relative to this load map item
        .word runtime_address_physical
        .word size
    }
} else {
    for each entry {
        .word storage_address_physical
        .word runtime_address_physical
        .word runtime_end_address_physical 
    }
}
    
```

NOTE: if the storage_address/storage_address_rel is `0x00000000`, then zeros are copying into runtime_address -> runtime_address + size;
NOTE: A load-map entry (with storage-address == runtime_address) MUST be present for part of XIP_RAM if your binary has code in the XIP_CACHE; this causes the cache to be pinned before entering the binary. it is fine for this to be:
```
0x00000001 // storage_address == runtim_address
XIP_SRAM_BASE // runtime addresss
0x00000000 // size of 0 is fine
```

#### VECTOR_TABLE (IMAGE_DEF only)

Optional item with location of the vector table. for ARM binaries, the entry_point/initial_sp will be taken from here 
if present
(unless there is an ENTRY POINT). Note if there is no ENTRY_POINT or VECTOR_TABLE, then a VECTOR_TABLE at the start of the image is assumed.

```
.byte PICOBIN_BLOCK_ITEM_VECTOR_TABLE  // item type
.byte 0x2                             // word size of this item
.byte 0                               // pad
.byte 0                               // pad 
.word vector_table                    // location (runtime address) 
```

#### ENTRY_POINT (IMAGE_DEF only)

Optional block with info on initial PC, SP
```
.byte PICOBIN_BLOCK_ITEM_ENTRY_POINT  // item type
.byte 0x3/0x4                         // word size of this item 
.byte 0                               // pad
.byte 0                               // pad 
.word entry_point                     // (runtime address)
.word initial_sp
.word initial_sp_lim                  // (optional)
```

#### ROLLING_WINDOW_DELTA (IMAGE_DEF only)

Optional item that allow for binaries that aren't intended to be run at 0x10000000. Note that
this delta is in addition to the roll resulting from the binary being stored in a different
partition in flash.

```
.byte PICOBIN_BLOCK_ITEM_1BS_ROLLING_WINDOW_DELTA    // item type with 1-byte size
.byte 0x2                                            // word size of this item
.hword 0                                             // pad
.word delta                                          // Where the first address belonging to the binary
                                                     // should end up at 0x10000000 + delta
```

## Flash layout

RP2040 had two alternatives:

* A bootable image at the start of flash (CRC of first 256 bytes valid boot2)
* No image at the start of flash (CRC failed)

We have more alternatives:

1. a single bootable image at the start of flash (there is an IMAGE_DEF and no PARTITION_TABLE in a valid block loop)
2. Partition table(s) at the start of flash (a PARTITION_TABLE is in a valid block loop starting in the first 4K of flash 
   "slot 0", or found starting in the 4K a fixed distance (default 4K, but overridable in OTP) into flash "slot 1".
   Defining partition tables is the only way to have multiple _separate_ bootable images. The use of two partition 
   tables helps avoid bricking your flash boot during power failure during flash write. Note "separate" here means that are stored in different locations, and compared by version, you can potentially have multiple images in a single combined image (e.g. ARM/RISC-V), but that is an entirely separate thing and still counts as a single binary.
3. Nothing in flash (no valid block loops in either slot with IMAGE_DEF or PARTITION_TABLE)

Note whether an image is bootable is more complex (as the image may fail hash/signature checks), and on top of this we now have anti-rollback, try-before-you-buy, A/B images etc.

## Use cases for partition tables

* Locating multiple possible binaries to boot (particularly A/B)
* Targeting UF2 downloads to the right area
   * Note this is not 100% foolproof, as we cannot stop people saying a UF2 is something it isn't via family ID, however you can make the secure area non UF2-able at least (and still allow NS)... in the simple use cases it will be helpful tho.
* Keeping data/embedded drives separate from main binary, and locating it/them
* Flash Permissions for bootrom flash related access APIs - note the information is NOT used by the bootrom to set up 
  MPU regions, though the secure binary could do so

### Some design notes for the boot path

* We want to support failures in the middle of flash writes (hence support for A/B images, and two partition tables)
* We want the data in flash to speak for itself... e.g if you download an image into a partition, you don't need to 
  update anything in the partition table to say you did so. This preserves the ability to load images/data any way 
  you want, e.g. gdb, picotool, UF2 download, entire flash write etc.) 

  **As a result which image to boot is determinally dynamically on each boot**
* We support try-before-you-buy, which means you install a new version of the code, try to run it, and the binary 
  calls back into a bootrom API to "commit" the update. If this doesn't happen the old version of the code will be 
  run again. 

  This basically means we write a TBYB flag into the IMAGE_DEF EXE_FLAGS indicating that the image should not normally be booted, remembering that we must always leave the flash in the state 
  that a power failure does the right thing (i.e. if we power fail before the "commit/buy", we must not use the new 
  version again), and set a flag while rebooting the first time to indicate we will be doing try-before-you-buy on 
  a given area. Note you should always hash sign an image, pretending the TBYB set to false (it is set to 0 when hashing). 

  TBYB is used with "flash update boot" which is a special type of boot after say UF2 download which indicates the beginning of  a slot or partition which was just updated. an image with a TBYB flag **can** be booted when it is the target of a flash update boot. Additionally, in the case of a choice of partition tables in slot 0/slot 1, or image_defs in a partition A/partition B, the "flash update boot" allows the partition table/image to be used even if it has a lower version than the other partition_table/image, and if so the boot will also ERASE the first sector of the other image on successful "buy" - either entering an iamge, or when the "buy" callback is made for TBYB=1

### Flash boot path details

Note that the method in the code is called "try_flash_boot"; it is possible there is nothing in flash to boot 
(possibly because the binary isn't signed). This method will return if there is nothing to boot, so we can try other 
options.

#### Part I - finding the partition table

* As mentioned before, the only way we can deal with more than one separate binary in flash, is if we have a 
  partition table.
* We have a partition table if we find a valid one in the block loop starting in slot 0 or slot 1. Note we **do not* 
  search 
  slot 1 if there is a singleton-flagged (to speed up boot) PARTITION_TABLE in the slot 0 block 
  loop, or if slot 0 block loop has a valid IMAGE_DEF and no valid PARTITION_TABLE (implying there _is_ no partition 
  table)
* What is a valid PARTITION_TABLE?  **todo: this is not 100% precise**
  * one that is a valid block.
  * one that passes SIGNATURE check if present, or if PT sig required in OTP and we're in secure mode (TODO clarify 
    the exact case here))
  * one that passes HASH check if present, or if PT hash is required in OTP (note for reasons this is optional for 
    partition tables see note below)
  * given the SIG/HASH checks, we don't do much other validation, other than checking the number of partitions, and 
    that the data is the right size.
  * one in the slot which starts at the "try-before-you-buy" base address (assuming all else is valid except the 
    VERSION 
    item)
* What happens if there is more than one PARTITION_TABLE in the block loop? Answer: we pick the last valid one.
* In the case there are valid PARTITION_TABLEs in both slots, we will pick the one with the highest VERSION, except 
  when using try-before-you-buy on one of the slots, in which case we'll pick the one in the "try" slot.
* What is a valid IMAGE_DEF? **todo: this is not 100% precise**
   * one that is a valid block.
   * one that has correct signature key, and passes SIGNATURE check if we are in secure mode 
   * one that passes HASH check if present and not in secure mode
   * one that is for RP2350
   * in the boot case, one that is executable (we have non executable IMAGE_DEFs)
   * one in the slot which starts at the "try-before-you-buy" base address.
   * if the IMAGE_DEF is in a partition, then it is valid if the "try-before-you-buy" base address is the start of
     that partition (assuming all else is valid except the VERSION item)
* What happens if there are multiple IMAGE_DEFs in a block loop
  * Ones signed with the wrong key are ignored
  * First valid one found wins, with the exception that we will replace an IMAGE_DEF for the wrong boot architecture 
    (assuming architecture switch is supported) with one for the right boot architecture if we find it.
  
NOTE: A try-before-you-buy is considered "bought" if a bootable image is entered (there is no corresponding API 
call) - this is because try-before-you-buy on a partition table is not image-centric, it is flash layout centric. A 
failed try-before-you-buy will simply reboot, to follow the boot path again without the "try-before-you-buy".

NOTE: We generally expect a partition table to be hashed (or possibly signed), as it is the best guarantee of 
validity. However, we do not enforce this. TODO should we?

#### Part II - finding the image

##### a. No partition table

If there is no found partition table, then the only place to find the IMAGE_DEF was in a block loop in slot 0.

##### b. IMAGE_DEF paired with partition table

We support putting an IMAGE_DEF in the same block loop with the PARTITION_TABLE.

NOTE: In this case the IMAGE_DEF that is booted is always the one found in the block loop, and the partition table is just used to define
flash layout and permissions.

This is useful in two cases:

1. As a convenience for the simple case where you only have a single binary, but you want to include a PARTITION_TABLE to describe the flash 
layout and permissions. 
2. Where the IMAGE_DEF is a bootloader executable.

NOTE: when there is both an IMAGE_DEF and a PARTITION_TABLE in a slot's block loop, then the IMAGE_DEF can sign/hash
the PARTITION_TABLE (the partition table must be covered by the LOAD_MAP). This feature is provided to avoid double
signature checks in this common case. a PARTITION_TABLE signature cannot
however cover an IMAGE_DEF.

You can have IMAGE_DEFs paired with PARTITION_TABLEs in both slots, however this is an advanced case, and more 
likely only used by bootloaders which are embedded in the slots. In this case, remember that the choice between slots is 
entirely a decision based on the PARTITION_TABLEs, and thus the IMAGE_DEFs in slot 0 and slot 1 are not compared 
against each other for decision-making purposes.

##### c. We have found a partition table without an IMAGE_DEF

In this case we have a PARTITION_TABLE which we've chosen according to the rules above, but there is no valid IMAGE_DEF 
paired with (in same the block loop as) the PARTITION_TABLE.

We therefore need to look for which IMAGE to boot by scanning the partitions in the partition table!

* We scan thru the partitions ignoring those which aren't bootable for the current architecture (including "Absolute 
  UF2" partitions), and those which are "B" partitions,
* For every such "A" partition, we must pick between a valid IMAGE_DEF in it, or a valid IMAGE_DEF in the 
  corresponding "B" partition if there is one, as which IMAGE_DEF to _try to boot first_. We try these criteria in 
  order:
  1. We try to boot the "try-before-you-buy" one first if the try_before_you_buy_base_addr matches one of the 
    partitions.
  2. We pick the one with the highest version first.

  We try any of the 0, 1, 2 images in order. Obviously the image has to be valid to be booted (signature and all).
* If we didn't find anything valid to boot, we move on to the next "A" partition in the partition table. 

## OTP values affecting the boot path

Here are the current knobs as of writing.
```c
// =============================================================================
// Register    : OTP_DATA_BOOT_FLAGS
// Description : Disable/Enable boot paths/features in the RP2350 mask ROM.
//               Disables always supersede enables. Enables are provided where
//               there are other configurations in OTP that must be valid.
//               (RBIT-3)
#define OTP_DATA_BOOT_FLAGS_ROW _u(0x5e)
// Field       : OTP_DATA_BOOT_FLAGS_HASHED_PARTITION_TABLE
// Description : Require a partition table to be hashed (if not signed)
#define OTP_DATA_BOOT_FLAGS_HASHED_PARTITION_TABLE_BITS   _u(0x00040000)
// Field       : OTP_DATA_BOOT_FLAGS_SECURE_PARTITION_TABLE
// Description : Require a partition table to be signed
#define OTP_DATA_BOOT_FLAGS_SECURE_PARTITION_TABLE_BITS   _u(0x00020000)
// Field       : OTP_DATA_BOOT_FLAGS_DISABLE_AUTO_SWITCH_ARCH
// Description : Disable auto-switch of CPU architecture on boot when the (only)
//               binary to be booted is for the other ARM/RISC-V architecture
//               and both architectures are enabled
#define OTP_DATA_BOOT_FLAGS_DISABLE_AUTO_SWITCH_ARCH_BITS   _u(0x00010000)
// Field       : OTP_DATA_BOOT_FLAGS_SINGLE_FLASH_BINARY
// Description : Restrict flash boot path to use of a single binary at the start
//               of flash
#define OTP_DATA_BOOT_FLAGS_SINGLE_FLASH_BINARY_BITS   _u(0x00008000)
// Field       : OTP_DATA_BOOT_FLAGS_OVERRIDE_FLASH_PARTITION_SLOT_SIZE
// Description : Override the limit for default flash metadata scanning. the
//               value is specified in FLASH_PARTITION_SLOT_SIZE. Make sure the
//               field is valid before setting this bit
#define OTP_DATA_BOOT_FLAGS_OVERRIDE_FLASH_PARTITION_SLOT_SIZE_BITS   _u(0x00004000)
// Field       : OTP_DATA_BOOT_FLAGS_OVERRIDE_FLASH_METADATA_MAX_SCAN_SIZE
// Description : Override the limit for default flash metadata scanning. the
//               value is specified in FLASH_METADATA_MAX_SCAN_SIZE. Make sure
//               the field is valid before setting this bit
#define OTP_DATA_BOOT_FLAGS_OVERRIDE_FLASH_METADATA_MAX_SCAN_SIZE_BITS   _u(0x00002000)
// Field       : OTP_DATA_BOOT_FLAGS_DOUBLE_TAP
// Description : Enable entering BOOTSEL mode via double-tap of the RUN/RSTn
//               pin. Adds a significant delay to boot time.
#define OTP_DATA_BOOT_FLAGS_DOUBLE_TAP_BITS   _u(0x00001000)
// Field       : OTP_DATA_BOOT_FLAGS_ENABLE_BOOTSEL_NON_DEFAULT_PLL_ROSC_CFG
// Description : Use ROSC for BOOTSEL mode. Note ROSC should not be used for USB
//               boot, but is sufficient for UART boot. Ignored if
//               ENABLE_BOOTSEL_NON_DEFAULT_PLL_XOSC_CFG is set.
//
//               Ensure that BOOTSEL_ROSC_DIV, BOOTSEL_ROSC_FREQA and
//               BOOTSEL_ROSC_FREQB are correctly programmed before setting this
//               bit.
#define OTP_DATA_BOOT_FLAGS_ENABLE_BOOTSEL_NON_DEFAULT_PLL_ROSC_CFG_BITS   _u(0x00000800)
// Field       : OTP_DATA_BOOT_FLAGS_ENABLE_BOOTSEL_NON_DEFAULT_PLL_XOSC_CFG
// Description : Enable loading of the non-default XOSC and PLL configuration
//               before entering BOOTSEL mode.
//
//               Ensure that BOOTSEL_XOSC_CFG and BOOTSEL_PLL_CFG are correctly
//               programmed before setting this bit.
//
//               If this bit is set, user software may use the contents of
//               BOOTSEL_PLL_CFG to calculated the expected ROSC frequency based
//               on the fixed USB boot frequency of 48 MHz.
#define OTP_DATA_BOOT_FLAGS_ENABLE_BOOTSEL_NON_DEFAULT_PLL_XOSC_CFG_BITS   _u(0x00000400)
// Field       : OTP_DATA_BOOT_FLAGS_ENABLE_BOOTSEL_LED
// Description : Enable bootloader activity LED. If set, bootsel_led_cfg is
//               assumed to be valid
#define OTP_DATA_BOOT_FLAGS_ENABLE_BOOTSEL_LED_BITS   _u(0x00000200)
// Field       : OTP_DATA_BOOT_FLAGS_ENABLE_BOOTSEL_UART_BOOT
// Description : None
#define OTP_DATA_BOOT_FLAGS_ENABLE_BOOTSEL_UART_BOOT_BITS   _u(0x00000100)
// Field       : OTP_DATA_BOOT_FLAGS_DISABLE_BOOTSEL_UART_BOOT
// Description : None
#define OTP_DATA_BOOT_FLAGS_DISABLE_BOOTSEL_UART_BOOT_BITS   _u(0x00000080)
// Field       : OTP_DATA_BOOT_FLAGS_DISABLE_BOOTSEL_USB_PICOBOOT_IFC
// Description : None
#define OTP_DATA_BOOT_FLAGS_DISABLE_BOOTSEL_USB_PICOBOOT_IFC_BITS   _u(0x00000040)
// Field       : OTP_DATA_BOOT_FLAGS_DISABLE_BOOTSEL_USB_MSD_IFC
// Description : None
#define OTP_DATA_BOOT_FLAGS_DISABLE_BOOTSEL_USB_MSD_IFC_BITS   _u(0x00000020)
// Field       : OTP_DATA_BOOT_FLAGS_DISABLE_WATCHDOG_SCRATCH
// Description : None
#define OTP_DATA_BOOT_FLAGS_DISABLE_WATCHDOG_SCRATCH_BITS   _u(0x00000010)
// Field       : OTP_DATA_BOOT_FLAGS_DISABLE_POWER_SCRATCH
// Description : None
#define OTP_DATA_BOOT_FLAGS_DISABLE_POWER_SCRATCH_BITS   _u(0x00000008)
// Field       : OTP_DATA_BOOT_FLAGS_ENABLE_OTP_BOOT
// Description : None
#define OTP_DATA_BOOT_FLAGS_ENABLE_OTP_BOOT_BITS   _u(0x00000004)
// Field       : OTP_DATA_BOOT_FLAGS_DISABLE_OTP_BOOT
// Description : None
#define OTP_DATA_BOOT_FLAGS_DISABLE_OTP_BOOT_BITS   _u(0x00000002)
// Field       : OTP_DATA_BOOT_FLAGS_DISABLE_FLASH_BOOT
// Description : None
#define OTP_DATA_BOOT_FLAGS_DISABLE_FLASH_BOOT_BITS   _u(0x00000001)
// Register    : OTP_DATA_BOOT_FLAGS_R1
// Description : Redundant copy of BOOT_FLAGS
#define OTP_DATA_BOOT_FLAGS_R1_BITS   _u(0x00ffffff)
// Register    : OTP_DATA_BOOT_FLAGS_R2
// Description : Redundant copy of BOOT_FLAGS
#define OTP_DATA_BOOT_FLAGS_R2_BITS   _u(0x00ffffff)
// =============================================================================
// Register    : OTP_DATA_FLASH_METADATA_MAX_SCAN_SIZE
// Description : Amount of flash to scan looking for partition table or image
//               metadata blocks (ECC) Enabled by the
//               OVERRIDE_FLASH_METADATA_MAX_SCAN_SIZE bit in BOOT_FLAGS, the
//               max number of bytes scanned is 512 * (value + 1).
//
//               Note that when scanning at the beginning of flash, rather than
//               in a partition, no more than the FLASH_PARTITION_SLOT_SIZE is
//               scanned.
#define OTP_DATA_FLASH_METADATA_MAX_SCAN_SIZE_BITS   _u(0x0000ffff)
// =============================================================================
// Register    : OTP_DATA_FLASH_PARTITION_SLOT_SIZE
// Description : Gap between partition table slot 0 and slot 1 at the start of
//               flash (the default size is 4096 bytes) (ECC) Enabled by the
//               OVERRIDE_FLASH_PARTITION_SLOT_SIZE bit in BOOT_FLAGS, the size
//               is 4096 * (value + 1)
#define OTP_DATA_FLASH_PARTITION_SLOT_SIZE_BITS   _u(0x0000ffff)
```

## Miscellaneous

We should test these as we support them:

* You can put both RISC-V and ARM IMAGE_DEF into the same blob/block loop (yay universal binary)
* You can sign a binary with multiple different keys (allows the same binary to be used on multiple devices perhaps)