# SUPERSEDED

This document is mostly superseded by the block format description in `../testing/BOOT_TESTING.md`. We still keep it around because it has some additional information on implementation details, but when these two files differ, this file is wrong.

# All about Amethyst Binaries, UF2 download, and bootrom execution of binaries

Note: Actually we should generally be keeping things valid for RP2040 SDK too;

**TODO** decide what this ^ means

## Existing (ELF / RP2040) Nomenclature

### ELF terms

- *virtual address* - the runtime address of code/data (note this corresponds to the `AT` in linker scripts, or is 
  just the physical address otherwise)
- *physical address* - where the data is loaded by the loader (note this corresponds to the > in linker scripts))

Now we don't actually have a loader, but we do have these which use physical addresses only.

1. gdb - i.e. when you load an ELF under the debugger
2. UF2 - `elf2uf2` will use the physical address to determine where the code/data should be loaded by nsboot.

What about virtual address != phyiscal_address on RP2040

* If virtual address == physical address then it doesn't matter.
* If virtual address != physical address then runtime startup (`crt0.S`) copies from flash to RAM at runtime (based on its own table)

### RP2040 Binary types

- **no_flash** - phys==virt & in SRAM
- **default** - mixture of phys==virt in flash, and phys!=virt for stuff to be copied to SRAM by crt0.S
- **copy_to_ram** - Nearly all phys!=virt (phys is in flash, virt is in SRAM)... stub copying code is phys==virt in 
  flash.
- **blocked_ram** - a variant of *default* which uses the blocked SRAM alias.

## RP2350

With *rolling windows* it is no longer a requirement for *physical address* to equal *storage address*. We can
have a binary stored at 0x10400000 in flash that at runtime appears at 0x10000000

But it is important to note that the actual storage address may never be known until the binary makes it to the 
device (e.g. because nsboot may choose which partition - and hence physical address - to store a UF2 on based on its contents)

### New nomenclature for our binaries

Now "physical" address is a bit confusing, and with our *rolling windows* it is not very precise.

- **storage address** - this is the physical SRAM or flash location that the data/code is stored by UF2 
  download or gdb. Note this may not be the same as ELF physical address because of *rolling windows* (see below)
- **runtime address** - this is the address when the application is running. In the case of flash resident runtime 
  code/data this may be "rolled" relative to the *storage address*. This is of course the ELF *virtual address*.

For runtime flash resident code/data, a fixed offset is needed to map between *storage address* and the *runtime 
address*. this is just the difference between the first *storage address* and its *runtime address*

Note these addresses are all from the point of view of the RP2350 system address map, i.e. the memory-mapped XIP region begins at `0x10000000`. The addresses going out on the wire on SPI are slightly different as they are only 24 bits in size (they are missing the leading `0x10...`).

### A note on rolling windows

RP2350 may have multiple flash applications. The *tired* way of dealing with this would be to recompile the binary with
different flash virtual/physical addresses, however this is a royal pain in the ass.

Instead, we can take the same binary, and store it anywhere (4k-aligned) in
flash, and the bootrom can reconfigure the *rolling windows* to map the flash
code/data back from the *storage address* to the *runtime address*

### UF2 wrinkles

On RP2040 (and arguably in general) the UF2 file specifies the *target address* for each UF2 block. 
For the existing `elf2uf2` uses the ELF *physical address* as the *target address*, which just happens to be the 
same as the *storage address*

This of course is broken if we are using *rolling windows*. In fact, the bootrom needs more information when 
receiving the UF2, as it cannot know what is meant by a block with a target address of `0x10040000`.

The piece of information it 
needs is the logical start of the flash code/data `FLASH_BASE` (defaults to `0x10000000`). 

In this case, if the UF2 is 
being 
written to a *partition* in flash starting at offset `P1_OFFSET`, then we write data for a block with *target 
address* of `0x10040000` at `P1_OFFSET + 0x10040000 - FLASH_BASE`.

In the case `P1_OFFSET` != `FLASH_BASE`, we have rolling windows in effect, and the difference (or absolute values) 
must be stored in additional metadata (see binary metadata section) so that the bootrom can know how to setup the 
rolling window correctly.

### A new type of binary

In RP2350 we would like to add a type of binary `packaged` (or some better name).

This will be read from flash (or somewhere else) to RAM by the bootrom.

Note that `packaged` is most useful for signed binaries where we would rather check the signature of a flash binary after
copying it to ram, vs in the flash (which could be maliciously changed later)

Note we think of this more as "packaging" rather than virtual/physical addresses, so we should

* use SRAM virtual/physical addresses in linker scripts
* use our tool to convert an SRAM elf to a packaged ELF (well really i guess it can take any ELF with all virtual 
  addresses in SRAM)
* the packaged ELF will 
  * have all the physical addresses updated to their flash location 
  * contain extra metadata indicating to the bootrom where to copy the various data/code (see *EXE header* below)
  * todo - need to double check this can be loaded and run by gdb

## Metadata requirements

Goal: We want to minimize the amount of effort required to annotate a user's binary
Result: We like to work on ELFs and add metadata as this is largely SDK/toolchain independent.

Goal: It should be possible to load an ELF file to flash via gdb, and boot into it
Result: This means that (particularly for flash) 
the metadata is in the *physical address* space of the ELF (i.e. it is LOAD/ALLOC)

Goal: A secure binary signature is stored in such metadata, and so the bootrom needs to be
able to quickly locate the metadata, ~~bearing in mind *XIP setup* has not been done.~~(obsolete as XIP setup is now done) 

Result: We will add features to mitigate scans for metadata (forwarding blocks below)

~~Goal: We must deal gracefully with cases where metadata is not present (a scan for metadata that is not there will 
be *very* slow)~~
~~Result: We will not require looking for metadata in the bootrom path in the case the bootrom does not know that it 
MUST be there. i.e. the non-secure boot path should not need to look for it.~~
~~**TODO** make sure this is the case,~~ (obsolete - metadata is now required, however we scan at most 2 * <4K before falling thru
to not flash boot path)) 

## Blocks

* Metadata is stored in *blocks* 
* *blocks* should be simpler to parse than binary info
* *blocks* should be recognisable by magic header/footer
* *blocks* may be embedded in source and thus included in the linked binary
* where possible *blocks* should have additional consistency checking
  - note that because of blocks embedded in the binary, this may be limited in some cases (more below)
* Blocks may be added by our `picobin` tool after regular link
* Metadata added to an ELF post-link appears somewhere in the *physical address* space of the binary
* Unclear if we support the following, but frankly I think it would be weird if we don't allow signing a UF2
  * Metadata added to a BIN post-link must go at the end (a BIN is a single linear piece of *physical address* space). 
    Note that a BIN however does not provide the needed origin of the *storage address* space where it should be 
    stored/ 
  * Metadata added to a UF2 post-link can again be added to the end of the *physical address* space.
    * todo maybe support side channel in UF2 with blocks (this is now on the feature bubble)
* All the blocks in the binary form a singly linked list
  * If the *current block* contains a pointer to the next block, then that is use
  * If there is no block pointer, the next block must be sequential in memory
  * If there is no block at the *next* location, then the list ends
* We will insert a block with a NULL forward link early in the binary. This is the first link in the list, and is 
  placed close to the start of the binary so the bootrom can find (and navigate) the block list without too much 
  scanning. Additional blocks can be addded post link by updating the forward pointer

### Block basics

* Blocks are word-aligned and an exact number of words
* A block is recognized by magic values at the start and end, and via internal consistency (sizes matching up etc., 
  use of parity where appropriate, including for example block item type ids)
* A block contains 1 or more (block) items.
* Each block item indicates its type and size (so items can be skipped without understanding them)
* The last block item must be of type `BLOCK_ITEM_NONE`. The size of this special item is actually the combined size 
  of all the items in the block excluding itself.
* blocks with special semantics may be recognized by the first block item. The only types of block with special 
  semantics today are **IMAGE_DEF** and **PARTITION_TABLE**. The **IMAGE_DEF** type of block is used to load and run the binary.
  We will support (in bootrom) running a binary based on (a copy of) this definition, and where it originated (e.g. where it was stored 
  in flash which may be pertinent). Note that an IMAGE_DEF is identified by having an `IMAGE_TYPE` item at the start
* Any unknown/irrelevant block types are ignored (except for looking for `BLOCK_ITEM_NEXT_OFFSET` items to build the 
  linked list`). Thus even tho the bootrom only cares about **IMAGE_DEF** and **PARTITION_TABLE**, other blocks can be embedded, and a future 
  updated **IMAGE_DEF** (with a different item type) could be defined later if we run out of bits in the current one  
* As a result of the copying, the block should not rely on its current location in flash/RAM to convey information, 
  or put another way, a block may be copied before being used (esp. for secure boot).
* Because of the use of a IMAGE_DEFs as a binary descriptor to launch a binary, we _might_ allow use of it 
  in a side channel in the UF2 to describe RAM binary launch settings, without having it mapped into the *storage* 
  address space

```
// === BLOCK ===

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

2 + s0 + s1 :  0x4 : 0xab123579 (MAGIC FOOTER) 
```

Note that I changed the size byte from 2 to either 1 or 2 in order to pack more info into single word items.

Obviously some blocks therefor MUST use 1 byte size (and that makes sense if they are 1 byte). BLOCK_ITEM_LAST must 
be 2 bytes, simply as it's easy to check for 0xff as the type. In general, I don't think it buts us much disallowing 
different sizes for other types, however we will indicate the suggested format (obviously you can't use a 2 byte 
size if it would overwrite some item data)

### Block Item types

#### NEXT_BLOCK_OFFSET

This allows for fast, forward scanning through blocks. This is the only block which is location aware; it is *not* 
useful/valid when a block has been copied.

We have two types which either store the delta, or two values which are subtracted to give the delta (since relocs 
may make this impossible in asm code)

```
.byte PICOBIN_BLOCK_ITEM_1BS_NEXT_BLOCK_OFFSET // item type with 1-byte size
.byte 0x2                                      // word size of this item
.byte 0                                        // padding
.byte 0                                        // 0 = use single relative value
.word offset_value                             // the offset value from this location
```
 or 

```
.byte PICOBIN_BLOCK_ITEM_1BS_NEXT_BLOCK_OFFSET // item type with 1-byte size
.byte 0x3                                      // word size of this item
.byte 0                                        // padding
.byte 1                                        // 1 = use two values to calcualte relative offset
.word .                                        // the address of this location (in some address space A)
.word __flash_binary_end                       // the address of the next block (in the same address space A)
```

Note that once we find the first block, we only follow immediately adjacent following blocks, or skipping via the 
`NEXT_BLOCK_OFFSET`. We stop when we don't land on a block.

*TODO*: decide whether we should add a flag to our first byte to indicate whether (and how) we should condintue scanning
if no block is found there. 

#### IMAGE_TYPE

Note that this item at the start of a block identifies an IMAGE_DEF. there is some space in the fields, however we
can extend

```
.byte PICOBIN_BLOCK_ITEM_1BS_IMAGE_TYPE  // item type with 1-byte size
.byte 0x1                              // word size of this item
.hword                                 // image type flags
```

Currently, we have: 

```

#define PICOBIN_IMAGE_TYPE_IMAGE_TYPE_MASK       0x000f
// note 0x0000 is reserved
#define PICOBIN_IMAGE_TYPE_IMAGE_TYPE_EXE        0x0001
#define PICOBIN_IMAGE_TYPE_IMAGE_TYPE_DATA       0x0002

// todo not 100% clear that we need thse for DATA, but some of them might make sense
#define PICOBIN_IMAGE_TYPE_SECURITY_MASK         0x0030
#define PICOBIN_IMAGE_TYPE_SECURITY_NS           0x0010
#define PICOBIN_IMAGE_TYPE_SECURITY_S            0x0020

#define PICOBIN_IMAGE_TYPE_PROCESSOR_MASK        0x00c0
#define PICOBIN_IMAGE_TYPE_PROCESSOR_ARM         0x0000
#define PICOBIN_IMAGE_TYPE_PROCESSOR_RISCV       0x0040

#define PICOBIN_IMAGE_TYPE_CHIP_MASK             0x0f00
#define PICOBIN_IMAGE_TYPE_CHIP_RP2040           0x0100
#define PICOBIN_IMAGE_TYPE_CHIP_RP2350           0x0200

// todo not sure this is super helpful
#define PICOBIN_IMAGE_TYPE_CHIP_REVISION         0xe000

```

Note that a 0 flag value is used to mean "an EXE you don't understand" and is used for future-proofing.

#### LOAD_MAP

Optional block with a similar representation to the ELF program header

i.e. a collection of *runtime address*, *physical address*, *size* and flags.

Note we are using *physical address* here not *storage address* as this data is written by a tool working on the 
ELF which may not 
This serves several purposes:

1. For a `packaged` binary, this tells the bootrom where to load the code
2. For a signed binary, the *runtime addresses* and *size*s indicate code/data that must be included in the hash 
   to be verified.

NOTE: `picotool` will need to be updated to understand the EXE header so it can translate addresses appropriately

```
.byte PICOBIN_BLOCK_ITEM_LOAD_MAP    // item type (1 or 2 byte size) 
.hword 1 + num_entries * 3                           // word size of this item
.byte num_entries                                    //
.word storage_address_rel                            // relative to the start of this load map item
.word runtime_address
.word size
```

#### VERSION

A major/minor version number for the binary, plus a list of OTP rows which can be read to determine the (thermometer-coded) minimum major version which this device will allow to be installed. The 32-bit minor version is always present, whereas the major version and OTP row list are included only if rollback protection is required. The major version is mainly useful in IMAGE_DEF blocks.

Each OTP row entry indicates the row number (0 through 4095 inclusive) of the first in a group of 3 OTP rows. The three OTP rows are read through the raw read alias, combined with a bitwise majority vote, and then the index of the most-significant `1` bit determines the version number. So, a single group of three rows can encode major versions from 0 to 24 inclusive, and each additional entry adds a further group of 3 rows which increases the maximum version by 24.

There is no requirement for different OTP row entries to be contiguous in OTP. They should not overlap, though the bootrom does not need to check this (the boot signing tool may).

For this entry to be considered valid, the maximum version supported by the indicated OTP rows must be *strictly greater than* the major version, i.e. there must be room to encode at least one more version in the allocated OTP space. This means that, with the list of OTP entries in this block item, it is always possible to determine that the device's minimum major version is greater than the major version indicated in this block, even if we don't know the full list of OTP rows used by later major versions.

If the number of OTP row entries is zero, we use the default six rows preallocated in page 0 (three each, starting at `DEFAULT_BOOT_VERSION0` and `DEFAULT_BOOT_VERSION1`). In this case major versions 0 through 47 are permitted: version 48 would require an additional OTP location.

The minor version is used to disambiguate which is newer out of two binaries with the same major version. For example, to select which A/B image to boot from. When no major version is specified, A/B comparisons will treat the major version as zero, but no rollback check will be performed.

The `tbyb` flag (try-before-you-buy) indicates this is not the active image, but is a candidate for a "try" operation which may subsequently be followed by a "buy". This flag is set by the signing tool *after* computing the image hash, so that attempting to boot the image normally will fail. A "try" boot will see this flag and clear it before computing the hash in the signature check, so it should compute the same hash as the signing tool and successfully verify the binary. The "buy" phase will clear the flag by reprogramming the sector containing the block, to make the image normally bootable.

```
.byte PICOBIN_BLOCK_ITEM_VERSION // item type
.hword 2 + (have_major + num_row_entries + 1) / 2
.byte {tbyb[0], have_major[0], num_otp_row_entries[5:0]}
.word minor
.hword major       // optional
.hword otp_row     // 0 or more
```

#### ROLLING_WINDOW_DELTA

Optional block that allow for binaries that aren't intended to be run at 0x10000000. Note that
this delta is in addition to the roll resulting from the binary being stored in a different
partition in flash.

```
.byte PICOBIN_BLOCK_ITEM_1BS_ROLLING_WINDOW_DELTA    // item type with 1-byte size
.byte 0x2                                            // word size of this item
.word 0                                              // pad
.word delta                                          // Where the first address belonging to the binary
                                                     // should end up at 0x10000000 + delta
```

TODO: have we defined what "first address is?"
TODO2: what happens if it isn't there, how else does a user specify it? (defaults to 0)
TODO3: is this relevant for packaged binaries; answer I think is no, because we would use the BLOCK_ITEM_LOAD_MAP

#### VECTOR_TABLE

Optional block with location of the vector table. for ARM binaries, the entry_point/initial_sp will be taken from here if present 
(unless there is an ENTRY POINT)

```
.byte PICOBIN_BLOCK_ITEM_VECTOR_TABLE  // item type
.byte 0x2                             // word size of this item
.byte 0                               // pad
.byte 0                               // pad 
.word vector_table                    // location (runtime address) 
```

#### ENTRY_POINT

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

#### HASH_DEF

Optional block woth information about what and how to hash

```
.byte PICOBIN_BLOCK_ITEM_1BS_HASH_DEF // item type (with one byte size)
.byte 0x2                         // word size of this item
.byte 0                           // pad
.byte PICOBIN_HASH_SHA256         // hash type
.hword . - scope_item             // unsigned offset to item defining scope within same block (current must be LOAD_MAP)
.hword block_words_hashed         // number of words of block (not including START marker) hashed; must include this 
block if used for a signature 
```

#### HASH_VALUE

Option block with hash result (for use when not using signature)

```
.byte PICOBIN_BLOCK_ITEM_HASH_VALUE // item type (with two byte size)
.hword 0x1 + n                    // word size of this item (note if the hash value is included, n > 0)
.byte 0                           // pad
.word [n]                         // hash value... which can be used for checking the binary is AOK           
```

Note tha everything in the scope is hashed along with everything in this block up until this hash item.

#### ITEM_SIGNATURE

Optional block with cyrptographic signature. If present, this **must** be the last item in the block, otherwise the block is invalid.

TODO: should we include sizes of keys, or have that implicit in sig type (which is probably better, as we only 
support one)
```
.byte PICOBIN_BLOCK_ITEM_SIGANTURE // item type 
.hword 0x21                        // word size of this item
.byte PICOBIN_SIGNATURE_SECP256K1  // signature type
.word [16]                          / public key
.word [16]                         // signature
```

## IMAGE_DEF block

This is a required block with BLOCK_ITEM_IMAGE_TYPE at the start

### Signed binary (Signed EXE block)

To sign a binary, you must include these items in the IMAGE_DEF block

* BLOCK_ITEM_LOAD_MAP (was optional before, but now needed to define scope of hashed contents) 
* BLOCK_ITEM_VERSION (Major/minor version, and a list of OTP thermo rows used to store the rollback watermark for the major version)
* BLOCK_ITEM_HASH_DEF (defines the hash type/scope) - this must come after items that need to be hashed
* BLOCK_ITEM_SIGNATURE (the signature) - this comes after hash_def, so it isn't included in it!

## Bootrom flash boot path

moved to PARTITION_TABLE.md

### ELF / UF2 / BIN

... notes about being able to do stuff to UF2 & BIN as well as ELF, but with some restrictions on what the address 
map might be.

## Other Open Questions

### thinking about packaging a RAM binary in flash

This is a bit obsolete:

I guess where this gets weird is that we're dealing with this in ELF terms;

TODO: Need to think more through prepending a 4K block on the beginning

Do we

1) Map that at 0xfffff000
2) Shift everthing else $K (sounds prefereable, but then the ELF strictly isn't loadable) - perhaps we only package 
   things to UF2/BIN as a solution?
