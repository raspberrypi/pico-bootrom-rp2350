# Boot Concepts

* **region** - term for a contiguous range of physical address space. (this is currently called 'window' in the 
  boot code, which is confusing w.r.t. "rolling windows", so I will rename it)

* **block loop** - an extensible machine-readable metadata made from a linked loop of blocks. A region has a _valid_ 
  block 
  loop if a first __structurally valid_ block is found near the start of the region ('near' defined later), 
  and the link at the end of each *block* forms a loop thru any additional _structurally valid_ blocks back 
  to the first block.
  
  _Purpose:_ a block loop assigns semantic meaning(s) to the contents of a region**. A _valid_ block loop
  is unlikely to appear in random data. 

* **block** - a self-contained piece of metadata found in a block loop. The block contains a sequence of 
  block items. And a link to the next block (or itself if it is the only block in a block loop).
  
  A block can be determined to be _structurally valid_ by its magic header, footer, and that the sizes of each 
  individual **block items** sums to the size of the block. This determination can be made without understanding 
  the individual block items in the block.

  A block has a type which is determined by the first **block item** in the block

  _Purpose_: to encapsulate a single meaningful piece of meta-data. Having multiple blocks allows for including 
  difference types of block in the block loop, or indeed multiple blocks of the same type. 

  **NOTE:** the only types of block defined for the boot rom are **partition_table* and **image_defs**. Each of these 
  can contain optionally contain versioning information, hash and/or crypto signature.

* **block item** - a constituent piece of information within a block. 

  _Purpose_: Splitting a block into block items allows certain pieces of information to be optional, and also allows
  parsing of blocks with items that are not understood by the reader (they may have been added since the parsing 
  code was written)

* **partition_table** - a block type which provides sub-division information for the 32M flash address space 
  into non-overlapping regions (**partitions**).
  * Each **partition** provides read/write permissions for S(ecure), NS(Non-secure) and PICOBOOT access
  * Each **partition** provides info to help identify where a particular UF2 should be dropped (very often they will be 
    dropped into a single partition)
  
  _Purpose_: Needed if you want to be able to specify different permissions for different areas of flash, or if you 
  want more than one **image** in flash.

  **NOTE**: use of partition_tables is optional. In the absence of a partition_table there is a single **binary** in 
  flash.

* **image_def** - a block type which provides information about how to interpret and/or excecute the contents of a 
  region (**binary**)
  
  _Purpose_: Most commonly these describe how to interpret the contents **binary** as something that can be loaded 
  (if needed) and executed, however the versioning and or hash/sig may be useful for other stuff (e.g. 
  wifi-firmware, other resources)

* **binary** - loose term for a single program or piece of data that is described by one or more image_def. You can 
  have a single binary if there is no partition_table, or a binary in each partition (and potentially **slot**)

* **boot region** - a region in RAM, XIP cache (`0x1200_0000`->`0x1400_0000`), or the first flash 
  (`0x1000_000`->`0x1100_0000` / wherever the first flash ends). This the only region that can be booted from (if it 
  contains an acceptable image-def)

  **NOTE** the only _flash_ boot regions we care about are a partition, or the entirety of the first flash (when we 
  don't have, or havent yet found, a partition table)

* **slot** - a 4K region at or near the start of flash where we look for the start of block loops. There are two slots:
  * slot 0 - the first 4K of flash
  * slot 1 - the 4K of flash either 4K into flash (the default) or further if specified in OTP

  _Purpose_: having two slots gives us two possible places to start block loops containing a partition_table, i.e. 
  it allows us to have two partition_tables (which is useful when updating partition_tables to not brick a device)

  **NOTE**: you will obviously notice that whatever starts in slot 0 may overwrite slot 1. In that case, we 
  only deem flash to have a single slot (slot 0)

* **version** - a partition_table or binary may include a VERSION. The version serves three purposes:
  1. to choose which of two valid partition tables to use if both slot 0 and slot 1 have one.
  2. to choose which of two valid binaries to use if both partiton A and partition B have one.
  3. to prevent rollback of binaries on a secure chip past a certain point. 

  In either case the higher versioned one is used.

  The version is of the form `(RRRR).MMMM.mmmm` (hex digits):
  * `MMMM.mmmm` are the major/minor version 
  * The `RRRR` is the rollback version is optional and is ignored except when booting in secure mode (it is useless 
    without signing of the binary). If present, it is accompanied by OTP locations where a persistent rollback
    version is to be stored. It is not possible 
  
* **"flash update" boot and "try before you buy" (TBYB)**

  "flash update" boot is a special type of flash boot which is entered via watchdog, and has an "update" address as a 
  parameter. This flash address is the address of the start of the slot or partition that has just been written. 
  This is for example used when you drag and drop a UF2.

  The purpose of this type of boot is to allow version downgrades when there is a choice of slot 0/1, or 
  partition A/B, and to support **try before you buy**. In other cases the "flash update" boot is the same as a 
  regular flash boot.

  1. Normally given valid partition tables in slot 0/1 or valid image_defs in a pair of partitions A/B, the partition 
  table or image_def with the highest version will be used. If the "update" address is the start of the newly 
     written slot or partition, then that slot/partition will be used for booting EVEN IF it has a lower version. 
     Additionally on "success" the first 4K of the other slot/partition will be erased if it had a higher version, 
     so that subsequent normal flash boots will use the updated slot/partition too
  2. Additionally, an executable IMAGE_DEF can marked as try before you buy (TBYB). Such a marked IMAGE_DEF is not 
     chosen on a normal boot (it is deemed to be bad), however when pointed at by the "flash update" boot, it will 
     be booted ("try"), and the executable can then call into the bootrom to mark itself good ("buy)". This 
     mechanism allows you to write a new executable to an A/B partition and defer the "commit" until the executable 
     has successfully run and decided it is happy. Note that the bootrom clears the flag by rewriting flash when the 
     executable calls back for the "buy".

  NOTE: re: "success" in 1.

  i. a "slot" is deemed to be successful for a "flash update" boot, if a bootable IMAGE is found having chosen that 
  slot (i.e. we get as far as entering an image")
  ii. a "partition" is deemed to be successful for a "flash udpate" boot, if a bootable IMAGE is found in the 
  partition during the "flash update" boot. Note the partition does have to be found by the boot process for this to 
  happen (i.e. if it is further down the boot path than another partition which is bootable, then the flash update 
  boot does nothing (i.e. other boot options are not ignored (other than the other partition of the A/B pair)

  You might wonder how you can deal with partial write failures etc, when writing say partition tables, or images 
  without TBYB, and the answer is of course to hash them.