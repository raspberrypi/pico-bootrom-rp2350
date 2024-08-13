# open question

- runtime permissions

- FLASH BOOT (w/wo try before you buy)
- watchdog with raw PC/SP
- (watchdog) RAM BOOT with "ram address start for image_def search"
- (watchdog) RAM BOOT with actual IMAGE_DEF pointer

- OTP (which requires an IMAGE_DEF)

# new
- we now want to check supported architectures before attempting reboot
- we should get rid of embedded otp version (uf2 field)
- try before you buy always in A/B slots
  - we should allow try before you buy to invalidate the there slot so you can downgrade a non

- Note: we expect in non embedded EXE/PT that neither or both partition tables should be bootable; we don't
  therefore try the other
  - however for embedded IMAGE_DEF we will use the newer PT unless its binary is not bootable, in which case we try
    the other (which is good for non bricking)
- reminder: you never look for bootable partitions within a PT with its own IMAGE_DEF

- RAM UF2 will NOT have PTs
- we will add API to prepend/append "ephemeral" partitions (just the in memory representation) (or you edit it yourself)
- in memory partitions are mapped to physical partitions via (start of PT in flash which we know) then start/end address
- make sure we rechecked PT hash when we reload it

# Partition Tables

- IMAGE_DEF renamed to something else, and we support non EXECUTABLE **IMAGE_DEF**
- Both of these may be SDK if the raw bootrom one is to hokey
  - Expose pick A/B API? (this requires passing a buffer)
  - Expose check sign of IMAGE_DEF 
- anything not covered by partition table should not be accessible   
- lets put the unpartitioned space info in the partition table (which would make sense to be clipped)
- do we clip to partition sizes in OTP? yes
  - answers span the gap too

## Overview

Unlike RP2040 which has a single linear always user writable flash area and a single binary at the beginning, RP2350 adds permissioning, and allows partitioning of the space using a partition table.

* The partition tables divides the 32M flash address space into (possibly named and/oridentified) partitions with attributes 
* There can be one or two partition tables (to allow for flash partial write/failures). The (valid hash/opt sig) one with the latest version is "active"
* In the absence of a partition table, the bootrom will use a default partition a single partition with offset/size & attributes from OTP (or just default to everything is writable if OTP not present)
  * we already said we had two flash sizes, so we should use those here
  
* Permissions are read/write for S, NS, PICOBOOT
  * anything not covered if there is a partition table is secure only 
* Partitions may be linked into A/B pairs, wherein which partition is "active" (e.g. would be the one used for boot) is dependent on the IMAGE_DEF of the binary in that partition, and whether it can be used to boot (passes verification etc). 
  * Note side effect of this is that A/B does not make sense for non bootable partitions (i.e. you can't have A/B copies of WiFi firmware), as we don't know how to version them)
* UF2 download is targeted based on UF2 family (or sub-family TBD) id. graham: i think family ID is better, because it makes more tools usable 
  * Partitions indicate which family(es) they support storing from UF2. (Note this allows you to have more restrictive permissions for UF2 download for a partition than the actual PICOBOOT permissions) 
  * a partition may be marked as UF2 only, in which case it may overlap other partition, and is not used for anything other than UF2 download routing; It can be used to accept a UF2 family-id that overwrites multiple partitions (e.g. replaces everything)
  * In the case of A/B pairs, the download will target the version which would NOT boot (i.e. the inactive one)
  * We do also support the notion of a partition (e.g. NS one) that is grouped with a parent partition (e.g. its corresponding S partition). This is only useful in the case of A/B and allows targeting of the NS matching family-id to the right NS partition based on which of the parent A/B partitions is active. Targeting in this case can either be to the inactive or active version (e.g. you might want to drop a UF2 for the NS partition to be used with the active partition not to set up the NS partition for the inactive one)

## Use Case Recap

* Locating multiple possible binaries to boot (particularly A/B)
* Targeting UF2 downloads to the right area
  * Note this is not 100% foolproof, as we cannot stop people saying a UF2 is something it isn't via family ID, however you can make the secure area non UF2-able at least (and still allow NS)... in the simple use cases it will be helpful tho.
* Keeping data/embedded drives separate from main binary, and locating it/them
* Flash Permissions for bootrom APIs - note the information is NOT used by the bootrom to set up MPU regions, though the secure binary could do so
  * **todo** should we add an API to do so?

## Details

* Partition table is a block
* We can expect to find the partition table by looking for block lists starting at the beginning, of flash.
* Because we support two partition tables, we define two slots.
  * For PT "slot 0" it must be found in a chain of blocks starting within the first 1?K of the first flash sector
  * For PT "slot 1" it must be found in a chain of blocks starting within the first 1?K of the second flash sector
  * Note 1?K is something <= 4K
* A PT has
  * partition count
  * version (no thermo since downgrading a pt doesn't really mean anything)
  * permission for partition spanning access
  * hash (SHA-256)
  * optional signature
  * unordered partitions (well the order is important for searching, but does not have to match flash order)... also 
    we don't actaully validate that partitions don't overlap, the first one found wins.
* Each PT partition has:
   * 26: 4K aligned start/end 
   * 6: permissions
     * read/write for S, NS, PICOBOOT
   * 1: optional 64 bit id
   * 1: optional name
   * 2: 4: one of two types of optional link
     * link to (index of) A partition (this partition is a B partition) - flags are ignored (taken from A instead)
     * link to (index of) parent partition (this partition is in a group)
   * 3: flags
     * bootable
     * boot architecture (note this isn't strictly necessary, but can be used to restrict without actually looking for IMAGE_DEFs)
     * "partition only" for UF2 targetting (may overlap others)
   * 6: set of UF2 families that can be dropped
     * built in ones (ARM S, ARM NS, RISC-V, data, whole_flash) are bits in the flags
     * additionally zero/one actually family IDs (allowing user more targeting ability - e.g. give your WiFI firmware a different UF2 image, then you can drop it on)
   ```
  uint32_t start:13;
  uint32_t end:13;
  uint32_t permissions:6;
  
  uint32_t has_id:1;
  uint32_t uf2_absolute:1; // partition accepts direct data via UF2/picotool; may overlap other partitions
  uint32_t bootable_arm:1;
  uint32_t bootable_riscv:2;
  uint32_t link_type:2;
  uint32_t link:4;
  uint32_t accepts_default_families : 5
  uint32_t n_addition_fams : 3
  
  (uint64_t id) 
   ``` 
* A PT covers all 32M of flash; it is a linear address space, so it only makes sense to have a single partition spanning across the 16M boundary, if the whole of the first 16M is populated.
  * now with bounds checking, it is even more less senible.
* PT in memory for each partition has just start/end/permission/flags (now likely 64 bits), and a pointer to the PT in flash - if we need other fields (not needed for permission checks) we will reload the PT and verify hash (we just don't have space to store it in BOOTRAM).. 
  * because of memory constraints we will limit number of partitions to 16 (in RP2350)
  * note i'm thinking i'll only keep 64 bits of the SHA-256 in memory to save space..we use this to check the PT on 
    flash is the same as wgeb we loaded, but we only use that to get ids and names, so you can't subvert the permissions after the fact by managing to match 128 bits of the hash! 
* An IMAGE_DEF may appear in the same chain of blocks as the PT.
  * I say it this way around,as a PT in an arbitrary binary is irrelevant, it is only pertinent if the chain starts 
    in PT slot0/slot1 at the start of flash.
    * The very much most likely situation here, is that you just have a single binary packaged with its own partition table (simpler than laying down PT separately) in slot 0.
    * It is possible to have PT with binary in both slots (though likely in this case the binary is a bootloader and fits within the 4K). Note in this case the two binaries are NOT treated as A/B. we have two versions of the Partition table (each with one binary) and we will use the newest valid partition table.
    * in the case the IMAGE_DEF and PT are in the same chain (i.e. PT is likely embedded in the same UF2/binary downloaded, you can have an unsigned PT which is signed as part of the binary signature - this is fine for boot because it will be verified before the binary is run... it won't force the PT to be signed for UF2 permissions)

## Pseudocode

Note "x_" functions are restricted, in that they may not be called other than during flash boot or the beginning of flash UF2 download, as they may cause trashing of RAM

### Flash Boot

```
x_try_flash_boot() {
  for (range = 0:1024 to 3072:4096 step 1024) {
     for (flash_mode in ordered_flash_modes) {
        // 1. look in slot 0, and possibly slot 1 for PT and/or IMAGE_DEF
        // ------------------------------------------------------------
        // 
        // * if there is a returned active_pt, it will have been "verified" (hash + sig verified if present (and pt_sig_required))
        // * if there is a returned boot_image_def, it is one that is an IMAGE_DEF when there is no PT,
        //     or where the PT and IMAGE_DEF are in the same block list.
        //
        // note; that only potentially bootable IMAGE_DEFs are returned (RP2350, right CPU unless we support CPU switching, etc.), however they are not "verified"
        // for match of hash/sig 
        verified_active_pt = invalid
        possibly_verified_boot_image_def = invalid 
        found_valid_block_list = false
        
        s_arm6_crit_check_slots_01(current_cpu, range, &found_valid_block_list, &verified_active_pt, &possibly_verified_boot_image_def,   boot_block_list_image_def_chooser)

        // we enforce the pt signature requirement here if required, because we want to allow the image_def to sign 
        the pt, so must be able to accept unsigned PT above
        if (verified_active_pt && pt_sig_required && !has_signature(verified_active_pt)) {
            // we can use the image_def sig if we have an image_def, it passes signature, and the signature coveres the pt 
            // (note check_pt_covered_by_signed_image_def
            if (!possibly_verified_boot_image_def || 
                !x_verify_via_loading_map(possibly_verified_boot_image_def) ||
                !check_pt_covered_by_signed_image_def(verified_active_pt, possibly_verified_boot_image_def)) {
                return;
            }
        }
         
        // note not strictly always unverified, as we might have verified it in the PT is signed by IMAGE_DEF case above. 
        if (possibly_verified_boot_image_def) {
           // if not already verified, x_enter_exe will verify hash/sig/version/thermo during call
           x_enter_exe(possibly_verified_boot_image_def, verified_active_pt, stash_default_pt_on_null_pt = true);
           // if that returns, we're falling thru to ns boot
           return
        } else if (verified_active_pt) {
           // we look for the first bootable partition, including picking amongst A/B partitions based on which bootable IMAGE_DEF
           // has the highest version   
           for(partition in verified_active_pt) {
              // note inline_s_partition_is_marked_bootable, also checks !uf2_only/absolute partition flag which indicates the partition only refers to UF2 download)
              if (inline_s_partition_is_marked_bootable(partition, current_cpu) && !inline_s_is_b_partition(partition)) {
                 // because A/B check requires verifying hash/sig, we go ahead and load the load map
                 // comparator picks bootable image_def amongst A/B in a partition... if there is a load map, it is loaded
                 //   since we want to check hash/sig. version/thermo validity is also verified while loading load map
                 verified_boot_image_def = invalid
                 x_choose_image_def_with_verify_via_loading_map(current_cpu, partition, &verified_boot_image_def, boot_block_list_image_def_chooser, boot_ab_image_def_chooser)
                 if (verified_boot_image_def) {
                     x_enter_exe(verified_boot_image_def, verified_active_pt, stash_default_pt_on_null_pt = true);
                     // if that returns, we're falling thru to ns boot
                     return
                 }
              }
           }
        }
        // if we found a valid block list then are happily done searching flash modes, and will fall thru to ns boot
        if (found_valid_block_list) {
           return        
        }
     }
  }
}

// decide whether a new IMAGE_DEF found in a block list supercedes one found earlier in the same block list
boot_block_list_image_def_chooser(boot_cpu, image_def current_image_def, image_def new_image_def) {
  // ignore IMAGE_DEF with the wrong signature key 
  if (secure_boot && image_def->sig_key_hash != boot_signature_key_hash) {
    return current_image_def
  }
  bool correct_cpu = cpu(current_image_def) == boot_current_cpu
  if (swap_cpu_boot_supported) {
    // prefer correct CPU
    if (!correct_cpu && has_correct_cpu(current_image_def)) {
      return current_image_def
    }
  } else if (!correct_cpu) {
    return current_image_def
  }
  // first matching image_def wins.
  if (!current_image_def) {
    return new_image_def
  }
} 

// range is byte range in 4K sector to search
// verified_active_pt is out param, and will hold "invalid" or a verified valid partition table (hash + sig verified if present (and pt sig check required))
// possibly_verified_boot_image_def is out param, and will hold "invalid" or an unverified (valid for RP2350, but no hash/sig verification) image_def if one is in the same 
//                            block list as the active partition (or there is no partiton table)
// block_list_image_def_chooser is NULL if we don't care about IMAGE_DEFs 
s_arm6_crit_check_slots_01(boot_cpu, range, &verified_active_pt, &found_valid_block_list, &possibly_verified_boot_image_def, block_list_image_def_chooser) {    
    // At this point we do not know if there is a PT, and whether we are doing A/B binaries.
    // We look for (and follow if present) a block list starting in the first 4K (one sector) of flash (slot 0)
    // If we have A/B partition tables, the B table's of blocks would start in the second 4K sector (slot 1)
    
    verified_pt_slot0 = invalid
    unverified_image_def_slot0 = invalid
    block_list_slot0 = find_valid_block_list_starting_in(range)
    if (block_list_slot0) {
       for(block in block_list_slot0) {
          // pt must be valid (incl hash/(sig if present)) to be suitable 
          pt = verified_pt_from_block(block)
          if (pt) {
              verified_pt_slot0 = pt;
          } else if (boot_list_image_def_chooser) {
             image_def = valid_rp2350_image_def_from_block(block)
             if (image_def) {
                unverified_image_def_slot0 = block_list_image_def_chooser(image_def_slot0, image_def)
             }
          }
       }
    }
    
    block_list_slot1 = invalid
    verified_pt_slot_B = invalid
    unverified_image_def_slot_B = invalid
    
    // we need to decide whether to look for a PT in slot B
    //
    // - if we found a partition table in slot A and that is marked as a singleton partition table, then we respect that;
    //   user will have to overwrite it to switch to A/B (note that it is hashed, so bit error won't cause this)
    // - If we found a bootable image_def in slot A and no partition table then we assume no slot B.
    if (!(verified_pt_slot0 && is_singleton_pt(verified_pt_slot0)) && !unverified_image_def_slot_A) {
      block_list_slot1 = find_valid_block_list_starting_in(range + 4096)
      if (block_list_slot1) {
         for(block in block_list_slot1) {
            // pt must be valid (incl hash/(sig if present)) to be suitable
            pt = verified_pt_from_block(block)
            if (pt) {
                verified_pt_slot1 = pt;
            } else if (boot_list_image_def_chooser) {
               image_def = valid_rp2350_image_def_from_block(block)
               if (image_def) {
                  unverified_image_def_slot1 = block_list_image_def_chooser(image_def_slot0, image_def)
              }
            }
        }
    }
    
    found_valid_block_list = block_list_slot0 || block_list_slot1
    // pick the best partition table; obviously if either slot is invalid pick the other one.
    //
    // in the case both slots are valid, we pick the one with the highest version number.
    // (hash/signatures will already have been verified)
    verified_active_pt = higher_versioned_pt_of(pt_slot0, pt_slot1)
    un_verified_boot_image_def = verified_active_pt == verified_pt_slot0 ? unverified_image_def_slot0 : unverified_image_def_slot1;
}

// note block_list_image_def_chooser is now always boot_block_list_image_def_chooser, so may not need a parm
// similarly ab_image_def_chooser is always boot_ab_image_def_chooser 
x_choose_image_def_with_verify_via_loading_map(boot_cpu, partition_A, &boot_verified_image_def, block_list_image_def_chooser, ab_image_def_chooser) {
    boot_verified_image_def = invalid
    best_image_def_PA = invalid
    best_image_def_PB = invalid
    for (range = 0:1024 to 3072:4096 step 1024) {
       block_list = find_valid_block_list_starting_in(range + start_offset(partition_A))
       for(block in block_list) {
          image_def = valid_rp2350_image_def_from_block(block)
          if (image_def) {
             best_image_def_PA = block_list_image_def_chooser(boot_cpu, best_image_def_PA, image_def)
          }
       }
    }
    partition_B = b_partition_of(partition_A)
    if (partition_B) {
       for (range = 0:1024 to 3072:4096 step 1024) {
          block_list = find_valid_block_list_starting_in(range + start_offset(partition_B))
          for(block in block_list) {
             image_def = valid_rp2350_image_def_from_block(block)
             if (image_def) {
                best_image_def_PB = block_list_image_def_chooser(boot_cpu, best_image_def_PB, image_def)
             }
          }
       }
    }
    boot_partition = invalid
    if (best_image_def_PA && best_image_def_PB) {
       // we pick the newer based on the version numbers... however in secure boot
       // mode it is still possible we will fail to boot based on signature/hash.

       // todo note we are trying to save having to do two signature verifications... so
       // we believe the versions first, hoping that they are both validly signed. 
       // picking one with newest version (note we have version, and within that build version)
       best_image_def = pick(image_def_AB_comparartor(best_image_def_PA, best_image_def_PB);
       if (x_verify_via_loading_map(best_image_def)) {
          boot_verified_image_def = best_image_def 
          boot_partition = ...
       } else if (x_verify_via_loading_map(other_image_def)) {
          boot_verified_image_def = other_image_def 
          boot_partition = ...
       }
    } else {
       only_image_def = best_image_def_PA ? best_image_def_PA : best_image_def_PB;
       if (x_verify_via_loading_map(only_image_def) {
          boot_verified_image_def = only_def
          boot_partition = ...
       }
    }
    return boot_partition
}

x_verify_via_loading_map(image_def) {
  // save RAM writable state
  // make RAM writable
  
  // todo verify hash/sig if present
  // note: if bootram.try_before_you_buy is set we will copy
  // the image_def.version field to the "image_def.tried_version" field (if present)
  // before hashing/sig check.  
  
  // if validation fails, clear out everything we loaded
  if (RAM not writable, set it so again)
}

x_enter_exe(image_def, optional_pt, stash_default_pt_on_null_pt) {
   if (!image_def.verified) {
      if (!x_verify_via_loading_map(image_def)) {
         return;
      }
   }
   if (optional_pt) {
      stash_partition_table(optional_pt)
   } else if (stash_default_pt_on_null_pt) {
      stash_default_partition_table()
   }
   // todo use image_def to start exe
   // do reboot switch if enabled and for wrong architecture (note we shouldn't have an IMAGE_DEF for wrong arch if not supported, as it should have been filtered out
   //    in other pseudocode functions here .. worth double checking tho)
}

check_pt_covered_by_signed_image_def(pt, image_def) {
   for (entry in image_def.load_map) {
       if (pt.flash_start:pt.flash_end in entry.source_range) {
           if (!entry.copied_to_ram || pt == copy_of_pt_now_in_ram) {
              return true
           }
           break
       }  
   }
   return fasle
}
```
### Arbitrary load of PT from NS boot or other

```
s_load_partition_table(workspace, force_reload) {
  // todo note if PT is already loaded, and not force_reload then skip
  // if flash already set up, then skip the flash_mode loop 
  range_loop:
  for (range = 0:1024 to 3072:4096 step 1024) {
     mode_loop:
     for (flash_mode in ordered_flash_modes) {
        verified_active_pt = invalid
        bool found_valid_block_list = false;
        // NULLs as we dom't actually care about the IMAGE_DEF
        find_partition_table(range, &found_valid_block_list, &verified_active_pt, NULL, NULL)
        if (verified_active_pt) {
          store_partition_table(verified_active_pt)
          return;
        }
        // if we found a valid block list then are happily done searching flash modes, and will fall thru to next boot type
        if (found_valid_block_list) {
           break range_loop;
        }
      }
  }
  stash_default_partition_table()
}

stash_default_partition_table() {
  // todo store pt with single 32M partition, or single range/permissions from OTP
}

```
### UF2 download / nsboot

* ~~we should support optional "reboot" extension to indicate whether reboot should happen.~~ now in partition
* global (targeting absolute family) UF2s are absolutely addressed, all others are slot relative.

The following search order is used based on the family ID being downloaded, and the attributes (and accepted families of the partition)
1. look for target bootable (or owned by bootable) with current CPU
rational: you could keep some partitions unbootable (or switch boot flags over time)... makes most sense to apply data to bootable
2. look for target bootable (or owned by bootable) with other CPU (if allowed)
rational: if cpu swap is supported, then this makes things more consistent when nsboot may be using either CPU
3. look for unowned partitions
rational: top level partitions over owned partitions of non bootable
4. look for rest

```
  // this is secure code called by NS code
  // todo for comparator, because this helps decide what is the boot partition. i guess we go with what is running as the CPU
  s_load_partition_table(workarea, false)
  // find_target_partition will find a partition which is writable, which matches the family (and the filter if present)
  target_partition = x_find_target_partition(pt, current_cpu, allow_owend=true, bootable_filter=true, family_id)
  if (!target_partition && cpu_switch_allowed) 
     target_partition = x_find_target_partition(pt, !current_cpu, allow_owend=true, bootable_filter=true, family_id)
  if (!target_partition) 
     target_partition = x_find_target_partition(pt, ignore, allow_owend=false, bootable_filter=false, family_id)
  if (!target_partition) 
     target_partition = x_find_target_partition(pt, ignore, allow_owend=true, bootable_filter=false, family_id)
}

x_find_target_partition(pt, boot_cpu, allowed_owned, bootable_filter, family_id, min_version) {
    for(partition in pt) {
        if (nsboot_writable(partition) && accepts_family(partition, family_id)) {
           owner = owner_partition(partition);
           if (owner) {
              partition_A = owner
              if (!allowed_owned || (bootable_filter && !is_bootable(partition_A, boot_cpu))) {
                  continue
              }
           } else {
              partition_A = partition
           }
           if (inline_s_is_b_partition(partition_A)) continue; // duh
           target_partition = invalid
           verified_boot_image_def = invalid
           if (bootable_filter) {
             if (is_bootable(partition_A, boot_cpu)) {
               if (has_b_partition(partition_A)) {
                  // we want to see which one would be booted, and pick the other one
                  // **todo** this is the point at which we should note that we can do a "try before you buy"
                  boot_partition = x_choose_image_def_with_verify_via_loading_map(boot_cpu, partition_A, &boot_image_def, boot_block_list_image_def_choose, boot_ab_image_def_chooser)
                  if (boot_partition == partition_A) {
                      target_partition = b_partition(partition_A)
                  } else {
                      target_partition = partition_A
                  }
                  // note the verified_boot_image_def is the version of the latest bootable A/B, so the version is compared against that (not what
                  // was in the non-active partiton). this is actually what makes sense i think.
                  // **todo luke** do you think we should just ignore version in this case.. i.e. allow people to download older verions into other partition -
                  //               the reason they might do this is to do an allowed downgrade - do this first, then wipe the other partition.. but then again
                  //               that is a bit pants
               } else if (min_version) {
                  // if we are not doing A/B, but doing version check, then we must check the image_def - we can reuse the choose
                  // function as we already know check_partition doesn't have a B partition, so will only consider check_prtition
                  target_partition = partition_A
                  x_choose_image_def_with_verify_via_loading_map(boot_cpu, check_partition, &boot_image_def, boot_block_list_image_def_choose, boot_ab_image_def_chooser)
               }                            
             }
             if (min_version && boot_image_def && min_version < boot_image_def.version) {
                continue
             }
           } else {
              // no bootable filter, so anything matching is good (owned check is done above)
           }     
           if (owner)
               // if parttiion had an owner, then whether we are the target depends on whether the owner partition is active (or not)
               // depending on the owner_switched flag (note this test might be backwards - I will check when i implement)
               if ((owner == target_partitition) == is_owner_switched(partition)) {
                  return target_partition
               }
           } else {
               return target_partition
           }  
        }
    }
}
```

### let's think about RAM boot

Right now i'm suggesting you can include a PT, but let's decide for sure. pros/cons vs having one in flash, and does it make sense for one in RAM to supercede one in flash

```
 possibly_verified_boot_image_def = invalid
 block_list = find_valid_block_list_starting_in(ram_binary_range)
 if (block_list) {
   for(block in block_list) {
       image_def = valid_rp2350_image_def_from_block(block)
       if (image_def) {
          possibly_verified_boot_image_def = boot_block_list_image_def_chooser(current_cpu, possibly_verified_boot_image_def, image_def)
       }
   }
 }
 if (possibly_verified_boot_image_def) {
    x_enter_exe(possibly_verified_boot_image_def, stash_default_pt_on_null_pt=false)
 }
 // nothing valid to boot - todo should we fall thru to NS boot like flash boot - seems plausible
 return
```

### "try-before-you-buy" flash reboot

"try before you buy" is implemented in a simple way. The IMAGE_DEF as downloaded contains both the regular version field (set to 0) and a tried_version field
set to the correct version. As written, therefore this won't boot as the version is incorrect for hash, and or low. There is a flag in the watchdog reboot
when rebooting from UF2 download (or picotool) which enables "try before you buy"... if this is set, then the tried_version will be copied into the version
field in memory before checking the hash/sig and/or doing version compares.

UPDATE: it actually needs to pick the try version over the other one even ignoring version order. this allows for permissible downgrades - note "buy" will have to trash the other partition

UPDATE: try before you buy should indicate which partition was written. on (next) reboot we treat said partition 
specially and try to use it in preference to another. 

The boot process will note the flash location, and version number that needed to be fixed, and will use that to "commit" the upgrade in an API later (note, that
will require a 4K work area provided by the user) **todo** luke are we willing to try for updating flash without 
erase? - no
**todo** should/could we force a reboot on commit, in which case we can do it without the buffer

This is a slight variation from what we talked about, as the pre-reboot code does not scan for the IMAGE_DEF.

**todo** um, what about debugger... in this case you are likely loading binary at beginning of flash - you don't have A/B partitions, so unless you have hashed and signed the binary you are fine. **todo** what do we do with debugger and secure binaries anyway.

Question: what is the correct behavior when putting a "try before you buy" in a non A/B partition.
* writing it as is, is not terrible... if it doesn't commit itself after the reboot, then the partition will be non bootable meaing you fall thru to nsboot, or another partition if there is one 
* ~~alternative would be to always copy tried_version to version if booting from a non A/B partition~~

UPDATE: try before you buy for partition tables, takes entering the image to mean success.
~~try before you buy for partitions does not support version downgrade~~
note when using partition tables you must do TBYB on the pt NOT the image.. I had considered making the image_def/pt combo image_def based, including picking amongst two pts with image_def rules, but this makes it impossible to switch from image+pt to pt only, as the image_def would surely win against no image_def

Note: Liam suggeste, and it makes sense that we allow for a watchdog timeout in "try before you buy" - I suggest we just always set this to the maximum watchdog timeout.


## picotool

* Add a "get_partition_table" request
* raw read/write should use permissions
* what about loading a binary though? how do we decide the partition **todo luke** thoughts
  1. do the hard work ourselves in picotool. this is painful as we may not have access to the partitions required to make the decision
  2. add a request to pick
  3. send it as a UF2 (family id) *ding ding*
     1. benefit of sending UF2 blocks is that we can likely reuse ALL existing code.
     2. if we can it could half the size if the code path is amenable.
* read/write flash
  * this will use the picoboot permissions, so fine
* reboot
  * reboot into nsboot 
  * normal reboot
  * normal reboot with "try before you buy"
  
## Edge cases / Restrictions

- For multiple IMAGE_DEFs in the same binary, we do not do a full "WHAT IF" to choose between them; we pick the best looking one (right CPU, (right key and) signature if required)
- If you have A/B main binaries, with owned sub partitions, then it is your responsibility to have them self-consistent
- If your main A/B partition choice is dependent on the boot architecture, then your drag drop is going to be similarly affected
- If you have A/B partitions, then you must update the version number, or the newest may not be picked (or rather the newest is arbitrary)

### Wacko scenarios

Just to think about pathological cases

#### lots of partitions

```
0 PT
1 (ARM) A F(ARM)
2->1 DATA F(DATA)
3 BOOTABLE(ARM) A F(ARM)
4 BOOTABLE(ARM) B F(ARM)
5->3 NS A F(ARM_NS)
6->4 NS B F(ARM_NS)
7->3 DATA A F(DATA)
8->4 DATA B F(DATA)
9 BOOTABLE(RISCV) A F(RISCV)
10 BOOTABLE(RISCV) B F(RISCV)
11->9 DATA A F(DATA)
12->10 DATA B F(DATA)
13 DATA F(DATA) // probably want to give this its own family
```

In the above case downing DATA will depend on the current CPU of the chip, since DATA will end up in 7,8, 11, 12


-----------------------------------------

## Some older stuff (may be answered above, but may jog thoughts)

### Questions

* What about no partition table and permissions
  * It's easy enough to make an OTP default for NS & boot permissions read/write
  * I guess this also makes sense because not having a PT is valid (you might want to allow picoboot read, but not write)
  * I was worried about ppl attacking by just removing the PT, but if they can do that they can liklely read/write flash anyway. still probably good as an extra level of security
new summary duerhwe soqn

### Notes

* If there isn't a standalone partition table, then there can only be one binary?
  * you could have the embedded partition table refer to a spot for binary B, but it would mean tha you could trash the partition table (you wouldn't have two copies) when overwriting binary A. Therefore we don't want to support that.
* Partition table is loaded by
  * Flash boot
  * nsboot (so we know what we're allowed to touch)
  * lazily, if queried)

### Scenarios/Questions

* We cannot prove that a binary is what it says it is when downloading UF2; therefore this is not great for "secure boot", unless you have A/B
  * what should you use with secure boot to download NS binary (ah, well you'd disable access to writing secure area altogether in the partition table)
* If we allow a partition table in a binary then it is not easy to edit (well the binary can keep it 4K aligned)
* ~~If we respect partition tables in binaries, what do we do with A/B~~
  * ~~Answer: we don't; the partition tables are separately versioned, however the only time it could possibly matter is if you have two partition table boot loaders (with embedded binaries)~~
  * question is obsolete because we only time we never have A/B binaries with A/B partitions; if you have A/B partitions each with binary, then you pick the latest 
* ~~If we have partition tables in binaries, what does that mean for launching RAM ones?~~ we imitialize if present
* If we have a single embedded partition table and we launch from debugger, what does that mean?
  * think this is ok, as we always go thru boot path
* If single, can binary sign PT?: answer, yes
* Signed partition tables
  * Why would you sign? if you have flash access already, then it doesn't help much.
    * maybe param
  * Regular boot path
  * single binary
* What are default PT permissions in secure boot (are they different from regular)? **todo** do we expect people to lock things down independently (I think so)
