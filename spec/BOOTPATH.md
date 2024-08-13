# Boot Path

## Scenarios

1. **Normal powman reset** - Core 0 and core 1 are both reset; core 1 remains in "holding" (using no mutable memory) 
   until it is awakened.

2. **Only core 0 is reset** - This might be core 1 debugging core 0, however it is important to realize that core 1 
   may be using resources, so we need to be careful what core 0 touches!

TODO: list/think tru all the possible scenarios (powman/watchdog resets etc.)

## Phases

There are several phases of the boot code (and post boot), which are specifically mentioned because various memory 
resources are shared differently in different phases

### preboot

This is the main initialization code before either entering nsboot or a binary

#### flashboot-setup

This is optional, and a subset of preboot as it can return (if no valid image is found).

### nsboot

This is optional, does not return, and is responsible for **PICOBOOT**, **USB MSD** and **UART Boot**

Note: this code is non-secure, with limited permissions to reduce attack surface so; on ARM it must 
call back via SG into secure code to perform various operations with elevated permissions

NOTE: we also reset core 1 at this point, and determine that **nsboot** is the ONLY thing running (this allows us to 
use more resources)

### postboot

This is the state when user code is running

## ARM vs RISC-V

To save space, the boot path is **arm6** code and runs under **varmulet**. **"arm6"** refers to code that is generally 
using ARMV6M instructions only, though may include RCP instructions, SG instructions, and (unused by ARM on M33) 16 
bit HINT instructions.

The RCP instructions are used to harden the **arm6** code as it is part of the _secure boot path_.

The RCP instructions are igonred by **varmulet** except for `mrc p7, #1, r15, c0, c0, #0` which is used to check 
the status of the RCP, and the **varmulet** code sets N (salt initialized - because we don't need to initialize it) 
and V 
(running under **varmulet**). 

SG instructions are only available in **varmulet** during **nsboot** and perform the same purpose under NS ARM and RISC 
V (calling into a single SG handler). In previous bootrom versions the SG was handled by a native switch code on 
both ARM, and RISC-V. Now it is a function table in both... the ARM one points at ARM secure code; the ARM6 one 
points at non secure ARM versions (i.e. SG varmulet stuff just redirects to more ARM varmulet code)

HINT instructions (with hint number 6-15) are used at the *very* beginning of **arm6** functions to indicate that the 
native 
RISCV-V code should be run instead. the hint number indicates what native code to run, and after completion an ARM 
"bx lr" is emulated to return out of the **arm6** function. Real ARM execution obviously ignores the hint, and 
continues to the **arm6** implementation of the function. Because the number of hints is limited, one hint 
HINT_MULTIPLEX is used with the function to call in ARM r3 (this is currently only used for nsboot calls into 
nsboot specific RISC-V code)

## Memory / Stack Usage

### BOOTRAM 
`BOOTRAM` is 256 words, and is generally split:

```
SIZE : USE 
64   : misc    \      
64   : core0    | phase specific 
64   : core1   /   
64   : always            
```

**always** is used for "secure on behalf of non-secure caller" permissions which make sense at all times (e.g. what 
part of flash NS code can write to), and of course core 1 still may need the permissions in place. TODO do we ever 
need to have different permissions for the two cores? 

Core 1 may be running duing **preboot** (and **flashboot-setup**), so during these phases it is not used by core 0 
(note that 
whilst this core 1 space belongs to the bootrom, it may be being used for **varmulet** state on behalf of varmulet-ed 
RISC-V bootrom functions)

The full 192 bytes are available to/used by **nsboot** as core 1 is reset.

**postboot** the first 64 words are used for a copy of the **XIP Setup** code

### USB RAM

This is a resource not strictly owned by the bootrom.

It is used for USB (obviously) along with runtime state under **nsboot**. This is so **nsboot** does not use any of 
MAIN RAM / XIP CACHE for the majority its state (it needs to be able to load a RAM binary covering all of it), and 
it needs more space than is available in **BOOTRAM**

### MAIN RAM / XIP CACHE

The bootrom does not use any of these until either an executable needs to be copied there or started, or **nsboot**. 

Up until then, access is disabled via **accessctrl** for security.

Note it is cleared in secure boot paths

## Varmulet and stacks

This obviously refers to RISC-V only.

### preboot
The stack is 125 words (same as secure ARM boot). Because we have no IRQs at this point, it is safe (and better than 
fixed partitioning) to let the native code called from **varmulet** use the same stack (since the native code is 
synchronous and returns).

### nsboot

Because **nsboot** uses native IRQs and nested calls arm6->riscv->arm6->riscv etc it is simpler to keep the RISC-V 
stack and the **arm6**(emulated) stack  separate. (Otherwise we have to bloat/slow down **varmulet** code and have 
it keep SP up to date, and other reasons- TODO: full accounting of this)

**nsbboot** on ARM already uses the end of **USB RAM** for the **arm6** stack, so we do the same, and keep a fresh 
(on entering **nsboot**) stack for RISC-V code in **BOOTRAM**.

### postboot

core0 and core1 areas are used for _small_ stacks for when **varmulet** is used to implement RISC-V bootrom functions 
(emulating the **arm6** code).

