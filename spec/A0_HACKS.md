# A0 HACKS

## RAM OTP Override

To enable:

```
0x401000cc: powman_scratch[7] = 0x755e6dec
set *(uint32_t *)0x401000cc = 0x755e6dec
```

* Override for _OTP offset_ (i.e. 2 bytes per location) `N` is at 4-byte word `0x2007c000 + N * 2`
* Override word is top bit set, and a 24 bit raw value (so you need to put ECC bits in for an ECC location)

e.g. to set secure boot enable in the first of the RBIT-8 replicas of CRIT1: 

```
// Register    : OTP_DATA_CRIT1
// Description : Page 1 critical boot flags (RBIT-8)
#define OTP_DATA_CRIT1_OFFSET _u(0x00000080)
#define OTP_DATA_CRIT1_SECURE_BOOT_ENABLE_BITS   _u(0x00000001)

*(uint32_t*)(0x2007c000 + OTP_DATA_CRIT1_OFFSET * 2) = 0x80000000 | OTP_DATA_CRIT1_SECURE_BOOT_ENABLE_BITS;

```

NOTE: the RAM OTP overrides obviously have no effect on the h/w reading of critical bits

## RAM boot

Jump targets can be set for either/both of ARM and RISC-V and the branch is taken before any other bootrom code is run.

### ARM

To enable:
```
0x401000c0: powman_scratch[4] = jump target
0x401000c4: powman_scratch[5] & 0xffff = 0x9b0d // low half
```
### RISC-V
To enable:

```
0x401000c4: powman_scratch[5] & 0xffff0000 = 0x27eb0000 // high half
0x401000c8: powman_scratch[6] = jump target
```

## Rolling Window Hack

We do not have an MBR (master boot record) i.e. partition support in the A0 bootrom; we can however load a binary 
from somewhere other than the start of flash (and roll the window back to 0x10000000)...

To do this, write the following to the start of flash, along with enabling 
`OTP_DATA_BOOT_TEMP_CHICKEN_BIT_OPT_IN_PARTITION_FORWARDING_HACK_BITS = 0x00000400` at OTP offset
`0x102`, `0x104` (and if you like `0x106`)

```
0x10000000 : 0x12348765
0x10000004 : partition offset in bytes from 0x10000000
0x10000009 : partition size in bytes
0x1000000c : 0xabcd1234
```

Note offset and size must both be multiples of 4K

