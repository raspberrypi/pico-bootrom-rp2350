# Bootrom fuzzing / security

## Introduction

Our primary bootrom security goal is that when booting in secure mode, we can **only** execute correctly signed binary.

1. We would like to simulate hardware attacks 
2. We would like to catch data dependent (and of course other) code bugs before we freeze the code
3. We do have RCP based mitigations, so we would also like to do some static analysis, to make sure they are used everywhere they should be. Indeed, static analysis should also check the code for other stuff (e.g. no SG in the wrong place).
4. Possibly some dynamic flow (under simulation) checks

A few months back, after reading two posts in a week about using `afl-unicorn` in secure attack locating/prevention, I decided to try to  

### Hardware attacks

We would like to simulate

* Skipped instructions
* Mutated instructions
* Exhaustive branches from instruction A to instruction B (perhaps)

We need to be able to detect:

* Unexpected peripheral access
* Execution of non-bootrom code in secure mode other than the correct secure binary
* RCP panics (this is an ok result)
* hard-fault (this is an ok result)

### Data dependencies

We are dependent on OTP data and flash data in the boot path. We would like
(along with our regular testing described in [BOOT_TESTING](BOOT_TESTING.md)).

We can use fuzzing of this data, to make sure that invalid data cannot cause
violation of our security.

### Static Analysis

"Static analysis" may just be a python script over the .DIS file(s)... alternatively we might use "Dynamic Analysis" under sim to catch some of these
We want to check (TODO not complete):

* RCP instructions get inlined, even after LTO
* All s_ functions have canary 
* We are using random delay RCP instructions where appropriate (i.e. in crit boot path)

### Dynamic flow

We can check certain things while we simulate:

* There are no functions in secure boot path that aren't "s_crit"
* Code coverage (64K bools!)
* Hot spots (64K counters!) - possible we might want to check perf under RISC-V and maybe nativize.

## Existing Work

As of right now we have some support for running bootrom using `afl-unicorn`
([blog part-1](https://medium.com/hackernoon/afl-unicorn-fuzzing-arbitrary-binary-code-563ca28936bf), 
[blog part-2](https://medium.com/hackernoon/afl-unicorn-part-2-fuzzing-the-unfuzzable-bea8de3540a5),
[github](https://github.com/Battelle/afl-unicorn))

I have made a single gigantic test driver, which allows simulating through the bootrom (works as far as enterinng flash binary, or nsboot)

* This sample has some commented-out code in it for skipping instructions... it would also be simple to perform mutation of instructions or data.
* It supports loading for flash image, and has an OTP array, so could load that too
* It is almost exactly what you want for a driver for AFL fuzzing, perhaps with some tweaks to make each run a bit quicker.
* I imagine it is probably best to factor out all the h/w simulation stuff in the driver into a library, which can be used by multiple drivers (the unicorn hooks you use for different tests might be different, so probably belong in diffect driver C files)

See the sections a bit below for how to install/run

## Other Possibilites

[ARMORY](https://github.com/emsec/arm-fault-simulator) has been suggested as a possibility for simulated hardware attacks

## Setup instructions:

Note for simplicity of my POC, I just forked unicorn, and added my sample in tree. I don't think it is worth fixing that up, though you could.

```bash
git clone https://asic-git.pitowers.org/amethyst/unicorn
cd unicorn
git submodule update --init
mkdir build
cd build
cmake -DPICO_SDK_PATH=/path/to/amy-sdk ..
make -j12 sample_bootrom
```

## Running

```bash
./sample_bootrom <combined_bootrom_bin> (<flash_bin>)
```

e.g. (without flash image), we run as far as the start of NS boot.

```bash
./sample_bootrom bootrom-combined.bin 
Bootrom go now!!
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
ENTERING NSBOOT, stopping for now
>>> Emulation done (568435 instructions) in 216366us. Below is the CPU context
>>> 2.627Mhz
>>> R0 = 00004100 R4 = 00004000  R8 = 00000021 R12 = 951890c0
>>> R1 = 400e02f8 R5 = 00000000  R9 = c1c4f8df  SP = 50101000
>>> R2 = 50101000 R6 = 00000000 R10 = e0010409  LR = 0000035d
>>> R3 = fffffffe R7 = 40120000 R11 = 0c06f10c  PC = 00004100
>>> MSP = 50101000 PSP = 00000000
>>> XPSR = a1000000 sec=0 priv=1
```

with a flash image, we stop after 1,000,000 instructions (with the error about possibly looping), which in this case is true... we're in runtime_init(), and it's waiting for some hardware to come out of reset which isn't handled properly in our sample. this is fine though, as we only care about getting as far as booting the binary.

```bash
./sample_bootrom bootrom-combined.bin serial/hello_serial.bin
Bootrom go now!!
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
returning bootsel_pressed = false
instruction 999994

0x10002086:	bics		r3, r2
****************
>>> R0 = 00000000 R4 = 100002e0  R8 = 10000269 R12 = 00000002
>>> R1 = 10002071 R5 = 00000003  R9 = 20082000  SP = 20081ff0
>>> R2 = efef3b7f R6 = 00000003 R10 = 00000000  LR = 10000299
>>> R3 = 0010c480 R7 = 10000100 R11 = 0c06f10c  PC = 10002088
>>> MSP = 20081ff0 PSP = 00000000 MSP_NS = 00000000 PSP_NS = 00000000
>>> XPSR = 21000000 sec=1 priv=1
instruction 999995

0x10002088:	bne		#0x10002080
****************
>>> R0 = 00000000 R4 = 100002e0  R8 = 10000269 R12 = 00000002
>>> R1 = 10002071 R5 = 00000003  R9 = 20082000  SP = 20081ff0
>>> R2 = efef3b7f R6 = 00000003 R10 = 00000000  LR = 10000299
>>> R3 = 0010c480 R7 = 10000100 R11 = 0c06f10c  PC = 10002080
>>> MSP = 20081ff0 PSP = 00000000 MSP_NS = 00000000 PSP_NS = 00000000
>>> XPSR = 21000000 sec=1 priv=1
instruction 999996

0x10002080:	ldr		r3, [pc, #0xcc]
****************
>>> R0 = 00000000 R4 = 100002e0  R8 = 10000269 R12 = 8aa2b9b0
>>> R1 = 10002071 R5 = 00000003  R9 = 20082000  SP = 20081ff0
>>> R2 = efef3b7f R6 = 00000003 R10 = 00000000  LR = 10000299
>>> R3 = 40020000 R7 = 10000100 R11 = 0c06f10c  PC = 10002082
>>> MSP = 20081ff0 PSP = 00000000 MSP_NS = 00000000 PSP_NS = 00000000
>>> XPSR = 21000000 sec=1 priv=1
instruction 999997

0x10002082:	ldr		r2, [r3, #8]
****************
>>> R0 = 00000000 R4 = 100002e0  R8 = 10000269 R12 = 8aa2b9b0
>>> R1 = 10002071 R5 = 00000003  R9 = 20082000  SP = 20081ff0
>>> R2 = efef3b7f R6 = 00000003 R10 = 00000000  LR = 10000299
>>> R3 = 40020000 R7 = 10000100 R11 = 0c06f10c  PC = 10002084
>>> MSP = 20081ff0 PSP = 00000000 MSP_NS = 00000000 PSP_NS = 00000000
>>> XPSR = 21000000 sec=1 priv=1
instruction 999998

0x10002084:	ldr		r3, [pc, #0xc4]
****************
>>> R0 = 00000000 R4 = 100002e0  R8 = 10000269 R12 = 8aa2b9b0
>>> R1 = 10002071 R5 = 00000003  R9 = 20082000  SP = 20081ff0
>>> R2 = efef3b7f R6 = 00000003 R10 = 00000000  LR = 10000299
>>> R3 = 03f3fff6 R7 = 10000100 R11 = 0c06f10c  PC = 10002086
>>> MSP = 20081ff0 PSP = 00000000 MSP_NS = 00000000 PSP_NS = 00000000
>>> XPSR = 21000000 sec=1 priv=1
instruction 999999

0x10002086:	bics		r3, r2
****************
>>> R0 = 00000000 R4 = 100002e0  R8 = 10000269 R12 = 00000002
>>> R1 = 10002071 R5 = 00000003  R9 = 20082000  SP = 20081ff0
>>> R2 = efef3b7f R6 = 00000003 R10 = 00000000  LR = 10000299
>>> R3 = 0010c480 R7 = 10000100 R11 = 0c06f10c  PC = 10002088
>>> MSP = 20081ff0 PSP = 00000000 MSP_NS = 00000000 PSP_NS = 00000000
>>> XPSR = 21000000 sec=1 priv=1
instruction 1000000

STOPPING BECAUSE MAYBE LOOPING
0x10002088:	bne		#0x10002080
****************
>>> Emulation done (1000001 instructions) in 307569us. Below is the CPU context
>>> 3.251Mhz
>>> R0 = 00000000 R4 = 100002e0  R8 = 10000269 R12 = 8aa320c0
>>> R1 = 10002071 R5 = 00000003  R9 = 20082000  SP = 20081ff0
>>> R2 = efef3b7f R6 = 00000003 R10 = 00000000  LR = 10000299
>>> R3 = 0010c480 R7 = 10000100 R11 = 0c06f10c  PC = 10002088
>>> MSP = 20081ff0 PSP = 00000000 MSP_NS = 00000000 PSP_NS = 00000000
>>> XPSR = 21000000 sec=1 priv=1
```


