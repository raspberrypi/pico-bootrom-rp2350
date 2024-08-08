/*
 * Copyright (c) 2024 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

// For stack guards:
.macro riscv_disable_32byte_memregion trashreg, pmpnum, addr
    li \trashreg, ((\addr & -32) | 0x0f) >> 2
    csrw RVCSR_PMPADDR0_OFFSET + \pmpnum, \trashreg
    // Clearing of permissions here can be skipped if this code is known to be run after a core reset
.if \pmpnum % 4 == 0
    // (use immediate instruction if within range of 5-bit immediate)
    csrci RVCSR_PMPCFG0_OFFSET + \pmpnum / 4, RVCSR_PMPCFG0_R0_X_BITS | RVCSR_PMPCFG0_R0_W_BITS | RVCSR_PMPCFG0_R0_R_BITS
.else
    li \trashreg, (RVCSR_PMPCFG0_R0_X_BITS | RVCSR_PMPCFG0_R0_W_BITS | RVCSR_PMPCFG0_R0_R_BITS) << (8 * (\pmpnum % 4))
    csrc RVCSR_PMPCFG0_OFFSET + \pmpnum / 4, \trashreg
.endif
    // Enable the region
.if \pmpnum % 4 == 0
    csrsi RVCSR_PMPCFG0_OFFSET + \pmpnum / 4, (RVCSR_PMPCFG0_R0_A_VALUE_NAPOT << RVCSR_PMPCFG0_R0_A_LSB)
.else
    li \trashreg, (RVCSR_PMPCFG0_R0_A_VALUE_NAPOT << RVCSR_PMPCFG0_R0_A_LSB) << (8 * (\pmpnum % 4))
    csrs RVCSR_PMPCFG0_OFFSET + \pmpnum / 4, \trashreg
.endif
    // Make it enabled for M-mode as well as U-mode
.if \pmpnum < 5
    csrsi RVCSR_PMPCFGM0_OFFSET, 1 << \pmpnum
.else
    li \trashreg, 1 << \pmpnum
    csrs RVCSR_PMPCFGM0_OFFSET, \trashreg
.endif
.endm

// Even with medlow code model, `la` generates an auipc; addi sequence after
// relaxation. As all ROM addresses are less than 60k, a 16-bit lui + 32-bit
// addi always suffices, so force the correct sequence using this macro:
.macro la_romaddr rd, sym
#if 0
    la \rd, \sym
#else
    lui \rd, %hi(\sym)
    addi \rd, \rd, %lo(\sym)
#endif
.endm

.macro h3.block
    slt x0, x0, x0
.endm

.macro h3.unblock
    slt x0, x0, x1
.endm

// I've tried j sym; c.j sym; insn c.j xxx sym; but all result in 32-bit j
// when sym is in a different section (note this is an *assembler* limitation
// only -- I imagine the usual R_RISCV_RELAX can't be used because the
// assembler can't allocate a register.) So, time for violence:

.macro j_force_rvc sym
#if USE_64K_BOOTROM
    // use a regular j as this may get pushed out of range for larger images
    j \sym
#else
    .reloc ., R_RISCV_RVC_JUMP, \sym
.insn 0xa001
#endif
.endm

// For jal, a `call` pseudo would do (auipc ra, 0; jalr 0(ra) with
// R_RISCV_CALL + R_RISCV_RELAX) but:
//
// - There is no clobberless equivalent for j, so no point in making the jal
//   behaviour different
//
// - If something we expect to be a short call is actually long, we want to
//   be told so we can review why
//
// Fun fact, the combination R_RISCV_RELAX + R_RISCV_JAL *is* defined but only
// for the cursed Zcmt, it doesn't relax jal -> c.jal like you might expect

.macro jal_force_rvc sym
#if USE_64K_BOOTROM
    jal \sym
#else
    .reloc ., R_RISCV_RVC_JUMP, \sym
.insn 0x2001
#endif
.endm
