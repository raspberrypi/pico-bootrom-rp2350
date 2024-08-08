/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#define NSBOOT_STACK_WORDS 236

#if !USE_16BIT_POINTERS || defined(__riscv)
#define P16_RAW(x) x
#define P16(x) x
#define P16_D(x) (&x)
#define P16_F(x) x
#define P16_A(x) x
#else
#define P16_PREFIX 0xbb00
#define P16_CONSTANT(x) (P16_PREFIX | P16_ ## x)
#ifndef __ASSEMBLER__
static __force_inline uintptr_t get_fp16(uint constant) {
    uintptr_t v;
    pico_default_asm(
        "movw %0, %1\n"
        : "=r" (v)
        : "i" (constant)
    );
    return v;
}
#define P16_TYPED(t, x) ((t)get_fp16(P16_CONSTANT(x)))
//#define P16_TYPED(t, x) ((t)P16_CONSTANT(x))
#define P16(x) P16_TYPED(typeof(x),x)
// replaces &data
#define P16_D(x) P16_TYPED(typeof(&(x)),x)
// replaces func
#define P16_F(x) P16_TYPED(typeof(&(x)),x)
// replaces array
#define P16_A(x) P16_TYPED(typeof(&(x)[0]),x)
#else
#define P16(x) P16_CONSTANT(x)
#endif
#endif

#ifndef __ASSEMBLER__
#include "hardware/rcp.h"

typedef __aligned(4) uint8_t aligned4_uint8_t;
typedef __aligned(2) uint8_t aligned2_uint8_t;

typedef struct {
    uint32_t e[2];
} uint32_pair_t;

typedef struct {
    uint32_t e[4];
} uint32_quad_t;

typedef struct {
    uint32_t e[6];
} uint32_sext_t;

// Stop the compiler from constant-folding a hardware base pointer into the
// pointers to individual registers, in cases where constant folding has
// produced redundant 32-bit pointer literals that could have been load/store
// offsets. (Note typeof(ptr+0) gives non-const, for +r constraint.) E.g.
//     uart_hw_t *uart0 = __get_opaque_ptr(uart0_hw);
#define __get_opaque_ptr(ptr) ({ \
    typeof((ptr)+0) __opaque_ptr = (ptr); \
    asm ("" : "+r"(__opaque_ptr)); \
    __opaque_ptr; \
})

// Similarly, for other constants that are prone to producing a new 32-bit
// constant every time some foldable operation is done on them:
#define __get_opaque_value(val) __get_opaque_ptr(val)

// Clone a value (in a more efficient way than __get_opaque_ptr
#define __clone_value(v) ({ \
    typeof((v)+0) __rc; \
    asm ("mov %0, %1\n" : "=&r"(__rc) : "r" (v)); \
    __rc; \
})

// We have two chip selects, with a 24-bit address window for each. The actual
// limit may be lower based on the sizes configured in FLASH_DEVINFO, but
// this is the hard stop.
#define MAX_FLASH_ADDR_OFFSET (0x2u << 24)

#define FLASH_SECTOR_SHIFT 12u
#define FLASH_SECTOR_SIZE (1ul << FLASH_SECTOR_SHIFT)
#define FLASH_SECTOR_REMAINDER_MASK (FLASH_SECTOR_SIZE - 1u)

#define PICOBIN_PARTITION_LOCATION_SECTOR_BIT_MASK           0x1fffu

#ifndef __ARM_ARCH_8M_MAIN__
#define branch_under_varmulet(label) ({ rcp_asm("mrc p7, #1, r15, c0, c0, #0\n"); asm goto ("bvs %l[" __XSTRING(label) "]\n" : : : : label); })
#define branch_under_non_varmulet(label) ({ rcp_asm("mrc p7, #1, r15, c0, c0, #0\n"); asm goto ("bvc %l[" __XSTRING(label) "]\n" : : : : label); })
#define branch_under_varmulet_far(label) ({ asm goto ( \
    ".cpu cortex-m33\n"\
    "mrc p7, #1, r15, c0, c0, #0\n"\
    "bvc 1f\n"\
    "b %l[" __XSTRING(label) "]\n"\
    ".cpu cortex-m23\n"\
    "1:\n"\
    : : : : label);\
    })

#endif

#if !defined(__riscv) && !defined(__ARM_ARCH_8M_MAIN__)
#define varm_callable(x) varm_to_##x
#define varm_and_native(x) varm_##x
#else
#define varm_callable(x) x
#define varm_and_native(x) native_##x
#endif

#if MINI_PRINTF || USE_64K_BOOTROM
static __force_inline uint32_t get_sp(void) {
    uint32_t rc;
    pico_default_asm(
#ifdef __riscv
        "mv %0, sp\n"
#else
        "mov %0, sp\n"
#endif
    : "=r" (rc));
    return rc;
}
#else
// declared but unimplemented so that it doesn't break compilation of asserts that use it
uint32_t get_sp(void);
#endif

#ifndef __riscv
static __force_inline void disable_irqs(void) {
    pico_default_asm_volatile("cpsid i");
}

static __force_inline void enable_irqs(void) {
    pico_default_asm_volatile("cpsie i");
}
#endif

#endif
