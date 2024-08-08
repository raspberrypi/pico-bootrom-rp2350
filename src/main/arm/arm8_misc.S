#include "bootrom.h"

.cpu cortex-m33
// note using near (.n) for branches as GCC still seems to do things like bcs.w for m33!
.thumb
.syntax unified

.section .text.s_arm8_misc

#ifndef SLIM_MEMCPY
#define SLIM_MEMCPY 1
#endif

#ifndef SLIM_MEMSET
#define SLIM_MEMSET 1
#endif

.macro memcpy_function_header
.global memcpy, varm_memcpy, native_memcpy, varm_to_native_memcpy
.thumb_func
memcpy: // (for compiler-inserted calls)
.thumb_func
varm_to_native_memcpy:
    RISCV_REDIRECT_HINT(native_memcpy)
.thumb_func
native_memcpy:
.thumb_func
varm_memcpy:
.endm

#if SLIM_MEMCPY

memcpy_function_header

// memcpy_44 is merged for SLIM_MEMCPY
.global varm_memcpy_44
.type varm_memcpy_44,%function
.thumb_func
varm_memcpy_44:
#if FEATURE_CANARIES
    rcp_count_set_nodelay STEPTAG_VARM_MEMCPY
#endif
    mov ip, r0
    subs r2, #3
    // Skip word loop if less than one word
    bls 2f
    // Skip word loop if either pointer is non-word-aligned (note we may use
    // this memcpy on Device memory, e.g. USB DPRAM buffers)
    orrs r3, r1, r0
    lsls r3, #30
    bne 2f

    // Calculate limit pointer (bias of -3, so we bail out when <4 bytes remaining)
    adds r2, r0

    // Word loop
.p2align 2
1:
    ldmia r1!, {r3}
    stmia r0!, {r3}
//    ldr r3, [r1], #4 // 32-bit instruction
//    str r3, [r0], #4
    cmp r0, r2
    blo 1b

    // recover counter from limit pointer
    subs r2, r0
2:
    adds r2, #3
#if !FEATURE_CANARIES
    bne 3f
    // fall through for common case of word-multiple (also this is the exit for 0-length)
    mov r0, ip
    bx lr
#else
    beq 4f
#endif

    // Byte loop (we know there is at least one byte, so fall through into loop)
3:
    subs r2, #1
    ldrb r3, [r1, r2]
    strb r3, [r0, r2]
    bne 3b

4:
    mov r0, ip
#if FEATURE_CANARIES
    rcp_count_check_nodelay STEPTAG_VARM_MEMCPY
#endif
    bx lr

#else
#if FEATURE_CANARIES
#error needs canaries
#endif
// Fancy memcpy based on RP2040 ROM v6-M version (not necessarily 100% optimal
// for M33 but still pretty fast)

// memset function assuming r0 and r1 are both word aligned
.global varm_memcpy_44
.type varm_memcpy_44,%function
.thumb_func
varm_memcpy_44:
    mov ip, r0
    cmp r2, #8
    blo.n __memcpy_slow
    push {r4-r6}
    b.n _memcpy_aligned

__memcpy_slow:
    cmp r2, #0
    beq.n 1f
__memcpy_slow_lp:
    subs r2, #1
    ldrb r3, [r1, r2]
    strb r3, [r0, r2]
    bne.n __memcpy_slow_lp
1:
    mov r0, ip
    bx lr

memcpy_function_header

    mov ip, r0
    cmp r2, #8
    blo.n __memcpy_slow
    subs r3, r0, r1
    lsls r3, #30
    bne.n __memcpy_slow_lp

    // r0 and r1 are co-aligned
    push {r4-r6}
    subs r1, r0
    movs r5, r0
    lsrs r3, r0, #1
    bcc.n 1f

    // byte at odd address
    ldrb r4, [r0, r1]
    strb r4, [r0]
    adds r0, #1
1:
    lsrs r3, r0, #2
    bcc.n 1f

    // halfword on non word boundary
    ldrh r4, [r0, r1]
    strh r4, [r0]
    adds r0, #2
1:
    // adjust length
    adds r1, r0
    subs r5, r0
    adds r2, r5

_memcpy_aligned:
    subs r2, #16
    bcc.n 5f
.align 2
    // 16 byte loop
1:
    ldmia r1!, {r3, r4, r5, r6}
    stmia r0!, {r3, r4, r5, r6}
    subs r2, #16
    bcs.n 1b
5:
    // 8 bytes remainder?
    lsls r2, #29
    bcc.n 1f
    ldmia r1!, {r3, r4}
    stmia r0!, {r3, r4}
1:
    // 4 bytes remainder?
    lsls r2, #1
    bcc.n 1f
    ldmia r1!, {r3}
    stmia r0!, {r3}
1:
    // early out for word aligned ending
    beq.n 2f
    // 2 bytes remainder?
    lsls r2, #1
    bcc.n 1f
    ldrh r3, [r1]
    strh r3, [r0]
    beq.n 2f
    adds r1, #2
    adds r0, #2
    // note fall thru into branch that wont take
1:
    // 1 bytes remainder?
    beq.n 2f
    ldrb r3, [r1]
    strb r3, [r0]

2:
    pop {r4-r6}
    mov r0, ip
    bx lr

#endif

// Pull this out into a macro to avoid copy/paste
.macro memset_function_header
.global varm_to_native_memset0, native_memset0, varm_memset0
.thumb_func
varm_to_native_memset0:
// fall thru (eventually reaches native code, via memset hint)
.thumb_func
native_memset0:
.thumb_func
varm_memset0:
    mov r2, r1
    movs r1, #0
    // fall thru to memset

.global memset, native_memset, varm_to_native_memset
.thumb_func
memset: // for compiler-inserted calls
.thumb_func
varm_to_native_memset:
RISCV_REDIRECT_HINT(native_memset)
    // fall thru
.thumb_func
native_memset:
.endm

#if SLIM_MEMSET

memset_function_header

.global varm_memset_4
.type __memset_4,%function
.thumb_func
varm_memset_4:
#if FEATURE_CANARIES
    rcp_count_set_nodelay STEPTAG_VARM_MEMSET
#endif

    mov ip, r0
    subs r2, #3
    // Skip word loop if less than one word
    bls 2f
    // Skip word loop if dst is non-word-aligned
    lsls r3, r0, #30
    bne 2f

    // Prepare for word loop (use limit pointer instead of counter)
    mov.w r3, 0x01010101
    muls r1, r3
    adds r2, r0
    // Word loop
.p2align 2
1:
    str r1, [r0], #4 // 32-bit instruction
    cmp r0, r2
    blo 1b

    // recover counter from limit pointer
    subs r2, r0
2:
    adds r2, #3
#if !FEATURE_CANARIES
    bne 3f
    // fall through for common case of word-multiple (also this is the exit for 0-length)
    mov r0, ip
    bx lr
#else
    beq 4f
#endif

    // Byte loop
3:
    subs r2, #1
    strb r1, [r0, r2]
    bne 3b

4:
    mov r0, ip
#if FEATURE_CANARIES
    rcp_count_check_nodelay STEPTAG_VARM_MEMSET
#endif
    bx lr


#else
#if FEATURE_CANARIES
#error needs canaries
#endif
// Fancy memset based on RP2040 ROM v6-M routine

// memset function assuming r0 is word aligned
.global varm_memset_4
.type __memset_4,%function
.thumb_func
varm_memset_4:
    mov ip, r0
    uxtb r1, r1
    lsls  r3, r1, #8
    orrs  r1, r3
    b.n _memset_word_boundary_with_hword_r1

memset_function_header

    mov ip, r0
    cmp r2, #8
    blo.n _memset_short

    lsrs r3, r0, #1
    bcc.n 1f
    // byte at odd address
    strb r1, [r0]
    adds r0, #1
1:

    // do byte->hword early
    uxtb r1, r1
    lsls  r3, r1, #8
    orrs  r1, r3
    lsrs r3, r0, #2
    bcc.n 1f

    // halfword on non word boundary
    strh r1, [r0]
    adds r0, #2
1:

    // adjust length
    mov r3, ip
    subs r3, r0
    add r2, r3

_memset_word_boundary_with_hword_r1:
    // at this point we already have r1 == 0000XXXX so extends to r1 = XXXXXXXX r3 = XXXXXXXX
    rev  r3, r1
    orrs  r1, r3
    mov r3, r1

    subs r2, #16
    bcc.n 5f

    // extend to r4 = XXXXXXXX r5 = XXXXXXXX
    push {r4-r5}
    mov r4, r1
    mov r5, r1
.align 2
    // 16 byte loop
1:
    stmia r0!, {r1, r3, r4, r5}
    subs r2, #16
    bcs.n 1b
    pop {r4-r5}
5:
    // 8 bytes remainder?
    lsls r2, #29
    bcc.n 1f
    stmia r0!, {r1, r3}
1:
    // 4 bytes remainder?
    lsls r2, #1
    bcc.n 1f
    stmia r0!, {r1}
1:
    // early out for word aligned ending
    beq.n 2f
    // 2 bytes remainder?
    lsls r2, #1
    bcc.n 1f
    strh r1, [r0]
    beq.n 2f
    adds r0, #2
    // note fall thru into branch that wont take
1:
    // 1 byte remainder?
    beq.n 2f
    strb r1, [r0]
2:
    mov r0, ip
    bx lr

_memset_short:
    adr r3, _memset_short_end
    subs r3, r2
    subs r3, r2
    adds r3, #1
    bx r3

    strb r1, [r0, #6]
    strb r1, [r0, #5]
    strb r1, [r0, #4]
    strb r1, [r0, #3]
    strb r1, [r0, #2]
    strb r1, [r0, #1]
    strb r1, [r0, #0]
_memset_short_end:
    mov r0, ip
    bx lr

#endif

// Critical erase/copy functions: same signature as memcpy/memset, but return
// the number of bytes written so that caller can assert on the amount of
// copied/erased memory. Return value is calculated from final pointer
// values, not copied straight from the arguments.

// These functions operate on whole words only, and should not be called on
// non-word-multiple sizes. This should be caught because these functions are
// written to round size *up* to a multiple of four, whereas the check
// constants at the call sites should round *down*, causing an RCP check if
// you pass a bad size.

.global varm_to_s_native_step_safe_crit_mem_erase_by_words_impl
varm_to_s_native_step_safe_crit_mem_erase_by_words_impl:
    RISCV_REDIRECT_HINT(native_memset)
.global s_native_step_safe_crit_mem_erase_by_words_impl
s_native_step_safe_crit_mem_erase_by_words_impl:
    rcp_canary_get_nodelay ip, CTAG_S_NATIVE_CRIT_MEM_ERASE_BY_WORDS_IMPL
    mov r3, r0
    cbz r2, 2f
    add r2, r3
    # note that this function is a substitute for memest; r1 is always passed (as 0)
1:
    stmia r0!, {r1}
    cmp r0, r2
    blo 1b
2:
    subs r0, r3
    rcp_canary_check_nodelay ip, CTAG_S_NATIVE_CRIT_MEM_ERASE_BY_WORDS_IMPL
    bx lr

.global varm_to_s_native_crit_mem_copy_by_words_impl
varm_to_s_native_crit_mem_copy_by_words_impl:
    RISCV_REDIRECT_HINT(native_memcpy)
.global s_native_crit_mem_copy_by_words_impl
s_native_crit_mem_copy_by_words_impl:
    rcp_canary_get_nodelay ip, CTAG_S_NATIVE_CRIT_MEM_COPY_BY_WORDS_IMPL
    push {r4, lr}
    mov r3, r0
    cbz r2, 2f
    add r2, r3
1:
    ldmia r1!, {r4}
    stmia r0!, {r4}
    cmp r0, r2
    blo 1b
2:
    subs r0, r3
    rcp_canary_check_nodelay ip, CTAG_S_NATIVE_CRIT_MEM_COPY_BY_WORDS_IMPL
    pop {r4, pc}
