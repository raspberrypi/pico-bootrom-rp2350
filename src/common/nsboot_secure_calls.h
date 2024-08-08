/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "pico.h"

// note the order of these is important as it is mirrored in asm tables in arm8_bootrom_rt0.S and varmulet_hooks_bootrom.S

// these SC_ calls (SC_foo is implemented by sc_foo stub) will pass r0, r1, r2 (and SC_ number in r3) to SG handler in
// ARM secure code. On RISC-V the SG is trapped, and the secure ARM code is executed directly

#define SC_connect_internal_flash               0x0
#define SC_flash_page_program                   0x1
#define SC_flash_sector_erase                   0x2
#define SC_flash_read_data                      0x3
#define SC_flash_abort                          0x4
#define SC_reboot                               0x5
#define SC_otp_access                           0x6
#define SC_ram_trash_get_uf2_target_partition   0x7
#define SC_get_partition_table_info             0x8
#define SC_get_sys_info                         0x9
#if FEATURE_EXEC2
#define SC_picoboot_exec2                       0xa
#define SC_max_secure_call_num                  0xa
#else
#define SC_max_secure_call_num                  0x9
#endif


#ifndef __ASSEMBLER__
#include "nsboot_config.h"
#include "boot/picoboot.h"
#include "pico/bootrom_constants.h"

// sc_or_varm_ is a SG into secure on ARM and a continuation to an ARM func still under varmulet on RISC-V
// sc_or_native_ is a SG into secure on ARM and a call into a native RISC-V function on RISC-V

// note all of these methods return PICOBOOT_ return codes
#ifndef __riscv
// Multiple callers, so routed through trampoline to save space on the ordinal:
void sc_or_varm_flash_exit_xip(void);
void sc_or_varm_flash_enter_cmd_xip(void);
void sc_or_varm_flash_abort(void);
int sc_or_varm_reboot(uint32_t flags, uint32_t delay_ms, uint32_t p0, uint32_t p1);
int sc_or_varm_otp_access(aligned4_uint8_t *buf, uint32_t buf_len, otp_cmd_t cmd);
int sc_or_varm_ram_trash_get_uf2_target_partition(resident_partition_t *partition_out, uint32_t family_id);
#if FEATURE_EXEC2
int sc_or_varm_picoboot_exec2(struct picoboot_exec2_cmd *cmd);
#endif

// Only called once, so no trampoline (this nonsense is all to get a call with
// r3 set just before the bl, to handle the multiplexing of the shared entry
// point -- we have an asm structure for this already, but it costs an extra
// b.n per entry point)

__force_inline void sc_or_varm_connect_internal_flash(void) {
    pico_default_asm_volatile (
        "movs r3, %0\n"
        "bl sc_or_varm_common\n"
        :
        : "i" (SC_connect_internal_flash)
        : "r0", "r1", "r2", "r3", "lr", "ip", "cc"
    );
}

__force_inline int sc_or_varm_flash_sector_erase(uint32_t addr) {
    register uint32_t r0 asm("r0") = addr; 
    pico_default_asm_volatile (
        "movs r3, %1\n"
        "bl sc_or_varm_common\n"
        : "+r" (r0)
        : "i" (SC_flash_sector_erase)
        : "r1", "r2", "r3", "lr", "ip", "cc"
    );
    return (int)r0;
}

__force_inline int sc_or_varm_flash_read_data(uint8_t *rx, uint32_t addr, size_t count) {
    register uint8_t *r0 asm("r0") = rx;
    register uint32_t r1 asm("r1") = addr;
    register size_t   r2 asm("r2") = count;
    pico_default_asm_volatile (
        "movs r3, %3\n"
        "bl sc_or_varm_common\n"
        : "+r" (r0), "+r" (r1), "+r" (r2)
        : "i" (SC_flash_read_data)
        : "r3", "lr", "ip", "cc"
    );
    return (int)r0;
}

__force_inline int sc_or_varm_flash_page_program(const uint8_t *data, uint32_t addr) {
    register const uint8_t *r0 asm("r0") = data;
    register uint32_t       r1 asm("r1") = addr;
    pico_default_asm_volatile (
        "movs r3, %2\n"
        "bl sc_or_varm_common\n"
        : "+r" (r0), "+r" (r1)
        : "i" (SC_flash_page_program)
        : "r2", "r3", "lr", "ip", "cc"
    );
    return (int)r0;
}

__force_inline int sc_or_varm_get_partition_table_info(uint32_t *out_buffer, uint32_t out_buffer_word_size, uint32_t flags) {
    register uint32_t *r0 asm("r0") = out_buffer;
    register uint32_t  r1 asm("r1") = out_buffer_word_size;
    register uint32_t  r2 asm("r2") = flags;
    pico_default_asm_volatile (
        "movs r3, %3\n"
        "bl sc_or_varm_common\n"
        : "+r" (r0), "+r" (r1), "+r" (r2)
        : "i" (SC_get_partition_table_info)
        : "r3", "lr", "ip", "cc"
    );
    return (int)r0;

}

__force_inline int sc_or_varm_get_sys_info(uint32_t *out_buffer, uint32_t out_buffer_word_size, uint32_t flags) {
    register uint32_t *r0 asm("r0") = out_buffer;
    register uint32_t  r1 asm("r1") = out_buffer_word_size;
    register uint32_t  r2 asm("r2") = flags;
    pico_default_asm_volatile (
        "movs r3, %3\n"
        "bl sc_or_varm_common\n"
        : "+r" (r0), "+r" (r1), "+r" (r2)
        : "i" (SC_get_sys_info)
        : "r3", "lr", "ip", "cc"
    );
    return (int)r0;
}
#endif //!__riscv

#endif // __ASSEMBLER__
