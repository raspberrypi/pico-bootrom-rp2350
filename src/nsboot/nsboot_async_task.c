/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include <string.h>
#include "pico.h"
#include "boot/picoboot.h"
#include "hardware/sync.h"
#include "hardware/gpio.h"

#include "nsboot.h"
#include "nsboot_usb_client.h"
#include "usb_msc.h"
#include "nsboot_async_task.h"
#include "nsboot_secure_calls.h"
#include "usb_virtual_disk.h"

CU_REGISTER_DEBUG_PINS(flash)

static inline bool is_address_nsboot_accessible_rom(uint32_t addr) {
    // commented out exact check as SG_SIZE might be set differently to the IDAU region which is what we care about
    return addr <= BOOTROM_SIZE - BOOTROM_SG_SIZE;
}

struct async_task_queue queues[2];

static void _do_flash_enter_cmd_xip(void);
static void _do_flash_exit_xip(void);
static int _do_flash_erase_sector(uint32_t addr);
static int _do_flash_erase_range(uint32_t addr, uint32_t len);
static int _do_flash_page_program(uint8_t *data, uint32_t addr);
static int _do_flash_page_read(uint8_t *data, uint32_t addr);


static void _do_flash_enter_cmd_xip(void) {
    usb_warn("flash enter cmd XIP\n");
    // This call is stubbed out on RP2350 as QMI is less dumb than SSI
    // sc_or_varm_flash_enter_cmd_xip();
}

static void _do_flash_exit_xip(void) {
    usb_warn("flash exit XIP\n");
    DEBUG_PINS_SET(flash, 2);
    // On RP2350 this just clears the flash abort:
    sc_or_varm_connect_internal_flash();
    DEBUG_PINS_SET(flash, 4);
    // XIP exit is not exposed to nsboot on RP2350, as we should have already
    // kicked the flash into serial command state in the Secure preamble:
    // sc_or_varm_flash_exit_xip();
    DEBUG_PINS_CLR(flash, 6);
}

static int _do_flash_erase_sector(uint32_t addr) {
    usb_warn("erasing flash sector @%08x\n", (uint) addr);
    DEBUG_PINS_SET(flash, 2);
    int rc = sc_or_varm_flash_sector_erase(addr - XIP_BASE);
    DEBUG_PINS_CLR(flash, 2);
    return rc;
}

static int _do_flash_erase_range(uint32_t addr, uint32_t len) {
    uint32_t end = addr + len;
    int ret = 0;
    while (addr < end && !ret) {
        ret = _do_flash_erase_sector(addr);
        addr += FLASH_SECTOR_ERASE_SIZE;
    }
    return ret;
}

static int _do_flash_page_program(uint8_t *data, uint32_t addr) {
    usb_warn("writing flash page @%08x\n", (uint) addr);
    DEBUG_PINS_SET(flash, 4);
    int rc = sc_or_varm_flash_page_program(data, addr - XIP_BASE);
    DEBUG_PINS_CLR(flash, 4);
    return rc;
}

static int _do_flash_page_read(uint8_t *data, uint32_t addr) {
    DEBUG_PINS_SET(flash, 4);
    usb_warn("reading flash page @%08x\n", (uint) addr);
    int rc = sc_or_varm_flash_read_data(data, addr - XIP_BASE, FLASH_PAGE_SIZE);
    DEBUG_PINS_CLR(flash, 4);
    return rc;
}

static uint8_t _last_mutation_source;

const uint8_t bootrom_error_to_picoboot_error[] = {
        PICOBOOT_OK,
        PICOBOOT_UNKNOWN_ERROR,                // unused #define BOOTROM_ERROR_TIMEOUT (-1)
        PICOBOOT_UNKNOWN_ERROR,                // unused #define BOOTROM_ERROR_GENERIC (-2)
        PICOBOOT_UNKNOWN_ERROR,                // unused #define BOOTROM_ERROR_NO_DATA (-3)
        PICOBOOT_NOT_PERMITTED,                // #define BOOTROM_ERROR_NOT_PERMITTED (-4)
        PICOBOOT_INVALID_ARG,                  // #define BOOTROM_ERROR_INVALID_ARG (-5)
        PICOBOOT_UNKNOWN_ERROR,                // unused #define BOOTROM_ERROR_IO (-6)
        PICOBOOT_UNKNOWN_ERROR,                // unused #define BOOTROM_ERROR_BADAUTH (-7)
        PICOBOOT_UNKNOWN_ERROR,                // unused #define BOOTROM_ERROR_CONNECT_FAILED (-8)
        PICOBOOT_UNKNOWN_ERROR,                // unused #define BOOTROM_ERROR_INSUFFICIENT_RESOURCES (-9)
        PICOBOOT_INVALID_ADDRESS,              // #define BOOTROM_ERROR_INVALID_ADDRESS (-10)
        PICOBOOT_BAD_ALIGNMENT,                // #define BOOTROM_ERROR_BAD_ALIGNMENT (-11)
        PICOBOOT_INVALID_STATE,                // #define BOOTROM_ERROR_INVALID_STATE (-12)
        PICOBOOT_BUFFER_TOO_SMALL,             // #define BOOTROM_ERROR_BUFFER_TOO_SMALL (-13)
        PICOBOOT_PRECONDITION_NOT_MET,         // #define BOOTROM_ERROR_PRECONDITION_NOT_MET (-14)
        PICOBOOT_MODIFIED_DATA,                // #define BOOTROM_ERROR_MODIFIED_DATA (-15)
        PICOBOOT_INVALID_DATA,                 // #define BOOTROM_ERROR_INVALID_DATA (-16)
        PICOBOOT_NOT_FOUND,                    // #define BOOTROM_ERROR_NOT_FOUND (-17)
        PICOBOOT_UNSUPPORTED_MODIFICATION,     // #define BOOTROM_ERROR_UNSUPPORTED_MODIFICATION (-18)
        PICOBOOT_INVALID_STATE,                // #define BOOTROM_ERROR_LOCK_REQIURED (-19) - should not happen frm NSBOOT
};

// make sure all errors are mapped
static_assert(count_of(bootrom_error_to_picoboot_error) == 1-BOOTROM_ERROR_LAST, "");

// NOTE for simplicity this returns error codes from PICOBOOT
static uint32_t _execute_task(struct async_task *task) {
    if (rebooting()) {
        return PICOBOOT_REBOOTING;
    }
    uint type = task->type;
    if (type & AT_MASKABLE_EXIT_XIP) {
        _do_flash_exit_xip();
    }
    int ret = PICOBOOT_OK;
    if (type == AT_VECTORIZE_FLASH || type == AT_EXEC) {
        return PICOBOOT_UNKNOWN_CMD; // no longer supported
    } else if (type == AT_EXCLUSIVE) {
        // we do this in execute_task, so we know we aren't executing and virtual_disk_queue tasks at this moment
        usb_warn("SET EXCLUSIVE ACCESS %d\n", task->exclusive_param);
        async_disable_queue(QUEUE_VIRTUAL_DISK, task->exclusive_param);
        if (task->exclusive_param == EXCLUSIVE_AND_EJECT) {
            msc_eject();
        }
#if FEATURE_EXEC2
    } else if (type == AT_EXEC2) {
        usb_warn("exec2 bin %08x->%08x, work %08x->%08x\n", (uint) task->exec2_cmd.image_base, (uint) task->exec2_cmd.image_base + task->exec2_cmd.image_size,
                 (uint) task->exec2_cmd.workarea_base, (uint) task->exec2_cmd.workarea_base + task->exec2_cmd.workarea_size);
        ret = sc_or_varm_picoboot_exec2(&task->exec2_cmd);
        printf("EXEC2 returned %d\n", ret);
#endif
    } else if (type == AT_GET_INFO) {
        uint32_t *buf = (uint32_t *)task->data;
        uint words = (task->data_length >> 2) - 1;
        uint arg = task->get_info_cmd.dParams[0];
        // pre-clear buffer
        varm_to_native_memset0(buf + 1, words * 4);
        if (task->get_info_cmd.bType == PICOBOOT_GET_INFO_SYS) {
            buf[0] = (uint32_t) sc_or_varm_get_sys_info(buf + 1, words, arg);
        } else if (task->get_info_cmd.bType == PICOBOOT_GET_INFO_PARTTION_TABLE) {
            buf[0] = (uint32_t) sc_or_varm_get_partition_table_info(buf + 1, words, arg);
        } else if (task->get_info_cmd.bType == PICOBOOT_GET_INFO_UF2_TARGET_PARTITION) {
            buf[0] = 3;
            ret = sc_or_varm_ram_trash_get_uf2_target_partition((resident_partition_t *)(buf + 2), arg);
            if (ret >= 0 || ret == BOOTROM_ERROR_NOT_FOUND) {
                // convert BOOTROM_ERROR_NOT_FOUND to 0xffffffff;
                buf[1] = (uint32_t)ret | (uint32_t)(((int32_t)ret) >> 31);
                ret = BOOTROM_OK;
            }
        } else if (task->get_info_cmd.bType == PICOBOOT_GET_INFO_UF2_STATUS) {
            buf[0] = 4;
            *(uint32_quad_t*)(buf+1) = *get_uf2_status();
        } else {
            return PICOBOOT_INVALID_ARG;
        }
        if ((int32_t)buf[0] < 0) {
            ret = (int32_t)buf[0];
        }
    } else if (type == AT_OTP_READ || type == AT_OTP_WRITE) {
        uint shift = 2 - task->otp_cmd.bEcc;
        uint base_row = (task->otp_cmd.wRow + (task->transfer_addr >> shift));
        // we just check this before casting to uint16_t the actual API will check validity within the uint16_t
        if (base_row>>16) {
            return PICOBOOT_INVALID_ADDRESS;
        }
        // note we don't check task->data_length vs otp_cmd.wRowCount, as
        // task->data_length is maxxed out at 256 bytes, which is the size of buffer
        // we have available. not to worry though, the transfer length is checked against th ECC flag and wRowCount
        // in nsboot_usb_client.c
        if (type == AT_OTP_READ) {
            varm_to_native_memset0((void *) task->data, task->data_length);
        }
        ret = sc_or_varm_otp_access(task->data, task->data_length,
                                    (otp_cmd_t) {.flags = (
                                            (base_row << OTP_CMD_ROW_LSB) |
                                            (task->otp_cmd.bEcc ? OTP_CMD_ECC_BITS : 0) |
                                            (type != AT_OTP_READ ? OTP_CMD_WRITE_BITS : 0)
                                    )});
        if (ret) goto translate_return_code;
    }

    if (type & (AT_MASKABLE_WRITE | AT_MASKABLE_FLASH_ERASE)) {
        if (task->check_last_mutation_source && _last_mutation_source != task->source) {
            return PICOBOOT_INTERLEAVED_WRITE;
        }
        _last_mutation_source = task->source;
    }
    if (type & AT_MASKABLE_FLASH_ERASE) {
        usb_warn("request flash erase at %08x+%08x\n", (uint) task->erase_addr, (uint) task->erase_size);
        if (task->erase_addr & (FLASH_SECTOR_ERASE_SIZE - 1)) return PICOBOOT_BAD_ALIGNMENT;
        if (task->erase_size & (FLASH_SECTOR_ERASE_SIZE - 1)) return PICOBOOT_BAD_ALIGNMENT;
        if (!(is_address_flash(task->erase_addr) && is_address_flash(task->erase_addr + task->erase_size))) {
            return PICOBOOT_INVALID_ADDRESS;
        }
        ret = _do_flash_erase_range(task->erase_addr, task->erase_size);
        if (ret) goto translate_return_code;
    }
    bool direct_access = false;
    if (type & (AT_MASKABLE_WRITE | AT_MASKABLE_READ)) {
        if ((varm_is_sram_or_xip_ram(task->transfer_addr) && varm_is_sram_or_xip_ram(task->transfer_addr + task->data_length - 1))
#if !NO_ROM_READ
            || (!(type & AT_MASKABLE_WRITE) && is_address_nsboot_accessible_rom(task->transfer_addr) &&
                is_address_nsboot_accessible_rom(task->transfer_addr + task->data_length))
#endif
                ) {
            direct_access = true;
        } else if ((is_address_flash(task->transfer_addr) &&
                    is_address_flash(task->transfer_addr + task->data_length))) {
            // flash
            if (task->transfer_addr & (FLASH_PAGE_SIZE - 1)) return PICOBOOT_BAD_ALIGNMENT;
        } else {
            // bad address
            return PICOBOOT_INVALID_ADDRESS;
        }
        if (type & AT_MASKABLE_WRITE) {
            if (direct_access) {
                usb_warn("writing %08x +%04x\n", (uint) task->transfer_addr, (uint) task->data_length);
                varm_to_native_memcpy((void *) task->transfer_addr, task->data, task->data_length);
            } else {
                bootrom_assert(NSBOOT, task->data_length <= FLASH_PAGE_SIZE);
                ret = _do_flash_page_program(task->data,  task->transfer_addr);
                if (ret) goto translate_return_code;
            }
        } else if (type & AT_MASKABLE_READ) {
            if (direct_access) {
                usb_warn("reading %08x +%04x\n", (uint) task->transfer_addr, (uint) task->data_length);
                varm_to_native_memcpy(task->data, (void *) task->transfer_addr, task->data_length);
            } else {
                bootrom_assert(NSBOOT, task->data_length <= FLASH_PAGE_SIZE);
                ret = _do_flash_page_read(task->data, task->transfer_addr);
                if (ret) goto translate_return_code;
            }
        }
    }
    if (type == AT_ENTER_CMD_XIP) {
        _do_flash_enter_cmd_xip();
    }
translate_return_code:
    bootrom_assert(MISC, ret <= 0);
    // since we should only get here with BOOTROM_ERRORS or 0, we add OK to the table, to save a branch
    ret = -ret;
    bootrom_assert(MISC, ret >=0 && ret < (int)count_of(bootrom_error_to_picoboot_error));
    return P16_A(bootrom_error_to_picoboot_error)[ret];
}

// just put this here in case it is worth noinlining - not atm
static void _task_copy(struct async_task *to, struct async_task *from) {
    //*to = *from;
    varm_to_native_memcpy(to, from, sizeof(struct async_task));
}

void reset_task(struct async_task *task) {
    varm_to_native_memset0(task, sizeof(struct async_task));
}

void queue_task(uint queue_index, struct async_task *task, async_task_callback callback) {
    struct async_task_queue *queue = deref_queue(queue_index);
    task->callback = callback;
#if ASYNC_TASK_REQUIRE_TASK_CALLBACK
    bootrom_assert(NSBOOT, callback);
#endif
    bootrom_assert(NSBOOT, !task->result); // convention is that it is zero, so try to catch missing rest
#if NO_ASYNC
    task->result = _execute_task(task);
    _call_task_complete(task);
#else
    if (queue->full) {
        usb_warn("overwriting already queued task for queue %p\n", queue);
    }
    _task_copy(&queue->task, task);
    queue->full = true;
    __sev();
#endif
}

static inline void _call_task_complete(struct async_task *task) {
#if ASYNC_TASK_REQUIRE_TASK_CALLBACK
    task->callback(task);
#else
    if (task->callback) task->callback(task);
#endif
}

bool dequeue_task(uint queue_index, struct async_task *task_out) {
    struct async_task_queue *queue = deref_queue(queue_index);
#if NO_ASYNC
    return false;
#else
    bool have_task = false;
    bootrom_assert(MISC, !save_and_disable_interrupts());
    disable_irqs();// save = save_and_disable_interrupts();
    __mem_fence_acquire();
    if (queue->full) {
        _task_copy(task_out, &queue->task);
        queue->full = false;
        have_task = true;
    }
    enable_irqs(); //restore_interrupts(save);
    return have_task;
#endif
}

void execute_task(uint queue_index, struct async_task *task) {
//    printf("-->TASK EXEC START\n");
    struct async_task_queue *queue = deref_queue(queue_index);
    if (queue->disable)
        task->result = 1; // todo better code (this is fine for now since we only ever disable virtual_disk queue which only cares where or not result is 0
    else
        task->result = _execute_task(task);
//    printf("-->TASK EXEC DONE\n");
    bootrom_assert(MISC, !save_and_disable_interrupts());
    disable_irqs(); //uint32_t save = save_and_disable_interrupts();
//    printf("-->TASK COMPLETE START\n");
    _call_task_complete(task);
//    printf("-->TASK COMPLETE DONE\n");
    enable_irqs(); //restore_interrupts(save);
}

#ifndef NDEBUG
static bool _worker_started;
#endif

static struct async_task _worker_task;

void __attribute__((noreturn)) async_task_worker(void) {
#ifndef NDEBUG
    _worker_started = true;
#endif
    uint q = QUEUE_VIRTUAL_DISK;
    do {
#if USE_PICOBOOT
        q ^= QUEUE_VIRTUAL_DISK ^ QUEUE_PICOBOOT;
#endif
        if (dequeue_task(q, &_worker_task)) {
            execute_task(q, &_worker_task);
        } else if (q != QUEUE_PICOBOOT) {
            __wfe();
        }
    } while (true);
}
