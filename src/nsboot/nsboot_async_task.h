/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

// Simple async task without real locking... tasks execute in thread mode, they are queued by IRQs and state management and completion callbacks called with IRQs disabled
// which effectively means everything but the task execution is single threaded; as such the task should used async_task structure for all input/output
#include "nsboot.h"

#define ASYNC_TASK_REQUIRE_TASK_CALLBACK 1
// bit field for task type
#define AT_EXCLUSIVE        0x01u
#define AT_ENTER_CMD_XIP    0x02u
#define AT_EXEC             0x03u
#define AT_VECTORIZE_FLASH  0x04u
#define AT_GET_INFO         0x05u
#define AT_OTP_READ         0x06u
#define AT_OTP_WRITE        0x07u
#define AT_EXEC2            0x08u

// these three are checked by AND with mask, so are given their own bits
// (they can be combined with eachother, but not any of the above)
#define AT_MASKABLE_EXIT_XIP         0x10u
#define AT_MASKABLE_FLASH_ERASE      0x20u
#define AT_MASKABLE_READ             0x40u
#define AT_MASKABLE_WRITE            0x80u

struct async_task;

typedef void (*async_task_callback)(struct async_task *task);

#define FLASH_PAGE_SIZE 256u
#define FLASH_PAGE_MASK (FLASH_PAGE_SIZE - 1u)
#define FLASH_SECTOR_ERASE_SIZE 4096u

enum task_source {
    TASK_SOURCE_VIRTUAL_DISK = 1,
    TASK_SOURCE_PICOBOOT,
};

// copy by value task definition
struct async_task {
    uint32_t token;
    uint32_t result;
    async_task_callback callback;

    // we only have one task type now, so inlining all fields since the task building
    // code does not know which fields are for which tasks (it just populates them all
    // speculatively (except get_info, otp and exec2 which are handled specially, so can overlap some other fields)
    uint32_t transfer_addr;
    union {
        // note these 2 are used both by the "erase" cmd itself, or by erases happening as a result of flash writes
        struct {
            uint32_t erase_size;
            uint32_t erase_addr;
        };
        uint32_quad_t raw_cmd; // we need space for any type
        struct picoboot_otp_cmd otp_cmd;
        struct picoboot_exec2_cmd exec2_cmd;
        struct picoboot_get_info_cmd get_info_cmd;
    };
    aligned4_uint8_t *data;
    uint32_t data_length;
    uint32_t picoboot_user_token;
    uint8_t type;
    uint8_t exclusive_param;
    // an identifier for the logical source of the task
    uint8_t source;
    // if true, fail the task if the source isn't the same as the last source that did a mutation
    bool check_last_mutation_source;
};

// arguably a very short queue; there is only one up "next" item which is set by queue_task...
// attempt to queue multiple items will overwrite (so generally use multiple queues)
//
// this purely allows us to queue one task from the IRQ scope to the worker scope while
// that worker scope may still be executing the last one
struct async_task_queue {
    struct async_task task;
    volatile bool full;
    volatile bool disable;
};

// called by irq handler to queue a task
void queue_task(uint queue_index, struct async_task *task, async_task_callback callback);

// called from thread to dequeue a task
bool dequeue_task(uint queue_index, struct async_task *task_out);

// runs forever dispatch tasks
void __attribute__((noreturn)) async_task_worker(void);

void reset_task(struct async_task *task);

#define QUEUE_PICOBOOT 0
#define QUEUE_VIRTUAL_DISK 1
extern struct async_task_queue queues[2];
#define deref_queue(x) (&queues[x])
static inline void async_disable_queue(uint queue_index, bool disable) {
    deref_queue(queue_index)->disable = disable;
}

static inline void reset_queue(uint queue_index) {
    deref_queue(queue_index)->full = false;
    async_disable_queue(queue_index, false);
}

// async task needs to know where the flash bitmap is so it can avoid it
#define FLASH_VALID_BLOCKS_BASE XIP_SRAM_BASE
#define FLASH_BITMAPS_SIZE (XIP_SRAM_END - XIP_SRAM_BASE)
