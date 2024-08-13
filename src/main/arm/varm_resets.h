/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "pico/types.h"
#include "hardware/resets.h"

void s_varm_reset_block_noinline(uint32_t mask);
void s_varm_step_safe_unreset_block_wait_noinline(uint32_t mask);
void s_varm_step_safe_reset_unreset_block_wait_noinline(uint32_t mask);

static __force_inline void inline_s_varm_reset_unreset_block_wait(uint32_t mask) {
    hw_set_bits(&resets_hw->reset, mask);
    hw_clear_bits(&resets_hw->reset, mask);
    while (!(resets_hw->reset_done & mask));
}
