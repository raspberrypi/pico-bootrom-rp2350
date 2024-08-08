/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#include "varmulet.h"

int varmulet_run_adapter(armulet_cpu_t *cpu, const varmulet_asm_hooks_t *hooks);

extern varmulet_asm_hooks_t varmulet_nsboot_asm_hooks;
extern varmulet_asm_hooks_t varmulet_preboot_asm_hooks;
extern asm_hook_t varmulet_hooks_default_exc_and_call_return[2];

extern const void bootrom_undefined32_canary_check;
