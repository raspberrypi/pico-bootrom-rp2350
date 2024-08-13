/*
 * Copyright (c) 2024 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#pragma once

#define STEPTAG_STEP5_SAU_SANITY_CHECK                                      0x05
#define STEPTAG_STEP6_MPU_SANITY_CHECK                                      0x06
#define STEPTAG_STEP7_CHECK_POWMAN_BOOT                                     0x07
#define STEPTAG_STEP8_TRY_VECTOR                                            0x08
#define STEPTAG_STEP9_CLEAR_BOOTDIS                                         0x09
#define STEPTAG_STEP10_SRAM_POWERUP                                         0x0a
#define STEPTAG_STEP11_MAIN_RESETS                                          0x0b
#define STEPTAG_STEP12_SELECT_BOOT_PATH                                     0x0c

#define STEPTAG_S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_BASE                     0x30
#define STEPTAG_S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_MID_CHECK                0x31
#define STEPTAG_S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_POST_CHECK               0x32
#define STEPTAG_S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_PRE_THUNK                0x33
// note... should follow from above steps
#define STEPTAG_S_VARM_CRIT_RAM_TRASH_LAUNCH_IMAGE_THUNK_BASE               0x34
#define STEPTAG_S_NATIVE_CRIT_INIT_DEFAULT_XIP_SETUP_AND_ENTER_FLASH_THUNK_BASE_ 0x38 // 0x3c
#define STEPTAG_S_NATIVE_API_VALIDATE_NS_BUFFER_BASE                        0x3c // ->0x3f
// "Lite" control flow checks which just set/check a step at the start/end of a leaf function
//  (code size reduction) -- by convention we use even numbers only, so that two exits can't be chained
#define STEPTAG_S_VARM_CRIT_FLASH_CHECK_IN_BOUNDS_SINGLE_ADDR               0x40
#define STEPTAG_S_VARM_CRIT_FLASH_CHECK_IN_BOUNDS_ADDR_SPAN                 0x42
#define STEPTAG_S_VARM_FLASH_TRANSLATE_RUNTIME_TO_STORAGE_ADDR              0x44
#define STEPTAG_S_ARM8_USB_CLIENT_NS_CALL_THUNK                             0x46
#define STEPTAG_ARM_TABLE_LOOKUP_ENTRY                                      0x48
#define STEPTAG_S_VARM_API_SET_NS_API_PERMISSION                            0x4a
#define STEPTAG_S_FROM_NS_ARM8_API_SECURE_CALL                              0x4c
#define STEPTAG_S_VARM_API_CRIT_CONNECT_INTERNAL_FLASH                      0x4e
#define STEPTAG_S_VARM_API_CRIT_FLASH_SELECT_XIP_READ_MODE                  0x50
#define STEPTAG_S_VARM_API_CRIT_FLASH_RESET_ADDRESS_TRANS                   0x52
#define STEPTAG_S_VARM_CRIT_B_PARTITION                                     0x54
#define STEPTAG_S_VARM_OTP_WAIT_SBPI_DONE                                   0x56
#define STEPTAG_S_VARM_FLASH_ABORT                                          0x58
#define STEPTAG_S_VARM_FLASH_ABORT_CLEAR                                    0x5a
#define STEPTAG_VARM_MEMCPY                                                 0x5c
#define STEPTAG_S_FROM_NS_NSBOOT_SERVICE_CALL                               0x5e

#define STEPTAG_VARM_MEMSET                                                 0x60
#define STEPTAG_S_SHA256_PUT_BYTE                                           0x62
// leave gap after S_SHA256_PUT_BYTE as we use S_SHA256_PUT_BYTE + 1
#define STEPTAG_S_VARM_SHA256_PUT_WORD                                      0x66
#define STEPTAG_S_SHA256_PUT_WORD_INC                                       0x68
#define STEPTAG_SB_SHA256_INIT                                              0x6a
#define STEPTAG_SB_HMAC_SHA256_KEY_PAD                                      0x6c

#define STEPTAG_SB_FE_ADC_SBC                                               0x70
#define STEPTAG_SB_FE_TEST_BIT                                              0x72

#define STEPTAG_SB_FE_SUB_BORROW                                            0x76
#define STEPTAG_SB_FE_MOD_SUB                                               0x78
#define STEPTAG_SB_FE_MOD_COPY_256BITS                                      0x7a
#define STEPTAG_SB_FE_CTSWAP                                                0x7c
#define STEPTAG_SB_FE_FROM_BYTES_BIG_ENDIAN                                 0x7e
#define STEPTAG_S_VARM_SECURE_CALL                                          0x80
#define STEPTAG_SB_FE_MONT_MULT                                             0x82
#define STEPTAG_SB_FE_LT_COND_SUB_P                                         0x84
#define STEPTAG_SB_FE_MOD_INV_R                                             0x86
#define STEPTAG_SG_CALL                                                     0x88
#define STEPTAG_S_VARM_CRIT_PARSE_BLOCK1                                    0x8a
#define STEPTAG_NSBOOT_OTP_ADVANCE                                          0x8c
// gap for multiple steps ^
#define STEPTAG_S_OTP_ADVANCE_BL_TO_S_VALUE                                 0x90
#define STEPTAG_S_VARM_CRIT_LATCH_BLOCK                                     0x92
#define STEPTAG_S_VARM_STEP_SAFE_HX_GET_BOOT_FLAGX_IMPL                     0x94
#define STEPTAG_S_VARM_DECODE_ITEM_SIZE_IMPL                                0x96
#define STEPTAG_S_VARM_INIT_DIAGNOSTIC32_IMPL                               0x98

// Note the asm rcp_count_check macro is a bit more crude and requires two
// decimal numbers between 0 and 15, so we just define the high half here:
#define STEPTAG_ASM_C1_BOOTPATH                                             0xc0
#define STEPTAG_ASM_MULTICORE_LAUNCH                                        0xd0

// Add a new #define CTAG_foobar xxx define, and then run:
// ./scripts/scramble_canary_tags src/main/native/rcp_tags.h

#define CTAG_S_FROM_NS_NSBOOT_SERVICE_CALL                           0x54
#define CTAG_S_VARM_CRIT_RAM_TRASH_TRY_FLASH_BOOT                    0x4d
#define CTAG_S_VARM_CRIT_TRY_VECTOR                                  0x88
#define CTAG_S_VARM_OTP_ACCESS                                       0x4f
#define CTAG_S_NATIVE_CRIT_FLASH_PUT_GET                             0x69
#define CTAG_S_VARM_CRIT_RAM_TRASH_TRY_RAM_BOOT                      0xa8
#define CTAG_S_NATIVE_CRIT_XIP_CACHE_MAINTENANCE                     0x43
#define CTAG_ARM8_TABLE_LOOKUP_VAL                                   0x6c
#define CTAG_RECEIVE_AND_CHECK_ZERO                                  0x81
#define CTAG_SEND_AND_THEN                                           0x95
#define CTAG_S_VARM_SECURE_CALL                                      0x70
#define CTAG_S_VARM_UNRESET_BLOCK_WAIT_NOINLINE                      0x48
#define CTAG_S_NATIVE_CRIT_MEM_ERASE_BY_WORDS_IMPL                   0xa0
#define CTAG_S_NATIVE_CRIT_MEM_COPY_BY_WORDS_IMPL                    0x9a
#define CTAG_S_FROM_NS_VARM_API_REBOOT_ENTRY                         0x52
#define CTAG_S_VARM_API_REBOOT                                       0x44
#define CTAG_S_VARM_API_GET_SYS_INFO                                 0x82
#define CTAG_S_VARM_API_GET_PARTITION_TABLE_INFO                     0x73
#define CTAG_S_VARM_API_SET_ROM_CALLBACK                             0x9f
#define CTAG_S_VARM_API_FLASH_RUNTIME_TO_STORAGE_ADDR                0xac
#define CTAG_S_VARM_API_PICK_AB_PARTITION                            0x86
#define CTAG_S_VARM_API_FLASH_RANGE_PROGRAM                          0x89
#define CTAG_S_VARM_API_FLASH_RANGE_ERASE                            0x45
#define CTAG_S_VARM_API_CRIT_FLASH_EXIT_XIP                          0x71
#define CTAG_S_VARM_API_CHECKED_FLASH_OP                             0x74
#define CTAG_S_VARM_API_LOAD_PARTITION_TABLE                         0x6e
#define CTAG_S_VARM_API_CHAIN_IMAGE                                  0x55
#define CTAG_S_VARM_API_EXPLICIT_BUY                                 0x93
#define CTAG_S_VARM_FLASHPERM_GET_PARTITION_NUM_FROM_STORAGE_ADDRESS 0xad
#define CTAG_S_VARM_STEP_SAFE_OTP_READ_RBIT3_GUARDED                 0x98
#define CTAG_S_VARM_CRIT_INIT_BOOT_SCAN_CONTEXT                      0x66
#define CTAG_S_VARM_CRIT_GET_PT_PARTITION_INFO                       0x57
#define CTAG_S_VARM_CRIT_INIT_RESIDENT_PARTITION_TABLE_FROM_BUFFER   0x46
#define CTAG_S_VARM_CRIT_PARSE_BLOCK                                 0x59
#define CTAG_S_VARM_CRIT_SEARCH_WINDOW                               0xb2
#define CTAG_S_VARM_CRIT_RAM_TRASH_PICK_AB_IMAGE_PART1               0x94
#define CTAG_S_ARM8_VERIFY_SIGNATURE_SECP256K1                       0x42
#define CTAG_S_VARM_STEP_SAFE_API_CRIT_BOOTROM_STATE_RESET           0x4a
#define CTAG_VARM_IS_SRAM_OR_XIP_RAM                                 0xb1
#define CTAG_S_VARM_CRIT_RAM_TRASH_VERIFY_PARSED_BLOCKS              0xae
#define CTAG_S_VARM_CRIT_CHOOSE_BY_TBYB_FLASH_UPDATE_BOOT_AND_VERSION 0x85
#define CTAG_S_VARM_CRIT_RAM_TRASH_FIND_UF2_TARGET_PARTITION         0x47
#define CTAG_S_VARM_FLASH_USER_ERASE                                 0x7b
#define CTAG_S_VARM_CRIT_BUY_ERASE_OTHER_VERSION                     0xaa
#define CTAG_S_VARM_CHECKED_FLASH_OP_NOTRANSLATE                     0xb3
#define CTAG_S_VARM_CRIT_BUY_UPDATE_OTP_VERSION                      0x75
#define CTAG_S_VARM_CRIT_RAM_TRASH_VERIFY_AND_LAUNCH_IMAGE           0x9d
#define CTAG_S_VARM_CRIT_RAM_TRASH_VERIFY_AND_LAUNCH_FLASH_IMAGE     0x5b
#define CTAG_S_VARM_CRIT_RAM_TRASH_PERFORM_FLASH_SCAN_AND_MAYBE_RUN_IMAGE 0x68
#define CTAG_S_VARM_CRIT_LOAD_RESIDENT_PARTITION_TABLE               0x8d
#define CTAG_S_FROM_NSBOOT_VARM_RAM_TRASH_GET_UF2_TARGET_PARTITION   0x6d
#define CTAG_S_FROM_NSBOOT_VARM_FLASH_PAGE_PROGRAM                   0xa5
#define CTAG_S_FROM_NSBOOT_VARM_FLASH_READ_DATA                      0x4e
#define CTAG_S_FROM_NS_VARM_PICOBOOT_EXEC2                           0x8b
#define CTAG_S_VARM_CRIT_FLASH_CHECK_IN_BOUNDS_ADDR_SPAN             0x5a
#define CTAG_S_VARM_CRIT_UPDATE_RBIT3                                0x84
#define CTAG_S_FROM_NS_VARM_API_OTP_ACCESS_INTERNAL                  0x67
#define CTAG_S_FROM_NS_VARM_API_GET_PARTITION_TABLE_INFO             0x9c

#define CTAG_S_FROM_NSBOOT_VARM_OTP_ACCESS                           0xa9
#define CTAG_S_FROM_NS_VARM_API_GET_SYS_INFO                         0xbb
#define CTAG_S_OTP_CONFIGURE_RQ_CQ                                   0x5e
#define CTAG_S_HX_OTP_GET_RBIT3_GUARDED                              0x6a
#define CTAG_SG_CALL                                                 0x60
#define CTAG_S_FROM_NS_ARM8_API_CHECKED_FLASH_OP                     0x96
#define CTAG_S_FROM_NS_ARM8_API_FLASH_RUNTIME_TO_STORAGE_ADDR        0xab
#define CTAG_SB_HMAC_SHA256_REINIT                                   0xa3
#define CTAG_SB_SW_POINT_MULT_ADD_APPLY_Z                            0xa2
#define CTAG_SB_SW_POINT_MULT_ADD_Z_UPDATE                           0x53
#define CTAG_S_VARM_OTP_SBPI_WRITE_BYTE                              0x9e
#define CTAG_S_SHA256_FINISH                                         0x92
#define CTAG_SB_FE_INTERP                                            0xb6
#define CTAG_S_VARM_API_GET_UF2_TARGET_PARTITION                     0xa7
#define CTAG_S_VARM_CRIT_LOAD_INIT_CONTEXT_AND_PREPARE_FOR_RESIDENT_PARTITION_TABLE_LOAD 0xb4
#define CTAG_S_VARM_RAM_TRASH_GET_UF2_TARGET_PARTITION_WORKAREA      0x58
#define CTAG_SB_FE_ADC_SBC                                           0xaf
#define CTAG_SB_SW_ZSCALAR_VALIDATE                                  0x7f
#define CTAG_SB_FE_CMP                                               0xbc
#define CTAG_SB_FE_MOV                                               0x99
#define CTAG_SB_FE_MOD_INV_R                                         0x8f
#define CTAG_S_VARM_STEP_SAFE_HX2_GET_BOOT_FLAG_IMPL                 0xbd
#define CTAG_SB_SW_VERIFY_CONTINUE_AND_FINISH                        0x40
#define CTAG_S_VARM_MAKE_HX2_BOOL_IMPL                               0x56
#define CTAG_S_SAVE_CLEAR_AND_DISABLE_MPU                            0xbe
#define CTAG_SB_FE_HARD                                              0x4b
#define CTAG_S_VARM_CHECK_SCAN_WORK_AREA_AND_CHECK_SHA_LOCK          0x8c

#if defined(__riscv) || !defined(FEATURE_CANARIES)
#define canary_entry(tag) ((void)0)
#define canary_entry_reg(reg, tag) ((void)0)
#define canary_exit_return(tag, rc) return rc
#define canary_exit_void(tag) ((void)0)
#define canary_set_step(step) ((void)0)
#define canary_check_step(step) ((void)0)
#else
#define TAG_CR(tag) (CTAG_##tag)

// load a canary value from the coprocessor onto a stack variable
//
// Note for code size reasons we don't store the canary on the stack
// ourselves, we just keep the value live through the function and let the
// compiler figure things out. It at least gives you some confidence, as you
// leave through the back door, that you came in through the front door.

#define canary_entry(tag) volatile uint32_t __stack_canary_value = rcp_canary_get_nodelay(TAG_CR(tag))
#define canary_entry_reg(reg, tag) register volatile uint32_t __stack_canary_value asm (__STRING(reg)) = rcp_canary_get_nodelay(TAG_CR(tag))

#define canary_exit_void(tag) rcp_canary_check_nodelay(TAG_CR(tag), __stack_canary_value)

#define canary_exit_return(tag, rc) ({ rcp_canary_check_nodelay(TAG_CR(tag), __stack_canary_value); return rc; })

// Note step must be a constexpr as this is mangled into asm.
#define canary_set_step(step)   do {static_assert(step >= 0 && step < 256, ""); rcp_count_set_nodelay(step);  } while (0)
#define canary_check_step(step) do {static_assert(step >= 0 && step < 256, ""); rcp_count_check_nodelay(step);} while (0)

#endif
