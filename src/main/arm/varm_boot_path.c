/*
 * Copyright (c) 2023 Raspberry Pi (Trading) Ltd.
 *
 * SPDX-License-Identifier: BSD-3-Clause
 */

#include "hardware/regs/tbman.h"
#include "hardware/structs/accessctrl.h"
#include "hardware/structs/clocks.h"
#include <hardware/structs/padsbank0.h>
#include <hardware/structs/pads_qspi.h>
#include "hardware/structs/powman.h"
#include "hardware/structs/psm.h"
#include "hardware/structs/sio.h"
#include "hardware/structs/trng.h"
#include "hardware/structs/watchdog.h"
#include "hardware/resets.h"
#include "native_generic_flash.h"
#include "mini_printf.h"
#include "varm_resets.h"
#include "varm_boot_path.h"

#if defined(__ARM_ARCH_8M_MAIN__) || !defined(__ARM_ARCH_8M_BASE__)
#error this must be compiled with armv8m-base
#endif

#define varm_to_native_memcpy dont_use_this_here
#define varm_to_native_memset dont_use_this_here
#define varm_to_native_memset0 dont_use_this_here

static void sonly_varm_step_safe_crit_try_vector(hx_bool disabled, mpu_hw_t *mpu_on_arm, io_rw_32 *vector, io_rw_32 *params);

// arm6 + RCP
// note: this should be __noreturn, but it doesn't currently make any difference to code gen, and removing it
//       makes me more confident that skipping the prolog is safe (i.e. it isn't going to overwrite any of the stacked registers)
void __used sonly_varm_crit_core0_boot_path_prolog(void) {
    // argh... we can't force GCC not to do a prolog, so we're wasting instructions above, but we can skip
    // all but the last "sub sp"
    asm volatile (".global s_varm_crit_core0_boot_path_entry_p2\n"
                  ".thumb_func\n"
                  "s_varm_crit_core0_boot_path_entry_p2:\n");

    // default to secure until we know otherwise;  note always1 as we had always as a variable below, and
    // we don't want it to live all the way from here
    typeof(bootram->always ) *always1 = __get_opaque_ptr(&bootram->always);
    always1->secure = hx_xbool_invalid();

    // Generally, core 1 is reset whenever core 0 is reset, so right now it is
    // either blocked or is about to be blocked:
    //
    // - Both cores are Arm     -> core 1 polling RCP salt (always readable)
    // - At least one is RISC-V -> core 1 polling SIO FIFO (always readable)
    //
    // In either case, core 1 does not use any stack etc until explicitly
    // launched by core 0. (Note IRQ->NMI routing is cleared on warm M33
    // reset, as it's configured by our EPPB reg block).
    //
    // If core 1 is intended to stay alive throughout core 0 boot -- e.g. core
    // 1 is running a self-hosted debug probe, or core 0 is rebooting itself
    // via AIRCR.SYSRESETREQ rather than watchdog -- then user firmware on
    // core 1 must not call ROM functions concurrently with core 0 reset, to
    // avoid RCP failures on empty salt register. Note when secure boot is
    // enabled, we explicitly reset core 1 to prevent it from interfering.

    // 0: reset all access ctrl
    // =====================
    // Reset ACCESSCTRL if it's unlocked; a) to give a known state, but b) because we
    // may not have access to the registers we need if locked down before a
    // warm boot!
    debug_label(step0_reset_access_ctrl);

    accessctrl_hw->cfgreset = ACCESSCTRL_PASSWORD_BITS | ACCESSCTRL_CFGRESET_BITS;

    mpu_hw_t *mpu_on_arm = mpu_hw;
    armv8m_sau_hw_t *sau_on_arm = sau_hw;
    branch_under_non_varmulet(not_varm);
    mpu_on_arm = get_fake_mpu_sau();
    sau_on_arm = __get_opaque_ptr((armv8m_sau_hw_t*)mpu_on_arm);
not_varm: ;

    uint mpu_steps = 0; __dataflow_barrier(mpu_steps);
    inline_s_set_romdata_ro_xn(mpu_on_arm);
    mpu_steps = mpu_steps + 0x01; __dataflow_barrier(mpu_steps);
    inline_s_set_core1_ro_xn(mpu_on_arm);
    // (Limit address is set in inline_s_set_romdata_ro_xn as it's call-once)
    mpu_steps = mpu_steps + 0x02; __dataflow_barrier(mpu_steps);
    inline_s_set_flash_ro_xn(mpu_on_arm);
    mpu_steps = mpu_steps + 0x04; __dataflow_barrier(mpu_steps);
    // note this continues setup of region 0 from set_flash_ro_xn() and enables the region
    uint rlar = 0x1fffffe0 | M33_MPU_RLAR_EN_BITS;
    mpu_on_arm->rlar = rlar;//0x1fffffe0 | M33_MPU_RLAR_EN_BITS;
    inline_s_set_ram_ro_xn(mpu_on_arm);
    mpu_steps = mpu_steps + 0x10; __dataflow_barrier(mpu_steps);
    // note this continues setup of region 0 from set_ram_ro_xn() and enables the region
#if HACK_RAM_BOOTROM_AT
    // This bootrom image is presumed to be running from upper half of RAM:
    mpu_on_arm->rlar = 0x2003ffe0 | M33_MPU_RLAR_EN_BITS;
#else
    // mpu_on_arm->rlar = 0x2fffffe0 | M33_MPU_RLAR_EN_BITS;
    pico_default_asm("movt %0, #0x2fff" : "+l" (rlar));
    bootrom_assert(MISC, __get_opaque_value(rlar) == (0x2fffffe0 | M33_MPU_RLAR_EN_BITS));
    mpu_on_arm->rlar = rlar;
#endif
    mpu_steps = mpu_steps + 0x20; __dataflow_barrier(mpu_steps);
    inline_s_enable_mpu(mpu_on_arm);
    mpu_steps = mpu_steps + 0x80; __dataflow_barrier(mpu_steps);
    // we will assert on mpu_hw->ctrl being correct once RCP is up

    // 1: check_rescue
    // ===============
    debug_label(step1_check_rescue);
    // If the rescue flag is set in PoR block, we should halt immediately.
    // (presumably some lethal code is in flash which would stop the debugger from
    // communicating with the processors).
    uint32_t chip_reset = powman_hw->chip_reset;
    if (chip_reset & POWMAN_CHIP_RESET_RESCUE_FLAG_BITS) {
        // Acknowledge and halt (note we write all currently set bits, but the rescue
        // flag is the only WC bit). We must use the powman write password.
        powman_hw->chip_reset = POWMAN_PASSWORD_BITS | POWMAN_CHIP_RESET_RESCUE_FLAG_BITS;
        varm_wait_rescue();
    }

    // we want to reset our diagnostics if bootram has been cleared. there isn't an ideal
    // test for this, but a zero reason means we didn't come through the watchdog.
    // we are either a RUN/cold boot, or a debugger reset, which we cannot detect
    if (!watchdog_hw->reason) {
        static_assert((sizeof(bootram->always) & 3) == 0, "");
        uint32_t *clear_ptr = (uint32_t *)always1;
        uint count = sizeof(bootram->always) / 4;
        // if we didn't watchdog reboot, then the BOOTRAM is in an indeterminate state, so
        // we should clear the "always" data
        pico_default_asm_volatile(
                "1:\n"
                "stmia %[clear_ptr]!, {%[zero]}\n"
                "subs %[count], #1\n"
                "bne 1b\n"
                : [count] "+&l" (count), [clear_ptr] "+&l" (clear_ptr)
                : [zero] "l" (0)
        );
        //always->zero_init.flash_devinfo = FLASH_DEFAULT_DEVINFO;
        static_assert(FLASH_DEFAULT_DEVINFO == 0xc00, "");
        ((uint8_t *)&always1->zero_init.flash_devinfo)[1] = 0xc;
        // most likely thing people want to look at slot 0 (note this also clears other fields to -1)
        always1->boot_word = (uint32_t)BOOT_PARTITION_SLOT0;
        bootrom_assert(MISC, bootram->always.diagnostic_partition_index == BOOT_PARTITION_SLOT0);
        bootrom_assert(MISC, bootram->always.recent_boot.partition == BOOT_PARTITION_NONE);
        // this is an invalid value, but is overwritten below anyway
        bootrom_assert(MISC, bootram->always.boot_type == (uint8_t)-1);
        bootrom_assert(MISC, bootram->always.boot_diagnostic == 0);
    }

    // 2: open system clock gates
    // ==========================
    debug_label(step2_enable_clock_gates);

    // Make sure all the control registers we are about to access are being clocked.
    // On a cold boot everything will be set up by the power-on state machine,
    // but the clock setup may be dirty on a warm boot.

    // On a cold boot, the clocks will already be enabled, because the power-on state
    // machine will have reset the clock controls. However, we can have trouble on a warm
    // boot, that is to say:
    // - The debugger has just reset the processors and started them running
    // - The watchdog has fired, with WDSEL selecting a restart point after
    //   clocks_bank_default.
    // Assume that enough clocks are already enabled to run this code!
    // Note it is NOT recommended to disable things like ROM clock if WDSEL is
    // later than CLOCKS_BANK_DEFAULT.

    // This is done early as we need to ensure the TRNG is clocked.

#if !defined(CLOCKS_WAKE_EN1_OFFSET) || defined(CLOCKS_WAKE_EN2_OFFSET)
#error "Number of clock enable registers has changed, update varm_boot_path"
#endif

    io_rw_32 *clocks_wake_en = __get_opaque_ptr(&clocks_hw->wake_en0);
    clocks_wake_en[0] = -1u;
    clocks_wake_en[1] = -1u;

    // 3: Reset TRNG, get random data for RCP seeds and per-boot-random.
    // ================================================================
    debug_label(step3_get_boot_random);

    // inline_s_varm_reset_unreset_block_wait(RESETS_RESET_TRNG_BITS | RESETS_RESET_SHA256_BITS);
    hw_set_bits(&resets_hw->reset, RESETS_RESET_TRNG_BITS | RESETS_RESET_SHA256_BITS);
    hw_clear_bits(&resets_hw->reset, RESETS_RESET_TRNG_BITS | RESETS_RESET_SHA256_BITS);
    // As these are clk_sys-clocked, 1 APB read is sufficient delay (no polling loop)
    (void)*hw_clear_alias(&resets_hw->reset);
    // second read is because I'm feeling generous
    (void)*hw_clear_alias(&resets_hw->reset);

    // Boot RNG is derived by streaming a large number of TRNG ROSC samples
    // into the SHA-256. BOOT_TRNG_SAMPLE_BLOCKS is the number of SHA-256
    // blocks to hash, each containing 384 samples from the TRNG ROSC:
    const unsigned int BOOT_TRNG_SAMPLE_BLOCKS = 25;

    // Sample one ROSC bit into EHR every cycle, subject to CPU keeping up.
    // More temporal resolution to measure ROSC phase noise is better, if we
    // use a high quality hash function instead of naive VN decorrelation.
    // (Also more metastability events, which are a secondary noise source)

    // Each half-block (192 samples) takes approx 235 cycles, so 470 cycles/block.
    uintptr_t trng = (uintptr_t)trng_hw;
    uintptr_t trng_witness;
    sha256_hw_t *sha256 = __get_opaque_ptr(sha256_hw);
    uint32_t _counter;
    // we used 0xff instead of -1 below to set all bits, so make sure there are no bits above bit 7
    static_assert(0xffffff00u == (
            (TRNG_TRNG_DEBUG_CONTROL_RESERVED_BITS | ~TRNG_TRNG_DEBUG_CONTROL_BITS) &
            (TRNG_RND_SOURCE_ENABLE_RESERVED_BITS | ~TRNG_RND_SOURCE_ENABLE_BITS) &
            (TRNG_RNG_ICR_RESERVED_BITS | ~TRNG_RNG_ICR_BITS) & ~0xffu), "");
    pico_default_asm_volatile (
        "movs %[witness], #1\n"
        "str %[witness], [%[trng], %[offset_trng_sw_reset]]\n"
        // Fixed delay is required after TRNG soft reset -- this plus
        // following sha256 write is sufficient:
        "ldr %[counter], [%[trng], %[offset_trng_sw_reset]]\n"
        // (reads as 0 -- initialises counter to 0.)
        // Initialise SHA internal state by writing START bit
        "movw r1, %[sha256_init]\n"
        "str r1, [%[sha256]]\n"
        // This is out of the loop because writing to this register seems to
        // restart the sampling, slowing things down. We don't care if this write
        // is skipped as that would just make sampling take longer.
        "str %[counter], [%[trng], %[offset_sample_cnt1]]\n"
        "adds %[counter], %[iterations] + 1\n"
    "2:\n"
        // TRNG setup is inside loop in case it is skipped. Disable checks and
        // bypass decorrelators, to stream raw TRNG ROSC samples:
        "movs r1, #0xff\n"
        "str r1, [%[trng], %[offset_debug_control]]\n"
        // Start ROSC if it is not already started
        "str r1, [%[trng], %[offset_rnd_source_enable]]\n"
        // Clear all interrupts (including EHR_VLD)
        "str r1, [%[trng], %[offset_rng_icr]]\n"
        // (hoist above polling loop to reduce poll->read delay)
        "movs r0, %[trng]\n"
        "adds r0, %[offset_ehr_data0]\n"
        // Wait for 192 ROSC samples to fill EHR, this should take constant time:
        "movs r2, %[offset_trng_busy]\n"
    "1:\n"
        "ldr  r1, [%[trng], r2]\n"
        "cmp r1, #0\n"
        "bne 1b\n"
        // Check counter and bail out if done -- we always end with a full
        // EHR, which is sufficient time for SHA to complete too.
        "subs %[counter], #1\n"
        "beq 3f\n"
        // r1 should now be 0, and we "check" by using it as the base for the loop count.
        // This 12-byte fragment gets replaced under RISC-V as it's (very) hot code:
        ".hword %c[hint_instr]\n"
        ".global boot_path_rnd_to_sha_start\n"
        "boot_path_rnd_to_sha_start:\n"
        // Copy 6 EHR words to SHA-256, plus garbage (RND_SOURCE_ENABLE and
        // SAMPLE_CNT1) which pads us out to half of a SHA-256 block. This
        // means we can avoid checking SHA-256 ready whilst reading EHR, so
        // we restart sampling sooner. (SHA-256 becomes non-ready for 57
        // cycles after each 16 words written.).
        "adds r1, #8\n"
    "1:\n"
        "ldmia r0!, {r2, r3}\n"
        "str r2, [%[sha256], #4]\n"
        "str r3, [%[sha256], #4]\n"
        "subs r1, #2\n"
        "bne 1b\n"
        ".global boot_path_rnd_to_sha_end\n"
        "boot_path_rnd_to_sha_end:\n"
        // TRNG is now sampling again, having started after we read the last
        // EHR word. Grab some in-progress SHA bits and use them to modulate
        // the chain length, to reduce chance of injection locking:
        "ldr r2, [%[sha256], #8]\n"
        "str r2, [%[trng], %[offset_trng_config]]\n"
        // Repeat for all blocks
        "adds %[witness], #0x55\n"
        "b.n 2b\n"
    "3:\n"
        // Done -- turn off rand source as it's a waste of power, and wipe SHA
        // bits left in TRNG config. r1 is known to be 0 (even on RISC-V), so
        // use that.
        "str r1, [%[trng], %[offset_trng_config]]\n"
        "str r1, [%[trng], %[offset_rnd_source_enable]]\n"
        // Function of the actual TRNG pointer we used, and the number of loop iterations
        "muls %[witness], %[trng]\n"
        :
            [counter] "=&l" (_counter),
            [witness] "=&l" (trng_witness),
            // Not actually written, but we tell the compiler to assume such:
            [trng]    "+l"  (trng),
            [sha256]  "+l"  (sha256)
        :
            [hint_instr]               "i" (HINT_OPCODE_BASE + 16 * HINT_TRNG_SHOVELLING),
            [iterations]               "i" (BOOT_TRNG_SAMPLE_BLOCKS * 2),
            [sha256_init]              "i" (SHA256_CSR_RESET | SHA256_CSR_START_BITS),
            [offset_trng_sw_reset]     "i" (TRNG_TRNG_SW_RESET_OFFSET       - TRNG_RNG_IMR_OFFSET),
            [offset_sample_cnt1]       "i" (TRNG_SAMPLE_CNT1_OFFSET         - TRNG_RNG_IMR_OFFSET),
            [offset_debug_control]     "i" (TRNG_TRNG_DEBUG_CONTROL_OFFSET  - TRNG_RNG_IMR_OFFSET),
            [offset_rnd_source_enable] "i" (TRNG_RND_SOURCE_ENABLE_OFFSET   - TRNG_RNG_IMR_OFFSET),
            [offset_rng_icr]           "i" (TRNG_RNG_ICR_OFFSET             - TRNG_RNG_IMR_OFFSET),
            [offset_trng_busy]         "i" (TRNG_TRNG_BUSY_OFFSET           - TRNG_RNG_IMR_OFFSET),
            [offset_ehr_data0]         "i" (TRNG_EHR_DATA0_OFFSET           - TRNG_RNG_IMR_OFFSET),
            [offset_trng_config]       "i" (TRNG_TRNG_CONFIG_OFFSET         - TRNG_RNG_IMR_OFFSET)
        : "r0", "r1", "r2", "r3"
    );
    // No need to wait for SHA, as we polled the EHR one extra time, which
    // takes longer than the SHA.

    // The per-boot random will change on every core 0 reset (except debugger
    // skipping ROM). If this is a problem then the user can sample the
    // per-boot random into a preserved variable in main SRAM.
#if !ASM_SIZE_HACKS
    for (int i = 0; i < 4; ++i) {
        bootram->always.boot_random.e[i] = sha256->sum[i];
    }
    uint32_t sha_sum = (uintptr_t)&sha256->sum[4];
#else
    // we don't care about re-reading from volatile addresses if interrupted
    uint32_t random_elements = (uintptr_t)bootram->always.boot_random.e;
    uint32_t sha_sum = (uintptr_t)&sha256->sum[0];
    pico_default_asm_volatile(
            "ldmia %0!, {r0, r1, r2, r3}\n"
            "stmia %1!, {r0, r1, r2, r3}\n"
            : "+l" (sha_sum), "+l" (random_elements)
            :
            : "r0", "r1", "r2", "r3"
            );
#endif

    // 4: init rcp seeds
    // =================
    debug_label(step4_init_rcp_seeds);
    static_assert(STEPTAG_STEP5_SAU_SANITY_CHECK == 5, ""); // used in asm
    // Flags set by reading rcp_canary_check() into APSR:
    // NZCV
    // 0000 - rcp not initialized
    // 1010 - rcp initialized
    // 1011 - running on RISC-V (so will be initialized)

    // note we have to use explicit registers as we cannot list the register we're using in the clobber list below
    // sha_sum happens to be in r5 already
    register uint32_t r5 asm("r5") = sha_sum;
    register uint32_t r6 asm("r6") = trng_witness;
    rcp_asm (
            // (make sure r5 has correct value on all paths)
            "ldmia r5!, {r0, r1, r2, r3}\n"
            "add r5, r6\n"
            // check if already initialized...
            "mrc p7, #1, r15, c0, c0, #0\n"
            // ... and skip if so. This is done to facilitate debugging through the startup code (which an end
            // user might do), in which case the rcp coprocessor may have already been initialized. In this
            // case, we don't really care what the seed values are, as we're not doing a regular boot.
            //
            // note: an attacker who somehow forces the skip of this initialization is not doing themselves
            // any favors, as all other rcp coprocessor instructions fault when no seed initialization has occurred.
            "bvs 2f\n" // if running under varmulet, want to skip the 32bit ldmia too
            "bmi 1f\n"
            // set core 0 seed
            "mcrr p7, #8, r0, r1, c0\n"
            // set core 1 seed
            "mcrr p7, #8, r2, r3, c1\n"
            // tell core 1 its seed is valid
            "sev\n"
        "1:\n"
            // note we only init the step in the ARM path, so it will be wrong in the RISC-V path but will never be checked
            // hx_set_step(5);
            "mcr p7, #4, r0, c0, c5, #0\n"
            // hack clear of all registers by loading with contents of bootrom, except for r5 which
            // has an expected value we assert on.
            "movs r0, #0\n"
            "ldmia r0, {r1-r4, r6-r12}\n"
        "2:\n"
            : "+l" (r5), "+l" (r6)
            :
            : "r0", "r1", "r2", "r3", "r4", "r7", "r8", "r9", "r10", "r11", "r12", "memory"
            );

    // Don't leave result bits behind in registers (now we have read the last 4 words in the asm above)
    sha256 = __get_opaque_ptr(sha256_hw);
    sha256->csr = SHA256_CSR_RESET | SHA256_CSR_START_BITS;
    hx_assert_equal2i(mpu_steps, 0xb7);

    // Make sure we read all 8 sha words, and did the expected number of TRNG
    // iterations on something that could conceivably have been the TRNG
    hx_assert_equal2i(r5,
        ((uintptr_t)sha256_hw + SHA256_SUM0_OFFSET + 32) +
        ((uintptr_t)trng_hw * (0x55 * 2u * BOOT_TRNG_SAMPLE_BLOCKS + 1))
    );

    // 5: sanity check of SAU configuration
    // ====================================
    debug_label(step5_sau_sanity_check);
    hx_check_step(STEPTAG_STEP5_SAU_SANITY_CHECK);
    // Hardware assertions via RCP are available once it has been seeded.

    // use assembly, because GCC being extra, extra dumb; maybe the register trashing above confuses it
//    rcp_iequal(sau_on_arm->ctrl, M33_SAU_CTRL_ENABLE_BITS);
//    extern char sonly_text_end;
//    rcp_iequal(sau_on_arm->rbar, (uintptr_t)P16_D(sonly_text_end));
    uint32_t tmp = (uintptr_t)sau_on_arm;
    pico_default_asm_volatile(
            "ldmia %[sau]!, {r0, r1, r2, r3}\n"
            "movs r1, %[m33_sau_ctrl_enable_bits]\n"
            ".cpu cortex-m33\n"
            "mcrr p7, #7, r0, r1, c0\n" // rcp_iequal
            ".cpu cortex-m23\n"
            "ldr r1, =%c[sonly_text_end]\n"
            ".cpu cortex-m33\n"
            "mcrr p7, #7, r3, r1, c0\n" // rcp_iequal
            ".cpu cortex-m23\n"
            : [sau] "+l" (tmp)
            : [m33_sau_ctrl_enable_bits] "i" (M33_SAU_CTRL_ENABLE_BITS),
              [sonly_text_end] "i" (P16_CONSTANT(sonly_text_end))
            : "r0", "r1", "r2", "r3", "cc");

    // 6: sanity check of MPU configuration
    // ====================================
    debug_label(step6_mpu_sanity_check);
    hx_check_step(STEPTAG_STEP6_MPU_SANITY_CHECK);
    // use assembly, because GCC being extra, extra dumb; maybe the register trashing above confuses it
//    // sanity check of mpu_on_arm; these would fail on RISC-V but rcp_iequal is a nop
//    rcp_iequal(mpu_on_arm->type, NUM_MPU_REGIONS << 8);
//    // make sure MPU is actually enabled (i.e. mpu_on_arm is correct)
//    rcp_iequal(mpu_on_arm->ctrl, M33_MPU_CTRL_PRIVDEFENA_BITS | M33_MPU_CTRL_ENABLE_BITS);

    tmp = (uintptr_t)mpu_on_arm;
    pico_default_asm_volatile(
            "ldmia %[mpu]!, {r0, r1}\n"
            "ldr r2, =%c[num_mpu_regisionx256]\n"
            ".cpu cortex-m33\n"
            "mcrr p7, #7, r0, r2, c0\n" // rcp_iequal
            ".cpu cortex-m23\n"
            "movs r2, %[ctrl_bits]\n"
            ".cpu cortex-m33\n"
            "mcrr p7, #7, r1, r2, c0\n" // rcp_iequal
            ".cpu cortex-m23\n"
        : [mpu] "+l" (tmp)
        : [num_mpu_regisionx256] "i" (NUM_MPU_REGIONS << 8),
          [ctrl_bits] "i" (M33_MPU_CTRL_PRIVDEFENA_BITS | M33_MPU_CTRL_ENABLE_BITS)
        : "r0", "r1");

    debug_label(step6_trng_sha_check);
    // Sanity check: make sure reset was removed on TRNG and SHA-256
    const uint32_t rng_reset_mask = RESETS_RESET_TRNG_BITS | RESETS_RESET_SHA256_BITS;
    hx_assert_equal2i(resets_hw->reset_done & rng_reset_mask, rng_reset_mask);
    // Sanity check: make sure TRNG EHR was filled by last half-block, and no
    // errors were reported (they ought to be disabled)
    // note trng variable is too far away now, so use real ptr
    hx_assert_equal2i(trng_hw->rng_isr, TRNG_RNG_ISR_EHR_VALID_BITS);

    debug_label(step6_bootram_init);
    // this can be set by try_vector functions if they see the magic USB boot PC
    bootram->pre_boot.enter_nsboot = bootram->pre_boot.boot_to_ram_image = hx_false();
    // this will translate to a flash offset of (0 - XIP_BASE) i.e. 0xf0000000 which cannot match any partition or slot
    bootrom_assert(MISC, !bootram->pre_boot.flash_update_boot_window_base); // should already be cleared
    //bootram->pre_boot.flash_update_boot_window_base = 0;

    static_assert(!(3 & sizeof(bootram->always.zero_init)), "");
    s_varm_step_safe_crit_mem_erase_by_words((uintptr_t)&bootram->always.zero_init, sizeof(bootram->always.zero_init));
    static_assert(!(OTP_DATA_CHIPID0_ROW & 1), "");
    static_assert(sizeof(chip_id_t) == 8, "");
    // save the chip id, so we can always return it irrespective of future OTP permissions
#if 1
        uint t0 = (OTP_DATA_BASE + OTP_DATA_CHIPID0_ROW * 2), t1 = (uintptr_t)(&bootram->always.chip_id), t2, t3;
        pico_default_asm_volatile("ldmia %0!, {%3, %2}\n"
                                  "stmia %1!, {%3, %2}\n"
        : "+l" (t0), "+l" (t1), "=l" (t2), "=l" (t3));
#else
        bootram->always.chip_id = *(const volatile chip_id_t *)(OTP_DATA_BASE + OTP_DATA_CHIPID0_ROW * 2);
#endif
    // note that s_varm_step_safe_api_crit_bootrom_state_reset has weird (but simple return code rules) - it returns it's
    // own argument unless the global state is reset in which case it returns 1.
    static_assert(BOOTROM_STATE_RESET_GLOBAL_STATE != 1, "");
    hx_assert_equal2i(s_varm_step_safe_api_crit_bootrom_state_reset(BOOTROM_STATE_RESET_GLOBAL_STATE), 1);

    uint crit_secure1 = otp_hw->critical & OTP_CRITICAL_SECURE_BOOT_ENABLE_BITS;
    // Secure boot is enabled if any 3 of 8 rows have the SECURE_BOOT_ENABLE bit set.
    int32_t secure_count = 11;
    int32_t secure_count2 = -3;
    int32_t looper = 0;
    static_assert(OTP_DATA_CRIT1_SECURE_BOOT_ENABLE_BITS == 1, "");
    for(;looper<8;looper++) {
        secure_count -= (int32_t)(inline_s_otp_read_raw_guarded(OTP_DATA_CRIT1_ROW + (uint32_t)looper) & OTP_DATA_CRIT1_SECURE_BOOT_ENABLE_BITS);
        secure_count2 += (int32_t)(inline_s_otp_read_raw_guarded(OTP_DATA_CRIT1_ROW + (uint32_t)looper) & OTP_DATA_CRIT1_SECURE_BOOT_ENABLE_BITS);
    }
    hx_assert_equal2i((uint32_t)(secure_count-looper), (uint32_t)-secure_count2);
    bootram->always.secure = make_hx_xbool2(secure_count <= looper, secure_count2 >= 0, hx_bit_pattern_xor_secure());
    // we should match what h/w got
    uint crit_secure2 = otp_hw->critical & OTP_CRITICAL_SECURE_BOOT_ENABLE_BITS;
    hx_assert_bequal(hx_xbool_to_bool(bootram->always.secure, hx_bit_pattern_xor_secure()), make_hx_bool2(crit_secure1, crit_secure2));
    // reset core 1 if secure boot
    crit_secure1 <<= 24;
    static_assert(__builtin_popcount(OTP_CRITICAL_SECURE_BOOT_ENABLE_BITS) == 1, "");
    static_assert(__builtin_popcount(PSM_FRCE_OFF_PROC1_BITS) == 1, "");
    static_assert(PSM_FRCE_OFF_PROC1_BITS == OTP_CRITICAL_SECURE_BOOT_ENABLE_BITS << 24, "");
    hw_set_bits(&psm_hw->frce_off, crit_secure1);

#if MINI_PRINTF
    s_varm_step_safe_reset_unreset_block_wait_noinline(RESETS_RESET_IO_BANK0_BITS);
    hw_write_masked(&padsbank0_hw->io[46],
                    PADS_BANK0_GPIO0_IE_BITS,
                    PADS_BANK0_GPIO0_IE_BITS | PADS_BANK0_GPIO0_OD_BITS | PADS_BANK0_GPIO0_ISO_BITS
    );

    // Configure GPIO 46 as UART TX, then remove isolation which was applied when resetting the pads registers.
    iobank0_hw->io[46].ctrl = IO_BANK0_GPIO46_CTRL_FUNCSEL_VALUE_UART0_TX << IO_BANK0_GPIO0_CTRL_FUNCSEL_LSB;
    hw_clear_bits(&padsbank0_hw->io[46], PADS_BANK0_GPIO0_ISO_BITS);

    // Ensure that clk_peri is running before setting up UART -- this would usually be done later,
    // during nsboot clock setup. Note CLK_SYS is the reset value of this aux mux, so this does not
    // usually glitch -- in any case, we are about to reset the UART inside of mini_printf_init.
    clocks_hw->clk[clk_peri].ctrl = CLOCKS_CLK_PERI_CTRL_ENABLE_BITS |
                                    CLOCKS_CLK_PERI_CTRL_AUXSRC_VALUE_CLK_SYS << CLOCKS_CLK_PERI_CTRL_AUXSRC_LSB;
    mini_printf_init();

    branch_under_varmulet(is_riscv);
    printf("ARM8\n");
    goto is_arm;
is_riscv:
    printf("RISC-V\n");
is_arm:
    printf("BOOTFLAGS: %08x\n", s_varm_step_safe_otp_read_rbit3_guarded(OTP_DATA_BOOT_FLAGS0_ROW));
    printf("PERBOOT RN %08x:%08x:%08x:%08x\n", (int)bootram->always.boot_random.e[0], (int)bootram->always.boot_random.e[1], (int)bootram->always.boot_random.e[2], (int)bootram->always.boot_random.e[3]);
    printf("CHIP_RESET %08x\n", powman_hw->chip_reset);
#endif

    // 7, 8: check boot vectors, powman first
    // =======================================

    // Check for direct-boot magic numbers:
    // - Powman boot 0 / watchdog scratch 4: BOOT_TO_PC_MAGIC
    // - Powman boot 1 / watchdog scratch 5: Entry point ^ -BOOT_TO_PC_MAGIC
    // - Powman boot 2 / watchdog scratch 6: Stack pointer
    // - Powman boot 3 / watchdog scratch 7: Entry point

    // sonly_varm_crit_try_vector may enter a vector directly, or it may set pre_boot.enter_nsboot or
    // preboot.boot_to_ram_image to cause a vectoring action to be taken later. None of these actions
    // should take place when one of the BOOTDIS flags (OTP_BOOTDIS_NOW_BITS or
    // POWMAN_BOOTDIS_NOW_BITS) is set, or when the relevant OTP DISABLE_POWER_SCRATCH /
    // DISABLE_WATCHDOG_SCRATCH flag is set.

    debug_label(step7_check_powman_boot);
    hx_check_step(STEPTAG_STEP7_CHECK_POWMAN_BOOT);
    hx_assert_equal2i(psm_hw->frce_off, crit_secure1);
    hw_clear_bits(&psm_hw->frce_off, crit_secure1);

    // note: try_vector initializes bootram->always.boot_type as a side effect
    sonly_varm_step_safe_crit_try_vector(hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_DISABLE_POWER_SCRATCH_LSB),
                                         mpu_on_arm, &powman_hw->boot[0], NULL);
    // s_varm_try_vector sets step 9
    hx_check_step(STEPTAG_STEP9_CLEAR_BOOTDIS);
    debug_label(step8_check_watchdog_boot);
    // s_varm_try_vector checks step 8, so we must reset
    hx_set_step(STEPTAG_STEP8_TRY_VECTOR);
    io_rw_32 *scratch2 = __get_opaque_ptr(&watchdog_hw->scratch[2]);
    sonly_varm_step_safe_crit_try_vector(hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_DISABLE_WATCHDOG_SCRATCH_LSB),
                                         mpu_on_arm,
                                         scratch2 + 2, // vector == &scratch[4]
                                         scratch2);    // params == &scratch[2]

    printf("once_bit nsboot_api_disable = %d\n", get_boot_once_bit(BOOT_ONCE_NSBOOT_API_DISABLED));

    // 9: clear boot vector disable
    // =============================
    debug_label(step9_clear_bootdis);
    hx_check_step(STEPTAG_STEP9_CLEAR_BOOTDIS);

    powman_hw_t *powman = __get_opaque_ptr(powman_hw);
    if ((otp_hw->bootdis & OTP_BOOTDIS_NOW_BITS) || (powman->bootdis & POWMAN_BOOTDIS_NOW_BITS)) {
        // Confirm the vector-to-image flag is not set if boot vectoring is disabled
        hx_assert_false(bootram->pre_boot.boot_to_ram_image);
    }
    // Unconditionally clear, since clearing when not set is idempotent
    otp_hw->bootdis = OTP_BOOTDIS_NOW_BITS;
    // opaque value to avoid getting too many literals of the form 5afexxxx
    uint32_t powman_password = __get_opaque_value(POWMAN_PASSWORD_BITS);
    powman->bootdis = powman_password | POWMAN_BOOTDIS_NOW_BITS;

    // 10: power up PDsram0/PDsram1
    // =============================

    // At this point we know there are no valid scratch vectors. Power up all
    // SRAM, to prepare to run flash boot or enter BOOTSEL mode. Note PDxip
    // (cache + bootram) is always powered when PDcore is powered.

    debug_label(step10_sram_powerup);
    hx_check_step(STEPTAG_STEP10_SRAM_POWERUP);

    powman_hw_t *powman_clear = __get_opaque_ptr((powman_hw_t *)((uintptr_t)powman + REG_ALIAS_CLR_BITS));
    // First clear all pwrup req enables, because a hardware-sourced request
    // will block a software-sourced request
    static_assert(count_of(powman_clear->pwrup) == 4, "");
    powman_clear->pwrup[0] = powman_password | POWMAN_PWRUP0_ENABLE_BITS;
    powman_clear->pwrup[1] = powman_password | POWMAN_PWRUP0_ENABLE_BITS;
    powman_clear->pwrup[2] = powman_password | POWMAN_PWRUP0_ENABLE_BITS;
    powman_clear->pwrup[3] = powman_password | POWMAN_PWRUP0_ENABLE_BITS;

    powman_clear->timer = powman_password | POWMAN_TIMER_PWRUP_ON_ALARM_BITS;

    // If anything is already in progress, wait for it to complete. Note, we only need to check
    // state changing here. State waiting is only set if powman is waiting for the processor to signal
    // it is ready to power down by calling __wfi
#if !ASM_SIZE_HACKS
#define powman_wait() while (powman->state & POWMAN_STATE_CHANGING_BITS)
#else
#define powman_wait() ({\
        static_assert(POWMAN_STATE_CHANGING_BITS == 0x2000, ""); \
        static_assert((POWMAN_STATE_CHANGING_BITS >> 13) == 1, ""); \
        pico_default_asm_volatile( \
                "1:\n" \
                "ldr %[tmp], [%[powman], %[state_offset]]\n" \
                "lsrs %[tmp], #14\n" \
                "bcs 1b\n"            \
                 : [tmp] "=&l" (tmp) \
                 : [powman] "l" (powman), [state_offset] "i" (offsetof(powman_hw_t, state)) \
                 : "cc" \
        ); \
})
#endif
    powman_wait();
    // Power up SRAMs. As the switched core is definitely not powering down now shouldn't need to check
    // state waiting here either
    powman->state = powman_password | 0u;
    powman_wait();


    // 11: reset hardware needed for main boot path
    // ============================================

    debug_label(step11_main_resets);
    hx_check_step(STEPTAG_STEP11_MAIN_RESETS);

    // Unlike RP2040, we reset *all* pad/IO registers, as we may have bootrom
    // functions on any pin (if so configured by OTP). However, we don't want
    // to disturb any external hardware attached to these GPIOs, so apply
    // isolation to bank 0 IOs before resetting their control registers. This
    // latches pad signals at their current values until isolation is
    // removed. If the pads registers are already in reset (e.g. first boot)
    // then this operation should be harmless.

    // Note __get_opaque_ptr here is to avoid extraneous 32-bit constants for loop bounds
    io_rw_32 *padsbank0_io_set = __get_opaque_ptr(hw_set_alias(&padsbank0_hw->io[0]));
    for (uint i = 0; i < NUM_BANK0_GPIOS; ++i) {
        padsbank0_io_set[i] = PADS_BANK0_GPIO0_ISO_BITS;
    }

    // Note resetting pads here is a convenient way to set QSPI CSn to input.
    // Be careful not to reset hardware that might be used by core-1-as-debug-probe
    const uint32_t rst_mask =
            RESETS_RESET_TIMER0_BITS |
            RESETS_RESET_PADS_QSPI_BITS |
            RESETS_RESET_IO_QSPI_BITS |
#if !MINI_PRINTF
            RESETS_RESET_IO_BANK0_BITS |
#endif
            RESETS_RESET_PADS_BANK0_BITS;
    s_varm_step_safe_reset_unreset_block_wait_noinline(rst_mask);

    // Need to remove isolation from QSPI pins to make CSn readable for
    // BOOTSEL check. (May also be required to make pads assume their reset
    // state, e.g. correct pulls, if this is not our first power up.)
    io_rw_32 *padsqspi_io_clear = __get_opaque_ptr(hw_clear_alias(&pads_qspi_hw->io[0]));
    for (uint i = 0; i < NUM_QSPI_GPIOS; ++i) {
        padsqspi_io_clear[i] = PADS_QSPI_GPIO_QSPI_SCLK_ISO_BITS;
    }

    // mark the resident partition table as invalid. now we're either entering IMAGE_DEF or NSBOOT
    typeof(bootram->always ) *always2 = __get_opaque_ptr(&bootram->always);
        always2->partition_table.counts_and_load_flag = 0;

    // Load flash device info from OTP if it's valid, otherwise use default from flash header
    always2->zero_init.flash_devinfo = FLASH_DEFAULT_DEVINFO;
    if (hx_is_true(hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_FLASH_DEVINFO_ENABLE_LSB))) {
        always2->zero_init.flash_devinfo = (uint16_t)inline_s_otp_read_ecc_guarded(OTP_DATA_FLASH_DEVINFO_ROW);
    }

    // 12: boot path selection
    // =======================
    debug_label(step12_select_boot_path);
    hx_check_step(STEPTAG_STEP12_SELECT_BOOT_PATH);

    // We use USB RAM, so at least the clk_sys side of the USB hw needs to be
    // out of reset. Can't wait for rst_done because clk_usb logic may remain
    // in reset, so read back through same pointer to give sufficient delay.
    unreset_block(RESETS_RESET_USBCTRL_BITS);
    (void) *hw_clear_alias(&resets_hw->reset);

    // we don't clear first part of USB RAM as it may be being used by other core
    bootrom_assert(MISC, (uintptr_t)&core0_boot_usbram_workspace == USBCTRL_DPRAM_BASE + USBCTRL_DPRAM_SIZE - sizeof(core0_boot_usbram_workspace));
    static_assert(sizeof(core0_boot_usbram_workspace) % 4 == 0, "");
    // Note this mem erase is also providing a ~100us min delay between
    // resetting the pads registers, and sampling the CSn/SD1 boot straps.
    s_varm_step_safe_crit_mem_erase_by_words(((uintptr_t)&core0_boot_usbram_workspace), sizeof(core0_boot_usbram_workspace));

    // At this point, if this is an emulated context (on RISC-V hardware), we relocate the emulated
    // register file from bottom of Arm stack redzone in bootram into a dedicated space in USB RAM.
    // This increases available stack and emulation performance. We don't do this earlier because
    // we don't want to trash USB RAM on simple watchdog/powman vector reboots.

    const uint varm_relocate_opcode = HINT_OPCODE_BASE + 16 * HINT_RELOCATE_VARM_REGISTERS;
    pico_default_asm_volatile (
        "movs r0, %1\n"
        "subs r0, %2\n"
        ".hword %c0\n"
        :
        : "i" (varm_relocate_opcode), "l" ((uintptr_t)&core0_boot_usbram_workspace), "i" (VARMULET_CPU_STATE_SIZE)
        : "r0", "cc"
    );

    // Check CSn strap (BOOTSEL) and SD1 strap (UART/nUSB) -- these may or
    // may not be used depending on boot_to_ram_image, flash_disable
    // flags etc, but easiest to sample them once now.
    uint32_t i, sum_cs = 0, sum_sd1 = 0;
    for (i = 0; i < 9; ++i) {
        varm_to_s_native_busy_wait_at_least_cycles(1 * ROSC_MHZ_MAX);
        uint32_t gpio_in_sample = sio_hw->gpio_hi_in;
        sum_cs += (gpio_in_sample >> SIO_GPIO_HI_IN_QSPI_CSN_LSB) & 1u;
        sum_sd1 += (gpio_in_sample >> (SIO_GPIO_HI_IN_QSPI_SD_LSB + 1)) & 1u;
    }
    bool bootsel_button_pressed = sum_cs < 5;
    uint bootsel_serialmode = sum_sd1 >= 5;

    // we skip flash/otp if we are specifically rebooting into USB boot
    // note: we don't ever fallback from nsboot to something else, even if nsboot is disabled in OTP!
    if (hx_is_false_checked(bootram->pre_boot.enter_nsboot)) {
        uint64_t saved_boot_type_and_diagnostics = bootram->always.boot_type_and_diagnostics;
        bootram->always.recent_boot.hword = (uint8_t)BOOT_PARTITION_NONE;
        bootram->always.boot_diagnostic = 0;
        s_varm_crit_init_boot_scan_context(&core0_boot_usbram_workspace,
                                           mpu_on_arm,
                                           true); // executable only
        // used if we aren't doing flash boot
        boot_scan_context_t *ctx = &core0_boot_usbram_workspace.ctx_holder.ctx;
        ctx->booting = hx_true();
        // note: this just controls whether we do the signature check when verifying blocks;
        // were you to set this to true, image launch checks would fail in secure mode.
        ctx->verify_image_defs_without_signatures = false;

        // note if flash_update_boot_window_base is 0, then this will be 0xf0000000 which won't match any slot or partition
        ctx->flash_update_boot_offset = bootram->pre_boot.flash_update_boot_window_base - XIP_BASE;
        ctx->flash_mode = BOOTROM_XIP_MODE_03H_SERIAL;
        ctx->flash_clkdiv = BOOTROM_SPI_CLKDIV_FLASH_BOOT_MAX;
        // the following fields are uninitialized at this point
        //    boot_window_t current_search_window;
        //    uint8_t load_image_counter; // which doesn't matter it just needs to not change from A to B

        if (hx_is_true(bootram->pre_boot.boot_to_ram_image)) {
            printf("Trying RAM boot\n");
            static_assert(offsetof(boot_window_t, base)==0, "");
            static_assert(offsetof(boot_window_t, size)==4, "");
            static_assert(sizeof(boot_window_t) == 8, "");
//            ctx->current_search_window.base = bootram->always.zero_init.reboot_params.e[0];
//            ctx->current_search_window.size = bootram->always.zero_init.reboot_params.e[1];
            ctx->current_search_window = *(boot_window_t *)bootram->always.zero_init.reboot_params.e;
            hx_assert_true(bootram->pre_boot.boot_to_ram_image);
            s_varm_crit_ram_trash_checked_ram_or_flash_window_launch(ctx);
            // note: since we explicitly chose RAM boot, we won't fall thru into OTP/flash
        } else {
            // Detect double tap of RUN pin, if this is enabled as a source of BOOTSEL request.
            // Note this does not need hardening as it's just another way of pressing the
            // BOOTSEL button, and BOOTSEL as a whole can be disabled.
            uint32_t boot_flags1 = s_varm_step_safe_otp_read_rbit3_guarded(OTP_DATA_BOOT_FLAGS1_ROW);
            if (boot_flags1 & OTP_DATA_BOOT_FLAGS1_DOUBLE_TAP_BITS) {
                uint32_t chip_reset_status = powman_hw->chip_reset;
                bool double_tap_flag_set = chip_reset_status & POWMAN_CHIP_RESET_DOUBLE_TAP_BITS;
                bool reset_caused_by_run_pin = chip_reset_status & POWMAN_CHIP_RESET_HAD_RUN_LOW_BITS;
                // Rematerialise to avoid keeping the constant live on the stack:
                powman_password = __get_opaque_value(POWMAN_PASSWORD_BITS);
                if (reset_caused_by_run_pin && double_tap_flag_set) {
                    // Previous delay loop was interrupted, meaning there was
                    // a double tap of the RUN pin.
                    bootsel_button_pressed = true;
                } else if (reset_caused_by_run_pin) {
                    // If this delay loop is interrupted by a reset, we will next
                    // take the `if` branch above, setting the bootsel request.
                    hw_set_bits(&powman_hw->chip_reset, POWMAN_CHIP_RESET_DOUBLE_TAP_BITS | powman_password);
                    // Wait for 50 to 400 ms (configurable)
                    uint double_tap_delay_ms = 50 * (1 + (
                            (boot_flags1 & OTP_DATA_BOOT_FLAGS1_DOUBLE_TAP_DELAY_BITS)
                                    >> OTP_DATA_BOOT_FLAGS1_DOUBLE_TAP_DELAY_LSB
                    ));
                    varm_to_s_native_busy_wait_at_least_cycles(double_tap_delay_ms * 1000 * ROSC_MHZ_TYP);
                }
                // Always clear the flag, to avoid nonconsecutive resets from being misdetected as double taps
                hw_clear_bits(&powman_hw->chip_reset, POWMAN_CHIP_RESET_DOUBLE_TAP_BITS | powman_password);
            }

            if (!bootsel_button_pressed) {
                puts("BOOTSEL not pressed");
                // USB boot API is not available in regular boot
                hx_assert_false(bootram->pre_boot.enter_nsboot);
                hx_bool disable_otp = hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_DISABLE_OTP_BOOT_LSB);
                if (hx_is_false(disable_otp)) {
                    hx_bool enable_otp = hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_ENABLE_OTP_BOOT_LSB);
                    if (hx_is_true(enable_otp)) {
                        s_varm_crit_ram_trash_try_otp_boot(mpu_on_arm, ctx);
                    } else {
                        hx_assert_false(enable_otp);
                    }
                } else {
                    hx_assert_true(disable_otp);
                    puts("boot from otp is disabled; skipping");
                }
                hx_bool disable_flash = hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_DISABLE_FLASH_BOOT_LSB);
                if (hx_is_false(disable_flash)) {
                    debug_label(stepx_flash_boot);
                    hx_assert_false(disable_flash);
                    s_varm_crit_ram_trash_try_flash_boot(&core0_boot_usbram_workspace.ctx_holder.flash_ctx);
                    puts("flash boot returned - i.e. no bootable flash image");
                } else {
                    puts("boot from flash is disabled; skipping");
                }
            } else {
                puts("BOOTSEL pressed, skipping flash boot");
                // restore the recent_boot_info so that it is still available when entering NSBOOT
                bootram->always.boot_type_and_diagnostics = saved_boot_type_and_diagnostics;
                bootram->always.boot_type = BOOT_TYPE_BOOTSEL;
            }
        }
    } else {
        puts("skipping otp/flash boot as resetting to nsboot");
    }
    debug_label(stepx_nsboot_preamble);

    // Soft check of permissions, go to friendly cant_boot handler if permissions are lacking
    // (We'll later perform a hard check via hx assertion on each path)
    // hardening: save space boot flags could be ok
    uint32_t bootsel_flags = 0;
    hx_bool bootsel_disabled;
    // make sure compiler doesn't elide init
    pico_default_asm_volatile("movs %0, #0" : "=r" (bootsel_disabled) : : "cc");
    if (bootsel_serialmode == BOOTSEL_MODE_USB) {
        hx_bool disable_usb_msd      = hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_DISABLE_BOOTSEL_USB_MSD_IFC_LSB);
        hx_bool disable_usb_picoboot = hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_DISABLE_BOOTSEL_USB_PICOBOOT_IFC_LSB);
        printf("disable USB %d PICOBOOT %d\n", hx_is_true(disable_usb_msd), hx_is_true(disable_usb_picoboot));
        bootsel_disabled = hx_and_checked(disable_usb_msd, disable_usb_picoboot);
        bootsel_flags = (uint32_t)(hx_is_true(disable_usb_msd) | (hx_is_true(disable_usb_picoboot) << 1u));
        hx_assert_equal2i(__get_opaque_value(bootsel_serialmode), BOOTSEL_MODE_USB);
    } else {
        // Assumedly, bootsel_serialmode == BOOTSEL_MODE_UART
        bootsel_disabled = hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_DISABLE_BOOTSEL_UART_BOOT_LSB);
        printf("disable UART %d\n", hx_is_true(bootsel_disabled));
        hx_assert_equal2i(bootsel_serialmode, BOOTSEL_MODE_UART);
    }

    debug_label(stepx_nsboot_preamble3);

    uint32_t gpio_pin_config = 0;

    if (hx_is_true(bootram->pre_boot.enter_nsboot)) {
        // note that we might not have booted from watchdog, but if this was a powman boot or a cold
        // boot, then these should be zero.
        bootsel_flags = watchdog_hw->scratch[2] | (bootsel_flags & 3); // don't clear any disabled interfaces
        gpio_pin_config = watchdog_hw->scratch[3];
        if ((bootsel_flags & 3) == 3) bootsel_disabled = hx_true();
    }
    if (hx_is_true(bootsel_disabled)) {
        // using goto here to end of func produces smaller code
        goto cant_boot;
    }

    // At this point we intend to enter the nsboot bootloader, but there are
    // three cases where we must perform an additional watchdog reset rather
    // than entering directly:
    //
    // - If we have reached this point due to a watchdog reset that dropped
    //   through flash boot, and that watchdog reset did *not* reset the
    //   clocks and oscillators, they may be in a dirty state which makes it
    //   unsafe to run the nsboot clock setup.
    //
    // - Similarly if we have reached this point following a watchdog or a
    //   debugger entry that did not reset the bootRAM set-once bits, then
    //   the nsboot->Secure callback interface may be disabled, and must be
    //   re-enabled via reset. Set-once bits can't be cleared without
    //   resetting the processors (by design)
    //
    // - If the clock configuration is dirty (!= power-on state) then the USB
    //   clock setup may e.g. reset PLLs we are running from. Two flavours:
    //
    //   1. We booted a user binary, then debugger halted core 0, and reset it
    //      via SYSRESETREQ. Covered by nsboot interface disable flag above.
    //
    //   2. We halted core 0 whilst in nsboot, and are now trying to reenter
    //      nsboot whilst still running from USB PLL. Detected by clk_ref no
    //      longer running from ROSC.

    const uint32_t wdsel_rosc_or_earlier = (1u << (PSM_FRCE_ON_ROSC_LSB + 1)) - 1;
    bool nsboot_unsafe_watchdog = watchdog_hw->reason != 0 && !(psm_hw->wdsel & wdsel_rosc_or_earlier);
    bool dirty_clk_ref_cfg = clocks_hw->clk[clk_ref].ctrl != CLOCKS_CLK_REF_CTRL_RESET;
    // note | not || to save space vs time
    if (nsboot_unsafe_watchdog | dirty_clk_ref_cfg | get_boot_once_bit(BOOT_ONCE_NSBOOT_API_DISABLED)) {
        // Padded to make sure the important part comes out the UART before reset:
        printf("**** RESETTING INTO NSBOOT              *****\n");
        // Reuse whatever LED pin and interface mask we have calculated,
        // should still be good for the next attempt
        s_varm_api_reboot(REBOOT2_FLAG_REBOOT_TYPE_BOOTSEL | REBOOT2_FLAG_NO_RETURN_ON_SUCCESS,
                          BOOTROM_SHORT_REBOOT_MS, bootsel_flags, gpio_pin_config);
    }

    hx_assert_false(bootsel_disabled);
    pico_default_asm_volatile("s_varm_crit_nsboot_start:");
    s_varm_crit_nsboot(mpu_on_arm, gpio_pin_config, bootsel_flags, bootsel_serialmode);
    // whilst not marked __noreturn for GCC code size reasons, the function cannot actually
    // return, and GCC can even figure this out, so make sure there is no code path that ends here;
    // otherwise we'd want a harder halt than can't boot
    pico_default_asm_volatile("this should not be compiled");
    cant_boot:
    pico_default_asm_volatile(
        "core0_boot_path_cant_boot:\n"
        "b varm_dead_quiet\n"
        "b.n core0_boot_path_cant_boot\n"
        "b.n core0_boot_path_cant_boot\n"
    );
    __builtin_unreachable();
}

static __noinline void sonly_varm_step_safe_crit_try_vector(hx_bool disabled, mpu_hw_t *mpu_on_arm, io_rw_32 *_vector, io_rw_32 *params) {
    canary_entry(S_VARM_CRIT_TRY_VECTOR);
    struct _scratch {
        uint32_t magic;
        uint32_t pc_mod;
        uint32_t sp;
        uint32_t pc;
    };
    volatile struct _scratch *vector = (volatile struct _scratch *)_vector;
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wcast-qual"
    const struct _scratch *nv_vector = (const struct _scratch *)vector;
#pragma GCC diagnostic pop
    // make sure our cheeky use of the bottom of the stack is not a problem
    bootrom_assert(MISC, get_sp() >= (uintptr_t)&bootram->pre_boot.vector_workarea_end);

    bool valid_vector =
            hx_is_false(disabled) &&
            nv_vector->magic == VECTORED_BOOT_MAGIC &&
            (nv_vector->pc_mod ^ -nv_vector->magic) == nv_vector->pc;

    // Note both BOOTDIS flags are always checked: they are not supposed to disable a particular set
    // of scratch registers, rather they disable both and detect different groups of resets.
    uint32_t otp_dis_a = otp_hw->bootdis;
    uint32_t powman_dis_a = powman_hw->bootdis;
    uint32_t otp_dis_b = otp_hw->bootdis;
    uint32_t powman_dis_b = powman_hw->bootdis;
    // note _u wich accepts non-boolean (avoid cast to bool) values which must be 0 or 1
    static_assert(OTP_BOOTDIS_NOW_BITS == 1, "");
    static_assert(POWMAN_BOOTDIS_NOW_BITS == 1, "");
    hx_bool bootdis_set = make_hx_bool2_u((otp_dis_a | powman_dis_a) & 1, (otp_dis_b | powman_dis_b) & 1);

    uint32_t boot_type = BOOT_TYPE_NORMAL;
    typeof(bootram->always) *always = &bootram->always;
    if (valid_vector) {
        uint32_t magic = vector->magic;
        // Always clear vectors, to make it safe to clear BOOTDIS later.
        vector->magic = 0;
        hx_assert_equal2i(magic, VECTORED_BOOT_MAGIC);
        hx_assert_equal2i((uintptr_t)vector >> 28, SYSINFO_BASE >> 28);
        hx_assert_equal2i(vector->magic, 0);
        // For POWMAN vector, we don't pass extra params (watchdog_hw->scratch[2..3]), so you don't
        // get any of the fancy magic-PC types. Note REBOOT_TO_MAGIC_PC is not a valid instruction
        // address, so trying to use the magic types with POWMAN vector will promptly crash.
        if (nv_vector->pc == REBOOT_TO_MAGIC_PC && params) {
            boot_type = nv_vector->sp;
            // Entering nsboot is still permitted when BOOTDIS is set, but user-defined vectoring is not.
            typeof(bootram->pre_boot) * pre_boot = __get_opaque_ptr(&bootram->pre_boot);
            always->zero_init.reboot_params = *(volatile uint32_pair_t *)params;
            printf("BOOT PARAMS %08x %08x\n", always->zero_init.reboot_params.e[0], always->zero_init.reboot_params.e[1]);
            if (boot_type == BOOT_TYPE_BOOTSEL) {
                pre_boot->enter_nsboot = hx_true();
                printf("VECTOR has BOOTSEL type\n");
            } else {
                if (boot_type == BOOT_TYPE_FLASH_UPDATE) {
                    // note: this doesn't require a bootdis check, because it is still a "real" boot, and in secure mode
                    // it must pass signature and rollback checks
                    pre_boot->flash_update_boot_window_base = params[0];
                    printf("VECTOR has FLASH_UPDATE window base of %08x\n", pre_boot->flash_update_boot_window_base);
                } else if (boot_type == BOOT_TYPE_RAM_IMAGE && hx_is_false(bootdis_set)) {
                    hx_bool disable_ram = hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_DISABLE_SRAM_WINDOW_BOOT_LSB);
                    printf("VECTOR has RAM boot into window range %08x->%08x\n", params[0], params[1]);
                    if (hx_is_false(disable_ram)) {
                        pre_boot->boot_to_ram_image = hx_true();
                        hx_assert_false(bootdis_set);
                        hx_assert_false(disable_ram);
                    } else {
                        printf("  .. but RAM boot is disabled by OTP\n");
                    }
                }
            }
        } else if (hx_is_false(bootdis_set)) {
            printf("VECTOR has PC/SP %08x/%08x\n", nv_vector->pc, nv_vector->sp);
            // note: you can still return and enter nsboot, but we will reset to do so
            set_boot_once_bit(BOOT_ONCE_NSBOOT_API_DISABLED);
            // re-enable default access control
            mpu_save_state_t save_state;
            s_save_clear_and_disable_mpu(mpu_on_arm, &save_state); // re-enable rwx
            hx_assert_false(disabled);
            // Hoist the check_step in this case, to make sure it is before the call
            mini_printf_flush();
            always->boot_type = BOOT_TYPE_PC_SP;
            hx_check_step(STEPTAG_STEP8_TRY_VECTOR);
            hx_assert_false(bootdis_set);
            uint32_t pc = vector->pc;
            hx_assert_equal2i(vector->pc_mod ^ -magic, pc);
            hx_assert_equal2i(pc, nv_vector->pc);
            canary_set_step(STEPTAG_S_VARM_SECURE_CALL);
            varm_to_s_native_secure_call_pc_sp(nv_vector->pc, nv_vector->sp);
            // note if this returns, it returns with STEPTAG_STEP7_TRY_VECTOR as the count again
            s_restore_and_enable_mpu(mpu_on_arm, &save_state);
        }
        hx_assert_false(disabled);
    }
    hx_check_step(STEPTAG_STEP8_TRY_VECTOR);
    always->boot_type = (uint8_t)boot_type;
    canary_exit_void(S_VARM_CRIT_TRY_VECTOR);
}

void __attribute__((noreturn)) bootrom_assertion_failure(__unused const char *fn, __unused uint line) {
#if MINI_PRINTF
    printf("ASSERTION FAILURE %s:%d\n", fn, line);
#endif
    __breakpoint();

    __builtin_unreachable();
}

void s_varm_crit_ram_trash_try_otp_boot(mpu_hw_t *mpu_on_arm, boot_scan_context_t *ctx) {
    debug_label(stepx_otp_boot);
    uint32_t dst;
    if (!(OTP_DATA_OTPBOOT_DST0_ROW & 1) && OTP_DATA_OTPBOOT_DST0_ROW + 1 == OTP_DATA_OTPBOOT_DST1_ROW) {
        dst = inline_s_otp_read_ecc2_guarded(OTP_DATA_OTPBOOT_DST0_ROW);
    } else {
#if !(!(OTP_DATA_OTPBOOT_DST0_ROW & 1) && OTP_DATA_OTPBOOT_DST0_ROW + 1 == OTP_DATA_OTPBOOT_DST1_ROW)
#error
        // This should be DCE'd if noone messes up the OTP layout
        dst = (
            inline_s_otp_read_ecc_guarded(OTP_DATA_OTPBOOT_DST0_ROW) |
            (inline_s_otp_read_ecc_guarded(OTP_DATA_OTPBOOT_DST1_ROW) << 16)
        );
#endif
    }
    uint32_t src_row = inline_s_otp_read_ecc_guarded(OTP_DATA_OTPBOOT_SRC_ROW);
    uint32_t len_rows = inline_s_otp_read_ecc_guarded(OTP_DATA_OTPBOOT_LEN_ROW);

    printf("Trying OTP boot: SRC_ROW %04x ROWS %04x load at %08x\n", src_row, len_rows, dst);

    uint32_t dest_limit = dst + 2 * len_rows;
    bool dst_out_of_bounds = dst < SRAM_BASE || dest_limit >= SRAM_END || dest_limit < dst;
    // No unsigned wrap check as these are both < 2^16:
    bool src_out_of_bounds = src_row + len_rows >= NUM_OTP_ROWS;
    bool bad_alignment = ((src_row | len_rows) & 0x1) || (dst & 0x3);
    if (dst_out_of_bounds || src_out_of_bounds || bad_alignment) {
        printf("Bad OTP address/size combination, refusing to load\n");
        return;
    }

    volatile uint32_t *dstp = (volatile uint32_t*)dst;
    io_ro_32 *srcp = (io_ro_32*)((const volatile void*)otp_data_guarded + 2 * src_row);
//    inline_s_set_ram_rw_xn(mpu_on_arm);
    // --- begin expansion
    mpu_on_arm->rnr = 0;
    // 0u for M33_MPU_RBAR_AP_LSB is r/w privileged only
    uint32_t rbar_ram_rw_xn = SRAM_BASE | (0u << M33_MPU_RBAR_AP_LSB) | (M33_MPU_RBAR_XN_BITS);
    mpu_on_arm->rbar = rbar_ram_rw_xn;
    // --- end expansion

#if !ASM_SIZE_HACKS
    for (uint i = 0; i < len_rows; i += 2) {
        *dstp++ = *srcp++;
    }
#else
    // Slightly smaller than whatever GCC was doing (a mystery), and much faster under RISC-V:
    uint32_t garbage;
    pico_default_asm_volatile(
        "b 2f\n"
    "1:\n"
        "ldmia %0!, {%2}\n"
        "stmia %1!, {%2}\n"
    "2:\n"
        "cmp %0, %3\n"
        "blo 1b\n"
        : "+l" (srcp), "+l" (dstp), "=&l" (garbage)
        : "r" (srcp + (len_rows >> 1))
        : "cc"
    );
#endif

    // inline_s_set_ram_ro_xn(mpu_on_arm);
    // --- begin expansion
    // skip rnr write as it is unmodified
    // mpu_on_arm->rnr = 0;
    // 2u for M33_MPU_RBAR_AP_LSB is r/o privileged only
    uint32_t rbar_ram_ro_xn = __get_opaque_value(rbar_ram_rw_xn) + (2u << M33_MPU_RBAR_AP_LSB);
    mpu_on_arm->rbar = rbar_ram_ro_xn;
    // --- end expansion

    // We re-use the RAM boot path -- requires signature if secure boot is enabled, etc,
    // which is why we aren't too fussy at this point about validating what we just copied.
    ctx->current_search_window.base = dst;
    ctx->current_search_window.size = len_rows * 2;
    s_varm_crit_ram_trash_checked_ram_or_flash_window_launch(ctx);
}

static __force_inline uint8_t inline_s_get_current_cpu_type(void) {
    uint32_t archsel_bits = otp_hw->archsel_status;
    static_assert(PICOBIN_IMAGE_TYPE_EXE_CPU_RISCV == 1, "");
    static_assert(PICOBIN_IMAGE_TYPE_EXE_CPU_ARM == 0, "");
    static_assert(OTP_ARCHSEL_CORE0_BITS == 1, "");
    static_assert(OTP_ARCHSEL_CORE1_BITS == 2, "");
    return (archsel_bits >> get_core_num()) & 1;
}

void s_varm_crit_init_boot_scan_context(scan_workarea_t *scan_workarea,
                                        mpu_hw_t *mpu_on_arm,
                                        bool executable_image_def_only) {
    canary_entry(S_VARM_CRIT_INIT_BOOT_SCAN_CONTEXT);
    boot_scan_context_t *ctx = &scan_workarea->ctx_holder.ctx;
    ctx->mpu_on_arm = mpu_on_arm;
    ctx->signed_partition_table_required = hx_and_checked(hx_xbool_to_bool(bootram->always.secure,
                                                                             hx_bit_pattern_xor_secure()),
                                                           hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_SECURE_PARTITION_TABLE_LSB));
    ctx->hashed_partition_table_required = hx_step_safe_get_boot_flagx(OTP_DATA_BOOT_FLAGS0_HASHED_PARTITION_TABLE_LSB);
    ctx->rollback_version_required = hx_step_safe_get_boot_flagx(OTP_DATA_BOOT_FLAGS0_ROLLBACK_REQUIRED_LSB);
    ctx->executable_image_def_only = executable_image_def_only;
    ctx->boot_cpu = inline_s_get_current_cpu_type();
    ctx->scan_workarea = scan_workarea;
    ctx->dont_scan_for_partition_tables = hx_step_safe_get_boot_flag(OTP_DATA_BOOT_FLAGS0_SINGLE_FLASH_BINARY_LSB);
#if FEATURE_EXEC2
    ctx->exec2 = hx_false();
#endif
#if !SILICON_BUILD
    // should always be initialized when used
    ctx->diagnostic = (uint16_t *)0xf0000000;
#endif
    // these must be initialized by caller
    //    ctx->booting
    //    ctx->loading_pt_only
    //    ctx->window_base =
    //    ctx->window_size =
    //    ctx->flash_update_boot_offset = INVALID_FLASH_UPDATE_BOOT_OFFSET
    //    ctx->allow_varmulet =
    //    ctx->flash_mode =
    //    ctx->flash_clkdiv =
    canary_exit_void(S_VARM_CRIT_INIT_BOOT_SCAN_CONTEXT);
}

// note this must return true if and only if the address is something we would
// be willing to load to (e.g. not an IO register)
bool __exported_from_arm __attribute__((section(".text.s_code"))) varm_is_sram_or_xip_ram(uint32_t addr) {
    static_assert((SRAM_BASE & ((1u << 25) - 1)) == 0, "");
    static_assert((XIP_BASE & ((1u << 25) - 1)) == 0, "");
    static_assert((XIP_END & ((1u << 25) - 1)) == 0, "");
    static_assert((SRAM_BASE >> 25) == 0x10, "");
    static_assert((SRAM_END >> 25) == 0x10, "");
    canary_entry_reg(ip, VARM_IS_SRAM_OR_XIP_RAM);
    bool rc = (addr >> 14) == (XIP_SRAM_BASE >> 14) || ((addr >> 25) == 0x10 && addr < SRAM_END);
    canary_exit_return(VARM_IS_SRAM_OR_XIP_RAM, rc);
}
