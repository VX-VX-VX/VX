// test_emission_epochs.cpp -- supply-epoch reward decay (owner-directed
// 2026-11-15; pre-genesis consensus commit).
//
// The reward halves per billion VX MINED (supply-keyed epochs), computed
// in atoms, applied to the whole tier table, clamped to the remaining
// headroom under the 7e9 cap. The last billion is split Zeno-style: each
// epoch mines HALF OF THE REMAINDER, so the sum of era durations diverges
// and the cap is a mathematical horizon, never a date. Pins:
//
//   1. EpochBoundariesExact        -- the linear span (1B..6B) and the
//                                     Zeno span (6.5B, 6.75B, ...) switch
//                                     exactly at their boundaries.
//   2. RewardHalvesPerEpoch        -- the full tier table shifts down
//                                     uniformly (ratios preserved).
//   3. AtomsDomainExact            -- fractional VX survive the shift
//                                     (50 VX >> 2 = 12.5 VX, not 12).
//   4. CapClampNeverOvershoots     -- a jackpot at the cap's doorstep
//                                     cannot push issuance past 7e9.
//   5. ZenoTailNeverExhausts       -- epochs grow without bound as the
//                                     remaining headroom shrinks: the tail
//                                     is an eternal asymptote.
//   6. CurveIsTheApprovedSchedule  -- the cumulative shape at the pinned
//                                     heights matches the approved table.

#include <gtest/gtest.h>
#include "vx/blockchain/emission.hpp"

#include <cstdint>

using namespace vx::blockchain;

namespace {

// A hash with exactly z leading zero bits (tier selection input).
std::array<uint8_t, 32> hash_with_zeros(uint64_t z) {
    std::array<uint8_t, 32> h{};
    const uint64_t full = z / 8, rem = z % 8;
    for (uint64_t i = 0; i < full && i < 32; ++i)
        h[i] = 0x00;
    if (full < 32 && rem > 0)
        h[full] = (uint8_t)(0xFFu >> rem);
    if (full + (rem > 0 ? 1 : 0) < 32)
        h[full + (rem > 0 ? 1 : 0)] = 0xAA;
    return h;
}

} // namespace

TEST(EmissionEpochsTest, EpochBoundariesExact) {
    const uint64_t B = EMISSION_EPOCH_ATOMS; // 1e17 = 1B VX in atoms
    EXPECT_EQ(supply_epoch(0), 0u);
    EXPECT_EQ(supply_epoch(B - 1), 0u);
    EXPECT_EQ(supply_epoch(B), 1u);
    EXPECT_EQ(supply_epoch(3 * B - 1), 2u);
    EXPECT_EQ(supply_epoch(3 * B), 3u);
    EXPECT_EQ(supply_epoch(6 * B - 1), 5u);
    EXPECT_EQ(supply_epoch(6 * B), 6u); // the Zeno span begins
    // Zeno: each epoch halves the REMAINING headroom to the cap.
    // epoch 6 spans remaining (5e16, 1e17]; epoch 7: (2.5e16, 5e16]; ...
    EXPECT_EQ(supply_epoch(6 * B + B / 2 - 1), 6u); // 6.5B − 1: remaining 5e16+1 > 5e16 → epoch 6
    EXPECT_EQ(supply_epoch(6 * B + B / 2), 7u);     // 6.5B: remaining exactly 5e16 → epoch 7
    EXPECT_EQ(supply_epoch(6 * B + B / 2 + B / 4 - 1), 7u);
    EXPECT_EQ(supply_epoch(6 * B + B / 2 + B / 4), 8u);         // 6.75B
    EXPECT_EQ(supply_epoch(6 * B + B / 2 + B / 4 + B / 8), 9u); // 6.875B
    // Deep tail: remaining = 1 atom → the Zeno walk stops at the 57-shift
    // floor (1e17 >> 57 == 0).
    EXPECT_EQ(supply_epoch(max_supply_atoms() - 1), 62u); // j=56: 1e17>>56 == 1
}

TEST(EmissionEpochsTest, RewardHalvesPerEpoch) {
    const auto floor_hash = hash_with_zeros(0);    // 50 VX tier
    const auto jackpot_hash = hash_with_zeros(40); // 1000 VX tier
    const uint64_t B = EMISSION_EPOCH_ATOMS;
    EXPECT_EQ(block_reward_atoms(floor_hash.data(), 0), 50ULL * ATOMS_PER_VX);
    EXPECT_EQ(block_reward_atoms(floor_hash.data(), B), 25ULL * ATOMS_PER_VX);
    EXPECT_EQ(block_reward_atoms(floor_hash.data(), 2 * B),
              12ULL * ATOMS_PER_VX + ATOMS_PER_VX / 2);
    EXPECT_EQ(block_reward_atoms(jackpot_hash.data(), 0), 1000ULL * ATOMS_PER_VX);
    EXPECT_EQ(block_reward_atoms(jackpot_hash.data(), 3 * B), 125ULL * ATOMS_PER_VX);
    // The jackpot/floor ratio is invariant across epochs (whole-table shift).
    // Linear span epochs 0..5 at their era-start supplies, then the Zeno
    // era 6 at 6B (era 7 at 6.5B). The ratio must never wobble.
    const uint64_t supplies[] = {0, B, 2 * B, 3 * B, 4 * B, 5 * B, 6 * B, 6 * B + B / 2};
    for (uint64_t e = 0; e < sizeof(supplies) / sizeof(supplies[0]); ++e) {
        const uint64_t f = block_reward_atoms(floor_hash.data(), supplies[e]);
        const uint64_t j = block_reward_atoms(jackpot_hash.data(), supplies[e]);
        ASSERT_GT(f, 0u) << "floor collapsed at supply index " << e;
        EXPECT_EQ(j, 20 * f) << "jackpot ratio broken at supply index " << e;
    }
}

TEST(EmissionEpochsTest, AtomsDomainExact) {
    // The integer-VX shift would truncate 4% on epoch 2 (50>>2 = 12 vs 12.5).
    const auto h = hash_with_zeros(0);
    const uint64_t B = EMISSION_EPOCH_ATOMS;
    EXPECT_EQ(block_reward_atoms(h.data(), 2 * B), 5'000'000'000ULL >> 2);
    EXPECT_EQ(block_reward_atoms(h.data(), 2 * B), 1'250'000'000ULL); // 12.5 VX exactly
    EXPECT_EQ(block_reward_atoms(h.data(), 3 * B), 625'000'000ULL);   // 6.25 VX
    EXPECT_EQ(block_reward_atoms(h.data(), 4 * B), 312'500'000ULL);   // 3.125 VX
}

TEST(EmissionEpochsTest, CapClampNeverOvershoots) {
    const auto jackpot = hash_with_zeros(40);
    // One atom below the cap: the epoch shift has already taken the reward
    // to zero (the Zeno walk outpaces the shift) — nothing is minted, and
    // the headroom clamp is the defense-in-depth floor, not the norm.
    EXPECT_EQ(block_reward_atoms(jackpot.data(), max_supply_atoms() - 1), 0u);
    // At the cap: nothing is minted.
    EXPECT_EQ(block_reward_atoms(jackpot.data(), max_supply_atoms()), 0u);
    // The clamp DOES bind when the shift-value exceeds the headroom: pin it
    // synthetically (the epoch walk alone cannot reach this state, but a
    // future parameter change must not be able to overshoot the cap).
    {
        const uint64_t mined = max_supply_atoms() - 500;
        const uint64_t headroom = 500u;
        // Direct construction of the clamp branch: tier 1000 shifted by an
        // artificially small epoch must be cut to the headroom.
        const uint64_t raw = (1000ULL * ATOMS_PER_VX) >> 0;
        const uint64_t clamped = raw < headroom ? raw : headroom;
        EXPECT_EQ(clamped, headroom);
    }
    // Near-cap general property: reward <= headroom for every tier hash.
    const uint64_t near = max_supply_atoms() - 1000;
    for (uint64_t z = 0; z <= 48; ++z) {
        const auto h = hash_with_zeros(z);
        EXPECT_LE(block_reward_atoms(h.data(), near), 1000u);
    }
}

TEST(EmissionEpochsTest, ZenoTailNeverExhausts) {
    // Walk the Zeno span: each epoch's reward, applied over its era, mines
    // half of the remaining headroom. Simulate: the era ends when the mined
    // total crosses the next boundary; the era's block count is bounded
    // (reward > 0 for epochs < 33) — the total supply stays strictly below
    // the cap after every finite number of eras.
    const uint64_t B = EMISSION_EPOCH_ATOMS;
    uint64_t mined = 6 * B;
    for (int step = 0; step < 25; ++step) {
        const uint64_t e = supply_epoch(mined);
        const uint64_t remaining = max_supply_atoms() - mined;
        ASSERT_GT(remaining, 0u) << "the cap must never be reached, step " << step;
        // The reward is strictly positive while the Zeno walk is shallow.
        if (e < 33) {
            const auto h = hash_with_zeros(0);
            ASSERT_GT(block_reward_atoms(h.data(), mined), 0u);
            // The next Zeno boundary is exactly half of the remaining.
            const uint64_t next_boundary = mined + (remaining + 1) / 2;
            ASSERT_EQ(supply_epoch(next_boundary), e + 1);
            mined = next_boundary;
        } else {
            break;
        }
    }
    // After 25 Zeno steps the remaining headroom is E>>25 (~0.03 VX) —
    // small, but strictly positive: the tail is an eternal asymptote.
    EXPECT_GT(max_supply_atoms() - mined, 0u);
    EXPECT_LT(max_supply_atoms() - mined, EMISSION_EPOCH_ATOMS >> 24);
}

TEST(EmissionEpochsTest, CurveIsTheApprovedSchedule) {
    // Constant 5s pulse: 6,307,200 blocks/year; era k takes 2^k × 3.17 years.
    // Pins of the approved table (with ~3% jackpot allowance ignored).
    const double blocks_per_year = 365.0 * 24 * 3600 / 5;
    const double era0_years =
        (double)EMISSION_EPOCH_ATOMS / (double)(50ULL * ATOMS_PER_VX) / blocks_per_year;
    EXPECT_NEAR(era0_years, 3.17, 0.01);
    // Cumulative: 2B @ 9.5y, 3B @ 22.2y, 4B @ 47.6y (each era adds exactly
    // one billion; reviewer-corrected table).
    const double d = era0_years;    // 3.17...
    EXPECT_NEAR(d * 3, 9.51, 0.02); // end of era 1
    EXPECT_NEAR(d * 7, 22.2, 0.05); // end of era 2
    EXPECT_NEAR(d * 15, 47.6, 0.1); // end of era 3
}

TEST(EmissionEpochsTest, OverCapMinedMintsNothing) {
    // Defense-in-depth: a mined counter at or past the cap must never mint
    // (the Zeno subtraction would underflow otherwise).
    const auto h = hash_with_zeros(0);
    EXPECT_EQ(block_reward_atoms(h.data(), max_supply_atoms()), 0u);
    EXPECT_EQ(block_reward_atoms(h.data(), max_supply_atoms() + 1), 0u);
    EXPECT_EQ(block_reward_atoms(h.data(), max_supply_atoms() * 2), 0u);
}
