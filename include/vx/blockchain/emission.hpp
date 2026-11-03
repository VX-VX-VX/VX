#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// VX emission schedule (hard-coded consensus, user-directed 2026-11-03).
//
// Hard supply cap: 7,000,000,000 VX. The 7 is the protocol's signature digit
// (the square root of seven — irrational by construction), so the cap is a
// protocol constant, not a parameter: no height, no vote, no soft fork of
// this file can ever issue the 7,000,000,001st VX. The cap is the ONLY end
// of emission: at the 50 VX floor rate it closes after roughly 140 million
// blocks, and every bonus tier only stretches that (see the table below).
//
// Per-block reward: a deterministic function of the block's own PoGW hash
// (the VortexSponge256 commitment over the full 64 KiB frame — the SAME
// hash the intake gate already checks for work). The guaranteed floor is
// 50 VX; the absolute maximum is 1,000 VX and it requires an exceptionally
// rare hash, so jackpot blocks are rare by construction — a miner cannot
// mint the bonus, it can only FIND a rarer hash, which is strictly more
// PoGW work:
//
//     leading zero bits of the block hash | reward | ~frequency
//     ------------------------------------+--------+----------------
//     any valid block (>= network target) |  50 VX | every block
//     >= 20                               |  75 VX | 1 in ~1,000,000
//     >= 24                               | 100 VX | 1 in ~16,700,000
//     >= 28                               | 200 VX | 1 in ~268,000,000
//     >= 32                               | 400 VX | 1 in ~4,300,000,000
//     >= 40                               | 1,000 VX | 1 in ~1.1 trillion
//
// At the dev-mode difficulty (16 zero bits) essentially every block earns
// the floor; as network difficulty grows past a threshold, every block
// clears it and the effective reward steps up — emission accelerates only
// when the security behind the chain grows, and the cap bounds it anyway.
//
// The thresholds are ABSOLUTE, not relative to the network difficulty: any
// node verifies the reward by hashing the frame it already hashes for the
// PoGW gate and counting leading zeros — no difficulty estimate enters
// consensus accounting. At the floor rate the cap closes after roughly
// 140 million blocks (~22 years at the 5-second target); every bonus tier
// only stretches that.
//
// On top of the schedule reward the producer may claim this block's fee
// share (50% of fees; the other 50% is the TDI burn). Fees re-credited to
// the producer are redistribution of value that already left the senders —
// not new emission. What counts as ISSUANCE (the capped quantity): every
// atom credited by a mint transaction (GENESIS allocations and MINER_
// coinbases) MINUS the re-credited fee share. Genesis allocations count
// against the cap, so near the end the cap - not the tier table -
// determines the last partial rewards, and after it nothing new is issued.
//
// Atomic resolution: 1 VX = 10^8 atoms, i.e. one atom is 0.00000001 VX —
// the smallest unit users handle, by design.
// ─────────────────────────────────────────────────────────────────────────────

#include <cstdint>

namespace vx::blockchain {

/// Hard lifetime supply cap in whole VX (never a parameter).
inline constexpr uint64_t MAX_SUPPLY_VX = 7'000'000'000ULL;

/// Atomic resolution: 1 VX = 10^8 atoms (8 decimal places; one atom is
/// 0.00000001 VX).
inline constexpr uint64_t ATOMS_PER_VX = 100'000'000ULL;

/// The lifetime cap in atoms: 7e9 * 1e8 = 7e17 (fits in uint64 with room).
inline constexpr uint64_t max_supply_atoms() noexcept {
    return MAX_SUPPLY_VX * ATOMS_PER_VX;
}

/// Guaranteed per-block reward floor (concrete-guaranteed — every valid
/// block earns it, whatever hash it carried).
inline constexpr uint64_t BLOCK_REWARD_BASE_VX = 50ULL;

/// Absolute per-block reward maximum (the jackpot tier).
inline constexpr uint64_t BLOCK_REWARD_MAX_VX = 1'000ULL;

/// Bonus tiers: leading-zero-bit thresholds of the block's PoGW hash and
/// the reward they unlock. Ascending in both columns; the last entry is
/// the jackpot and equals BLOCK_REWARD_MAX_VX.
inline constexpr uint64_t REWARD_TIER_ZEROS[] = {20, 24, 28, 32, 40};
inline constexpr uint64_t REWARD_TIER_VX[]    = {75, 100, 200, 400, 1000};
inline constexpr size_t   REWARD_TIER_COUNT =
    sizeof(REWARD_TIER_ZEROS) / sizeof(REWARD_TIER_ZEROS[0]);

/// Leading zero bits of a 32-byte hash (big-endian bit order).
inline uint64_t leading_zero_bits(const uint8_t hash[32]) noexcept {
    uint64_t zeros = 0;
    for (size_t i = 0; i < 32; ++i) {
        if (hash[i] == 0) {
            zeros += 8;
            continue;
        }
        uint8_t b = hash[i];
        while ((b & 0x80) == 0) {
            ++zeros;
            b <<= 1;
        }
        break;
    }
    return zeros;
}

/// The block reward in whole VX, from the block's own PoGW hash: the base
/// floor plus every tier whose zero-bit threshold the hash meets.
inline uint64_t block_reward_vx(const uint8_t block_hash[32]) noexcept {
    const uint64_t zeros = leading_zero_bits(block_hash);
    uint64_t reward = BLOCK_REWARD_BASE_VX;
    for (size_t i = 0; i < REWARD_TIER_COUNT; ++i) {
        if (zeros >= REWARD_TIER_ZEROS[i]) reward = REWARD_TIER_VX[i];
    }
    return reward;
}

/// The block reward in atoms, from the block's own PoGW hash.
inline uint64_t block_reward_atoms(const uint8_t block_hash[32]) noexcept {
    return block_reward_vx(block_hash) * ATOMS_PER_VX;
}

static_assert(max_supply_atoms() == 700'000'000'000'000'000ULL,
              "the 7,000,000,000 VX cap must be exactly 7e17 atoms");
static_assert(BLOCK_REWARD_BASE_VX < REWARD_TIER_VX[0] &&
                  REWARD_TIER_VX[REWARD_TIER_COUNT - 1] == BLOCK_REWARD_MAX_VX,
              "the tier table must start above the base and end at the max");
static_assert(BLOCK_REWARD_MAX_VX * ATOMS_PER_VX == 100'000'000'000ULL,
              "the jackpot must be exactly 1,000 VX");
static_assert(BLOCK_REWARD_BASE_VX * ATOMS_PER_VX == 5'000'000'000ULL,
              "the guaranteed floor must be exactly 50 VX");

} // namespace vx::blockchain
