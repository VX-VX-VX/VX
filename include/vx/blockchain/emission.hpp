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

#include <cstddef>
#include <cstdint>

namespace vx::blockchain {

/// Hard lifetime supply cap in whole VX (never a parameter).
inline constexpr uint64_t MAX_SUPPLY_VX = 7'000'000'000ULL;

/// Nickname registration fee (owner-directed 2026-11-15): 1 VX in atoms,
/// paid as a regular transaction fee (the general 50/50 split applies —
/// half burns). Raised from the aspirational 0.001 VX: at the old price a
/// spammer could fill 1 GB of every node's durable index RAM with 10
/// million registrations for a mere 10 000 VX.
inline constexpr uint32_t SGMT_REGISTRATION_FEE_ATOMS = 100'000'000ULL;

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

// ── Supply-epoch reward decay (owner-directed 2026-11-15) ───────────────────
//
// The per-block reward halves every EMISSION_EPOCH_ATOMS of CUMULATIVE
// MINED supply — "the more coins mined, the harder the next coins are to
// get" — while the network pulse stays fixed at the 5 s ASERT target (the
// reviewer-corrected architecture: the emission schedule must NEVER be
// paid for with block-interval stretching; GQC finalization, DKSAP
// confirmation UX and the 0.2.x contract layer all live off a stable
// pulse). The decay is computed in ATOMS: an integer-VX shift would
// already truncate 4% of the floor on epoch 2 (50>>2 = 12 vs 12.5).
//
// Epoch boundaries: LINEAR steps of one billion VX up to six billion,
// then the LAST billion is split Zeno-style — each further epoch mines
// HALF OF THE REMAINDER toward the 7e9 cap. Consequence: the sum of era
// durations diverges and the cap is a mathematical horizon, never a date;
// no future hardware (including post-quantum mining clusters) can dilute
// the supply past the cap. Reviewer catch 2026-11-15: a purely linear
// 1B..7B table would exhaust the cap at the end of epoch 6 — epochs 7+
// would never exist and the "eternal tail" would be a lie. Honesty note
// (fork review, P2): the atom-domain shift itself reaches ZERO at Zeno
// epoch ~33 — the last ~7.5 VX of the schedule are unmineable in
// practice, so the precise claim is "asymptote to the sub-cent level",
// not "to the last atom".
inline constexpr uint64_t EMISSION_EPOCH_ATOMS = 100'000'000'000'000'000ULL; // 1e9 VX
inline constexpr uint64_t EMISSION_LINEAR_EPOCHS = 6; // linear span: 0..6e9 VX

/// The supply epoch of a cumulative-mined value. Pure, division-free:
/// the linear span is 6 comparisons; the Zeno span walks the halved
/// remainders (at most 57 shifts — everything here is PUBLIC consensus
/// data, never secret-dependent).
inline uint64_t supply_epoch(uint64_t mined_atoms) noexcept {
    // Saturation guard: at/past the cap there is no next epoch — return the
    // deepest one so every caller sees a zero reward (the Zeno subtraction
    // below would otherwise underflow; the reward-site guard stays as the
    // second belt).
    if (mined_atoms >= max_supply_atoms())
        return EMISSION_LINEAR_EPOCHS + 63;
    uint64_t epoch = 0;
    while (epoch < EMISSION_LINEAR_EPOCHS && mined_atoms >= (epoch + 1) * EMISSION_EPOCH_ATOMS)
        ++epoch;
    if (epoch < EMISSION_LINEAR_EPOCHS)
        return epoch;
    // Zeno span: mined is within the last billion. Era 6+k covers the
    // remaining headroom in (E >> k, E >> (k−1)] — each era mines HALF of
    // what is left toward the cap. j = the largest shift with
    // (E >> (j+1)) >= remaining; everything here is PUBLIC consensus
    // data, and the walk is comparison-only (no division, no logarithms).
    const uint64_t remaining = max_supply_atoms() - mined_atoms;
    uint64_t j = 0;
    while (j + 1 < 64 && (EMISSION_EPOCH_ATOMS >> (j + 1)) >= remaining)
        ++j;
    return EMISSION_LINEAR_EPOCHS + j;
}

/// The block reward in ATOMS: the tier of the block's own PoGW hash
/// shifted down by the supply epoch, clamped to the remaining headroom
/// under the hard cap (a jackpot tier on the cap's doorstep must never
/// overshoot 7e9). The epoch applies to the WHOLE tier table so the
/// jackpot-to-floor ratio stays constant in every era.
inline uint64_t block_reward_atoms(const uint8_t block_hash[32], uint64_t mined_atoms) noexcept {
    // Defense-in-depth: a mined value at/over the cap (corrupted state, a
    // hostile test seam) must mint NOTHING — the Zeno subtraction below
    // would otherwise underflow into a huge fake headroom.
    if (mined_atoms >= max_supply_atoms())
        return 0;
    const uint64_t tier = block_reward_vx(block_hash);
    const uint64_t epoch = supply_epoch(mined_atoms);
    const uint64_t reward = (tier * ATOMS_PER_VX) >> epoch;
    const uint64_t headroom = max_supply_atoms() - mined_atoms;
    return reward < headroom ? reward : headroom;
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
