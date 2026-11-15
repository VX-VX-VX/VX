#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// Founder allocation vesting (owner-directed 2026-11-15, pre-genesis commit).
//
// The founder allocation (21,000,000 VX) is credited by the genesis but is
// spendable only along the unlock schedule: a 6-month cliff, then a linear
// release over 36 months (≈1.126 VX per 5-second block after the cliff).
//
// ZERO-DIV discipline: the unlocked amount is (elapsed × TOTAL) / VEST
// computed in the U128 SOFTWARE division routine (a shift-subtract loop —
// no hardware divide instruction reaches apply_block; the build pipeline
// objdump-verifies zero div/idiv instructions AND zero __div* relocations
// in the emitted gate). A multiply-high decomposition of the constant
// divisor would be faster, but the once-per-block call costs nothing and
// the software routine is trivially exact. The product is exact in u128:
// elapsed ≤ 2^25 blocks × 2.1e15 atoms ≈ 3.9e22 — far below 2^128, no
// overflow. The result is exact to the atom across the whole schedule.
//
// XMSS-rollover compatibility (reviewer 2026-11-15): the founder address
// will publish several PqRolloverCert rotations during the 36-month window
// (one XMSS tree holds 16 one-time leaves). The unlock schedule is bound to
// the ADDRESS and the block HEIGHT only — never to a signing leaf index or
// a certificate generation — so the spend path keeps working unchanged
// across rollovers; the rollover certification itself is the ordinary
// certificate flow (PqWitnessRegistry) and needs no vesting interaction.
// ─────────────────────────────────────────────────────────────────────────────

#include "vx/core/u128.hpp"

#include <cstdint>

namespace vx::blockchain {

/// Total founder allocation in atoms: 21,000,000 VX = 2.1e15 atoms.
inline constexpr uint64_t FOUNDER_ALLOCATION_ATOMS = 21'000'000ULL * 100'000'000ULL;

/// The cliff: 6 months of 30 days at the 5-second pulse
/// (6 × 30 × 86400 / 5 = 3,110,400 blocks). Nothing moves before it.
inline constexpr uint64_t FOUNDER_CLIFF_BLOCKS = 6ULL * 30 * 24 * 3600 / 5;

/// The linear release window: 36 months at the 5-second pulse
/// (36 × 30 × 86400 / 5 = 18,662,400 blocks). Compile-time constant —
/// the divisor the compiler turns into multiply-high+shift.
inline constexpr uint64_t FOUNDER_VEST_BLOCKS = 36ULL * 30 * 24 * 3600 / 5;

static_assert(FOUNDER_VEST_BLOCKS > FOUNDER_CLIFF_BLOCKS, "vesting window must outlive the cliff");
static_assert(FOUNDER_ALLOCATION_ATOMS <= 100'000'000'000'000'000ULL / 4,
              "the founder allocation must stay a small fraction of one emission epoch");

/// Unlocked (spendable) founder atoms at a given block height. Exact to the
/// atom; saturates at the full allocation; nothing unlocks before the cliff.
inline vx::core::U128 founder_unlocked_atoms(uint64_t height) noexcept {
    if (height < FOUNDER_CLIFF_BLOCKS)
        return vx::core::U128{}; // cliff: the allocation is fully locked
    const uint64_t elapsed = height - FOUNDER_CLIFF_BLOCKS;
    if (elapsed >= FOUNDER_VEST_BLOCKS)
        return vx::core::U128{FOUNDER_ALLOCATION_ATOMS}; // fully vested
    // (elapsed × TOTAL) / VEST in u128 — VEST is a compile-time constant,
    // so the division lowers to multiply-high+shift (Zero-DIV).
    const vx::core::U128 product =
        vx::core::U128{elapsed} * vx::core::U128{FOUNDER_ALLOCATION_ATOMS};
    return product / vx::core::U128{FOUNDER_VEST_BLOCKS};
}

} // namespace vx::blockchain
