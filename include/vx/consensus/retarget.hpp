#pragma once

#include "vx/blockchain/block.hpp"
#include <cstdint>

namespace vx::consensus {

// -- ASERT PoGW difficulty retarget (BACKLOG 0.9 remainder) -------------------
//
//   target(h) = target(anchor) * 2^((h - anchor - 1) / half_life)
//
// The anchor is the genesis frame (height 0) with its anchor difficulty; the
// half-life is the number of blocks over which the work requirement doubles
// (one extra leading zero bit). The anchor difficulty is the BlockStore ctor
// parameter, re-documented as the genesis/anchor seal strength; the genesis
// frame itself is exempt (it is seeded directly and never passes the gate).
//
// REDUCTION PROOF (why the real-valued curve is an integer bit increment on
// this chain):
//   1. The work requirement is encoded ONLY as a leading-zero-bit count:
//      pogw_meets_target accepts a frame iff zeros(full-frame hash) >= bits.
//      The set of enforceable work levels is therefore exactly the lattice
//      {2^b : b integer, 0 <= b <= 256} -- there is no way to express a
//      fractional work factor 2^eps; the granularity of the check IS one bit.
//   2. Writing W(h) = 2^bits(h) and W(anchor) = 2^anchor, the real-valued
//      ASERT curve becomes, after taking log2 of both sides:
//          bits(h) = anchor + (h - anchor - 1) / half_life
//      (anchor is fixed at height 0, so the exponent is (h - 1)/half_life).
//   3. The exponent delta(h) = (h-1)/half_life is generally fractional. The
//      faithful integer encoding of the curve on the bit lattice is the
//      lattice point nearest to the curve: bits(h) = anchor +
//      round_nearest_ties_up(delta(h)). Rounding the exponent BEFORE adding
//      the anchor is exact, because the anchor is an integer and
//      nearest-rounding commutes with adding an integer. Ties (r == half/2
//      for even half-lives) round up, mirroring how Bitcoin's ASERT rounds
//      its computed target into the compact encoding. Max deviation from the
//      real curve is 1/2 bit (floor or ceil would deviate by up to a full
//      bit over each half-life cycle).
//   4. The function is pure and deterministic: no timestamps, no cumulative
//      chain work, no per-chain state -- two nodes with the same anchor and
//      parameters always compute identical bits for any height, even after a
//      fork. Difficulty is derived from the height at intake time and is
//      never stored in any frame, so no wire or store format changes.
//
// Overflow safety: height is uint64_t; delta = q + (r >= threshold) where
// q = (h-1)/half_life is bounded by an early return before the sum, so
// anchor + delta can never wrap (both operands are <= 2*POGW_MAX_BITS).

/// Protocol clamps. 64 leading zero bits is beyond any plausible miner
/// (2^64 expected sponge evaluations per block); 1 bit is the weakest
/// meaningful seal. pogw_meets_target() itself hard-fails beyond 256 bits,
/// so the clamp is also what keeps the gate satisfiable forever.
inline constexpr uint64_t POGW_MIN_BITS = 1;
inline constexpr uint64_t POGW_MAX_BITS = 64;

/// Mainnet retarget parameters. The nominal block interval is 5 s
/// (PoGWMiner::target_block_time_), so the half-life is 2 days expressed in
/// blocks: 2 * 24 * 3600 / 5 = 34560 blocks per target doubling.
inline constexpr uint64_t POGW_HALF_LIFE_BLOCKS = 34560;

/// Retarget parameters. All nodes on one chain MUST use the same values;
/// the anchor lives in the genesis frame, which is shared by construction
/// (every node reconstructs the same genesis deterministically), so the
/// difficulty needs no consensus exchange whatsoever.
struct PogwRetargetParams {
    uint64_t anchor_bits;       // genesis/anchor difficulty in leading zero bits
    uint64_t half_life_blocks;  // blocks per target doubling
};

inline constexpr PogwRetargetParams POGW_MAINNET_RETARGET{
    blockchain::DEFAULT_POGW_DIFFICULTY_BITS, POGW_HALF_LIFE_BLOCKS};

/// ASERT bits for height h (anchor fixed at genesis, height 0). Pure and
/// deterministic, overflow-safe for any uint64_t height and half-life.
inline uint64_t asert_pogw_bits(const PogwRetargetParams& p, uint64_t height) noexcept {
    // Clamp the anchor into the protocol lattice first.
    uint64_t anchor = p.anchor_bits;
    if (anchor < POGW_MIN_BITS) anchor = POGW_MIN_BITS;
    if (anchor > POGW_MAX_BITS) anchor = POGW_MAX_BITS;
    const uint64_t half_life = p.half_life_blocks == 0 ? 1 : p.half_life_blocks;

    // Genesis itself and the first mined block sit exactly at the anchor.
    if (height <= 1) return anchor;

    // Exponent numerator (h - anchor_height - 1) with anchor_height = 0.
    const uint64_t shift = height - 1;
    const uint64_t q = shift / half_life;
    // Saturated ceiling: every further bit increment is clamped anyway, and
    // this guard also covers heights near 2^64 without any multiplication.
    if (q >= POGW_MAX_BITS) return POGW_MAX_BITS;

    // Round-to-nearest (ties up) of shift / half_life, no overflow: r < half_life.
    const uint64_t r = shift % half_life;
    uint64_t delta = q;
    if (r >= (half_life >> 1) + (half_life & 1)) ++delta;

    // delta <= q + 1 <= POGW_MAX_BITS, so the sum cannot wrap.
    uint64_t bits = anchor + delta;
    if (bits > POGW_MAX_BITS) bits = POGW_MAX_BITS;
    if (bits < POGW_MIN_BITS) bits = POGW_MIN_BITS;
    return bits;
}

} // namespace vx::consensus
