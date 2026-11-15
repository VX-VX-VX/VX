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
//      for even half-lives) round up. (Math-audit F9: this differs from
//      Bitcoin's ASERT, which rounds the TARGET MANTISSA into its compact
//      encoding — here the work lattice IS integer bits, so the exponent
//      itself is what gets rounded; the choice is self-consistent per
//      proof steps 1-3.) Max deviation from the
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

/// ── TIME-ASERT (owner-directed 2026-11-15; consensus commit) ─────────────
///
/// The previous retarget was an unconditional HEIGHT ratchet: the target
/// doubled every 34560 blocks forever, regardless of hashrate — a liveness
/// mine (a hashrate exodus froze the chain: difficulty kept doubling) and
/// a lie in the emission math. The replacement is a true time-based ASERT
/// around the FIXED 5-second pulse: the difficulty tracks the real
/// hashrate so blocks keep arriving on target forever (the pulse is what
/// GQC finalization, DKSAP confirmation UX and the 0.2.x contract layer
/// live on — it is never traded away to slow emission; the emission
/// schedule bends via the supply-epoch reward decay in emission.hpp).
///
///   bits = anchor − round_ties(dev / TAU),
///   dev = (t_parent − t_anchor) − (h − 2) × TARGET_BLOCK_SECONDS
///
/// (The MINUS: our difficulty is measured in required leading-zero BITS —
/// the inverse of Bitcoin's target VALUE. Fast blocks make dev negative,
/// so −round(negative) adds bits: harder. A lagging chain subtracts.)
///
/// Blocks arriving ahead of schedule raise the difficulty; a lagging
/// chain lowers it — self-correcting in BOTH directions, so a hashrate
/// winter eases mining instead of freezing the chain. Division by the
/// compile-time constants folds into multiply-high+shift (zero runtime
/// div; objdump-verified by the retarget test).
inline constexpr uint64_t POGW_TARGET_BLOCK_SECONDS = 5;
inline constexpr uint64_t POGW_TAU_SECONDS = 172800; // 2-day time half-life

/// Retarget parameters. All nodes on one chain MUST use the same values;
/// the anchor lives in the genesis frame, which is shared by construction
/// (every node reconstructs the same genesis deterministically), so the
/// difficulty needs no consensus exchange whatsoever.
struct PogwRetargetParams {
    uint64_t anchor_bits; // genesis/anchor difficulty in leading zero bits
};

inline constexpr PogwRetargetParams POGW_MAINNET_RETARGET{blockchain::DEFAULT_POGW_DIFFICULTY_BITS};

// -- Retarget parameter lock (BACKLOG 0.9 review finding F2) ------------------
//
// The anchor difficulty and half-life are CODE constants, not part of the
// genesis frame: "same genesis" enforces nothing about them. A build that
// changes either value silently computes a different difficulty curve and
// forks from every other node with no visible disagreement — the worst
// failure mode for a parameter that has no wire representation.
//
// The fingerprint pins the pair: it is derived from the parameter bytes and
// asserted (static_assert here, EXPECT in the retarget test). Changing a
// parameter MUST be a deliberate, announced consensus change that updates
// both pins in the same commit — never a drive-by edit.
inline constexpr uint64_t retarget_fingerprint(uint64_t anchor_bits, uint64_t tau_seconds,
                                               uint64_t target_block_seconds) noexcept {
    uint64_t h = 1469598103934665603ull; // FNV-1a 64
    const uint64_t words[3] = {anchor_bits, tau_seconds, target_block_seconds};
    for (const uint64_t w : words)
        for (int i = 0; i < 8; ++i) {
            h ^= (w >> (8 * i)) & 0xffull;
            h *= 1099511628211ull;
        }
    return h;
}

inline constexpr uint64_t POGW_RETARGET_FINGERPRINT = retarget_fingerprint(
    POGW_MAINNET_RETARGET.anchor_bits, POGW_TAU_SECONDS, POGW_TARGET_BLOCK_SECONDS);

static_assert(POGW_RETARGET_FINGERPRINT == 0xd59af7a8dd8ca2f9ull,
              "consensus-critical: ASERT anchor/tau/pulse changed - this forks "
              "every peer silently; announce the change and update the "
              "fingerprint pin in the same commit");

/// Time-ASERT bits for a block at `height`, given its PARENT's timestamp
/// and the ANCHOR timestamp — the stamp of the FIRST MINED block (height
/// 1), which is the clock the 5-second pulse is measured against. The
/// height-0 genesis stamp is deliberately NOT the anchor: it is a fixed
/// deterministic constant, and a chain resumed long after its genesis
/// would explode the deviation at every restart. Height 1's stamp is
/// chain data every node holds, and a long mining pause correctly eases
/// the difficulty (liveness), never freezes it. Pure and deterministic
/// from (height, parent ts, anchor ts) — no wire representation, no
/// stored state. Division by the compile-time TAU folds into
/// multiply-high+shift (zero hardware div; the test objdump-verifies).
inline uint64_t asert_pogw_bits(uint64_t anchor_bits, uint64_t height, int64_t parent_ts,
                                int64_t anchor_ts) noexcept {
    uint64_t anchor = anchor_bits;
    if (anchor < POGW_MIN_BITS)
        anchor = POGW_MIN_BITS;
    if (anchor > POGW_MAX_BITS)
        anchor = POGW_MAX_BITS;

    // Heights 0-2 sit at the anchor: the deviation is not yet measurable
    // (fewer than two on-schedule intervals between height 1 and the parent).
    if (height <= 2)
        return anchor;

    // Absurd heights: (height-2)*5s would overflow the int64 deviation
    // arithmetic. Nothing real gets near this; clamp at the lattice top.
    if (height > (1ull << 59))
        return POGW_MAX_BITS;

    // Time deviation: actual elapsed since the first mined block minus the
    // elapsed an on-target chain would have produced over (height-2)
    // intervals. Signed: a lagging chain eases, a fast chain tightens.
    //
    // STRICT int64 with saturating overflow guards — NOT __int128 (security
    // review 2026-11-15, HIGH + fork-review P1): a __int128 deviation
    // divided by a constant is lowered by GCC into a libgcc __divmodti4
    // CALL whose internals contain a hardware divide — the Zero-DIV law is
    // violated by the RELOCATION, not by any instruction in this TU. Both
    // stamps are sanity-bounded at intake (monotone, <= now+300s), so int64
    // is sufficient; the guards make even a hostile (pre-bounds) value
    // saturate instead of wrapping.
    int64_t elapsed;
    if (__builtin_sub_overflow(parent_ts, anchor_ts, &elapsed))
        elapsed = parent_ts > anchor_ts ? INT64_MAX : INT64_MIN;
    const int64_t expected =
        (height - 2) > (uint64_t)(INT64_MAX / (int64_t)POGW_TARGET_BLOCK_SECONDS)
            ? INT64_MAX
            : (int64_t)((height - 2) * POGW_TARGET_BLOCK_SECONDS);
    int64_t dev;
    if (__builtin_sub_overflow(elapsed, expected, &dev))
        dev = elapsed > expected ? INT64_MAX : INT64_MIN;

    // delta = round-to-nearest of dev / TAU, ties away from zero. Division
    // by the COMPILE-TIME TAU constant folds into multiply-high+shift —
    // zero hardware divide, zero __div* relocations (the retarget test
    // objdump-verifies both).
    int64_t q = dev / (int64_t)POGW_TAU_SECONDS;
    const int64_t r = dev % (int64_t)POGW_TAU_SECONDS;
    if (r >= (int64_t)POGW_TAU_SECONDS / 2)
        ++q;
    else if (r <= -(int64_t)POGW_TAU_SECONDS / 2)
        --q;
    if (q > (int64_t)POGW_MAX_BITS)
        q = (int64_t)POGW_MAX_BITS;
    if (q < -(int64_t)POGW_MAX_BITS)
        q = -(int64_t)POGW_MAX_BITS;

    // Clamp into the protocol lattice.
    int64_t bits = (int64_t)anchor - q;
    if (bits < (int64_t)POGW_MIN_BITS)
        return POGW_MIN_BITS;
    if (bits > (int64_t)POGW_MAX_BITS)
        return POGW_MAX_BITS;
    return (uint64_t)bits;
}

} // namespace vx::consensus
