#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// VX emission schedule (hard-coded consensus, user-directed 2026-11-03).
//
// Hard supply cap: 7,000,000,000 VX. The 7 is the protocol's signature digit
// (the square root of seven — irrational by construction), so the cap is a
// protocol constant, not a parameter: no height, no vote, no soft fork of
// this file can ever issue the 7,000,000,001st VX.
//
// Schedule: a flat 1,000 VX block subsidy for chain heights 1..7,000,000 and
// zero afterwards. The full schedule mints exactly 7,000,000,000 VX over
// 7,000,000 blocks; the protocol genesis allocations (2.54M faucet + the
// one-time 100k legacy mint) also count against the cap, so the final blocks
// of the window mint only the remaining headroom and cumulative issuance
// then locks at the cap forever. After the window the only value entering
// circulation is fee redistribution (see below).
//
// What counts as ISSUANCE: every atom credited by a mint transaction
// (GENESIS allocations and MINER_ coinbases) MINUS the fee share re-credited
// to the producer. Fees left circulation when the senders paid them; the
// producer's 50% fee share re-enters circulation as redistribution, not new
// emission. The 50% TDI burn keeps circulating supply below issuance.
// ─────────────────────────────────────────────────────────────────────────────

#include <cstdint>

namespace vx::blockchain {

/// Hard lifetime supply cap in whole VX (never a parameter).
inline constexpr uint64_t MAX_SUPPLY_VX = 7'000'000'000ULL;

/// Atomic resolution: 1 VX = 10^8 atoms (8 decimal places).
inline constexpr uint64_t ATOMS_PER_VX = 100'000'000ULL;

/// Blocks carrying the flat subsidy (heights 1..7,000,000).
inline constexpr uint64_t EMISSION_WINDOW_BLOCKS = 7'000'000ULL;

/// Flat per-block subsidy while the emission window is open.
inline constexpr uint64_t BLOCK_SUBSIDY_VX = 1'000ULL;

/// The lifetime cap in atoms: 7e9 * 1e8 = 7e17 (fits in uint64 with room).
inline constexpr uint64_t max_supply_atoms() noexcept {
    return MAX_SUPPLY_VX * ATOMS_PER_VX;
}

/// Block subsidy in atoms for a chain height: 1,000 VX for heights
/// 1..7,000,000, zero at height 0 (the genesis frame mints its own
/// allocations) and zero after the emission window closes.
inline constexpr uint64_t subsidy_atoms(uint64_t height) noexcept {
    return (height >= 1 && height <= EMISSION_WINDOW_BLOCKS)
               ? BLOCK_SUBSIDY_VX * ATOMS_PER_VX
               : 0;
}

static_assert(max_supply_atoms() == 700'000'000'000'000'000ULL,
              "the 7,000,000,000 VX cap must be exactly 7e17 atoms");
static_assert(subsidy_atoms(1) == 100'000'000'000ULL &&
                  subsidy_atoms(EMISSION_WINDOW_BLOCKS) == 100'000'000'000ULL &&
                  subsidy_atoms(0) == 0 &&
                  subsidy_atoms(EMISSION_WINDOW_BLOCKS + 1) == 0,
              "subsidy window shape must hold: flat 1000 VX inside, zero outside");

} // namespace vx::blockchain
