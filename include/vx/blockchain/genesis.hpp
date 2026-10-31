#pragma once

#include "vx/blockchain/block.hpp"
#include <string>

namespace vx::blockchain {

// ── Deterministic genesis builder ────────────────────────────────────────────
// Block #0 is not shipped as a file: it is derived deterministically, in
// process, from the published canonical attractor seed (see the seed constant
// in the implementation). Every node and every test reconstructs the exact
// same 64 KiB frame bit-for-bit — "always regenerate, never copy" by design.

/// Builds the deterministic 64 KiB genesis frame (#0) in memory.
/// 1000-round Tri-Barrel attractor run (secure CRT moduli) → 472 B header
/// with the real attractor coordinates + 1 signed coinbase transaction.
BlockFrame build_genesis_frame();

/// Writes the deterministic genesis frame to `path` (exactly 65536 B).
/// Overwrites atomically-safe local files only; callers use it to materialize
/// genesis.bin next to a fresh ledger.
void write_genesis_file(const std::string& path);

/// Returns true if a genesis file exists at `path` or has just been written
/// there by the deterministic builder. Never reads network state.
bool ensure_genesis_file(const std::string& path);

/// The NFA address of the genesis coinbase receiver (deterministic).
std::string genesis_coinbase_receiver();

} // namespace vx::blockchain
