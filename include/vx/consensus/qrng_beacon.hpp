#pragma once

// QRNG beacon — Phase E (0.2.4): the epoch seed as a VERIFIED nondeterminism
// point.
//
// The rechain-commitment scheme (variant b of the Phase E spec): the
// producer of block N commits to a hardware-RNG byte in the block header
// (qrng_commit = sponge("VX_QRNG_COMMIT_V1" | rN)), the producer of block
// N+1 reveals rN, and every node re-derives the commit. Mismatch -> block
// N+1 rejected (fail-closed). The epoch seed is a rolling window of the
// last k revealed bytes, domain-separated under "VX_QRNG_SEED_V1".
//
// This is the PURE layer: commit/reveal math, seed derivation, the
// misconduct ledger for slash policy, and the hardware-RNG read with a
// fail-closed deterministic fallback. Header wiring (where the fields
// live in the block format) is a later normative step.

#include <array>
#include <cstdint>
#include <vector>

namespace vx::consensus::qrng {

// Domain separation tags (NORMATIVE, spec §4): one tag per intent, never
// shared. The radar-on-IVK tag is reserved for future use.
inline constexpr uint8_t kTagCommit[] = "VX_QRNG_COMMIT_V1";
inline constexpr uint8_t kTagSeed[] = "VX_QRNG_SEED_V1";
inline constexpr uint8_t kTagRadar[] = "VX_QRNG_RADER_V1"; // reserved
inline constexpr uint8_t kTagFallback[] = "VX_QRNG_FALLBACK_V1";

// Rolling window size k of revealed bytes folded into the epoch seed.
// Candidate per spec §2.4; the owner ratifies the final value.
inline constexpr size_t kSeedWindow = 8;

// Misconduct thresholds (spec §3): W blocks out of the producer rotation
// per proven mismatch; 3 proven mismatches in one epoch -> committee
// escalation (Phase C equivocation mechanics).
inline constexpr uint32_t kProducerBanBlocks = 1000;
inline constexpr uint32_t kEpochEscalationStrikes = 3;

/// The commitment: sponge("VX_QRNG_COMMIT_V1" | rN). 32 bytes.
std::array<uint8_t, 32> qrng_commit(uint8_t rng_byte) noexcept;

/// Verifies a reveal against a commit: re-derives the commitment and
/// compares byte-for-byte. This is the fail-closed gate on block N+1.
bool verify_reveal(const std::array<uint8_t, 32> &commit, uint8_t rng_byte) noexcept;

/// The epoch seed: sponge("VX_QRNG_SEED_V1" | rN-1 | rN-2 | ... | rN-k)
/// over the rolling window of the last k revealed bytes, OLDEST FIRST
/// (the window folds chronologically; order sensitivity is tested).
/// Returns all-zero on an empty window (caller must treat as "no seed
/// update" — fail-closed, the old epoch continues).
std::array<uint8_t, 32> seed_from_window(const std::vector<uint8_t> &window) noexcept;

/// Misconduct ledger for the slash policy (spec §3). One entry per
/// producer identity; strikes are per-epoch.
struct MisconductLedger {
    struct Entry {
        std::array<uint8_t, 32> producer_id{};
        uint32_t strikes = 0;      // proven mismatches this epoch
        uint64_t banned_until = 0; // block height; 0 = not banned
    };
    std::vector<Entry> entries;

    /// Records a proven mismatch (the commit/reveal pair IS the proof —
    /// it lives in the blocks themselves, no extra evidence needed).
    /// Returns true if this strike triggered the epoch escalation.
    bool record_mismatch(const std::array<uint8_t, 32> &producer_id,
                         uint64_t current_height) noexcept;

    /// True while the producer is excluded from the rotation.
    bool is_banned(const std::array<uint8_t, 32> &producer_id,
                   uint64_t current_height) const noexcept;

    /// Clears the strike counters on an epoch rollover (the escalation
    /// counter is per-epoch; the ban window outlives it).
    void reset_epoch() noexcept;
};

/// Reads one hardware-RNG byte (getrandom(2), BLOCKING until seeded).
/// Returns false only if the kernel RNG itself is unavailable — the
/// caller then uses the deterministic fallback below, never /dev/urandom
/// (fail-closed, spec §5).
bool read_hardware_rng(uint8_t &out) noexcept;

/// The deterministic fallback when the hardware RNG is unavailable:
/// sponge("VX_QRNG_FALLBACK_V1" | previous seed window). Fail-closed:
/// the seed degrades to determinism, never to attacker-controlled
/// entropy. The caller marks the beacon "degraded" downstream.
uint8_t fallback_byte(const std::vector<uint8_t> &prev_window) noexcept;

} // namespace vx::consensus::qrng
