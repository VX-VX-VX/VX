#pragma once

// ── GQC Bitmasked m-of-n committee votes (Phase C, 0.2.2) ───────────────────
// The vote is a REAL XMSS signature: each committee member signs the
// domain-separated vote message with its one-shot leaf, and the aggregator
// verifies every vote against the member's whitelist root (never against a
// root carried inside the witness itself — a hostile peer cannot substitute
// an identity by claiming a root it happens to control).
//
// The certificate records exactly WHO signed: a uint64_t bitmap (n <= 64,
// one bit per member in the canonical whitelist order) — accountable BFT,
// the basis of the equivoque proof below. The aggregate is a commitment to
// the exact signer set (bitmap + witness commitments).
//
// Prior art (Phase C spec, 2026-11-21): NIST "Haystack" (MPTS 2026) turns
// stateful HBS into TRUE threshold signatures (one key split into shares,
// trusted dealer, huge CRS, n < 10). This is NOT that: m-of-n multisig of
// independent XMSS identities — no dealer, no CRS, no key splitting, and
// the signer set is public by design (accountability, not hiding).
//
// Leaf discipline: votes share the transaction leaf policy — leaf 15 is
// reserved for rollover certificates and is never consumed by a vote
// (PqLeafLedger::reserve_for_tx). One XMSS tree covers 15 checkpoints;
// exhaustion fails closed (the signer refuses; the whitelist rotates).

#include "vx/crypto/pq_signature.hpp"

#include <array>
#include <cstdint>
#include <vector>

namespace vx::consensus::gqc {

/// One bit per member; a committee above this size cannot be bitmasked.
inline constexpr size_t kMaxCommitteeSize = 64;
/// Subtree the epoch-1 whitelist roots bind: the initial tree (subtree 0).
/// Checkpoint leaves beyond the tree's usable leaves exhaust it — the
/// whitelist rotation (epoch transition) is the documented fail-closed
/// recovery, not a silent reuse.
inline constexpr uint32_t kVoteSubtree = 0;

/// The domain-separated message every committee member signs:
/// sponge("VX_GQC_VOTE_V1" || epoch(8 LE) || height(8 LE) || block_hash(32)).
std::array<uint8_t, 32> vote_msg(uint64_t epoch, uint64_t height,
                                 const std::array<uint8_t, 32> &block_hash) noexcept;

/// One vote on the wire / in the pool.
struct GqcVote {
    uint16_t validator_id = 0;
    vx::crypto::pq::PqSignatureWitness witness{};
};

/// Verifies one vote against a whitelist member root: the witness must
/// verify the vote message AND carry exactly that root. Malformed or
/// substituted votes return false.
bool verify_vote(const std::array<uint8_t, 32> &member_root, uint64_t epoch, uint64_t height,
                 const std::array<uint8_t, 32> &block_hash, const GqcVote &vote) noexcept;

/// Signs a vote with the member's key: reserves a one-shot leaf from the
/// ledger (lowest free, never leaf 15), subtree 0. The vote carries the
/// member's id — the pool keys on it, so an unsigned id (0) would collapse
/// every member onto one identity. Returns a default witness (verification
/// fails) when the ledger refuses — fail-closed, no leaf reuse ever.
GqcVote sign_vote(uint16_t validator_id, const std::array<uint8_t, 32> &master_sk, uint64_t epoch,
                  uint64_t height, const std::array<uint8_t, 32> &block_hash,
                  vx::crypto::pq::PqLeafLedger &ledger) noexcept;

/// The 32-byte aggregate stamped into the sidecar: a commitment to the
/// exact signer set (bitmap + the witness commitments of the quorum votes).
std::array<uint8_t, 32> aggregate_votes(uint64_t height, uint64_t bitmap,
                                        const std::vector<GqcVote> &votes) noexcept;

/// Accountable-BFT evidence: the same member produced two valid witnesses
/// for two DIFFERENT block hashes at the same height. Both witnesses are
/// verified before the proof is recorded (garbage is not evidence).
struct GqcEquivocationProof {
    uint16_t validator_id = 0;
    uint64_t height = 0;
    std::array<uint8_t, 32> block_hash_a{};
    std::array<uint8_t, 32> block_hash_b{};
    vx::crypto::pq::PqSignatureWitness witness_a{};
    vx::crypto::pq::PqSignatureWitness witness_b{};
};

} // namespace vx::consensus::gqc
