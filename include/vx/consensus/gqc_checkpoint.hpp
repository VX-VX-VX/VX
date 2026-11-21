#pragma once

// Galois Quorum Certificate — Phase D: PQ-threshold checkpoint (0.2.3).
//
// The checkpoint certificate is ONE verifiable object: given the master-
// signed whitelist, verify_checkpoint() re-derives the quorum from the
// votes carried inside the certificate — no external state, no trust in
// the aggregator. The threshold property is NOT cryptographic share
// aggregation (Haystack territory, occupied): it is the accountable
// m-of-n mask of Phase C carried into a self-contained cert, plus the
// rollover certificate that rotates the epoch trees.

#include "vx/consensus/gqc_votes.hpp"
#include "vx/blockchain/genesis.hpp"

#include <array>
#include <cstdint>
#include <vector>

namespace vx::consensus::gqc {

/// A minimal whitelist view for verify_checkpoint: the member's root keyed
/// by canonical index (the bitmap bit). Derived from the GqcEpochConfig.
struct GqcWhitelistView {
    std::vector<std::array<uint8_t, 32>> roots_by_index; // canonical order
    uint64_t epoch = 1;
};

/// Builds the canonical whitelist view from the epoch config (sorted by
/// root bytes — the same order genesis.cpp guarantees).
GqcWhitelistView whitelist_view(const blockchain::GqcEpochConfig &config);

// QUORUM_NUM/QUORUM_DEN re-exported from gqc_finality.hpp semantics:
// needed = ceil(2n/3).

/// The checkpoint certificate: verifiable as ONE object against the
/// epoch whitelist. This is the wire object other nodes consume; the
/// finalize path of Phase C assembles it, the verifier path here
/// consumes it.
struct GqcCheckpointCert {
    uint64_t epoch = 0;
    uint64_t height = 0;
    std::array<uint8_t, 32> block_hash{};
    std::array<uint8_t, 32> agg{}; // gqc::aggregate_votes fold
    uint64_t signers_bitmap = 0;   // canonical whitelist order
    uint32_t validator_count = 0;
    std::vector<GqcVote> votes; // the quorum's votes
};

/// Verifies the certificate as ONE object against the whitelist:
///   1. every vote's witness root == its whitelist member root;
///   2. every vote verifies over (epoch, height, block_hash);
///   3. the bitmap matches exactly the set of verified votes (canonical
///      order) and covers >= ceil(2n/3) distinct members;
///   4. the agg fold re-computes to the cert's agg.
/// Returns true only if ALL hold. No trust in the aggregator.
bool verify_checkpoint(const GqcCheckpointCert &cert, const GqcWhitelistView &whitelist);

/// The rollover certificate: closes epoch E and opens epoch E+1.
/// Carries the OLD master-root, the NEW whitelist (roots), and the
/// master's signature over the new whitelist made with the rollover
/// leaf (leaf 15) of the OLD tree — the only designated use of leaf 15.
/// After a successful rollover stamp the old tree is dead: the ledger
/// refuses every further reservation for it (fail-closed).
struct GqcRolloverCert {
    uint64_t old_epoch = 0;
    uint64_t new_epoch = 0;
    std::array<uint8_t, 32> old_master_root{};
    std::vector<std::array<uint8_t, 32>> new_roots;      // canonical order
    vx::crypto::pq::PqSignatureWitness rollover_witness; // leaf 15, old tree
};

/// Verifies the rollover certificate: the witness must verify over the
/// canonical rollover message (old master root + new epoch + new roots)
/// AND carry the old master root (root gate, same discipline as votes).
/// Returns true only if all hold.
bool verify_rollover(const GqcRolloverCert &cert,
                     const std::vector<std::array<uint8_t, 32>> &new_roots_canonical);

/// The canonical rollover message: old_master_root ‖ new_epoch ‖ every
/// new root in canonical order. Domain-separated from votes.
std::array<uint8_t, 32>
rollover_msg(uint64_t old_epoch, uint64_t new_epoch, const std::array<uint8_t, 32> &old_master_root,
             const std::vector<std::array<uint8_t, 32>> &new_roots) noexcept;

} // namespace vx::consensus::gqc
