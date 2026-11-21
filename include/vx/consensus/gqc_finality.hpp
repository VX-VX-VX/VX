#pragma once

// Galois Quorum Certificate (GQC) — Phase C: Bitmasked m-of-n XMSS committee.
//
// Finalization gadget over REAL post-quantum signatures: each whitelist
// member signs the domain-separated vote message (epoch, height, block_hash)
// with its one-shot XMSS leaf; the aggregator verifies every vote against the
// member's whitelist root (verify-before-store, the same discipline as the
// SVA witness registry), folds the signers bitmap and stamps the aggregate as
// a sidecar record. Once at least ceil(2/3 * n) members have voted, the block
// is cemented as a finalized checkpoint in the UndoEngine.
//
// After cementation any rollback_to_height(h) with h below the checkpoint is
// refused with ERR_FINALIZED_BY_GQC — an absolute defence against deep
// reorganizations and 51% attacks.
//
// Accountability: the certificate records exactly WHO signed (a uint64_t
// bitmap over the canonically-ordered whitelist). Two valid witnesses from
// one member on different block hashes at the same height are a mathematical
// proof of equivocation (GqcEquivocationProof).

#include "vx/consensus/gqc_votes.hpp"
#include "vx/state/undo_engine.hpp"
#include "vx/storage/block_store.hpp"
#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <set>
#include <string>
#include <vector>

namespace vx::consensus {

inline constexpr size_t   GQC_AGG_BYTES   = 32;
// The aggregate is persisted as a versioned sidecar record (<ledger>.gqc),
// NOT inside the frame: the 104-byte tail is fully occupied by VM/PoGW
// metadata (external review round 5).

struct GaloisQuorumCert {
    std::array<uint8_t, 32> block_hash{};
    uint64_t block_height = 0;
    uint32_t validator_count = 0;   // size of the quorum set
    uint32_t share_count = 0;       // aggregated votes (kept for the RPC shape)
    uint64_t signers_bitmap = 0;    // one bit per canonical member
    std::array<uint8_t, 32> gqc_signature_agg{};
    bool certified = false;
    std::string error;              // non-empty when certified == false
};

class GqcFinality {
public:
    /// 2/3 quorum threshold.
    static constexpr size_t QUORUM_NUM = 2;
    static constexpr size_t QUORUM_DEN = 3;

    explicit GqcFinality(state::UndoEngine& undo, storage::BlockStore& store);

    uint64_t finalized_checkpoint_height() const noexcept { return finalized_height_; }

    /// Hygiene 2v (owner-directed 19.11): health-RPC observability.
    /// Seconds since the last successful finalize (0 = never finalized).
    uint64_t finalize_age_sec() const noexcept {
        if (last_finalize_time_ == std::chrono::steady_clock::time_point{})
            return 0;
        return std::chrono::duration_cast<std::chrono::seconds>(std::chrono::steady_clock::now() -
                                                                last_finalize_time_)
            .count();
    }

    /// Highest height with collected votes still pending a quorum (0 = none).
    /// G3 (audit dc8c4e6): pools are pruned after finalize, so this reports
    /// the last UN-finalized height honestly — never the finalized one.
    uint64_t pending_quorum_height() const noexcept {
        return vote_pools_.empty() ? 0 : vote_pools_.rbegin()->first;
    }

    /// Collect one vote for (height, hash). Verify-before-store: the vote
    /// must come from a whitelist member (forged ids are refused) and verify
    /// against that member's root. A second valid vote from the same member
    /// at the same height on a DIFFERENT hash is equivocation — both
    /// witnesses are recorded as a GqcEquivocationProof.
    void collect_vote(uint64_t block_height, const std::array<uint8_t, 32> &block_hash,
                      const gqc::GqcVote &vote);

    /// Aggregate the collected votes (>= ceil(2/3 * validator_count) distinct
    /// members) into a certificate, stamp the aggregate into the sidecar and
    /// cement the checkpoint in the UndoEngine. Returns a cert with
    /// certified=false when the quorum is not met.
    GaloisQuorumCert finalize_block(uint64_t block_height,
                                    const std::array<uint8_t, 32>& block_hash,
                                    uint32_t validator_count);

    /// Drain the equivocation proofs recorded so far (durable copy lands in
    /// the .gqcv sidecar; the slashing consequences are P4).
    std::vector<gqc::GqcEquivocationProof> take_equivocations();

private:
    state::UndoEngine& undo_;
    storage::BlockStore& store_;
    uint64_t finalized_height_ = 0;
    uint64_t epoch_ = 1; // bound into every vote message
    // epoch = never finalized (health RPC, hygiene 2v).
    std::chrono::steady_clock::time_point last_finalize_time_{};
    // (height, hash) -> validator_id -> vote
    // Votes are pooled per (height, block hash) — keying by height alone
    // let votes for DIFFERENT blocks at the same height mix into one
    // quorum (external review P1).
    std::map<uint64_t, std::map<std::array<uint8_t, 32>, std::map<uint16_t, gqc::GqcVote>>>
        vote_pools_;
    // (height, validator_id) -> first valid vote with its block hash (the
    // equivocation baseline: a second valid vote on a DIFFERENT hash proves
    // the member signed two forks at the same height).
    struct FirstVote {
        std::array<uint8_t, 32> block_hash{};
        gqc::GqcVote vote{};
    };
    std::map<std::pair<uint64_t, uint16_t>, FirstVote> first_vote_by_;
    // (height, validator_id) keys that already produced a proof — the spec's
    // O(1) drop: the first valid proof is the evidence, further conflicting
    // votes from the same guilty member add nothing.
    std::set<std::pair<uint64_t, uint16_t>> guilty_keys_;
    std::vector<gqc::GqcEquivocationProof> equivocations_;
};

} // namespace vx::consensus
