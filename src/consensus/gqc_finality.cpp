#include "vx/consensus/gqc_finality.hpp"
#include "vx/blockchain/genesis.hpp"
#include <cstring>
#include <limits>
#include <utility>

namespace vx::consensus {

GqcFinality::GqcFinality(state::UndoEngine &undo, storage::BlockStore &store)
    : undo_(undo), store_(store),
      // BACKLOG 0.13: the undo engine restores the persisted checkpoint
      // from the store's GQC sidecar on open — seed from it so a restarted
      // node reports the cemented height instead of 0.
      finalized_height_(undo.finalized_checkpoint_height()),
      epoch_(blockchain::gqc_epoch_committee().epoch) {
}

void GqcFinality::collect_vote(uint64_t block_height, const std::array<uint8_t, 32> &block_hash,
                               const gqc::GqcVote &vote) {
    // Cemented checkpoints are past: a vote for an already-finalized height
    // can never be aggregated again and would sit in the pool forever (the
    // prune only runs on the finalize of its own height) — refuse it.
    if (block_height <= finalized_height_)
        return;
    // Membership gate FIRST: a vote from a validator_id outside the genesis
    // whitelist is FORGED — it must never pool into a quorum. Refused
    // silently (the caller has no ack path; the refuser-side observability
    // is the pending_quorum_height staying flat while the tip advances).
    const size_t member_idx = blockchain::gqc_epoch_member_index(vote.validator_id);
    if (member_idx == std::numeric_limits<size_t>::max())
        return;

    // Verify-before-store (the SVA witness registry discipline): the
    // witness must verify the vote message AND carry exactly the member's
    // whitelist root. A witness that verifies under the root it transports
    // is not membership — the attacker controls its own tree.
    const auto &member_root = blockchain::gqc_epoch_committee().members[member_idx].root;
    if (!gqc::verify_vote(member_root, epoch_, block_height, block_hash, vote))
        return;

    // Equivocation: the same member produced a valid vote for a DIFFERENT
    // block hash at the same height. Both witnesses are already verified —
    // this is a mathematical proof of guilt, recorded regardless of which
    // fork ultimately wins. Dedup: only the first proof per (height,
    // validator_id) is kept; further conflicting votes are O(1) drops.
    const auto key = std::make_pair(block_height, vote.validator_id);
    const auto seen = first_vote_by_.find(key);
    if (seen != first_vote_by_.end()) {
        if (seen->second.block_hash == block_hash)
            return; // same fork — the first valid vote for it wins
        // Equivocation: one member, two valid witnesses, two fork hashes at
        // the same height. The FIRST proof is the evidence; every further
        // conflicting vote from the same guilty member is an O(1) drop.
        if (guilty_keys_.insert(key).second)
            equivocations_.push_back({vote.validator_id, block_height, seen->second.block_hash,
                                      block_hash, seen->second.vote.witness, vote.witness});
        return;
    }
    first_vote_by_[key] = {block_hash, vote};
    // Bound to the exact block: votes for different blocks at the same
    // height never mix into one quorum.
    vote_pools_[block_height][block_hash][vote.validator_id] = vote;
}

GaloisQuorumCert GqcFinality::finalize_block(uint64_t block_height,
                                             const std::array<uint8_t, 32>& block_hash,
                                             uint32_t validator_count) {
    GaloisQuorumCert cert;
    cert.block_hash = block_hash;
    cert.block_height = block_height;
    cert.validator_count = validator_count;

    const auto pool_it = vote_pools_.find(block_height);
    if (pool_it == vote_pools_.end()) {
        cert.error = "no votes collected for this height";
        return cert;
    }

    // Only votes collected for THIS exact block hash count.
    const auto hash_it = pool_it->second.find(block_hash);
    if (hash_it == pool_it->second.end()) {
        cert.error = "no votes collected for this block hash";
        return cert;
    }

    // Quorum: >= ceil(2/3 * validator_count) distinct member votes.
    const size_t needed = (QUORUM_NUM * validator_count + QUORUM_DEN - 1) / QUORUM_DEN;
    // Canonical order: the bitmap bit of a member is its position in the
    // canonically-sorted whitelist, so every node derives the same mask.
    const auto &members = blockchain::gqc_epoch_committee().members;
    std::vector<gqc::GqcVote> quorum;
    quorum.reserve(hash_it->second.size());
    uint64_t bitmap = 0;
    for (size_t i = 0; i < members.size(); ++i) {
        const auto v = hash_it->second.find(members[i].validator_id);
        if (v == hash_it->second.end())
            continue;
        bitmap |= (1ULL << i);
        quorum.push_back(v->second);
    }
    cert.share_count = static_cast<uint32_t>(quorum.size());
    cert.signers_bitmap = bitmap;

    if (quorum.size() < needed) {
        cert.error = "quorum not met: " + std::to_string(quorum.size()) + "/" +
                     std::to_string(needed) + " votes";
        return cert;
    }

    cert.gqc_signature_agg = gqc::aggregate_votes(block_height, bitmap, quorum);

    // Persist the aggregate as a sidecar record (<ledger>.gqc). A failed
    // stamp must NOT certify: the certificate would exist only in RAM
    // while nothing durable records it (external review P1; round 5 moved
    // the stamp out of the frame tail, which has no free bytes).
    if (!store_.stamp_gqc(block_height, cert.gqc_signature_agg.data())) {
        cert.error = "gqc tail stamp failed";
        return cert;
    }

    // Cement: no rollback may ever cross below this checkpoint again.
    undo_.lock_finalized_height(block_height);
    finalized_height_ = block_height;
    last_finalize_time_ = std::chrono::steady_clock::now();
    cert.certified = true;

    // G3 (audit dc8c4e6): the pools of finalized heights are dead weight —
    // erase them so pending_quorum_height() reports the last UN-finalized
    // height honestly and the map cannot grow unboundedly. The guilt keys
    // prune the same way: once a height is final, no new vote at it can
    // arrive (the pool is gone), so the key is dead weight too.
    vote_pools_.erase(vote_pools_.begin(), vote_pools_.upper_bound(finalized_height_));
    first_vote_by_.erase(first_vote_by_.begin(),
                         first_vote_by_.upper_bound({finalized_height_, 0xFFFF}));
    guilty_keys_.erase(guilty_keys_.begin(), guilty_keys_.upper_bound({finalized_height_, 0xFFFF}));
    return cert;
}

std::vector<gqc::GqcEquivocationProof> GqcFinality::take_equivocations() {
    return std::exchange(equivocations_, {});
}

} // namespace vx::consensus
