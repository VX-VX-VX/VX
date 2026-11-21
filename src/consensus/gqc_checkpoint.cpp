// GQC checkpoint certificates — Phase D (0.2.3).
//
// verify_checkpoint(): the certificate is one verifiable object. The
// verifier trusts only the whitelist (master-signed, boot-checked) and
// re-derives everything else: membership, quorum count, bitmap, agg.

#include "vx/consensus/gqc_checkpoint.hpp"
#include "vx/blockchain/crypto_sponge.hpp"

#include <algorithm>

namespace vx::consensus::gqc {

GqcWhitelistView whitelist_view(const blockchain::GqcEpochConfig &config) {
    GqcWhitelistView view;
    view.epoch = config.epoch;
    view.roots_by_index.reserve(config.members.size());
    for (const auto &m : config.members)
        view.roots_by_index.push_back(m.root);
    // Canonical order: sorted by root bytes — the same order genesis.cpp
    // guarantees, re-enforced here so a hand-built config still yields a
    // deterministic bitmap.
    std::sort(view.roots_by_index.begin(), view.roots_by_index.end());
    return view;
}

bool verify_checkpoint(const GqcCheckpointCert &cert, const GqcWhitelistView &whitelist) {
    const size_t n = whitelist.roots_by_index.size();
    if (n == 0 || n > 64)
        return false; // bitmap is uint64_t — fail-closed above 64
    // DoS gate: a member votes at most once, so more than n votes can
    // never verify — refuse the flood before any per-vote work.
    if (cert.votes.size() > n)
        return false;
    // The cert's claimed epoch must match the whitelist's epoch: a cert
    // minted under a different epoch's whitelist is stale or foreign and
    // must not verify even if its votes happen to pass the vote check.
    if (cert.epoch != whitelist.epoch)
        return false;

    // Quorum: >= ceil(2n/3) distinct members.
    const size_t needed = (2 * n + 2) / 3;

    // Each vote must verify against ITS OWN member root — the root comes
    // from the whitelist, never from the witness (identity substitution
    // gate, Phase C discipline).
    uint64_t bitmap = 0;
    std::vector<bool> root_seen(n, false);
    for (const auto &v : cert.votes) {
        // Locate the member: the witness root must be a whitelist root.
        // Every whitelist root is unique (canonical sort, deterministic
        // test keys) — a duplicate would be a genesis bug, not a vote
        // property.
        int64_t idx = -1;
        for (size_t i = 0; i < n; ++i) {
            if (v.witness.pq_pubkey_root == whitelist.roots_by_index[i]) {
                idx = static_cast<int64_t>(i);
                break;
            }
        }
        if (idx < 0)
            return false; // a vote from outside the whitelist: forged
        if (root_seen[static_cast<size_t>(idx)])
            return false; // two votes from one member: equivocation-shaped
        if (!verify_vote(whitelist.roots_by_index[static_cast<size_t>(idx)], whitelist.epoch,
                         cert.height, cert.block_hash, v))
            return false;
        root_seen[static_cast<size_t>(idx)] = true;
        bitmap |= (1ULL << idx);
    }

    // The bitmap must be exactly the verified set — no phantom signers.
    if (bitmap != cert.signers_bitmap)
        return false;
    if (cert.votes.size() < needed)
        return false;

    // The agg fold must re-compute: the cert's agg commits to the exact
    // signer set (bitmap + witness commitments).
    const auto agg = aggregate_votes(cert.height, cert.signers_bitmap, cert.votes);
    return agg == cert.agg;
}

std::array<uint8_t, 32>
rollover_msg(uint64_t old_epoch, uint64_t new_epoch, const std::array<uint8_t, 32> &old_master_root,
             const std::vector<std::array<uint8_t, 32>> &new_roots) noexcept {
    blockchain::VortexSponge256 sponge;
    const uint8_t tag[] = "VX_GQC_ROLLOVER_V1";
    sponge.absorb(tag, sizeof(tag) - 1);
    const uint8_t le[16] = {
        static_cast<uint8_t>(old_epoch),       static_cast<uint8_t>(old_epoch >> 8),
        static_cast<uint8_t>(old_epoch >> 16), static_cast<uint8_t>(old_epoch >> 24),
        static_cast<uint8_t>(old_epoch >> 32), static_cast<uint8_t>(old_epoch >> 40),
        static_cast<uint8_t>(old_epoch >> 48), static_cast<uint8_t>(old_epoch >> 56),
        static_cast<uint8_t>(new_epoch),       static_cast<uint8_t>(new_epoch >> 8),
        static_cast<uint8_t>(new_epoch >> 16), static_cast<uint8_t>(new_epoch >> 24),
        static_cast<uint8_t>(new_epoch >> 32), static_cast<uint8_t>(new_epoch >> 40),
        static_cast<uint8_t>(new_epoch >> 48), static_cast<uint8_t>(new_epoch >> 56)};
    sponge.absorb(le, 16);
    sponge.absorb(old_master_root.data(), old_master_root.size());
    for (const auto &r : new_roots)
        sponge.absorb(r.data(), r.size());
    std::array<uint8_t, 32> out{};
    sponge.finalize(out.data());
    return out;
}

bool verify_rollover(const GqcRolloverCert &cert,
                     const std::vector<std::array<uint8_t, 32>> &new_roots_canonical) {
    if (cert.new_epoch <= cert.old_epoch)
        return false; // epochs only move forward
    if (cert.new_roots != new_roots_canonical)
        return false; // the cert must carry the canonical order
    if (cert.new_roots.empty())
        return false;
    // DoS gate: the whitelist is at most 64 members (the bitmap bound of
    // the checkpoint path) — a rollover list beyond that is a flood.
    if (cert.new_roots.size() > 64)
        return false;
    // Root gate: the rollover witness must carry the OLD master root —
    // the tree that leaf 15 belongs to. A witness under a different tree
    // is not a rollover. The leaf gate: leaf 15 is reserved EXCLUSIVELY
    // for rollover certificates (owner directive) — a witness on any
    // other leaf is not a rollover even if it verifies cryptographically.
    if (cert.rollover_witness.leaf_index != vx::crypto::pq::PQ_ROLLOVER_CERT_LEAF)
        return false;
    const auto msg =
        rollover_msg(cert.old_epoch, cert.new_epoch, cert.old_master_root, cert.new_roots);
    return vx::crypto::pq::pq_verify_wots_xmss(msg, cert.rollover_witness) &&
           cert.rollover_witness.pq_pubkey_root == cert.old_master_root;
}

} // namespace vx::consensus::gqc
