// GQC Bitmasked m-of-n committee votes — Phase C (0.2.2).
//
// Vote = a real XMSS signature over the (epoch, height, block_hash) triple.
// The aggregator verifies every vote against the whitelist member root
// (verify-before-store, the same discipline as the SVA witness registry),
// folds the signers bitmap and stamps the aggregate as a sidecar record.

#include "vx/consensus/gqc_votes.hpp"
#include "vx/blockchain/crypto_sponge.hpp"

#include <cstring>

namespace vx::consensus::gqc {

std::array<uint8_t, 32> vote_msg(uint64_t epoch, uint64_t height,
                                 const std::array<uint8_t, 32> &block_hash) noexcept {
    blockchain::VortexSponge256 sponge;
    const uint8_t tag[] = "VX_GQC_VOTE_V1";
    sponge.absorb(tag, sizeof(tag) - 1);
    const uint8_t ele[8] = {static_cast<uint8_t>(epoch),       static_cast<uint8_t>(epoch >> 8),
                            static_cast<uint8_t>(epoch >> 16), static_cast<uint8_t>(epoch >> 24),
                            static_cast<uint8_t>(epoch >> 32), static_cast<uint8_t>(epoch >> 40),
                            static_cast<uint8_t>(epoch >> 48), static_cast<uint8_t>(epoch >> 56)};
    sponge.absorb(ele, 8);
    const uint8_t hle[8] = {static_cast<uint8_t>(height),       static_cast<uint8_t>(height >> 8),
                            static_cast<uint8_t>(height >> 16), static_cast<uint8_t>(height >> 24),
                            static_cast<uint8_t>(height >> 32), static_cast<uint8_t>(height >> 40),
                            static_cast<uint8_t>(height >> 48), static_cast<uint8_t>(height >> 56)};
    sponge.absorb(hle, 8);
    sponge.absorb(block_hash.data(), 32);
    std::array<uint8_t, 32> out{};
    sponge.finalize(out.data());
    return out;
}

bool verify_vote(const std::array<uint8_t, 32> &member_root, uint64_t epoch, uint64_t height,
                 const std::array<uint8_t, 32> &block_hash, const GqcVote &vote) noexcept {
    // Root gate FIRST: the witness must carry exactly the whitelist
    // member's root. A witness that verifies under the root it transports
    // is not membership — the attacker controls its own tree.
    if (vote.witness.pq_pubkey_root != member_root)
        return false;
    const auto msg = vote_msg(epoch, height, block_hash);
    return vx::crypto::pq::pq_verify_wots_xmss(msg, vote.witness);
}

GqcVote sign_vote(uint16_t validator_id, const std::array<uint8_t, 32> &master_sk, uint64_t epoch,
                  uint64_t height, const std::array<uint8_t, 32> &block_hash,
                  vx::crypto::pq::PqLeafLedger &ledger) noexcept {
    // The vote message is committed to the exact (epoch, height, hash), so
    // one leaf per (validator, checkpoint) is required — a reused leaf
    // signing two different messages is a WOTS+ leak. The ledger refuses
    // reuse; the lowest free leaf fills the tree 0..14 and exhaustion
    // fails closed (the whitelist rotation is the documented recovery).
    const auto msg = vote_msg(epoch, height, block_hash);
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(master_sk);
    const auto root = vx::crypto::pq::xmss_root(master_sk, pub_seed);
    const int leaf = ledger.reserve_for_tx(root, 0);
    if (leaf < 0)
        return GqcVote{}; // default witness does not verify — fail-closed
    GqcVote v;
    v.validator_id = validator_id;
    v.witness = vx::crypto::pq::pq_sign_message(static_cast<uint32_t>(leaf), kVoteSubtree,
                                                master_sk, pub_seed, msg);
    v.witness.pq_pubkey_root = root;
    return v;
}

std::array<uint8_t, 32> aggregate_votes(uint64_t height, uint64_t bitmap,
                                        const std::vector<GqcVote> &votes) noexcept {
    // Commitment to the exact signer set: the bitmap fixes WHO signed and
    // each witness commitment fixes WHAT was signed. The fold is an XOR
    // over sponge outputs — order-independent, and it cannot be steered by
    // a hostile pool without owning a quorum's keys.
    std::array<uint8_t, 32> acc{};
    const uint8_t hle[8] = {static_cast<uint8_t>(height),       static_cast<uint8_t>(height >> 8),
                            static_cast<uint8_t>(height >> 16), static_cast<uint8_t>(height >> 24),
                            static_cast<uint8_t>(height >> 32), static_cast<uint8_t>(height >> 40),
                            static_cast<uint8_t>(height >> 48), static_cast<uint8_t>(height >> 56)};
    std::memcpy(acc.data(), hle, 8);
    std::memcpy(acc.data() + 8, &bitmap, 8);
    for (const auto &v : votes) {
        const auto c = vx::crypto::pq::witness_commitment(v.witness);
        for (size_t i = 0; i < 32; ++i)
            acc[i] ^= c[i];
    }
    blockchain::VortexSponge256 sponge;
    const uint8_t tag[] = "GQCAGG2";
    sponge.absorb(tag, sizeof(tag) - 1);
    sponge.absorb(acc.data(), 32);
    std::array<uint8_t, 32> out{};
    sponge.finalize(out.data());
    return out;
}

} // namespace vx::consensus::gqc
