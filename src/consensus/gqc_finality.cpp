#include "vx/consensus/gqc_finality.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/state/galois_trie.hpp" // gf256_mul over GF(2^8), 0x11B
#include <algorithm>
#include <cstring>

namespace vx::consensus {

GqcFinality::GqcFinality(state::UndoEngine& undo, storage::BlockStore& store)
    : undo_(undo), store_(store) {}

std::array<uint8_t, 32> GqcFinality::derive_validator_share(
    const std::array<uint8_t, 32>& block_hash,
    uint64_t block_height,
    uint16_t validator_id) {
    // Shamir/Galois evaluation s_i = P(x_i) simulated through the sponge:
    // the polynomial is domain-bound to this exact block commitment.
    blockchain::VortexSponge256 sponge;
    const uint8_t tag[] = "GQCSHARE";
    sponge.absorb(tag, sizeof(tag) - 1);
    sponge.absorb(block_hash.data(), 32);
    const uint8_t hle[8] = {
        static_cast<uint8_t>(block_height), static_cast<uint8_t>(block_height >> 8),
        static_cast<uint8_t>(block_height >> 16), static_cast<uint8_t>(block_height >> 24),
        static_cast<uint8_t>(block_height >> 32), static_cast<uint8_t>(block_height >> 40),
        static_cast<uint8_t>(block_height >> 48), static_cast<uint8_t>(block_height >> 56)};
    sponge.absorb(hle, 8);
    const uint8_t ile[2] = {static_cast<uint8_t>(validator_id),
                            static_cast<uint8_t>(validator_id >> 8)};
    sponge.absorb(ile, 2);
    std::array<uint8_t, 32> out{};
    sponge.finalize(out.data());
    return out;
}

std::array<uint8_t, 32> GqcFinality::aggregate_shares(
    const std::vector<GqcShare>& shares,
    const std::array<uint8_t, 32>& block_hash,
    uint64_t block_height) {
    // Threshold fold in GF(2^8): running accumulator is multiplied by every
    // share byte (no division anywhere), then domain-separated by the sponge.
    std::array<uint8_t, 32> acc{};
    std::memcpy(acc.data(), block_hash.data(), 32);

    std::vector<GqcShare> sorted(shares);
    std::sort(sorted.begin(), sorted.end(),
              [](const GqcShare& a, const GqcShare& b) { return a.validator_id < b.validator_id; });
    for (const auto& sh : sorted) {
        for (size_t j = 0; j < 32; ++j) {
            acc[j] = static_cast<uint8_t>(
                vx::state::gf256_mul(acc[j], sh.share[j]) ^ sh.share[j]);
        }
    }

    blockchain::VortexSponge256 sponge;
    const uint8_t tag[] = "GQCAGG";
    sponge.absorb(tag, sizeof(tag) - 1);
    const uint8_t hle[8] = {
        static_cast<uint8_t>(block_height), static_cast<uint8_t>(block_height >> 8),
        static_cast<uint8_t>(block_height >> 16), static_cast<uint8_t>(block_height >> 24),
        static_cast<uint8_t>(block_height >> 32), static_cast<uint8_t>(block_height >> 40),
        static_cast<uint8_t>(block_height >> 48), static_cast<uint8_t>(block_height >> 56)};
    sponge.absorb(hle, 8);
    sponge.absorb(acc.data(), 32);
    std::array<uint8_t, 32> out{};
    sponge.finalize(out.data());
    return out;
}

void GqcFinality::collect_share(uint64_t block_height,
                                const std::array<uint8_t, 32>& block_hash,
                                uint16_t validator_id,
                                const std::array<uint8_t, 32>& share) {
    share_pools_[block_height][validator_id] = share;
    (void)block_hash;
}

GaloisQuorumCert GqcFinality::finalize_block(uint64_t block_height,
                                             const std::array<uint8_t, 32>& block_hash,
                                             uint32_t validator_count) {
    GaloisQuorumCert cert;
    cert.block_hash = block_hash;
    cert.block_height = block_height;
    cert.validator_count = validator_count;

    const auto pool_it = share_pools_.find(block_height);
    if (pool_it == share_pools_.end()) {
        cert.error = "no shares collected for this height";
        return cert;
    }

    // Quorum: >= ceil(2/3 * validator_count) distinct validator shares.
    const size_t needed = (QUORUM_NUM * validator_count + QUORUM_DEN - 1) / QUORUM_DEN;
    std::vector<GqcShare> shares;
    shares.reserve(pool_it->second.size());
    for (const auto& [id, share] : pool_it->second) shares.push_back({id, share});
    cert.share_count = static_cast<uint32_t>(shares.size());

    if (shares.size() < needed) {
        cert.error = "quorum not met: " + std::to_string(shares.size()) + "/" +
                     std::to_string(needed) + " shares";
        return cert;
    }

    cert.gqc_signature_agg = aggregate_shares(shares, block_hash, block_height);

    // Stamp the aggregate into the stored 64 KB frame tail (offset 65464).
    store_.stamp_gqc_into_tail(block_height, cert.gqc_signature_agg.data());

    // Cement: no rollback may ever cross below this checkpoint again.
    undo_.lock_finalized_height(block_height);
    finalized_height_ = block_height;
    cert.certified = true;
    return cert;
}

} // namespace vx::consensus
