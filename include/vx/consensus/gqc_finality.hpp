#pragma once

// Galois Quorum Certificate (GQC).
//
// Threshold finality gadget over GF(2^8) (irreducible polynomial 0x11B):
// swarm validators evaluate a per-block Shamir/Galois share; once at least
// 2/3 of the quorum set have contributed, the shares are aggregated into a
// 32-byte gqc_signature_agg which is stamped into the 104-byte block tail
// (offset 65464..65495 of the 64 KB frame) and cements the block as a
// finalized checkpoint in the UndoEngine.
//
// After cementation any rollback_to_height(h) with h below the checkpoint is
// refused with ERR_FINALIZED_BY_GQC — an absolute defence against deep
// reorganizations and 51% attacks.

#include "vx/state/undo_engine.hpp"
#include "vx/storage/block_store.hpp"
#include <array>
#include <cstdint>
#include <map>
#include <string>
#include <vector>

namespace vx::consensus {

inline constexpr size_t   GQC_AGG_BYTES   = 32;
/// Byte offset of gqc_signature_agg inside a 64 KB block frame
/// (blockchain::GQC_TAIL_OFFSET = 65464; tail bytes 32..63).
inline constexpr uint64_t GQC_TAIL_OFFSET = blockchain::GQC_TAIL_OFFSET;

struct GqcShare {
    uint16_t validator_id = 0;
    std::array<uint8_t, 32> share{};
};

struct GaloisQuorumCert {
    std::array<uint8_t, 32> block_hash{};
    uint64_t block_height = 0;
    uint32_t validator_count = 0;   // size of the quorum set
    uint32_t share_count = 0;       // aggregated shares
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

    /// Collect one GF(2^8) share for (height, hash) from a validator.
    void collect_share(uint64_t block_height,
                       const std::array<uint8_t, 32>& block_hash,
                       uint16_t validator_id,
                       const std::array<uint8_t, 32>& share);

    /// Aggregate the collected shares (>= ceil(2/3 * validator_count)) into a
    /// certificate, stamp gqc_signature_agg into the block tail and cement
    /// the checkpoint in the UndoEngine. Returns a cert with certified=false
    /// when the quorum is not met.
    GaloisQuorumCert finalize_block(uint64_t block_height,
                                    const std::array<uint8_t, 32>& block_hash,
                                    uint32_t validator_count);

    /// Deterministic per-validator share: simulates the GF(2^8) Shamir
    /// polynomial evaluation performed by each swarm peer for (hash, height).
    static std::array<uint8_t, 32> derive_validator_share(
        const std::array<uint8_t, 32>& block_hash,
        uint64_t block_height,
        uint16_t validator_id);

    /// Fold shares (sorted by validator id) through GF(2^8) multiplication
    /// and domain-separate the result through the Vortex sponge.
    static std::array<uint8_t, 32> aggregate_shares(
        const std::vector<GqcShare>& shares,
        const std::array<uint8_t, 32>& block_hash,
        uint64_t block_height);

private:
    state::UndoEngine& undo_;
    storage::BlockStore& store_;
    uint64_t finalized_height_ = 0;
    // (height, hash) -> validator_id -> share
    std::map<uint64_t, std::map<uint16_t, std::array<uint8_t, 32>>> share_pools_;
};

} // namespace vx::consensus
