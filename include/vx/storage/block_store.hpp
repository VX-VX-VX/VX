#pragma once

#include "vx/blockchain/block.hpp"
#include <cstdint>
#include <string>
#include <span>

namespace vx::storage {

/**
 * @brief Append-only binary ledger: ledger.vxb is a plain concatenation of
 * fixed 64 KB block frames. Because every frame has identical size, block at
 * height H lives at byte offset H * 65536 — random access is O(1) with no
 * index structure, and the whole file is mmap'd so get_block() returns a
 * zero-copy BlockView straight from the page cache.
 *
 * On open, an empty ledger is auto-initialized from ./genesis.bin.
 */
class BlockStore {
public:
    /// Opens (or creates) the ledger file. If empty, seeds it with genesis.bin.
    /// `required_pogw_bits` is the live-intake work requirement enforced by
    /// append_block (BACKLOG 0.9); production uses the default (16), tests
    /// may lower it to keep PoGW search fast. Throws std::runtime_error on
    /// I/O failure or corrupt frames.
    explicit BlockStore(const std::string& path, const std::string& genesis_path = "genesis.bin",
                        uint64_t required_pogw_bits = blockchain::DEFAULT_POGW_DIFFICULTY_BITS);

    ~BlockStore() noexcept;

    BlockStore(const BlockStore&) = delete;
    BlockStore& operator=(const BlockStore&) = delete;

    /// Appends a frame at the chain tip after the single intake gate
    /// (BACKLOG 0.9): magic, height == tip + 1, prev-hash binding, tx_count
    /// bound, merkle commitment, timestamp monotonicity/sanity and PoGW work.
    /// O(1) append (single pwrite + fsync).
    bool append_block(const blockchain::BlockFrame& frame);

    /// Removes the last appended frame from the ledger file (ftruncate back
    /// to the previous tip). Safety net for the rare case where a block the
    /// gate accepted is refused by the state layer afterwards: the store and
    /// the ledger must never disagree about the tip. The genesis frame is
    /// never rolled back.
    bool rollback_last_append() noexcept;

    /// Reason of the most recent append_block rejection (empty after a
    /// success). Diagnostics only — the bool return is the contract.
    const std::string& last_error() const noexcept { return last_error_; }

    /// Live-intake difficulty this store enforces (miners query it so their
    /// search never aims below the gate).
    uint64_t required_pogw_bits() const noexcept { return required_pogw_bits_; }

    /// Zero-copy O(1) view of the block at height H. nullptr if out of range.
    const blockchain::RawBlock* get_block(uint64_t height) const noexcept;

    /// Number of blocks in the chain (highest height + 1).
    uint64_t chain_height() const noexcept { return count_; }

    /// Header commitment of the tip block (32 bytes) for the next block's prev_block_hash.
    void tip_hash(uint8_t out[32]) const noexcept;

 /// Persist the 32-byte GQC aggregate for a certified block as a versioned
    /// sidecar record (<ledger>.gqc). The frame's 104-byte tail has no free
    /// bytes (VM state root / gas / PoGW nonce / bytecode), so the frame
    /// itself is never modified after append (external review round 5).
    // Returns false if the record could not be persisted — the caller must
    // not certify on a failed stamp.
    bool stamp_gqc(uint64_t height, const uint8_t agg[32]);

    /// Read back the persisted GQC aggregate for a block height. Returns
    /// false when no record exists or the sidecar contains a corrupt record
    /// (fail closed).
    bool gqc_stamp(uint64_t height, uint8_t out[32]) const;

    /// Highest height stamped in the GQC sidecar (BACKLOG 0.13: the
    /// finalized checkpoint must outlive the process — on open the rollback
    /// guard restores it, fail-closed and monotonic). clean=false when the
    /// sidecar contains a corrupt record — the caller must NOT trust the
    /// returned height then; a torn tail (fewer than 48 trailing bytes) is
    /// healed by truncation instead.
    uint64_t highest_gqc_stamp(bool& clean) const;
    const std::string& path() const noexcept { return path_; }

private:
    bool ensure_mapping(uint64_t new_bytes);

    std::string path_;
    int fd_ = -1;
    void* mapped_ = nullptr;
    uint64_t mapped_bytes_ = 0;
    uint64_t count_ = 0;
    uint64_t required_pogw_bits_ = blockchain::DEFAULT_POGW_DIFFICULTY_BITS;
    std::string last_error_;
};

} // namespace vx::storage
