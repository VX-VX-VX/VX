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
    /// Throws std::runtime_error on I/O failure or corrupt frames.
    explicit BlockStore(const std::string& path, const std::string& genesis_path = "genesis.bin");

    ~BlockStore() noexcept;

    BlockStore(const BlockStore&) = delete;
    BlockStore& operator=(const BlockStore&) = delete;

    /// Appends a validated frame at the chain tip. O(1) (single pwrite).
    /// Rejects frames with wrong magic or height != current tip + 1 (no genesis double-append).
    bool append_block(const blockchain::BlockFrame& frame);

    /// Zero-copy O(1) view of the block at height H. nullptr if out of range.
    const blockchain::RawBlock* get_block(uint64_t height) const noexcept;

    /// Number of blocks in the chain (highest height + 1).
    uint64_t chain_height() const noexcept { return count_; }

    /// Header commitment of the tip block (32 bytes) for the next block's prev_block_hash.
    void tip_hash(uint8_t out[32]) const noexcept;

 /// write the 32-byte GQC aggregate into the block tail at frame
    /// offset 65464..65495 and flush the mapping (the tail is the padding area,
    /// so this does not alter the header commitment).
    void stamp_gqc_into_tail(uint64_t height, const uint8_t agg[32]);
    const std::string& path() const noexcept { return path_; }

private:
    bool ensure_mapping(uint64_t new_bytes);

    std::string path_;
    int fd_ = -1;
    void* mapped_ = nullptr;
    uint64_t mapped_bytes_ = 0;
    uint64_t count_ = 0;
};

} // namespace vx::storage
