#pragma once

#include "vx/blockchain/block.hpp"
#include "vx/consensus/retarget.hpp"
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
 *
 * PoGW difficulty is ASERT-retargeted and height-derived (BACKLOG 0.9
 * remainder): the ctor parameter carries the genesis/anchor seal strength
 * and the difficulty for any height is recomputed from it and the half-life,
 * never stored -- so every node with the same genesis anchor agrees on the
 * difficulty with no wire or store format change.
 */
class BlockStore {
public:
    /// Opens (or creates) the ledger file. If empty, seeds it with genesis.bin.
    /// `required_pogw_bits` is the ASERT anchor/genesis difficulty (the seal
    /// strength of heights 0 and 1); the live requirement at later heights
    /// grows from it by the retarget half-life (see vx/consensus/retarget.hpp).
    /// Production uses the default (16); tests may lower it to keep PoGW
    /// search fast. `retarget` pins the retarget parameters; all nodes on one
    /// chain must share them. Throws std::runtime_error on I/O failure or
    /// corrupt frames.
    explicit BlockStore(
        const std::string &path, const std::string &genesis_path = "genesis.bin",
        uint64_t required_pogw_bits = blockchain::DEFAULT_POGW_DIFFICULTY_BITS,
        const consensus::PogwRetargetParams &retarget = consensus::POGW_MAINNET_RETARGET);

    ~BlockStore() noexcept;

    BlockStore(const BlockStore &) = delete;
    BlockStore &operator=(const BlockStore &) = delete;

    /// Appends a frame at the chain tip after the single intake gate
    /// (BACKLOG 0.9): magic, height == tip + 1, prev-hash binding, tx_count
    /// bound, merkle commitment, timestamp monotonicity/sanity and PoGW work.
    /// O(1) append (single pwrite + fsync).
    bool append_block(const blockchain::BlockFrame &frame);

    /// Removes the last appended frame from the ledger file (ftruncate back
    /// to the previous tip). Safety net for the rare case where a block the
    /// gate accepted is refused by the state layer afterwards: the store and
    /// the ledger must never disagree about the tip. The genesis frame is
    /// never rolled back.
    bool rollback_last_append() noexcept;

    /// Reason of the most recent append_block rejection (empty after a
    /// success). Diagnostics only — the bool return is the contract.
    const std::string &last_error() const noexcept {
        return last_error_;
    }

    /// ASERT PoGW difficulty (required leading zero bits) at a given height.
    /// Pure function of the anchor parameters and the height; heights 0 and 1
    /// sit at the anchor. The height-0 genesis frame is the anchor and is
    /// exempt from the gate (it is seeded directly, never appended).
    uint64_t pogw_bits_for_height(uint64_t height) const noexcept {
        return consensus::asert_pogw_bits(retarget_, height);
    }

    /// Live-intake difficulty this store enforces: the ASERT bits for the
    /// NEXT expected height (the sealing frontier, height == chain_height()).
    /// Height-aware, so miners, RPC sealing helpers and tests can keep
    /// querying it exactly as before the retarget -- their search always aims
    /// at the difficulty the append gate will demand.
    uint64_t required_pogw_bits() const noexcept {
        return pogw_bits_for_height(count_);
    }

    /// Zero-copy O(1) view of the block at height H. nullptr if out of range.
    const blockchain::RawBlock *get_block(uint64_t height) const noexcept;

    /// Number of blocks in the chain (highest height + 1).
    uint64_t chain_height() const noexcept {
        return count_;
    }

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

    /// One-time migration of a legacy v1 sidecar ("VXGQCRT1", 48 B, no
    /// integrity) to v2 ("VXGQCRT2", 52 B with a CRC32C over height+
    /// aggregate). No-op when the file is empty, absent or already v2;
    /// false only when the rewrite fails or the file mixes versions.
    /// The rewrite trusts the pre-migration content exactly once — the
    /// documented bootstrap (crash-torture finding 1, 2026-11-04).
    bool gqc_ensure_integrity() const;

    /// Highest height stamped in the GQC sidecar (BACKLOG 0.13: the
    /// finalized checkpoint must outlive the process — on open the rollback
    /// guard restores it, fail-closed and monotonic). clean=false when the
    /// sidecar contains a corrupt record — the caller must NOT trust the
    /// returned height then; a torn tail (fewer than 52 trailing bytes) is
    /// healed by truncation instead.
    uint64_t highest_gqc_stamp(bool &clean) const;
    const std::string &path() const noexcept {
        return path_;
    }

private:
    bool ensure_mapping(uint64_t new_bytes);

    // ── Write-ahead intent marker (crash-consistent append) ─────────────
    // append_block is ftruncate -> pwrite -> fsync: a crash between the
    // ftruncate and the fsync leaves a TORN frame whose size still lands on
    // the 65536 boundary, so the size check cannot see it - only
    // validate_region can, and its verdict is a hard "corrupted ledger"
    // that needs operator hands. The marker fixes that honestly: before
    // touching the ledger, an INTENT record (height + frame CRC) is fsynced
    // into the sidecar <ledger>.walmark; after the ledger fsync the record
    // is overwritten with COMMITTED and fsynced again. Recovery on open:
    // INTENT + CRC-matching frame = the crash hit between the ledger fsync
    // and the COMMITTED fsync, the frame is complete and stays; INTENT +
    // CRC mismatch = torn frame, healed by truncation; COMMITTED + CRC
    // mismatch at the tip = the durable marker and the disk disagree - real
    // corruption, fail closed (never silently drop a durable block); a
    // marker naming a frame that is not on disk (legitimate truncations
    // below a marker exist - the reorg heal resizes the file directly) or a
    // stale record naming history is resolved (cleared) without authorizing
    // any healing - the surviving chain is always re-judged by
    // validate_region; a corrupt or unreadable sidecar record falls back to
    // the pre-marker fail-closed behavior (full validate_region, torn frame
    // = refuse to start). The sidecar carries at most one 32-byte record:
    // it is truncated to zero once recovery has resolved it.
    static constexpr uint32_t WAL_STATE_INTENT = 1;
    static constexpr uint32_t WAL_STATE_COMMITTED = 2;
    bool wal_write_record_(uint32_t state, uint64_t height, uint32_t frame_crc) noexcept;
    bool wal_clear_() noexcept;
    /// Resolves a leftover marker before the ledger is validated/mmap'd.
    /// `size` is the ledger's byte size (the caller guarantees a whole
    /// number of frames - the byte-accurate torn-tail gate runs first);
    /// returns the frame count to seed the chain height with (the healed
    /// count on the one healing path). Throws std::runtime_error on the
    /// fail-closed paths. A missing or corrupt sidecar falls back to
    /// ledger-only validation (no healing, old semantics).
    uint64_t wal_recover_(uint64_t size);

    std::string path_;
    int fd_ = -1;
    int wal_fd_ = -1;
    void *mapped_ = nullptr;
    uint64_t mapped_bytes_ = 0;
    uint64_t count_ = 0;
    consensus::PogwRetargetParams retarget_ = consensus::POGW_MAINNET_RETARGET;
    std::string last_error_;
};

} // namespace vx::storage
