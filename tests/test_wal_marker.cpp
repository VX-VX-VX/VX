// VortexWalMarkerTest - crash-consistent append for BlockStore (WAL marker).
//
// The append path is ftruncate -> pwrite -> fsync. A crash between the
// ftruncate and the fsync leaves a torn frame whose file size still lands
// on the 65536 boundary, so the size check cannot see it and the pre-marker
// recovery was a hard "corrupted ledger" throw needing operator hands.
// The sidecar <ledger>.walmark carries ONE 32-byte record
// ("VXWALMK1" + state + height + frame-CRC32C + reserved + record-CRC32C):
// INTENT is fsynced before the ledger is touched, COMMITTED after the
// ledger fsync. These tests pin the recovery matrix by writing the marker
// bytes exactly the way the crashed writer would have left them:
//
//   1. clean roundtrip        - marker empty after a normal run
//   2. INTENT + torn frame    - healed by truncation, chain continues
//   3. INTENT + whole frame   - crash between ledger fsync and COMMITTED
//                               fsync: the frame stays, height preserved
//   4. COMMITTED + CRC miss   - durable marker vs disk disagreement at the
//                               tip = real corruption, fail closed (throw)
//   5. corrupt sidecar record - fail-closed fallback to ledger-only
//                               validation (clean ledger opens; torn
//                               frame still refuses to start)
//   6. COMMITTED, frame absent- legitimate truncation below a marker (the
//                               reorg heal resizes the file directly): the
//                               marker is resolved, the chain reopens at
//                               its real height (first draft failed this
//                               closed - the crash-torture gate caught it)
//   7. stale marker height    - resolved (cleared), never authorized to
//                               truncate valid history
//   8. INTENT beyond the file - crash before the ftruncate: nothing to
//                               heal, resolved, the chain continues
//   9. rollback clears marker - no marker may outlive the frame it names
//
// No production code is touched by this test; everything it exercises is
// the shipped BlockStore durability contract.

#include <gtest/gtest.h>

#include "vx/blockchain/block.hpp"
#include "vx/net/swarm_node.hpp" // compute_wire_crc32c (marker CRC parity)
#include "vx/storage/block_store.hpp"

#include <unistd.h>

#include <cstring>
#include <filesystem>
#include <fstream>
#include <memory>
#include <stdexcept>
#include <string>
#include <vector>

using namespace vx::blockchain;

namespace {

constexpr size_t kWalRec = 32;
constexpr size_t kWalBody = 28;
constexpr uint32_t kIntent = 1;
constexpr uint32_t kCommitted = 2;

std::string temp_dir(const char *tag) {
    auto root = std::filesystem::temp_directory_path() /
                ("vx_wal_" + std::to_string(::getpid()) + "_" + tag);
    std::filesystem::remove_all(root);
    std::filesystem::create_directories(root);
    return root.string();
}

// Mirrors the production record layout byte for byte (the format is a pin:
// if the writer changes it, these tests must change with it).
void write_marker(const std::string &path, uint32_t state, uint64_t height, uint32_t frame_crc) {
    uint8_t rec[kWalRec] = {};
    std::memcpy(rec, "VXWALMK1", 8);
    std::memcpy(rec + 8, &state, 4);
    std::memcpy(rec + 12, &height, 8);
    std::memcpy(rec + 20, &frame_crc, 4);
    const uint32_t crc = vx::net::compute_wire_crc32c(rec, kWalBody);
    std::memcpy(rec + kWalBody, &crc, 4);
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char *>(rec), sizeof(rec));
    ASSERT_TRUE(f.good());
}

void write_frame_bytes(const std::string &path, uint64_t height, const uint8_t *src) {
    std::ofstream f(path, std::ios::binary | std::ios::in | std::ios::out);
    f.seekp(static_cast<std::streamoff>(height * BLOCK_SIZE_BYTES));
    f.write(reinterpret_cast<const char *>(src), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(f.good());
}

struct Harness {
    std::string dir;
    std::string ledger;
    std::string marker;

    explicit Harness(const char *tag)
        : dir(temp_dir(tag)), ledger(dir + "/chain.vxb"), marker(ledger + ".walmark") {
    }

    std::unique_ptr<vx::storage::BlockStore> open() {
        return std::make_unique<vx::storage::BlockStore>(ledger, "genesis.bin", 8);
    }
};

// Seal + append one honest floor-coinbase block; asserts the gate accepted.
void push_block(vx::storage::BlockStore &store) {
    // Timestamps must march forward from the genesis header (the gate
    // rejects an "older than the tip" frame), so every harness derives its
    // clock from the genesis frame, like the crash-torture suite does.
    BlockBuilder b;
    b.set_height(store.chain_height());
    b.set_timestamp(store.get_block(store.chain_height() - 1)->header.timestamp + 1);
    uint8_t tip[32];
    store.tip_hash(tip);
    b.set_prev_hash(tip);
    std::array<uint8_t, 384> coords{};
    b.set_attractor_coords(coords.data());
    b.finalize();
    BlockFrame frame;
    std::memcpy(frame.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(seal_pogw_nonce(frame, store.required_pogw_bits()));
    ASSERT_TRUE(store.append_block(frame)) << store.last_error();
}

// A sealed-but-unappended frame for the store's next height (the crash
// writers "were about to append this"). The timestamp continues the tip's
// clock, exactly as a real append would have set it.
BlockFrame build_next_frame(vx::storage::BlockStore &store) {
    BlockBuilder b;
    b.set_height(store.chain_height());
    b.set_timestamp(store.get_block(store.chain_height() - 1)->header.timestamp + 1);
    uint8_t tip[32];
    store.tip_hash(tip);
    b.set_prev_hash(tip);
    std::array<uint8_t, 384> coords{};
    b.set_attractor_coords(coords.data());
    b.finalize();
    BlockFrame frame;
    std::memcpy(frame.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    EXPECT_TRUE(seal_pogw_nonce(frame, store.required_pogw_bits()));
    return frame;
}

std::vector<uint8_t> read_file(const std::string &path) {
    std::ifstream f(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
}

} // namespace

// 1. A normal append run leaves the sidecar holding at most the last
//    COMMITTED record (cleared on the next open's recovery); a reopen
//    resolves it and the chain continues exactly.
TEST(VortexWalMarkerTest, CleanRunLeavesMarkerEmpty) {
    Harness h("clean");
    {
        auto store = h.open();
        ASSERT_EQ(store->chain_height(), 1u);
        push_block(*store);
        push_block(*store);
        ASSERT_EQ(store->chain_height(), 3u);
    }
    // After a clean run the marker is either empty (nothing in flight) or
    // the COMMITTED record of the last durable append - never INTENT.
    std::vector<uint8_t> rec = read_file(h.marker);
    ASSERT_TRUE(rec.size() == 0 || rec.size() == kWalRec);
    if (rec.size() == kWalRec) {
        ASSERT_EQ(std::memcmp(rec.data(), "VXWALMK1", 8), 0);
        uint32_t state = 0;
        std::memcpy(&state, rec.data() + 8, 4);
        ASSERT_EQ(state, kCommitted) << "a clean run must never leave an INTENT marker";
        uint64_t mheight = 0;
        std::memcpy(&mheight, rec.data() + 12, 8);
        ASSERT_EQ(mheight, 2u) << "marker must name the last appended height";
    }
    auto store = h.open(); // recovery resolves the COMMITTED record
    std::error_code ec;
    const uintmax_t sz = std::filesystem::file_size(h.marker, ec);
    ASSERT_TRUE(ec || sz == 0) << "recovery left the marker unresolved";
    ASSERT_EQ(store->chain_height(), 3u);
    push_block(*store); // the store keeps appending normally
    ASSERT_EQ(store->chain_height(), 4u);
}

// 2. Crash between the ftruncate and the ledger fsync: INTENT marker with a
//    frame that never landed whole. Recovery must truncate the torn frame
//    away and leave a chain the next append continues exactly.
TEST(VortexWalMarkerTest, IntentTornFrameHealsByTruncation) {
    Harness h("torn");
    {
        auto store = h.open();
        push_block(*store);
        ASSERT_EQ(store->chain_height(), 2u);
    }
    // Simulate the crashed append at height 2: file extended, garbage frame.
    std::filesystem::resize_file(h.ledger, 3 * BLOCK_SIZE_BYTES);
    std::vector<uint8_t> garbage(BLOCK_SIZE_BYTES, 0xFF);
    write_frame_bytes(h.ledger, 2, garbage.data());
    write_marker(h.marker, kIntent, 2, 0xDEADBEEF);

    auto store = h.open(); // must NOT throw - this is the healing win
    ASSERT_EQ(store->chain_height(), 2u) << "torn frame survived recovery";
    const auto sz = std::filesystem::file_size(h.ledger);
    ASSERT_EQ(sz, 2 * BLOCK_SIZE_BYTES);
    push_block(*store); // the healed tip accepts the next block
    ASSERT_EQ(store->chain_height(), 3u);
}

// 3. Crash between the ledger fsync and the COMMITTED fsync: the marker
//    still says INTENT but the frame on disk is whole and its CRC matches.
//    The frame must be KEPT - the fsynced append is durable regardless of
//    the marker's final flip.
TEST(VortexWalMarkerTest, IntentWholeFrameIsKept) {
    Harness h("kept");
    BlockFrame pending;
    {
        auto store = h.open();
        push_block(*store);
        pending = build_next_frame(*store);
        ASSERT_EQ(store->chain_height(), 2u);
    }
    // The writer had already extended the file and fsynced the frame; only
    // the COMMITTED flip was lost.
    std::filesystem::resize_file(h.ledger, 3 * BLOCK_SIZE_BYTES);
    write_frame_bytes(h.ledger, 2, pending.data());
    const uint32_t crc = vx::net::compute_wire_crc32c(pending.data(), BLOCK_SIZE_BYTES);
    write_marker(h.marker, kIntent, 2, crc);

    auto store = h.open();
    ASSERT_EQ(store->chain_height(), 3u) << "a whole fsynced frame was dropped";
    const RawBlock *kept = store->get_block(2);
    ASSERT_NE(kept, nullptr);
    ASSERT_EQ(std::memcmp(kept, pending.data(), BLOCK_SIZE_BYTES), 0)
        << "recovered frame differs from the appended bytes";
}

// 4. COMMITTED marker whose frame fails its CRC: the marker is only ever
//    written AFTER the ledger fsync, so a mismatch is corruption (bit rot,
//    tampering) - never a torn write. Fail closed; silently truncating a
//    durable block would fabricate a shorter chain.
TEST(VortexWalMarkerTest, CommittedCrcMismatchFailsClosed) {
    Harness h("committed_miss");
    {
        auto store = h.open();
        push_block(*store);
    }
    std::filesystem::resize_file(h.ledger, 3 * BLOCK_SIZE_BYTES);
    std::vector<uint8_t> garbage(BLOCK_SIZE_BYTES, 0x5A);
    write_frame_bytes(h.ledger, 2, garbage.data());
    write_marker(h.marker, kCommitted, 2, 0xDEADBEEF);
    EXPECT_THROW(h.open(), std::runtime_error);
}

// 5. A corrupt sidecar record is untrusted metadata: fail-closed fallback
//    to the pre-marker behavior. A clean ledger still opens; a torn frame
//    behind a corrupt marker still refuses to start (no healing from
//    garbage, but no bypass either).
TEST(VortexWalMarkerTest, CorruptSidecarFallsBackToLedgerValidation) {
    // 5a. corrupt marker + clean ledger: opens, height intact.
    {
        Harness h("fallback_clean");
        {
            auto store = h.open();
            push_block(*store);
        }
        std::vector<uint8_t> junk(kWalRec, 0x42);
        std::ofstream f(h.marker, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char *>(junk.data()),
                static_cast<std::streamsize>(junk.size()));
        ASSERT_TRUE(f.good());
        auto store = h.open();
        ASSERT_EQ(store->chain_height(), 2u);
    }
    // 5b. corrupt marker + torn frame: refuse to start, like pre-marker.
    {
        Harness h("fallback_torn");
        {
            auto store = h.open();
            push_block(*store);
        }
        std::filesystem::resize_file(h.ledger, 3 * BLOCK_SIZE_BYTES);
        std::vector<uint8_t> garbage(BLOCK_SIZE_BYTES, 0xFF);
        write_frame_bytes(h.ledger, 2, garbage.data());
        std::vector<uint8_t> junk(kWalRec, 0x42);
        std::ofstream f(h.marker, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char *>(junk.data()),
                static_cast<std::streamsize>(junk.size()));
        ASSERT_TRUE(f.good());
        EXPECT_THROW(h.open(), std::runtime_error);
    }
}

// 6. COMMITTED for a height the file does not contain: the ledger fsync
//    always precedes the COMMITTED flip, so this state proves an
//    inconsistent store (external truncation). Throw.
// 6. COMMITTED for a height the file no longer contains: LEGITIMATE ledger
//    truncations below a marker exist - the reorg heal resizes the ledger
//    file directly (truncate_store_to) and leaves the last append's
//    COMMITTED record behind. The first draft of the marker failed those
//    reopens closed (the crash-torture gate caught it); the honest rule is
//    that the marker only speaks about the append frontier, the surviving
//    chain is re-judged by validate_region, and a marker naming a frame
//    that is not on disk is simply resolved (cleared), not a verdict.
TEST(VortexWalMarkerTest, CommittedMarkerSurvivesExternalTruncation) {
    Harness h("truncated_below_marker");
    {
        auto store = h.open();
        push_block(*store);
        ASSERT_EQ(store->chain_height(), 2u); // frames = 2
    }
    // The reorg-heal shape: the ledger is truncated by hand to 1 frame
    // while the marker still names height 1 (the frame just removed).
    std::filesystem::resize_file(h.ledger, 1 * BLOCK_SIZE_BYTES);
    write_marker(h.marker, kCommitted, 1, 0xDEADBEEF);
    auto store = h.open();
    ASSERT_EQ(store->chain_height(), 1u) << "truncated chain must reopen at its real height";
    std::error_code ec;
    const uintmax_t sz = std::filesystem::file_size(h.marker, ec);
    ASSERT_TRUE(ec || sz == 0) << "the resolved marker was not cleared";
    push_block(*store);
    ASSERT_EQ(store->chain_height(), 2u);
}

// 7. A record that passes its CRC but names a long-past height cannot come
//    from the writer (one record, always the live tip). Fail closed.
// 7. A stale record naming long-past history cannot come from the live
//    writer (one record, always the tip), but it also cannot authorize any
//    healing: it is resolved (cleared) and the ledger is judged by
//    validate_region, exactly like every historical frame on every open.
TEST(VortexWalMarkerTest, StaleMarkerHeightIsResolvedNotHonored) {
    Harness h("stale");
    {
        auto store = h.open();
        push_block(*store);
        push_block(*store);
        ASSERT_EQ(store->chain_height(), 3u); // frames = 3
    }
    // INTENT for height 0 while the ledger has 3 frames: stale/injected.
    write_marker(h.marker, kIntent, 0, 0xDEADBEEF);
    auto store = h.open();
    ASSERT_EQ(store->chain_height(), 3u) << "a stale marker must never truncate valid history";
    push_block(*store);
    ASSERT_EQ(store->chain_height(), 4u);
}

// 8. INTENT beyond the ledger's end: the marked frame was never written,
//    which no writer ordering can produce with a smaller file. Throw.
// 8. INTENT beyond the ledger's end: the marked frame was never written
//    (the crash hit between the marker fsync and the ftruncate). Nothing
//    to heal - the marker is resolved and the chain continues.
TEST(VortexWalMarkerTest, IntentBeyondFileResolvesCleanly) {
    Harness h("beyond");
    {
        auto store = h.open();
        push_block(*store);
    }
    write_marker(h.marker, kIntent, 5, 0xDEADBEEF);
    auto store = h.open();
    ASSERT_EQ(store->chain_height(), 2u);
    push_block(*store);
    ASSERT_EQ(store->chain_height(), 3u);
}

// 9. rollback_last_append removes the frame a COMMITTED marker may still
//    name; a leftover marker would fail the next open, so the rollback
//    must clear the sidecar.
TEST(VortexWalMarkerTest, RollbackClearsMarker) {
    Harness h("rollback");
    {
        auto store = h.open();
        push_block(*store);
        push_block(*store);
        ASSERT_TRUE(store->rollback_last_append());
        ASSERT_EQ(store->chain_height(), 2u);
    }
    auto store = h.open();
    ASSERT_EQ(store->chain_height(), 2u) << "rollback left a marker that poisoned the reopen";
    push_block(*store);
    ASSERT_EQ(store->chain_height(), 3u);
}
