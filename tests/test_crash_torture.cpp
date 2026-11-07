// VxCrashTortureTest -- crash/persistence torture for the VX durability layer.
//
// Two levels, all deterministic (fixed-seed PRNG, fixed chain, fixed cut
// points; only real SIGKILL timing varies, and its assertions are
// outcome-tolerant):
//
//   LEVEL 1 -- simulated torn states (~100 PRNG trials). Each trial copies a
//   freshly built template chain (20 blocks: genesis + GENESIS_2 mint block
//   + MINER_-coinbase blocks with PQ-signed transfers; per-block undo
//   journal commits; displaced-frame side journal; GQC sidecar on the gqc
//   template) into a fresh temp dir, corrupts one byte stream at a
//   PRNG-chosen offset and asserts the reopen outcome:
//
//     (a) truncated .vxb tail (inside the last 3 frames) and, every 4th
//         trial, a zeroed appended frame (the ftruncate-landed-pwrite-did-
//         not crash window)
//         -> either a clean "corrupted ledger" / "bad magic" throw, or an
//            open whose chain height is exactly the intact prefix, whose
//            frames are byte-identical to the template prefix and whose
//            fresh replay equals the pre-computed state snapshot for that
//            prefix; the zero-frame variant additionally recovers via the
//            operator truncation and replays the full chain.
//     (b) truncated undo journal (whole-record and mid-record cuts)
//         -> healed to the last complete record; a subsequent rollback
//            over the healed journal succeeds (no gap error) and lands on
//            the state a fresh replay of the surviving prefix produces.
//     (c) truncated undo journal inside a MULTI-TX record tail
//         -> the record's own tx_count probe must heal it (not report
//            corruption); same rollback-equality assertions as (b).
//     (d) flipped magic bytes inside a middle GQC sidecar record
//         -> highest_gqc_stamp fails closed (clean == false, nothing
//            fabricated beyond the intact prefix), gqc_stamp refuses every
//            height, and a reopened UndoEngine reports the persisted
//            checkpoint as NOT trusted.
//     (e) truncated GQC sidecar tail
//         -> healed to the last complete 48-byte record; the highest stamp
//            equals the surviving record count and the checkpoint guard is
//            restored trusted to exactly that height.
//     (f) garbage appended to the undo journal
//         -> reject-or-migrate: a torn-tail-shaped tail is healed to the
//            valid prefix; an unparseable tail discards the file; nothing
//            with a fabricated height is ever replayed.
//     (g) truncated displaced-frames journal mid-record
//         -> the torn record is not replayed; exactly the complete records
//            come back, byte-identical to the displaced fork frames.
//
//   LEVEL 2 -- real SIGKILL (30 trials, gated out under sanitizers). A child
//   process opens the store and appends a 20-block coinbase chain one
//   block at a time (append_block fsyncs internally; the undo journal is
//   committed+fsynced after every block). The parent kills it with SIGKILL
//   at a PRNG-seeded delay (1-50 ms) while it is mid-chain, then asserts
//   the on-disk result is never an invalid chain: the store either reopens
//   cleanly (validate_region passed in the constructor) and replays into a
//   fresh LedgerState with every block applying, or exactly the last frame
//   is torn (crash mid ftruncate/pwrite) and everything below the torn
//   frame replays cleanly after the operator truncation the error message
//   prescribes. The undo journal must load without throwing, may not
//   reference a height the store does not have, and its pre-state records
//   must match the fresh replay of the surviving prefix exactly.
//
// No production code is touched by this test; everything it exercises is
// the shipped BlockStore / UndoEngine / LedgerState durability contract.

#include <gtest/gtest.h>

#include "vx/blockchain/block.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/core/u128.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/state/undo_engine.hpp"
#include "vx/storage/block_store.hpp"

#include <sys/stat.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <unistd.h>

#include <array>
#include <csignal>
#include <iterator>
#include <cstdint>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iostream>
#include <memory>
#include <string>
#include <vector>

using namespace vx::blockchain;
using vx::core::U128;
using vx::state::LedgerState;

namespace {

// -- Deterministic PRNG (splitmix64) -----------------------------------------

struct Rng {
    uint64_t s;
    explicit Rng(uint64_t seed) : s(seed) {}
    uint64_t next() {
        s += 0x9E3779B97F4A7C15ULL;
        uint64_t z = s;
        z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ULL;
        z = (z ^ (z >> 27)) * 0x94D049BB133111EBULL;
        return z ^ (z >> 31);
    }
    uint64_t below(uint64_t n) { return n == 0 ? 0 : next() % n; }
};

// One PRNG stream for every trial; the seed is a policy constant so any
// reviewer replays the exact same corruption matrix.
Rng& trial_rng() {
    static Rng rng(0x5658435241534857ULL); // "VXCRASHHW" bits
    return rng;
}

// -- Small file helpers ------------------------------------------------------

std::string temp_root() {
    auto root = std::filesystem::temp_directory_path() /
                ("vx_crash_torture_" + std::to_string(::getpid()));
    std::filesystem::create_directories(root);
    return root.string();
}

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    return std::vector<uint8_t>((std::istreambuf_iterator<char>(f)),
                                std::istreambuf_iterator<char>());
}

void truncate_file(const std::string& path, uint64_t size) {
    std::filesystem::resize_file(path, static_cast<uintmax_t>(size));
}

void flip_byte(const std::string& path, uint64_t off, uint8_t mask) {
    std::vector<uint8_t> bytes = read_file(path);
    ASSERT_LT(off, bytes.size());
    bytes[off] = static_cast<uint8_t>(bytes[off] ^ mask);
    std::ofstream f(path, std::ios::binary | std::ios::trunc);
    f.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
    ASSERT_TRUE(f.good());
}

void copy_chain(const std::string& src, const std::string& dst) {
    std::filesystem::remove_all(dst);
    std::filesystem::copy(src, dst, std::filesystem::copy_options::recursive);
}

uint64_t u64_le(const uint8_t* p) {
    uint64_t v = 0;
    for (int i = 7; i >= 0; --i) v = (v << 8) | p[i];
    return v;
}

// -- Account / tx idioms (same shapes the other chain tests use) -------------

Address addr_of(const std::string& s) {
    Address a{};
    std::memcpy(a.data(), s.data(), s.size() < 42 ? s.size() : 42);
    return a;
}

struct PqAccount {
    std::array<uint8_t, 32> sk{};
    std::array<uint8_t, 32> root{};
    Address addr{};
};

PqAccount make_pq_account(const char* tag) {
    PqAccount acc;
    VortexSponge256::compute(reinterpret_cast<const uint8_t*>(tag),
                             std::strlen(tag), acc.sk.data());
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(acc.sk);
    acc.root = vx::crypto::pq::xmss_root(acc.sk, pub_seed);
    derive_pq_address(acc.root.data(), acc.addr.data());
    return acc;
}

bool pq_sign(Transaction& tx, const PqAccount& acc) {
    return vx::crypto::pq::pq_sign_transaction(tx, acc.sk);
}

Transaction make_tx(const Address& sender, const Address& receiver,
                    uint64_t amount, uint32_t nonce) {
    Transaction tx{};
    std::memcpy(tx.sender_nfa, sender.data(), 42);
    std::memcpy(tx.receiver_nfa, receiver.data(), 42);
    tx_set_amount(tx, amount);
    tx_set_fee(tx, 100);
    tx_set_nonce(tx, nonce);
    return tx;
}

Transaction make_coinbase(const Address& recv, uint64_t height,
                          const uint8_t prev_tip[32], uint64_t amount_atoms) {
    Transaction cb{};
    std::memcpy(cb.sender_nfa, "MINER_", 6);
    for (size_t i = 6; i < 42; ++i) cb.sender_nfa[i] = '0';
    std::memcpy(cb.receiver_nfa, recv.data(), 42);
    tx_set_amount(cb, amount_atoms); // the guaranteed floor reward
    tx_set_fee(cb, 0);
    tx_set_nonce(cb, 0);
    set_coinbase_binding(cb, height, prev_tip);
    return cb;
}

BlockBuilder next_block(vx::storage::BlockStore& store, uint64_t ts) {
    BlockBuilder b;
    b.set_height(store.chain_height());
    b.set_timestamp(ts);
    uint8_t tip[32];
    store.tip_hash(tip);
    b.set_prev_hash(tip);
    std::array<uint8_t, 384> coords{};
    b.set_attractor_coords(coords.data());
    return b;
}

// Seal + append + ledger-apply + journal, in the production intake order:
// journal the pre-state, append (fsync inside), apply, commit the journal
// (fsync inside). Returns false on the first refusal.
bool push_journaled_block(vx::state::UndoEngine& undo,
                          vx::storage::BlockStore& store,
                          vx::state::LedgerState& ledger, BlockBuilder& b) {
    // VXC7: the producer commits the canonical witness set (one binding
    // per user transaction) into the header BEFORE sealing.
    b.bind_canonical_witnesses(
        [&ledger](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
            return ledger.pq_root_of(a, out);
        });
    b.finalize();
    BlockFrame frame;
    std::memcpy(frame.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    if (!seal_pogw_nonce(frame, store.required_pogw_bits())) return false;
    undo.apply_block(BlockView(frame));
    if (!store.append_block(frame)) return false;
    if (!ledger.apply_block(BlockView(frame)).ok) return false;
    undo.commit_undo_point();
    return true;
}

// -- Journal / sidecar byte-format scanners (read-only, own bytes) -----------

constexpr size_t kJournalHeader = 12;      // "VXUNDOJL" + u32 version
constexpr size_t kUndoTxSize = 42 + 42 + 16 + 16 + 4; // 120 B per undo tx

struct JournalLayout {
    size_t size = 0;
    std::vector<size_t> rec_end;      // end offset of each complete record
    std::vector<uint64_t> heights;    // per complete record
    std::vector<uint64_t> tx_counts;  // per complete record
};

// Walks the journal's complete-record prefix exactly the way the engine's
// reader does; stops at the first torn or malformed tail.
JournalLayout scan_journal(const std::vector<uint8_t>& d) {
    JournalLayout L;
    L.size = d.size();
    if (d.size() < kJournalHeader || std::memcmp(d.data(), "VXUNDOJL", 8) != 0) {
        return L;
    }
    size_t off = kJournalHeader;
    while (off + 88 <= d.size()) {
        const uint64_t tx = u64_le(d.data() + off + 72);
        if (tx > MAX_TX_PER_BLOCK) break;
        const size_t created_pos = off + 80 + tx * kUndoTxSize;
        if (created_pos + 8 > d.size()) break;
        const uint64_t created = u64_le(d.data() + created_pos);
        if (created > 2 * MAX_TX_PER_BLOCK) break;
        // Record size (UndoEngine::record_bytes): 88 fixed bytes, which
        // already include the created-count field, plus the tx array and
        // the created-address list.
        const size_t rec = 88 + tx * kUndoTxSize + created * 42;
        if (off + rec > d.size()) break;
        L.heights.push_back(u64_le(d.data() + off));
        L.tx_counts.push_back(tx);
        off += rec;
        L.rec_end.push_back(off);
    }
    return L;
}

struct DisplacedLayout {
    size_t size = 0;
    size_t complete = 0; // complete records after the header
};

DisplacedLayout scan_displaced(const std::vector<uint8_t>& d) {
    DisplacedLayout L;
    L.size = d.size();
    if (d.size() < 12 || std::memcmp(d.data(), "VXDISPLC", 8) != 0) return L;
    const size_t rec = 8 + 4 + BLOCK_SIZE_BYTES;
    L.complete = (d.size() - 12) / rec;
    return L;
}

// -- State comparison (fresh-replay equality idiom) --------------------------

void expect_same_state(const LedgerState& a, const LedgerState& b,
                       const std::vector<Address>& senders, const char* what) {
    EXPECT_EQ(a.next_expected_height(), b.next_expected_height()) << what;
    EXPECT_EQ(a.total_supply(), b.total_supply()) << what;
    EXPECT_EQ(a.issued_supply(), b.issued_supply()) << what;
    EXPECT_EQ(a.total_burned(), b.total_burned()) << what;
    ASSERT_EQ(a.accounts().size(), b.accounts().size()) << what;
    for (const auto& [addr, bal] : a.accounts()) {
        EXPECT_EQ(bal, b.balance_of(addr)) << what;
    }
    for (const auto& s : senders) {
        EXPECT_EQ(a.get_next_nonce(s), b.get_next_nonce(s)) << what;
    }
}

bool replay_frames(const std::vector<BlockFrame>& frames, size_t count,
                   LedgerState& out, std::string* err) {
    for (size_t i = 0; i < count && i < frames.size(); ++i) {
        const auto res = out.apply_block(BlockView(frames[i]));
        if (!res.ok) {
            if (err) *err = res.error;
            return false;
        }
    }
    return true;
}

// -- Template chain (built once, copied per trial) ---------------------------

constexpr int kTemplateBlocks = 19;   // heights 1..19 (+ genesis = 20 frames)
constexpr int kMinerAccounts = 8;

struct ChainTemplate {
    std::string dir;
    std::vector<BlockFrame> frames;  // 20 frames (0 = genesis)
    std::vector<LedgerState> snap;   // snap[c] = state after c frames
    std::vector<Address> senders;    // every PQ sender (for nonce equality)
    Address sink;
    uint64_t store_size = 0;
    JournalLayout journal;           // layout of <dir>/undo/undo.vxl
    DisplacedLayout displaced;       // layout of <dir>/undo/displaced.vxd
    uint64_t base_ts = 0;
};

// The gqc variant is the same chain plus four GQC sidecar stamps
// (heights 1..4). Kept separate so the journal-rollback trials do not trip
// the finalized-checkpoint guard, exactly like production (a rollback below
// a cemented height is refused with ERR_FINALIZED_BY_GQC).
struct GqcTemplate {
    std::string dir;
    std::vector<uint64_t> stamped_heights; // {1, 2, 3, 4}
};

// Build helpers are void so gtest ASSERT_* may abort them mid-build; the
// templates themselves are lazily built process-wide singletons (every
// trial copies the same immutable chain).
void build_plain_template(ChainTemplate& t) {
    const std::string root = temp_root();
    t.dir = root + "/template_plain";
    std::filesystem::remove_all(t.dir);
    std::filesystem::create_directories(t.dir);

    {
        // Scoped: the engines destruct in reverse declaration order (undo
        // first, then the store) exactly like a closing chain.
        vx::storage::BlockStore store(t.dir + "/ledger.vxb", "genesis.bin", 8);
        vx::state::LedgerState ledger;
        vx::state::UndoEngine undo(t.dir, store, ledger);

        // Genesis frame: journal + apply it (the replay baseline, frame 0).
        const auto* g = store.get_block(0);
        BlockFrame gf;
        std::memcpy(gf.data(), reinterpret_cast<const uint8_t*>(g),
                    BLOCK_SIZE_BYTES);
        // Journal the PRE-state before applying (the same ordering every
        // other block uses), so the genesis record's pre-supply is the true
        // empty state.
        undo.apply_block(BlockView(gf));
        ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);
        undo.commit_undo_point();
        t.frames.push_back(gf);
        t.snap.push_back(LedgerState{}); // snap[0]: empty, for completeness
        t.snap.push_back(ledger);        // snap[1]: after genesis

        // The demo spender funded by the pinned GENESIS_2 mint at height 1,
        // and the rolling pool of self-certifying PQ accounts the coinbases
        // fund (each key signs well under its 16-witness cap).
        PqAccount demo = make_pq_account("VX_CRASH_DEMO_SPENDER_V1");
        demo.addr = vx::blockchain::genesis2_mint_receiver_payload();
        std::vector<PqAccount> miners;
        for (int i = 0; i < kMinerAccounts; ++i) {
            const std::string tag = "VX_CRASH_MINER_SK_V" + std::to_string(i);
            miners.push_back(make_pq_account(tag.c_str()));
        }
        t.sink = addr_of("NFA_CRASH_TORTURE_SINK_000000000000000000000000000");
        t.senders.push_back(demo.addr);
        for (const auto& m : miners) t.senders.push_back(m.addr);

        // Block timestamps: strictly above the genesis frame's own timestamp
        // so the intake gate's monotonicity check passes for any genesis.
        const uint64_t base_ts = store.get_block(0)->header.timestamp + 1;
        t.base_ts = base_ts;

        auto snap_frame = [&store](uint64_t h) {
            BlockFrame f;
            const auto* raw = store.get_block(h);
            std::memcpy(f.data(), reinterpret_cast<const uint8_t*>(raw),
                        BLOCK_SIZE_BYTES);
            return f;
        };

        // Height 1: the MINER_ floor coinbase (index 0) + the pinned
        // GENESIS_2 mint (100,000 VX to the demo spender, once per chain).
        {
            uint8_t tip[32];
            store.tip_hash(tip);
            BlockBuilder b = next_block(store, base_ts + 1);
            Transaction cb = make_coinbase(miners[0].addr, 1, tip,
                                           50ULL * ATOMS_PER_VX);
            Transaction mint = make_tx(addr_of("GENESIS_2"), demo.addr,
                                       vx::blockchain::GENESIS_2_MINT_ATOMICS,
                                       0);
            sign_transaction(mint);
            EXPECT_TRUE(b.add_transaction(cb));
            EXPECT_TRUE(b.add_transaction(mint));
            ASSERT_TRUE(push_journaled_block(undo, store, ledger, b));
            t.frames.push_back(snap_frame(1));
            t.snap.push_back(ledger);
        }

        // Heights 2..19: a floor coinbase funds the next pool account; the
        // account funded one block earlier spends 2 x 1 VX to the sink (PQ
        // signed, sequential nonces).
        uint32_t nonce_counter[kMinerAccounts] = {};
        for (int h = 2; h <= kTemplateBlocks; ++h) {
            const int recv_idx = (h - 1) % kMinerAccounts;
            const int spend_idx = (h - 2) % kMinerAccounts;
            uint8_t tip[32];
            store.tip_hash(tip);
            BlockBuilder b =
                next_block(store, base_ts + static_cast<uint64_t>(h));
            Transaction cb = make_coinbase(miners[recv_idx].addr,
                                           static_cast<uint64_t>(h), tip,
                                           50ULL * ATOMS_PER_VX);
            EXPECT_TRUE(b.add_transaction(cb));
            for (int k = 0; k < 2; ++k) {
                Transaction t1 = make_tx(miners[spend_idx].addr, t.sink,
                                         100000000ULL,
                                         nonce_counter[spend_idx]);
                ASSERT_TRUE(pq_sign(t1, miners[spend_idx]));
                ++nonce_counter[spend_idx];
                EXPECT_TRUE(b.add_transaction(t1));
            }
            ASSERT_TRUE(push_journaled_block(undo, store, ledger, b));
            t.frames.push_back(snap_frame(static_cast<uint64_t>(h)));
            t.snap.push_back(ledger);
        }

        // Preserve the top fork frames in the displaced side journal (the
        // same side file a real reorg rollback fills): blocks above height 5.
        const size_t displaced_records = undo.journal_displaced_frames(5);
        ASSERT_EQ(displaced_records,
                  static_cast<size_t>(kTemplateBlocks - 5));

        // Undo commits (nothing pending), then the store closes.
    }

    t.store_size = std::filesystem::file_size(t.dir + "/ledger.vxb");
    ASSERT_EQ(t.store_size,
              static_cast<uint64_t>(kTemplateBlocks + 1) * BLOCK_SIZE_BYTES);
    t.journal = scan_journal(read_file(t.dir + "/undo/undo.vxl"));
    ASSERT_EQ(t.journal.heights.size(),
              static_cast<size_t>(kTemplateBlocks + 1)); // heights 0..19
    for (size_t i = 0; i < t.journal.heights.size(); ++i) {
        ASSERT_EQ(t.journal.heights[i], i);
    }
    t.displaced = scan_displaced(read_file(t.dir + "/undo/displaced.vxd"));
    ASSERT_EQ(t.displaced.complete, static_cast<size_t>(kTemplateBlocks - 5));
}

const ChainTemplate& plain_template() {
    static ChainTemplate t;
    static bool built = false;
    if (!built) {
        built = true;
        build_plain_template(t);
    }
    return t;
}

void build_gqc_template(GqcTemplate& t) {
    const ChainTemplate& base = plain_template();
    t.dir = temp_root() + "/template_gqc";
    copy_chain(base.dir, t.dir);
    vx::storage::BlockStore store(t.dir + "/ledger.vxb", "genesis.bin", 8);
    for (uint64_t h = 1; h <= 4; ++h) {
        uint8_t agg[32];
        const std::string tag = "VX_GQC_TORTURE_AGG_" + std::to_string(h);
        VortexSponge256::compute(reinterpret_cast<const uint8_t*>(tag.data()),
                                 tag.size(), agg);
        ASSERT_TRUE(store.stamp_gqc(h, agg)) << "GQC stamp for height " << h;
        t.stamped_heights.push_back(h);
    }
}

const GqcTemplate& gqc_template() {
    static GqcTemplate t;
    static bool built = false;
    if (!built) {
        built = true;
        build_gqc_template(t);
    }
    return t;
}

// -- Trial scaffolding -------------------------------------------------------

std::string fresh_trial_dir(const std::string& template_dir, int index) {
    const std::string dst =
        temp_root() + "/trial_" + std::to_string(index);
    copy_chain(template_dir, dst);
    return dst;
}

// Opens a store, returning nullptr (and the error text) when the
// constructor refused the file.
std::unique_ptr<vx::storage::BlockStore> try_open(const std::string& path,
                                                  std::string* err) {
    try {
        return std::make_unique<vx::storage::BlockStore>(path, "genesis.bin", 8);
    } catch (const std::exception& e) {
        if (err) *err = e.what();
        return nullptr;
    }
}

// -- LEVEL 1 trial (a): truncated .vxb tail inside the last 3 frames ---------

void trial_store_truncation(const ChainTemplate& t, int index) {
    Rng& rng = trial_rng();
    const std::string dir = fresh_trial_dir(t.dir, index);
    const std::string path = dir + "/ledger.vxb";

    const uint64_t total_frames = t.store_size / BLOCK_SIZE_BYTES;

    // Every 4th trial also covers the other crash window append_block has:
    // the size-extending ftruncate landed but the frame bytes did not (the
    // LEVEL 2 torn-frame case). The file stays frame-multiple, so the
    // region validation must refuse it with a clean error, and after the
    // operator truncation the error message prescribes, the intact prefix
    // must reopen and replay exactly.
    const bool zero_frame = (index % 4 == 3);
    if (zero_frame) {
        std::ofstream f(path, std::ios::binary | std::ios::app);
        std::vector<char> zeros(BLOCK_SIZE_BYTES, '\0');
        f.write(zeros.data(), static_cast<std::streamsize>(zeros.size()));
        ASSERT_TRUE(f.good());
        std::string err;
        auto store = try_open(path, &err);
        EXPECT_EQ(store, nullptr) << "trial " << index << ": zero frame opened";
        ASSERT_NE(err.find("bad magic"), std::string::npos)
            << "trial " << index << ": unclean reopen error: " << err;
        // Operator move: drop the torn frame, reopen, replay, compare.
        truncate_file(path, t.store_size);
        store = try_open(path, &err);
        ASSERT_NE(store, nullptr) << "trial " << index << ": " << err;
        ASSERT_EQ(store->chain_height(), total_frames) << "trial " << index;
        for (uint64_t h = 0; h < total_frames; ++h) {
            const auto* raw = store->get_block(h);
            ASSERT_NE(raw, nullptr);
            EXPECT_EQ(0, std::memcmp(raw, t.frames[h].data(), BLOCK_SIZE_BYTES))
                << "trial " << index << ": frame " << h << " differs";
        }
        LedgerState replay;
        std::string rerr;
        ASSERT_TRUE(replay_frames(t.frames, total_frames, replay, &rerr))
            << "trial " << index << ": " << rerr;
        expect_same_state(replay, t.snap.back(), t.senders,
                          "zero-frame recovery trial");
        std::filesystem::remove_all(dir);
        return;
    }

    const uint64_t frame =
        total_frames - 3 + rng.below(3); // one of the last 3 frames
    const uint64_t r = rng.below(BLOCK_SIZE_BYTES);
    const uint64_t off = frame * BLOCK_SIZE_BYTES + r;
    truncate_file(path, off);

    const bool boundary = (off % BLOCK_SIZE_BYTES == 0);
    const uint64_t expect_count = off / BLOCK_SIZE_BYTES;

    std::string err;
    auto store = try_open(path, &err);
    if (!boundary) {
        // A partial tail frame can never be opened: fail closed, loudly.
        EXPECT_EQ(store, nullptr) << "trial " << index << ": torn tail opened";
        ASSERT_NE(err.find("corrupted ledger"), std::string::npos)
            << "trial " << index << ": unclean reopen error: " << err;
        EXPECT_NE(err.find("not a multiple of 65536"), std::string::npos)
            << "trial " << index << ": " << err;
    } else {
        // A frame-boundary cut is the intact prefix: reopen must succeed.
        ASSERT_NE(store, nullptr) << "trial " << index << ": " << err;
        ASSERT_EQ(store->chain_height(), expect_count)
            << "trial " << index << ": reopened height is not the intact prefix";
        for (uint64_t h = 0; h < expect_count; ++h) {
            const auto* raw = store->get_block(h);
            ASSERT_NE(raw, nullptr);
            EXPECT_EQ(0, std::memcmp(raw, t.frames[h].data(), BLOCK_SIZE_BYTES))
                << "trial " << index << ": frame " << h << " differs";
        }
        // Fresh replay of the surviving prefix equals the pre-computed state.
        LedgerState replay;
        std::string rerr;
        ASSERT_TRUE(replay_frames(t.frames, expect_count, replay, &rerr))
            << "trial " << index << ": " << rerr;
        expect_same_state(replay, t.snap[expect_count], t.senders,
                          "store-truncation trial");
    }
    std::filesystem::remove_all(dir);
}

// -- LEVEL 1 trials (b)/(c)/(f) shared rollback assertions -------------------

// Loads the corrupted journal against a ledger staged at the journal's own
// healed depth, rolls back to genesis and asserts the reversal lands on the
// fresh-replay state after genesis only (the RoundTrip idiom, over many
// records instead of two).
void expect_journal_heals_and_rolls_back(const std::string& dir, int index,
                                         size_t expect_records) {
    const ChainTemplate& base = plain_template();
    auto store = try_open(dir + "/ledger.vxb", nullptr);
    ASSERT_NE(store, nullptr);

    // Stage the ledger at the state the healed journal can reverse: the
    // journal holds records 0..R-1 (pre-states of genesis and blocks
    // 1..R-1), the rollback undoes blocks 1..R-1, and the coverage guard
    // demands the ledger tip be no further ahead than the journal depth.
    // snap[c] is the state after c applied frames, so c == R here.
    LedgerState ledger = base.snap[expect_records];
    ASSERT_EQ(ledger.next_expected_height(), expect_records);

    vx::state::UndoEngine undo(dir, *store, ledger); // heals on load

    // Healed to the last complete record, never discarded, never shorter.
    const JournalLayout healed =
        scan_journal(read_file(dir + "/undo/undo.vxl"));
    ASSERT_TRUE(std::filesystem::exists(dir + "/undo/undo.vxl"))
        << "trial " << index << ": a torn tail was discarded, not healed";
    ASSERT_EQ(healed.heights.size(), expect_records)
        << "trial " << index << ": healed journal holds the wrong records";
    for (size_t i = 0; i < expect_records; ++i) {
        ASSERT_EQ(healed.heights[i], i);
    }
    ASSERT_EQ(healed.rec_end.back(), healed.size)
        << "trial " << index << ": healed journal still has a torn tail";

    // No gap errors: the rollback over the healed journal must succeed and
    // land exactly on the fresh-replay state after genesis.
    ASSERT_TRUE(undo.rollback_to_height(0)) << "trial " << index << ": "
                                            << undo.last_error();
    expect_same_state(ledger, base.snap[1], base.senders,
                      "post-rollback vs fresh replay");
}

// -- LEVEL 1 trial (b): truncated journal, whole-record and mid-record -------

void trial_journal_truncation(const ChainTemplate& t, int index) {
    Rng& rng = trial_rng();
    const std::string dir = fresh_trial_dir(t.dir, index);
    const std::string jpath = dir + "/undo/undo.vxl";
    const size_t nrec = t.journal.heights.size();

    // Policy reality the trials pin down: a whole-record cut (anywhere) and
    // a mid-record cut that the last record's own tx_count can prove
    // tail-only both heal to the last complete record. A mid-record cut
    // deeper into the last record's created-address list is beyond what the
    // probe can prove, so the engine fails closed and discards the journal
    // instead. Both outcomes are fail-safe; neither may lose the valid
    // prefix silently or fabricate records.
    if (rng.below(2) == 0) {
        // Whole-record cut: keep records 0..keep-1 (at least 2 so the
        // healed journal still reverses a non-empty block range).
        const size_t keep = 2 + rng.below(nrec - 2); // [2, nrec-1]
        truncate_file(jpath, t.journal.rec_end[keep - 1]);
        expect_journal_heals_and_rolls_back(dir, index, keep);
    } else {
        // Mid-record cut. Only a torn LAST record can be proven tail-only:
        // the probe reads its tx_count and requires fewer remaining bytes
        // than 88 + tx_count * 120. A torn record EARLIER in the file, or a
        // deeper tear of the last one, is unprovable mid-file corruption.
        const size_t last = nrec - 1;
        const size_t rec_start = t.journal.rec_end[last - 1];
        const size_t rec_size = t.journal.rec_end[last] - rec_start;
        const size_t provable = 88 + t.journal.tx_counts[last] * kUndoTxSize;
        const size_t cut = rec_start + 1 + rng.below(rec_size - 1);
        truncate_file(jpath, cut);

        if (cut - rec_start < provable) {
            expect_journal_heals_and_rolls_back(dir, index, last);
        } else {
            // Fail closed: the whole journal is discarded and rebuilt from
            // live application; a rollback must then refuse, never
            // half-revert.
            auto store = try_open(dir + "/ledger.vxb", nullptr);
            ASSERT_NE(store, nullptr);
            LedgerState ledger = t.snap.back();
            vx::state::UndoEngine undo(dir, *store, ledger);
            EXPECT_FALSE(std::filesystem::exists(jpath))
                << "trial " << index << ": an unprovable torn tail was kept";
            EXPECT_FALSE(undo.rollback_to_height(0));
        }
    }
    std::filesystem::remove_all(dir);
}

// -- LEVEL 1 trial (c): torn tail inside a MULTI-TX record -------------------

void trial_multi_tx_record_truncation(const ChainTemplate& t, int index) {
    Rng& rng = trial_rng();
    const std::string dir = fresh_trial_dir(t.dir, index);
    const std::string jpath = dir + "/undo/undo.vxl";

    // The LAST record is the only one a truncation can tear; every record
    // here is multi-tx (coinbase + transfers). The engine's probe reads the
    // record's own tx_count at byte 72 and must classify a tail that cannot
    // hold 88 + tx_count * 120 bytes as a torn tail -- healed, not corrupt.
    const size_t last = t.journal.heights.size() - 1;
    ASSERT_GT(t.journal.tx_counts[last], 1u) << "template record must be multi-tx";
    const size_t rec_start = t.journal.rec_end[last - 1];
    const size_t min_body = 88 + t.journal.tx_counts[last] * kUndoTxSize;
    ASSERT_LT(min_body, t.journal.rec_end[last])
        << "template last record has no tail to tear";
    const size_t cut = rec_start + 88 + rng.below(min_body - 88);
    truncate_file(jpath, cut);

    expect_journal_heals_and_rolls_back(dir, index, last);
    std::filesystem::remove_all(dir);
}

// -- LEVEL 1 trial (f): garbage appended to the journal ----------------------

void trial_journal_garbage_append(const ChainTemplate& t, int index) {
    Rng& rng = trial_rng();
    const std::string dir = fresh_trial_dir(t.dir, index);
    const std::string jpath = dir + "/undo/undo.vxl";
    const size_t good_size = t.journal.size;

    const size_t garbage_len = 1 + rng.below(300);
    std::vector<uint8_t> garbage(garbage_len);
    for (auto& b : garbage) b = static_cast<uint8_t>(rng.next() & 0xFF);
    {
        std::ofstream f(jpath, std::ios::binary | std::ios::app);
        f.write(reinterpret_cast<const char*>(garbage.data()),
                static_cast<std::streamsize>(garbage.size()));
        ASSERT_TRUE(f.good());
    }

    auto store = try_open(dir + "/ledger.vxb", nullptr);
    ASSERT_NE(store, nullptr);
    LedgerState ledger = t.snap.back();
    vx::state::UndoEngine undo(dir, *store, ledger); // reject-or-migrate on load

    if (!std::filesystem::exists(jpath)) {
        // Reject: the tail was malformed beyond healing, the whole file is
        // discarded and rebuilt from live application. The rollback then
        // finds no journal and refuses (no state is ever fabricated).
        EXPECT_FALSE(undo.rollback_to_height(0));
    } else {
        const JournalLayout after = scan_journal(read_file(jpath));
        // Heal or migration: the valid prefix must survive intact, and no
        // fabricated record (a height the chain never had) may exist.
        for (size_t i = 0; i < after.heights.size(); ++i) {
            ASSERT_LE(after.heights[i],
                      static_cast<uint64_t>(kTemplateBlocks))
                << "trial " << index << ": a garbage record entered the journal";
        }
        ASSERT_LE(after.heights.size(), static_cast<size_t>(kTemplateBlocks + 1));
        if (after.heights.size() == t.journal.heights.size() &&
            after.size == good_size) {
            // Full valid prefix kept: a rollback over it must still work.
            ASSERT_TRUE(undo.rollback_to_height(0))
                << "trial " << index << ": " << undo.last_error();
            expect_same_state(ledger, t.snap[1], t.senders,
                              "garbage-append full-prefix rollback");
        }
    }
    std::filesystem::remove_all(dir);
}

// -- LEVEL 1 trials (d)/(e): GQC sidecar -------------------------------------

void trial_gqc_middle_corrupt(const GqcTemplate& t, int index) {
    Rng& rng = trial_rng();
    const std::string dir = fresh_trial_dir(t.dir, index);
    const std::string gpath = dir + "/ledger.vxb.gqc";

    // A middle record (not the tail): flip a byte of its magic tag. The
    // reader must fail closed -- no trusted height, no per-height aggregate.
    const size_t recs = t.stamped_heights.size();
    const size_t rec = 1 + rng.below(recs - 2); // strictly middle: 1..recs-2
    const size_t off = rec * 52 + rng.below(8);
    const uint8_t mask = static_cast<uint8_t>(1 + rng.below(255));
    flip_byte(gpath, off, mask);

    auto store = try_open(dir + "/ledger.vxb", nullptr);
    ASSERT_NE(store, nullptr);

    bool clean = true;
    const uint64_t highest = store->highest_gqc_stamp(clean);
    EXPECT_FALSE(clean) << "trial " << index << ": corrupt sidecar read clean";
    EXPECT_LE(highest, rec) << "trial " << index
                            << ": a height beyond the intact prefix leaked";
    for (const uint64_t h : t.stamped_heights) {
        uint8_t out[32];
        EXPECT_FALSE(store->gqc_stamp(h, out))
            << "trial " << index << ": corrupt sidecar served height " << h;
    }

    // The consumer of the persisted checkpoint must see the sidecar as
    // untrusted: nothing restored, nothing fabricated.
    vx::state::LedgerState ledger;
    vx::state::UndoEngine undo(dir, *store, ledger);
    EXPECT_FALSE(undo.finalized_sidecar_trusted())
        << "trial " << index << ": corrupt sidecar restored a trusted guard";
    EXPECT_EQ(undo.finalized_checkpoint_height(), 0u);
    std::filesystem::remove_all(dir);
}

void trial_gqc_tail_heal(const GqcTemplate& t, int index) {
    Rng& rng = trial_rng();
    const std::string dir = fresh_trial_dir(t.dir, index);
    const std::string gpath = dir + "/ledger.vxb.gqc";
    const size_t side_size = t.stamped_heights.size() * 52;

    const size_t cut = 1 + rng.below(side_size - 1); // [1, side_size)
    truncate_file(gpath, cut);
    const size_t complete = cut / 52;

    auto store = try_open(dir + "/ledger.vxb", nullptr);
    ASSERT_NE(store, nullptr);

    bool clean = false;
    const uint64_t highest = store->highest_gqc_stamp(clean);
    EXPECT_TRUE(clean) << "trial " << index << ": torn sidecar tail not clean";
    EXPECT_EQ(highest, complete) << "trial " << index << ": wrong healed stamp";
    // Healed on disk to the last complete record.
    EXPECT_EQ(std::filesystem::file_size(gpath), complete * 52ULL)
        << "trial " << index << ": sidecar tail not truncated";

    vx::state::LedgerState ledger;
    vx::state::UndoEngine undo(dir, *store, ledger);
    EXPECT_TRUE(undo.finalized_sidecar_trusted()) << "trial " << index;
    EXPECT_EQ(undo.finalized_checkpoint_height(), complete) << "trial " << index;
    std::filesystem::remove_all(dir);
}

// -- LEVEL 1 trial (g): displaced-frames journal torn mid-record -------------

void trial_displaced_torn_record(const ChainTemplate& t, int index) {
    Rng& rng = trial_rng();
    const std::string dir = fresh_trial_dir(t.dir, index);
    const std::string dpath = dir + "/undo/displaced.vxd";
    const size_t rec = 12 + BLOCK_SIZE_BYTES;

    const size_t cut = 1 + rng.below(t.displaced.size - 1);
    truncate_file(dpath, cut);
    const size_t expect_complete =
        (cut <= 12) ? 0 : (cut - 12) / rec; // torn record is never replayed

    auto store = try_open(dir + "/ledger.vxb", nullptr);
    ASSERT_NE(store, nullptr);
    vx::state::LedgerState ledger;
    vx::state::UndoEngine undo(dir, *store, ledger);

    const auto displaced = undo.load_displaced_frames();
    ASSERT_EQ(displaced.size(), expect_complete)
        << "trial " << index << ": torn displaced record replayed (or lost)";
    for (size_t i = 0; i < displaced.size(); ++i) {
        EXPECT_EQ(displaced[i].height, 6 + i) << "trial " << index;
        EXPECT_EQ(0, std::memcmp(displaced[i].frame.data(),
                                 t.frames[6 + i].data(), BLOCK_SIZE_BYTES))
            << "trial " << index << ": displaced frame " << i << " differs";
    }
    std::filesystem::remove_all(dir);
}

// -- LEVEL 2: real SIGKILL mid-append ----------------------------------------

// The child's coinbase receiver: a fixed address no PQ key is needed for
// (coinbase credits need no witness; the child signs nothing).
Address kill_child_recv() {
    return addr_of("NFA_CRASH_KILL_RECEIVER_0000000000000000000000000");
}

// Never returns: the child builds the chain block by block and exits with a
// plain _exit (no gtest, no static destructors, no atexit flush racing the
// parent's kill).
[[noreturn]] void sigkill_child_main(const std::string& dir) {
    try {
        vx::storage::BlockStore store(dir + "/ledger.vxb", "genesis.bin", 8);
        vx::state::LedgerState ledger;
        vx::state::UndoEngine undo(dir, store, ledger);

        const auto* g = store.get_block(0);
        BlockFrame gf;
        std::memcpy(gf.data(), reinterpret_cast<const uint8_t*>(g),
                    BLOCK_SIZE_BYTES);
        undo.apply_block(BlockView(gf));
        if (!ledger.apply_block(BlockView(gf)).ok) ::_exit(4);
        undo.commit_undo_point();

        const uint64_t base_ts = store.get_block(0)->header.timestamp + 1;
        const Address recv = kill_child_recv();
        for (uint64_t h = 1; h <= 20; ++h) {
            uint8_t tip[32];
            store.tip_hash(tip);
            BlockBuilder b = next_block(store, base_ts + h);
            Transaction cb = make_coinbase(recv, h, tip, 50ULL * ATOMS_PER_VX);
            if (!b.add_transaction(cb)) ::_exit(5);
            b.finalize();
            BlockFrame f;
            std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
            if (!seal_pogw_nonce(f, store.required_pogw_bits())) ::_exit(6);
            undo.apply_block(BlockView(f));
            if (!store.append_block(f)) ::_exit(7);
            if (!ledger.apply_block(BlockView(f)).ok) ::_exit(8);
            undo.commit_undo_point();
        }
        ::_exit(0); // full chain written before the kill landed
    } catch (...) {
        ::_exit(3);
    }
    ::_exit(2); // unreachable; never fall off a forked child
}

struct SigKillOutcome {
    size_t full_chains = 0;    // child finished all 20 blocks
    size_t partial_chains = 0; // killed mid-chain, store reopened cleanly
    size_t torn_frames = 0;    // crash inside append_block's ftruncate/pwrite
    uint64_t min_tip = 9999;
    uint64_t max_tip = 0;
};

void sigkill_trial(const ChainTemplate& /*unused*/, int index,
                   SigKillOutcome& outcome) {
    Rng& rng = trial_rng();
    const std::string root = temp_root();
    const std::string dir = root + "/kill_" + std::to_string(index);
    std::filesystem::remove_all(dir);
    std::filesystem::create_directories(dir);
    const std::string path = dir + "/ledger.vxb";

    // Warm the store so the child never races the genesis auto-init.
    {
        vx::storage::BlockStore warm(path, "genesis.bin", 8);
        ASSERT_EQ(warm.chain_height(), 1u);
    }

    const pid_t pid = ::fork();
    ASSERT_GE(pid, 0) << "fork failed";
    if (pid == 0) {
        sigkill_child_main(dir); // never returns
        ::_exit(9);
    }

    // PRNG-seeded kill delays from 1 to 700 ms: the child needs on the
    // order of 200+ ms for the full 20-block chain (per-block PoGW seal +
    // two fsyncs), so the sweep covers early, mid and late chain states as
    // well as completed chains.
    const unsigned delay_ms = 1 + static_cast<unsigned>(rng.below(700));
    ::usleep(delay_ms * 1000);
    ::kill(pid, SIGKILL);
    int st = 0;
    ::waitpid(pid, &st, 0);
    if (WIFEXITED(st)) {
        ASSERT_EQ(WEXITSTATUS(st), 0) << "trial " << index
                                      << ": child failed on its own (exit "
                                      << WEXITSTATUS(st) << ")";
    } else {
        ASSERT_TRUE(WIFSIGNALED(st) && WTERMSIG(st) == SIGKILL)
            << "trial " << index << ": child died of an unexpected signal";
    }

    // -- Reopen and judge -------------------------------------------------
    std::string err;
    auto store = try_open(path, &err);
    if (store == nullptr) {
        // The only crash window append_block cannot make atomic: the SIGKILL
        // landed between the size-extending ftruncate and the pwrite/fsync.
        // The constructor refuses it with a clean error: either the torn
        // size ("corrupted ledger", partial frame tail) or the region
        // validation ("bad magic", zeroed or half-written frame).
        ++outcome.torn_frames;
        EXPECT_TRUE(err.find("corrupted ledger") != std::string::npos ||
                    err.find("bad magic") != std::string::npos)
            << "trial " << index << ": unclean reopen error: " << err;
        const std::vector<uint8_t> raw = read_file(path);
        ASSERT_EQ(raw.size() % BLOCK_SIZE_BYTES, 0u)
            << "trial " << index << ": torn file is not frame-multiple";
        // Exactly one frame may be torn; everything below must be intact.
        size_t valid = 0;
        while (valid < raw.size() / BLOCK_SIZE_BYTES) {
            const auto* rb = reinterpret_cast<const RawBlock*>(
                raw.data() + valid * BLOCK_SIZE_BYTES);
            if (rb->header.magic != BLOCK_MAGIC ||
                rb->header.block_height != valid ||
                !verify_block_merkle(*rb)) {
                break;
            }
            ++valid;
        }
        ASSERT_GE(valid, 1u) << "trial " << index << ": genesis frame lost";
        ASSERT_EQ(valid + 1, raw.size() / BLOCK_SIZE_BYTES)
            << "trial " << index << ": more than one frame torn";
        truncate_file(path, static_cast<uint64_t>(valid) * BLOCK_SIZE_BYTES);
        store = try_open(path, &err);
        ASSERT_NE(store, nullptr) << "trial " << index << ": " << err;
        ASSERT_EQ(store->chain_height(), valid) << "trial " << index;
    }

    const uint64_t tip = store->chain_height();
    ASSERT_GE(tip, 1u) << "trial " << index << ": genesis frame missing";
    ASSERT_LE(tip, 21u) << "trial " << index << ": chain overgrew the child";
    outcome.min_tip = (tip < outcome.min_tip) ? tip : outcome.min_tip;
    outcome.max_tip = (tip > outcome.max_tip) ? tip : outcome.max_tip;
    if (tip == 21) {
        ++outcome.full_chains;
    } else {
        ++outcome.partial_chains;
    }

    // Fresh replay of the surviving prefix: every frame must apply.
    std::vector<BlockFrame> frames;
    std::vector<LedgerState> after; // after[c] = state after c frames
    after.push_back(LedgerState{});
    LedgerState replay;
    for (uint64_t h = 0; h < tip; ++h) {
        const auto* raw = store->get_block(h);
        ASSERT_NE(raw, nullptr) << "trial " << index;
        BlockFrame f;
        std::memcpy(f.data(), reinterpret_cast<const uint8_t*>(raw),
                    BLOCK_SIZE_BYTES);
        frames.push_back(f);
        const auto res = replay.apply_block(BlockView(f));
        ASSERT_TRUE(res.ok) << "trial " << index << ", height " << h << ": "
                            << res.error;
        after.push_back(replay);
    }

    // -- The undo journal must be coherent with the store -----------------
    const std::string jpath = dir + "/undo/undo.vxl";
    if (std::filesystem::exists(jpath)) {
        const JournalLayout j = scan_journal(read_file(jpath));
        ASSERT_FALSE(j.heights.empty());
        for (size_t i = 0; i < j.heights.size(); ++i) {
            ASSERT_EQ(j.heights[i], i)
                << "trial " << index << ": journal has a gap at record " << i;
        }
        // No journal record may reference a height the store lacks: a frame
        // is fsynced before the record for it is committed.
        const uint64_t last_record = j.heights.back();
        ASSERT_LT(last_record, tip)
            << "trial " << index << ": journal is ahead of the store";
        // Cross-check every record's pre-state against the fresh replay.
        const std::vector<uint8_t> jbytes = read_file(jpath);
        for (size_t i = 0; i < j.heights.size(); ++i) {
            const std::vector<uint8_t>& d = jbytes;
            const size_t off = (i == 0) ? kJournalHeader : j.rec_end[i - 1];
            const uint64_t supply_lo = u64_le(d.data() + off + 48);
            const uint64_t supply_hi = u64_le(d.data() + off + 56);
            const uint64_t accounts = u64_le(d.data() + off + 64);
            const LedgerState& expect = after[static_cast<size_t>(i)];
            EXPECT_EQ(U128(supply_lo, supply_hi), expect.total_supply())
                << "trial " << index << ": record " << i
                << " pre-supply does not match the replay";
            EXPECT_EQ(accounts, expect.accounts().size())
                << "trial " << index << ": record " << i
                << " pre-account count does not match the replay";
        }
    }

    // The journal must load without throwing, and a rollback either
    // succeeds exactly (full coverage) or fails closed with the coverage
    // gap -- never a crash, never a mismatch.
    {
        LedgerState for_undo = replay;
        vx::state::UndoEngine undo(dir, *store, for_undo);
        const bool rolled = undo.rollback_to_height(0);
        if (rolled) {
            expect_same_state(for_undo, after[1], {},
                              "sigkill rollback vs fresh replay");
        } else {
            const std::string& e = undo.last_error();
            EXPECT_TRUE(e.empty() || e == "ERR_UNDO_JOURNAL_GAP")
                << "trial " << index << ": unexpected rollback error: " << e;
        }
    }
    std::filesystem::remove_all(dir);
}

} // namespace

// === TESTS ==================================================================

// LEVEL 1 (a): 25 PRNG trials on the .vxb tail (truncations plus
// zeroed-frame crash windows).
TEST(VxCrashTortureTest, Level1StoreTailTruncation) {
    const ChainTemplate& t = plain_template();
    for (int i = 0; i < 25; ++i) {
        trial_store_truncation(t, 100 + i);
    }
    SUCCEED() << "25 store-tail truncation trials done";
}

// LEVEL 1 (b): 15 journal truncation trials (whole-record + mid-record).
TEST(VxCrashTortureTest, Level1UndoJournalTruncation) {
    const ChainTemplate& t = plain_template();
    for (int i = 0; i < 15; ++i) {
        trial_journal_truncation(t, 200 + i);
    }
    SUCCEED() << "15 journal truncation trials done";
}

// LEVEL 1 (c): 10 multi-tx-record torn-tail trials (tx_count probe heals).
TEST(VxCrashTortureTest, Level1MultiTxRecordTailHeals) {
    const ChainTemplate& t = plain_template();
    for (int i = 0; i < 10; ++i) {
        trial_multi_tx_record_truncation(t, 300 + i);
    }
    SUCCEED() << "10 multi-tx torn-tail trials done";
}

// LEVEL 1 (d): 10 corrupt-middle-GQC-record trials (fail closed).
TEST(VxCrashTortureTest, Level1GqcMiddleRecordFailsClosed) {
    const GqcTemplate& t = gqc_template();
    for (int i = 0; i < 10; ++i) {
        trial_gqc_middle_corrupt(t, 400 + i);
    }
    SUCCEED() << "10 GQC middle-corruption trials done";
}

// LEVEL 1 (e): 10 torn-GQC-tail trials (heal to the last complete record).
TEST(VxCrashTortureTest, Level1GqcTailHeals) {
    const GqcTemplate& t = gqc_template();
    for (int i = 0; i < 10; ++i) {
        trial_gqc_tail_heal(t, 500 + i);
    }
    SUCCEED() << "10 GQC tail-heal trials done";
}

// Regression (crash-torture finding 1, fixed 2026-11-04): the v2 record
// carries a CRC32C over height+aggregate, so flipping a HEIGHT byte in a
// middle record must fail closed -- the old v1 reader accepted it clean and
// would have inflated the finality guard.
TEST(VxCrashTortureTest, GqcHeightByteFlipFailsClosed) {
    const GqcTemplate& t = gqc_template();
    Rng& rng = trial_rng();
    const std::string dir = fresh_trial_dir(t.dir, 990);
    const std::string gpath = dir + "/ledger.vxb.gqc";

    const size_t recs = t.stamped_heights.size();
    const size_t rec = 1 + rng.below(recs - 2); // strictly middle
    const size_t off = rec * 52 + 8 + rng.below(8); // height bytes
    const uint8_t mask = static_cast<uint8_t>(1 + rng.below(255));
    flip_byte(gpath, off, mask);

    auto store = try_open(dir + "/ledger.vxb", nullptr);
    ASSERT_NE(store, nullptr);

    bool clean = true;
    store->highest_gqc_stamp(clean);
    EXPECT_FALSE(clean) << "a flipped height byte read clean";
    for (const uint64_t h : t.stamped_heights) {
        uint8_t out[32];
        EXPECT_FALSE(store->gqc_stamp(h, out))
            << "corrupt sidecar served height " << h;
    }
    vx::state::LedgerState ledger;
    vx::state::UndoEngine undo(dir, *store, ledger);
    EXPECT_FALSE(undo.finalized_sidecar_trusted());
    EXPECT_EQ(undo.finalized_checkpoint_height(), 0u);
    std::filesystem::remove_all(dir);
}

// Regression: a legacy v1 sidecar (no checksum) migrates to v2 on first open
// and stays trusted, with every aggregate intact and the file rewritten to
// 52-byte records.
TEST(VxCrashTortureTest, LegacyGqcSidecarMigratesToV2) {
    const GqcTemplate& t = gqc_template();
    const std::string dir = fresh_trial_dir(t.dir, 991);
    const std::string gpath = dir + "/ledger.vxb.gqc";

    // Overwrite the (now v2) sidecar with a hand-written legacy v1 file.
    std::string legacy;
    for (const uint64_t h : t.stamped_heights) {
        uint8_t agg[32];
        const std::string tag = "VX_GQC_TORTURE_AGG_" + std::to_string(h);
        VortexSponge256::compute(reinterpret_cast<const uint8_t*>(tag.data()),
                                 tag.size(), agg);
        legacy.append("VXGQCRT1", 8);
        legacy.append(reinterpret_cast<const char*>(&h), 8);
        legacy.append(reinterpret_cast<const char*>(agg), 32);
    }
    {
        std::ofstream f(gpath, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(f.good());
        f.write(legacy.data(), static_cast<std::streamsize>(legacy.size()));
    }

    auto store = try_open(dir + "/ledger.vxb", nullptr);
    ASSERT_NE(store, nullptr);

    bool clean = false;
    const uint64_t highest = store->highest_gqc_stamp(clean);
    EXPECT_TRUE(clean) << "legacy sidecar migration failed";
    EXPECT_EQ(highest, t.stamped_heights.size());
    for (size_t i = 0; i < t.stamped_heights.size(); ++i) {
        const uint64_t h = t.stamped_heights[i];
        uint8_t out[32];
        uint8_t want[32];
        const std::string tag = "VX_GQC_TORTURE_AGG_" + std::to_string(h);
        VortexSponge256::compute(reinterpret_cast<const uint8_t*>(tag.data()),
                                 tag.size(), want);
        EXPECT_TRUE(store->gqc_stamp(h, out))
            << "height " << h << " not served after migration";
        EXPECT_EQ(std::memcmp(out, want, 32), 0)
            << "aggregate mismatch after migration for height " << h;
    }
    // Migrated on disk to v2 52-byte records.
    EXPECT_EQ(std::filesystem::file_size(gpath), t.stamped_heights.size() * 52ULL)
        << "sidecar not rewritten to v2";
    std::filesystem::remove_all(dir);
}

// Regression (review F3): a sidecar that mixes v1 and v2 records can never
// be legitimately written — the realistic accident is a v2 record appended
// (at the 48-aligned tip) onto a not-yet-migrated v1 file. The engine must
// refuse it loudly, fail closed, and leave the file untouched.
TEST(VxCrashTortureTest, GqcMixedSidecarFailsClosed) {
    const GqcTemplate& t = gqc_template();
    const std::string dir = fresh_trial_dir(t.dir, 992);
    const std::string gpath = dir + "/ledger.vxb.gqc";
    // v1 file, then one 52-byte v2 record appended at the 48-aligned tip —
    // exactly what a second writer would produce before migration ran.
    {
        std::ofstream f(gpath, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(f.good());
        std::string legacy;
        for (const uint64_t h : t.stamped_heights) {
            legacy.append("VXGQCRT1", 8);
            legacy.append(reinterpret_cast<const char*>(&h), 8);
            legacy.append(32, '\x22');
        }
        std::string rec;
        rec.append("VXGQCRT2", 8);
        const uint64_t h = 1;
        rec.append(reinterpret_cast<const char*>(&h), 8);
        rec.append(32, '\x33');
        rec.append(4, '\x00'); // CRC placeholder
        f.write((legacy + rec).data(), static_cast<std::streamsize>(legacy.size() + rec.size()));
    }

    auto store = try_open(dir + "/ledger.vxb", nullptr);
    ASSERT_NE(store, nullptr);

    bool clean = true;
    store->highest_gqc_stamp(clean);
    EXPECT_FALSE(clean) << "mixed RT1/RT2 sidecar read clean";
    vx::state::LedgerState ledger;
    vx::state::UndoEngine undo(dir, *store, ledger);
    EXPECT_FALSE(undo.finalized_sidecar_trusted());
    EXPECT_EQ(undo.finalized_checkpoint_height(), 0u);
    // Untouched on disk: the v1 records plus the offending v2 record.
    EXPECT_EQ(std::filesystem::file_size(gpath), t.stamped_heights.size() * 48ULL + 52ULL);
    std::filesystem::remove_all(dir);
}

// Regression (review F1): migration may trust only what a legitimate v1
// writer could have produced. A garbage tag mid-file must fail the whole
// migration closed — no rewrite, no CRC blessing of corrupt content.
TEST(VxCrashTortureTest, GqcMigrationRejectsGarbageTags) {
    const GqcTemplate& t = gqc_template();
    const std::string dir = fresh_trial_dir(t.dir, 993);
    const std::string gpath = dir + "/ledger.vxb.gqc";

    std::string legacy;
    for (const uint64_t h : t.stamped_heights) {
        uint8_t agg[32];
        const std::string tag = "VX_GQC_TORTURE_AGG_" + std::to_string(h);
        VortexSponge256::compute(reinterpret_cast<const uint8_t*>(tag.data()),
                                 tag.size(), agg);
        legacy.append("VXGQCRT1", 8);
        legacy.append(reinterpret_cast<const char*>(&h), 8);
        legacy.append(reinterpret_cast<const char*>(agg), 32);
    }
    // Corrupt the tag of the middle record (same length, unknown version).
    const size_t mid = (t.stamped_heights.size() / 2) * 48;
    std::memcpy(legacy.data() + mid, "VXGQCRT9", 8);
    {
        std::ofstream f(gpath, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(f.good());
        f.write(legacy.data(), static_cast<std::streamsize>(legacy.size()));
    }

    auto store = try_open(dir + "/ledger.vxb", nullptr);
    ASSERT_NE(store, nullptr);

    bool clean = true;
    store->highest_gqc_stamp(clean);
    EXPECT_FALSE(clean) << "v1 file with a garbage-tagged block migrated clean";
    // File untouched: still the original 48-byte-stride content.
    EXPECT_EQ(std::filesystem::file_size(gpath), t.stamped_heights.size() * 48ULL)
        << "migration rewrote a file it should have refused";
    vx::state::LedgerState ledger;
    vx::state::UndoEngine undo(dir, *store, ledger);
    EXPECT_FALSE(undo.finalized_sidecar_trusted());
    EXPECT_EQ(undo.finalized_checkpoint_height(), 0u);
    std::filesystem::remove_all(dir);
}

// Regression (review F1): a v1 record claiming a height the chain never had
// cannot be a legitimate legacy record — stamp_gqc has always enforced
// height < chain_height. Migration must refuse instead of inflating the
// finality guard.
TEST(VxCrashTortureTest, GqcMigrationRejectsInflatedHeight) {
    const GqcTemplate& t = gqc_template();
    const std::string dir = fresh_trial_dir(t.dir, 994);
    const std::string gpath = dir + "/ledger.vxb.gqc";

    std::string legacy;
    for (const uint64_t h : t.stamped_heights) {
        uint8_t agg[32];
        const std::string tag = "VX_GQC_TORTURE_AGG_" + std::to_string(h);
        VortexSponge256::compute(reinterpret_cast<const uint8_t*>(tag.data()),
                                 tag.size(), agg);
        legacy.append("VXGQCRT1", 8);
        legacy.append(reinterpret_cast<const char*>(&h), 8);
        legacy.append(reinterpret_cast<const char*>(agg), 32);
    }
    // Inflate the height of the first record far beyond any real height.
    const uint64_t bogus = 0x00000000FFFFFFFEull;
    std::memcpy(legacy.data() + 8, &bogus, 8);
    {
        std::ofstream f(gpath, std::ios::binary | std::ios::trunc);
        ASSERT_TRUE(f.good());
        f.write(legacy.data(), static_cast<std::streamsize>(legacy.size()));
    }

    auto store = try_open(dir + "/ledger.vxb", nullptr);
    ASSERT_NE(store, nullptr);

    bool clean = true;
    const uint64_t highest = store->highest_gqc_stamp(clean);
    EXPECT_FALSE(clean) << "inflated-height v1 record migrated clean";
    EXPECT_EQ(highest, 0u) << "inflated height leaked into the guard";
    EXPECT_EQ(std::filesystem::file_size(gpath), t.stamped_heights.size() * 48ULL)
        << "migration rewrote a file it should have refused";
    vx::state::LedgerState ledger;
    vx::state::UndoEngine undo(dir, *store, ledger);
    EXPECT_FALSE(undo.finalized_sidecar_trusted());
    EXPECT_EQ(undo.finalized_checkpoint_height(), 0u);
    std::filesystem::remove_all(dir);
}

// LEVEL 1 (f): 15 garbage-append trials (reject-or-migrate).
TEST(VxCrashTortureTest, Level1JournalGarbageAppend) {
    const ChainTemplate& t = plain_template();
    for (int i = 0; i < 15; ++i) {
        trial_journal_garbage_append(t, 600 + i);
    }
    SUCCEED() << "15 garbage-append trials done";
}

// LEVEL 1 (g): 15 displaced-journal torn-record trials.
TEST(VxCrashTortureTest, Level1DisplacedJournalTornRecord) {
    const ChainTemplate& t = plain_template();
    for (int i = 0; i < 15; ++i) {
        trial_displaced_torn_record(t, 700 + i);
    }
    SUCCEED() << "15 displaced-journal trials done";
}

// LEVEL 2: 30 real-SIGKILL trials. Fork+kill is unsafe under sanitizers;
// the ASan lane skips this test (LEVEL 1 still runs there).
#ifndef __SANITIZE_ADDRESS__
TEST(VxCrashTortureTest, Level2SigKillMidChain) {
    const ChainTemplate& t = plain_template();
    SigKillOutcome outcome;
    for (int i = 0; i < 30; ++i) {
        sigkill_trial(t, 800 + i, outcome);
    }
    std::cout << "[crash-torture] SIGKILL outcomes: full=" << outcome.full_chains
              << " partial=" << outcome.partial_chains
              << " torn-frame=" << outcome.torn_frames
              << " tips-span=" << outcome.min_tip << ".." << outcome.max_tip
              << " (30 trials, PRNG-seeded delays 1-700 ms)\n";
    // Every outcome class is legitimate; nothing else is. The per-trial
    // assertions already proved each observed chain was valid or healed.
    EXPECT_EQ(outcome.full_chains + outcome.partial_chains + outcome.torn_frames,
              30u);
}
#endif
