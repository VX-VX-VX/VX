// VortexReorgCarouselTest - deterministic state-level reorg carousel.
//
// Two independent node views A and B (each its own temp dir, its own
// BlockStore + LedgerState + UndoEngine) share one chain prefix, then trade
// the lead in a fixed-seed PRNG carousel: the current leader abandons a
// short tail, builds a longer fork of k fresh blocks from the branch height,
// and the other node must heal - rollback to the fork height (journal
// BEFORE the store append, the resync ordering), truncate its store file
// (resize to (height+1)*65536 + reopen, as ReorgUndoRestoresNoncesAndFrames
// does), then re-apply the winner's frames (journal + append + apply in the
// same resync order). After EVERY heal both nodes must agree byte-for-byte:
// canonical state digests (accounts sorted by address BYTES + balances +
// nonces + supplies + height, hashed through the consensus sponge), the
// full frame lists, and the emission supply identity.
//
// Torture axes on top of the carousel:
//   (a) consecutive reversals: the previous leader immediately reclaims -
//       the lead alternates every cycle, so the SAME seed senders' nonces
//       rise and fall across consecutive heals on the same addresses;
//   (b) displaced-frame integrity after every rollback: load_displaced_
//       frames() must return exactly the abandoned frames, byte-exact;
//   (c) the undo journal survives every reorg: no rollback ever fails with
//       ERR_UNDO_JOURNAL_GAP (the journal is never pruned below the live
//       span, across 26+ rollbacks including fork spans of 90-100 blocks);
//   (d) GQC interplay: certifications happen ONLY at common-prefix heights
//       (32 blocks under the converged tip, always strictly above any later
//       fork point). The cement is absolute - a rollback below it is refused
//       with ERR_FINALIZED_BY_GQC on both nodes (also after a restart) -
//       while everything above it keeps reorganizing;
//   (e) nonce and supply sanity at every checkpoint: every tracked sender's
//       next nonce equals the count of its user transactions on the winning
//       chain, and total_supply == base + (issued - base_issued) -
//       (burned - base_burned), the relation the ledger commit loop defines
//       (issued mints, fee redistribution, floor(fees/2) TDI burn).
//
// A restart epilogue commits both undo journals, reopens fresh UndoEngines
// over the same stores (the finalized checkpoint must come back from the
// GQC sidecar, fail-closed), rolls both nodes back six blocks and
// re-applies the tail: the chain heals a second time from cold state.
//
// Deterministic: one fixed-seed PRNG drives every fork length, branch
// depth, transfer amount and account tag. No wall-clock data enters any
// assertion (timestamps are a monotonic counter starting past the genesis
// time). STATE-LEVEL only: no live VX60 networking, no mempool or RPC
// wiring - those seams are owned by parallel work.

#include <gtest/gtest.h>
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/blockchain/emission.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/consensus/gqc_finality.hpp"
#include "vx/core/u128.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/storage/block_store.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/state/undo_engine.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <cstring>
#include <iterator>
#include <filesystem>
#include <memory>
#include <random>
#include <string>
#include <unordered_map>
#include <vector>
#include <unistd.h>

using namespace vx::blockchain;
using vx::core::U128;
using vx::state::AddressHash;

namespace {

// -- Deterministic constants -------------------------------------------------

// Genesis unix time (the seeded frame in genesis.cpp) - the carousel's
// timestamp counter starts strictly above it and only ever grows.
constexpr uint64_t kGenesisTs = 1761000000ULL;
// Dev-mode PoGW work: 8 leading zero bits, the same difficulty the
// documented-gaps lane seals with (16 is the production default and would
// dominate the runtime).
constexpr uint64_t kPogwBits = 8;
// Shared prefix: genesis + 100 blocks (mint, fundings, floor coinbases).
constexpr uint64_t kPrefixBlocks = 100;
// Seed PQA accounts funded by the demo spender in the prefix; these are the
// fork senders, so consecutive reversal cycles spend from the same
// addresses and their nonces rise and fall across heals.
constexpr size_t kSeedAccounts = 12;
// Each seed is funded once with 40 VX (4e9 atoms); the whole carousel spends
// ~1.5k transfers of 1.12M..3.12M atoms from these 12 senders, so every
// sender stays far from its balance with deterministic headroom.
constexpr uint64_t kSeedFundingAtoms = 4'000'000'000ULL;
// The guaranteed emission floor: the exact reward any valid block may mint.
constexpr uint64_t kCoinbaseFloorAtoms = BLOCK_REWARD_BASE_VX * ATOMS_PER_VX;

std::string temp_dir(const char* tag) {
    auto dir = std::filesystem::temp_directory_path() /
               (std::string(tag) + "_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    return dir.string();
}

Address addr_of(const std::string& s) {
    Address a{};
    std::memcpy(a.data(), s.data(), s.size() < 42 ? s.size() : 42);
    return a;
}

// A unique zero-padded 42-byte address from a prefix + serial. Width is
// derived from the prefix length, so every serial always fits.
std::string zero_padded(uint64_t v, size_t width) {
    std::string s = std::to_string(v);
    if (s.size() < width) s.insert(0, width - s.size(), '0');
    return s;
}

Address tagged_addr(const char* prefix, uint64_t serial) {
    std::string s(prefix);
    s += zero_padded(serial, 42 - s.size());
    Address a{};
    std::memcpy(a.data(), s.data(), 42);
    return a;
}

// -- Accounts (the documented-gaps PQ idioms) --------------------------------

struct PqAccount {
    std::array<uint8_t, 32> sk{};
    std::array<uint8_t, 32> root{};
    Address addr{};
};

PqAccount make_pq_account(const std::string& tag) {
    PqAccount acc;
    VortexSponge256::compute(reinterpret_cast<const uint8_t*>(tag.data()),
                             tag.size(), acc.sk.data());
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

// A MINER_ coinbase bound to its exact chain position (receiver + height +
// previous tip hash): the only legal emission claim shape, at index 0.
Transaction make_coinbase(const Address& recv, uint64_t amount_atoms,
                          uint64_t height, const uint8_t prev_tip[32]) {
    Transaction cb{};
    std::memcpy(cb.sender_nfa, "MINER_", 6);
    for (size_t i = 6; i < 42; ++i) cb.sender_nfa[i] = '0';
    std::memcpy(cb.receiver_nfa, recv.data(), 42);
    tx_set_amount(cb, amount_atoms);
    tx_set_fee(cb, 0);
    tx_set_nonce(cb, 0);
    set_coinbase_binding(cb, height, prev_tip);
    return cb;
}

// -- Node view ---------------------------------------------------------------

struct ReorgNode {
    std::string dir;
    uint64_t bits = kPogwBits;
    std::unique_ptr<vx::storage::BlockStore> store;
    vx::state::LedgerState ledger;
    std::unique_ptr<vx::state::UndoEngine> undo;
    // chain[h] mirrors the frame the store holds at height h (chain[0] is
    // the auto-seeded genesis). The mirror is only written after the store
    // gate accepted the frame, so it tracks the file exactly.
    std::vector<BlockFrame> chain;

    void open_store() {
        store = std::make_unique<vx::storage::BlockStore>(dir + "/chain.vxb",
                                                          "genesis.bin", bits);
        if (undo) undo->attach_store(*store);
    }

    // Reorg store truncation: close the mmap'd file, resize it to exactly
    // (height+1) frames, reopen. The undo engine survives the reopen via
    // attach_store (its journal and in-memory records are file-backed and
    // independent of the store object).
    void truncate_store_to(uint64_t height) {
        const std::string path = dir + "/chain.vxb";
        store.reset();
        std::filesystem::resize_file(path, (height + 1) * BLOCK_SIZE_BYTES);
        open_store();
        ASSERT_EQ(store->chain_height(), height + 1u)
            << "store truncation left the wrong chain height";
    }

    void drop_displaced_file() {
        std::error_code ec;
        std::filesystem::remove(dir + "/undo/displaced.vxd", ec);
    }
};

// Resync-order application of one frame: journal the pre-state BEFORE the
// store append, then append through the intake gate, then apply to the
// ledger. This is the ordering the live reorg path runs.
void apply_frame(ReorgNode& n, const BlockFrame& f, const char* what) {
    BlockView view(f);
    n.undo->apply_block(view); // journal BEFORE the store append
    const uint64_t h = view.header().block_height;
    ASSERT_TRUE(n.store->append_block(f))
        << what << ": store refused frame at height " << h << ": "
        << n.store->last_error();
    const auto res = n.ledger.apply_block(view);
    ASSERT_TRUE(res.ok) << what << ": ledger refused height " << h << ": "
                        << res.error;
    n.chain.push_back(f);
}

// -- Canonical convergence digest --------------------------------------------
// Accounts sorted by address BYTES; per account: address (42 B) + balance
// (16 B LE) + next nonce (4 B LE); then issued supply, burned supply and
// the expected next height. Hashed with the consensus sponge, so two node
// views converge iff their digests match.

std::array<uint8_t, 32> canonical_digest(const vx::state::LedgerState& led) {
    std::vector<const std::pair<const Address, U128>*> accs;
    accs.reserve(led.accounts().size());
    for (const auto& kv : led.accounts()) accs.push_back(&kv);
    std::sort(accs.begin(), accs.end(),
              [](const auto* x, const auto* y) {
                  return std::memcmp(x->first.data(), y->first.data(), 42) < 0;
              });

    std::vector<uint8_t> buf;
    buf.reserve(accs.size() * 62 + 40);
    auto put = [&buf](const uint8_t* p, size_t n) {
        buf.insert(buf.end(), p, p + n);
    };
    auto put_u64 = [&buf](uint64_t v) {
        for (int i = 0; i < 8; ++i)
            buf.push_back(static_cast<uint8_t>(v >> (8 * i)));
    };
    auto put_u32 = [&buf](uint32_t v) {
        for (int i = 0; i < 4; ++i)
            buf.push_back(static_cast<uint8_t>(v >> (8 * i)));
    };
    for (const auto* kv : accs) {
        put(kv->first.data(), 42);
        uint8_t bal[16];
        kv->second.to_le_bytes(bal);
        put(bal, 16);
        put_u32(led.get_next_nonce(kv->first));
    }
    uint8_t issued[16], burned[16];
    led.issued_supply().to_le_bytes(issued);
    led.total_burned().to_le_bytes(burned);
    put(issued, 16);
    put(burned, 16);
    put_u64(led.next_expected_height());

    std::array<uint8_t, 32> digest{};
    VortexSponge256::compute(buf.data(), buf.size(), digest.data());
    return digest;
}

// Count of user (non-coinbase) transactions per sender on a chain - the
// exact quantity every sender's nonce counter must equal after a heal.
std::unordered_map<Address, uint32_t, AddressHash> spent_counts(
    const std::vector<BlockFrame>& chain) {
    std::unordered_map<Address, uint32_t, AddressHash> counts;
    for (size_t h = 1; h < chain.size(); ++h) {
        BlockView view(chain[h]);
        const uint32_t n = view.header().tx_count;
        for (uint32_t i = 0; i < n; ++i) {
            const Address sender = tx_address(view.tx(i).sender_nfa);
            const char* s = reinterpret_cast<const char*>(sender.data());
            if (std::strncmp(s, "GENESIS", 7) == 0) continue;
            if (std::strncmp(s, "MINER_", 6) == 0) continue;
            ++counts[sender];
        }
    }
    return counts;
}

// -- Carousel harness --------------------------------------------------------

// A fork sender with its one-time-leaf budget. The PQ engine signs with an
// H=4 XMSS tree: exactly 16 one-time leaves per key, and a nonce >= 16
// would derive a leaf from a subtree the published root does not span
// (pq_sign_transaction refuses it). So the fork's sender pool is a rolling
// one: every transfer spends one leaf AND mints the next sender account,
// and no key ever signs more than 16 transactions.
struct PoolSender {
    PqAccount acc;
    uint32_t signs_left = 16; // leaves 0..15 of the key's first XMSS tree
};

struct Carousel {
    ReorgNode a;
    ReorgNode b;
    PqAccount demo;              // the pinned GENESIS_2 mint receiver
    std::vector<PoolSender> pool; // rolling fork-sender pool
    std::vector<Address> accounts; // every address nonce-tracking watches

    std::mt19937_64 rng{0xC0C0DEED5EEDC0C0ULL}; // fixed carousel seed
    uint64_t ts = kGenesisTs + 1000;            // monotonic block clock
    uint64_t serial = 0;                        // unique tag/serial source
    uint64_t send_cursor = 0;                   // round-robin pool cursor
    uint64_t certified_height = 0;              // GQC cement
    uint64_t rollbacks = 0;                     // successful reorg rollbacks

    U128 base_total{};
    U128 base_issued{};
    U128 base_burned{};

    uint64_t next_ts() { return ++ts; }
    uint64_t next_serial() { return ++serial; }
};

void init_node(ReorgNode& n, const std::string& dir) {
    n.dir = dir;
    std::filesystem::create_directories(dir);
    n.open_store();
    const auto* g = n.store->get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t*>(g),
                BLOCK_SIZE_BYTES);
    ASSERT_TRUE(n.ledger.apply_block(BlockView(gf)).ok)
        << "genesis frame refused on a fresh ledger";
    n.chain.push_back(gf);
    n.undo = std::make_unique<vx::state::UndoEngine>(dir, *n.store, n.ledger);
}

// Build + seal one frame on top of a node's current tip: coinbase bound to
// the chain position at index 0 plus the caller's transactions.
void build_mined_block(Carousel& c, ReorgNode& n, const Address& cb_recv,
                       const std::vector<Transaction>& extra, BlockFrame& out) {
    const uint64_t h = n.store->chain_height();
    uint8_t tip[32];
    n.store->tip_hash(tip);
    std::vector<Transaction> txs;
    txs.reserve(extra.size() + 1);
    txs.push_back(make_coinbase(cb_recv, kCoinbaseFloorAtoms, h, tip));
    for (const auto& t : extra) txs.push_back(t);

    BlockBuilder b;
    b.set_height(h);
    b.set_timestamp(c.next_ts());
    b.set_prev_hash(tip);
    std::array<uint8_t, 384> coords{};
    b.set_attractor_coords(coords.data());
    for (const auto& t : txs) {
        if (!b.add_transaction(t)) ADD_FAILURE() << "block builder full";
    }
    b.finalize();
    out.fill(0);
    std::memcpy(out.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    if (!seal_pogw_nonce(out, kPogwBits))
        ADD_FAILURE() << "PoGW seal failed at height " << h;
}

// One fresh fork block: floor coinbase + 2..3 PQ-signed transfers, each
// funding a brand-new PQA account with a PRNG amount >= 1.12M atoms.
// The sender comes from the rolling pool (leaf budget + funds, sequential
// nonces read off the leader's live ledger after its rollback); the
// receiver joins the pool, so the address pool is exactly the same across
// consecutive reversal cycles.
void build_fork_block(Carousel& c, ReorgNode& n, BlockFrame& out) {
    constexpr uint64_t kMinAmount = 1'120'000;
    constexpr uint64_t kFee = 100;
    std::vector<Transaction> extra;
    const uint32_t m = 2 + static_cast<uint32_t>(c.rng() % 2);
    for (uint32_t t = 0; t < m; ++t) {
        // Pick the next sender with leaf budget and funds. A spent-down
        // account (balance under the minimum) simply drops out of the
        // rotation - its dust stays locked, by design of the amounts.
        PoolSender* chosen = nullptr;
        const size_t pool_n = c.pool.size();
        ASSERT_GT(pool_n, 0u) << "fork sender pool exhausted";
        for (size_t probe = 0; probe < pool_n && !chosen; ++probe) {
            PoolSender& cand = c.pool[(c.send_cursor + probe) % pool_n];
            if (cand.signs_left == 0) continue;
            if (n.ledger.balance_of(cand.acc.addr) < U128(kMinAmount + kFee))
                continue;
            chosen = &cand;
            c.send_cursor = (c.send_cursor + probe + 1) % pool_n;
        }
        if (!chosen) {
            ADD_FAILURE() << "no funded fork sender with leaf budget";
            return;
        }
        uint64_t amount = kMinAmount + (c.rng() % 2'000'000);
        const U128 bal = n.ledger.balance_of(chosen->acc.addr);
        if (U128(amount) + U128(kFee) > bal) amount = (bal - U128(kFee)).lo;
        ASSERT_GE(amount, kMinAmount)
            << "sender selection let a below-minimum amount through";
        const PqAccount recv =
            make_pq_account("VX_CAROUSEL_ACCT_" + std::to_string(c.next_serial()));
        c.accounts.push_back(recv.addr);
        Transaction tx = make_tx(chosen->acc.addr, recv.addr, amount,
                                 n.ledger.get_next_nonce(chosen->acc.addr));
        ASSERT_TRUE(pq_sign(tx, chosen->acc)) << "fork sender signing failed";
        --chosen->signs_left;
        c.pool.push_back({recv, 16});
        extra.push_back(tx);
    }
    build_mined_block(c, n, tagged_addr("NFA_CAR_CB_", c.next_serial()),
                      extra, out);
}

// -- Checkpoints -------------------------------------------------------------

// The emission supply identity the ledger commit loop defines: per block,
// senders pay amount+fee, receivers gain amount, the producer mints its
// claim, floor(fees/2) is burned and the fee share is re-credited inside
// the claim. Summed over any prefix of a chain:
//   total_supply == base_total + (issued - base_issued) - (burned - base_burned)
void expect_supply_identity(const Carousel& c, const ReorgNode& n,
                            const char* what) {
    const U128 issued = n.ledger.issued_supply();
    const U128 burned = n.ledger.total_burned();
    ASSERT_TRUE(issued >= c.base_issued && burned >= c.base_burned)
        << what << ": supply counters regressed";
    const U128 minted = issued - c.base_issued;
    const U128 torched = burned - c.base_burned;
    ASSERT_TRUE(minted >= torched)
        << what << ": burned exceeded issued";
    const U128 expect = c.base_total + (minted - torched);
    ASSERT_TRUE(n.ledger.total_supply() == expect)
        << what << ": supply identity violated";
}

// Nonce sanity: every tracked account's next nonce must equal the count of
// its user transactions on the winning chain. Receivers never send, so
// their counters must read exactly 0.
void expect_nonce_sanity(const Carousel& c, const ReorgNode& n,
                         const std::unordered_map<Address, uint32_t, AddressHash>&
                             counts,
                         const char* what) {
    for (const Address& a : c.accounts) {
        const auto it = counts.find(a);
        const uint32_t expect = it == counts.end() ? 0u : it->second;
        ASSERT_EQ(n.ledger.get_next_nonce(a), expect)
            << what << ": nonce drift for account serial-index "
            << (&a - c.accounts.data());
    }
}

// Full convergence: identical frame lists, identical tips, identical
// digests, supply identity on both nodes, nonce sanity on both nodes.
void expect_convergence(Carousel& c, const char* what) {
    ASSERT_EQ(c.a.chain.size(), c.b.chain.size())
        << what << ": chain lengths diverged";
    for (size_t h = 0; h < c.a.chain.size(); ++h) {
        ASSERT_EQ(0, std::memcmp(c.a.chain[h].data(), c.b.chain[h].data(),
                                 BLOCK_SIZE_BYTES))
            << what << ": frame " << h << " differs between the nodes";
    }
    ASSERT_EQ(c.a.store->chain_height(), c.b.store->chain_height())
        << what << ": store heights diverged";
    ASSERT_EQ(c.a.ledger.next_expected_height(),
              c.b.ledger.next_expected_height())
        << what << ": ledger heights diverged";

    const auto dig_a = canonical_digest(c.a.ledger);
    const auto dig_b = canonical_digest(c.b.ledger);
    ASSERT_EQ(0, std::memcmp(dig_a.data(), dig_b.data(), 32))
        << what << ": canonical state digests diverged";

    expect_supply_identity(c, c.a, what);
    expect_supply_identity(c, c.b, what);
    const auto counts = spent_counts(c.a.chain);
    expect_nonce_sanity(c, c.a, counts, what);
    expect_nonce_sanity(c, c.b, counts, what);
}

// Displaced-frame integrity (torture axis b): the side journal must hold
// exactly the frames the rollback abandoned, in height order, byte-exact.
void expect_displaced_exact(const ReorgNode& n,
                            const std::vector<BlockFrame>& displaced,
                            uint64_t from_height, const char* what) {
    const auto got = n.undo->load_displaced_frames();
    ASSERT_EQ(got.size(), displaced.size())
        << what << ": displaced-frame count mismatch";
    for (size_t i = 0; i < displaced.size() && i < got.size(); ++i) {
        ASSERT_EQ(got[i].height, from_height + i)
            << what << ": displaced record " << i << " at the wrong height";
        ASSERT_EQ(0, std::memcmp(got[i].frame.data(), displaced[i].data(),
                                 BLOCK_SIZE_BYTES))
            << what << ": displaced frame " << i << " is not byte-exact";
    }
}

// -- GQC certification at a common-prefix height -----------------------------

void certify_common_prefix(Carousel& c, const char* what) {
    const uint64_t H = c.a.chain.size() - 1;
    ASSERT_GE(H, 32u);
    const uint64_t target = H - 32;
    // The certified height only moves up, and always stays 32 blocks under
    // a converged tip - a common-prefix height by construction, never a
    // block inside a live fork.
    ASSERT_GT(target, c.certified_height) << what << ": cement regressed";
    const auto block_hash = [&c](uint64_t h) {
        std::array<uint8_t, 32> bh{};
        RawBlock raw;
        std::memcpy(&raw, c.a.chain[h].data(), BLOCK_SIZE_BYTES);
        hash_block(raw, bh.data());
        return bh;
    };

    for (ReorgNode* n : {&c.a, &c.b}) {
        ASSERT_EQ(n->chain.size(), c.a.chain.size())
            << what << ": certification on a diverged node";
        const std::array<uint8_t, 32> bh = block_hash(target);
        vx::consensus::GqcFinality gqc(*n->undo, *n->store);
        for (uint16_t v = 0; v < 9; ++v) {
            gqc.collect_share(target, bh, v,
                              vx::consensus::GqcFinality::derive_validator_share(
                                  bh, target, v));
        }
        const auto cert = gqc.finalize_block(target, bh, 9);
        ASSERT_TRUE(cert.certified) << what << ": " << cert.error;
        ASSERT_GE(n->undo->finalized_checkpoint_height(), target)
            << what << ": the cement did not move up";
        // The aggregate is persisted as a sidecar record and must read back.
        uint8_t stamp[32];
        ASSERT_TRUE(n->store->gqc_stamp(target, stamp))
            << what << ": GQC sidecar record missing";
        ASSERT_EQ(0, std::memcmp(stamp, cert.gqc_signature_agg.data(), 32))
            << what << ": persisted aggregate mismatch";
        // Absolute deep-reorg protection: a rollback below the cement is
        // refused on both nodes, everything above it stays reorganizable.
        ASSERT_FALSE(n->undo->rollback_to_height(target - 1))
            << what << ": a finalized height was rolled back!";
        ASSERT_EQ(n->undo->last_error(), "ERR_FINALIZED_BY_GQC");
    }
    c.certified_height = target;
}

// -- Shared prefix -----------------------------------------------------------

void build_shared_prefix(Carousel& c) {
    // Node A builds the canonical prefix; node B replays the very same
    // frames (journal + append + apply, resync order), so the two stores'
    // bytes are identical by construction.
    // Height 1: the pinned GENESIS_2 mint (100,000 VX to the demo spender).
    {
        BlockBuilder b;
        b.set_height(c.a.store->chain_height());
        b.set_timestamp(c.next_ts());
        uint8_t tip[32];
        c.a.store->tip_hash(tip);
        b.set_prev_hash(tip);
        std::array<uint8_t, 384> coords{};
        b.set_attractor_coords(coords.data());
        Transaction mint = make_tx(addr_of("GENESIS_2"), c.demo.addr,
                                   GENESIS_2_MINT_ATOMICS, 0);
        sign_transaction(mint);
        ASSERT_TRUE(b.add_transaction(mint));
        b.finalize();
        BlockFrame f;
        std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
        ASSERT_TRUE(seal_pogw_nonce(f, kPogwBits));
        apply_frame(c.a, f, "prefix mint");
    }
    // Heights 2..13: MINER_ floor coinbase + one PQ-signed funding transfer
    // per block, seeding the rolling fork-sender pool from the demo spender.
    for (size_t i = 0; i < kSeedAccounts; ++i) {
        const PqAccount seed =
            make_pq_account("VX_CAROUSEL_SEED_" + std::to_string(c.next_serial()));
        c.accounts.push_back(seed.addr);
        Transaction funding =
            make_tx(c.demo.addr, seed.addr, kSeedFundingAtoms,
                    c.a.ledger.get_next_nonce(c.demo.addr));
        ASSERT_TRUE(pq_sign(funding, c.demo));
        c.pool.push_back({seed, 16});
        BlockFrame f;
        build_mined_block(c, c.a, tagged_addr("NFA_CAR_MINER_H", c.next_serial()),
                          {funding}, f);
        apply_frame(c.a, f, "prefix funding");
    }
    // Heights 14..100: pure floor coinbase blocks (miner churn on the
    // shared prefix, no state beyond the emission credit).
    while (c.a.chain.size() - 1 < kPrefixBlocks) {
        BlockFrame f;
        build_mined_block(c, c.a, tagged_addr("NFA_CAR_MINER_H", c.next_serial()),
                          {}, f);
        apply_frame(c.a, f, "prefix coinbase");
    }
    // Node B adopts the prefix frame by frame.
    for (size_t h = 1; h < c.a.chain.size(); ++h) {
        apply_frame(c.b, c.a.chain[h], "prefix replay");
    }
    ASSERT_EQ(c.a.chain.size(), c.b.chain.size());
    expect_convergence(c, "shared prefix");
}

// -- One carousel cycle ------------------------------------------------------
// The leader abandons its top d blocks, builds k fresh blocks from the
// branch height, and the loser heals onto the winner's fork: rollback ->
// store truncate -> re-apply the winner's frames in resync order. Both
// nodes roll back (they both held the abandoned tail), so both displace
// exactly the same d frames into their side journals.

void run_cycle(Carousel& c, uint64_t k, bool a_leads, const char* what) {
    ReorgNode& leader = a_leads ? c.a : c.b;
    ReorgNode& loser = a_leads ? c.b : c.a;

    const uint64_t H = c.a.chain.size() - 1;
    const uint64_t d = 8 + (c.rng() % 5); // branch depth 8..12
    const uint64_t F = H - d;             // fork point = branch height
    ASSERT_GT(F, c.certified_height)
        << what << ": fork point must stay strictly above the GQC cement";
    ASSERT_LE(d, k) << what << ": the fork must grow past the abandoned tail";

    // Both nodes hold the same tail above F; capture it once for the
    // displaced-frame integrity check.
    const std::vector<BlockFrame> displaced(c.a.chain.begin() + (F + 1),
                                            c.a.chain.end());
    ASSERT_EQ(displaced.size(), d);
    ASSERT_EQ(0, std::memcmp(loser.chain[F + 1].data(), displaced[0].data(),
                             BLOCK_SIZE_BYTES))
        << what << ": the nodes were not converged before the cycle";

    // The undo journal must cover the whole abandoned span: the rollback
    // refuses with ERR_UNDO_JOURNAL_GAP otherwise (torture axis c). Every
    // rollback below must therefore succeed.
    ASSERT_TRUE(c.a.undo->rollback_to_height(F))
        << what << ": A rollback failed: " << c.a.undo->last_error();
    ++c.rollbacks;
    ASSERT_TRUE(c.b.undo->rollback_to_height(F))
        << what << ": B rollback failed: " << c.b.undo->last_error();
    ++c.rollbacks;

    c.a.chain.resize(F + 1);
    c.b.chain.resize(F + 1);
    c.a.truncate_store_to(F);
    c.b.truncate_store_to(F);

    // The leader builds k fresh blocks (journal + append + apply, resync
    // order) on top of the branch height.
    std::vector<BlockFrame> fork;
    fork.reserve(k);
    for (uint64_t i = 0; i < k; ++i) {
        BlockFrame f;
        build_fork_block(c, leader, f);
        apply_frame(leader, f, what);
        fork.push_back(f);
    }
    // The loser heals onto the winner's frames.
    for (const auto& f : fork) apply_frame(loser, f, what);

    // Byte-level convergence after the heal.
    expect_convergence(c, what);

    // Displaced-frame integrity after the cycle (axis b): exactly the
    // abandoned frames, byte-exact, on both nodes.
    expect_displaced_exact(c.a, displaced, F + 1, what);
    expect_displaced_exact(c.b, displaced, F + 1, what);
    // Keep the side journals small: the next cycle verifies its own
    // displacement from a fresh file.
    c.a.drop_displaced_file();
    c.b.drop_displaced_file();
}

// -- The test ----------------------------------------------------------------

} // namespace

TEST(VortexReorgCarouselTest, StateCarouselConverges) {
    Carousel c;
    c.demo = make_pq_account("VX_DEMO_SPENDER_SK_V1");
    c.demo.addr = vx::blockchain::genesis2_mint_receiver_payload();
    c.accounts.push_back(c.demo.addr);

    const std::string dir_a = temp_dir("vx_carousel_a");
    const std::string dir_b = temp_dir("vx_carousel_b");
    init_node(c.a, dir_a);
    init_node(c.b, dir_b);

    // Base counters for the emission supply identity (post-genesis state).
    c.base_total = c.a.ledger.total_supply();
    c.base_issued = c.a.ledger.issued_supply();
    c.base_burned = c.a.ledger.total_burned();

    build_shared_prefix(c);

    // Cement the first common-prefix checkpoint (68, i.e. 32 under the
    // 100-block tip): every later fork point branches strictly above it.
    certify_common_prefix(c, "prefix cement");

    // The carousel: fork lengths grow 20 -> 100, the lead alternates every
    // cycle - so the previous leader is the next loser and every cycle is
    // an immediate reversal on the same address pool.
    const uint64_t fork_lengths[] = {20, 30, 40, 50, 60, 70, 80, 90, 100};
    for (size_t i = 0; i < std::size(fork_lengths); ++i) {
        const bool a_leads = (i % 2 == 0);
        const std::string what =
            "cycle " + std::to_string(i) + " (fork " +
            std::to_string(fork_lengths[i]) + ", " + (a_leads ? "A" : "B") +
            " leads)";
        run_cycle(c, fork_lengths[i], a_leads, what.c_str());
        // Certify at common-prefix heights only, every other cycle, so the
        // cement trails the tip while fork points keep branching above it.
        if (i % 2 == 0) certify_common_prefix(c, what.c_str());
    }

    // Reversal torture (axis a): four short consecutive reclaim cycles -
    // B reclaims from A, A reclaims back, and so on, with the same seed
    // senders spending on every pass.
    for (size_t r = 0; r < 4; ++r) {
        const size_t i = std::size(fork_lengths) + r;
        const bool a_leads = (i % 2 == 0);
        const std::string what = "reversal " + std::to_string(r) + " (" +
                                 (a_leads ? "A" : "B") + " reclaims)";
        run_cycle(c, 20, a_leads, what.c_str());
    }

    ASSERT_GT(c.rollbacks, 10u)
        << "the carousel must run at least 10 consecutive large reorgs";

    // -- Restart epilogue: cold-state heal -------------------------------
    const uint64_t H = c.a.chain.size() - 1;
    const uint64_t target = H - 6;
    const std::vector<BlockFrame> tail(c.a.chain.begin() + (target + 1),
                                       c.a.chain.end());
    ASSERT_EQ(tail.size(), 6u);

    // Commit both journals (the destructor appends everything still
    // pending), then reopen fresh undo engines over the SAME stores: the
    // finalized checkpoint must come back from the GQC sidecar (fail-closed
    // restore), and a cold rollback must still work - and must still refuse
    // below the cement.
    c.a.undo.reset();
    c.b.undo.reset();
    for (ReorgNode* n : {&c.a, &c.b}) {
        auto undo2 = std::make_unique<vx::state::UndoEngine>(n->dir, *n->store,
                                                             n->ledger);
        ASSERT_TRUE(undo2->finalized_sidecar_trusted())
            << "the persisted GQC sidecar did not parse cleanly";
        ASSERT_GE(undo2->finalized_checkpoint_height(), c.certified_height)
            << "the checkpoint evaporated across the restart";
        ASSERT_FALSE(undo2->rollback_to_height(c.certified_height - 1))
            << "a cold rollback unwound a finalized height!";
        ASSERT_EQ(undo2->last_error(), "ERR_FINALIZED_BY_GQC");
        ASSERT_TRUE(undo2->rollback_to_height(target))
            << "cold rollback failed: " << undo2->last_error();
        ++c.rollbacks;
        n->undo = std::move(undo2);
        n->chain.resize(target + 1);
        n->truncate_store_to(target);
    }
    // Both nodes rolled back to the same height: still converged.
    expect_convergence(c, "restart rollback");

    // Displaced tail integrity on the cold path too.
    expect_displaced_exact(c.a, tail, target + 1, "restart rollback");
    expect_displaced_exact(c.b, tail, target + 1, "restart rollback");

    // Re-apply the tail: the chain heals a second time from cold state.
    for (const auto& f : tail) {
        apply_frame(c.a, f, "restart heal");
        apply_frame(c.b, f, "restart heal");
    }
    expect_convergence(c, "restart heal");

    EXPECT_GT(c.rollbacks, 12u);

    std::filesystem::remove_all(dir_a);
    std::filesystem::remove_all(dir_b);
}
