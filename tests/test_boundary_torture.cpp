// VortexBoundaryTortureTest -- boundary-value torture on the money math
// (STAGE H; test-only file, NO production code changes).
//
// Every case asserts either the PRECISE rejection error of
// LedgerState::apply_block / Mempool::submit / BlockStore::append_block, or
// acceptance with the EXACT expected post-state derived from the code (not
// from the stage brief). Where the code's actual rule differs from the
// brief's assumption, the deviation is pinned with a [FINDING] comment:
//
//   [FINDING] 1. The TDI dust gate is an ADMISSION filter, not consensus:
//      it lives only in Mempool::submit (vx/math/tdi_filter.hpp + the
//      hardcoded 112-byte size in src/state/mempool.cpp). The ledger
//      accepts ANY positive amount, including 1 atom. The dust boundary is
//      exactly 1,120,000 atoms (0.0112 VX): density = (amount/1e8)/112*10000
//      >= MIN_THRESHOLD (1.0)  <=>  amount >= 112 * 1e8 / 10000.
//   [FINDING] 2. fee=0/nonce=0 (genesis-v1 shape) at height 2+ is NOT
//      rejected per se: the legacy exemption is scoped away, so the NORMAL
//      nonce check runs -- and a fresh sender's correct expected nonce IS 0.
//      The refusal fires only once the sender's counter has moved
//      ("nonce mismatch (expected 1, got 0)").
//   [FINDING] 3. A MINER_ claim of 0 is neither rejected nor recomputed to
//      the floor: a zero-amount coinbase is legal (the zero-transfer gate
//      explicitly exempts MINER_), pays 0, and still TRACKS the receiver
//      as a zero-balance account.
//   [FINDING] 4. The live ledger NEVER untracks a zero-balance address in
//      apply_block (balances_[a] = ... keeps the entry at 0). Untracking
//      happens only in the reorg undo forget-loop (forget_empty_address).
//   [FINDING] 5. A U128 credit-sum overflow is unreachable by construction
//      (MAX_TX_PER_BLOCK=580 x UINT64_MAX ~= 2^73.6 << 2^128); the reachable
//      overflow is the u64-bounded per-sender intra-block DEBIT accumulator,
//      which the checked add refuses pre-commit ("debit accumulator
//      overflow") with zero mutation.
//   [FINDING] 6. One PQ key signs at most 16 transactions EVER: the WOTS+
//      leaf is the tx nonce's low 4 bits and pq_sign_transaction refuses
//      nonce >= 16 (XMSS subtree rollover unimplemented). "580 txs from one
//      sender" is unproducible; the 580-tx maximum is exercised with 37
//      keys instead. The ledger itself has no such limit.
//   [FINDING] 7. The public invariant helper total_supply() SATURATES at
//      2^64-1 (its treat-as-anomaly sentinel) once balances cross 2^64 in
//      sum; per-address math stays exact.
//
// Idioms follow tests/test_documented_gaps.cpp (make_pq_account, pq_sign,
// seal_pogw_nonce, push_block, hostile-frame byte patches at 0x1D4).

#include <gtest/gtest.h>

#include "vx/blockchain/block.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/blockchain/emission.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/core/u128.hpp"
#include "vx/math/tdi_filter.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/state/mempool.hpp"
#include "vx/state/undo_engine.hpp"
#include "vx/storage/block_store.hpp"

#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <string>
#include <vector>

using namespace vx::blockchain;
using vx::core::U128;

namespace {

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

Address payload_of(const std::string& nfa) { // strips the "NFA_V6_" prefix
    Address a{};
    std::memcpy(a.data(), nfa.data() + 7, 42);
    return a;
}

// A post-quantum account (self-certifying "PQA..." address).
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

// Unsigned transaction shell; callers sign (pq_sign for user senders,
// sign_transaction for system senders).
Transaction mk_tx(const Address& sender, const Address& receiver,
                  uint64_t amount, uint32_t fee, uint32_t nonce) {
    Transaction tx{};
    std::memcpy(tx.sender_nfa, sender.data(), 42);
    std::memcpy(tx.receiver_nfa, receiver.data(), 42);
    tx_set_amount(tx, amount);
    tx_set_fee(tx, fee);
    tx_set_nonce(tx, nonce);
    return tx;
}

// The protocol-shaped GENESIS_2 mint (keyless structural digest).
Transaction mint_tx(const Address& to, uint64_t amount) {
    Transaction tx{};
    std::memcpy(tx.sender_nfa, "GENESIS_2", 9);
    for (size_t i = 9; i < 42; ++i) tx.sender_nfa[i] = '0';
    std::memcpy(tx.receiver_nfa, to.data(), 42);
    tx_set_amount(tx, amount);
    tx_set_fee(tx, 0);
    tx_set_nonce(tx, 0);
    sign_transaction(tx);
    return tx;
}

// A chain-position-bound MINER_ coinbase.
Transaction coinbase_tx(const Address& recv, uint64_t amount, uint64_t height,
                        const uint8_t prev_tip[32]) {
    Transaction cb{};
    std::memcpy(cb.sender_nfa, "MINER_", 6);
    for (size_t i = 6; i < 42; ++i) cb.sender_nfa[i] = '0';
    std::memcpy(cb.receiver_nfa, recv.data(), 42);
    tx_set_amount(cb, amount);
    tx_set_fee(cb, 0);
    tx_set_nonce(cb, 0);
    set_coinbase_binding(cb, height, prev_tip);
    return cb;
}

// The demo spender: bound to the PUBLIC demo key, funded by the pinned
// GENESIS_2 mint (see test_documented_gaps.cpp).
PqAccount demo_spender() {
    PqAccount acc = make_pq_account("VX_DEMO_SPENDER_SK_V1");
    acc.addr = genesis2_mint_receiver_payload();
    return acc;
}

// Append + ledger-apply, returning the ledger's verdict.
vx::state::ApplyResult push_block(vx::storage::BlockStore& store,
                                  vx::state::LedgerState& ledger,
                                  BlockBuilder& b) {
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    if (!seal_pogw_nonce(f, store.required_pogw_bits())) {
        vx::state::ApplyResult r;
        r.error = "seal failed";
        return r;
    }
    if (!store.append_block(f)) {
        vx::state::ApplyResult r;
        r.error = "store: " + store.last_error();
        return r;
    }
    return ledger.apply_block(BlockView(f));
}

// A builder configured for the next store height (tip-bound, like
// test_documented_gaps.cpp next_block).
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

// Ledger-direct apply of a user block (no store; the consensus authority
// under test is apply_block alone -- no PoGW gate on this path).
vx::state::ApplyResult apply_user_block(vx::state::LedgerState& ledger,
                                        const std::vector<Transaction>& txs) {
    uint8_t prev[32] = {};
    BlockBuilder b;
    b.set_height(ledger.next_expected_height());
    b.set_timestamp(1'761'000'000ull);
    b.set_prev_hash(prev);
    std::array<uint8_t, 384> coords{};
    b.set_attractor_coords(coords.data());
    for (const auto& tx : txs) b.add_transaction(tx);
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    return ledger.apply_block(BlockView(f));
}

// Ledger-direct apply of a single MINER_ coinbase claim (mirrors the
// documented-gaps helper: fixed 0x11 prev tip; variable pogw nonce steers
// the frame hash the reward is computed from).
vx::state::ApplyResult apply_miner_claim(vx::state::LedgerState& ledger,
                                         uint64_t amount_atoms,
                                         const Address& recv,
                                         uint64_t pogw_nonce = 0) {
    Transaction cb{};
    std::memcpy(cb.sender_nfa, "MINER_", 6);
    for (size_t i = 6; i < 42; ++i) cb.sender_nfa[i] = '0';
    std::memcpy(cb.receiver_nfa, recv.data(), 42);
    tx_set_amount(cb, amount_atoms);
    tx_set_fee(cb, 0);
    tx_set_nonce(cb, 0);
    const uint64_t h = ledger.next_expected_height();
    uint8_t prev[32];
    std::memset(prev, 0x11, sizeof(prev));
    set_coinbase_binding(cb, h, prev);
    BlockBuilder b;
    b.set_height(h);
    b.set_timestamp(1'761'000'000ull);
    b.set_nonce(pogw_nonce);
    b.set_prev_hash(prev);
    std::array<uint8_t, 384> coords{};
    b.set_attractor_coords(coords.data());
    b.add_transaction(cb);
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    return ledger.apply_block(BlockView(f));
}

void apply_genesis(vx::storage::BlockStore& store, vx::state::LedgerState& ledger) {
    const auto* g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t*>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);
}

// Height-1 pinned mint to the demo spender; returns the ledger verdict.
vx::state::ApplyResult push_mint(vx::storage::BlockStore& store,
                                 vx::state::LedgerState& ledger, uint64_t ts) {
    BlockBuilder b = next_block(store, ts);
    b.add_transaction(mint_tx(demo_spender().addr, GENESIS_2_MINT_ATOMICS));
    return push_block(store, ledger, b);
}

constexpr uint64_t MINT = GENESIS_2_MINT_ATOMICS; // 10,000,000,000,000 atoms

} // namespace

// -- 1. BALANCE EDGES --------------------------------------------------------

// Spend the EXACT balance minus fee: accepted, sender left at exactly 0.
// The actual tracking rule: the live ledger NEVER untracks (apply_block has
// no erase path; only the reorg forget-loop does), so a drained address
// stays tracked at zero. A later spend from a drained address must fail
// with the precise "insufficient funds" refusal and zero mutation.
TEST(VxBoundaryTortureTest, BalanceExactDrain) {
    const std::string dir = temp_dir("vx_bt_drain");
    vx::storage::BlockStore store(dir + "/bt.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;
    apply_genesis(store, ledger);
    const PqAccount spender = demo_spender();
    const PqAccount r2 = make_pq_account("VX_BT_DRAIN_R2_SK_V1");
    const Address sink = addr_of("NFA_BT_DRAIN_SINK_000000000000000000000");
    const uint64_t ts = std::time(nullptr);

    // Height 1: the pinned mint funds the demo spender (10,000 VX).
    ASSERT_TRUE(push_mint(store, ledger, ts).ok);

    // Height 2: fund a freshly created account with 10 VX.
    {
        BlockBuilder b = next_block(store, ts + 1);
        Transaction t = mk_tx(spender.addr, r2.addr, 1'000'000'000ull, 100, 0);
        ASSERT_TRUE(pq_sign(t, spender));
        b.add_transaction(t);
        const auto res = push_block(store, ledger, b);
        ASSERT_TRUE(res.ok) << res.error;
    }
    EXPECT_EQ(ledger.balance_of(spender.addr), U128(9'998'999'999'900ULL));
    EXPECT_EQ(ledger.balance_of(r2.addr), U128(1'000'000'000ull));

    // Height 3: r2 spends the EXACT balance minus fee (999,999,900 + 100
    // == 1,000,000,000): accepted, r2 left at exactly 0.
    {
        BlockBuilder b = next_block(store, ts + 2);
        Transaction t = mk_tx(r2.addr, sink, 999'999'900ull, 100, 0);
        ASSERT_TRUE(pq_sign(t, r2));
        b.add_transaction(t);
        const auto res = push_block(store, ledger, b);
        ASSERT_TRUE(res.ok) << res.error;
    }
    EXPECT_EQ(ledger.balance_of(r2.addr), U128(0));
    // [FINDING 4] zero-balance addresses stay tracked in the live ledger.
    EXPECT_TRUE(ledger.tracked_addresses_containing(r2.addr));
    EXPECT_EQ(ledger.balance_of(sink), U128(999'999'900ull));
    EXPECT_EQ(ledger.get_next_nonce(r2.addr), 1u);

    // Height 4 (ledger-only): a later spend from the drained address --
    // even 1 atom with a zero fee -- is refused before any mutation.
    {
        Transaction t = mk_tx(r2.addr, sink, 1, 0, 1);
        ASSERT_TRUE(pq_sign(t, r2));
        const auto res = apply_user_block(ledger, {t});
        EXPECT_FALSE(res.ok);
        EXPECT_NE(res.error.find("tx 0: insufficient funds"), std::string::npos)
            << res.error;
        EXPECT_EQ(ledger.balance_of(r2.addr), U128(0));
        EXPECT_EQ(ledger.balance_of(sink), U128(999'999'900ull));
    }

    // Height 4: the demo spender drains itself to the last atom.
    {
        BlockBuilder b = next_block(store, ts + 3);
        Transaction t =
            mk_tx(spender.addr, sink, 9'998'999'999'800ULL, 100, 1);
        ASSERT_TRUE(pq_sign(t, spender));
        b.add_transaction(t);
        const auto res = push_block(store, ledger, b);
        ASSERT_TRUE(res.ok) << res.error;
    }
    EXPECT_EQ(ledger.balance_of(spender.addr), U128(0));
    EXPECT_TRUE(ledger.tracked_addresses_containing(spender.addr))
        << "the drained demo spender stays tracked (no live untrack path)";
    EXPECT_EQ(ledger.balance_of(sink),
              U128(999'999'900ull + 9'998'999'999'800ULL));

    // A later 1-atom spend from the drained spender is refused too.
    {
        Transaction t = mk_tx(spender.addr, sink, 1, 0, 2);
        ASSERT_TRUE(pq_sign(t, spender));
        const auto res = apply_user_block(ledger, {t});
        EXPECT_FALSE(res.ok);
        EXPECT_NE(res.error.find("tx 0: insufficient funds"), std::string::npos)
            << res.error;
        EXPECT_EQ(ledger.balance_of(spender.addr), U128(0));
        EXPECT_EQ(ledger.balance_of(sink),
                  U128(999'999'900ull + 9'998'999'999'800ULL))
            << "a refused block must not mutate";
    }

    std::filesystem::remove_all(dir);
}

// Forgot-the-fee and balance+fee+1: both are the precise "insufficient
// funds" refusal; the block mutates nothing (height, balances unchanged).
TEST(VxBoundaryTortureTest, BalanceOffByFeeEdges) {
    const std::string dir = temp_dir("vx_bt_offfee");
    vx::storage::BlockStore store(dir + "/bt.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;
    apply_genesis(store, ledger);
    const PqAccount spender = demo_spender();
    const Address sink = addr_of("NFA_BT_OFFFEE_SINK_0000000000000000000");
    const uint64_t ts = std::time(nullptr);
    ASSERT_TRUE(push_mint(store, ledger, ts).ok);

    // amount == balance (fee forgotten): total cost is 1 atom over.
    {
        BlockBuilder b = next_block(store, ts + 1);
        Transaction t = mk_tx(spender.addr, sink, MINT, 100, 0);
        ASSERT_TRUE(pq_sign(t, spender));
        b.add_transaction(t);
        b.finalize();
        BlockFrame f;
        std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
        ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
        const auto res = ledger.apply_block(BlockView(f));
        EXPECT_FALSE(res.ok);
        EXPECT_NE(res.error.find("tx 0: insufficient funds"), std::string::npos)
            << res.error;
    }
    // amount == balance - fee + 1: total cost is exactly 1 atom over.
    {
        BlockBuilder b = next_block(store, ts + 1);
        Transaction t = mk_tx(spender.addr, sink, MINT - 99, 100, 0);
        ASSERT_TRUE(pq_sign(t, spender));
        b.add_transaction(t);
        b.finalize();
        BlockFrame f;
        std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
        ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
        const auto res = ledger.apply_block(BlockView(f));
        EXPECT_FALSE(res.ok);
        EXPECT_NE(res.error.find("tx 0: insufficient funds"), std::string::npos)
            << res.error;
    }
    // Both refusals left the ledger byte-identical.
    EXPECT_EQ(ledger.balance_of(spender.addr), U128(MINT));
    EXPECT_EQ(ledger.next_expected_height(), 2u);
    EXPECT_FALSE(ledger.tracked_addresses_containing(sink));

    std::filesystem::remove_all(dir);
}

// Intra-block double-spend on the last atoms: the first tx drains the
// balance exactly, the second (individually fundable-looking only against
// pending credits) must be refused by the intra-debit accounting; the whole
// block is rejected with "insufficient funds" and NOTHING is applied.
TEST(VxBoundaryTortureTest, DoubleSpendOnLastAtoms) {
    const std::string dir = temp_dir("vx_bt_dslast");
    vx::storage::BlockStore store(dir + "/bt.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;
    apply_genesis(store, ledger);
    const PqAccount spender = demo_spender();
    const Address sink = addr_of("NFA_BT_DSLAST_SINK_0000000000000000000");
    const uint64_t ts = std::time(nullptr);
    ASSERT_TRUE(push_mint(store, ledger, ts).ok);

    BlockBuilder b = next_block(store, ts + 1);
    Transaction s1 = mk_tx(spender.addr, sink, MINT - 100, 100, 0);
    Transaction s2 = mk_tx(spender.addr, sink, 1'120'000ull, 100, 1);
    ASSERT_TRUE(pq_sign(s1, spender));
    ASSERT_TRUE(pq_sign(s2, spender));
    b.add_transaction(s1);
    b.add_transaction(s2);
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));

    const auto res = ledger.apply_block(BlockView(f));
    EXPECT_FALSE(res.ok);
    EXPECT_NE(res.error.find("tx 1: insufficient funds"), std::string::npos)
        << res.error;
    EXPECT_EQ(res.error.find("underflow"), std::string::npos)
        << "the underflow guard must never fire; the pre-check refuses first";
    // No partial state: sender keeps everything, the sink was never created.
    EXPECT_EQ(ledger.balance_of(spender.addr), U128(MINT));
    EXPECT_FALSE(ledger.tracked_addresses_containing(sink));
    EXPECT_EQ(ledger.next_expected_height(), 2u);

    std::filesystem::remove_all(dir);
}

// -- 2. AMOUNT EDGES ---------------------------------------------------------

// amount = 1 atom. [FINDING 1] The TDI dust gate is a mempool admission
// filter only: the LEDGER accepts a 1-atom transfer (any positive amount),
// while mempool submit refuses it with the exact TDI text. A zero amount is
// refused on both layers ("zero transfer" / TDI "Non-positive...").
TEST(VxBoundaryTortureTest, AmountOneAtomLedgerVsMempoolTdi) {
    const std::string dir = temp_dir("vx_bt_atom");
    vx::storage::BlockStore store(dir + "/bt.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;
    apply_genesis(store, ledger);
    const PqAccount spender = demo_spender();
    const Address r1 = addr_of("NFA_BT_ATOM_R1_000000000000000000000000");
    const uint64_t ts = std::time(nullptr);
    ASSERT_TRUE(push_mint(store, ledger, ts).ok);

    // Ledger: 1 atom moves (no dust gate on the consensus path).
    {
        BlockBuilder b = next_block(store, ts + 1);
        Transaction t = mk_tx(spender.addr, r1, 1, 100, 0);
        ASSERT_TRUE(pq_sign(t, spender));
        b.add_transaction(t);
        const auto res = push_block(store, ledger, b);
        EXPECT_TRUE(res.ok) << res.error;
        EXPECT_EQ(ledger.balance_of(r1), U128(1));
        EXPECT_EQ(ledger.balance_of(spender.addr), U128(MINT - 101));
        EXPECT_EQ(res.fees_burned, U128(50)); // floor(100/2)
    }
    // Ledger: zero amount is refused ("zero transfer"), after PQ
    // authorization succeeds.
    {
        Transaction t = mk_tx(spender.addr, r1, 0, 100, 1);
        ASSERT_TRUE(pq_sign(t, spender));
        const auto res = apply_user_block(ledger, {t});
        EXPECT_FALSE(res.ok);
        EXPECT_NE(res.error.find("tx 0: zero transfer"), std::string::npos)
            << res.error;
    }
    // Mempool: 1 atom is TDI-annihilated before balance/nonce checks.
    {
        vx::state::Mempool pool;
        Transaction t = mk_tx(addr_of("BT_MEMPOOL_A_00000000000000000000000"),
                              addr_of("BT_MEMPOOL_R_000000000000000000000000"),
                              1, 100, 0);
        sign_transaction(t); // admission pre-filter verifies the proof only
        const auto res = pool.submit(t, U128(MINT), 0);
        EXPECT_FALSE(res.ok);
        EXPECT_NE(res.error.find("TDI violation"), std::string::npos) << res.error;
        EXPECT_NE(res.error.find("dust attack"), std::string::npos) << res.error;
        // Mempool: zero amount is a TDI violation too (non-positive amount).
        Transaction z = mk_tx(addr_of("BT_MEMPOOL_B_00000000000000000000000"),
                              addr_of("BT_MEMPOOL_R_000000000000000000000000"),
                              0, 100, 0);
        sign_transaction(z);
        const auto resz = pool.submit(z, U128(MINT), 0);
        EXPECT_FALSE(resz.ok);
        EXPECT_NE(resz.error.find("Non-positive transaction transfer amount"),
                  std::string::npos) << resz.error;
    }

    std::filesystem::remove_all(dir);
}

// The exact dust boundary. TdiFilter::evaluate(112, amountVx) with
// MIN_THRESHOLD = 1.0: density = (amount/1e8/112)*10000 >= 1.0  <=>
// amount >= 1,120,000 atoms. Exactly 1,120,000 yields density == 1.0
// (double math, verified) -> accepted; 1,119,999 is annihilated.
TEST(VxBoundaryTortureTest, TdiDustBoundaryExactlyOnePointOneTwoMillion) {
    // Direct filter probes.
    {
        const auto ok = vx::math::TdiFilter::evaluate(112, 1'120'000.0 / 1e8);
        EXPECT_FALSE(ok.isAnnihilated) << ok.reason;
        EXPECT_DOUBLE_EQ(ok.tdi, 1.0);
        EXPECT_EQ(ok.reason, "Valid");
        const auto dust = vx::math::TdiFilter::evaluate(112, 1'119'999.0 / 1e8);
        EXPECT_TRUE(dust.isAnnihilated);
        EXPECT_LT(dust.tdi, 1.0);
        EXPECT_EQ(dust.reason,
                  "Transaction density falls below critical economic"
                  " threshold (dust attack)");
    }
    // Mempool admission at the boundary.
    {
        vx::state::Mempool pool;
        const Address s1 = addr_of("BT_TDI_S1_000000000000000000000000000");
        const Address s2 = addr_of("BT_TDI_S2_000000000000000000000000000");
        const Address r = addr_of("BT_TDI_R_00000000000000000000000000000");
        Transaction at_boundary = mk_tx(s1, r, 1'120'000, 100, 0);
        sign_transaction(at_boundary);
        const auto res_ok = pool.submit(at_boundary, U128(1'000'000'000), 0);
        EXPECT_TRUE(res_ok.ok) << res_ok.error;
        Transaction below_boundary = mk_tx(s2, r, 1'119'999, 100, 0);
        sign_transaction(below_boundary);
        const auto res_dust = pool.submit(below_boundary, U128(1'000'000'000), 0);
        EXPECT_FALSE(res_dust.ok);
        EXPECT_NE(res_dust.error.find("TDI violation"), std::string::npos)
            << res_dust.error;
    }
    // The ledger still moves both amounts (consensus has no dust rule).
    {
        vx::state::LedgerState ledger;
        ledger.set_next_height(2); // outside the genesis replay window
        const PqAccount spender = demo_spender();
        const Address r = addr_of("NFA_BT_TDI_LEDGER_0000000000000000000");
        ledger.adjust_balance(spender.addr, U128(10'000'000'000ull), true);
        {
            Transaction t = mk_tx(spender.addr, r, 1'119'999, 0, 0);
            ASSERT_TRUE(pq_sign(t, spender));
            const auto res = apply_user_block(ledger, {t});
            EXPECT_TRUE(res.ok) << "sub-dust amount is legal on the consensus"
                                   " path (TDI is mempool-only): " << res.error;
        }
        {
            Transaction t = mk_tx(spender.addr, r, 1, 0, 1);
            ASSERT_TRUE(pq_sign(t, spender));
            const auto res = apply_user_block(ledger, {t});
            EXPECT_TRUE(res.ok) << res.error;
        }
        EXPECT_EQ(ledger.balance_of(r), U128(1'120'000));
        EXPECT_EQ(ledger.balance_of(spender.addr), U128(9'998'880'000ull));
    }
}

// amount = UINT64_MAX. With any realistic balance the pre-check refuses
// ("insufficient funds" -- the balance gate runs before the debit
// accumulator). With a staged 2^64 balance the ledger handles the full
// u64 amount exactly: sender left at 1 atom, receiver credited 2^64-1,
// no wrap anywhere (transfers do not touch the issuance cap).
TEST(VxBoundaryTortureTest, AmountUint64Max) {
    const PqAccount spender = demo_spender();
    const Address sink = addr_of("NFA_BT_U64MAX_SINK_0000000000000000000");

    // (a) Realistic balance: refused before any arithmetic can wrap.
    {
        vx::state::LedgerState ledger;
        ledger.set_next_height(2);
        ledger.adjust_balance(spender.addr, U128(MINT), true);
        auto probe = [&](uint32_t fee) {
            Transaction t = mk_tx(spender.addr, sink, UINT64_MAX, fee, 0);
            EXPECT_TRUE(pq_sign(t, spender));
            const auto res = apply_user_block(ledger, {t});
            EXPECT_FALSE(res.ok);
            EXPECT_NE(res.error.find("tx 0: insufficient funds"), std::string::npos)
                << res.error;
        };
        probe(100);
        probe(0);
        EXPECT_EQ(ledger.balance_of(spender.addr), U128(MINT));
        EXPECT_FALSE(ledger.tracked_addresses_containing(sink));
    }
    // (b) Staged 2^64 balance: UINT64_MAX with fee 0 applies exactly.
    {
        vx::state::LedgerState ledger;
        ledger.set_next_height(2);
        ledger.adjust_balance(spender.addr, U128(0, 1), true); // exactly 2^64
        Transaction t = mk_tx(spender.addr, sink, UINT64_MAX, 0, 0);
        ASSERT_TRUE(pq_sign(t, spender));
        const auto res = apply_user_block(ledger, {t});
        EXPECT_TRUE(res.ok) << res.error;
        EXPECT_EQ(ledger.balance_of(spender.addr), U128(1));
        EXPECT_EQ(ledger.balance_of(sink), U128(0xFFFFFFFFFFFFFFFFULL));
        // The public invariant helper SATURATES at 2^64-1 (its documented
        // treat-as-anomaly sentinel): 1 + (2^64-1) crosses the u64-bounded
        // checked accumulation. Per-address balances above are exact; the
        // consensus math never relies on this helper.
        EXPECT_EQ(ledger.total_supply(), U128(0xFFFFFFFFFFFFFFFFULL));
        EXPECT_EQ(ledger.issued_supply(), U128(0))
            << "a transfer must not touch the issuance counter";
        EXPECT_EQ(ledger.get_next_nonce(spender.addr), 1u);
    }
    // (c) Staged 2^64 with a 100-atom fee: total cost 2^64+99 overflows the
    // balance -- refused at the balance gate (before the accumulator).
    {
        vx::state::LedgerState ledger;
        ledger.set_next_height(2);
        ledger.adjust_balance(spender.addr, U128(0, 1), true);
        Transaction t = mk_tx(spender.addr, sink, UINT64_MAX, 100, 0);
        ASSERT_TRUE(pq_sign(t, spender));
        const auto res = apply_user_block(ledger, {t});
        EXPECT_FALSE(res.ok);
        EXPECT_NE(res.error.find("tx 0: insufficient funds"), std::string::npos)
            << res.error;
        EXPECT_EQ(ledger.balance_of(spender.addr), U128(0, 1));
        EXPECT_FALSE(ledger.tracked_addresses_containing(sink));
    }
}

// [FINDING 5] Two max-ish credits in one block: the U128 CREDIT sum cannot
// overflow (580 x UINT64_MAX ~= 2^73.6 << 2^128), but the per-sender
// intra-block DEBIT accumulator is u64-bounded and its checked add must
// refuse pre-commit. (a) two full-u64 debits overflow the accumulator at
// tx 1; (b) one full-u64 debit plus a fee overflows at tx 0. Both leave
// the ledger byte-identical (staged balances via the test-only reorg
// adjust_balance helper).
TEST(VxBoundaryTortureTest, DebitAccumulatorOverflowGuard) {
    const PqAccount spender = demo_spender();
    const Address sink = addr_of("NFA_BT_ACC_SINK_0000000000000000000000");

    // (a) two max-ish credits from one sender in one block.
    {
        vx::state::LedgerState ledger;
        ledger.set_next_height(2);
        ledger.adjust_balance(spender.addr, U128(0, 2), true); // 2^65
        Transaction t0 = mk_tx(spender.addr, sink, UINT64_MAX, 0, 0);
        Transaction t1 = mk_tx(spender.addr, sink, UINT64_MAX, 0, 0);
        ASSERT_TRUE(pq_sign(t0, spender));
        ASSERT_TRUE(pq_sign(t1, spender));
        const auto res = apply_user_block(ledger, {t0, t1});
        EXPECT_FALSE(res.ok);
        EXPECT_NE(res.error.find("tx 1: debit accumulator overflow"),
                  std::string::npos) << res.error;
        EXPECT_EQ(ledger.balance_of(spender.addr), U128(0, 2))
            << "refused pre-commit: no mutation";
        EXPECT_FALSE(ledger.tracked_addresses_containing(sink));
        EXPECT_EQ(ledger.next_expected_height(), 2u);
    }
    // (b) one max-ish debit plus a fee: this_debit = 2^64-1+100 > 2^64-1.
    {
        vx::state::LedgerState ledger;
        ledger.set_next_height(2);
        ledger.adjust_balance(spender.addr, U128(0, 2), true);
        Transaction t = mk_tx(spender.addr, sink, UINT64_MAX, 100, 0);
        ASSERT_TRUE(pq_sign(t, spender));
        const auto res = apply_user_block(ledger, {t});
        EXPECT_FALSE(res.ok);
        EXPECT_NE(res.error.find("tx 0: debit accumulator overflow"),
                  std::string::npos) << res.error;
        EXPECT_EQ(ledger.balance_of(spender.addr), U128(0, 2));
        EXPECT_FALSE(ledger.tracked_addresses_containing(sink));
    }
}

// -- 3. FEE / SHAPE EDGES ----------------------------------------------------

// fee=0/nonce=0 (genesis-v1 shape) at height 2+. [FINDING 2] The
// window-scoped exemption means the NORMAL nonce check runs; a fresh
// sender's expected nonce IS 0, so the first such tx is ACCEPTED. The
// refusal fires only on the REPLAY (counter already at 1):
// "nonce mismatch (expected 1, got 0)".
TEST(VxBoundaryTortureTest, FeeZeroNonceZeroAtHeightTwo) {
    const std::string dir = temp_dir("vx_bt_fee0n0");
    vx::storage::BlockStore store(dir + "/bt.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;
    apply_genesis(store, ledger);
    const PqAccount spender = demo_spender();
    const Address r = addr_of("NFA_BT_FEE0N0_R_000000000000000000000000");
    const uint64_t ts = std::time(nullptr);
    ASSERT_TRUE(push_mint(store, ledger, ts).ok);

    // Nonce 1 on a fresh counter: refused by the (now unscoped) check.
    {
        Transaction t = mk_tx(spender.addr, r, 2'000'000ull, 0, 1);
        ASSERT_TRUE(pq_sign(t, spender));
        const auto res = apply_user_block(ledger, {t});
        EXPECT_FALSE(res.ok);
        EXPECT_NE(res.error.find("nonce mismatch (expected 0, got 1)"),
                  std::string::npos) << res.error;
        EXPECT_EQ(ledger.get_next_nonce(spender.addr), 0u);
    }
    // Nonce 0 on a fresh counter: accepted -- the correct expected nonce.
    {
        BlockBuilder b = next_block(store, ts + 1);
        Transaction t = mk_tx(spender.addr, r, 2'000'000ull, 0, 0);
        ASSERT_TRUE(pq_sign(t, spender));
        b.add_transaction(t);
        const auto res = push_block(store, ledger, b);
        EXPECT_TRUE(res.ok) << res.error;
        EXPECT_EQ(ledger.balance_of(spender.addr), U128(MINT - 2'000'000ull));
        EXPECT_EQ(ledger.balance_of(r), U128(2'000'000ull));
        EXPECT_EQ(ledger.get_next_nonce(spender.addr), 1u);
    }
    // The replay (fee=0/nonce=0 again) is refused: the exemption is
    // window-scoped, so the nonce check compares 0 against the new
    // expected 1.
    {
        Transaction t = mk_tx(spender.addr, r, 2'000'000ull, 0, 0);
        ASSERT_TRUE(pq_sign(t, spender));
        const auto res = apply_user_block(ledger, {t});
        EXPECT_FALSE(res.ok);
        EXPECT_NE(res.error.find("nonce mismatch (expected 1, got 0)"),
                  std::string::npos) << res.error;
    }
    // fee=0 with nonce=1 (the legitimate next nonce): accepted.
    {
        BlockBuilder b = next_block(store, ts + 2);
        Transaction t = mk_tx(spender.addr, r, 3'000'000ull, 0, 1);
        ASSERT_TRUE(pq_sign(t, spender));
        b.add_transaction(t);
        const auto res = push_block(store, ledger, b);
        EXPECT_TRUE(res.ok) << res.error;
        EXPECT_EQ(ledger.balance_of(spender.addr), U128(MINT - 5'000'000ull));
        EXPECT_EQ(ledger.balance_of(r), U128(5'000'000ull));
    }

    std::filesystem::remove_all(dir);
}

// fee = UINT32_MAX. TDI fee burn: burned = floor(total/2) = 2,147,483,647,
// miner share = 2,147,483,648 (odd split rounds UP the share). (a) Without
// a coinbase the share is reported but paid to nobody. (b) A coinbase
// claiming exactly the odd share passes the emission gate and the share is
// re-credited WITHOUT counting as issuance (block_issuance == 0).
TEST(VxBoundaryTortureTest, FeeUint32MaxBurnAndOddShare) {
    using vx::blockchain::ATOMS_PER_VX;
    const PqAccount spender = demo_spender();
    const Address sink = addr_of("NFA_BT_FEEBIG_SINK_0000000000000000000");
    const Address mrec = addr_of("NFA_BT_FEEBIG_MINER_00000000000000000");
    constexpr uint64_t FEE = 4'294'967'295ull; // UINT32_MAX
    constexpr uint64_t AMOUNT = 200'000'000ull;
    constexpr uint64_t BURNED = 2'147'483'647ull; // floor(FEE/2)
    constexpr uint64_t SHARE = 2'147'483'648ull;  // FEE - BURNED

    // (a) no coinbase: the burn is booked, the share unclaimed.
    {
        vx::state::LedgerState ledger;
        ledger.set_next_height(1);
        ledger.adjust_balance(spender.addr, U128(MINT), true);
        Transaction t = mk_tx(spender.addr, sink, AMOUNT, FEE, 0);
        ASSERT_TRUE(pq_sign(t, spender));
        const auto res = apply_user_block(ledger, {t});
        EXPECT_TRUE(res.ok) << res.error;
        EXPECT_EQ(res.fees_burned, U128(BURNED));
        EXPECT_EQ(res.fees_miner_reward, U128(SHARE));
        EXPECT_EQ(ledger.total_burned(), U128(BURNED));
        EXPECT_EQ(ledger.issued_supply(), U128(0))
            << "fees are redistribution, never issuance";
        EXPECT_EQ(ledger.balance_of(spender.addr), U128(MINT - AMOUNT - FEE));
        EXPECT_EQ(ledger.balance_of(sink), U128(AMOUNT));
        EXPECT_EQ(ledger.balance_of(mrec), U128(0));
        EXPECT_FALSE(ledger.tracked_addresses_containing(mrec))
            << "with no coinbase in the block nobody was even credited, so"
               " the miner address never enters state";
    }
    // (b) coinbase claims exactly the odd fee share at index 0.
    {
        vx::state::LedgerState ledger;
        ledger.set_next_height(1);
        ledger.adjust_balance(spender.addr, U128(MINT), true);
        uint8_t prev[32];
        std::memset(prev, 0x11, sizeof(prev));
        Transaction cb = coinbase_tx(mrec, SHARE, 1, prev);
        Transaction t = mk_tx(spender.addr, sink, AMOUNT, FEE, 0);
        ASSERT_TRUE(pq_sign(t, spender));
        BlockBuilder b;
        b.set_height(1);
        b.set_timestamp(1'761'000'000ull);
        b.set_prev_hash(prev);
        std::array<uint8_t, 384> coords{};
        b.set_attractor_coords(coords.data());
        b.add_transaction(cb);  // index 0
        b.add_transaction(t);   // index 1
        b.finalize();
        BlockFrame f;
        std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
        const auto res = ledger.apply_block(BlockView(f));
        EXPECT_TRUE(res.ok) << res.error;
        EXPECT_EQ(res.fees_burned, U128(BURNED));
        EXPECT_EQ(res.fees_miner_reward, U128(SHARE));
        EXPECT_EQ(ledger.balance_of(mrec), U128(SHARE));
        EXPECT_EQ(ledger.balance_of(sink), U128(AMOUNT));
        EXPECT_EQ(ledger.balance_of(spender.addr), U128(MINT - AMOUNT - FEE));
        EXPECT_EQ(ledger.total_burned(), U128(BURNED));
        EXPECT_EQ(ledger.issued_supply(), U128(0))
            << "the fee share re-credit must not count as issuance";
        // The gate never fired: the claim is below the floor + share
        // entitlement for ANY frame hash.
        (void)ATOMS_PER_VX;
    }
}

// Self-transfer (sender == receiver): accepted; the commit order (debit,
// then credit the same key) nets to exactly the fee.
TEST(VxBoundaryTortureTest, SelfTransferNetFeeOnly) {
    const std::string dir = temp_dir("vx_bt_selfx");
    vx::storage::BlockStore store(dir + "/bt.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;
    apply_genesis(store, ledger);
    const PqAccount spender = demo_spender();
    const uint64_t ts = std::time(nullptr);
    ASSERT_TRUE(push_mint(store, ledger, ts).ok);

    BlockBuilder b = next_block(store, ts + 1);
    Transaction t = mk_tx(spender.addr, spender.addr, 2'000'000ull, 100, 0);
    ASSERT_TRUE(pq_sign(t, spender));
    b.add_transaction(t);
    const auto res = push_block(store, ledger, b);
    EXPECT_TRUE(res.ok) << res.error;
    EXPECT_EQ(ledger.balance_of(spender.addr), U128(MINT - 100));
    EXPECT_EQ(ledger.get_next_nonce(spender.addr), 1u);
    EXPECT_EQ(res.fees_burned, U128(50));

    std::filesystem::remove_all(dir);
}

// -- 4. COINBASE EDGES -------------------------------------------------------

// MINER_ claim of 0. [FINDING 3] Neither rejected nor recomputed to the
// floor: the zero-transfer gate explicitly exempts MINER_, the emission
// gate passes a 0 claim, the receiver is credited 0 -- and the receiver
// becomes a TRACKED zero-balance account.
TEST(VxBoundaryTortureTest, CoinbaseClaimZeroTracksReceiverAtZero) {
    vx::state::LedgerState ledger;
    ledger.set_next_height(1);
    const Address recv = addr_of("NFA_BT_CB0_MINER_00000000000000000000");
    const auto res = apply_miner_claim(ledger, 0, recv, 0);
    EXPECT_TRUE(res.ok) << res.error;
    EXPECT_EQ(ledger.balance_of(recv), U128(0));
    EXPECT_TRUE(ledger.tracked_addresses_containing(recv))
        << "the zero claim still created a tracked account";
    EXPECT_EQ(ledger.issued_supply(), U128(0));
    EXPECT_EQ(ledger.total_burned(), U128(0));
}

// MINER_ claim of exactly the 50 VX floor: the entitlement is
// reward(hash) >= 50 VX for ANY hash, so the exact floor claim is accepted
// for every frame; the floor is paid and booked as issuance.
TEST(VxBoundaryTortureTest, CoinbaseClaimFloorAlwaysPaid) {
    constexpr uint64_t FLOOR = 5'000'000'000ull; // 50 VX
    for (const uint64_t nonce : {uint64_t{0}, uint64_t{7}}) {
        vx::state::LedgerState ledger;
        ledger.set_next_height(1);
        const Address recv = addr_of("NFA_BT_CBFLOOR_MINER_000000000000000");
        const auto res = apply_miner_claim(ledger, FLOOR, recv, nonce);
        EXPECT_TRUE(res.ok) << res.error;
        EXPECT_EQ(ledger.balance_of(recv), U128(FLOOR));
        EXPECT_EQ(ledger.issued_supply(), U128(FLOOR));
    }
}

// MINER_ claim of 1001 VX: ALWAYS rejected regardless of the frame hash
// (the hash-oracle property). The schedule reward tops out at the 1,000 VX
// jackpot (40 leading zero bits), so with no fees the entitlement is at
// most 100,000,000,000 atoms < 100,100,000,000. Probed over 8 nonces.
TEST(VxBoundaryTortureTest, CoinbaseClaim1001AlwaysRejected) {
    constexpr uint64_t JACKPOT = 100'000'000'000ull;   // 1,000 VX
    constexpr uint64_t CLAIM = 100'100'000'000ull;     // 1,001 VX
    // A hash with exactly the 40-zero-bit jackpot threshold (the schedule
    // MAXIMUM): 5 full zero bytes, then the highest set bit.
    std::array<uint8_t, 32> jackpot_hash{};
    jackpot_hash[5] = 0xFF;
    jackpot_hash[6] = 0xFF;
    EXPECT_EQ(block_reward_vx(jackpot_hash.data()), 1000ull)
        << "the jackpot is the schedule maximum";
    EXPECT_LT(JACKPOT, CLAIM);
    vx::state::LedgerState ledger;
    ledger.set_next_height(1);
    const Address recv = addr_of("NFA_BT_CB1001_MINER_00000000000000000");
    for (uint64_t nonce = 0; nonce < 8; ++nonce) {
        const auto res = apply_miner_claim(ledger, CLAIM, recv, nonce);
        EXPECT_FALSE(res.ok) << "nonce " << nonce << " minted the 1001st VX";
        EXPECT_NE(res.error.find("coinbase exceeds emission entitlement"),
                  std::string::npos) << res.error;
    }
    EXPECT_EQ(ledger.balance_of(recv), U128(0));
    EXPECT_FALSE(ledger.tracked_addresses_containing(recv))
        << "a refused block must not even create the receiver";
}

// A second coinbase (MINER_ not at index 0) is refused with the exact
// "MINER_ must be index 0" error; nothing mutates.
TEST(VxBoundaryTortureTest, SecondCoinbaseNotIndexZero) {
    const std::string dir = temp_dir("vx_bt_cb2nd");
    vx::storage::BlockStore store(dir + "/bt.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;
    apply_genesis(store, ledger);
    const PqAccount spender = demo_spender();
    const Address sink = addr_of("NFA_BT_CB2ND_SINK_00000000000000000000");
    const Address mrec = addr_of("NFA_BT_CB2ND_MINER_000000000000000000");
    const uint64_t ts = std::time(nullptr);
    ASSERT_TRUE(push_mint(store, ledger, ts).ok);

    BlockBuilder b = next_block(store, ts + 1); // height 2, tip-bound
    Transaction t = mk_tx(spender.addr, sink, 1'000'000ull, 100, 0);
    ASSERT_TRUE(pq_sign(t, spender));
    uint8_t tip[32];
    store.tip_hash(tip);
    Transaction cb = coinbase_tx(mrec, 5'000'000'000ull, 2, tip);
    b.add_transaction(t);  // index 0: legal user spend
    b.add_transaction(cb); // index 1: the second coinbase
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));

    const auto res = ledger.apply_block(BlockView(f));
    EXPECT_FALSE(res.ok);
    EXPECT_NE(res.error.find("tx 1: MINER_ must be index 0"), std::string::npos)
        << res.error;
    EXPECT_EQ(ledger.balance_of(spender.addr), U128(MINT));
    EXPECT_EQ(ledger.balance_of(mrec), U128(0));
    EXPECT_FALSE(ledger.tracked_addresses_containing(mrec));
    EXPECT_EQ(ledger.next_expected_height(), 2u);

    std::filesystem::remove_all(dir);
}

// -- 5. MINT EDGES -----------------------------------------------------------

// GENESIS_2 shape edges, count-before-shape, and the height-2 refusal:
//   (a) amount + 1 -> "GENESIS mint unauthorized at height 1";
//   (b) tracked receiver (the genesis coinbase receiver) -> same error;
//   (c) two mints in one block -> "tx 1: second GENESIS mint in one block"
//       (the COUNT rule fires before the second mint's shape check);
//   (d) the legal mint applies (receiver untracked, exact amount, height 1);
//   (e) any mint at height 2 -> "GENESIS mint unauthorized at height 2".
TEST(VxBoundaryTortureTest, MintShapeCountAndHeightEdges) {
    const std::string dir = temp_dir("vx_bt_mintedge");
    vx::storage::BlockStore store(dir + "/bt.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;
    apply_genesis(store, ledger);
    const PqAccount spender = demo_spender();
    const Address gen_recv =
        payload_of(vx::blockchain::genesis_coinbase_receiver()); // tracked
    const Address r1 = addr_of("NFA_BT_MINT_R1_000000000000000000000000");
    const Address r2 = addr_of("NFA_BT_MINT_R2_000000000000000000000000");
    const uint64_t ts = std::time(nullptr);

    auto ledger_apply = [&](BlockBuilder& b) {
        b.finalize();
        BlockFrame f;
        std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
        return ledger.apply_block(BlockView(f));
    };

    // (a) amount + 1.
    {
        BlockBuilder b = next_block(store, ts);
        b.add_transaction(mint_tx(r1, GENESIS_2_MINT_ATOMICS + 1));
        const auto res = ledger_apply(b);
        EXPECT_FALSE(res.ok);
        EXPECT_NE(res.error.find("tx 0: GENESIS mint unauthorized at height 1"),
                  std::string::npos) << res.error;
    }
    // (b) tracked receiver.
    {
        BlockBuilder b = next_block(store, ts);
        b.add_transaction(mint_tx(gen_recv, GENESIS_2_MINT_ATOMICS));
        const auto res = ledger_apply(b);
        EXPECT_FALSE(res.ok);
        EXPECT_NE(res.error.find("tx 0: GENESIS mint unauthorized at height 1"),
                  std::string::npos) << res.error;
    }
    // (c) two mints in one block: the COUNT check catches the second.
    {
        BlockBuilder b = next_block(store, ts);
        b.add_transaction(mint_tx(spender.addr, GENESIS_2_MINT_ATOMICS));
        b.add_transaction(mint_tx(r2, GENESIS_2_MINT_ATOMICS));
        const auto res = ledger_apply(b);
        EXPECT_FALSE(res.ok);
        EXPECT_NE(res.error.find("tx 1: second GENESIS mint in one block"),
                  std::string::npos) << res.error;
    }
    // All refusals above left the ledger byte-identical.
    EXPECT_EQ(ledger.issued_supply(), U128(254'000'000'000'000ULL));
    EXPECT_FALSE(ledger.tracked_addresses_containing(spender.addr));
    EXPECT_FALSE(ledger.tracked_addresses_containing(r1));
    EXPECT_EQ(ledger.next_expected_height(), 1u);

    // (d) the legal pinned mint applies.
    {
        const auto res = push_mint(store, ledger, ts + 1);
        ASSERT_TRUE(res.ok) << res.error;
        EXPECT_EQ(ledger.balance_of(spender.addr), U128(GENESIS_2_MINT_ATOMICS));
        EXPECT_EQ(ledger.issued_supply(),
                  U128(254'000'000'000'000ULL + GENESIS_2_MINT_ATOMICS));
    }
    // (e) any GENESIS_2 mint at height 2 is refused.
    {
        BlockBuilder b = next_block(store, ts + 2);
        b.add_transaction(mint_tx(r2, GENESIS_2_MINT_ATOMICS));
        const auto res = ledger_apply(b);
        EXPECT_FALSE(res.ok);
        EXPECT_NE(res.error.find("GENESIS mint unauthorized at height 2"),
                  std::string::npos) << res.error;
        EXPECT_EQ(ledger.balance_of(r2), U128(0));
        EXPECT_EQ(ledger.next_expected_height(), 2u);
    }

    std::filesystem::remove_all(dir);
}

// End-to-end reorg: after a rollback to genesis the mint receiver returns
// to UNTRACKED (the undo forget-loop), so the pinned GENESIS_2 mint is
// legal again and re-applies to the exact same state.
TEST(VxBoundaryTortureTest, MintReapplyAfterRollback) {
    const std::string dir = temp_dir("vx_bt_mintreorg");
    vx::storage::BlockStore store(dir + "/bt.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;
    apply_genesis(store, ledger);
    const PqAccount spender = demo_spender();
    const Address sink = addr_of("NFA_BT_MINTREORG_SINK_00000000000000000");
    const uint64_t ts = std::time(nullptr);
    std::vector<BlockFrame> fork;

    {
        vx::state::UndoEngine undo(dir, store, ledger);

        // Height 1: the pinned mint (journaled before the store append).
        {
            BlockBuilder b = next_block(store, ts);
            b.add_transaction(mint_tx(spender.addr, GENESIS_2_MINT_ATOMICS));
            b.finalize();
            BlockFrame f;
            std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
            ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
            undo.apply_block(BlockView(f));
            ASSERT_TRUE(store.append_block(f));
            ASSERT_TRUE(ledger.apply_block(BlockView(f)).ok);
            fork.push_back(f);
        }
        // Height 2: a normal spend (fee 100).
        {
            BlockBuilder b = next_block(store, ts + 1);
            Transaction t = mk_tx(spender.addr, sink, 2'000'000ull, 100, 0);
            ASSERT_TRUE(pq_sign(t, spender));
            b.add_transaction(t);
            b.finalize();
            BlockFrame f;
            std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
            ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
            undo.apply_block(BlockView(f));
            ASSERT_TRUE(store.append_block(f));
            ASSERT_TRUE(ledger.apply_block(BlockView(f)).ok);
            fork.push_back(f);
        }
        EXPECT_EQ(ledger.balance_of(spender.addr),
                  U128(GENESIS_2_MINT_ATOMICS - 2'000'100ull));

        // Roll the fork back to genesis.
        ASSERT_TRUE(undo.rollback_to_height(0)) << undo.last_error();
        EXPECT_EQ(ledger.balance_of(spender.addr), U128(0));
        EXPECT_EQ(ledger.balance_of(sink), U128(0));
        // The forget-loop restored the PRE-FORK tracking state: both
        // fork-created addresses are untracked again.
        EXPECT_FALSE(ledger.tracked_addresses_containing(spender.addr));
        EXPECT_FALSE(ledger.tracked_addresses_containing(sink));
        EXPECT_EQ(ledger.get_next_nonce(spender.addr), 0u);
        EXPECT_EQ(ledger.next_expected_height(), 1u);
    }

    // Re-apply the SAME mint frame: legal again (the receiver is untracked
    // thanks to the forget-loop), lands on the exact pre-fork state.
    {
        vx::state::UndoEngine undo(dir, store, ledger);
        undo.apply_block(BlockView(fork[0]));
        const auto res = ledger.apply_block(BlockView(fork[0]));
        ASSERT_TRUE(res.ok) << "re-apply refused after rollback: " << res.error;
        EXPECT_EQ(ledger.balance_of(spender.addr), U128(GENESIS_2_MINT_ATOMICS));
        EXPECT_TRUE(ledger.tracked_addresses_containing(spender.addr));
        EXPECT_EQ(ledger.next_expected_height(), 2u);
    }

    std::filesystem::remove_all(dir);
}

// -- 6. BLOCK EDGES ----------------------------------------------------------

// [FINDING 6] A full block of 580 txs from ONE sender is IMPOSSIBLE to
// produce honestly: pq_sign_transaction derives the WOTS+ leaf from the tx
// nonce and REFUSES nonce >= 16 (XMSS subtree rollover is unimplemented --
// the published root covers subtree 0, leaves 0..15 only). One PQ key can
// therefore sign at most 16 transactions EVER (and after 16 lifetime txs a
// key is dead: the ledger nonce keeps counting past what any witness can
// cover). The structural 580-tx maximum is exercised below with 37
// distinct fresh keys (36 x 16 + 4 = 580), staged with the test-only
// adjust_balance helper (the demo spender itself cannot fund 37 accounts --
// its 16 leaves are exhausted). The 581st tx cannot even enter the frame.
TEST(VxBoundaryTortureTest, MaxTxsPerBlockFull) {
    const std::string dir = temp_dir("vx_bt_maxtx");
    vx::storage::BlockStore store(dir + "/bt.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;
    apply_genesis(store, ledger);
    const Address sink = addr_of("NFA_BT_MAXTX_SINK_000000000000000000000");
    const uint64_t ts = std::time(nullptr);
    ASSERT_TRUE(push_mint(store, ledger, ts).ok);

    constexpr uint64_t AMOUNT = 10'000'000ull; // 0.1 VX each
    constexpr uint32_t FEE = 100;

    // 37 fresh senders, staged 2 VX each (test-only funding helper).
    std::vector<PqAccount> senders;
    senders.reserve(37);
    for (int i = 0; i < 37; ++i) {
        senders.push_back(
            make_pq_account(("VX_BT_MAXTX_S" + std::to_string(i)).c_str()));
        ledger.adjust_balance(senders.back().addr, U128(200'000'000ull), true);
    }

    // The full 580-tx block: 36 senders x 16 txs + 1 sender x 4 txs.
    BlockBuilder b = next_block(store, ts + 1);
    uint32_t added = 0;
    for (size_t s = 0; s < senders.size() && added < MAX_TX_PER_BLOCK; ++s) {
        const uint32_t txs_for_this_sender =
            (s + 1 < senders.size()) ? 16u : (MAX_TX_PER_BLOCK - added);
        for (uint32_t n = 0; n < txs_for_this_sender; ++n) {
            Transaction t = mk_tx(senders[s].addr, sink, AMOUNT, FEE, n);
            ASSERT_TRUE(pq_sign(t, senders[s])) << "sign failed at " << added;
            ASSERT_TRUE(b.add_transaction(t)) << "add failed at " << added;
            ++added;
        }
    }
    ASSERT_EQ(added, MAX_TX_PER_BLOCK);
    // The 581st cannot enter the frame.
    {
        Transaction t581 = mk_tx(senders[36].addr, sink, AMOUNT, FEE, 4);
        ASSERT_TRUE(pq_sign(t581, senders[36]));
        EXPECT_FALSE(b.add_transaction(t581));
    }
    const auto res = push_block(store, ledger, b);
    EXPECT_TRUE(res.ok) << res.error;

    EXPECT_EQ(res.transfers, 580u);
    EXPECT_EQ(ledger.balance_of(sink), U128(MAX_TX_PER_BLOCK * AMOUNT));
    EXPECT_EQ(ledger.total_burned(), U128(MAX_TX_PER_BLOCK * FEE / 2)); // 29,000
    EXPECT_EQ(ledger.issued_supply(),
              U128(254'000'000'000'000ULL + GENESIS_2_MINT_ATOMICS))
        << "a pure-transfer block must not issue";
    EXPECT_EQ(store.chain_height(), 3u);
    // Every sender drained to the atom: 16 x (amount + fee) or 4 x (...).
    for (size_t s = 0; s + 1 < senders.size(); ++s) {
        EXPECT_EQ(ledger.balance_of(senders[s].addr),
                  U128(200'000'000ull - 16ull * (AMOUNT + FEE))) << s;
    }
    EXPECT_EQ(ledger.balance_of(senders[36].addr),
              U128(200'000'000ull - 4ull * (AMOUNT + FEE)));

    std::filesystem::remove_all(dir);
}

// [FINDING 6] pinned exactly: the 16th signature is the last one a PQ key
// can ever produce. Nonces 0..15 sign; nonce 16 (subtree 1) is refused by
// the signer itself, so the 17th tx from one key cannot exist on the wire
// (the ledger's nonce accounting would accept it -- the limit is in the
// signature engine, not in apply_block).
TEST(VxBoundaryTortureTest, PqKeySignsAtMostSixteenNonces) {
    const std::string dir = temp_dir("vx_bt_16leaf");
    vx::storage::BlockStore store(dir + "/bt.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;
    apply_genesis(store, ledger);
    const PqAccount spender = demo_spender();
    const PqAccount acc = make_pq_account("VX_BT_16LEAF_SK_V1");
    const Address sink = addr_of("NFA_BT_16LEAF_SINK_00000000000000000000");
    const uint64_t ts = std::time(nullptr);
    ASSERT_TRUE(push_mint(store, ledger, ts).ok);

    // Fund the fresh account, then spend from it 16 times in one block
    // (nonces 0..15): accepted, intra-block sequential nonces.
    {
        BlockBuilder b = next_block(store, ts + 1);
        Transaction f = mk_tx(spender.addr, acc.addr, 1'000'000'000ull, 100, 0);
        ASSERT_TRUE(pq_sign(f, spender));
        ASSERT_TRUE(b.add_transaction(f));
        const auto res = push_block(store, ledger, b);
        ASSERT_TRUE(res.ok) << res.error;
    }
    {
        BlockBuilder b = next_block(store, ts + 2);
        for (uint32_t n = 0; n < 16; ++n) {
            Transaction t = mk_tx(acc.addr, sink, 1'000'000ull, 100, n);
            ASSERT_TRUE(pq_sign(t, acc)) << "sign failed at " << n;
            ASSERT_TRUE(b.add_transaction(t));
        }
        const auto res = push_block(store, ledger, b);
        EXPECT_TRUE(res.ok) << res.error;
        EXPECT_EQ(ledger.balance_of(acc.addr), U128(983'998'400ull));
        EXPECT_EQ(ledger.get_next_nonce(acc.addr), 16u);
    }
    // The 17th tx: the signer refuses the nonce BEFORE any key work.
    {
        Transaction t17 = mk_tx(acc.addr, sink, 1'000'000ull, 100, 16);
        EXPECT_FALSE(pq_sign(t17, acc));
        // And the ledger itself would have accepted nonce 16 -- the state
        // layer has no such limit; the engine cannot produce the witness.
    }

    std::filesystem::remove_all(dir);
}


// A hostile frame whose header tx_count lies beyond the structural
// capacity: the store refuses with the exact capacity error AND the ledger
// refuses with its own bound before any reader walks past the frame. The
// clean frame then goes through untouched.
TEST(VxBoundaryTortureTest, TxCountHeaderLie) {
    const std::string dir = temp_dir("vx_bt_txlie");
    vx::storage::BlockStore store(dir + "/bt.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;
    apply_genesis(store, ledger);
    const Address sink = addr_of("NFA_BT_TXLIE_SINK_00000000000000000000");
    const uint64_t ts = std::time(nullptr);

    BlockBuilder b = next_block(store, ts);
    b.add_transaction(mint_tx(demo_spender().addr, GENESIS_2_MINT_ATOMICS));
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    // Seal first: the rejection below must name tx_count, not missing work.
    ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));

    for (const uint32_t lie : {uint32_t{581}, uint32_t{0xFFFFFFFFu}}) {
        BlockFrame poisoned = f;
        std::memcpy(poisoned.data() + 0x1D4, &lie, sizeof(lie));
        const auto res = ledger.apply_block(BlockView(poisoned));
        EXPECT_FALSE(res.ok);
        EXPECT_EQ(res.error, "tx_count " + std::to_string(lie) +
                                 " exceeds block capacity 580")
            << res.error;
        EXPECT_FALSE(store.append_block(poisoned));
        EXPECT_EQ(store.last_error(), "tx_count exceeds MAX_TX_PER_BLOCK");
    }
    EXPECT_EQ(store.chain_height(), 1u);
    EXPECT_EQ(ledger.next_expected_height(), 1u);
    EXPECT_FALSE(ledger.tracked_addresses_containing(sink));

    // The honest frame goes through.
    const auto res = push_block(store, ledger, b);
    EXPECT_TRUE(res.ok) << res.error;
    EXPECT_EQ(ledger.balance_of(demo_spender().addr),
              U128(GENESIS_2_MINT_ATOMICS));
    EXPECT_EQ(store.chain_height(), 2u);

    std::filesystem::remove_all(dir);
}
