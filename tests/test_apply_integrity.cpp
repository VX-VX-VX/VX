// VortexApplyIntegrityTest - the half-applied-block commit guard (D2).
//
// "No partial application" is explicit and enforced in LedgerState::apply_block:
//
//   part A (pre-mutation): the body commitment is re-verified - a header
//     that lies about tx_count (patched after the merkle root was computed)
//     is refused before a single balance moves;
//   part B: the supply snapshot  pre_supply  is taken before the commit loop;
//   part C (post-apply): applied tx count == header tx_count, and the
//     supply law  post_supply == pre_supply - total_fees + coinbase_mints
//     holds (coinbase_mints = GENESIS_*/MINER_ credits; fees are split
//     floor/2 burn, ceil/2 producer share - fees never re-enter balances);
//     the commit journal rolls every mutation back on any refusal.
//
// Supply law derivation (from the commit code, not from a spec): every user
// tx moves (amount + fee) out of the sender and amount back to the receiver
// (net -fee); every coinbase credit is new money; the fee split lands in
// burned_supply_ / the producer, never back in balances inside the block.

#include <gtest/gtest.h>
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/storage/block_store.hpp"
#include "vx/state/ledger_state.hpp"

#include <cstring>
#include <ctime>
#include <filesystem>
#include <memory>
#include <string>
#include <unistd.h>

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

// Builds + seals a frame from a builder without touching store/ledger.
BlockFrame sealed_frame(vx::storage::BlockStore& store, BlockBuilder& b) {
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    EXPECT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
    return f;
}

void patch_tx_count(BlockFrame& f, uint32_t count) {
    std::memcpy(f.data() + 0x1D4, &count, sizeof(count));
}

// The full setup: genesis replayed, the height-1 protocol mint applied, and
// the demo spender funded with the pinned 100,000 VX mint.
struct IntegrityChain {
    std::string dir;
    std::unique_ptr<vx::storage::BlockStore> store;
    std::unique_ptr<vx::state::LedgerState> ledger;
    PqAccount demo{};
    Address spender{};
    Address sink_a{};
    Address sink_b{};

    explicit IntegrityChain(const char* tag) : dir(temp_dir(tag)) {
        store = std::make_unique<vx::storage::BlockStore>(dir + "/ledger.vxb",
                                                          "genesis.bin", 8);
        ledger = std::make_unique<vx::state::LedgerState>();
        const auto* g = store->get_block(0);
        if (!g) { ADD_FAILURE(); return; }
        if (!g) return;
        BlockFrame gf;
        std::memcpy(gf.data(), reinterpret_cast<const uint8_t*>(g), BLOCK_SIZE_BYTES);
        if (!ledger->apply_block(BlockView(gf)).ok) { ADD_FAILURE(); return; }

        demo = make_pq_account("VX_DEMO_SPENDER_SK_V1");
        spender = genesis2_mint_receiver_payload();

        BlockBuilder b = next_block(*store, static_cast<uint64_t>(std::time(nullptr)));
        Transaction mint = make_tx(addr_of("GENESIS_2"), spender,
                                   GENESIS_2_MINT_ATOMICS, 0);
        sign_transaction(mint); // system sender: structural digest only
        if (!b.add_transaction(mint)) { ADD_FAILURE(); return; }
        const BlockFrame f = sealed_frame(*store, b);
        if (!store->append_block(f)) { ADD_FAILURE(); return; }
        if (!ledger->apply_block(BlockView(f)).ok) { ADD_FAILURE(); return; }
        if (!(ledger->balance_of(spender) == U128(GENESIS_2_MINT_ATOMICS))) { ADD_FAILURE(); return; }

        sink_a = addr_of("NFA_INTEGRITY_SINK_A_000000000000000000000");
        sink_b = addr_of("NFA_INTEGRITY_SINK_B_000000000000000000000");
    }

    ~IntegrityChain() { std::filesystem::remove_all(dir); }
};

// Snapshot of everything the guard must protect against partial mutation.
struct StateSnapshot {
    U128 spender;
    U128 sink_a;
    U128 sink_b;
    uint32_t spender_nonce;
    U128 burned;
    U128 issued;
    U128 supply;
    uint64_t height;
};

StateSnapshot snapshot(const IntegrityChain& c) {
    StateSnapshot s;
    s.spender = c.ledger->balance_of(c.spender);
    s.sink_a = c.ledger->balance_of(c.sink_a);
    s.sink_b = c.ledger->balance_of(c.sink_b);
    s.spender_nonce = c.ledger->get_next_nonce(c.spender);
    s.burned = c.ledger->total_burned();
    s.issued = c.ledger->issued_supply();
    s.supply = c.ledger->total_supply();
    s.height = c.ledger->next_expected_height();
    return s;
}

} // namespace

// -- The hostile frame the guard exists for: a header whose tx_count lies
// about its body (patched AFTER the merkle root was computed). The body
// commitment is re-verified in apply_block, so the lie fails cleanly with
// ERR_APPLY_INTEGRITY and the ledger is byte-identical to the pre-call
// state - not half-applied, not supply-shifted.
TEST(VortexApplyIntegrityTest, TxCountDownwardLieRejected) {
    IntegrityChain c("vx_integ_down");
    const StateSnapshot before = snapshot(c);

    // A valid 2-tx block: both transfers witnessed and consistent...
    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction t0 = make_tx(c.spender, c.sink_a, 1000000000u, 0);
    Transaction t1 = make_tx(c.spender, c.sink_b, 2000000000u, 1);
    ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(t0, c.demo.sk));
    ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(t1, c.demo.sk));
    ASSERT_TRUE(b.add_transaction(t0));
    ASSERT_TRUE(b.add_transaction(t1));
    BlockFrame f = sealed_frame(*c.store, b);

    // ...then the header lies that only the first transaction exists
    // (patched after the merkle root was computed; the count stays within
    // the structural bound, so only the body-commitment check sees it).
    patch_tx_count(f, 1);

    const auto res = c.ledger->apply_block(BlockView(f));
    EXPECT_FALSE(res.ok) << "a lying tx_count was applied!";
    EXPECT_NE(res.error.find("ERR_APPLY_INTEGRITY"), std::string::npos)
        << "expected the integrity refusal, got: " << res.error;
    EXPECT_NE(res.error.find("merkle_root does not commit the block body"),
              std::string::npos)
        << "expected the body-commitment refusal, got: " << res.error;

    // Nothing moved: no balance, no nonce, no counter, no height.
    const StateSnapshot after = snapshot(c);
    EXPECT_EQ(after.spender, before.spender);
    EXPECT_EQ(after.sink_a, before.sink_a);
    EXPECT_EQ(after.sink_b, before.sink_b);
    EXPECT_EQ(after.spender_nonce, before.spender_nonce);
    EXPECT_EQ(after.burned, before.burned);
    EXPECT_EQ(after.issued, before.issued);
    EXPECT_EQ(after.supply, before.supply);
    EXPECT_EQ(after.height, before.height);

    // The refusal is not sticky: restoring the honest header (tx_count 2,
    // which the computed merkle root commits again) lets the same frame
    // apply normally.
    patch_tx_count(f, 2);
    const auto retry = c.ledger->apply_block(BlockView(f));
    EXPECT_TRUE(retry.ok) << retry.error;
    EXPECT_EQ(c.ledger->balance_of(c.sink_a), U128(1000000000u));
    EXPECT_EQ(c.ledger->balance_of(c.sink_b), U128(2000000000u));
}

// -- An upward tx_count lie (body has 1 tx, header says 2) is refused the
// same way: the recomputed commitment covers the zeroed slot and the header
// field cannot match both.
TEST(VortexApplyIntegrityTest, TxCountUpwardLieRejected) {
    IntegrityChain c("vx_integ_up");
    const StateSnapshot before = snapshot(c);

    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction t0 = make_tx(c.spender, c.sink_a, 1000000000u, 0);
    ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(t0, c.demo.sk));
    ASSERT_TRUE(b.add_transaction(t0));
    BlockFrame f = sealed_frame(*c.store, b);

    patch_tx_count(f, 2);
    const auto res = c.ledger->apply_block(BlockView(f));
    EXPECT_FALSE(res.ok) << "an inflated tx_count was applied!";
    EXPECT_NE(res.error.find("ERR_APPLY_INTEGRITY"), std::string::npos)
        << "expected the integrity refusal, got: " << res.error;

    const StateSnapshot after = snapshot(c);
    EXPECT_EQ(after.spender, before.spender);
    EXPECT_EQ(after.sink_a, before.sink_a);
    EXPECT_EQ(after.spender_nonce, before.spender_nonce);
    EXPECT_EQ(after.burned, before.burned);
    EXPECT_EQ(after.height, before.height);
}

// -- Control: the honest multi-tx block applies, and the recorded supply
// accounting matches the law exactly (fees floor/2 burned, ceil/2 to the
// producer, no coinbase in this block so issuance does not move).
TEST(VortexApplyIntegrityTest, HonestMultiTxBlockMatchesSupplyLaw) {
    IntegrityChain c("vx_integ_ok");
    const StateSnapshot before = snapshot(c);

    const uint64_t a0 = 1000000000u;
    const uint64_t a1 = 2000000000u;
    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction t0 = make_tx(c.spender, c.sink_a, a0, 0);
    Transaction t1 = make_tx(c.spender, c.sink_b, a1, 1);
    ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(t0, c.demo.sk));
    ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(t1, c.demo.sk));
    ASSERT_TRUE(b.add_transaction(t0));
    ASSERT_TRUE(b.add_transaction(t1));
    const BlockFrame f = sealed_frame(*c.store, b);
    const auto res = c.ledger->apply_block(BlockView(f));
    ASSERT_TRUE(res.ok) << res.error;
    EXPECT_EQ(res.transfers, 2u);

    // Exact balances: sender paid both amounts + 2 x 100 fee.
    EXPECT_EQ(c.ledger->balance_of(c.sink_a), U128(a0));
    EXPECT_EQ(c.ledger->balance_of(c.sink_b), U128(a1));
    EXPECT_EQ(c.ledger->balance_of(c.spender),
              U128(GENESIS_2_MINT_ATOMICS) - U128(a0) - U128(a1) - U128(200));
    EXPECT_EQ(c.ledger->get_next_nonce(c.spender), 2u);

    // Supply law, checked through the public counters:
    //   burned delta == floor(total_fees / 2) == 100
    //   issued delta == 0 (no coinbase in the frame)
    //   total_supply == pre_supply - total_fees (fees left all balances)
    EXPECT_EQ(c.ledger->total_burned(), before.burned + U128(100));
    EXPECT_EQ(c.ledger->issued_supply(), before.issued);
    EXPECT_EQ(c.ledger->total_supply(), before.supply - U128(200));
    EXPECT_EQ(res.fees_burned, U128(100));
    EXPECT_EQ(res.fees_miner_reward, U128(100));
    EXPECT_EQ(c.ledger->next_expected_height(), before.height + 1);
}
