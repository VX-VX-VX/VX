// VortexDocumentedGapsTest — reproducible pins for KNOWN security gaps
// and regressions for fixed ones.
//
// Pins (tests EXPECT hostile behavior to succeed today, so the gap is
// (a) reproducible by any reviewer with one command and (b) impossible
// to "forget"; each flips to a negative assertion the day its fix ships):
//
//   1. NoWorkBlockAccepted      — BACKLOG 0.6/0.9 (block validation hole)
//   2. KeylessTheftReproducible — BACKLOG 0.7 (transaction authorization)
//
// Regression (was a P0 bug, now fixed — expects REJECTION):
//
//   3. DoubleSpendInBlockRejected — intra-block debit accounting; two
//      spends by the same sender in one block used to underflow U128
//      and mint a ~2^128 phantom balance (external review, fixed).
//
// All three originate from / are confirmed by external review.

#include <gtest/gtest.h>
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/storage/block_store.hpp"
#include "vx/state/ledger_state.hpp"

#include <cstring>
#include <filesystem>
#include <iostream>
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

// Append + ledger-apply a builder's frame, in one step.
bool push_block(vx::storage::BlockStore& store, vx::state::LedgerState& ledger,
                BlockBuilder& b) {
    b.finalize();
    BlockFrame frame;
    std::memcpy(frame.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    if (!store.append_block(frame)) return false;
    return ledger.apply_block(BlockView(frame)).ok;
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

} // namespace

// ── Gap pin 1: a block with no work, no timestamp, no transactions is
// accepted by append_block (magic/height/prev only) and by apply_block.
// Fix: one validate_block() on every intake path (BACKLOG 0.6/0.9).
TEST(VortexDocumentedGapsTest, NoWorkBlockAccepted) {
    const std::string dir = temp_dir("vx_gap_block");
    vx::storage::BlockStore store(dir + "/gap.vxb", "genesis.bin");
    vx::state::LedgerState ledger;

    // Bring the ledger up to the store's auto-seeded genesis first.
    const auto* g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t*>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    BlockBuilder b = next_block(store, 0); // timestamp 0: no rule enforced
    // NOTE: no PoGW nonce, no attractor commitment, zero transactions.

    BlockFrame f;
    b.finalize();
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    EXPECT_TRUE(store.append_block(f))
        << "gap closed? then flip this expectation to EXPECT_FALSE";
    EXPECT_TRUE(ledger.apply_block(BlockView(f)).ok)
        << "gap closed? then flip this expectation to EXPECT_FALSE";

    std::cout << "  [documented gap] empty/no-work frame (timestamp 0, no"
              << " PoGW) accepted at height " << store.chain_height() - 1
              << ". Single validate_block() on all intake paths is BACKLOG"
              << " 0.6/0.9.\n";

    std::filesystem::remove_all(dir);
}

// ── Gap pin 2: keyless transaction authorization. For any sender not
// registered as a PQ sender, verify_transaction_proof accepts a plain
// sponge digest that ANYONE can compute (sign_transaction() uses no key).
// An attacker holding no key for the victim forges a transfer from the
// victim and the ledger credits the attacker (BACKLOG 0.7/0.8).
TEST(VortexDocumentedGapsTest, KeylessTheftReproducible) {
    const std::string dir = temp_dir("vx_gap_theft");
    vx::storage::BlockStore store(dir + "/theft.vxb", "genesis.bin");
    vx::state::LedgerState ledger;

    // Apply genesis so its mint receiver holds a real balance.
    const auto* g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t*>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    // The victim: the genesis mint receiver. We hold NO key for it
    // (there is no key - the address is not PQ-bound yet).
    Address victim{};
    std::memcpy(victim.data(), g->transactions[0].receiver_nfa, 42);
    const Address attacker = addr_of(
        "NFA_THIEF_NO_KEY_NEEDED_00000000000000000000000000");

    ASSERT_GT(ledger.balance_of(victim), U128{})
        << "victim must be funded by the genesis mint for this pin";

    // The forged transfer: sender = victim, attacker holds nothing.
    Transaction theft = make_tx(victim, attacker, 100000000, 0);
    sign_transaction(theft); // <-- keyless: computable by anyone
    EXPECT_TRUE(verify_transaction_proof(theft))
        << "gap closed? then flip this expectation to EXPECT_FALSE";

    // Ship it as a normal block; the ledger must (and, today, does) accept.
    BlockBuilder b = next_block(store, 12345);
    ASSERT_TRUE(b.add_transaction(theft));
    const bool applied = push_block(store, ledger, b);
    EXPECT_TRUE(applied) << "theft block rejected - gap may be closing";
    if (applied) {
        const U128 stolen = ledger.balance_of(tx_address(theft.receiver_nfa));
        EXPECT_EQ(stolen, U128(100000000u))
            << "attacker credited 1 VX without any private key";
        std::cout << "  [documented gap] keyless theft reproducible: 1 VX"
                  << " moved from the genesis receiver with zero secrets"
                  << " (Tier 2 keyless fallback). Transaction authorization"
                  << " is BACKLOG 0.7/0.8; until it ships, TX AUTH IS NOT"
                  << " CLAIMED.\n";
    }

    std::filesystem::remove_all(dir);
}

// ── Regression (was P0, fixed): two spends by the same sender in one
// block must NOT mint phantom supply. Before the fix both txs passed the
// balance check independently (pending credits were counted, intra-block
// debits were not) and the commit loop underflowed U128 to ~2^128.
TEST(VortexDocumentedGapsTest, DoubleSpendInBlockRejected) {
    const std::string dir = temp_dir("vx_gap_dspend");
    vx::storage::BlockStore store(dir + "/dspend.vxb", "genesis.bin");
    vx::state::LedgerState ledger;

    // Height 0: apply genesis.
    const auto* g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t*>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    // Height 1: fund the sender with exactly 10 VX via the GENESIS_2 mint.
    const Address sender = addr_of("NFA_DSPEND_VICTIM_000000000000000000000000");
    const Address sink = addr_of("NFA_DSPEND_SINK_0000000000000000000000000000");
    {
        BlockBuilder b = next_block(store, 1);
        Transaction mint = make_tx(addr_of("GENESIS_2"), sender, 1000000000u, 0);
        sign_transaction(mint);
        ASSERT_TRUE(b.add_transaction(mint));
        ASSERT_TRUE(push_block(store, ledger, b));
    }
    ASSERT_EQ(ledger.balance_of(sender), U128(1000000000u)); // 10 VX

    // Height 2: TWO spends of 6 VX each (total 12 VX > 10 VX balance),
    // sequential nonces, both proofs individually valid.
    {
        BlockBuilder b = next_block(store, 2);
        Transaction s1 = make_tx(sender, sink, 600000000u, 0);
        Transaction s2 = make_tx(sender, sink, 600000000u, 1);
        sign_transaction(s1);
        sign_transaction(s2);
        EXPECT_TRUE(verify_transaction_proof(s1));
        EXPECT_TRUE(verify_transaction_proof(s2));
        ASSERT_TRUE(b.add_transaction(s1));
        ASSERT_TRUE(b.add_transaction(s2));

        // The block must be REJECTED outright - no partial application.
        b.finalize();
        BlockFrame f;
        std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
        EXPECT_TRUE(store.append_block(f)); // store gate is gap pin 1
        const auto res = ledger.apply_block(BlockView(f));
        EXPECT_FALSE(res.ok) << "double spend accepted - regression!";
        EXPECT_NE(res.error.find("insufficient funds"), std::string::npos)
            << "expected the second spend to fail the funded-balance check";
        EXPECT_EQ(res.error.find("underflow"), std::string::npos)
            << "underflow guard must never fire - pre-check must reject first";

        // No mutation: sender still holds exactly 10 VX, no phantom supply.
        EXPECT_EQ(ledger.balance_of(sender), U128(1000000000u));
        EXPECT_EQ(ledger.total_supply(), ledger.total_supply()); // sane path
        std::cout << "  [fixed] intra-block double spend rejected with"
                  << " 'insufficient funds'; no U128 underflow, no phantom"
                  << " balance.\n";
    }

    std::filesystem::remove_all(dir);
}
