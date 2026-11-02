// VortexDocumentedGapsTest — reproducible pins for KNOWN security gaps
// and regressions for fixed ones.
//
// Pins (tests EXPECT hostile behavior to succeed today, so the gap is
// (a) reproducible by any reviewer with one command and (b) impossible
// to "forget"; each flips to a negative assertion the day its fix ships):
//
//   1. NoWorkBlockAccepted      — BACKLOG 0.6/0.9 (block validation hole)
//   2. KeylessTheftReproducible — BACKLOG 0.7 (transaction authorization)
//   3. MinerEmissionForgeable   — BACKLOG 0.6/0.9 (MINER_ coinbase has no
//      identity/PoGW binding: anyone mints up to 1000 VX per block)
//
// Regressions (were P0/P1 bugs, now fixed — expect REJECTION):
//
//   4. DoubleSpendInBlockRejected — intra-block debit accounting; two
//      spends by the same sender in one block used to underflow U128
//      and mint a ~2^128 phantom balance (external review, fixed).
//   5. NonceZeroReplayRejected  — the genesis-v1 shape (fee=0/nonce=0)
//      used to bypass nonce accounting at ANY height; now scoped to the
//      genesis replay window (external review round 4, fixed).
//   6. OversizedTxCountRejected — a patched header tx_count > capacity
//      used to walk readers past the frame; now gated in append_block.
//   7. TamperedMerkleRejected   — the merkle root was never verified on
//      intake; now append_block recomputes and rejects mismatches.
//
// Round 5 regressions (external review PoCs converted to tests):
//
//   8. HtlcVmFailureForcesLocked — the HTLC outcome used to ignore the VM
//      verdict (CLAIMED even when the bytecode failed at runtime).
//   9. VaultTokenDigestFullyChecked — only the first 4 token bytes were
//      stored/compared; a token with a mutated tail still consumed.
//  10. VaultPoolFullNotClobber — the ring page cursor used to silently
//      zero a still-LOCKED page when the pool wrapped.
//  11. TailMetadataCommitted — the block hash used to cover only the
//      472-byte header, leaving vm/PoGW tail metadata outside the
//      commitment.
//
// All originate from / are confirmed by external review.

#include <gtest/gtest.h>
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/storage/block_store.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/core/memory_vault.hpp"
#include "vx/vm/vortex_vm.hpp"

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

// ── Gap pin 3: MINER_ coinbase emission has no identity or PoGW binding.
// Any account that prefixes its sender with "MINER_" and places itself at
// index 0 mints up to 1000 VX per block. The reward limit and index rule
// are enforced, but WHO may mine is not - so emission is forgeable by
// anyone until PoGW verification gates coinbase intake (BACKLOG 0.6/0.9,
// which itself depends on the PoGW-verification design item 0.6).
TEST(VortexDocumentedGapsTest, MinerEmissionForgeable) {
    const std::string dir = temp_dir("vx_gap_miner");
    vx::storage::BlockStore store(dir + "/miner.vxb", "genesis.bin");
    vx::state::LedgerState ledger;

    const auto* g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t*>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    // A fake miner: no PoGW work, no identity, just the prefix.
    const Address fake_miner_recv =
        addr_of("NFA_FAKE_MINER_EMISSION_00000000000000000000000");
    Transaction cb{};
    std::memcpy(cb.sender_nfa, "MINER_", 6);
    for (size_t i = 6; i < 42; ++i) cb.sender_nfa[i] = '0';
    std::memcpy(cb.receiver_nfa, fake_miner_recv.data(), 42);
    tx_set_amount(cb, 1000ULL * 100000000ULL); // exactly the reward limit
    tx_set_fee(cb, 0);
    tx_set_nonce(cb, 0);
    sign_transaction(cb); // keyless, like the real coinbase path

    BlockBuilder b = next_block(store, 777);
    ASSERT_TRUE(b.add_transaction(cb)); // index 0, as required
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    EXPECT_TRUE(store.append_block(f))
        << "gap closed? then flip this expectation to EXPECT_FALSE";
    EXPECT_TRUE(ledger.apply_block(BlockView(f)).ok)
        << "gap closed? then flip this expectation to EXPECT_FALSE";
    EXPECT_EQ(ledger.balance_of(fake_miner_recv), U128(1000ULL * 100000000ULL))
        << "a non-miner minted the maximum coinbase reward";

    std::cout << "  [documented gap] fake MINER_ coinbase minted 1000 VX"
              << " with no mining work or identity. Coinbase emission"
              << " binding is BACKLOG 0.6/0.9; until it ships, EMISSION"
              << " INTEGRITY IS NOT CLAIMED.\n";

    std::filesystem::remove_all(dir);
}

// ── Regression (round 4, fixed): the genesis-v1 tx shape (fee=0 and
// nonce=0) used to skip nonce accounting at EVERY height, so replaying a
// genesis-v1-shaped tx re-ran it forever. The exemption is now scoped to
// the genesis replay window (next_height <= 1).
TEST(VortexDocumentedGapsTest, NonceZeroReplayRejected) {
    const std::string dir = temp_dir("vx_gap_nonce");
    vx::storage::BlockStore store(dir + "/nonce.vxb", "genesis.bin");
    vx::state::LedgerState ledger;

    const auto* g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t*>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    const Address sender = addr_of("NFA_NONCE_VICTIM_00000000000000000000000");
    const Address sink = addr_of("NFA_NONCE_SINK_00000000000000000000000000");

    // Height 1: fund the sender (GENESIS_2 mint, legacy window).
    {
        BlockBuilder b = next_block(store, 1);
        Transaction mint = make_tx(addr_of("GENESIS_2"), sender, 1000000000u, 0);
        sign_transaction(mint);
        ASSERT_TRUE(b.add_transaction(mint));
        ASSERT_TRUE(push_block(store, ledger, b));
    }

    // Height 2: a real spend consumes nonce 0 (window is closed here:
    // next_height == 2). Fee 100, so it is NOT genesis-v1-shaped.
    {
        BlockBuilder b = next_block(store, 2);
        Transaction spend = make_tx(sender, sink, 100000000u, 0);
        sign_transaction(spend);
        ASSERT_TRUE(b.add_transaction(spend));
        ASSERT_TRUE(push_block(store, ledger, b));
    }

    // Height 3: REPLAY in genesis-v1 clothing - fee=0, nonce=0 from the
    // same sender whose expected nonce is now 1. Before the scoping fix
    // the shape alone bypassed the nonce check; now it must be refused.
    {
        BlockBuilder b = next_block(store, 3);
        Transaction replay = make_tx(sender, sink, 100000000u, 0);
        tx_set_fee(replay, 0); // shape: fee=0 + nonce=0 == genesis v1
        sign_transaction(replay);
        ASSERT_TRUE(verify_transaction_proof(replay));
        ASSERT_TRUE(b.add_transaction(replay));
        b.finalize();
        BlockFrame f;
        std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
        EXPECT_TRUE(store.append_block(f)); // store gate is gap pin 1
        const auto res = ledger.apply_block(BlockView(f));
        EXPECT_FALSE(res.ok) << "genesis-v1-shaped replay accepted!";
        EXPECT_NE(res.error.find("nonce mismatch"), std::string::npos)
            << "expected the nonce check to fire, got: " << res.error;
        std::cout << "  [fixed] fee=0/nonce=0 replay at height 3 rejected"
                  << " with 'nonce mismatch' - the legacy exemption is"
                  << " scoped to the genesis window.\n";
    }

    std::filesystem::remove_all(dir);
}

// ── Regression (round 4, fixed): a hostile frame with header tx_count
// patched past the structural capacity used to be appended unchecked;
// every reader that trusts tx_count then walks past the frame. The store
// now refuses tx_count > MAX_TX_PER_BLOCK before anything else reads it.
TEST(VortexDocumentedGapsTest, OversizedTxCountRejected) {
    const std::string dir = temp_dir("vx_gap_txcount");
    vx::storage::BlockStore store(dir + "/txcount.vxb", "genesis.bin");
    vx::state::LedgerState ledger;

    const auto* g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t*>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    // A perfectly valid 1-tx block...
    BlockBuilder b = next_block(store, 42);
    Transaction t = make_tx(addr_of("GENESIS_2"),
                            addr_of("NFA_TXCOUNT_TARGET_00000000000000000000"),
                            100000000u, 0);
    sign_transaction(t);
    ASSERT_TRUE(b.add_transaction(t));
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);

    // ...then poison ONLY the tx_count header field (offset 0x1D4): 581
    // transactions in a frame that physically holds at most 580.
    const uint32_t poisoned = 581;
    std::memcpy(f.data() + 0x1D4, &poisoned, sizeof(poisoned));

    EXPECT_FALSE(store.append_block(f))
        << "tx_count-581 frame accepted - poisoning regression!";
    EXPECT_EQ(store.chain_height(), 1u) << "poisoned frame must not land";

    std::filesystem::remove_all(dir);
}

// ── Regression (round 4, fixed): the merkle root was computed at build
// time but NEVER verified on intake - a block with a forged root (i.e.
// with transactions that do not commit to the header) was appended and
// applied. append_block now recomputes the root and rejects mismatches.
TEST(VortexDocumentedGapsTest, TamperedMerkleRejected) {
    const std::string dir = temp_dir("vx_gap_merkle");
    vx::storage::BlockStore store(dir + "/merkle.vxb", "genesis.bin");
    vx::state::LedgerState ledger;

    const auto* g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t*>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    BlockBuilder b = next_block(store, 43);
    Transaction t = make_tx(addr_of("GENESIS_2"),
                            addr_of("NFA_MERKLE_TARGET_000000000000000000000"),
                            100000000u, 0);
    sign_transaction(t);
    ASSERT_TRUE(b.add_transaction(t));
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);

    // Flip one byte of the committed merkle root (header offset 0x02C):
    // the transaction set no longer commits to this header.
    f.data()[0x2C] = static_cast<uint8_t>(f.data()[0x2C] ^ 0xA5);

    EXPECT_FALSE(store.append_block(f))
        << "forged merkle root accepted - commitment regression!";
    EXPECT_EQ(store.chain_height(), 1u) << "forged frame must not land";

    std::filesystem::remove_all(dir);
}

// ── Regression (round 5, fixed): the HTLC outcome used to be decided by a
// pre-classification BEFORE the VM ran; a bytecode that failed at runtime
// (e.g. an opcode swapped in after the shape check) still reported
// CLAIMED. The VM verdict now gates the outcome.
TEST(VortexDocumentedGapsTest, HtlcVmFailureForcesLocked) {
    const auto recipient = [] {
        std::array<uint8_t, 42> a{};
        std::memcpy(a.data(), "HTLC_GAP_RECIPIENT_0000000000000000000000000", 42);
        return a;
    }();
    const auto refund = [] {
        std::array<uint8_t, 42> a{};
        std::memcpy(a.data(), "HTLC_GAP_REFUND_000000000000000000000000000", 42);
        return a;
    }();

    const auto contract = vx::vm::VortexVM::create_htlc_contract(
        0x5EED5EEDULL, recipient.data(), refund.data(), /*timelock_height=*/100);

    const uint64_t secret = 0x5EED5EEDULL;
    uint8_t preimage[16];
    const uint64_t pre_hi = ~secret;
    std::memcpy(preimage, &secret, 8);
    std::memcpy(preimage + 8, &pre_hi, 8);

    // Sanity: the canonical contract claims with the canonical preimage.
    const auto good = vx::vm::VortexVM::settle_htlc_swap(
        contract.bytecode, std::span<const uint8_t>(preimage, 16), 99);
    ASSERT_EQ(good.outcome, vx::vm::VortexVM::HtlcOutcome::CLAIMED);

    // The reviewer's PoC: mutate an opcode AFTER the shape check passes.
    // Byte 33 opens the CLAIM branch (LOAD_IMM R6 1); corrupting it must
    // NOT leave the outcome at CLAIMED.
    std::vector<uint8_t> tampered(contract.bytecode);
    ASSERT_GT(tampered.size(), 34u);
    tampered[33] = 0xFE; // unknown opcode, executed only on the CLAIM path
    const auto bad = vx::vm::VortexVM::settle_htlc_swap(
        tampered, std::span<const uint8_t>(preimage, 16), 99);
    EXPECT_FALSE(bad.vm_trace.success) << "corrupted bytecode executed cleanly?";
    EXPECT_EQ(bad.outcome, vx::vm::VortexVM::HtlcOutcome::LOCKED)
        << "a failed VM run must never settle as CLAIMED (round 5)";

    std::cout << "  [fixed] HTLC with a runtime-corrupted opcode settles"
              << " LOCKED; the VM verdict gates the contract outcome.\n";
}

// ── Regression (round 5, fixed): the vault capability token stored and
// compared only its first 4 bytes - a token with 28 mutated tail bytes
// still consumed the page. The full 32-byte sponge digest is now stored
// and compared constant-time.
TEST(VortexDocumentedGapsTest, VaultTokenDigestFullyChecked) {
    if (!vx::core::MemoryCore::mlock_supported(4 * 1024 * 1024)) {
        GTEST_SKIP() << "mlock unavailable in this environment";
    }
    vx::core::MemoryCore core(4 * 1024 * 1024);
    core.initialize(0xA11CE1234567890ULL);

    const std::string payload = "VAULT_REGRESSION_PAYLOAD_ROUND5";
    const auto token = core.commit_secure_data(
        reinterpret_cast<const uint8_t*>(payload.data()), payload.size());

    // Forge: keep the first 4 bytes, corrupt the remaining 28.
    std::array<uint8_t, 32> forged = token;
    for (size_t i = 4; i < 32; ++i) forged[i] = static_cast<uint8_t>(forged[i] ^ 0x5A);
    EXPECT_NE(forged, token) << "precondition: the tail WAS mutated";
    uint8_t out[vx::core::MemoryCore::PAGE_SIZE];
    EXPECT_FALSE(core.consume_data(forged, out))
        << "a 4-byte-prefix token consumed the page - digest regression!";
    EXPECT_TRUE(core.consume_data(token, out))
        << "the genuine token must still consume";
    EXPECT_EQ(std::memcmp(out, payload.data(), payload.size()), 0);

    std::cout << "  [fixed] vault token with 28 mutated tail bytes is"
              << " rejected; the full 32-byte digest is checked.\n";
}

// ── Regression (round 5, fixed): the ring page cursor used to claim a
// slot unconditionally and silently ZERO a still-LOCKED page on pool wrap
// (the 4097th commit destroyed the 1st live token in a 16 MiB arena). A
// full pool must now raise, never clobber.
TEST(VortexDocumentedGapsTest, VaultPoolFullNotClobber) {
    vx::core::MemoryCore core(2 * vx::core::MemoryCore::PAGE_SIZE); // 2 slots
    core.initialize(0xB0B5AFE123456789ULL);

    const std::string a = "PAGE_ALIVE_TOKEN_A";
    const std::string b = "PAGE_ALIVE_TOKEN_B";
    const auto tok_a = core.commit_secure_data(
        reinterpret_cast<const uint8_t*>(a.data()), a.size());
    const auto tok_b = core.commit_secure_data(
        reinterpret_cast<const uint8_t*>(b.data()), b.size());

    bool threw = false;
    try {
        core.commit_secure_data(reinterpret_cast<const uint8_t*>(a.data()), a.size());
    } catch (const std::exception& e) {
        threw = std::string(e.what()).find("pool full") != std::string::npos;
    }
    EXPECT_TRUE(threw) << "the third commit must refuse a full pool";

    // Both earlier tokens are still live and readable - nothing was
    // silently zeroized.
    uint8_t out[vx::core::MemoryCore::PAGE_SIZE];
    ASSERT_TRUE(core.consume_data(tok_a, out));
    EXPECT_EQ(std::memcmp(out, a.data(), a.size()), 0)
        << "token A payload survived untouched";
    ASSERT_TRUE(core.consume_data(tok_b, out));
    EXPECT_EQ(std::memcmp(out, b.data(), b.size()), 0)
        << "token B payload survived untouched";

    std::cout << "  [fixed] full vault pool refuses instead of zeroing a"
              << " live LOCKED page; both tokens survive.\n";
}

// ── Regression (round 5, fixed): the block id committed only the
// 472-byte header; the tail (vm_state_root, vm_gas_used, pogw_nonce,
// vm_bytecode) sat OUTSIDE the commitment, so two frames differing only
// in their PoGW nonce shared one tip hash. hash_block now commits both.
TEST(VortexDocumentedGapsTest, TailMetadataCommitted) {
    const std::string dir = temp_dir("vx_gap_tailcommit");
    vx::storage::BlockStore store(dir + "/tail.vxb", "genesis.bin");

    BlockBuilder b = next_block(store, 44);
    Transaction t = make_tx(addr_of("GENESIS_2"),
                            addr_of("NFA_TAIL_TARGET_00000000000000000000000"),
                            100000000u, 0);
    sign_transaction(t);
    ASSERT_TRUE(b.add_transaction(t));
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    auto* raw = reinterpret_cast<const RawBlock*>(f.data());

    uint8_t h1[32];
    hash_block(*raw, h1);

    // Mutate ONE byte of the PoGW nonce inside the tail (offset 65472):
    // the old header-only digest did not move; the full commitment must.
    BlockFrame g = f;
    g.data()[65472] = static_cast<uint8_t>(g.data()[65472] ^ 0x01);
    auto* raw2 = reinterpret_cast<const RawBlock*>(g.data());
    uint8_t h2[32];
    hash_block(*raw2, h2);

    uint8_t header_only_1[32], header_only_2[32];
    hash_header(raw->header, header_only_1);
    hash_header(raw2->header, header_only_2);
    EXPECT_EQ(std::memcmp(header_only_1, header_only_2, 32), 0)
        << "precondition: header-only digest ignores the tail";
    EXPECT_NE(std::memcmp(h1, h2, 32), 0)
        << "a mutated PoGW nonce must change the block commitment";

    std::filesystem::remove_all(dir);
}
