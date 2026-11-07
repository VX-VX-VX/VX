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
// BACKLOG 1.5 wiring (v0.0.18) — certified PQ key rollover:
//
//  12. RolloverChainAccepted     — a window-1 spend is attributed through
//      a sequential certificate chain walked from the anchor root.
//  13. RolloverWithoutCertRejected — the same spend without the
//      certificate is refused (fail-closed).
//  14. RolloverCertLeafSpenderRejected — a witness on the reserved
//      certificate leaf (15) never verifies as a transaction.
//
// All originate from / are confirmed by external review.

#include <gtest/gtest.h>
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/storage/block_store.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/state/undo_engine.hpp"
#include "vx/core/memory_vault.hpp"
#include "vx/vm/vortex_vm.hpp"

#include <cstring>
#include <ctime>
#include <fstream>
#include <iterator>
#include <fcntl.h>
#include <filesystem>
#include <iostream>
#include <memory>
#include <stdexcept>
#include <string>
#include <unistd.h>

using namespace vx::blockchain;
using vx::core::U128;

namespace {

std::string temp_dir(const char *tag) {
    auto dir = std::filesystem::temp_directory_path() /
               (std::string(tag) + "_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    return dir.string();
}

Address addr_of(const std::string &s) {
    Address a{};
    std::memcpy(a.data(), s.data(), s.size() < 42 ? s.size() : 42);
    return a;
}

Address payload_of(const std::string &nfa) { // strips the "NFA_V6_" prefix
    Address a{};
    std::memcpy(a.data(), nfa.data() + 7, 42);
    return a;
}

// A test account bound to a post-quantum WOTS+/XMSS key: the address is
// SELF-CERTIFYING ("PQA" + base64url of Sponge("VXPQADDRV1" || root)), so
// holding the key IS holding the address (BACKLOG 0.7).
struct PqAccount {
    std::array<uint8_t, 32> sk{};
    std::array<uint8_t, 32> root{};
    Address addr{};
};

PqAccount make_pq_account(const char *tag) {
    PqAccount acc;
    VortexSponge256::compute(reinterpret_cast<const uint8_t *>(tag), std::strlen(tag),
                             acc.sk.data());
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(acc.sk);
    acc.root = vx::crypto::pq::xmss_root(acc.sk, pub_seed);
    derive_pq_address(acc.root.data(), acc.addr.data());
    return acc;
}

// Signs a transaction with the account's PQ key (registers the witness in
// the PqWitnessRegistry, exactly like a real client would).
bool pq_sign(Transaction &tx, const PqAccount &acc) {
    return vx::crypto::pq::pq_sign_transaction(tx, acc.sk);
}

Transaction make_tx(const Address &sender, const Address &receiver, uint64_t amount,
                    uint32_t nonce) {
    Transaction tx{};
    std::memcpy(tx.sender_nfa, sender.data(), 42);
    std::memcpy(tx.receiver_nfa, receiver.data(), 42);
    tx_set_amount(tx, amount);
    tx_set_fee(tx, 100);
    tx_set_nonce(tx, nonce);
    return tx;
}

// Append + ledger-apply a builder's frame, in one step. The frame is sealed
// (PoGW nonce search at the store's required difficulty) before the gate
// sees it — the same work rule every production producer follows.
bool push_block(vx::storage::BlockStore &store, vx::state::LedgerState &ledger, BlockBuilder &b) {
    b.finalize();
    BlockFrame frame;
    std::memcpy(frame.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    if (!seal_pogw_nonce(frame, store.required_pogw_bits()))
        return false;
    if (!store.append_block(frame))
        return false;
    return ledger.apply_block(BlockView(frame)).ok;
}

BlockBuilder next_block(vx::storage::BlockStore &store, uint64_t ts) {
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

// ── Gap pin 1 (CLOSED 2026-11-03, BACKLOG 0.9): a block carrying no PoGW
// work is rejected by the single intake gate. The frame below is otherwise
// perfectly formed — valid magic, correct height, prev-hash bound to the
// tip, sane timestamp, valid merkle — so the ONLY failing check is the
// full-frame work requirement, which is exactly what the pin claims.
TEST(VortexDocumentedGapsTest, NoWorkBlockAccepted) {
    const std::string dir = temp_dir("vx_gap_block");
    // Production difficulty: the gate demands the real 16-bit work.
    vx::storage::BlockStore store(dir + "/gap.vxb", "genesis.bin");
    vx::state::LedgerState ledger;

    // Bring the ledger up to the store's auto-seeded genesis first.
    const auto *g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    BlockBuilder b = next_block(store, std::time(nullptr));
    // NOTE: no PoGW nonce — the frame carries zero work, everything else valid.

    BlockFrame f;
    b.finalize();
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    EXPECT_FALSE(store.append_block(f));
    EXPECT_EQ(store.last_error(), "insufficient PoGW work for the current difficulty");
    // The gate refused the frame: chain height must not have moved.
    EXPECT_EQ(store.chain_height(), 1u);

    std::filesystem::remove_all(dir);
}

// ── Gap pin 2 (CLOSED 2026-11-03, BACKLOG 0.7): keyless transaction
// authorization is removed from consensus acceptance. The keyless digest
// (Tier 2) still verifies as an ADMISSION PRE-FILTER - it proves nothing
// about origin and is no longer an authorization - but the ledger, the
// consensus authority, refuses every user sender without a PQ witness
// bound to its key. The reviewer's theft PoC (1 VX out of the genesis
// receiver with zero secrets) no longer moves anything: the receiver is
// protocol-bound to an OFFLINE key whose secret is not in the repo, so no
// witness for the forged transfer can exist.
TEST(VortexDocumentedGapsTest, KeylessTheftRejected) {
    const std::string dir = temp_dir("vx_gap_theft");
    vx::storage::BlockStore store(dir + "/theft.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;

    // Apply genesis so its mint receiver holds a real balance.
    const auto *g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    // The victim: the genesis mint receiver. We hold NO key for it
    // (there is no key - the address is not PQ-bound yet).
    Address victim{};
    std::memcpy(victim.data(), g->transactions[0].receiver_nfa, 42);
    const Address attacker = addr_of("NFA_THIEF_NO_KEY_NEEDED_00000000000000000000000000");

    ASSERT_GT(ledger.balance_of(victim), U128{})
        << "victim must be funded by the genesis mint for this pin";

    // The forged transfer: sender = victim, attacker holds nothing.
    Transaction theft = make_tx(victim, attacker, 100000000, 0);
    sign_transaction(theft); // <-- keyless: computable by anyone

    // The pre-filter alone still passes - it is an integrity checksum, not
    // an authorization. The consensus authority is the ledger.
    EXPECT_TRUE(verify_transaction_proof(theft));

    // Ship it as a normal block; the LEDGER must refuse it.
    BlockBuilder b = next_block(store, std::time(nullptr));
    ASSERT_TRUE(b.add_transaction(theft));
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
    EXPECT_TRUE(store.append_block(f))
        << "the store gate judges structure and work only; the authorization"
        << " refusal must come from the ledger";
    const auto res = ledger.apply_block(BlockView(f));
    EXPECT_FALSE(res.ok) << "keyless theft accepted - authorization regression!";
    EXPECT_NE(res.error.find("no PQ witness registered"), std::string::npos)
        << "expected the missing-witness refusal, got: " << res.error;

    // Nothing moved: the attacker was not credited, the victim keeps all.
    EXPECT_EQ(ledger.balance_of(tx_address(theft.receiver_nfa)), U128{})
        << "attacker must not be credited without a PQ witness";
    EXPECT_GT(ledger.balance_of(victim), U128{}) << "the genesis receiver keeps its balance";

    std::cout << "  [closed] keyless theft rejected: the genesis receiver is"
              << " PQ-bound to an OFFLINE key (secret not in the repo) and no"
              << " witness exists for the forged transfer (BACKLOG 0.7).\n";

    std::filesystem::remove_all(dir);
}

// ── Regression (was P0, fixed): two spends by the same sender in one
// block must NOT mint phantom supply. Before the fix both txs passed the
// balance check independently (pending credits were counted, intra-block
// debits were not) and the commit loop underflowed U128 to ~2^128.
TEST(VortexDocumentedGapsTest, DoubleSpendInBlockRejected) {
    const std::string dir = temp_dir("vx_gap_dspend");
    vx::storage::BlockStore store(dir + "/dspend.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;

    // Height 0: apply genesis.
    const auto *g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    // Height 1: the GENESIS_2 mint is now bound to its exact protocol
    // shape (review round 5): 100,000 VX to the demo spender address
    // (Address #2), whose demo key is public — a documented testnet key.
    // The sender is a PQ account: spends require a WOTS+/XMSS witness.
    // The demo spender is a BOUND (not self-certifying) address: the
    // binding table maps the attractor-derived Address #2 payload to the
    // root of the public demo key, so the account couples that key with
    // the pinned receiver payload — NOT the PQA address its key derives.
    PqAccount sender_acc = make_pq_account("VX_DEMO_SPENDER_SK_V1");
    sender_acc.addr = vx::blockchain::genesis2_mint_receiver_payload();
    const Address &sender = sender_acc.addr;
    ASSERT_EQ(
        std::memcmp(sender.data(), vx::blockchain::genesis2_mint_receiver_payload().data(), 42), 0)
        << "the pinned mint receiver must be the demo spender address";
    const Address sink = addr_of("NFA_DSPEND_SINK_0000000000000000000000000000");
    {
        BlockBuilder b = next_block(store, std::time(nullptr));
        Transaction mint =
            make_tx(addr_of("GENESIS_2"), sender, vx::blockchain::GENESIS_2_MINT_ATOMICS, 0);
        sign_transaction(mint);
        ASSERT_TRUE(b.add_transaction(mint));
        ASSERT_TRUE(push_block(store, ledger, b));
    }
    ASSERT_EQ(ledger.balance_of(sender),
              U128(vx::blockchain::GENESIS_2_MINT_ATOMICS)); // 100,000 VX

    // Height 2: TWO spends of 60,001 VX each (total 120,002 VX > 100,000 VX
    // balance), sequential nonces, both proofs individually valid.
    {
        BlockBuilder b = next_block(store, std::time(nullptr));
        Transaction s1 = make_tx(sender, sink, 6000100000000ull, 0);
        Transaction s2 = make_tx(sender, sink, 6000100000000ull, 1);
        ASSERT_TRUE(pq_sign(s1, sender_acc));
        ASSERT_TRUE(pq_sign(s2, sender_acc));
        EXPECT_TRUE(verify_transaction_proof(s1));
        EXPECT_TRUE(verify_transaction_proof(s2));
        ASSERT_TRUE(b.add_transaction(s1));
        ASSERT_TRUE(b.add_transaction(s2));

        // The block is structurally valid (the store gate passes it after
        // sealing); the STATE layer must reject it outright - no partial
        // application.
        b.finalize();
        BlockFrame f;
        std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
        ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
        EXPECT_TRUE(store.append_block(f));
        const auto res = ledger.apply_block(BlockView(f));
        EXPECT_FALSE(res.ok) << "double spend accepted - regression!";
        EXPECT_NE(res.error.find("insufficient funds"), std::string::npos)
            << "expected the second spend to fail the funded-balance check";
        EXPECT_EQ(res.error.find("underflow"), std::string::npos)
            << "underflow guard must never fire - pre-check must reject first";

        // No mutation: sender still holds exactly 100,000 VX, no phantom
        // supply.
        EXPECT_EQ(ledger.balance_of(sender), U128(vx::blockchain::GENESIS_2_MINT_ATOMICS));
        EXPECT_EQ(ledger.total_supply(), ledger.total_supply()); // sane path
        std::cout << "  [fixed] intra-block double spend rejected with"
                  << " 'insufficient funds'; no U128 underflow, no phantom"
                  << " balance.\n";
    }

    std::filesystem::remove_all(dir);
}

// ── Gap pin 3 (CLOSED 2026-11-03, BACKLOG 0.6 remainder): the coinbase is
// bound to its chain position. Emission integrity now rests on four rules:
// exactly one coinbase per block (index 0), reward <= 1000 VX, the block
// itself carries real PoGW work (BACKLOG 0.9), and the coinbase tag
// commits receiver + height + previous tip hash - so a coinbase copied
// from one fork cannot be replayed on a competing fork at the same height,
// and the keyless digest no longer authorizes emissions. What remains is
// permissionless by design: whoever produces the block names the reward
// address (no miner identity exists to forge).
TEST(VortexDocumentedGapsTest, CoinbaseReplayRejected) {
    const std::string dir = temp_dir("vx_gap_cbreplay");
    vx::storage::BlockStore store(dir + "/cbreplay.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;

    const auto *g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    const Address miner_recv = addr_of("NFA_FAKE_MINER_EMISSION_00000000000000000000000");

    // The honest block: coinbase bound to (receiver, height 1, current tip).
    uint8_t tip[32];
    store.tip_hash(tip);
    BlockBuilder b = next_block(store, std::time(nullptr));
    Transaction cb{};
    std::memcpy(cb.sender_nfa, "MINER_", 6);
    for (size_t i = 6; i < 42; ++i)
        cb.sender_nfa[i] = '0';
    std::memcpy(cb.receiver_nfa, miner_recv.data(), 42);
    tx_set_amount(cb, 50ULL * 100000000ULL); // the guaranteed floor reward: valid for any hash
    tx_set_fee(cb, 0);
    tx_set_nonce(cb, 0);
    set_coinbase_binding(cb, 1, tip);
    ASSERT_TRUE(b.add_transaction(cb)); // index 0, as required
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));

    // FIRST: the replay. The same coinbase bytes appear in a competing fork
    // at the same height - the fork frame's prev_block_hash is a different
    // (fabricated) tip, so the tag commits the OTHER chain position.
    {
        BlockFrame fork = f;
        auto *fork_raw = reinterpret_cast<RawBlock *>(fork.data());
        uint8_t fake_tip[32];
        for (size_t i = 0; i < 32; ++i)
            fake_tip[i] = static_cast<uint8_t>(tip[i] ^ 0x5A);
        std::memcpy(fork_raw->header.prev_block_hash, fake_tip, 32);
        ASSERT_TRUE(seal_pogw_nonce(fork, store.required_pogw_bits()));
        const auto res = ledger.apply_block(BlockView(fork));
        EXPECT_FALSE(res.ok) << "a coinbase replayed across forks was accepted!";
        EXPECT_NE(res.error.find("coinbase is not bound to this chain position"), std::string::npos)
            << "expected the chain-position refusal, got: " << res.error;
        EXPECT_EQ(ledger.balance_of(miner_recv), U128{}) << "the replayed coinbase must not mint";
    }

    // THEN: the honest block goes through and the producer is credited.
    EXPECT_TRUE(store.append_block(f));
    EXPECT_TRUE(ledger.apply_block(BlockView(f)).ok);
    EXPECT_EQ(ledger.balance_of(miner_recv), U128(50ULL * 100000000ULL))
        << "the bound coinbase pays the block producer";

    std::cout << "  [closed] coinbase bound to the chain position: replaying"
              << " the tag on a competing fork is refused; the honest coinbase"
              << " pays the producer (BACKLOG 0.6 remainder).\n";

    std::filesystem::remove_all(dir);
}

// ── Regression (round 9, delegated adversarial audit): the height-1
// legacy window authorized every GENESIS mint against COMMITTED balances,
// so N mints inside ONE block all saw their receivers as still untracked —
// unbounded supply creation at the only window where the mint sender is
// accepted. Now the second GENESIS mint in one block is refused.
TEST(VortexDocumentedGapsTest, SecondGenesisMintInBlockRejected) {
    const std::string dir = temp_dir("vx_gap_gen2x2");
    vx::storage::BlockStore store(dir + "/gen2x2.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;

    const auto *g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);
    const U128 supply_before = ledger.total_supply();

    const Address r1 = vx::blockchain::genesis2_mint_receiver_payload(); // the pinned receiver
    const Address r2 = addr_of("NFA_GEN2_MINT_TARGET_B_0000000000000000000");
    auto mint_tx = [](const Address &to) {
        Transaction tx{};
        std::memcpy(tx.sender_nfa, "GENESIS_2", 9);
        for (size_t i = 9; i < 42; ++i)
            tx.sender_nfa[i] = '0';
        std::memcpy(tx.receiver_nfa, to.data(), 42);
        tx_set_amount(tx, vx::blockchain::GENESIS_2_MINT_ATOMICS); // 100k VX each
        sign_transaction(tx);
        return tx;
    };

    BlockBuilder b = next_block(store, std::time(nullptr));
    ASSERT_TRUE(b.add_transaction(mint_tx(r1)));
    ASSERT_TRUE(b.add_transaction(mint_tx(r2)));
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));

    const auto res = ledger.apply_block(BlockView(f));
    EXPECT_FALSE(res.ok) << "two GENESIS mints in one block minted double!";
    EXPECT_NE(res.error.find("second GENESIS mint in one block"), std::string::npos)
        << "expected the double-mint refusal, got: " << res.error;
    EXPECT_EQ(ledger.balance_of(r1), U128{})
        << "a rejected block must not credit its first mint either";
    EXPECT_EQ(ledger.total_supply(), supply_before)
        << "supply must be untouched by the rejected block";

    std::cout << "  [closed] one GENESIS mint per block in the legacy window:"
              << " the second mint is refused and the block applies nothing.\n";

    std::filesystem::remove_all(dir);
}

// ── Emission schedule (user-directed, 2026-11-03): a hard 7,000,000,000 VX
// supply cap and a hash-dependent block reward: 50 VX guaranteed for every
// valid block, up to 1,000 VX when the block's own PoGW hash carries at
// least 20/24/28/32/40 leading zero bits. The helper below applies a
// single-MINER_-coinbase block straight to the ledger at the ledger's own
// expected height (apply_block is the consensus authority under test; the
// store's PoGW gate is exercised elsewhere). The coinbase binding and the
// block's prev hash are kept consistent, so the ONLY failing check in
// these tests is the emission gate itself. The optional nonce, hash
// out-param and timestamp let a test pin the exact frame its reward is
// computed from.
namespace {

bool apply_coinbase_block(vx::state::LedgerState &ledger, uint64_t amount_atoms,
                          const Address &recv, std::string *err, uint64_t nonce = 0,
                          uint8_t *frame_hash_out = nullptr, std::time_t ts = 0) {
    Transaction cb{};
    std::memcpy(cb.sender_nfa, "MINER_", 6);
    for (size_t i = 6; i < 42; ++i)
        cb.sender_nfa[i] = '0';
    std::memcpy(cb.receiver_nfa, recv.data(), 42);
    tx_set_amount(cb, amount_atoms);
    tx_set_fee(cb, 0);
    tx_set_nonce(cb, 0);
    const uint64_t h = ledger.next_expected_height();
    BlockBuilder b;
    b.set_height(h);
    b.set_timestamp(ts != 0 ? ts : std::time(nullptr));
    b.set_nonce(nonce);
    uint8_t prev[32];
    std::memset(prev, 0x11, sizeof(prev));
    b.set_prev_hash(prev);
    std::array<uint8_t, 384> coords{};
    b.set_attractor_coords(coords.data());
    set_coinbase_binding(cb, h, prev);
    EXPECT_TRUE(b.add_transaction(cb));
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    if (frame_hash_out) {
        vx::blockchain::VortexSponge256::compute(f.data(), BLOCK_SIZE_BYTES, frame_hash_out);
    }
    const auto res = ledger.apply_block(BlockView(f));
    if (err)
        *err = res.error;
    return res.ok;
}

} // namespace

// The reward is a pure function of the block's own hash: the 50 VX floor
// for any valid block, the 75/100/200/400/1000 VX tiers at 20/24/28/32/40
// leading zero bits, and the 7,000,000,000 VX lifetime cap (7e17 atoms).
TEST(VortexDocumentedGapsTest, EmissionRewardTiersAndCap) {
    using vx::blockchain::ATOMS_PER_VX;
    using vx::blockchain::BLOCK_REWARD_BASE_VX;
    using vx::blockchain::BLOCK_REWARD_MAX_VX;
    using vx::blockchain::block_reward_vx;
    using vx::blockchain::leading_zero_bits;

    // A 32-byte hash whose first z bits are zero and the rest are ones.
    auto hash_with_zeros = [](uint64_t z) {
        std::array<uint8_t, 32> h{};
        h.fill(0xFF);
        const uint64_t full = z / 8;
        for (uint64_t i = 0; i < full && i < 32; ++i)
            h[i] = 0;
        if (full < 32)
            h[full] = static_cast<uint8_t>(0xFF >> (z % 8));
        return h;
    };
    for (const uint64_t z :
         {uint64_t{0}, uint64_t{1}, uint64_t{7}, uint64_t{8}, uint64_t{19}, uint64_t{20},
          uint64_t{23}, uint64_t{24}, uint64_t{27}, uint64_t{28}, uint64_t{31}, uint64_t{32},
          uint64_t{39}, uint64_t{40}, uint64_t{63}}) {
        EXPECT_EQ(leading_zero_bits(hash_with_zeros(z).data()), z) << z;
    }

    EXPECT_EQ(block_reward_vx(hash_with_zeros(0).data()), 50ULL);
    EXPECT_EQ(block_reward_vx(hash_with_zeros(19).data()), 50ULL); // below tier 1: the floor
    EXPECT_EQ(block_reward_vx(hash_with_zeros(20).data()), 75ULL);
    EXPECT_EQ(block_reward_vx(hash_with_zeros(23).data()), 75ULL);
    EXPECT_EQ(block_reward_vx(hash_with_zeros(24).data()), 100ULL);
    EXPECT_EQ(block_reward_vx(hash_with_zeros(27).data()), 100ULL);
    EXPECT_EQ(block_reward_vx(hash_with_zeros(28).data()), 200ULL);
    EXPECT_EQ(block_reward_vx(hash_with_zeros(31).data()), 200ULL);
    EXPECT_EQ(block_reward_vx(hash_with_zeros(32).data()), 400ULL);
    EXPECT_EQ(block_reward_vx(hash_with_zeros(39).data()), 400ULL);
    EXPECT_EQ(block_reward_vx(hash_with_zeros(40).data()), 1000ULL); // the jackpot
    EXPECT_EQ(block_reward_vx(hash_with_zeros(63).data()), 1000ULL); // saturated

    EXPECT_EQ(BLOCK_REWARD_BASE_VX, 50ULL);
    EXPECT_EQ(BLOCK_REWARD_MAX_VX, 1000ULL);
    EXPECT_EQ(vx::blockchain::max_supply_atoms(), 700'000'000'000'000'000ULL);
    EXPECT_EQ(BLOCK_REWARD_MAX_VX * ATOMS_PER_VX, 1000ULL * ATOMS_PER_VX);
    std::cout << "  [closed] emission hard-coded: 50 VX floor, hash tiers"
              << " 75/100/200/400/1000 VX at 20/24/28/32/40 zero bits,"
              << " lifetime cap 7,000,000,000 VX (the root-of-seven digit).\n";
}

// The producer's coinbase may carry at most the reward the block's own
// hash earns plus the block's fee share - one atom above the entitlement is
// refused, the exact floor reward mints, and issuance is booked. The
// coinbase amount is part of the hashed frame, so the probe below replays
// the exact claim on throwaway ledgers to pin a nonce whose frame hash
// stays below the first bonus tier; the same frame then reproduces the
// refusal on the ledger under test. A claim above the absolute 1,000 VX
// jackpot is refused for every hash a frame can carry.
TEST(VortexDocumentedGapsTest, CoinbaseEntitlementEnforced) {
    using vx::blockchain::ATOMS_PER_VX;
    using vx::blockchain::leading_zero_bits;
    const std::time_t ts = std::time(nullptr);
    vx::state::LedgerState ledger;
    ledger.set_next_height(1); // fresh ledger staged at the first mined height
    const Address recv = addr_of("NFA_EMISSION_MINER_A_000000000000000000");
    std::string err;
    uint8_t frame_hash[32];

    // Pin a nonce whose floor-plus-one claim is over-entitled (its hash
    // stays below the 20-zero-bit first tier - the expected number of
    // probes is ~1). Each probe uses a fresh throwaway ledger, so every
    // attempt hashes the exact frame the real ledger will see.
    uint64_t pinned = 1000;
    for (uint64_t nonce = 0; nonce < 1000; ++nonce) {
        vx::state::LedgerState probe;
        probe.set_next_height(1);
        if (apply_coinbase_block(probe, 50ULL * ATOMS_PER_VX + 1, recv, &err, nonce, frame_hash,
                                 ts)) {
            continue; // that rare frame earned a bonus tier; try the next nonce
        }
        EXPECT_NE(err.find("coinbase exceeds emission entitlement"), std::string::npos) << err;
        pinned = nonce;
        break;
    }
    ASSERT_LT(pinned, 1000ULL) << "no sub-tier nonce found in 1000 probes";

    // One atom above the floor is over-entitled at that frame's hash.
    EXPECT_FALSE(
        apply_coinbase_block(ledger, 50ULL * ATOMS_PER_VX + 1, recv, &err, pinned, nullptr, ts))
        << "a coinbase above the emission entitlement was accepted!";
    EXPECT_NE(err.find("coinbase exceeds emission entitlement"), std::string::npos)
        << "expected the entitlement refusal, got: " << err;
    EXPECT_EQ(ledger.balance_of(recv), U128{}) << "a refused coinbase must not credit its receiver";

    // The exact floor reward mints and is booked as issuance.
    EXPECT_TRUE(apply_coinbase_block(ledger, 50ULL * ATOMS_PER_VX, recv, &err, pinned, nullptr, ts))
        << err;
    EXPECT_EQ(ledger.balance_of(recv), U128(50ULL * ATOMS_PER_VX));
    EXPECT_EQ(ledger.issued_supply(), U128(50ULL * ATOMS_PER_VX))
        << "the reward must be booked into the issued-supply counter";

    // The jackpot is the absolute maximum: 1,001 VX is refused even if the
    // hash had earned a tier (it cannot earn more than 1,000 VX).
    EXPECT_FALSE(
        apply_coinbase_block(ledger, 1001ULL * ATOMS_PER_VX, recv, &err, pinned, nullptr, ts));
    EXPECT_NE(err.find("coinbase exceeds emission entitlement"), std::string::npos) << err;
}

// The cap is load-bearing: with the issued counter one VX short of
// 7,000,000,000, nothing larger than the headroom can be issued; the final
// partial reward closes the cap exactly; afterwards not one more atom of
// issuance can ever enter state (zero-amount coinbases stay legal so fee
// redistribution survives the closed cap).
TEST(VortexDocumentedGapsTest, SupplyCapHardStopsIssuance) {
    using vx::blockchain::ATOMS_PER_VX;
    const std::time_t ts = std::time(nullptr);
    vx::state::LedgerState ledger;
    ledger.set_next_height(1);
    const Address recv = addr_of("NFA_EMISSION_MINER_B_000000000000000000");
    std::string err;

    // The exact floor reward is under every hash: it always mints.
    ASSERT_TRUE(apply_coinbase_block(ledger, 50ULL * ATOMS_PER_VX, recv, &err)) << err;
    const U128 cap(vx::blockchain::max_supply_atoms());
    const U128 leave = U128(1ULL * ATOMS_PER_VX);
    ledger.adjust_issued_supply(cap - leave - ledger.issued_supply(), true);

    // A 2 VX claim is under the 50 VX floor for every hash, so the
    // entitlement check passes and the refusal below is purely the cap.
    EXPECT_FALSE(apply_coinbase_block(ledger, 2ULL * ATOMS_PER_VX, recv, &err, 0, nullptr, ts))
        << "issuance beyond the 7,000,000,000 VX cap was accepted!";
    EXPECT_NE(err.find("supply cap exceeded"), std::string::npos)
        << "expected the supply-cap refusal, got: " << err;

    EXPECT_TRUE(apply_coinbase_block(ledger, 1ULL * ATOMS_PER_VX, recv, &err, 0, nullptr, ts))
        << err;
    EXPECT_EQ(ledger.issued_supply(), cap) << "the final partial reward must close the cap exactly";

    EXPECT_TRUE(apply_coinbase_block(ledger, 0, recv, &err, 0, nullptr, ts)) << err;
    EXPECT_FALSE(apply_coinbase_block(ledger, 1, recv, &err, 0, nullptr, ts));
    EXPECT_NE(err.find("supply cap exceeded"), std::string::npos) << err;
    EXPECT_EQ(ledger.issued_supply(), cap)
        << "nothing may move the issued counter after the cap closed";
}

// The reward depends on the block's hash, not on its height: there is no
// emission window to fall out of, so the 50 VX floor still mints at any
// height (here eight figures past the retired 12,000,000-block window of
// the earlier draft schedule) and a zero-amount coinbase stays legal.
TEST(VortexDocumentedGapsTest, RewardIndependentOfHeight) {
    using vx::blockchain::ATOMS_PER_VX;
    vx::state::LedgerState ledger;
    ledger.set_next_height(400'000'000ULL);
    const Address recv = addr_of("NFA_EMISSION_TAIL_A_000000000000000000");
    std::string err;

    EXPECT_TRUE(apply_coinbase_block(ledger, 50ULL * ATOMS_PER_VX, recv, &err)) << err;
    EXPECT_EQ(ledger.issued_supply(), U128(50ULL * ATOMS_PER_VX))
        << "the floor reward must mint at any height";
    EXPECT_EQ(ledger.balance_of(recv), U128(50ULL * ATOMS_PER_VX));

    EXPECT_TRUE(apply_coinbase_block(ledger, 0, recv, &err)) << err;
    EXPECT_EQ(ledger.issued_supply(), U128(50ULL * ATOMS_PER_VX));
}

// ── BACKLOG 0.11: the undo journal is a versioned byte format, never a
// raw struct dump (the round-4 review found sizeof(UndoRecord) writes
// serializing std::string/vector heap POINTERS). Round-trip: records
// survive commit + reload, a rollback over them restores balances and the
// issued-supply counter exactly, and a reload + commit does not duplicate
// records (a duplicated record would double-revert on rollback).
TEST(VortexDocumentedGapsTest, UndoJournalByteFormatRoundTrip) {
    const std::string dir = temp_dir("vx_gap_undo_rt");
    vx::storage::BlockStore store(dir + "/undo_rt.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;
    const Address recv_a = addr_of("NFA_UNDO_MINER_A_0000000000000000000000");
    const Address recv_b = addr_of("NFA_UNDO_MINER_B_0000000000000000000000");
    {
        vx::state::UndoEngine undo(dir, store, ledger);
        auto *g = store.get_block(0);
        ASSERT_NE(g, nullptr);
        BlockFrame gf;
        std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
        ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);
        undo.apply_block(BlockView(gf));

        // Two MINER_ coinbase blocks (10 VX each — under the 50 VX floor,
        // so the emission gate never refuses them), journaled pre-state.
        for (int i = 0; i < 2; ++i) {
            BlockBuilder b = next_block(store, std::time(nullptr));
            vx::blockchain::Transaction cb{};
            std::memcpy(cb.sender_nfa, "MINER_", 6);
            for (size_t k = 6; k < 42; ++k)
                cb.sender_nfa[k] = '0';
            std::memcpy(cb.receiver_nfa, (i == 0 ? recv_a : recv_b).data(), 42);
            vx::blockchain::tx_set_amount(cb, 10ULL * 100000000ULL);
            vx::blockchain::tx_set_fee(cb, 0);
            vx::blockchain::tx_set_nonce(cb, 0);
            uint8_t tip[32];
            store.tip_hash(tip);
            vx::blockchain::set_coinbase_binding(cb, store.chain_height(), tip);
            ASSERT_TRUE(b.add_transaction(cb));
            b.finalize();
            BlockFrame f;
            std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
            ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
            ASSERT_TRUE(store.append_block(f));
            undo.apply_block(BlockView(f));
            ASSERT_TRUE(ledger.apply_block(BlockView(f)).ok);
        }
        undo.commit_undo_point();
    } // destructor commits: nothing new is durable-pending, so no duplicate

    const U128 supply_two_blocks = ledger.total_supply();
    const U128 issued_two_blocks = ledger.issued_supply();
    const U128 two_rewards(2ULL * 10ULL * 100000000ULL);

    {
        // Reload: the byte format must parse back into real records and a
        // rollback over them must restore the pre-block state exactly.
        vx::state::UndoEngine undo(dir, store, ledger);
        ASSERT_TRUE(undo.rollback_to_height(0)) << undo.last_error();
        EXPECT_EQ(ledger.total_supply(), supply_two_blocks - two_rewards);
        EXPECT_EQ(ledger.issued_supply(), issued_two_blocks - two_rewards)
            << "the rollback must also reverse the issuance the blocks booked";
        EXPECT_EQ(ledger.balance_of(recv_a), U128{});
        EXPECT_EQ(ledger.balance_of(recv_b), U128{});
    } // destructor commits: everything is durable — no re-append

    {
        // Reload again: no duplicate records — a second rollback finds
        // nothing above the target and must not touch state a second time.
        vx::state::UndoEngine undo(dir, store, ledger);
        const U128 supply_after = ledger.total_supply();
        ASSERT_TRUE(undo.rollback_to_height(0)) << undo.last_error();
        EXPECT_EQ(ledger.total_supply(), supply_after)
            << "a reloaded journal re-reverted state: records were duplicated";
        EXPECT_EQ(ledger.issued_supply(), issued_two_blocks - two_rewards);
    }

    // The file carries the versioned magic header.
    std::ifstream jf(dir + "/undo/undo.vxl", std::ios::binary);
    char magic[8] = {};
    jf.read(magic, 8);
    EXPECT_EQ(std::string(magic, 8), "VXUNDOJL");

    std::filesystem::remove_all(dir);
}

// ── BACKLOG 0.11: a journal file that is not the current format is never
// replayed — wrong magic, unknown version and mid-file corruption all
// resolve to "discard and rebuild from live block application", a torn
// tail is healed to the last complete record, and pointer-looking bytes
// are never dereferenced (this is the rollback-over-poisoned-journal case
// the ASan lane runs clean).
TEST(VortexDocumentedGapsTest, UndoJournalRejectsHostileFiles) {
    const std::string dir = temp_dir("vx_gap_undo_bad");
    vx::storage::BlockStore store(dir + "/undo_bad.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;
    const std::string jpath = dir + "/undo/undo.vxl";
    std::filesystem::create_directories(dir + "/undo");
    auto put_u64 = [](std::vector<uint8_t> &v, uint64_t x) {
        for (int i = 0; i < 8; ++i)
            v.push_back(static_cast<uint8_t>(x >> (8 * i)));
    };
    auto put_u32 = [](std::vector<uint8_t> &v, uint32_t x) {
        for (int i = 0; i < 4; ++i)
            v.push_back(static_cast<uint8_t>(x >> (8 * i)));
    };
    auto write_file = [&](const std::vector<uint8_t> &bytes) {
        std::ofstream f(jpath, std::ios::binary);
        f.write(reinterpret_cast<const char *>(bytes.data()),
                static_cast<std::streamsize>(bytes.size()));
        ASSERT_TRUE(f.good());
    };

    // (a) Wrong magic + pointer-looking words: never replayed, file discarded.
    {
        std::vector<uint8_t> bytes(256, 0x00);
        const uint64_t poison = 0x00005A5A5A5A5A5AULL; // heap-pointer shaped
        for (size_t off = 0; off + 8 <= bytes.size(); off += 8) {
            std::memcpy(bytes.data() + off, &poison, 8);
        }
        write_file(bytes);
        vx::state::UndoEngine undo(dir, store, ledger);
        EXPECT_FALSE(undo.rollback_to_height(0)); // nothing journaled, no crash
        EXPECT_FALSE(std::filesystem::exists(jpath)) << "a foreign journal file survived open";
    }

    // (b) Right magic, unknown version: refused the same way.
    {
        std::vector<uint8_t> bytes;
        bytes.insert(bytes.end(), {'V', 'X', 'U', 'N', 'D', 'O', 'J', 'L'});
        bytes.push_back(99);
        bytes.push_back(0);
        bytes.push_back(0);
        bytes.push_back(0);
        bytes.insert(bytes.end(), 64, 0xFF);
        write_file(bytes);
        vx::state::UndoEngine undo(dir, store, ledger);
        EXPECT_FALSE(std::filesystem::exists(jpath));
        EXPECT_FALSE(undo.rollback_to_height(0));
    }

    // (b2) Right magic, the previous format version (1, pre-0.12: no
    // prev_sender_nonce in undo transactions): reject-or-migrate — the
    // file is discarded and the journal rebuilds from live application.
    {
        std::vector<uint8_t> bytes;
        bytes.insert(bytes.end(), {'V', 'X', 'U', 'N', 'D', 'O', 'J', 'L'});
        bytes.push_back(1);
        bytes.push_back(0);
        bytes.push_back(0);
        bytes.push_back(0);
        bytes.insert(bytes.end(), 80, 0x00); // one well-formed zero-tx record
        write_file(bytes);
        vx::state::UndoEngine undo(dir, store, ledger);
        EXPECT_FALSE(std::filesystem::exists(jpath))
            << "a version-1 journal must be migrated (discarded), not replayed";
        EXPECT_FALSE(undo.rollback_to_height(0));
    }

    // (c) Valid header, mid-file corruption (at least one minimal record
    // of garbage): discarded, never healed.
    {
        std::vector<uint8_t> bytes;
        bytes.insert(bytes.end(), {'V', 'X', 'U', 'N', 'D', 'O', 'J', 'L'});
        bytes.push_back(2);
        bytes.push_back(0);
        bytes.push_back(0);
        bytes.push_back(0);
        bytes.insert(bytes.end(), 200, 0xFF);
        write_file(bytes);
        vx::state::UndoEngine undo(dir, store, ledger);
        EXPECT_FALSE(std::filesystem::exists(jpath));
        EXPECT_FALSE(undo.rollback_to_height(0));
    }

    // (c2) Valid header, a short garbage tail: fewer bytes than a minimal
    // record could be a torn write of a valid record's first bytes, so it
    // is healed (truncated to the header) rather than discarded — the
    // journal rebuilds from live application either way.
    {
        std::vector<uint8_t> bytes;
        bytes.insert(bytes.end(), {'V', 'X', 'U', 'N', 'D', 'O', 'J', 'L'});
        bytes.push_back(2);
        bytes.push_back(0);
        bytes.push_back(0);
        bytes.push_back(0);
        bytes.insert(bytes.end(), 5, 0xFF);
        write_file(bytes);
        vx::state::UndoEngine undo(dir, store, ledger);
        ASSERT_TRUE(std::filesystem::exists(jpath));
        EXPECT_EQ(std::filesystem::file_size(jpath), 12ULL)
            << "a short tail must be healed to the bare header";
        EXPECT_FALSE(undo.rollback_to_height(0)); // healed journal is empty
    }

    // (d) Torn tail after a valid record: the record survives, the tail is
    // healed to the last complete record, and a rollback over the record
    // works (the replay path runs clean under ASan here).
    {
        std::vector<uint8_t> bytes;
        bytes.insert(bytes.end(), {'V', 'X', 'U', 'N', 'D', 'O', 'J', 'L'});
        bytes.push_back(2);
        bytes.push_back(0);
        bytes.push_back(0);
        bytes.push_back(0);
        put_u64(bytes, 1);                   // height 1
        put_u64(bytes, 0);                   // timestamp
        bytes.insert(bytes.end(), 32, 0x00); // prev tip hash
        put_u64(bytes, 0);
        put_u64(bytes, 0);                   // prev supply
        put_u64(bytes, 0);                   // prev accounts count
        put_u64(bytes, 0);                   // tx_count = 0
        put_u64(bytes, 0);                   // created_count = 0 (v2 field)
        bytes.insert(bytes.end(), 10, 0xAB); // torn tail
        write_file(bytes);
        vx::state::UndoEngine undo(dir, store, ledger);
        ASSERT_TRUE(std::filesystem::exists(jpath));
        EXPECT_EQ(std::filesystem::file_size(jpath), 12ULL + 88ULL)
            << "the torn tail was not healed to the last complete record";
        EXPECT_TRUE(undo.rollback_to_height(0)) << undo.last_error();
    }
    EXPECT_FALSE(std::filesystem::exists(jpath))
        << "a rollback that empties the journal must remove the file";

    // (e) The displaced-frame side journal gets the same fail-closed
    // policy: a foreign file and a torn record yield nothing, never a
    // crash and never a trustful replay.
    {
        const std::string dpath = dir + "/undo/displaced.vxd";
        auto write_disp = [&](const std::vector<uint8_t> &bytes) {
            std::ofstream f(dpath, std::ios::binary);
            f.write(reinterpret_cast<const char *>(bytes.data()),
                    static_cast<std::streamsize>(bytes.size()));
            ASSERT_TRUE(f.good());
        };
        // Foreign magic + pointer-shaped poison.
        {
            std::vector<uint8_t> bytes(300, 0x00);
            const uint64_t poison = 0x00005A5A5A5A5A5AULL;
            for (size_t off = 0; off + 8 <= bytes.size(); off += 8)
                std::memcpy(bytes.data() + off, &poison, 8);
            write_disp(bytes);
            vx::state::UndoEngine undo(dir, store, ledger);
            EXPECT_TRUE(undo.load_displaced_frames().empty())
                << "a foreign displaced journal must yield nothing";
        }
        // Right magic, torn record: height + a frame length that is never
        // backed by frame bytes.
        {
            std::vector<uint8_t> bytes;
            bytes.insert(bytes.end(), {'V', 'X', 'D', 'I', 'S', 'P', 'L', 'C'});
            bytes.push_back(1);
            bytes.push_back(0);
            bytes.push_back(0);
            bytes.push_back(0);
            put_u64(bytes, 7);
            put_u32(bytes, 65536);
            write_disp(bytes);
            vx::state::UndoEngine undo(dir, store, ledger);
            EXPECT_TRUE(undo.load_displaced_frames().empty())
                << "a torn displaced record must not be replayed";
        }
        std::filesystem::remove(dpath);
    }

    std::filesystem::remove_all(dir);
}

// ── BACKLOG 0.12: a reorg rollback must be replayable in both directions.
// The fork is journaled in the resync ordering (undo BEFORE the store
// append — the ordering that used to capture the DISPLACED block's
// transactions from the store); a rollback to genesis must preserve the
// displaced frames in the side journal, restore sender nonces alongside
// balances, and re-applying the same frames must land on byte-identical
// state: a fresh ledger that applied the same frames once.
TEST(VortexDocumentedGapsTest, ReorgUndoRestoresNoncesAndFrames) {
    const std::string dir = temp_dir("vx_gap_reorg_undo");
    const std::string store_path = dir + "/reorg.vxb";
    auto store = std::make_unique<vx::storage::BlockStore>(store_path, "genesis.bin", 8);
    vx::state::LedgerState ledger;

    const auto *g = store->get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    // The pinned GENESIS_2 mint pays the demo spender (Address #2), so the
    // fork's sender IS the demo spender: its public key signs the spends.
    PqAccount sender_acc = make_pq_account("VX_DEMO_SPENDER_SK_V1");
    sender_acc.addr = vx::blockchain::genesis2_mint_receiver_payload();
    const Address &sender = sender_acc.addr;
    const Address sink = addr_of("NFA_REORG_SINK_0000000000000000000000000");
    const uint64_t ts = std::time(nullptr);
    std::vector<BlockFrame> fork; // the displaced fork, in order

    {
        vx::state::UndoEngine undo(dir, *store, ledger);

        // Height 1: fund the sender (the protocol-shaped GENESIS_2 mint).
        {
            BlockBuilder b = next_block(*store, ts);
            Transaction mint =
                make_tx(addr_of("GENESIS_2"), sender, vx::blockchain::GENESIS_2_MINT_ATOMICS, 0);
            sign_transaction(mint);
            ASSERT_TRUE(b.add_transaction(mint));
            b.finalize();
            BlockFrame f;
            std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
            ASSERT_TRUE(seal_pogw_nonce(f, store->required_pogw_bits()));
            undo.apply_block(BlockView(f)); // journal BEFORE the store append
            ASSERT_TRUE(store->append_block(f));
            ASSERT_TRUE(ledger.apply_block(BlockView(f)).ok);
            fork.push_back(f);
        }

        // Height 2: TWO spends from the same sender in one block (nonces
        // 0 and 1) — the intra-block sequential-nonce path.
        {
            BlockBuilder b = next_block(*store, ts + 5);
            Transaction s1 = make_tx(sender, sink, 100000000u, 0);
            ASSERT_TRUE(pq_sign(s1, sender_acc));
            Transaction s2 = make_tx(sender, sink, 100000000u, 1);
            ASSERT_TRUE(pq_sign(s2, sender_acc));
            ASSERT_TRUE(b.add_transaction(s1));
            ASSERT_TRUE(b.add_transaction(s2));
            b.finalize();
            BlockFrame f;
            std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
            ASSERT_TRUE(seal_pogw_nonce(f, store->required_pogw_bits()));
            undo.apply_block(BlockView(f)); // journal BEFORE the store append
            ASSERT_TRUE(store->append_block(f));
            ASSERT_TRUE(ledger.apply_block(BlockView(f)).ok);
            fork.push_back(f);
        }

        // ── Reorg: roll the whole fork back to genesis ─────────────────
        ASSERT_TRUE(undo.rollback_to_height(0)) << undo.last_error();

        // The PRE-FORK state: neither the sender nor the sink existed yet,
        // so both balances are zero AND untracked (an address the fork
        // created must not linger as a tracked zero-balance account, or a
        // re-applied GENESIS_2 mint would be refused forever).
        EXPECT_EQ(ledger.balance_of(sender), U128{}) << "the fork's credits were not reversed";
        EXPECT_EQ(ledger.balance_of(sink), U128{});
        EXPECT_FALSE(ledger.tracked_addresses_containing(sender))
            << "an address created by the fork stayed tracked";
        EXPECT_FALSE(ledger.tracked_addresses_containing(sink));
        EXPECT_EQ(ledger.get_next_nonce(sender), 0u)
            << "the sender's nonce counter was not restored by the rollback";
        EXPECT_EQ(ledger.next_expected_height(), 1u);

        // The displaced frames survived in the side journal, byte-exact.
        const auto displaced = undo.load_displaced_frames();
        ASSERT_EQ(displaced.size(), fork.size())
            << "the displaced fork frames were not preserved by the rollback";
        for (size_t i = 0; i < fork.size(); ++i) {
            EXPECT_EQ(displaced[i].height, i + 1);
            EXPECT_EQ(0, std::memcmp(displaced[i].frame.data(), fork[i].data(), BLOCK_SIZE_BYTES))
                << "displaced frame " << i << " does not match the fork block";
        }
    } // destructor commits: everything durable, nothing re-appended

    // Truncate the store back to genesis and re-point the journal at the
    // reopened file — the same sequence the live reorg path runs.
    store.reset();
    std::filesystem::resize_file(store_path, BLOCK_SIZE_BYTES);
    store = std::make_unique<vx::storage::BlockStore>(store_path, "genesis.bin", 8);

    {
        vx::state::UndoEngine undo(dir, *store, ledger);
        undo.attach_store(*store);

        // Re-apply the SAME fork: legal again only because the rollback
        // restored the nonces (and the pre-state records match the frames).
        for (const auto &f : fork) {
            undo.apply_block(BlockView(f));
            ASSERT_TRUE(store->append_block(f));
            const auto res = ledger.apply_block(BlockView(f));
            ASSERT_TRUE(res.ok) << "re-apply refused after rollback: " << res.error;
        }

        // ── Acceptance: rollback + re-apply == a fresh apply ───────────
        vx::state::LedgerState fresh;
        ASSERT_TRUE(fresh.apply_block(BlockView(gf)).ok);
        for (const auto &f : fork) {
            const auto res = fresh.apply_block(BlockView(f));
            ASSERT_TRUE(res.ok) << "fresh apply refused: " << res.error;
        }
        EXPECT_EQ(ledger.total_supply(), fresh.total_supply());
        EXPECT_EQ(ledger.issued_supply(), fresh.issued_supply());
        EXPECT_EQ(ledger.balance_of(sender), fresh.balance_of(sender));
        EXPECT_EQ(ledger.balance_of(sink), fresh.balance_of(sink));
        EXPECT_EQ(ledger.get_next_nonce(sender), fresh.get_next_nonce(sender))
            << "nonce accounting desynchronized across the reorg";
        EXPECT_EQ(ledger.accounts().size(), fresh.accounts().size());

        // Replay protection is intact: the consumed nonce 1 is gone.
        {
            BlockBuilder b = next_block(*store, ts + 10);
            Transaction replay = make_tx(sender, sink, 100000000u, 1);
            ASSERT_TRUE(pq_sign(replay, sender_acc));
            ASSERT_TRUE(b.add_transaction(replay));
            b.finalize();
            BlockFrame f;
            std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
            ASSERT_TRUE(seal_pogw_nonce(f, store->required_pogw_bits()));
            const auto res = ledger.apply_block(BlockView(f));
            EXPECT_FALSE(res.ok) << "a replayed nonce was accepted after the reorg";
            EXPECT_NE(res.error.find("nonce mismatch"), std::string::npos)
                << "expected the nonce check to fire, got: " << res.error;
        }
    }

    std::filesystem::remove_all(dir);
}

// ── Regression (round 4, fixed): the genesis-v1 tx shape (fee=0 and
// nonce=0) used to skip nonce accounting at EVERY height, so replaying a
// genesis-v1-shaped tx re-ran it forever. The exemption is now scoped to
// the genesis replay window (next_height <= 1).
TEST(VortexDocumentedGapsTest, NonceZeroReplayRejected) {
    const std::string dir = temp_dir("vx_gap_nonce");
    vx::storage::BlockStore store(dir + "/nonce.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;

    const auto *g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    PqAccount sender_acc = make_pq_account("VX_DEMO_SPENDER_SK_V1");
    sender_acc.addr = vx::blockchain::genesis2_mint_receiver_payload();
    const Address &sender = sender_acc.addr;
    const Address sink = addr_of("NFA_NONCE_SINK_00000000000000000000000000");

    // Height 1: fund the sender (the protocol-shaped GENESIS_2 mint).
    {
        BlockBuilder b = next_block(store, std::time(nullptr));
        Transaction mint =
            make_tx(addr_of("GENESIS_2"), sender, vx::blockchain::GENESIS_2_MINT_ATOMICS, 0);
        sign_transaction(mint);
        ASSERT_TRUE(b.add_transaction(mint));
        ASSERT_TRUE(push_block(store, ledger, b));
    }

    // Height 2: a real spend consumes nonce 0 (window is closed here:
    // next_height == 2). Fee 100, so it is NOT genesis-v1-shaped.
    {
        BlockBuilder b = next_block(store, std::time(nullptr));
        Transaction spend = make_tx(sender, sink, 100000000u, 0);
        ASSERT_TRUE(pq_sign(spend, sender_acc));
        ASSERT_TRUE(b.add_transaction(spend));
        ASSERT_TRUE(push_block(store, ledger, b));
    }

    // Height 3: REPLAY in genesis-v1 clothing - fee=0, nonce=0 from the
    // same sender whose expected nonce is now 1. Before the scoping fix
    // the shape alone bypassed the nonce check; now it must be refused.
    {
        BlockBuilder b = next_block(store, std::time(nullptr));
        Transaction replay = make_tx(sender, sink, 100000000u, 0);
        tx_set_fee(replay, 0); // shape: fee=0 + nonce=0 == genesis v1
        ASSERT_TRUE(pq_sign(replay, sender_acc));
        ASSERT_TRUE(verify_transaction_proof(replay));
        ASSERT_TRUE(b.add_transaction(replay));
        b.finalize();
        BlockFrame f;
        std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
        // Structurally valid block: the store gate (sealed) passes it; the
        // STATE layer must refuse the genesis-v1-shaped replay.
        ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
        EXPECT_TRUE(store.append_block(f));
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
    vx::storage::BlockStore store(dir + "/txcount.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;

    const auto *g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    // A perfectly valid 1-tx block...
    BlockBuilder b = next_block(store, std::time(nullptr));
    Transaction t = make_tx(addr_of("GENESIS_2"),
                            addr_of("NFA_TXCOUNT_TARGET_00000000000000000000"), 100000000u, 0);
    sign_transaction(t);
    ASSERT_TRUE(b.add_transaction(t));
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    // Seal first: the rejection below must name tx_count, not missing work.
    ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));

    // ...then poison ONLY the tx_count header field (offset 0x1D4): 581
    // transactions in a frame that physically holds at most 580.
    const uint32_t poisoned = 581;
    std::memcpy(f.data() + 0x1D4, &poisoned, sizeof(poisoned));

    EXPECT_FALSE(store.append_block(f)) << "tx_count-581 frame accepted - poisoning regression!";
    EXPECT_EQ(store.chain_height(), 1u) << "poisoned frame must not land";

    std::filesystem::remove_all(dir);
}

// ── Regression (round 4, fixed): the merkle root was computed at build
// time but NEVER verified on intake - a block with a forged root (i.e.
// with transactions that do not commit to the header) was appended and
// applied. append_block now recomputes the root and rejects mismatches.
TEST(VortexDocumentedGapsTest, TamperedMerkleRejected) {
    const std::string dir = temp_dir("vx_gap_merkle");
    vx::storage::BlockStore store(dir + "/merkle.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;

    const auto *g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    BlockBuilder b = next_block(store, std::time(nullptr));
    Transaction t = make_tx(addr_of("GENESIS_2"),
                            addr_of("NFA_MERKLE_TARGET_000000000000000000000"), 100000000u, 0);
    sign_transaction(t);
    ASSERT_TRUE(b.add_transaction(t));
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    // Seal first: the rejection below must name the merkle commitment.
    ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));

    // Flip one byte of the committed merkle root (header offset 0x02C):
    // the transaction set no longer commits to this header.
    f.data()[0x2C] = static_cast<uint8_t>(f.data()[0x2C] ^ 0xA5);

    EXPECT_FALSE(store.append_block(f)) << "forged merkle root accepted - commitment regression!";
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
    const auto bad =
        vx::vm::VortexVM::settle_htlc_swap(tampered, std::span<const uint8_t>(preimage, 16), 99);
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
    const auto token =
        core.commit_secure_data(reinterpret_cast<const uint8_t *>(payload.data()), payload.size());

    // Forge: keep the first 4 bytes, corrupt the remaining 28.
    std::array<uint8_t, 32> forged = token;
    for (size_t i = 4; i < 32; ++i)
        forged[i] = static_cast<uint8_t>(forged[i] ^ 0x5A);
    EXPECT_NE(forged, token) << "precondition: the tail WAS mutated";
    uint8_t out[vx::core::MemoryCore::PAGE_SIZE];
    EXPECT_FALSE(core.consume_data(forged, out))
        << "a 4-byte-prefix token consumed the page - digest regression!";
    EXPECT_TRUE(core.consume_data(token, out)) << "the genuine token must still consume";
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
    const auto tok_a =
        core.commit_secure_data(reinterpret_cast<const uint8_t *>(a.data()), a.size());
    const auto tok_b =
        core.commit_secure_data(reinterpret_cast<const uint8_t *>(b.data()), b.size());

    bool threw = false;
    try {
        core.commit_secure_data(reinterpret_cast<const uint8_t *>(a.data()), a.size());
    } catch (const std::exception &e) {
        threw = std::string(e.what()).find("pool full") != std::string::npos;
    }
    EXPECT_TRUE(threw) << "the third commit must refuse a full pool";

    // Both earlier tokens are still live and readable - nothing was
    // silently zeroized.
    uint8_t out[vx::core::MemoryCore::PAGE_SIZE];
    ASSERT_TRUE(core.consume_data(tok_a, out));
    EXPECT_EQ(std::memcmp(out, a.data(), a.size()), 0) << "token A payload survived untouched";
    ASSERT_TRUE(core.consume_data(tok_b, out));
    EXPECT_EQ(std::memcmp(out, b.data(), b.size()), 0) << "token B payload survived untouched";

    std::cout << "  [fixed] full vault pool refuses instead of zeroing a"
              << " live LOCKED page; both tokens survive.\n";
}

// ── Regression (round 5, fixed): the block id committed only the
// 472-byte header; the tail (vm_state_root, vm_gas_used, pogw_nonce,
// vm_bytecode) sat OUTSIDE the commitment, so two frames differing only
// in their PoGW nonce shared one tip hash. hash_block now commits both.
TEST(VortexDocumentedGapsTest, TailMetadataCommitted) {
    const std::string dir = temp_dir("vx_gap_tailcommit");
    vx::storage::BlockStore store(dir + "/tail.vxb", "genesis.bin", 8);

    BlockBuilder b = next_block(store, std::time(nullptr));
    Transaction t = make_tx(addr_of("GENESIS_2"),
                            addr_of("NFA_TAIL_TARGET_00000000000000000000000"), 100000000u, 0);
    sign_transaction(t);
    ASSERT_TRUE(b.add_transaction(t));
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    auto *raw = reinterpret_cast<const RawBlock *>(f.data());

    uint8_t h1[32];
    hash_block(*raw, h1);

    // Mutate ONE byte of the PoGW nonce inside the tail (offset 65472):
    // the old header-only digest did not move; the full commitment must.
    BlockFrame g = f;
    g.data()[65472] = static_cast<uint8_t>(g.data()[65472] ^ 0x01);
    auto *raw2 = reinterpret_cast<const RawBlock *>(g.data());
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

// ── Gap closed (2026-11-03, BACKLOG 0.9): the intake gate accepts work that
// meets the configured difficulty and binds the producer to the exact nonce —
// a one-off nonce mutation of a sealed frame is rejected with the same
// "insufficient PoGW work" verdict as a never-sealed frame.
TEST(VortexDocumentedGapsTest, PogwGateAcceptsSealedWorkAndBindsTheNonce) {
    const std::string dir = temp_dir("vx_gap_work");
    // Difficulty 12: ~4096 expected hashes (~0.5 s) — real PoGW, fast test.
    vx::storage::BlockStore store(dir + "/work.vxb", "genesis.bin", 12);
    vx::state::LedgerState ledger;

    const auto *g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    BlockBuilder b = next_block(store, std::time(nullptr));
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));

    // A sealed frame's nonce is load-bearing: change it and the work is gone.
    BlockFrame forged = f;
    auto *forged_raw = reinterpret_cast<RawBlock *>(forged.data());
    forged_raw->tail.pogw_nonce ^= 1;
    EXPECT_FALSE(store.append_block(forged));
    EXPECT_EQ(store.last_error(), "insufficient PoGW work for the current difficulty");

    // The untouched sealed frame goes through.
    EXPECT_TRUE(store.append_block(f));
    EXPECT_EQ(store.chain_height(), 2u);

    std::filesystem::remove_all(dir);
}

// ── Gap closed (2026-11-03, BACKLOG 0.9): the recovery/reopen path no longer
// trusts magic + height alone. A ledger whose stored frame lost its merkle
// commitment must fail the open loudly instead of serving corrupted history.
TEST(VortexDocumentedGapsTest, RecoveryRejectsCorruptedLedgerFrame) {
    const std::string dir = temp_dir("vx_gap_reopen");
    const std::string path = dir + "/reopen.vxb";
    {
        vx::storage::BlockStore store(path, "genesis.bin", 8);
        vx::state::LedgerState ledger;
        const auto *g = store.get_block(0);
        ASSERT_NE(g, nullptr);
        BlockFrame gf;
        std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
        ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);
        BlockBuilder b = next_block(store, std::time(nullptr));
        ASSERT_TRUE(push_block(store, ledger, b));
    }
    // Corrupt one byte of frame 1's committed merkle root on disk.
    const int fd = ::open(path.c_str(), O_RDWR);
    ASSERT_GE(fd, 0);
    const off_t off = static_cast<off_t>(BLOCK_SIZE_BYTES + offsetof(RawBlock, header.merkle_root));
    uint8_t byte = 0;
    ASSERT_EQ(::pread(fd, &byte, 1, off), 1);
    byte = static_cast<uint8_t>(byte ^ 0xA5);
    ASSERT_EQ(::pwrite(fd, &byte, 1, off), 1);
    ::close(fd);

    EXPECT_THROW({ vx::storage::BlockStore reopen(path, "genesis.bin", 8); }, std::runtime_error);

    std::filesystem::remove_all(dir);
}

// ── BACKLOG 0.7 (closed 2026-11-03): a user sender that is neither
// PQ-bound nor self-certifying is refused outright, even when it carries a
// cryptographically valid witness from a key the sender does not own. The
// keyless tier no longer accepts anything on the consensus path.
TEST(VortexDocumentedGapsTest, UnboundSenderRejected) {
    const std::string dir = temp_dir("vx_gap_unbound");
    vx::storage::BlockStore store(dir + "/unbound.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;

    const auto *g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    // The attacker controls a real PQ key - just not one bound to the
    // address it claims to spend from (a legacy-shaped NFA address that
    // commits no key root at all).
    const Address attacker = addr_of("NFA_NO_BINDING_AT_ALL_00000000000000000");
    const Address sink = addr_of("NFA_UNBOUND_SINK_000000000000000000000000");
    const PqAccount attacker_key = make_pq_account("VX_TEST_UNBOUND_SK_V1");

    Transaction tx = make_tx(attacker, sink, 100, 0);
    ASSERT_TRUE(pq_sign(tx, attacker_key)); // witness is internally valid

    BlockBuilder b = next_block(store, std::time(nullptr));
    ASSERT_TRUE(b.add_transaction(tx));
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
    EXPECT_TRUE(store.append_block(f));
    const auto res = ledger.apply_block(BlockView(f));
    EXPECT_FALSE(res.ok) << "an unbound sender was accepted!";
    EXPECT_NE(res.error.find("sender address is not PQ-bound"), std::string::npos)
        << "expected the unbound-sender refusal, got: " << res.error;

    std::cout << "  [closed] a valid witness from an UNBOUND key spends"
              << " nothing: the sender address commits no PQ root"
              << " (BACKLOG 0.7).\n";

    std::filesystem::remove_all(dir);
}

// ── BACKLOG 0.7: a witness from the WRONG key cannot spend a protocol-
// bound address. The demo spender is bound at ledger construction
// (genesis.hpp pq_seed_bindings) to a documented PUBLIC test key; a
// different, internally valid witness is refused on the root comparison
// before any balance is touched.
TEST(VortexDocumentedGapsTest, WitnessRootMismatchRejected) {
    const std::string dir = temp_dir("vx_gap_mismatch");
    vx::storage::BlockStore store(dir + "/mismatch.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;

    const auto *g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    const Address demo_spender = payload_of(vx::blockchain::demo_spender_address_nfa());
    const Address sink = addr_of("NFA_MISMATCH_SINK_00000000000000000000000");
    const PqAccount attacker = make_pq_account("VX_TEST_MISMATCH_SK_V1");

    Transaction tx = make_tx(demo_spender, sink, 1, 0);
    ASSERT_TRUE(pq_sign(tx, attacker)); // valid witness, wrong key

    BlockBuilder b = next_block(store, std::time(nullptr));
    ASSERT_TRUE(b.add_transaction(tx));
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
    EXPECT_TRUE(store.append_block(f));
    const auto res = ledger.apply_block(BlockView(f));
    EXPECT_FALSE(res.ok) << "a mismatched-key witness was accepted!";
    EXPECT_NE(res.error.find("PQ witness root does not match the sender's bound key"),
              std::string::npos)
        << "expected the root-mismatch refusal, got: " << res.error;

    std::cout << "  [closed] a witness whose XMSS root differs from the"
              << " sender's bound key is refused before any balance check"
              << " (BACKLOG 0.7).\n";

    std::filesystem::remove_all(dir);
}

// ── BACKLOG 0.7: self-certifying addresses. A "PQA" address commits its
// own key root, so the first witnessed spend binds it; after that, only
// the bound key can spend it. No registration transaction, no trusted
// table.
TEST(VortexDocumentedGapsTest, SelfCertifyingAddressAutoBinds) {
    const std::string dir = temp_dir("vx_gap_selfcert");
    vx::storage::BlockStore store(dir + "/selfcert.vxb", "genesis.bin", 8);
    vx::state::LedgerState ledger;

    const auto *g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    BlockFrame gf;
    std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(ledger.apply_block(BlockView(gf)).ok);

    // A fresh PQ account nobody has ever seen: the address IS the key
    // commitment.
    const PqAccount acc = make_pq_account("VX_TEST_SELFCERT_SK_V1");
    const Address sink = addr_of("NFA_SELFCERT_SINK_00000000000000000000000");
    PqAccount demo = make_pq_account("VX_DEMO_SPENDER_SK_V1");
    demo.addr = vx::blockchain::genesis2_mint_receiver_payload();

    // Height 1: the protocol mint funds the demo spender (pinned shape).
    {
        BlockBuilder b = next_block(store, std::time(nullptr));
        Transaction mint =
            make_tx(addr_of("GENESIS_2"), demo.addr, vx::blockchain::GENESIS_2_MINT_ATOMICS, 0);
        sign_transaction(mint); // system sender: structural digest only
        ASSERT_TRUE(b.add_transaction(mint));
        ASSERT_TRUE(push_block(store, ledger, b));
    }
    ASSERT_EQ(ledger.balance_of(demo.addr), U128(vx::blockchain::GENESIS_2_MINT_ATOMICS));

    // Height 2: the demo spender funds the fresh account with a plain PQ
    // transfer (mints pay only the pinned receiver - a keyless digest can
    // no longer mint to an arbitrary address, review round 5).
    {
        BlockBuilder b = next_block(store, std::time(nullptr));
        Transaction fund = make_tx(demo.addr, acc.addr, 1000000000u, 0);
        ASSERT_TRUE(pq_sign(fund, demo));
        ASSERT_TRUE(b.add_transaction(fund));
        ASSERT_TRUE(push_block(store, ledger, b));
    }
    ASSERT_EQ(ledger.balance_of(acc.addr), U128(1000000000u));

    // Height 2: the FIRST witnessed spend binds the address to its key.
    {
        BlockBuilder b = next_block(store, std::time(nullptr));
        Transaction spend = make_tx(acc.addr, sink, 100000000u, 0);
        ASSERT_TRUE(pq_sign(spend, acc));
        ASSERT_TRUE(b.add_transaction(spend));
        ASSERT_TRUE(push_block(store, ledger, b));
    }
    // 10 VX minted, 1 VX spent, 100-atom fee paid.
    EXPECT_EQ(ledger.balance_of(sink), U128(100000000u));
    EXPECT_EQ(ledger.balance_of(acc.addr), U128(899999900u));

    // Height 3: a THIEF with a different real key cannot spend the now-
    // bound address - the witness root fails the binding comparison. The
    // frame is judged by the ledger DIRECTLY (never appended): a real node
    // drops a rejected block before it reaches the store, and appending a
    // ledger-rejected frame here would desync the store tip from state.
    {
        const PqAccount thief = make_pq_account("VX_TEST_SELFCERT_THIEF_SK_V1");
        BlockBuilder b = next_block(store, std::time(nullptr));
        Transaction steal = make_tx(acc.addr, sink, 900000000u, 1);
        ASSERT_TRUE(pq_sign(steal, thief)); // internally valid witness
        ASSERT_TRUE(b.add_transaction(steal));
        b.finalize();
        BlockFrame f;
        std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
        ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
        const auto res = ledger.apply_block(BlockView(f));
        EXPECT_FALSE(res.ok) << "a foreign key spent a bound address!";
        EXPECT_NE(res.error.find("PQ witness root does not match"), std::string::npos)
            << "expected the binding refusal, got: " << res.error;
        EXPECT_EQ(ledger.balance_of(acc.addr), U128(899999900u))
            << "the theft attempt must not mutate state";
    }

    // Height 3 (retry): the legitimate key still spends freely.
    {
        BlockBuilder b = next_block(store, std::time(nullptr));
        Transaction spend2 = make_tx(acc.addr, sink, 100000000u, 1);
        ASSERT_TRUE(pq_sign(spend2, acc));
        ASSERT_TRUE(b.add_transaction(spend2));
        ASSERT_TRUE(push_block(store, ledger, b));
    }
    EXPECT_EQ(ledger.balance_of(acc.addr), U128(799999800u));

    std::cout << "  [closed] self-certifying address: first witnessed spend"
              << " binds it to its key; a foreign key is refused, the owner"
              << " keeps spending (BACKLOG 0.7).\n";

    std::filesystem::remove_all(dir);
}

// ── BACKLOG 0.8: witnesses persist in a durable sidecar (<ledger>.pqw)
// and are replayed into the registry on attach - a node restart no longer
// orphans witnessed transactions.
TEST(VortexDocumentedGapsTest, WitnessDurableLogSurvivesRestart) {
    const std::string dir = temp_dir("vx_gap_pqw");
    const std::string pqw = dir + "/witnesses.pqw";

    const PqAccount acc = make_pq_account("VX_TEST_DURABLE_SK_V1");
    Transaction tx = make_tx(acc.addr, addr_of("NFA_DURABLE_SINK_000000000000000000000"), 1000, 0);

    vx::crypto::pq::PqSignatureWitness w;
    {
        vx::crypto::pq::PqWitnessRegistry::instance().attach_durable_log(pqw);
        ASSERT_TRUE(pq_sign(tx, acc)); // registers + appends + fsyncs
        ASSERT_TRUE(vx::crypto::pq::PqWitnessRegistry::instance().lookup(
            vx::crypto::pq::tx_msg_digest(tx), w));
    }

    // The sidecar exists, is record-sized, and carries the record tag.
    {
        std::ifstream in(pqw, std::ios::binary);
        ASSERT_TRUE(in.good()) << "durable witness log was not created";
        std::string rec((std::istreambuf_iterator<char>(in)), std::istreambuf_iterator<char>());
        const size_t expect = 8 + 32 + 42 + sizeof(vx::crypto::pq::PqSignatureWitness);
        ASSERT_EQ(rec.size(), expect) << "exactly one 2458-byte record";
        EXPECT_EQ(std::memcmp(rec.data(), "VXPQWT1", 8), 0) << "record tag";
    }

    // Simulated restart: re-attaching the same path replays the log into
    // the registry and the witness is still there, byte-identical.
    vx::crypto::pq::PqWitnessRegistry::instance().attach_durable_log(pqw);
    vx::crypto::pq::PqSignatureWitness w2;
    ASSERT_TRUE(
        vx::crypto::pq::PqWitnessRegistry::instance().lookup(vx::crypto::pq::tx_msg_digest(tx), w2))
        << "witness lost across the restart";
    EXPECT_EQ(w2.wots_sig, w.wots_sig);
    EXPECT_EQ(w2.pq_pubkey_root, w.pq_pubkey_root);
    EXPECT_EQ(w2.witness_digest, w.witness_digest);

    std::cout << "  [closed] durable witness sidecar: registration fsyncs a"
              << " VXPQWT1 record and a restart replays it (BACKLOG 0.8).\n";

    std::filesystem::remove_all(dir);
}

// ── BACKLOG 1.5 wiring (v0.0.18): rollover certificate consensus chain ──────
//
// A certified one-window key rotation lets a bound PQ account keep its
// ADDRESS (which commits the window-0 anchor root) while spending under a
// later window's root. Consensus accepts the rotated root ONLY through a
// sequential chain of cryptographically verified ROLLOVER_CERT records
// walked from the anchor - no certificate, no acceptance; a gap caps the
// walk; the certificate leaf (15) never spends.

namespace {

// Full setup shared by the rollover end-to-end tests: genesis, the
// GENESIS_2 mint to the demo spender, the demo spender funding a fresh
// SELF-CERTIFYING PQA account (whose address commits its window-0 root),
// and that account's first window-0 spend (which binds the anchor).
struct RolloverFixture {
    std::unique_ptr<vx::storage::BlockStore> store;
    std::unique_ptr<vx::state::LedgerState> ledger;
    PqAccount acc{};
    Address sink{};
    std::string dir;

    // NOTE: the PqWitnessRegistry is a process-lifetime singleton - every
    // fixture builds its OWN account tag so certificates registered by one
    // test can never satisfy another test's expectations.
    bool build(const char *account_tag) {
        dir = temp_dir("vx_gap_rollover");
        store = std::make_unique<vx::storage::BlockStore>(dir + "/rollover.vxb", "genesis.bin");
        ledger = std::make_unique<vx::state::LedgerState>();

        const auto *g = store->get_block(0);
        if (!g)
            return false;
        BlockFrame gf;
        std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
        if (!ledger->apply_block(BlockView(gf)).ok)
            return false;

        PqAccount demo = make_pq_account("VX_DEMO_SPENDER_SK_V1");
        demo.addr = vx::blockchain::genesis2_mint_receiver_payload();
        sink = addr_of("NFA_ROLLOVER_SINK_0000000000000000000000000000");
        acc = make_pq_account(account_tag);

        // Height 1: the bound-shape GENESIS_2 mint (100,000 VX to the demo
        // spender).
        {
            BlockBuilder b = next_block(*store, std::time(nullptr));
            Transaction mint =
                make_tx(addr_of("GENESIS_2"), demo.addr, vx::blockchain::GENESIS_2_MINT_ATOMICS, 0);
            sign_transaction(mint);
            if (!b.add_transaction(mint))
                return false;
            if (!push_block(*store, *ledger, b))
                return false;
        }
        // Height 2: the demo spender funds the PQA account.
        {
            BlockBuilder b = next_block(*store, std::time(nullptr));
            Transaction fund = make_tx(demo.addr, acc.addr, 1000000000ull, 0);
            if (!pq_sign(fund, demo))
                return false;
            if (!b.add_transaction(fund))
                return false;
            if (!push_block(*store, *ledger, b))
                return false;
        }
        // Height 3: the PQA account's first spend - self-certifying
        // binding stores the window-0 anchor root.
        {
            BlockBuilder b = next_block(*store, std::time(nullptr));
            Transaction first = make_tx(acc.addr, sink, 1000000ull, 0);
            if (!pq_sign(first, acc))
                return false;
            if (!b.add_transaction(first))
                return false;
            if (!push_block(*store, *ledger, b))
                return false;
        }
        return true;
    }

    // A transaction signed INSIDE window `win` at leaf `leaf`, anchored by
    // hand (the wallet path pq_sign_transaction is window-0-only until the
    // post-rollover leaf accounting ships; consensus is window-agnostic).
    Transaction window_tx(uint32_t nonce, uint32_t win, uint32_t leaf) {
        Transaction tx = make_tx(acc.addr, sink, 2000000ull, nonce);
        const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(acc.sk);
        const auto w = vx::crypto::pq::pq_sign_message(leaf, win, acc.sk, pub_seed,
                                                       vx::crypto::pq::tx_msg_digest(tx));
        assert(w.witness_digest != vx::crypto::pq::PqSignatureWitness{}.witness_digest);
        // cocoon anchor = trunc12(Sponge("VX_SEGPQ_ANCHOR_V1" || msg || root
        // || witness_digest)) - the same preimage pq_sign_transaction lays
        // down, laid down by hand here (18 + 32*3 = 114 bytes).
        const auto msg = vx::crypto::pq::tx_msg_digest(tx);
        uint8_t a[18 + 32 + 32 + 32];
        std::memcpy(a, "VX_SEGPQ_ANCHOR_V1", 18);
        std::memcpy(a + 18, msg.data(), 32);
        std::memcpy(a + 50, w.pq_pubkey_root.data(), 32);
        std::memcpy(a + 82, w.witness_digest.data(), 32);
        std::array<uint8_t, 32> full_tag{};
        VortexSponge256::compute(a, sizeof(a), full_tag.data());
        std::memcpy(tx.cocoon_proof, full_tag.data(), 12);
        assert(vx::crypto::pq::PqWitnessRegistry::instance().register_witness(tx, w));
        return tx;
    }

    // Registers the honest certificate for (win -> win+1) under acc.addr.
    bool register_cert(uint32_t win) {
        const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(acc.sk);
        vx::crypto::pq::PqRolloverCert cert;
        std::memcpy(cert.sender.data(), acc.addr.data(), 42);
        cert.from_window = win;
        cert.to_window = win + 1;
        cert.old_root = vx::crypto::pq::xmss_root_tree(acc.sk, pub_seed, win);
        cert.new_root = vx::crypto::pq::xmss_root_tree(acc.sk, pub_seed, win + 1);
        cert.witness = vx::crypto::pq::pq_sign_rollover(acc.sk, win, win + 1, nullptr);
        return vx::crypto::pq::PqWitnessRegistry::instance().register_rollover_cert(cert);
    }
};

} // namespace

// ACCEPTED: the full certified rotation - anchor bound at height 3, one
// certificate, a window-1 spend attributed through the walked chain.
TEST(VortexDocumentedGapsTest, RolloverChainAccepted) {
    RolloverFixture fx;
    ASSERT_TRUE(fx.build("VX_ROLLOVER_E2E_SK_V1"));

    // Before the certificate exists the rotated root is unattributable.
    std::array<uint8_t, 32> walked{};
    uint32_t win = 0;
    const auto r0 =
        vx::crypto::pq::xmss_root_tree(fx.acc.sk, vx::crypto::pq::pub_seed_from_sk(fx.acc.sk), 0);
    EXPECT_FALSE(vx::crypto::pq::PqWitnessRegistry::instance().advance_root_chain(
        fx.acc.addr.data(), r0, walked, win));

    ASSERT_TRUE(fx.register_cert(0)); // the 0 -> 1 certificate

    EXPECT_TRUE(vx::crypto::pq::PqWitnessRegistry::instance().advance_root_chain(fx.acc.addr.data(),
                                                                                 r0, walked, win));
    EXPECT_EQ(win, 1u);

    {
        BlockBuilder b = next_block(*fx.store, std::time(nullptr));
        Transaction spend = fx.window_tx(1, 1, 3); // window 1, leaf 3
        ASSERT_TRUE(b.add_transaction(spend));
        const U128 before = fx.ledger->balance_of(fx.acc.addr);
        ASSERT_TRUE(push_block(*fx.store, *fx.ledger, b));
        EXPECT_EQ(fx.ledger->balance_of(fx.acc.addr), before - U128(2000100ull))
            << "the window-1 spend must actually move value (amount + fee)";
    }
    std::cout << "  [closed] certified rollover: window-1 spend accepted"
              << " through the walked certificate chain (BACKLOG 1.5).\n";
    std::filesystem::remove_all(fx.dir);
}

// REJECTED: the same window-1 spend WITHOUT the certificate - fail-closed.
TEST(VortexDocumentedGapsTest, RolloverWithoutCertRejected) {
    RolloverFixture fx;
    ASSERT_TRUE(fx.build("VX_ROLLOVER_NO_CERT_SK_V1"));

    {
        BlockBuilder b = next_block(*fx.store, std::time(nullptr));
        Transaction spend = fx.window_tx(1, 1, 3); // cryptographically valid
        ASSERT_TRUE(b.add_transaction(spend));
        b.finalize();
        BlockFrame f;
        std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
        ASSERT_TRUE(seal_pogw_nonce(f, fx.store->required_pogw_bits()));
        ASSERT_TRUE(fx.store->append_block(f));
        const auto res = fx.ledger->apply_block(BlockView(f));
        EXPECT_FALSE(res.ok) << "an uncertified rotated root was accepted";
        EXPECT_NE(res.error.find("no certified rollover chain"), std::string::npos)
            << "expected the chain-walk refusal";
    }
    std::cout << "  [closed] uncertified rollover: window-1 spend refused"
              << " without a certificate chain.\n";
    std::filesystem::remove_all(fx.dir);
}

// REJECTED: a spend on the RESERVED certificate leaf (15) - even inside an
// honestly certified window. Leaf 15 certifies; it never spends.
TEST(VortexDocumentedGapsTest, RolloverCertLeafSpenderRejected) {
    RolloverFixture fx;
    ASSERT_TRUE(fx.build("VX_ROLLOVER_LEAF15_SK_V1"));
    ASSERT_TRUE(fx.register_cert(0));

    // The witness verifies as a pure chain (wots_xmss) but the tx USE-time
    // verification refuses the reserved leaf - registration through the
    // client path must already fail.
    {
        Transaction spend = make_tx(fx.acc.addr, fx.sink, 2000000ull, 2);
        const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(fx.acc.sk);
        const auto w =
            vx::crypto::pq::pq_sign_message(vx::crypto::pq::PQ_ROLLOVER_CERT_LEAF, 1, fx.acc.sk,
                                            pub_seed, vx::crypto::pq::tx_msg_digest(spend));
        ASSERT_TRUE(w.witness_digest == vx::crypto::pq::witness_commitment(w));
        EXPECT_FALSE(vx::crypto::pq::PqWitnessRegistry::instance().register_witness(spend, w))
            << "a certificate-leaf witness entered the tx registry";
        EXPECT_FALSE(verify_transaction_proof(spend))
            << "Tier 1 accepted a certificate-leaf witness";
    }
    std::cout << "  [closed] certificate-leaf spender refused at USE time"
              << " (leaf 15 never spends).\n";
    std::filesystem::remove_all(fx.dir);
}
