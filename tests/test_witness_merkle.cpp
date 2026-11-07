// VortexWitnessMerkleTest - BACKLOG 2.11 stage 1: the witness_merkle_root
// header commitment (VXC7 frame format).
//
// What is enforced, and where:
//   - the producer commits the CANONICAL witness set (one binding per user
//     transaction: tx index + sender + ledger-bound / genesis-table /
//     self-certifying XMSS root) into the 504-byte header before PoGW
//     sealing - the commitment is inside the work-sealed frame;
//   - LedgerState::apply_block recomputes the tree from the witnesses its
//     own verification accepted and refuses a frame whose header lies
//     (ERR_WITNESS_ROOT), before any state mutation;
//   - the intake gate structurally requires the empty constant on blocks
//     with no user transactions, and refuses VXC6 frames outright.
//
// The leaf commits the canonical ROOT, not raw witness bytes: two witnesses
// of the same tree (different one-time leaves) must verify as the same set,
// and witness arrival order must not change what a node computes.

#include <gtest/gtest.h>
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/crypto/pq_signature.hpp"
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

BlockFrame sealed_frame(vx::storage::BlockStore &store, BlockBuilder &b) {
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    EXPECT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
    return f;
}

// The full setup: genesis replayed, the height-1 protocol mint applied, and
// the demo spender funded with the pinned 100,000 VX mint.
struct WitnessChain {
    std::string dir;
    std::unique_ptr<vx::storage::BlockStore> store;
    std::unique_ptr<vx::state::LedgerState> ledger;
    PqAccount demo{};
    Address spender{};

    explicit WitnessChain(const char *tag) : dir(temp_dir(tag)) {
        store = std::make_unique<vx::storage::BlockStore>(dir + "/ledger.vxb", "genesis.bin", 8);
        ledger = std::make_unique<vx::state::LedgerState>();
        const auto *g = store->get_block(0);
        if (!g) {
            ADD_FAILURE();
            return;
        }
        BlockFrame gf;
        std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
        if (!ledger->apply_block(BlockView(gf)).ok) {
            ADD_FAILURE();
            return;
        }

        demo = make_pq_account("VX_DEMO_SPENDER_SK_V1");
        spender = genesis2_mint_receiver_payload();

        BlockBuilder b = next_block(*store, static_cast<uint64_t>(std::time(nullptr)));
        Transaction mint = make_tx(addr_of("GENESIS_2"), spender, GENESIS_2_MINT_ATOMICS, 0);
        sign_transaction(mint); // system sender: structural digest only
        if (!b.add_transaction(mint)) {
            ADD_FAILURE();
            return;
        }
        const BlockFrame f = sealed_frame(*store, b);
        if (!store->append_block(f)) {
            ADD_FAILURE();
            return;
        }
        if (!ledger->apply_block(BlockView(f)).ok) {
            ADD_FAILURE();
            return;
        }
        if (!(ledger->balance_of(spender) == U128(GENESIS_2_MINT_ATOMICS))) {
            ADD_FAILURE();
            return;
        }
    }

    ~WitnessChain() {
        std::filesystem::remove_all(dir);
    }

    // The ledger's binding oracle, as the production verifiers pass it.
    BoundRootOf oracle() {
        vx::state::LedgerState *l = ledger.get();
        return [l](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
            return l->pq_root_of(a, out);
        };
    }
};

} // namespace

// -- The empty constant is a fixed, deterministic sponge digest: the empty
// witness set must commit to the SAME value on every node and every call.
TEST(VortexWitnessMerkleTest, EmptyConstantIsDeterministic) {
    uint8_t a[32];
    uint8_t b[32];
    compute_witness_merkle_root(nullptr, 0, a);
    compute_witness_merkle_root(nullptr, 0, b);
    EXPECT_EQ(0, std::memcmp(a, b, 32));
    EXPECT_EQ(0, std::memcmp(a, witness_merkle_empty_root(), 32));
    // Not accidentally all-zero: the constant is domain-separated.
    bool nonzero = false;
    for (uint8_t byte : a)
        if (byte != 0)
            nonzero = true;
    EXPECT_TRUE(nonzero);
}

// -- A system-sender-only block commits the empty constant automatically,
// and the intake gate's structural check accepts exactly that.
TEST(VortexWitnessMerkleTest, SystemOnlyBlockCommitsEmptyConstant) {
    BlockBuilder b;
    b.set_height(7);
    Transaction cb{};
    set_nfa_field(cb.sender_nfa, "MINER_");
    set_nfa_field(cb.receiver_nfa, "MINER_REWARD_WITNESS_EMPTY_CONST");
    tx_set_amount(cb, 1000);
    ASSERT_TRUE(b.add_transaction(cb));
    b.finalize();
    EXPECT_EQ(0, std::memcmp(b.raw().header.witness_merkle_root, witness_merkle_empty_root(), 32));

    // The structural gate: a witness-free block claiming a NON-empty root
    // is refused at intake.
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    auto *raw = reinterpret_cast<RawBlock *>(f.data());
    raw->header.witness_merkle_root[0] ^= 0x01;
    BlockIntakeContext ctx{};
    ctx.expected_height = 7;
    ctx.difficulty_bits = 0;
    std::string err;
    EXPECT_FALSE(validate_block(*reinterpret_cast<RawBlock *>(f.data()), ctx, &err));
    EXPECT_NE(err.find("witness_merkle_root is not the empty constant"), std::string::npos) << err;
}

// -- The tree binds tx index and sender: reordering bindings changes the
// root, and identical roots with different positions never collide.
TEST(VortexWitnessMerkleTest, TreeBindsIndexAndSender) {
    WitnessBinding x{0, addr_of("PQA_SENDER_X_00000000000000000000000000000000"), {{1}}};
    WitnessBinding y{1, addr_of("PQA_SENDER_Y_00000000000000000000000000000000"), {{2}}};
    uint8_t xy[32];
    uint8_t yx[32];
    const WitnessBinding pair_xy[2] = {x, y};
    const WitnessBinding pair_yx[2] = {y, x};
    compute_witness_merkle_root(pair_xy, 2, xy);
    compute_witness_merkle_root(pair_yx, 2, yx);
    EXPECT_NE(0, std::memcmp(xy, yx, 32));

    // Same senders, same order, different roots -> different tree.
    WitnessBinding x2 = x;
    x2.pq_root[0] ^= 0x01;
    const WitnessBinding pair_x2y[2] = {x2, y};
    uint8_t x2y[32];
    compute_witness_merkle_root(pair_x2y, 2, x2y);
    EXPECT_NE(0, std::memcmp(xy, x2y, 32));

    // Odd counts: 1 and 3 leaves compute deterministically.
    uint8_t one[32];
    uint8_t one_again[32];
    compute_witness_merkle_root(&x, 1, one);
    compute_witness_merkle_root(&x, 1, one_again);
    EXPECT_EQ(0, std::memcmp(one, one_again, 32));
    std::vector<WitnessBinding> three = {x, y, x2};
    uint8_t t1[32];
    uint8_t t2[32];
    compute_witness_merkle_root(three.data(), 3, t1);
    compute_witness_merkle_root(three.data(), 3, t2);
    EXPECT_EQ(0, std::memcmp(t1, t2, 32));
}

// -- VXC6 frames are refused at the intake gate with a version-named
// diagnostic (fail-closed format bump, never a silent swap).
TEST(VortexWitnessMerkleTest, Vxc6FrameIsRefusedByName) {
    BlockBuilder b;
    b.set_height(1);
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    auto *raw = reinterpret_cast<RawBlock *>(f.data());
    raw->header.magic = BLOCK_MAGIC_V1;
    BlockIntakeContext ctx{};
    ctx.expected_height = 1;
    ctx.difficulty_bits = 0;
    std::string err;
    EXPECT_FALSE(validate_block(*raw, ctx, &err));
    EXPECT_NE(err.find("VXC6 frame refused"), std::string::npos) << err;
}

// -- The inverse structural rule, checked WITHOUT any registry access:
// every user transaction resolves to exactly one canonical witness before
// a block may apply, so a block WITH user transactions that commits the
// empty constant is a lie on its face and is refused at intake.
TEST(VortexWitnessMerkleTest, UserTxBlockCannotCommitEmptyConstant) {
    WitnessChain c("vx_wm_empty_inv");
    ASSERT_TRUE(c.store != nullptr);

    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction t0 =
        make_tx(c.spender, addr_of("NFA_WM_SINK_F_000000000000000000000000"), 1000000000u, 0);
    ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(t0, c.demo.sk));
    ASSERT_TRUE(b.add_transaction(t0));
    // Deliberately NO bindings: finalize commits the empty constant.
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    BlockIntakeContext ctx{};
    ctx.expected_height = c.store->chain_height();
    c.store->tip_hash(ctx.expected_prev_hash);
    ctx.difficulty_bits = 0;
    std::string err;
    EXPECT_FALSE(validate_block(*reinterpret_cast<RawBlock *>(f.data()), ctx, &err));
    EXPECT_NE(err.find("empty constant on a block with user transactions"), std::string::npos)
        << err;
}

// -- E2E: an honest block (canonical bindings, real witness) applies; the
// same frame with ONE header root byte patched is refused by apply_block
// with ERR_WITNESS_ROOT and leaves the ledger byte-identical; the
// standalone recomputation reports MISMATCH, not MISSING.
TEST(VortexWitnessMerkleTest, LyingHeaderRootIsRefusedBeforeMutation) {
    WitnessChain c("vx_wm_lying");
    ASSERT_TRUE(c.store != nullptr);

    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction t0 =
        make_tx(c.spender, addr_of("NFA_WM_SINK_A_000000000000000000000000"), 1000000000u, 0);
    ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(t0, c.demo.sk));
    ASSERT_TRUE(b.add_transaction(t0));
    ASSERT_EQ(1u, b.bind_canonical_witnesses(c.oracle()));
    BlockFrame f = sealed_frame(*c.store, b);
    auto *raw = reinterpret_cast<RawBlock *>(f.data());

    // The honest frame verifies standalone and applies.
    EXPECT_EQ(WitnessRootStatus::MATCH, verify_witness_merkle(*raw, c.oracle()));
    const U128 spender_before = c.ledger->balance_of(c.spender);
    ASSERT_TRUE(c.store->append_block(f));
    EXPECT_TRUE(c.ledger->apply_block(BlockView(f)).ok);
    EXPECT_EQ(spender_before - U128(1000000100u), c.ledger->balance_of(c.spender));

    // Now a fresh block whose header lies about its witness set: build an
    // honest frame, then patch the header commitment.
    BlockBuilder b2 = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction t1 =
        make_tx(c.spender, addr_of("NFA_WM_SINK_B_000000000000000000000000"), 2000000000u, 1);
    ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(t1, c.demo.sk));
    ASSERT_TRUE(b2.add_transaction(t1));
    ASSERT_EQ(1u, b2.bind_canonical_witnesses(c.oracle()));
    BlockFrame f2 = sealed_frame(*c.store, b2);
    auto *raw2 = reinterpret_cast<RawBlock *>(f2.data());
    raw2->header.witness_merkle_root[5] ^= 0x80;

    EXPECT_EQ(WitnessRootStatus::MISMATCH, verify_witness_merkle(*raw2, c.oracle()));
    const auto res = c.ledger->apply_block(BlockView(f2));
    EXPECT_FALSE(res.ok);
    EXPECT_NE(res.error.find("ERR_WITNESS_ROOT"), std::string::npos) << res.error;
    // No partial mutation: the spender's balance is untouched.
    EXPECT_EQ(spender_before - U128(1000000100u), c.ledger->balance_of(c.spender));

    // A MISSING report (not MISMATCH) is the case for parking: same frame,
    // but the registry no longer holds a consensus-consistent witness.
    // Re-derive the situation by building the frame against a FRESH
    // registry - simulate by checking the status of a frame whose tx was
    // never registered (a different nonce => different digest).
    BlockBuilder b3 = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction t2 =
        make_tx(c.spender, addr_of("NFA_WM_SINK_C_000000000000000000000000"), 3000000000u, 2);
    // Intentionally NOT signed/registered.
    ASSERT_TRUE(b3.add_transaction(t2));
    ASSERT_EQ(0u, b3.bind_canonical_witnesses(c.oracle()));
    BlockFrame f3 = sealed_frame(*c.store, b3);
    EXPECT_EQ(WitnessRootStatus::MISSING_WITNESS,
              verify_witness_merkle(*reinterpret_cast<RawBlock *>(f3.data()), c.oracle()));
}

// -- A block whose producer bound the WRONG key (a different account's
// canonical root) is refused even though a perfectly valid witness for the
// real key sits in the registry: the commitment is attributable.
TEST(VortexWitnessMerkleTest, WrongKeyBindingIsRefusedWithWitnessPresent) {
    WitnessChain c("vx_wm_wrong");
    ASSERT_TRUE(c.store != nullptr);

    // A second, unrelated PQ account whose root will poison the binding.
    const PqAccount impostor = make_pq_account("VX_WM_IMPOSTOR_SK_V1");

    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction t0 =
        make_tx(c.spender, addr_of("NFA_WM_SINK_D_000000000000000000000000"), 1000000000u, 0);
    ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(t0, c.demo.sk));
    ASSERT_TRUE(b.add_transaction(t0));
    // Bind the IMPOSTOR's root instead of the spender's canonical root.
    ASSERT_TRUE(b.add_witness_binding(0, t0.sender_nfa, impostor.root.data()));
    BlockFrame f = sealed_frame(*c.store, b);

    EXPECT_EQ(WitnessRootStatus::MISMATCH,
              verify_witness_merkle(*reinterpret_cast<RawBlock *>(f.data()), c.oracle()));
    const auto res = c.ledger->apply_block(BlockView(f));
    EXPECT_FALSE(res.ok);
    EXPECT_NE(res.error.find("ERR_WITNESS_ROOT"), std::string::npos) << res.error;
}

// -- The canonical selection is arrival-order independent: registering a
// SECOND self-consistent witness for the same digest first (an attacker's
// pre-registration, math-audit F7) must not change the root a producer
// binds for a ledger-bound sender.
TEST(VortexWitnessMerkleTest, CanonicalRootIgnoresForeignCandidate) {
    WitnessChain c("vx_wm_order");
    ASSERT_TRUE(c.store != nullptr);

    const PqAccount impostor = make_pq_account("VX_WM_FOREIGN_SK_V1");

    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction t0 =
        make_tx(c.spender, addr_of("NFA_WM_SINK_E_000000000000000000000000"), 1000000000u, 0);

    // Poison attempt FIRST: a self-consistent witness by a FOREIGN key for
    // the same digest, registered BEFORE the honest witness. The demo
    // spender is ledger-bound, so the canonical root is pinned and the
    // foreign candidate cannot displace it (arrival-order independence).
    vx::crypto::pq::PqSignatureWitness foreign{};
    ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(t0, impostor.sk, nullptr, nullptr, &foreign));

    ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(t0, c.demo.sk));
    ASSERT_TRUE(b.add_transaction(t0));

    std::array<uint8_t, 32> root{};
    ASSERT_TRUE(consensus_witness_root(t0, c.oracle(), root));
    EXPECT_EQ(0, std::memcmp(root.data(), c.demo.root.data(), 32))
        << "a foreign candidate displaced the canonical root";
    ASSERT_EQ(1u, b.bind_canonical_witnesses(c.oracle()));
    BlockFrame f = sealed_frame(*c.store, b);
    EXPECT_EQ(WitnessRootStatus::MATCH,
              verify_witness_merkle(*reinterpret_cast<RawBlock *>(f.data()), c.oracle()));
    ASSERT_TRUE(c.store->append_block(f));
    EXPECT_TRUE(c.ledger->apply_block(BlockView(f)).ok)
        << "the canonical-selection block must apply";
}
