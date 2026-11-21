// SVA-8192 Sovereign Vault — ledger wiring tests (0.2.x phase A).
//
// Cover: the full spend path (witness registered out of band, block
// applies, counter advances), verify-before-store refusal of a tampered
// preimage/path, out-of-order leaf refusal, the 1000 VX minimum-balance
// gate, the 1 VX burn-fee gate, the 256-spend exhaustion → tombstone,
// counter persistence across a ledger restart (replay from the block
// store), and the reorg rollback restoring the exact pre-block counter.
//
// The vault is keyless: authorization is the revealed preimage. Every
// test drives the same production path a wallet would — register the
// witness via SvaWitnessRegistry (the wire entry point), then apply the
// frame through LedgerState::apply_block.
#include <gtest/gtest.h>

#include "vx/blockchain/block.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/blockchain/sva_vault.hpp"
#include "vx/blockchain/sva_witness.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/state/undo_engine.hpp"
#include "vx/storage/block_store.hpp"

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
    Address addr{};
};

PqAccount make_pq_account(const char *tag) {
    PqAccount acc;
    VortexSponge256::compute(reinterpret_cast<const uint8_t *>(tag), std::strlen(tag),
                             acc.sk.data());
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(acc.sk);
    const auto root = vx::crypto::pq::xmss_root(acc.sk, pub_seed);
    derive_pq_address(root.data(), acc.addr.data());
    return acc;
}

Transaction make_tx(const Address &sender, const Address &receiver, uint64_t amount, uint32_t nonce,
                    uint32_t fee = 100) {
    Transaction tx{};
    std::memcpy(tx.sender_nfa, sender.data(), 42);
    std::memcpy(tx.receiver_nfa, receiver.data(), 42);
    tx_set_amount(tx, amount);
    tx_set_fee(tx, fee);
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
    // The caller binds canonical witnesses BEFORE calling this.
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    EXPECT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
    return f;
}

// A deterministic 256-leaf vault: preimages derived from a tag in counter
// mode. The owner's offline operation — the full set never leaves the test.
struct SvaVault {
    std::array<sva::SvaPreimage, sva::kSvaLeaves> preimages{};
    sva::SvaAddress root{};
    Address addr{};

    explicit SvaVault(const char *tag) {
        for (size_t i = 0; i < sva::kSvaLeaves; ++i) {
            const std::string base = std::string(tag) + ":" + std::to_string(i);
            for (size_t off = 0; off < sva::kSvaPreimageSize; off += 32) {
                const std::string inp = base + ":" + std::to_string(off);
                VortexSponge256::compute(reinterpret_cast<const uint8_t *>(inp.data()), inp.size(),
                                         preimages[i].data() + off);
            }
        }
        root = sva::sva_address_of(preimages);
        derive_sva_address(root.data(), addr.data());
    }

    sva::SvaMerklePath path_for(size_t i) const {
        return sva::sva_path_of(preimages, i);
    }
};

// Registers the spend witness the way a wallet/PQ_WITNESS-style wire
// message does: digest-keyed, verify-before-store.
bool register_sva_witness(const Transaction &tx, const SvaVault &v, uint32_t index) {
    const auto digest = vx::crypto::pq::tx_msg_digest(tx);
    return sva::SvaWitnessRegistry::instance().register_witness_bytes(
        digest, tx.sender_nfa, v.preimages[index], v.path_for(index), index);
}

// A funded chain: genesis replayed, the protocol mint applied, and a PQ
// funder holding spendable balance.
struct WiringChain {
    std::string dir;
    std::unique_ptr<vx::storage::BlockStore> store;
    std::unique_ptr<vx::state::LedgerState> ledger;
    PqAccount demo{};
    PqAccount funder{};
    Address spender{};

    explicit WiringChain(const char *tag) : dir(temp_dir(tag)) {
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
        funder = make_pq_account("VX_SVA_WIRING_FUNDER_SK_V1");
        spender = genesis2_mint_receiver_payload();

        BlockBuilder b = next_block(*store, static_cast<uint64_t>(std::time(nullptr)));
        Transaction mint = make_tx(addr_of("GENESIS_2"), spender, GENESIS_2_MINT_ATOMICS, 0);
        sign_transaction(mint);
        if (!b.add_transaction(mint)) {
            ADD_FAILURE();
            return;
        }
        const BlockFrame f = sealed_frame(*store, b);
        if (!store->append_block(f) || !ledger->apply_block(BlockView(f)).ok) {
            ADD_FAILURE();
            return;
        }
        // Note: the mint lands on the protocol receiver (spender). The
        // funder PQ account is funded per-test via fund_funder() — the
        // spender is PQ-bound to demo.sk, so every transfer from it
        // carries a real PQ witness (the f2 block here would be keyless
        // and refused by the unbound-sender rule).
    }

    ~WiringChain() {
        std::filesystem::remove_all(dir);
    }

    // The generic signed-transfer block used to fund the funder and the
    // vault: PQ witness registered out of band, canonical bindings, apply.
    bool apply_signed_transfer(const Address &from, const PqAccount &from_sk, const Address &to,
                               uint64_t amount, uint32_t nonce) {
        BlockBuilder b = next_block(*store, static_cast<uint64_t>(std::time(nullptr)));
        Transaction t = make_tx(from, to, amount, nonce);
        vx::crypto::pq::PqSignatureWitness w{};
        if (!vx::crypto::pq::pq_sign_transaction(t, from_sk.sk, nullptr, nullptr, &w))
            return false;
        vx::crypto::pq::PqWitnessRegistry::instance().register_witness_bytes(
            vx::crypto::pq::tx_msg_digest(t), t.sender_nfa, w);
        if (!b.add_transaction(t))
            return false;
        if (b.bind_canonical_witnesses(
                [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                    return ledger->pq_root_of(a, out);
                }) != 1u)
            return false;
        const BlockFrame f = sealed_frame(*store, b);
        if (!store->append_block(f))
            return false;
        return ledger->apply_block(BlockView(f)).ok;
    }

    bool fund_funder(uint64_t amount) {
        // The spender's balance is exactly the mint; the transfer fee comes
        // out of the same balance, so the pull must leave room for it.
        return apply_signed_transfer(spender, demo, funder.addr, amount - 10'000, 0) &&
               ledger->balance_of(funder.addr) == U128(amount - 10'000);
    }

    bool fund_vault(const SvaVault &v, uint64_t amount) {
        return apply_signed_transfer(funder.addr, funder, v.addr, amount, 0) &&
               ledger->balance_of(v.addr) == U128(amount);
    }

    /// Applies one vault-spend block. Returns "" on success, the apply
    /// error otherwise (the frame is appended then rolled back on refusal,
    /// mirroring the producer's path).
    std::string apply_spend_block(const SvaVault &v, Address receiver, uint64_t amount,
                                  uint32_t nonce, uint32_t index, uint32_t fee) {
        BlockBuilder b = next_block(*store, static_cast<uint64_t>(std::time(nullptr)));
        Transaction t = make_tx(v.addr, receiver, amount, nonce, fee);
        if (!register_sva_witness(t, v, index))
            return "witness registration refused";
        if (!b.add_transaction(t))
            return "builder full";
        if (b.bind_canonical_witnesses(
                [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                    return ledger->pq_root_of(a, out);
                }) != 1u)
            return "no witness binding";
        const BlockFrame f = sealed_frame(*store, b);
        if (!store->append_block(f))
            return "append failed";
        const auto r = ledger->apply_block(BlockView(f));
        if (!r.ok) {
            store->rollback_last_append();
            return r.error;
        }
        return std::string();
    }
};

constexpr uint64_t VX_ATOMS = 100'000'000ull;
constexpr uint64_t kSpendAmount = 20 * VX_ATOMS; // 20 VX per spend
constexpr uint64_t kSpendFee = VX_ATOMS;         // the 1 VX minimum fee

} // namespace

// -- 1. The happy path: witness registered out of band, block applies,
// value moves, the counter advances, and the undo journal carries the
// pre-block counter.
TEST(VortexSvaWiringTest, SpendAppliesAndAdvancesCounter) {
    WiringChain c("vx_svaw_spend");
    ASSERT_TRUE(c.fund_funder(GENESIS_2_MINT_ATOMICS));
    SvaVault v("vx_svaw_vault_a");
    ASSERT_TRUE(c.fund_vault(v, 50'000 * VX_ATOMS));

    const Address receiver = addr_of("VX_SVA_WIRING_RCV1");
    const std::string err = c.apply_spend_block(v, receiver, kSpendAmount, 0, 0, kSpendFee);
    ASSERT_TRUE(err.empty()) << err;

    EXPECT_EQ(c.ledger->balance_of(receiver), U128(kSpendAmount));
    // The vault paid amount + fee.
    EXPECT_EQ(c.ledger->balance_of(v.addr), U128(50'000 * VX_ATOMS - kSpendAmount - kSpendFee));
    EXPECT_EQ(c.ledger->sva_counter_of(v.addr), 1u);
}

// -- 2. Verify-before-store: a tampered preimage or path never enters the
// registry (it cannot derive the claimed vault encoding), and the apply
// refuses fail-closed without a witness.
TEST(VortexSvaWiringTest, TamperedWitnessRefused) {
    WiringChain c("vx_svaw_tamper");
    ASSERT_TRUE(c.fund_funder(GENESIS_2_MINT_ATOMICS));
    SvaVault v("vx_svaw_vault_b");
    ASSERT_TRUE(c.fund_vault(v, 50'000 * VX_ATOMS));

    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction t = make_tx(v.addr, addr_of("VX_SVA_WIRING_RCV2"), kSpendAmount, 0, kSpendFee);
    const auto digest = vx::crypto::pq::tx_msg_digest(t);

    // A one-bit flip in the preimage: the witness must derive the vault
    // root byte-for-byte, so registration refuses.
    sva::SvaPreimage bad_preimage = v.preimages[0];
    bad_preimage[0] ^= 0x01;
    EXPECT_FALSE(sva::SvaWitnessRegistry::instance().register_witness_bytes(
        digest, t.sender_nfa, bad_preimage, v.path_for(0), 0));

    // A one-bit flip in the sibling path: same refusal.
    sva::SvaMerklePath bad_path = v.path_for(0);
    bad_path[0][0] ^= 0x01;
    EXPECT_FALSE(sva::SvaWitnessRegistry::instance().register_witness_bytes(
        digest, t.sender_nfa, v.preimages[0], bad_path, 0));

    // A wrong index: the leaf binds to its position, so a valid preimage
    // with a foreign index derives the wrong root and is refused.
    EXPECT_FALSE(sva::SvaWitnessRegistry::instance().register_witness_bytes(
        digest, t.sender_nfa, v.preimages[1], v.path_for(0), 0));

    // The tx now enters the frame with NO witness in the registry: the
    // producer's canonical binding is empty and the apply refuses.
    ASSERT_TRUE(b.add_transaction(t));
    EXPECT_EQ(b.bind_canonical_witnesses(
                  [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                      return c.ledger->pq_root_of(a, out);
                  }),
              0u);
    const BlockFrame f = sealed_frame(*c.store, b);
    // Intake layer: the witness-root gate refuses the frame before it can
    // enter the chain (the registry has no entry for this digest).
    EXPECT_FALSE(c.store->append_block(f));
    // Ledger layer (defense in depth): even if the frame had made it past
    // intake — a diverged sidecar, an evicted entry — the apply refuses
    // fail-closed and nothing is debited.
    const auto r = c.ledger->apply_block(BlockView(f));
    EXPECT_FALSE(r.ok);
    EXPECT_NE(r.error.find("no SVA spend witness"), std::string::npos) << r.error;
    // Nothing changed: the counter is still 0, the vault keeps its funds.
    EXPECT_EQ(c.ledger->sva_counter_of(v.addr), 0u);
    EXPECT_EQ(c.ledger->balance_of(v.addr), U128(50'000 * VX_ATOMS));
}

// -- 3. Out-of-order leaf: a valid witness for leaf #1 lands while the
// vault's counter is 0 — registration succeeds (it derives the vault) but
// the apply refuses on the counter binding.
TEST(VortexSvaWiringTest, OutOfOrderIndexRefused) {
    WiringChain c("vx_svaw_order");
    ASSERT_TRUE(c.fund_funder(GENESIS_2_MINT_ATOMICS));
    SvaVault v("vx_svaw_vault_c");
    ASSERT_TRUE(c.fund_vault(v, 50'000 * VX_ATOMS));

    const std::string err =
        c.apply_spend_block(v, addr_of("VX_SVA_WIRING_RCV3"), kSpendAmount, 0, 1, kSpendFee);
    EXPECT_NE(err.find("out of order"), std::string::npos) << err;
    EXPECT_EQ(c.ledger->sva_counter_of(v.addr), 0u);
    EXPECT_EQ(c.ledger->balance_of(v.addr), U128(50'000 * VX_ATOMS));
}

// -- 4. The anti-dust gate: a vault below the 1000 VX minimum cannot move
// value at all (the gate binds the PRE-debit balance).
TEST(VortexSvaWiringTest, MinBalanceGateRefused) {
    WiringChain c("vx_svaw_minbal");
    ASSERT_TRUE(c.fund_funder(GENESIS_2_MINT_ATOMICS));
    SvaVault v("vx_svaw_vault_d");
    ASSERT_TRUE(c.fund_vault(v, 999 * VX_ATOMS));

    const std::string err =
        c.apply_spend_block(v, addr_of("VX_SVA_WIRING_RCV4"), kSpendAmount, 0, 0, kSpendFee);
    EXPECT_NE(err.find("below the 1000 VX minimum"), std::string::npos) << err;
    EXPECT_EQ(c.ledger->sva_counter_of(v.addr), 0u);
}

// -- 5. The burn-fee gate: a vault spend pays at least 1 VX of fee.
TEST(VortexSvaWiringTest, FeeGateRefused) {
    WiringChain c("vx_svaw_fee");
    ASSERT_TRUE(c.fund_funder(GENESIS_2_MINT_ATOMICS));
    SvaVault v("vx_svaw_vault_e");
    ASSERT_TRUE(c.fund_vault(v, 50'000 * VX_ATOMS));

    const std::string err =
        c.apply_spend_block(v, addr_of("VX_SVA_WIRING_RCV5"), kSpendAmount, 0, 0, kSpendFee - 1);
    EXPECT_NE(err.find("fee below the minimum"), std::string::npos) << err;
    EXPECT_EQ(c.ledger->sva_counter_of(v.addr), 0u);
}

// -- 6. Exhaustion → tombstone: 256 spends advance the counter to the
// cap; a further spend (even with a valid witness for the last leaf)
// refuses on the tombstone gate.
TEST(VortexSvaWiringTest, ExhaustionTombstone) {
    WiringChain c("vx_svaw_tomb");
    ASSERT_TRUE(c.fund_funder(GENESIS_2_MINT_ATOMICS));
    SvaVault v("vx_svaw_vault_t");
    ASSERT_TRUE(c.fund_vault(v, 50'000 * VX_ATOMS));

    const Address receiver = addr_of("VX_SVA_WIRING_TOMB_RCV");
    for (uint32_t i = 0; i < sva::kSvaMaxSpends; ++i) {
        const std::string err = c.apply_spend_block(v, receiver, kSpendAmount, i, i, kSpendFee);
        ASSERT_TRUE(err.empty()) << "spend " << i << ": " << err;
        EXPECT_EQ(c.ledger->sva_counter_of(v.addr), i + 1u);
    }
    // The vault is spent out: 256 × (20 VX + 1 VX fee).
    EXPECT_EQ(c.ledger->balance_of(v.addr), U128(50'000 * VX_ATOMS - 256 * 21 * VX_ATOMS));

    // A further spend re-using the LAST leaf's witness: the counter gate
    // fires first — the tombstone. The probe tx is byte-identical to the
    // 256th spend (nonce 255, leaf 255): a fresh nonce would mint a fresh
    // digest whose witness registration is refused by the per-sender cap
    // (256) before the ledger's tombstone gate is ever reached. The
    // identical tx dedups in the registry (same digest, same content), so
    // the lookup hits the existing entry and the tombstone gate fires.
    const std::string err = c.apply_spend_block(v, receiver, kSpendAmount, sva::kSvaMaxSpends - 1,
                                                sva::kSvaMaxSpends - 1, kSpendFee);
    EXPECT_NE(err.find("tombstone"), std::string::npos) << err;
    EXPECT_EQ(c.ledger->sva_counter_of(v.addr), 256u);
}

// -- 7. Counter persistence: a fresh LedgerState replaying the block
// store rebuilds the exact counter state (no restart desync).
TEST(VortexSvaWiringTest, CounterSurvivesRestart) {
    WiringChain c("vx_svaw_replay");
    ASSERT_TRUE(c.fund_funder(GENESIS_2_MINT_ATOMICS));
    SvaVault v("vx_svaw_vault_r");
    ASSERT_TRUE(c.fund_vault(v, 50'000 * VX_ATOMS));

    const Address receiver = addr_of("VX_SVA_WIRING_RCV7");
    ASSERT_TRUE(c.apply_spend_block(v, receiver, kSpendAmount, 0, 0, kSpendFee).empty());
    ASSERT_TRUE(c.apply_spend_block(v, receiver, kSpendAmount, 1, 1, kSpendFee).empty());
    ASSERT_TRUE(c.apply_spend_block(v, receiver, kSpendAmount, 2, 2, kSpendFee).empty());
    ASSERT_EQ(c.ledger->sva_counter_of(v.addr), 3u);

    // A fresh ledger replaying the whole chain from the store must land
    // on the same counter and balances.
    auto replayed = std::make_unique<vx::state::LedgerState>();
    for (uint64_t h = 0; h < c.store->chain_height(); ++h) {
        const auto *g = c.store->get_block(h);
        ASSERT_NE(g, nullptr) << "height " << h;
        BlockFrame gf;
        std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
        const auto r = replayed->apply_block(BlockView(gf));
        ASSERT_TRUE(r.ok) << "replay height " << h << ": " << r.error;
    }
    EXPECT_EQ(replayed->sva_counter_of(v.addr), 3u);
    EXPECT_EQ(replayed->balance_of(v.addr), c.ledger->balance_of(v.addr));
    EXPECT_EQ(replayed->balance_of(receiver), c.ledger->balance_of(receiver));
}

// -- 8. Reorg rollback: the undo journal restores the exact pre-block
// counter (and balances) when the fork point is abandoned.
TEST(VortexSvaWiringTest, ReorgRollbackRestoresCounter) {
    WiringChain c("vx_svaw_undo");
    ASSERT_TRUE(c.fund_funder(GENESIS_2_MINT_ATOMICS));
    SvaVault v("vx_svaw_vault_u");
    ASSERT_TRUE(c.fund_vault(v, 50'000 * VX_ATOMS));

    const uint64_t fork_height = c.store->chain_height();
    const U128 vault_before = c.ledger->balance_of(v.addr);
    const U128 rcv_before = c.ledger->balance_of(addr_of("VX_SVA_WIRING_RCV8"));

    vx::state::UndoEngine undo(c.dir, *c.store, *c.ledger);

    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction t = make_tx(v.addr, addr_of("VX_SVA_WIRING_RCV8"), kSpendAmount, 0, kSpendFee);
    ASSERT_TRUE(register_sva_witness(t, v, 0));
    ASSERT_TRUE(b.add_transaction(t));
    ASSERT_EQ(b.bind_canonical_witnesses(
                  [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                      return c.ledger->pq_root_of(a, out);
                  }),
              1u);
    const BlockFrame f = sealed_frame(*c.store, b);
    undo.apply_block(BlockView(f));
    const auto r = c.ledger->apply_block(BlockView(f));
    ASSERT_TRUE(r.ok) << r.error;
    ASSERT_EQ(r.sva_undo.size(), 1u);
    EXPECT_EQ(r.sva_undo[0].vault, v.addr);
    EXPECT_EQ(r.sva_undo[0].prev_counter, 0u);
    EXPECT_FALSE(r.sva_undo[0].existed);
    undo.record_sva_undo(reinterpret_cast<const RawBlock *>(f.data())->header.block_height,
                         r.sva_undo);
    undo.commit_undo_point();
    ASSERT_TRUE(c.store->append_block(f));

    // The block applied: counter 1, funds moved.
    EXPECT_EQ(c.ledger->sva_counter_of(v.addr), 1u);

    // Roll the fork point away: the counter returns to 0 and the funds
    // return to the vault (the spend block sat at height fork_height, so
    // the rollback target is one below it).
    ASSERT_TRUE(undo.rollback_to_height(fork_height - 1));
    // The ledger is reversed; the fork frame must leave the store too
    // (rollback_to_height does not truncate the file — the caller does).
    ASSERT_TRUE(c.store->rollback_last_append());
    EXPECT_EQ(c.ledger->sva_counter_of(v.addr), 0u);
    EXPECT_EQ(c.ledger->balance_of(v.addr), vault_before);
    EXPECT_EQ(c.ledger->balance_of(addr_of("VX_SVA_WIRING_RCV8")), rcv_before);

    // The vault can spend again from leaf 0 — the burned leaf is restored.
    const std::string err =
        c.apply_spend_block(v, addr_of("VX_SVA_WIRING_RCV9"), kSpendAmount, 0, 0, kSpendFee);
    EXPECT_TRUE(err.empty()) << err;
    EXPECT_EQ(c.ledger->sva_counter_of(v.addr), 1u);
}
