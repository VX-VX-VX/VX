// test_genesis_vesting.cpp -- founder allocation unlock schedule
// (owner-directed 2026-11-15; pre-genesis consensus commit).
//
// 21,000,000 VX credited at genesis, a 6-month cliff, then a linear
// release over 36 months — exact to the atom via (elapsed × TOTAL) / VEST
// with a compile-time VEST divisor (the compiler lowers it into
// multiply-high+shift; the build pipeline objdump-verifies that no
// div/idiv lands in the emitted consensus path). The schedule is bound to
// the ADDRESS and the HEIGHT only, so the founder address can go through
// its XMSS rollover rotations (16-leaf trees) without touching the unlock
// math.

#include <gtest/gtest.h>
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/blockchain/vesting.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/storage/block_store.hpp"

#include <cstdint>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <memory>

using namespace vx::blockchain;
using vx::core::U128;

namespace {

// A test account bound to a post-quantum WOTS+/XMSS key: the address is
// SELF-CERTIFYING ("PQA" + base64url of Sponge("VXPQADDRV1" || root)), so
// holding the key IS holding the address.
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

Address addr_of(const std::string &s) {
    Address a{};
    std::memcpy(a.data(), s.data(), s.size() < 42 ? s.size() : 42);
    return a;
}

} // namespace

TEST(GenesisVestingTest, CliffHoldsEverythingLocked) {
    EXPECT_EQ(founder_unlocked_atoms(0).lo, 0u);
    EXPECT_EQ(founder_unlocked_atoms(FOUNDER_CLIFF_BLOCKS - 1).lo, 0u);
    EXPECT_EQ(founder_unlocked_atoms(FOUNDER_CLIFF_BLOCKS).lo, 0u)
        << "the cliff block itself is still locked (elapsed == 0)";
    // One block past the cliff the linear rate is already ~1.126 VX — the
    // per-block release is finer than one whole VX, and the u128 math is
    // exact to the atom (integer-VX vesting would have lost this block
    // entirely to truncation).
    EXPECT_EQ(founder_unlocked_atoms(FOUNDER_CLIFF_BLOCKS + 1).lo,
              FOUNDER_ALLOCATION_ATOMS / FOUNDER_VEST_BLOCKS);
    EXPECT_GT(founder_unlocked_atoms(FOUNDER_CLIFF_BLOCKS + 1).lo, 100'000'000ULL);
}

TEST(GenesisVestingTest, LinearReleaseExactToTheAtom) {
    // A quarter into the window: exactly a quarter of the allocation.
    const uint64_t quarter = FOUNDER_CLIFF_BLOCKS + FOUNDER_VEST_BLOCKS / 4;
    const uint64_t q = founder_unlocked_atoms(quarter).lo;
    EXPECT_EQ(q, FOUNDER_ALLOCATION_ATOMS / 4);
    // Halfway.
    const uint64_t half = FOUNDER_CLIFF_BLOCKS + FOUNDER_VEST_BLOCKS / 2;
    EXPECT_EQ(founder_unlocked_atoms(half).lo, FOUNDER_ALLOCATION_ATOMS / 2);
    // Monotone non-decreasing across the whole window.
    uint64_t prev = 0;
    for (uint64_t h = FOUNDER_CLIFF_BLOCKS; h < FOUNDER_CLIFF_BLOCKS + FOUNDER_VEST_BLOCKS;
         h += (FOUNDER_VEST_BLOCKS / 512)) {
        const uint64_t u = founder_unlocked_atoms(h).lo;
        ASSERT_GE(u, prev);
        ASSERT_LE(u, FOUNDER_ALLOCATION_ATOMS);
        prev = u;
    }
}

TEST(GenesisVestingTest, FullyVestedAndSaturated) {
    const uint64_t end = FOUNDER_CLIFF_BLOCKS + FOUNDER_VEST_BLOCKS;
    EXPECT_EQ(founder_unlocked_atoms(end).lo, FOUNDER_ALLOCATION_ATOMS);
    EXPECT_EQ(founder_unlocked_atoms(end + 1'000'000).lo, FOUNDER_ALLOCATION_ATOMS);
    EXPECT_EQ(founder_unlocked_atoms(0xffffffffffffffffULL).hi, 0u);
    EXPECT_EQ(founder_unlocked_atoms(0xffffffffffffffffULL).lo, FOUNDER_ALLOCATION_ATOMS);
    // u128 sanity: the unlock never carries a high limb.
    EXPECT_EQ(founder_unlocked_atoms(end).hi, 0u);
}

TEST(GenesisVestingTest, ScheduleConstantsMatchTheApprovedPlan) {
    // 5-second pulse: 6 months = 3,110,400 blocks; 36 months = 18,662,400.
    EXPECT_EQ(FOUNDER_CLIFF_BLOCKS, 3'110'400u);
    EXPECT_EQ(FOUNDER_VEST_BLOCKS, 18'662'400u);
    EXPECT_EQ(FOUNDER_ALLOCATION_ATOMS, 2'100'000'000'000'000ULL);
    // The per-block rate after the cliff (~1.126 VX/block — the market
    // barely notices; reviewer-checked scale).
    const double per_block = (double)FOUNDER_ALLOCATION_ATOMS / (double)FOUNDER_VEST_BLOCKS;
    EXPECT_NEAR(per_block / 1e8, 1.126, 0.001);
}

// ── The LEDGER gate (fork-review requirement, owner-directed 2026-11-15) ──
// The unlock schedule above is advisory until the ledger enforces it. The
// gate is a locked floor on the balance AFTER each debit: the allocation
// may leave the founder address only along the curve, income the founder
// address earns BEYOND the allocation (mining fees, incoming transfers)
// stays freely spendable even before the cliff, and an empty gate address
// disables the check entirely (pre-genesis default = vacuum-true).
//
// The demo genesis.bin predates the allocation, so the test credits the
// founder the way the production mainnet genesis will: a GENESIS_ mint of
// the full allocation plus a small earned extra, applied at height 0.
TEST(GenesisVestingTest, LedgerGateEnforcesTheUnlockFloor) {
    vx::state::LedgerState ledger;
    const PqAccount founder = make_pq_account("VX_FOUNDER_21M_SK_V1");
    const Address sink = addr_of("NFA_VESTING_SINK_000000000000000000000000000000");

    // Height-0 genesis: the allocation + the earned extra, both to the
    // founder address (exactly the shape the mainnet genesis will carry).
    {
        BlockBuilder b;
        b.set_height(0);
        b.set_timestamp(1'700'000'000);
        std::array<uint8_t, 384> coords{};
        b.set_attractor_coords(coords.data());
        Transaction alloc{};
        std::memcpy(alloc.sender_nfa, "GENESIS_ALLOCATION", 18);
        std::memcpy(alloc.receiver_nfa, founder.addr.data(), 42);
        tx_set_amount(alloc, FOUNDER_ALLOCATION_ATOMS);
        sign_transaction(alloc); // system sender: structural digest only
        Transaction extra = alloc;
        tx_set_amount(extra, 500);
        sign_transaction(extra);
        ASSERT_TRUE(b.add_transaction(alloc));
        ASSERT_TRUE(b.add_transaction(extra));
        b.finalize();
        BlockFrame gf;
        std::memcpy(gf.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
        const auto res = ledger.apply_block(BlockView(gf));
        ASSERT_TRUE(res.ok) << "genesis apply failed: " << res.error;
    }
    ASSERT_EQ(ledger.balance_of(founder.addr), U128(FOUNDER_ALLOCATION_ATOMS + 500));
    ledger.set_founder_vesting_address(founder.addr);

    // The one helper the four pins below share: a sealed single-spend
    // frame at the given height (PoGW work is an intake-gate concern, not
    // a ledger one — the ledger applies the frame the producer would hand
    // over after sealing).
    auto spend_frame = [&](uint64_t h, uint64_t amount, uint32_t nonce) {
        BlockBuilder b;
        b.set_height(h);
        b.set_timestamp(1'700'000'000 + h * 5);
        std::array<uint8_t, 384> coords{};
        b.set_attractor_coords(coords.data());
        Transaction tx{};
        std::memcpy(tx.sender_nfa, founder.addr.data(), 42);
        std::memcpy(tx.receiver_nfa, sink.data(), 42);
        tx_set_amount(tx, amount);
        tx_set_fee(tx, 100);
        tx_set_nonce(tx, nonce);
        EXPECT_TRUE(vx::crypto::pq::pq_sign_transaction(tx, founder.sk));
        EXPECT_TRUE(b.add_transaction(tx));
        b.bind_canonical_witnesses(
            [&ledger](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                return ledger.pq_root_of(a, out);
            });
        b.finalize();
        BlockFrame f;
        std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
        return f;
    };

    // PIN 1 — before the cliff the ALLOCATION is immovable: a 1 VX spend
    // is refused by name, and the refusal is transactional (no balance,
    // no nonce, no height move — the retry block below reuses height 1).
    {
        BlockFrame f = spend_frame(1, 100'000'000, 0);
        const auto res = ledger.apply_block(BlockView(f));
        EXPECT_FALSE(res.ok) << "a pre-cliff allocation spend was accepted!";
        EXPECT_NE(res.error.find("founder allocation locked"), std::string::npos)
            << "expected the vesting refusal, got: " << res.error;
        EXPECT_EQ(ledger.balance_of(founder.addr), U128(FOUNDER_ALLOCATION_ATOMS + 500));
        EXPECT_EQ(ledger.get_next_nonce(founder.addr), 0u);
        EXPECT_EQ(ledger.next_expected_height(), 1u);
    }

    // PIN 2 — income BEYOND the allocation spends freely EVEN before the
    // cliff: the fee-inclusive cost of the 500 earned atoms is exactly the
    // extra, so the floor (which binds only the allocation) never sees it.
    {
        BlockFrame f = spend_frame(1, 400, 0);
        EXPECT_TRUE(ledger.apply_block(BlockView(f)).ok);
        EXPECT_EQ(ledger.balance_of(founder.addr), U128(FOUNDER_ALLOCATION_ATOMS));
        EXPECT_EQ(ledger.balance_of(sink), U128(400));
    }

    // PIN 3 — at the first post-cliff height the founder may move exactly
    // the unlocked atoms: the spend lands on the locked floor with ZERO
    // headroom (balance - total_cost == locked) and must still pass.
    {
        const uint64_t h = FOUNDER_CLIFF_BLOCKS + 1;
        ledger.set_next_height(h); // the public reorg hook: state is
                                   // height-keyed only through the schedule
        const uint64_t unlocked = founder_unlocked_atoms(h).lo;
        ASSERT_GT(unlocked, 100u);
        BlockFrame f = spend_frame(h, unlocked - 100, 1);
        EXPECT_TRUE(ledger.apply_block(BlockView(f)).ok);
        EXPECT_EQ(ledger.balance_of(sink), U128(400 + unlocked - 100))
            << "sink holds the PIN 2 extra plus the unlocked spend";
        EXPECT_EQ(ledger.balance_of(founder.addr), U128(FOUNDER_ALLOCATION_ATOMS - unlocked))
            << "the exact-boundary spend must leave exactly the locked floor";
    }

    // PIN 4 — the floor tracks the SCHEDULE: between blocks the unlock
    // curve only advances, so the founder's headroom resets to the matured
    // delta, and ANY debit that digs one atom below the NEW floor is
    // refused. The hostile frame tries to move the whole newly-matured
    // delta as amount and pay the fee out of locked territory.
    {
        const uint64_t h = FOUNDER_CLIFF_BLOCKS + 2;
        ledger.set_next_height(h);
        const uint64_t unlocked_now = founder_unlocked_atoms(h).lo;
        const uint64_t matured = unlocked_now - founder_unlocked_atoms(h - 1).lo;
        // Balance sits exactly on the cliff+1 floor; the matured delta is
        // the ONLY new headroom. Spending the delta amount itself plus a
        // fee is 100 atoms below the new floor.
        ASSERT_GT(matured, 100u);
        BlockFrame f = spend_frame(h, matured, 2);
        const auto res = ledger.apply_block(BlockView(f));
        EXPECT_FALSE(res.ok) << "a spend past the floor was accepted!";
        EXPECT_NE(res.error.find("founder allocation locked"), std::string::npos)
            << "expected the vesting refusal, got: " << res.error;
        EXPECT_EQ(
            ledger.balance_of(founder.addr),
            U128(FOUNDER_ALLOCATION_ATOMS - founder_unlocked_atoms(FOUNDER_CLIFF_BLOCKS + 1).lo));
        // And the honest alternative IS accepted: the fee-inclusive cost
        // of the honest frame is exactly the matured delta — it lands on
        // the new floor with zero headroom and still passes.
        BlockFrame good = spend_frame(h, matured - 100, 2);
        EXPECT_TRUE(ledger.apply_block(BlockView(good)).ok);
        EXPECT_EQ(ledger.balance_of(founder.addr), U128(FOUNDER_ALLOCATION_ATOMS - unlocked_now));
    }
}

// ── Ledger-level gate (fork review 2026-11-15, must-fix #2) ──────────────────
// The vesting gate must be WIRED into the spend path, not a paper schedule.
// The security-critical pin: a spend that would dip the founder balance
// below the locked remainder is REFUSED outright, and a refused spend
// mutates nothing. The chain helpers below are the proven end-to-end flow
// (genesis replay → GENESIS_2 mint → funded accounts with real PQ
// witnesses). The allowance direction is compositional: at full vesting
// the locked floor is zero (pinned by the pure-math tests above) and the
// gate comparison vacuums.
namespace {

std::string vest_temp_dir(const char *tag) {
    auto dir = std::filesystem::temp_directory_path() /
               (std::string(tag) + "_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    return dir.string();
}

Address vest_addr_of(const std::string &s) {
    Address a{};
    std::memcpy(a.data(), s.data(), s.size() < 42 ? s.size() : 42);
    return a;
}

struct VestPqAccount {
    std::array<uint8_t, 32> sk{};
    std::array<uint8_t, 32> root{};
    Address addr{};
};

VestPqAccount vest_pq_account(const char *tag) {
    VestPqAccount acc;
    VortexSponge256::compute(reinterpret_cast<const uint8_t *>(tag), std::strlen(tag),
                             acc.sk.data());
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(acc.sk);
    acc.root = vx::crypto::pq::xmss_root(acc.sk, pub_seed);
    derive_pq_address(acc.root.data(), acc.addr.data());
    return acc;
}

Transaction vest_tx(const Address &sender, const Address &receiver, uint64_t amount,
                    uint32_t nonce) {
    Transaction tx{};
    std::memcpy(tx.sender_nfa, sender.data(), 42);
    std::memcpy(tx.receiver_nfa, receiver.data(), 42);
    tx_set_amount(tx, amount);
    tx_set_fee(tx, 100);
    tx_set_nonce(tx, nonce);
    return tx;
}

BlockBuilder vest_next_block(vx::storage::BlockStore &store, uint64_t ts) {
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

BlockFrame vest_sealed(vx::storage::BlockStore &store, BlockBuilder &b) {
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    EXPECT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
    return f;
}

struct VestChain {
    std::string dir;
    std::unique_ptr<vx::storage::BlockStore> store;
    std::unique_ptr<vx::state::LedgerState> ledger;
    VestPqAccount demo{};
    Address spender{};

    explicit VestChain(const char *tag) : dir(vest_temp_dir(tag)) {
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
        demo = vest_pq_account("VX_DEMO_SPENDER_SK_V1");
        spender = genesis2_mint_receiver_payload();

        BlockBuilder b = vest_next_block(*store, (uint64_t)std::time(nullptr));
        Transaction mint = vest_tx(vest_addr_of("GENESIS_2"), spender, GENESIS_2_MINT_ATOMICS, 0);
        sign_transaction(mint);
        if (!b.add_transaction(mint)) {
            ADD_FAILURE();
            return;
        }
        const BlockFrame f = vest_sealed(*store, b);
        if (!store->append_block(f)) {
            ADD_FAILURE();
            return;
        }
        if (!ledger->apply_block(BlockView(f)).ok) {
            ADD_FAILURE();
            return;
        }
    }

    ~VestChain() {
        std::filesystem::remove_all(dir);
    }

    VestPqAccount fund_new_account(const char *tag, uint64_t amount) {
        VestPqAccount acc = vest_pq_account(tag);
        BlockBuilder b = vest_next_block(*store, (uint64_t)std::time(nullptr));
        Transaction t = vest_tx(spender, acc.addr, amount, 0);
        vx::crypto::pq::PqSignatureWitness w{};
        if (!vx::crypto::pq::pq_sign_transaction(t, demo.sk, nullptr, nullptr, &w)) {
            ADD_FAILURE();
            return acc;
        }
        vx::crypto::pq::PqWitnessRegistry::instance().register_witness_bytes(
            vx::crypto::pq::tx_msg_digest(t), t.sender_nfa, w);
        if (!b.add_transaction(t)) {
            ADD_FAILURE();
            return acc;
        }
        EXPECT_EQ(b.bind_canonical_witnesses(
                      [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                          return ledger->pq_root_of(a, out);
                      }),
                  1u);
        const BlockFrame f = vest_sealed(*store, b);
        if (!store->append_block(f)) {
            ADD_FAILURE();
            return acc;
        }
        if (!ledger->apply_block(BlockView(f)).ok) {
            ADD_FAILURE();
            return acc;
        }
        return acc;
    }
};

} // namespace

TEST(VortexGenesisVestingTest, LedgerGateRefusesBeforeCliff) {
    VestChain c("vx_vesting_gate");
    VestPqAccount founder = c.fund_new_account("VX_VESTING_FOUNDER_SK", 40'000'000'000u);
    VestPqAccount buddy = vest_pq_account("VX_VESTING_BUDDY_SK");

    // Arm the gate on the funded founder.
    c.ledger->set_founder_vesting_address(founder.addr);

    // A 30 VX spend pre-cliff: balance after = 10 VX - fee, far below the
    // locked floor (the FULL allocation pre-cliff) — refused, nothing moved.
    BlockBuilder b = vest_next_block(*c.store, (uint64_t)std::time(nullptr));
    Transaction t = vest_tx(founder.addr, buddy.addr, 30'000'000'000ull, 0);
    vx::crypto::pq::PqSignatureWitness w{};
    ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(t, founder.sk, nullptr, nullptr, &w));
    vx::crypto::pq::PqWitnessRegistry::instance().register_witness_bytes(
        vx::crypto::pq::tx_msg_digest(t), t.sender_nfa, w);
    ASSERT_TRUE(b.add_transaction(t));
    EXPECT_EQ(b.bind_canonical_witnesses(
                  [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                      return c.ledger->pq_root_of(a, out);
                  }),
              1u);
    const BlockFrame f = vest_sealed(*c.store, b);
    ASSERT_TRUE(c.store->append_block(f));
    const auto res = c.ledger->apply_block(BlockView(f));
    EXPECT_FALSE(res.ok) << "a pre-cliff spend past the locked floor must be refused";
    EXPECT_NE(res.error.find("founder allocation locked"), std::string::npos) << res.error;
    EXPECT_EQ(c.ledger->balance_of(founder.addr), U128(40'000'000'000ull))
        << "a refused spend must not mutate balances";
}
