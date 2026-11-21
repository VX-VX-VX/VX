// SVA-8192 zero-day regression suite (vx-zeroday first run, 2026-11-21).
//
// Three findings with runnable PoCs driving the production paths
// (wire-shaped registration + LedgerState::apply_block). Harness copied
// from tests/test_sva_wiring.cpp (WiringChain/SvaVault). Each test ran
// GREEN against the pre-fix tree (the bug reproduced), then flipped to
// assert the fixed behavior — the attack scenarios are documented in
// archives/notes/zeroday-pocs/zeroday-hunt-report-2026-11-21.md.
//
//   1. Digest poisoning (CWE-345): a hostile first-arriver that derives
//      ITS OWN vault (passes verify-before-store) must NOT lock the
//      honest owner's witness out of the digest slot. Pre-fix, the
//      first-come-wins refusal poisoned the digest durably (fsync'd
//      sidecar) and the dependent block refused on every poisoned node.
//      Fixed: entries are keyed by (digest, sender); the apply-time
//      lookup selects by the claimed sender.
//
//   2. Registry saturation (CWE-400): kSvaMaxWitnessEntries (16384) with
//      no per-sender cap let 16384 self-vault registrations (22 MB) fill
//      the map permanently and censor all new vault spends. Fixed: a
//      per-sender cap stops the flood; at the global cap the OLDEST entry
//      is evicted, so honest witnesses are never permanently blocked.
//
//   3. Torn tail (CWE-367): a crash mid-append left a torn half-record;
//      the pre-fix code appended BEHIND the tear (O_APPEND) and the
//      replay — which stops at the tear — stranded every later witness.
//      Fixed: appends are positioned at the logical end (pwrite +
//      ftruncate), healing the tear at the first append after a crash.
#include <gtest/gtest.h>

#include "vx/blockchain/block.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/blockchain/sva_vault.hpp"
#include "vx/blockchain/sva_witness.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/storage/block_store.hpp"

#include <cstring>
#include <ctime>
#include <fcntl.h>
#include <filesystem>
#include <fstream>
#include <memory>
#include <string>
#include <unistd.h>
#include <vector>

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

// A funded chain: genesis replayed, protocol mint applied, PQ funder.
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
    }

    // mint block: GENESIS_2 -> spender (the wiring harness's funding step).
    void apply_mint_block() {
        BlockBuilder b = next_block(*store, static_cast<uint64_t>(std::time(nullptr)));
        Transaction mint = make_tx(addr_of("GENESIS_2"), spender, GENESIS_2_MINT_ATOMICS, 0);
        sign_transaction(mint);
        if (!b.add_transaction(mint))
            ADD_FAILURE();
        const BlockFrame f = sealed_frame(*store, b);
        if (!store->append_block(f) || !ledger->apply_block(BlockView(f)).ok)
            ADD_FAILURE();
    }

    // The generic signed transfer used to fund the funder and the vault.
    bool apply_signed_transfer(const Address &from, const PqAccount &from_sk, const Address &to,
                               uint64_t amount, uint32_t nonce) {
        BlockBuilder b = next_block(*store, static_cast<uint64_t>(std::time(nullptr)));
        Transaction t = make_tx(from, to, amount, nonce);
        vx::crypto::pq::PqSignatureWitness w{};
        if (!vx::crypto::pq::pq_sign_transaction(t, from_sk.sk, nullptr, nullptr, &w)) {
            std::fprintf(stderr, "[ZD] transfer: sign failed\n");
            return false;
        }
        vx::crypto::pq::PqWitnessRegistry::instance().register_witness_bytes(
            vx::crypto::pq::tx_msg_digest(t), t.sender_nfa, w);
        if (!b.add_transaction(t)) {
            std::fprintf(stderr, "[ZD] transfer: add_transaction failed\n");
            return false;
        }
        if (b.bind_canonical_witnesses(
                [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                    return ledger->pq_root_of(a, out);
                }) != 1u) {
            std::fprintf(stderr, "[ZD] transfer: bind_canonical_witnesses != 1\n");
            return false;
        }
        const BlockFrame f = sealed_frame(*store, b);
        if (!store->append_block(f)) {
            std::fprintf(stderr, "[ZD] transfer: append_block failed\n");
            return false;
        }
        const auto r = ledger->apply_block(BlockView(f));
        if (!r.ok)
            std::fprintf(stderr, "[ZD] transfer: apply failed: %s\n", r.error.c_str());
        return r.ok;
    }

    bool fund_funder(uint64_t amount) {
        return apply_signed_transfer(spender, demo, funder.addr, amount - 10'000, 0) &&
               ledger->balance_of(funder.addr) == U128(amount - 10'000);
    }

    bool fund_vault(const SvaVault &v, uint64_t amount) {
        return apply_signed_transfer(funder.addr, funder, v.addr, amount, 0) &&
               ledger->balance_of(v.addr) == U128(amount);
    }
};

constexpr uint64_t VX_ATOMS = 100'000'000ull;
constexpr uint64_t kSpendAmount = 20 * VX_ATOMS;
constexpr uint64_t kSpendFee = VX_ATOMS;

} // namespace

// ── Finding 1: witness-registry digest poisoning (CWE-345) ───────────────────
// Pre-fix: the attacker's witness (their own vault — passes
// verify-before-store) arrived first for digest D and locked the honest
// owner out: the registry refused the owner's witness as a conflict, the
// dependent block refused at apply ("no SVA spend witness") and the poison
// persisted in the durable sidecar.
// Fixed: entries are keyed by (digest, sender) — both witnesses coexist,
// the apply-time lookup selects by the claimed sender, and the owner's
// block applies.
TEST(SvaZerodayTest, DigestPoisoningNeutralized) {
    WiringChain c("vx_zd_poison");
    c.apply_mint_block();
    ASSERT_TRUE(c.fund_funder(GENESIS_2_MINT_ATOMICS));
    SvaVault owner("vx_zd_owner_vault");
    SvaVault attacker("vx_zd_attacker_vault");
    ASSERT_TRUE(c.fund_vault(owner, 50'000 * VX_ATOMS));

    // The owner's spend tx: digest D.
    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction t = make_tx(owner.addr, addr_of("VX_ZD_RCV"), kSpendAmount, 0, kSpendFee);
    const auto digest = vx::crypto::pq::tx_msg_digest(t);

    // Attack step 1: the attacker's witness for digest D arrives FIRST —
    // it derives the attacker's vault (verify-before-store passes) and is
    // stored under its own (digest, sender) key.
    EXPECT_TRUE(sva::SvaWitnessRegistry::instance().register_witness_bytes(
        digest, attacker.addr.data(), attacker.preimages[0], attacker.path_for(0), 0));

    // Attack step 2: the honest owner's witness for the same digest arrives
    // — stored under a DIFFERENT sender key, never refused as a conflict.
    EXPECT_TRUE(sva::SvaWitnessRegistry::instance().register_witness_bytes(
        digest, owner.addr.data(), owner.preimages[0], owner.path_for(0), 0));

    // The apply-time lookup selects by the claimed sender: the poison
    // cannot shadow the owner's entry.
    sva::SvaWitnessEntry got{};
    ASSERT_TRUE(sva::SvaWitnessRegistry::instance().lookup(digest, owner.addr.data(), got));
    EXPECT_EQ(got.root, owner.root);
    ASSERT_TRUE(sva::SvaWitnessRegistry::instance().lookup(digest, attacker.addr.data(), got));
    EXPECT_EQ(got.root, attacker.root);

    // The owner's block applies: the registry serves the owner's entry.
    ASSERT_TRUE(b.add_transaction(t));
    ASSERT_EQ(b.bind_canonical_witnesses(
                  [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                      return c.ledger->pq_root_of(a, out);
                  }),
              1u);
    const BlockFrame f = sealed_frame(*c.store, b);
    EXPECT_TRUE(c.store->append_block(f));
    const auto r = c.ledger->apply_block(BlockView(f));
    EXPECT_TRUE(r.ok) << r.error;
    EXPECT_EQ(c.ledger->balance_of(addr_of("VX_ZD_RCV")), U128(kSpendAmount));
}

// ── Finding 3: durable sidecar torn tail (CWE-367) ───────────────────────────
// Pre-fix: a crash mid-append left a torn half-record; the O_APPEND
// append landed BEHIND the tear, and the replay — which stops at the tear
// — never loaded the witnesses recorded after it. Fixed: appends are
// positioned at the logical end (pwrite + ftruncate), healing the tear at
// the first append after a crash.
TEST(SvaZerodayTest, TornTailHealedByNextAppend) {
    const std::string dir = temp_dir("vx_zd_torn");
    const std::string sidecar = dir + "/node.svaw";
    constexpr size_t kDurableRecSize = 8 + 32 + 42 + 32 + 1024 + 256 + 4;

    // Record 1: a valid witness for vault A (digest 0xAB..).
    SvaVault va("vx_zd_torn_vault_a");
    std::array<uint8_t, 32> d1{};
    d1.fill(0xAB);
    sva::SvaWitnessRegistry::instance().attach_durable_log(sidecar);
    EXPECT_TRUE(sva::SvaWitnessRegistry::instance().register_witness_bytes(
        d1, va.addr.data(), va.preimages[0], va.path_for(0), 0));

    // A crash mid-append: half of a record, appended by hand (the flock
    // does not survive the crash).
    std::vector<uint8_t> torn(kDurableRecSize / 2, 0x42);
    int fd = ::open(sidecar.c_str(), O_WRONLY | O_APPEND);
    ASSERT_GE(fd, 0);
    ASSERT_EQ(::write(fd, torn.data(), torn.size()), (ssize_t)torn.size());
    ::close(fd);

    // The next append after the crash heals the tear: it lands at the
    // logical end (behind record 1, at the torn bytes) and truncates the
    // tail — the file ends up exactly 2 good records, no torn bytes.
    std::array<uint8_t, 32> d2{};
    d2.fill(0xCD);
    EXPECT_TRUE(sva::SvaWitnessRegistry::instance().register_witness_bytes(
        d2, va.addr.data(), va.preimages[1], va.path_for(1), 1));

    std::ifstream f(sidecar, std::ios::binary);
    f.seekg(0, std::ios::end);
    const size_t size = static_cast<size_t>(f.tellg());
    EXPECT_EQ(size, 2 * kDurableRecSize)
        << "torn tail not healed: " << size << " != " << 2 * kDurableRecSize;

    // Fresh-process simulation: copy the healed sidecar, replay it from a
    // new attach (the singleton cannot be reset), and register a third
    // witness — the replay must recover both records and the append must
    // continue cleanly (3 records).
    const std::string sidecar2 = dir + "/node2.svaw";
    std::filesystem::copy_file(sidecar, sidecar2,
                               std::filesystem::copy_options::overwrite_existing);
    sva::SvaWitnessRegistry::instance().attach_durable_log(sidecar2);
    std::array<uint8_t, 32> d3{};
    d3.fill(0xEF);
    EXPECT_TRUE(sva::SvaWitnessRegistry::instance().register_witness_bytes(
        d3, va.addr.data(), va.preimages[2], va.path_for(2), 2));
    std::ifstream f2(sidecar2, std::ios::binary);
    f2.seekg(0, std::ios::end);
    const size_t size2 = static_cast<size_t>(f2.tellg());
    EXPECT_EQ(size2, 3 * kDurableRecSize)
        << "replay lost records or the append went behind the tear";
    std::filesystem::remove_all(dir);
}

// ── Finding 2: registry saturation (CWE-400) ─────────────────────────────────
// Pre-fix: 16384 self-vault registrations (22 MB) filled the map
// permanently; every new honest witness was refused and vault spends were
// censored on the node until an operator wiped the sidecar. Fixed: a
// per-sender cap stops the flood from one sender, and at the global cap
// the OLDEST entry is evicted to admit a fresh verify-passing witness.
TEST(SvaZerodayTest, RegistrySaturationRateLimited) {
    WiringChain c("vx_zd_flood");
    c.apply_mint_block();
    ASSERT_TRUE(c.fund_funder(GENESIS_2_MINT_ATOMICS));
    SvaVault owner("vx_zd_flood_owner");
    SvaVault attacker("vx_zd_flood_attacker");
    ASSERT_TRUE(c.fund_vault(owner, 50'000 * VX_ATOMS));

    // The attacker's registration flood: distinct digests, one vault's
    // material — every registration passes verify-before-store until the
    // per-sender cap stops the flood.
    const size_t before = sva::SvaWitnessRegistry::instance().size();
    SvaVault &a = attacker;
    uint64_t n = 0;
    for (; n < 200000; ++n) {
        std::array<uint8_t, 32> digest{};
        std::memcpy(digest.data(), &n, 8);
        std::memcpy(digest.data() + 8, "FLOOD", 5);
        if (!sva::SvaWitnessRegistry::instance().register_witness_bytes(
                digest, a.addr.data(), a.preimages[0], a.path_for(0), 0))
            break;
    }
    EXPECT_EQ(n, sva::kSvaMaxWitnessesPerSender) << "per-sender cap not enforced";
    EXPECT_EQ(sva::SvaWitnessRegistry::instance().size(), before + n);

    // The honest owner's witness for a fresh digest: admitted (the flood
    // from ONE sender cannot exhaust the global budget).
    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction t = make_tx(owner.addr, addr_of("VX_ZD_RCV2"), kSpendAmount, 0, kSpendFee);
    EXPECT_TRUE(sva::SvaWitnessRegistry::instance().register_witness_bytes(
        vx::crypto::pq::tx_msg_digest(t), owner.addr.data(), owner.preimages[0], owner.path_for(0),
        0));

    // The dependent block applies: no censorship.
    ASSERT_TRUE(b.add_transaction(t));
    ASSERT_EQ(b.bind_canonical_witnesses(
                  [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                      return c.ledger->pq_root_of(a, out);
                  }),
              1u);
    const BlockFrame f = sealed_frame(*c.store, b);
    EXPECT_TRUE(c.store->append_block(f));
    const auto r = c.ledger->apply_block(BlockView(f));
    EXPECT_TRUE(r.ok) << r.error;
    EXPECT_EQ(c.ledger->balance_of(addr_of("VX_ZD_RCV2")), U128(kSpendAmount));
}
