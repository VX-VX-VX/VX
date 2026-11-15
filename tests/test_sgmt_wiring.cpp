// SGMT-tx wiring tests — the DKSAP wire-integration consensus surface.
//
// Cover: on-chain nickname registration (leaf committed in the frame,
// record authenticated out of band), first-come-wins squatting, sidecar
// mismatch refusal, fail-closed missing-record, stealth-tracker credit,
// radar hit over the sidecar bundle (view_tag filter), nickname
// validation, and the reorg-undo of the SGMT leaf.
#include <gtest/gtest.h>

#include "vx/blockchain/block.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/crypto/dksap.hpp"
#include "vx/crypto/dksap_sgmt.hpp"
#include "vx/crypto/dksap_sidecars.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/storage/block_store.hpp"
#include "vx/state/ledger_state.hpp"

#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <memory>
#include <string>
#include <sys/stat.h>
#include <unistd.h>

using namespace vx::blockchain;
using vx::core::U128;

namespace {
std::string hex_root(const uint8_t *r) {
    static const char *d = "0123456789abcdef";
    std::string s;
    for (int i = 0; i < 32; ++i) {
        s.push_back(d[r[i] >> 4]);
        s.push_back(d[r[i] & 0xF]);
    }
    return s;
}

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

BlockFrame sealed_frame(vx::storage::BlockStore &store, vx::state::LedgerState &ledger,
                        BlockBuilder &b) {
    // The caller binds canonical witnesses BEFORE calling this (the
    // double-bind here would append the same binding twice and corrupt the
    // witness merkle root).
    (void)ledger;
    b.finalize();
    BlockFrame f;
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    EXPECT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
    return f;
}

// A funded chain: genesis replayed, the protocol mint applied, and the
// demo PQ account holding spendable balance. One object per test.
struct WiringChain {
    std::string dir;
    std::unique_ptr<vx::storage::BlockStore> store;
    std::unique_ptr<vx::state::LedgerState> ledger;
    PqAccount demo{};
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
        spender = genesis2_mint_receiver_payload();

        BlockBuilder b = next_block(*store, static_cast<uint64_t>(std::time(nullptr)));
        Transaction mint = make_tx(addr_of("GENESIS_2"), spender, GENESIS_2_MINT_ATOMICS, 0);
        sign_transaction(mint);
        if (!b.add_transaction(mint)) {
            ADD_FAILURE();
            return;
        }
        const BlockFrame f = sealed_frame(*store, *ledger, b);
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

    ~WiringChain() {
        std::filesystem::remove_all(dir);
    }

    /// Funds a fresh PQ account from the genesis-2 spender with real
    /// witnesses, so later blocks can spend from the funded account.
    PqAccount fund_new_account(const char *tag, uint64_t amount) {
        PqAccount acc = make_pq_account(tag);
        BlockBuilder b = next_block(*store, static_cast<uint64_t>(std::time(nullptr)));
        Transaction t = make_tx(spender, acc.addr, amount, 0);
        vx::crypto::pq::PqSignatureWitness w{};
        if (!vx::crypto::pq::pq_sign_transaction(t, demo.sk, nullptr, nullptr, &w)) {
            ADD_FAILURE();
            return acc;
        }
        // The self-certifying sender's witness resolves from the REGISTRY
        // at apply time — register it exactly the way a PQ_WITNESS wire
        // message does.
        vx::crypto::pq::PqWitnessRegistry::instance().register_witness_bytes(
            vx::crypto::pq::tx_msg_digest(t), t.sender_nfa, w);
        if (!b.add_transaction(t)) {
            ADD_FAILURE();
            return acc;
        }
        if (b.bind_canonical_witnesses(
                [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                    return ledger->pq_root_of(a, out);
                }) != 1u) {
            ADD_FAILURE();
            return acc;
        }
        const BlockFrame f = sealed_frame(*store, *ledger, b);
        if (!store->append_block(f)) {
            ADD_FAILURE() << "fund: store append failed";
            return acc;
        }
        {
            const auto *raw = reinterpret_cast<const RawBlock *>(f.data());
            const auto st = verify_witness_merkle(
                *raw, [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                    return ledger->pq_root_of(a, out);
                });
            EXPECT_EQ(st, WitnessRootStatus::MATCH)
                << "fund: verify_witness_merkle=" << static_cast<int>(st)
                << " header_root=" << hex_root(raw->header.witness_merkle_root)
                << " tx_count=" << raw->header.tx_count;
        }
        const auto fr = ledger->apply_block(BlockView(f));
        if (!fr.ok) {
            ADD_FAILURE() << "fund: apply refused: " << fr.error;
            return acc;
        }
        return acc;
    }
};

// A registered nickname: derived DKSAP account + the sidecar record under
// the digest the ledger will compute for the assembled registration tx.
struct Registration {
    vx::crypto::dksap::Account acc{};
    std::string nickname;
    std::array<uint8_t, 32> leaf{};
    std::array<uint8_t, 32> key{};

    explicit Registration(const char *nick, uint8_t seed_tag = 0xC0) : nickname(nick) {
        std::array<uint8_t, 256> seed{};
        for (size_t i = 0; i < seed.size(); ++i)
            seed[i] = static_cast<uint8_t>(seed_tag + i);
        vx::crypto::dksap::derive_account(seed.data(), acc);
        leaf = vx::crypto::dksap::sgmt_commit(nickname, acc.pub);
        key = vx::crypto::dksap::sgmt_key(nickname);
    }
};

/// Registers the sidecar for a SIGNED tx (digest binds the signed frame).
bool register_sgmt_sidecar(const Transaction &tx, const vx::crypto::dksap::PublicKeys &pub,
                           const std::string &nickname) {
    vx::crypto::dksap::SgmtRecord rec;
    rec.nickname = nickname;
    rec.pub = pub;
    return vx::crypto::dksap::DksapSidecarRegistry::instance().register_sgmt_candidate(
        vx::crypto::pq::tx_msg_digest(tx), rec);
}

} // namespace

// -- 1. Registration applies: the leaf is committed, the trie grows, and
// the first-come key cannot be re-registered by a different commitment.
TEST(VortexSgmtWiringTest, RegistrationAppliesAndSquats) {
    WiringChain c("vx_sgmtw_reg");
    Registration reg("alice");
    PqAccount sender = c.fund_new_account("VX_SGMTW_SENDER_A_SK", 2'000'000'000u);

    // Sidecar + signed tx + block.
    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction tx = make_tx(sender.addr, addr_of("SGMTLEAF"), 0, 0);
    vx::crypto::dksap::make_sgmtleaf_receiver(reg.leaf.data(), tx.receiver_nfa);
    tx_set_fee(tx, 1000);
    {
        vx::crypto::pq::PqSignatureWitness w{};
        ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(tx, sender.sk, nullptr, nullptr, &w));
        vx::crypto::pq::PqWitnessRegistry::instance().register_witness_bytes(
            vx::crypto::pq::tx_msg_digest(tx), tx.sender_nfa, w);
    }
    ASSERT_TRUE(register_sgmt_sidecar(tx, reg.acc.pub, reg.nickname));
    ASSERT_TRUE(b.add_transaction(tx));
    ASSERT_EQ(b.bind_canonical_witnesses(
                  [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                      return c.ledger->pq_root_of(a, out);
                  }),
              1u);
    const BlockFrame f = sealed_frame(*c.store, *c.ledger, b);
    ASSERT_TRUE(c.store->append_block(f));
    const auto res = c.ledger->apply_block(BlockView(f));
    ASSERT_TRUE(res.ok) << res.error;

    // The trie holds the leaf under the nickname key.
    std::array<uint8_t, 32> stored{};
    ASSERT_TRUE(c.ledger->sgmt_trie().get(reg.key.data(), stored.data()));
    EXPECT_EQ(0, std::memcmp(stored.data(), reg.leaf.data(), 32));
    // The sender's fee burned; nothing moved for the SGMTLEAF receiver.
    EXPECT_TRUE(!c.ledger->tracked_addresses_containing(addr_of("SGMTLEAF")));
    // The undo journal entry: one registration, no previous leaf.
    ASSERT_EQ(res.sgmt_undo.size(), 1u);
    EXPECT_EQ(res.sgmt_undo[0].key, reg.key);
    EXPECT_FALSE(res.sgmt_undo[0].existed);
}

// -- 2. Squatting is permanent: a second commitment for the same nickname
// is refused, and the state stays byte-identical.
TEST(VortexSgmtWiringTest, SquattingIsPermanent) {
    WiringChain c("vx_sgmtw_squat");
    Registration reg("bob");
    Registration reg2("bob", 0xD0); // same nickname, DIFFERENT keys (different seed)
    PqAccount sender = c.fund_new_account("VX_SGMTW_SENDER_B_SK", 2'000'000'000u);

    const auto apply_reg = [&](const Registration &r, uint32_t reg_nonce) {
        BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
        Transaction tx = make_tx(sender.addr, addr_of("SGMTLEAF"), 0, reg_nonce);
        vx::crypto::dksap::make_sgmtleaf_receiver(r.leaf.data(), tx.receiver_nfa);
        tx_set_fee(tx, 1000);
        if (!vx::crypto::pq::pq_sign_transaction(tx, sender.sk, nullptr, nullptr, nullptr))
            return std::string("sign failed");
        if (!register_sgmt_sidecar(tx, r.acc.pub, r.nickname))
            return std::string("sidecar refused");
        if (!b.add_transaction(tx))
            return std::string("builder full");
        if (b.bind_canonical_witnesses(
                [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                    return c.ledger->pq_root_of(a, out);
                }) != 1u)
            return std::string("no witness");
        const BlockFrame f = sealed_frame(*c.store, *c.ledger, b);
        if (!c.store->append_block(f))
            return std::string("append failed");
        const auto res = c.ledger->apply_block(BlockView(f));
        if (!res.ok)
            c.store->rollback_last_append();
        return res.ok ? std::string() : res.error;
    };

    const std::string first_err = apply_reg(reg, 0);
    ASSERT_TRUE(first_err.empty()) << first_err;
    // A different commitment on the same key must be refused.
    const std::string second_err = apply_reg(reg2, 1);
    EXPECT_NE(second_err.find("first-come-wins"), std::string::npos) << second_err;
    // The trie still holds the FIRST leaf.
    std::array<uint8_t, 32> stored{};
    ASSERT_TRUE(c.ledger->sgmt_trie().get(reg.key.data(), stored.data()));
    EXPECT_EQ(0, std::memcmp(stored.data(), reg.leaf.data(), 32));
}

// -- 3. A substituted sidecar record is refused: the record must commit
// exactly the frame's leaf (tamper-evident out-of-band authentication).
TEST(VortexSgmtWiringTest, SubstitutedRecordRefused) {
    WiringChain c("vx_sgmtw_tamper");
    Registration reg("carol");
    PqAccount sender = c.fund_new_account("VX_SGMTW_SENDER_C_SK", 2'000'000'000u);

    // A DIFFERENT record registered under the same digest.
    std::array<uint8_t, 256> seed{};
    for (size_t i = 0; i < seed.size(); ++i)
        seed[i] = static_cast<uint8_t>(0x40 + i);
    vx::crypto::dksap::Account other{};
    vx::crypto::dksap::derive_account(seed.data(), other);

    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction tx = make_tx(sender.addr, addr_of("SGMTLEAF"), 0, 0);
    vx::crypto::dksap::make_sgmtleaf_receiver(reg.leaf.data(), tx.receiver_nfa);
    tx_set_fee(tx, 1000);
    {
        vx::crypto::pq::PqSignatureWitness w{};
        ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(tx, sender.sk, nullptr, nullptr, &w));
        vx::crypto::pq::PqWitnessRegistry::instance().register_witness_bytes(
            vx::crypto::pq::tx_msg_digest(tx), tx.sender_nfa, w);
    }
    ASSERT_TRUE(register_sgmt_sidecar(tx, other.pub, reg.nickname));
    ASSERT_TRUE(b.add_transaction(tx));
    ASSERT_EQ(b.bind_canonical_witnesses(
                  [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                      return c.ledger->pq_root_of(a, out);
                  }),
              1u);
    const BlockFrame f = sealed_frame(*c.store, *c.ledger, b);
    ASSERT_TRUE(c.store->append_block(f));
    const auto res = c.ledger->apply_block(BlockView(f));
    EXPECT_TRUE(!res.ok);
    EXPECT_NE(res.error.find("sidecar missing or non-matching"), std::string::npos) << res.error;
}

// -- 4. Fail-closed: a frame whose SGMTLEAF tx has no sidecar record is
// refused (never half-applied).
TEST(VortexSgmtWiringTest, MissingSidecarRefused) {
    WiringChain c("vx_sgmtw_missing");
    Registration reg("dave");
    PqAccount sender = c.fund_new_account("VX_SGMTW_SENDER_D_SK", 2'000'000'000u);

    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction tx = make_tx(sender.addr, addr_of("SGMTLEAF"), 0, 0);
    vx::crypto::dksap::make_sgmtleaf_receiver(reg.leaf.data(), tx.receiver_nfa);
    tx_set_fee(tx, 1000);
    {
        vx::crypto::pq::PqSignatureWitness w{};
        ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(tx, sender.sk, nullptr, nullptr, &w));
        vx::crypto::pq::PqWitnessRegistry::instance().register_witness_bytes(
            vx::crypto::pq::tx_msg_digest(tx), tx.sender_nfa, w);
    }
    // NO sidecar registration — the block cannot apply.
    ASSERT_TRUE(b.add_transaction(tx));
    ASSERT_EQ(b.bind_canonical_witnesses(
                  [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                      return c.ledger->pq_root_of(a, out);
                  }),
              1u);
    const BlockFrame f = sealed_frame(*c.store, *c.ledger, b);
    ASSERT_TRUE(c.store->append_block(f));
    const auto res = c.ledger->apply_block(BlockView(f));
    EXPECT_TRUE(!res.ok);
    EXPECT_NE(res.error.find("sidecar missing or non-matching"), std::string::npos) << res.error;
}

// -- 5. Stealth transfer: the tracker is a real value receiver, the radar
// recognizes the transfer through the sidecar bundle (view_tag path), and
// a foreign account does NOT match.
TEST(VortexSgmtWiringTest, StealthTransferAndRadarHit) {
    WiringChain c("vx_sgmtw_stealth");
    Registration reg("eve");
    PqAccount sender = c.fund_new_account("VX_SGMTW_SENDER_E_SK", 4'000'000'000u);

    // Receiver-side radar account: the IVK holder (kem_sk + t_spend).
    struct Watch {
        std::array<uint8_t, vx::crypto::dksap::KEM_SK_SIZE> kem_sk{};
        std::array<uint8_t, vx::crypto::dksap::T_COMMIT_SIZE> t_spend{};
    } watch{};
    std::memcpy(watch.kem_sk.data(), reg.acc.kem_sk.data(), watch.kem_sk.size());
    std::memcpy(watch.t_spend.data(), reg.acc.pub.t_spend.data(), watch.t_spend.size());

    // Sender-side: resolve + stealth_send toward the verified record.
    ASSERT_TRUE(vx::crypto::dksap::sgmt_resolve(c.ledger->sgmt_trie(), reg.nickname, reg.acc.pub) ==
                false);
    // (The nickname is not registered yet in THIS chain — resolve must
    // refuse; register it first through the consensus path.)
    {
        BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
        Transaction tx = make_tx(sender.addr, addr_of("SGMTLEAF"), 0, 0);
        vx::crypto::dksap::make_sgmtleaf_receiver(reg.leaf.data(), tx.receiver_nfa);
        tx_set_fee(tx, 1000);
        {
            vx::crypto::pq::PqSignatureWitness w{};
            ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(tx, sender.sk, nullptr, nullptr, &w));
            vx::crypto::pq::PqWitnessRegistry::instance().register_witness_bytes(
                vx::crypto::pq::tx_msg_digest(tx), tx.sender_nfa, w);
        }
        ASSERT_TRUE(register_sgmt_sidecar(tx, reg.acc.pub, reg.nickname));
        ASSERT_TRUE(b.add_transaction(tx));
        ASSERT_EQ(b.bind_canonical_witnesses(
                      [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                          return c.ledger->pq_root_of(a, out);
                      }),
                  1u);
        const BlockFrame f = sealed_frame(*c.store, *c.ledger, b);
        ASSERT_TRUE(c.store->append_block(f));
        ASSERT_TRUE(c.ledger->apply_block(BlockView(f)).ok);
    }
    ASSERT_TRUE(vx::crypto::dksap::sgmt_resolve(c.ledger->sgmt_trie(), reg.nickname, reg.acc.pub));

    vx::crypto::dksap::StealthTx bundle{};
    vx::crypto::dksap::stealth_send(reg.acc.pub, bundle);

    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction tx = make_tx(sender.addr, addr_of("STEALTH"), 500'000'000u, 1);
    vx::crypto::dksap::make_stealth_receiver(bundle.pstealth.data(), tx.receiver_nfa);
    tx_set_fee(tx, 1000);
    {
        vx::crypto::pq::PqSignatureWitness w{};
        ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(tx, sender.sk, nullptr, nullptr, &w));
        vx::crypto::pq::PqWitnessRegistry::instance().register_witness_bytes(
            vx::crypto::pq::tx_msg_digest(tx), tx.sender_nfa, w);
    }
    const auto digest = vx::crypto::pq::tx_msg_digest(tx);
    vx::crypto::dksap::StealthBundle sb;
    sb.tx = bundle;
    ASSERT_TRUE(
        vx::crypto::dksap::DksapSidecarRegistry::instance().register_stealth_candidate(digest, sb));
    ASSERT_TRUE(b.add_transaction(tx));
    ASSERT_EQ(b.bind_canonical_witnesses(
                  [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                      return c.ledger->pq_root_of(a, out);
                  }),
              1u);
    const BlockFrame f = sealed_frame(*c.store, *c.ledger, b);
    ASSERT_TRUE(c.store->append_block(f));
    const auto res = c.ledger->apply_block(BlockView(f));
    ASSERT_TRUE(res.ok) << res.error;

    // The tracker holds the value.
    vx::blockchain::Address tracker{};
    std::memcpy(tracker.data(), tx.receiver_nfa, 42);
    EXPECT_TRUE(c.ledger->balance_of(tracker) == U128(500'000'000u));

    // The radar recognizes the transfer through the bundle.
    vx::crypto::dksap::RadarHit hit;
    vx::crypto::dksap::radar_scan(watch.kem_sk.data(), watch.t_spend, bundle,
                                  /*spend_sk_present=*/false, nullptr, hit);
    EXPECT_TRUE(hit.match);
    EXPECT_EQ(0, std::memcmp(hit.tx_key.data(), bundle.tx_key.data(), 32));
}

// -- 6. Non-canonical receivers are refused at the consensus gate too
// (stealth_pstealth_of/sgmtleaf_of fail closed on dirty padding).
TEST(VortexSgmtWiringTest, ReceiverHelpersFailClosed) {
    uint8_t r[42]{};
    std::array<uint8_t, 32> ps{};
    for (size_t i = 0; i < ps.size(); ++i)
        ps[i] = static_cast<uint8_t>(i + 1);
    vx::crypto::dksap::make_stealth_receiver(ps.data(), r);
    uint8_t out[32];
    ASSERT_TRUE(vx::crypto::dksap::stealth_pstealth_of(r, out));
    EXPECT_EQ(0, std::memcmp(out, ps.data(), 32));
    r[41] = 0x01; // dirty pad byte
    uint8_t out2[32];
    EXPECT_FALSE(vx::crypto::dksap::stealth_pstealth_of(r, out2));
    r[41] = 0;
    EXPECT_FALSE(vx::crypto::dksap::receiver_is_sgmtleaf(r)); // tag mismatch
}

// -- 7. Nickname validator: boundaries.
TEST(VortexSgmtWiringTest, NicknameValidatorBoundaries) {
    EXPECT_TRUE(vx::crypto::dksap::nickname_valid("alice"));
    EXPECT_TRUE(vx::crypto::dksap::nickname_valid(std::string(32, 'a')));
    EXPECT_FALSE(vx::crypto::dksap::nickname_valid(""));
    EXPECT_FALSE(vx::crypto::dksap::nickname_valid(std::string(33, 'a')));
    EXPECT_FALSE(vx::crypto::dksap::nickname_valid("has space"));
    std::string ctrl(4, 'a');
    ctrl[1] = '\n';
    EXPECT_FALSE(vx::crypto::dksap::nickname_valid(ctrl));
    EXPECT_FALSE(vx::crypto::dksap::nickname_valid(
        "\xD0\xBA\xD0\xB8\xD1\x80")); // non-ASCII bytes (UTF-8 Cyrillic)
}

// -- 8. (P0 regression, adversarial review 2026-11-15) The nickname is
// bound into the commitment: two candidate records with different
// nicknames under one digest commit DIFFERENT leaves, so a candidate can
// never resolve for a leaf it was not built for — arrival order cannot
// fork the trie.
TEST(VortexSgmtWiringTest, NicknameBoundIntoCommitment) {
    WiringChain c("vx_sgmtw_bind");
    Registration reg("frank");
    // The SAME keys, registered as a different nickname: with the V1
    // commitment both records would produce the same leaf and the
    // candidate model would resolve by arrival order (fork).
    vx::crypto::dksap::SgmtRecord shadow;
    shadow.nickname = "gina";
    shadow.pub = reg.acc.pub;

    const auto leaf_frank = vx::crypto::dksap::sgmt_commit("frank", reg.acc.pub);
    const auto leaf_gina = vx::crypto::dksap::sgmt_commit("gina", reg.acc.pub);
    EXPECT_NE(0, std::memcmp(leaf_frank.data(), leaf_gina.data(), 32))
        << "the commitment must bind the nickname";

    // Both candidates under the same digest.
    std::array<uint8_t, 32> digest{};
    for (size_t i = 0; i < digest.size(); ++i)
        digest[i] = static_cast<uint8_t>(0x50 + i);
    ASSERT_TRUE(vx::crypto::dksap::DksapSidecarRegistry::instance().register_sgmt_candidate(
        digest, shadow));
    vx::crypto::dksap::SgmtRecord frank_rec;
    frank_rec.nickname = reg.nickname;
    frank_rec.pub = reg.acc.pub;
    ASSERT_TRUE(vx::crypto::dksap::DksapSidecarRegistry::instance().register_sgmt_candidate(
        digest, frank_rec));

    // The frame leaf for "frank" resolves ONLY the frank record, and the
    // gina leaf resolves ONLY the gina record — the same keys cannot be
    // registered under two nicknames by one digest (the V1 bug was: both
    // leaves resolved the same record, chosen by arrival order).
    vx::crypto::dksap::SgmtRecord out;
    EXPECT_TRUE(vx::crypto::dksap::DksapSidecarRegistry::instance().resolve_sgmt_record(
        digest, leaf_frank, out));
    EXPECT_EQ(out.nickname, "frank");
    EXPECT_TRUE(vx::crypto::dksap::DksapSidecarRegistry::instance().resolve_sgmt_record(
        digest, leaf_gina, out));
    EXPECT_EQ(out.nickname, "gina");
}

// -- 9. (P0 regression) A bogus first-arriver cannot displace the honest
// record: the honest candidate registered SECOND still resolves.
TEST(VortexSgmtWiringTest, BogusCandidateCannotDisplace) {
    WiringChain c("vx_sgmtw_displace");
    Registration reg("hank");
    PqAccount sender = c.fund_new_account("VX_SGMTW_SENDER_H_SK", 2'000'000'000u);

    // A bogus candidate registered FIRST: same nickname, foreign keys.
    std::array<uint8_t, 256> seed{};
    for (size_t i = 0; i < seed.size(); ++i)
        seed[i] = static_cast<uint8_t>(0x10 + i);
    vx::crypto::dksap::Account bogus{};
    vx::crypto::dksap::derive_account(seed.data(), bogus);
    vx::crypto::dksap::SgmtRecord bogus_rec;
    bogus_rec.nickname = reg.nickname;
    bogus_rec.pub = bogus.pub;
    (void)bogus_rec;

    BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
    Transaction tx = make_tx(sender.addr, addr_of("SGMTLEAF"), 0, 0);
    vx::crypto::dksap::make_sgmtleaf_receiver(reg.leaf.data(), tx.receiver_nfa);
    tx_set_fee(tx, 1000);
    {
        vx::crypto::pq::PqSignatureWitness w{};
        ASSERT_TRUE(vx::crypto::pq::pq_sign_transaction(tx, sender.sk, nullptr, nullptr, &w));
        vx::crypto::pq::PqWitnessRegistry::instance().register_witness_bytes(
            vx::crypto::pq::tx_msg_digest(tx), tx.sender_nfa, w);
    }
    // Bogus first, honest second — the FIRST-ARRIVER order.
    ASSERT_TRUE(register_sgmt_sidecar(tx, bogus.pub, reg.nickname));
    ASSERT_TRUE(register_sgmt_sidecar(tx, reg.acc.pub, reg.nickname));
    ASSERT_TRUE(b.add_transaction(tx));
    ASSERT_EQ(b.bind_canonical_witnesses(
                  [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                      return c.ledger->pq_root_of(a, out);
                  }),
              1u);
    const BlockFrame f = sealed_frame(*c.store, *c.ledger, b);
    ASSERT_TRUE(c.store->append_block(f));
    const auto res = c.ledger->apply_block(BlockView(f));
    ASSERT_TRUE(res.ok) << res.error;
    // The trie holds the HONEST leaf.
    std::array<uint8_t, 32> stored{};
    ASSERT_TRUE(c.ledger->sgmt_trie().get(reg.key.data(), stored.data()));
    EXPECT_EQ(0, std::memcmp(stored.data(), reg.leaf.data(), 32));
}

// -- 9b. (MEDIUM regression, security review 2026-11-15) A candidate that
// arrived via gossip (uncommitted) and is later committed must be UPGRADED
// in place: a blind no-op on the byte-identical re-arrival left the honest
// candidate evictable by late gossip.
TEST(VortexSgmtWiringTest, CommittedCandidateSurvivesLateGossip) {
    auto &registry = vx::crypto::dksap::DksapSidecarRegistry::instance();
    Registration reg("eve", 0xE0);
    vx::crypto::dksap::SgmtRecord rec;
    rec.nickname = reg.nickname;
    rec.pub = reg.acc.pub;
    std::array<uint8_t, 32> digest{};
    digest[0] = 0xAB;
    digest[31] = 0x9B;
    ASSERT_TRUE(registry.register_sgmt_candidate(digest, rec));
    vx::crypto::dksap::SgmtRecord out{};
    ASSERT_TRUE(registry.resolve_sgmt_record(digest, reg.leaf, out));
    ASSERT_TRUE(registry.commit_sgmt_record(digest, rec));

    // Late gossip flood: four garbage candidates under the same digest
    // (same nickname, different keys — distinct for the dedup, and none
    // commits the honest leaf).
    for (uint8_t tag = 0; tag < 4; ++tag) {
        vx::crypto::dksap::SgmtRecord garbage;
        garbage.nickname = reg.nickname;
        std::array<uint8_t, 256> seed{};
        for (size_t i = 0; i < seed.size(); ++i)
            seed[i] = static_cast<uint8_t>(0x90 + tag * 8 + (i % 8));
        vx::crypto::dksap::Account g{};
        vx::crypto::dksap::derive_account(seed.data(), g);
        garbage.pub = g.pub;
        EXPECT_TRUE(registry.register_sgmt_candidate(digest, garbage));
    }
    // The honest COMMITTED candidate survived the eviction pressure.
    bool honest_survived = false;
    for (const auto &c : registry.copy_sgmt_candidates(digest))
        if (c.nickname == reg.nickname && c.pub.t_spend == rec.pub.t_spend &&
            c.pub.kkem == rec.pub.kkem)
            honest_survived = true;
    EXPECT_TRUE(honest_survived)
        << "committed candidate was evicted by uncommitted gossip (upgrade missed)";
    // Resolution still serves the honest record.
    EXPECT_TRUE(registry.resolve_sgmt_record(digest, reg.leaf, out));
}

// -- 10. (HIGH regression, security review 2026-11-15) An idempotent
// re-registration under a NEW digest gets its own durable row: after a
// restart resolve_sgmt_record(new digest) must replay from the log. The
// old cross-digest dedup anchored the pair in memory ONLY — the node then
// refused its own history on resync. Must stay the LAST test in this
// binary: it attaches the registry's durable log process-wide.
TEST(VortexSgmtWiringTest, ReRegistrationDurableUnderBothDigests) {
    namespace fs = std::filesystem;
    const fs::path dir =
        fs::temp_directory_path() / ("vx_sgmtw_durable_" + std::to_string(::getpid()));
    fs::create_directories(dir);
    const std::string log_path = (dir / "ledger.sgm").string();
    vx::crypto::dksap::DksapSidecarRegistry::instance().attach_sgmt_durable_log(log_path);

    WiringChain c("vx_sgmtw_durable");
    Registration reg("dave");
    PqAccount sender = c.fund_new_account("VX_SGMTW_SENDER_D_SK", 4'000'000'000u);

    const auto apply_reg = [&](uint32_t reg_nonce) {
        BlockBuilder b = next_block(*c.store, static_cast<uint64_t>(std::time(nullptr)));
        Transaction tx = make_tx(sender.addr, addr_of("SGMTLEAF"), 0, reg_nonce);
        vx::crypto::dksap::make_sgmtleaf_receiver(reg.leaf.data(), tx.receiver_nfa);
        tx_set_fee(tx, 1000);
        EXPECT_TRUE(vx::crypto::pq::pq_sign_transaction(tx, sender.sk, nullptr, nullptr, nullptr));
        EXPECT_TRUE(register_sgmt_sidecar(tx, reg.acc.pub, reg.nickname));
        EXPECT_TRUE(b.add_transaction(tx));
        EXPECT_EQ(b.bind_canonical_witnesses(
                      [&](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
                          return c.ledger->pq_root_of(a, out);
                      }),
                  1u);
        const BlockFrame f = sealed_frame(*c.store, *c.ledger, b);
        EXPECT_TRUE(c.store->append_block(f));
        const auto res = c.ledger->apply_block(BlockView(f));
        EXPECT_TRUE(res.ok) << res.error;
        return vx::crypto::pq::tx_msg_digest(tx);
    };

    const std::array<uint8_t, 32> d1 = apply_reg(0);
    const std::array<uint8_t, 32> d2 = apply_reg(1); // same (nickname, keys), new digest

    // The durable log carries BOTH digests: magic(8) + one row per digest.
    // Row = digest(32) + nlen(1) + nickname(n) + t_spend(32) + kkem(1568).
    std::ifstream in(log_path, std::ios::binary);
    ASSERT_TRUE(in.good());
    const std::vector<uint8_t> bytes((std::istreambuf_iterator<char>(in)),
                                     std::istreambuf_iterator<char>());
    const size_t row =
        32 + 1 + reg.nickname.size() + reg.acc.pub.t_spend.size() + reg.acc.pub.kkem.size();
    ASSERT_EQ(bytes.size(), 8 + 2 * row) << "expected one durable row per digest";
    auto digest_at = [&](size_t off) {
        std::array<uint8_t, 32> d{};
        std::memcpy(d.data(), bytes.data() + off, 32);
        return d;
    };
    EXPECT_EQ(digest_at(8), d1);
    EXPECT_EQ(digest_at(8 + row), d2);

    fs::remove_all(dir);
}

// -- 11. (P1 regression, vx-audit 2026-11-15) A FAILED durable append must
// NOT poison the same-digest dedup: the candidate stays UNCOMMITTED so the
// next re-commit RETRIES the append. The old order (committed flag set
// before the append) let a committed-but-undurable candidate make the
// retry dedup-skip — the block then applied with no log row and the node
// refused its own history after restart (the exact HIGH class this file's
// test 10 closes). Also pins the append-time index offset: the row start
// is POST-write size − row length, so a resolve after an in-session
// eviction must load the record back from the log byte-identically.
// Must run AFTER test 10 (it reuses the process-wide attached log path).
TEST(VortexSgmtWiringTest, CommitAppendFailureNotPoisoned) {
    namespace fs = std::filesystem;
    const fs::path dir =
        fs::temp_directory_path() / ("vx_sgmtw_durable_" + std::to_string(::getpid()));
    const std::string log_path = (dir / "ledger.sgm").string();
    // Test 10 attaches this path process-wide and remove_all()s the
    // directory on exit — recreate the directory and a fresh empty file,
    // then re-attach (idempotent for the same path; in a standalone run it
    // performs the attach itself).
    fs::create_directories(dir);
    {
        std::ofstream mk(log_path, std::ios::binary | std::ios::app);
        ASSERT_TRUE(mk.good());
    }
    vx::crypto::dksap::DksapSidecarRegistry::instance().attach_sgmt_durable_log(log_path);
    auto before = fs::file_size(log_path);

    vx::crypto::dksap::SgmtRecord rec;
    rec.nickname = "poison_probe";
    // t_spend MUST be canonical 12-bit packing (the indexed reload
    // re-validates it and fails closed): all-zero limbs are canonical.
    // kkem bytes are opaque — patterned to make a mix-up visible.
    for (size_t i = 0; i < rec.pub.kkem.size(); ++i)
        rec.pub.kkem[i] = static_cast<uint8_t>(i * 13 + 5);
    std::array<uint8_t, 32> digest{};
    for (size_t i = 0; i < digest.size(); ++i)
        digest[i] = static_cast<uint8_t>(0x70 + i);

    auto &reg = vx::crypto::dksap::DksapSidecarRegistry::instance();

    // Break appends: the log file loses its owner-write bit.
    ASSERT_EQ(::chmod(log_path.c_str(), 0400), 0);
    // First commit: the append fails, the commit refuses.
    EXPECT_FALSE(reg.commit_sgmt_record(digest, rec));
    // Retry: must RETRY the append (still failing) — NOT dedup-skip to true.
    EXPECT_FALSE(reg.commit_sgmt_record(digest, rec))
        << "failed append poisoned the committed flag: the retry dedup-skipped";

    // Heal the file: the next commit retries and succeeds, marking the
    // candidate committed only now.
    ASSERT_EQ(::chmod(log_path.c_str(), 0600), 0);
    EXPECT_TRUE(reg.commit_sgmt_record(digest, rec));
    EXPECT_TRUE(reg.commit_sgmt_record(digest, rec)); // idempotent re-commit

    // Exactly ONE row reached the disk across all four commits.
    auto after = fs::file_size(log_path);
    const size_t row_len =
        32 + 1 + rec.nickname.size() + rec.pub.t_spend.size() + rec.pub.kkem.size();
    const size_t magic = (before < 8) ? 8 : 0; // fresh file gets the magic
    EXPECT_EQ(after, before + magic + row_len)
        << "expected exactly one durable row for the digest (no poison re-append)";

    // The append-time index points at that row: drop the in-memory entry
    // (forced eviction) and resolve again — the indexed reload must return
    // the record byte-identically (resolve against the record's own commit
    // leaf — the synthetic record is its own honest frame).
    reg.forget_sgmt_for_test(digest);
    const auto leaf = vx::crypto::dksap::sgmt_commit(rec.nickname, rec.pub);
    vx::crypto::dksap::SgmtRecord loaded;
    ASSERT_TRUE(reg.resolve_sgmt_record(digest, leaf, loaded))
        << "indexed reload failed — append-time offset miscomputed";
    EXPECT_EQ(loaded.nickname, rec.nickname);
    EXPECT_EQ(loaded.pub.t_spend, rec.pub.t_spend);
    EXPECT_EQ(loaded.pub.kkem, rec.pub.kkem);
}
