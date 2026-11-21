// VortexGqcCheckpointTest — Phase D (0.2.3): the checkpoint certificate as
// ONE verifiable object + the rollover certificate.
//
// Verifies:
//   1. verify_checkpoint(): a full quorum cert from real XMSS votes
//      verifies; forged votes, non-members, double-votes, phantom bitmap
//      bits and a tampered agg all fail.
//   2. verify_rollover(): the leaf-15 rollover cert verifies under the old
//      master root; wrong epoch order and a foreign root fail.

#include <gtest/gtest.h>
#include "vx/consensus/gqc_checkpoint.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/crypto/pq_signature.hpp"

#include <cstring>
#include <filesystem>

using vx::consensus::gqc::GqcCheckpointCert;
using vx::consensus::gqc::GqcRolloverCert;
using vx::consensus::gqc::GqcVote;
using vx::consensus::gqc::GqcWhitelistView;

namespace {

// One PqLeafLedger serves all members — the ledger is keyed by XMSS root.
struct Fixture {
    std::filesystem::path tmp_dir;
    vx::crypto::pq::PqLeafLedger ledger; // non-copyable: built in the init list
    const vx::blockchain::GqcEpochConfig &committee = vx::blockchain::gqc_epoch_committee();
    GqcWhitelistView view;

    // Creates the temp dir BEFORE the ledger opens its log inside it —
    // member-init order (tmp_dir declared first) guarantees this.
    static std::filesystem::path make_tmp_dir() {
        const auto p = std::filesystem::temp_directory_path() /
                       ("vx_gqc_checkpoint_test_" + std::to_string(::getpid()));
        std::filesystem::create_directories(p);
        return p;
    }

    Fixture() : tmp_dir(make_tmp_dir()), ledger(tmp_dir / "leaf_ledger.gqcl") {
        view = vx::consensus::gqc::whitelist_view(committee);
    }
    ~Fixture() {
        std::filesystem::remove_all(tmp_dir);
    }

    GqcVote member_vote(uint16_t validator_id, uint64_t height,
                        const std::array<uint8_t, 32> &block_hash) {
        const auto sk = vx::blockchain::gqc_epoch_validator_sk(validator_id);
        return vx::consensus::gqc::sign_vote(validator_id, sk, committee.epoch, height, block_hash,
                                             ledger);
    }
};

std::array<uint8_t, 32> test_hash(uint64_t height) {
    std::array<uint8_t, 32> h{};
    for (size_t i = 0; i < h.size(); ++i)
        h[i] = static_cast<uint8_t>(height * 31 + i * 7);
    return h;
}

} // namespace

// ── 1. Checkpoint certificate ───────────────────────────────────────────────

// The happy path: a full quorum of real votes verifies as ONE object.
TEST(VortexGqcCheckpointTest, FullQuorumVerifies) {
    Fixture f;
    const auto hash = test_hash(100);
    GqcCheckpointCert cert;
    cert.epoch = f.committee.epoch;
    cert.height = 100;
    cert.block_hash = hash;
    cert.validator_count = static_cast<uint32_t>(f.committee.members.size());
    for (const auto &m : f.committee.members)
        cert.votes.push_back(f.member_vote(m.validator_id, 100, hash));
    cert.signers_bitmap = (1ULL << f.committee.members.size()) - 1;
    cert.agg = vx::consensus::gqc::aggregate_votes(100, cert.signers_bitmap, cert.votes);

    EXPECT_TRUE(vx::consensus::gqc::verify_checkpoint(cert, f.view));
}

// A below-quorum cert must fail: ceil(2n/3) is the floor, not a target.
TEST(VortexGqcCheckpointTest, BelowQuorumFails) {
    Fixture f;
    const auto hash = test_hash(101);
    GqcCheckpointCert cert;
    cert.epoch = f.committee.epoch;
    cert.height = 101;
    cert.block_hash = hash;
    cert.validator_count = static_cast<uint32_t>(f.committee.members.size());
    // 2 of 4 < ceil(8/3)=3 — the mask still claims 2 signers.
    for (size_t i = 0; i < 2; ++i)
        cert.votes.push_back(f.member_vote(f.committee.members[i].validator_id, 101, hash));
    for (const auto &v : cert.votes) {
        for (size_t i = 0; i < f.committee.members.size(); ++i)
            if (f.committee.members[i].root == v.witness.pq_pubkey_root)
                cert.signers_bitmap |= (1ULL << i);
    }
    cert.agg = vx::consensus::gqc::aggregate_votes(101, cert.signers_bitmap, cert.votes);
    EXPECT_FALSE(vx::consensus::gqc::verify_checkpoint(cert, f.view));
}

// A vote from a non-member (a foreign tree's root) must fail: the root
// gate is the identity substitution defense.
TEST(VortexGqcCheckpointTest, ForeignVoteFails) {
    Fixture f;
    const auto hash = test_hash(102);
    GqcCheckpointCert cert;
    cert.epoch = f.committee.epoch;
    cert.height = 102;
    cert.block_hash = hash;
    cert.validator_count = static_cast<uint32_t>(f.committee.members.size());
    for (const auto &m : f.committee.members)
        cert.votes.push_back(f.member_vote(m.validator_id, 102, hash));
    cert.signers_bitmap = (1ULL << f.committee.members.size()) - 1;
    cert.agg = vx::consensus::gqc::aggregate_votes(102, cert.signers_bitmap, cert.votes);

    // Poison one vote: swap its witness root for a foreign one.
    auto poisoned = cert.votes[0];
    poisoned.witness.pq_pubkey_root[0] ^= 0xFF;
    auto bad = cert;
    bad.votes[0] = poisoned;
    EXPECT_FALSE(vx::consensus::gqc::verify_checkpoint(bad, f.view));
}

// An equivocation-shaped cert (two votes from one member) must fail.
TEST(VortexGqcCheckpointTest, DoubleVoteFails) {
    Fixture f;
    const auto hash = test_hash(103);
    GqcCheckpointCert cert;
    cert.epoch = f.committee.epoch;
    cert.height = 103;
    cert.block_hash = hash;
    cert.validator_count = static_cast<uint32_t>(f.committee.members.size());
    for (const auto &m : f.committee.members)
        cert.votes.push_back(f.member_vote(m.validator_id, 103, hash));
    // Duplicate the first member's vote — 5 votes, but 4 distinct roots.
    cert.votes.push_back(cert.votes[0]);
    cert.signers_bitmap = (1ULL << f.committee.members.size()) - 1;
    cert.agg = vx::consensus::gqc::aggregate_votes(103, cert.signers_bitmap, cert.votes);
    EXPECT_FALSE(vx::consensus::gqc::verify_checkpoint(cert, f.view));
}

// A phantom bitmap bit (claiming a signer that did not vote) must fail.
TEST(VortexGqcCheckpointTest, PhantomBitmapBitFails) {
    Fixture f;
    const auto hash = test_hash(104);
    GqcCheckpointCert cert;
    cert.epoch = f.committee.epoch;
    cert.height = 104;
    cert.block_hash = hash;
    cert.validator_count = static_cast<uint32_t>(f.committee.members.size());
    for (const auto &m : f.committee.members)
        cert.votes.push_back(f.member_vote(m.validator_id, 104, hash));
    cert.signers_bitmap = (1ULL << f.committee.members.size()) - 1;
    cert.agg = vx::consensus::gqc::aggregate_votes(104, cert.signers_bitmap, cert.votes);

    auto bad = cert;
    bad.signers_bitmap |= (1ULL << 63); // phantom signer
    EXPECT_FALSE(vx::consensus::gqc::verify_checkpoint(bad, f.view));
}

// A tampered agg must fail: the cert's agg commits to the exact signer set.
TEST(VortexGqcCheckpointTest, TamperedAggFails) {
    Fixture f;
    const auto hash = test_hash(105);
    GqcCheckpointCert cert;
    cert.epoch = f.committee.epoch;
    cert.height = 105;
    cert.block_hash = hash;
    cert.validator_count = static_cast<uint32_t>(f.committee.members.size());
    for (const auto &m : f.committee.members)
        cert.votes.push_back(f.member_vote(m.validator_id, 105, hash));
    cert.signers_bitmap = (1ULL << f.committee.members.size()) - 1;
    cert.agg = vx::consensus::gqc::aggregate_votes(105, cert.signers_bitmap, cert.votes);

    auto bad = cert;
    bad.agg[0] ^= 0x01;
    EXPECT_FALSE(vx::consensus::gqc::verify_checkpoint(bad, f.view));
}

// ── 2. Rollover certificate ─────────────────────────────────────────────────

// The rollover cert: the old tree's leaf 15 signs the new whitelist.
TEST(VortexGqcCheckpointTest, RolloverVerifies) {
    Fixture f;
    // The old master root: the whitelist's own master root (the epoch-1
    // master tree is the rollover tree in this deterministic test).
    const auto old_root = f.committee.master_root;
    std::vector<std::array<uint8_t, 32>> new_roots;
    for (const auto &m : f.committee.members)
        new_roots.push_back(m.root);

    // The rollover signer is the master key itself (the same key that
    // signs the whitelist — the deterministic test vector, as in
    // genesis.cpp), on leaf 15: the designated rollover leaf.
    std::array<uint8_t, 32> master_sk{};
    vx::blockchain::VortexSponge256::compute(
        reinterpret_cast<const uint8_t *>("VX_GQC_EPOCH1_MASTER_SK_V1"), 26, master_sk.data());
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(master_sk);
    const auto msg = vx::consensus::gqc::rollover_msg(1, 2, old_root, new_roots);
    const auto leaf = f.ledger.reserve_cert_leaf(old_root);
    ASSERT_GE(leaf, 0);
    EXPECT_EQ(leaf, 15); // the rollover leaf is reserved for this

    GqcRolloverCert cert;
    cert.old_epoch = 1;
    cert.new_epoch = 2;
    cert.old_master_root = old_root;
    cert.new_roots = new_roots;
    cert.rollover_witness =
        vx::crypto::pq::pq_sign_message(static_cast<uint32_t>(leaf), 0, master_sk, pub_seed, msg);

    EXPECT_TRUE(vx::consensus::gqc::verify_rollover(cert, new_roots));
}

// Epochs only move forward: a rollover to an older epoch must fail.
TEST(VortexGqcCheckpointTest, RolloverBackwardsEpochFails) {
    Fixture f;
    const auto old_root = f.committee.master_root;
    std::vector<std::array<uint8_t, 32>> new_roots;
    for (const auto &m : f.committee.members)
        new_roots.push_back(m.root);

    std::array<uint8_t, 32> master_sk{};
    vx::blockchain::VortexSponge256::compute(
        reinterpret_cast<const uint8_t *>("VX_GQC_EPOCH1_MASTER_SK_V1"), 26, master_sk.data());
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(master_sk);
    // The message binds new_epoch=2, but the cert claims new_epoch=1 —
    // the witness no longer verifies over the cert's claimed content.
    const auto msg = vx::consensus::gqc::rollover_msg(2, 2, old_root, new_roots);
    const auto leaf = f.ledger.reserve_cert_leaf(old_root);
    ASSERT_GE(leaf, 0);

    GqcRolloverCert cert;
    cert.old_epoch = 2;
    cert.new_epoch = 1; // backwards: refused before verification
    cert.old_master_root = old_root;
    cert.new_roots = new_roots;
    cert.rollover_witness =
        vx::crypto::pq::pq_sign_message(static_cast<uint32_t>(leaf), 0, master_sk, pub_seed, msg);
    EXPECT_FALSE(vx::consensus::gqc::verify_rollover(cert, new_roots));
}

// A rollover witness under a foreign tree must fail (root gate).
TEST(VortexGqcCheckpointTest, RolloverForeignRootFails) {
    Fixture f;
    const auto old_root = f.committee.master_root;
    std::vector<std::array<uint8_t, 32>> new_roots;
    for (const auto &m : f.committee.members)
        new_roots.push_back(m.root);

    std::array<uint8_t, 32> master_sk{};
    vx::blockchain::VortexSponge256::compute(
        reinterpret_cast<const uint8_t *>("VX_GQC_EPOCH1_MASTER_SK_V1"), 26, master_sk.data());
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(master_sk);
    const auto msg = vx::consensus::gqc::rollover_msg(1, 2, old_root, new_roots);
    const auto leaf = f.ledger.reserve_cert_leaf(old_root);
    ASSERT_GE(leaf, 0);

    GqcRolloverCert cert;
    cert.old_epoch = 1;
    cert.new_epoch = 2;
    cert.old_master_root = old_root;
    cert.new_roots = new_roots;
    cert.rollover_witness =
        vx::crypto::pq::pq_sign_message(static_cast<uint32_t>(leaf), 0, master_sk, pub_seed, msg);
    cert.rollover_witness.pq_pubkey_root[0] ^= 0xFF; // foreign tree

    EXPECT_FALSE(vx::consensus::gqc::verify_rollover(cert, new_roots));
}
