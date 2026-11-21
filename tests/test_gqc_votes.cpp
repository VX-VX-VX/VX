// GQC Bitmasked m-of-n committee votes — Phase C (0.2.2) regression tests.
// The vote is a real XMSS signature bound to (epoch, height, block_hash);
// the aggregator verifies against the whitelist member root (never the
// root transported inside the witness) and the one-shot leaf discipline
// holds (a leaf that signed a vote never signs another).
#include <gtest/gtest.h>

#include "vx/consensus/gqc_votes.hpp"
#include "vx/blockchain/crypto_sponge.hpp"

#include <string>

namespace {

std::array<uint8_t, 32> test_sk(uint16_t id) {
    // Independent of the genesis whitelist tags: the vote module must be
    // testable without the genesis self-check in the loop.
    const std::string tag = "VX_GQC_VOTE_TEST_SK_" + std::to_string(id) + "_V1";
    std::array<uint8_t, 32> out{};
    vx::blockchain::VortexSponge256::compute(reinterpret_cast<const uint8_t *>(tag.data()),
                                             tag.size(), out.data());
    return out;
}

std::array<uint8_t, 32> test_hash(uint64_t h) {
    const std::string tag = "VX_GQC_VOTE_TEST_HASH_" + std::to_string(h);
    std::array<uint8_t, 32> out{};
    vx::blockchain::VortexSponge256::compute(reinterpret_cast<const uint8_t *>(tag.data()),
                                             tag.size(), out.data());
    return out;
}

std::array<uint8_t, 32> root_of(const std::array<uint8_t, 32> &sk) {
    const auto ps = vx::crypto::pq::pub_seed_from_sk(sk);
    return vx::crypto::pq::xmss_root(sk, ps);
}

} // namespace

TEST(GqcVotes, VoteMsgIsDeterministicAndBound) {
    const auto h = test_hash(7);
    const auto a = vx::consensus::gqc::vote_msg(1, 100, h);
    const auto b = vx::consensus::gqc::vote_msg(1, 100, h);
    EXPECT_EQ(a, b);
    // Different height / hash / epoch -> a different message.
    EXPECT_NE(vx::consensus::gqc::vote_msg(1, 101, h), a);
    EXPECT_NE(vx::consensus::gqc::vote_msg(1, 100, test_hash(8)), a);
    EXPECT_NE(vx::consensus::gqc::vote_msg(2, 100, h), a);
}

TEST(GqcVotes, VoteSignVerifyRoundtrip) {
    const auto sk = test_sk(1);
    const auto root = root_of(sk);
    const auto h = test_hash(7);
    vx::crypto::pq::PqLeafLedger ledger;
    const auto vote = vx::consensus::gqc::sign_vote(1, sk, 1, 100, h, ledger);
    EXPECT_TRUE(vx::consensus::gqc::verify_vote(root, 1, 100, h, vote));
    EXPECT_EQ(vote.witness.subtree_index, vx::consensus::gqc::kVoteSubtree);

    // A tampered witness (one flipped byte in the WOTS chains) must not
    // verify — the message binding is cryptographic, not positional.
    auto tampered = vote;
    tampered.witness.wots_sig[0][0] ^= 0x01;
    EXPECT_FALSE(vx::consensus::gqc::verify_vote(root, 1, 100, h, tampered));
}

TEST(GqcVotes, VoteRejectsForeignRoot) {
    // A witness signed by a DIFFERENT key is internally valid but is not
    // membership: the verifier checks the whitelist member root first.
    const auto sk_a = test_sk(1);
    const auto sk_b = test_sk(2);
    const auto root_a = root_of(sk_a);
    const auto root_b = root_of(sk_b);
    const auto h = test_hash(7);
    vx::crypto::pq::PqLeafLedger ledger;
    const auto vote = vx::consensus::gqc::sign_vote(2, sk_b, 1, 100, h, ledger);
    // The witness is valid under its own root…
    EXPECT_TRUE(vx::consensus::gqc::verify_vote(root_b, 1, 100, h, vote));
    // …but not under a member root it does not own.
    EXPECT_FALSE(vx::consensus::gqc::verify_vote(root_a, 1, 100, h, vote));
}

TEST(GqcVotes, VoteRejectsWrongHeight) {
    const auto sk = test_sk(1);
    const auto root = root_of(sk);
    const auto h = test_hash(7);
    vx::crypto::pq::PqLeafLedger ledger;
    const auto vote = vx::consensus::gqc::sign_vote(1, sk, 1, 100, h, ledger);
    EXPECT_FALSE(vx::consensus::gqc::verify_vote(root, 1, 101, h, vote));
    EXPECT_FALSE(vx::consensus::gqc::verify_vote(root, 1, 100, test_hash(8), vote));
}

TEST(GqcVotes, LeafNeverReusedTreeExhaustionFailsClosed) {
    const auto sk = test_sk(3);
    const auto root = root_of(sk);
    const auto h = test_hash(7);
    vx::crypto::pq::PqLeafLedger ledger;
    uint32_t seen_leaf = 0xFFFFFFFFu;
    for (unsigned i = 0; i < 15; ++i) {
        const auto vote = vx::consensus::gqc::sign_vote(1, sk, 1, 100 + i, h, ledger);
        ASSERT_TRUE(vx::consensus::gqc::verify_vote(root, 1, 100 + i, h, vote)) << "vote " << i;
        EXPECT_NE(vote.witness.leaf_index, seen_leaf) << "leaf reused at vote " << i;
        seen_leaf = vote.witness.leaf_index;
    }
    // 15 usable leaves consumed: the 16th checkpoint must fail closed —
    // a default witness that does not verify, never a reused leaf.
    const auto overflow = vx::consensus::gqc::sign_vote(1, sk, 1, 115, h, ledger);
    EXPECT_FALSE(vx::consensus::gqc::verify_vote(root, 1, 115, h, overflow));
}

// ── GqcFinality pool path is covered by the ring-stealth suite (equivocation,
// forged-id gate, bitmap) — this file pins the message/verify level. ─────────

TEST(GqcVotes, AggregateCommitsToSignerSet) {
    using vx::consensus::gqc::GqcVote;
    const auto h = test_hash(7);
    vx::crypto::pq::PqLeafLedger ledger;
    std::vector<GqcVote> votes;
    for (uint16_t id = 1; id <= 3; ++id) {
        const auto sk = test_sk(id);
        votes.push_back(vx::consensus::gqc::sign_vote(id, sk, 1, 100, h, ledger));
    }
    const uint64_t bitmap = 0x7;
    const auto agg = vx::consensus::gqc::aggregate_votes(100, bitmap, votes);
    // Deterministic for the same signer set…
    EXPECT_EQ(agg, vx::consensus::gqc::aggregate_votes(100, bitmap, votes));
    // …and bound to the exact set: one vote dropped, one added, or a
    // different bitmap each change the aggregate.
    std::vector<GqcVote> fewer(votes.begin(), votes.end() - 1);
    EXPECT_NE(agg, vx::consensus::gqc::aggregate_votes(100, bitmap, fewer));
    EXPECT_NE(agg, vx::consensus::gqc::aggregate_votes(100, bitmap - 1, votes));
    EXPECT_NE(agg, vx::consensus::gqc::aggregate_votes(101, bitmap, votes));
}
