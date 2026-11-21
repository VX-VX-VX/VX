// VortexGqcRingStealthTest — GQC finality, ring pipeline, stealth envelopes
//
// Verifies:
//   1. GQC finality: a certified checkpoint makes rollback_to_height below
//      it fail with ERR_FINALIZED_BY_GQC (absolute deep-reorg protection).
//   2. RingPipeline: 100k+ txs through the lock-free ring with zero heap
//      allocations, TDI spam annihilated before entering the ring.
//   3. Stealth 1-of-16: envelope creation, own-IVK scan finds the incoming
//      transfer, a foreign IVK finds nothing.

#include <gtest/gtest.h>
#include "vx/consensus/gqc_finality.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/core/ring_pipeline.hpp"
#include "vx/crypto/zk_key_matrix.hpp"

#include <cstring>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <random>
#include <unistd.h>

using vx::consensus::GqcFinality;
using vx::core::RingPipeline;
using vx::blockchain::Transaction;

// Phase C: sign a committee member's vote with its deterministic test key.
// One PqLeafLedger serves all members — the ledger is keyed by XMSS root.
static vx::consensus::gqc::GqcVote member_vote(uint16_t validator_id, uint64_t height,
                                               const std::array<uint8_t, 32> &block_hash,
                                               vx::crypto::pq::PqLeafLedger &ledger) {
    const auto sk = vx::blockchain::gqc_epoch_validator_sk(validator_id);
    const auto &committee = vx::blockchain::gqc_epoch_committee();
    return vx::consensus::gqc::sign_vote(validator_id, sk, committee.epoch, height, block_hash,
                                         ledger);
}

// Mines one PoGW-sealed block on the current tip. Finality tests vote on
// the tip height: the finalized-height gate refuses votes at the genesis
// height (height 0 is implicitly final everywhere) and stamp_gqc records
// only heights that exist in the store — so every finality test mines first.
static bool mine_one_block(vx::storage::BlockStore &store) {
    vx::blockchain::BlockBuilder builder;
    builder.set_height(store.chain_height());
    builder.set_timestamp(1'761'000'005ULL); // >= genesis ts
    uint8_t tip0[32] = {};
    store.tip_hash(tip0);
    builder.set_prev_hash(tip0);
    std::array<uint8_t, 384> coords{};
    builder.set_attractor_coords(coords.data());
    vx::blockchain::Transaction mint{};
    vx::blockchain::set_nfa_field(mint.sender_nfa, "MINER_GQC_TEST_000000000000000000000000000");
    vx::blockchain::set_nfa_field(mint.receiver_nfa, "GQC_TEST_RECV_0000000000000000000000000000");
    vx::blockchain::tx_set_amount(mint, 1'000'000);
    vx::blockchain::tx_set_fee(mint, 100);
    vx::blockchain::set_coinbase_binding(mint, store.chain_height(), tip0);
    builder.add_transaction(mint);
    builder.finalize();
    vx::blockchain::BlockFrame frame;
    std::memcpy(frame.data(), builder.bytes().data(), 65536);
    if (!vx::blockchain::seal_pogw_nonce(frame, 1))
        return false;
    return store.append_block(frame);
}

// ── 1. GQC finality ─────────────────────────────────────────────────────────

// Plan step 3: the genesis epoch committee is a protocol constant — two
// invocations must return byte-identical data (deterministic derivation).
TEST(VortexGqcRingStealthTest, GqcEpochCommitteeDeterministic) {
    const auto &a = vx::blockchain::gqc_epoch_committee();
    const auto &b = vx::blockchain::gqc_epoch_committee();
    ASSERT_EQ(&a, &b) << "the committee config must be a process-wide singleton";
    ASSERT_EQ(a.members.size(), 4u) << "localhost topology: 4 validators";
    // The members are canonically sorted by root bytes, so the ids are not
    // necessarily in tag order — check the SET instead.
    uint16_t id_mask = 0;
    for (const auto &m : a.members)
        id_mask |= static_cast<uint16_t>(1u << m.validator_id);
    EXPECT_EQ(id_mask, 0x0F);
    // The whitelist message must be a pure function of the member list.
    const auto msg1 = vx::blockchain::gqc_epoch_whitelist_msg(a.members);
    const auto msg2 = vx::blockchain::gqc_epoch_whitelist_msg(b.members);
    EXPECT_EQ(msg1, msg2);
    // Membership gate: every member is contained, a foreign id is not.
    for (const auto &m : a.members)
        EXPECT_TRUE(vx::blockchain::gqc_epoch_committee_contains(m.validator_id));
    EXPECT_FALSE(vx::blockchain::gqc_epoch_committee_contains(a.members.size()));
    EXPECT_FALSE(vx::blockchain::gqc_epoch_committee_contains(9999));
}

// Plan step 3: the architect's master key signs the whitelist. The shipped
// (list, sig) pair must verify against the pinned master root — and the
// signature must bind EXACTLY this list (a mutated member list breaks it).
TEST(VortexGqcRingStealthTest, GqcEpochCommitteeMasterSigVerifies) {
    const auto &cfg = vx::blockchain::gqc_epoch_committee();
    const auto msg = vx::blockchain::gqc_epoch_whitelist_msg(cfg.members);
    EXPECT_TRUE(vx::crypto::pq::pq_verify_wots_xmss(msg, cfg.master_sig))
        << "the shipped (list, sig) pair must verify against the master root";
    EXPECT_EQ(cfg.master_sig.pq_pubkey_root, cfg.master_root)
        << "the witness root must equal the pinned master root";
    // Tamper check: a single flipped validator id must break the signature.
    auto mutated = cfg.members;
    mutated[0].validator_id = 99;
    const auto bad_msg = vx::blockchain::gqc_epoch_whitelist_msg(mutated);
    EXPECT_FALSE(vx::crypto::pq::pq_verify_wots_xmss(bad_msg, cfg.master_sig))
        << "an edited list must fail verification (fail-closed self-check)";
}

TEST(VortexGqcRingStealthTest, GqcFinalizedReorgBlocked) {
    const std::string tmp_dir = (std::filesystem::temp_directory_path() / ("vx_gqc_test_" + std::to_string(::getpid()))).string();
    std::filesystem::create_directories(tmp_dir);

    vx::storage::BlockStore store(tmp_dir + "/gqc_ledger.vxb", "genesis.bin", 1);

    // Ensure a real (non-genesis) tip exists to certify.
    if (store.chain_height() < 2)
        ASSERT_TRUE(mine_one_block(store)) << "test block rejected";

    vx::state::LedgerState ledger;
    vx::state::UndoEngine undo(tmp_dir, store, ledger);
    GqcFinality gqc(undo, store);

    const uint64_t height = store.chain_height();
    ASSERT_GE(height, 1u); // genesis auto-seeded
    const uint64_t tip_h = height - 1;

    uint8_t tip[32];
    store.tip_hash(tip);
    std::array<uint8_t, 32> block_hash{};
    std::memcpy(block_hash.data(), tip, 32);

    // Collect votes from the genesis epoch committee, finalize the tip.
    const auto &committee = vx::blockchain::gqc_epoch_committee();
    const uint32_t kValidators = static_cast<uint32_t>(committee.members.size());
    vx::crypto::pq::PqLeafLedger vote_ledger;
    // Quorum threshold first: 2 of the 4 members < 2/3 (3 needed) — no
    // certification, no lock. Then the remaining votes complete the quorum.
    uint16_t collected = 0;
    for (const auto &m : committee.members) {
        if (collected++ >= 2)
            break;
        gqc.collect_vote(tip_h, block_hash,
                         member_vote(m.validator_id, tip_h, block_hash, vote_ledger));
    }
    const auto cert_pending = gqc.finalize_block(tip_h, block_hash, kValidators);
    EXPECT_FALSE(cert_pending.certified);
    EXPECT_NE(cert_pending.error.find("quorum"), std::string::npos);
    EXPECT_EQ(gqc.finalized_checkpoint_height(), 0u) << "a failed quorum must not cement";

    for (const auto &m : committee.members) {
        gqc.collect_vote(tip_h, block_hash,
                         member_vote(m.validator_id, tip_h, block_hash, vote_ledger));
    }
    const auto cert = gqc.finalize_block(tip_h, block_hash, kValidators);
    ASSERT_TRUE(cert.certified) << cert.error;
    EXPECT_EQ(cert.share_count, committee.members.size());
    EXPECT_EQ(cert.gqc_signature_agg.size(), 32u);
    EXPECT_EQ(gqc.finalized_checkpoint_height(), tip_h);
    EXPECT_EQ(undo.finalized_checkpoint_height(), tip_h);

    // The aggregate is persisted as a sidecar record (<ledger>.gqc) — the
    // frame tail has no free bytes (VM/PoGW metadata), and the certified
    // frame must stay byte-identical after certification (round 5).
    const auto* raw = store.get_block(tip_h);
    ASSERT_NE(raw, nullptr);
    uint8_t persisted[32];
    ASSERT_TRUE(store.gqc_stamp(tip_h, persisted)) << "sidecar record missing";
    EXPECT_EQ(std::memcmp(persisted, cert.gqc_signature_agg.data(), 32), 0);

    // Deep reorg below the checkpoint is now impossible. Rolling back to the
    // checkpoint itself stays legal (removes nothing above it).
    for (uint64_t h = 0; h < tip_h; ++h) {
        EXPECT_FALSE(undo.rollback_to_height(h));
        EXPECT_EQ(undo.last_error(), "ERR_FINALIZED_BY_GQC") << "height " << h;
    }

    std::filesystem::remove_all(tmp_dir);
}

// ── BACKLOG 0.13: the finalized checkpoint outlives the process. After a
// restart the rollback guard must report at least the persisted cemented
// height (fail-closed, monotonic), a rollback below it must still be
// refused, and a sidecar that does not parse cleanly must not be trusted.
TEST(VortexGqcRingStealthTest, GqcCheckpointSurvivesRestart) {
    const std::string tmp_dir = (std::filesystem::temp_directory_path() / ("vx_gqc_restart_" + std::to_string(::getpid()))).string();
    std::filesystem::create_directories(tmp_dir);

    vx::storage::BlockStore store(tmp_dir + "/gqc_restart.vxb", "genesis.bin", 1);

    // Mine one block so there is a non-genesis tip to certify.
    {
        vx::blockchain::BlockBuilder builder;
        builder.set_height(store.chain_height());
        builder.set_timestamp(1'761'000'005ULL); // >= genesis ts
        uint8_t tip0[32] = {};
        store.tip_hash(tip0);
        builder.set_prev_hash(tip0);
        std::array<uint8_t, 384> coords{};
        builder.set_attractor_coords(coords.data());
        vx::blockchain::Transaction mint{};
        vx::blockchain::set_nfa_field(mint.sender_nfa, "MINER_GQC_RESTART_000000000000000000000000");
        vx::blockchain::set_nfa_field(mint.receiver_nfa, "GQC_RESTART_RECV_00000000000000000000000");
        vx::blockchain::tx_set_amount(mint, 1'000'000);
        vx::blockchain::tx_set_fee(mint, 100);
        vx::blockchain::set_coinbase_binding(mint, store.chain_height(), tip0);
        builder.add_transaction(mint);
        builder.finalize();
        vx::blockchain::BlockFrame frame;
        std::memcpy(frame.data(), builder.bytes().data(), 65536);
        ASSERT_TRUE(vx::blockchain::seal_pogw_nonce(frame, 1)) << "PoGW seal failed";
        ASSERT_TRUE(store.append_block(frame)) << "test block rejected";
    }
    const uint64_t tip_h = store.chain_height() - 1;
    ASSERT_GE(tip_h, 1u);

    // Session 1: certify the tip with a full quorum.
    {
        vx::state::LedgerState ledger;
        vx::state::UndoEngine undo(tmp_dir, store, ledger);
        GqcFinality gqc(undo, store);
        uint8_t tip[32];
        store.tip_hash(tip);
        std::array<uint8_t, 32> block_hash{};
        std::memcpy(block_hash.data(), tip, 32);
        vx::crypto::pq::PqLeafLedger vote_ledger;
        for (const auto &m : vx::blockchain::gqc_epoch_committee().members) {
            gqc.collect_vote(tip_h, block_hash,
                             member_vote(m.validator_id, tip_h, block_hash, vote_ledger));
        }
        const auto cert = gqc.finalize_block(
            tip_h, block_hash,
            static_cast<uint32_t>(vx::blockchain::gqc_epoch_committee().members.size()));
        ASSERT_TRUE(cert.certified) << cert.error;
        EXPECT_EQ(undo.finalized_checkpoint_height(), tip_h);
    }

    // Session 2 (the restart): a fresh ledger and a fresh undo engine over
    // the SAME store — the guard must come back from the sidecar.
    {
        vx::state::LedgerState ledger2;
        vx::state::UndoEngine undo2(tmp_dir, store, ledger2);
        EXPECT_TRUE(undo2.finalized_sidecar_trusted());
        EXPECT_EQ(undo2.finalized_checkpoint_height(), tip_h)
            << "the checkpoint evaporated on restart (RAM-only guard)";
        // Monotonic: a lower cement attempt cannot lower the guard.
        undo2.lock_finalized_height(0);
        EXPECT_EQ(undo2.finalized_checkpoint_height(), tip_h);
        // Acceptance: rolling back BELOW the persisted checkpoint is refused.
        EXPECT_FALSE(undo2.rollback_to_height(tip_h - 1));
        EXPECT_EQ(undo2.last_error(), "ERR_FINALIZED_BY_GQC");
    }

    // A sidecar that does not parse cleanly is not trusted: nothing is
    // fabricated, the engine says so, and the journal still works.
    {
        std::ofstream f(tmp_dir + "/gqc_restart.vxb.gqc",
                        std::ios::binary | std::ios::app);
        // A full-size garbage record: with 52-byte v2 records, appending
        // fewer bytes presents as a torn TAIL (healed conservatively —
        // truncation can only lower the guard), while a complete record
        // with a bad magic tag must fail the read closed.
        f << std::string(52, '\xFF'); // corrupt record after the valid ones
    }
    {
        vx::state::LedgerState ledger3;
        vx::state::UndoEngine undo3(tmp_dir, store, ledger3);
        EXPECT_FALSE(undo3.finalized_sidecar_trusted());
        EXPECT_EQ(undo3.finalized_checkpoint_height(), 0u)
            << "a corrupt sidecar must not fabricate a checkpoint";
    }

    std::filesystem::remove_all(tmp_dir);
}

// Phase C: the honest-gap test from the share era is now CLOSED. A quorum
// forged from public data alone must FAIL — every vote must verify against
// a whitelist member's XMSS root, and public data yields no signature. The
// forged votes are dropped by the verify-before-store gate and the
// certificate never reaches the quorum.
TEST(VortexGqcRingStealthTest, GqcQuorumForgeFailsClosed) {
    const std::string tmp_dir = (std::filesystem::temp_directory_path() / ("vx_gqc_forge_" + std::to_string(::getpid()))).string();
    std::filesystem::create_directories(tmp_dir);

    vx::storage::BlockStore store(tmp_dir + "/gqc_forge_ledger.vxb", "genesis.bin", 1);
    ASSERT_TRUE(mine_one_block(store)) << "test block rejected";
    vx::state::LedgerState ledger;
    vx::state::UndoEngine undo(tmp_dir, store, ledger);
    GqcFinality gqc(undo, store);

    const uint64_t height = store.chain_height();
    ASSERT_GE(height, 1u);
    const uint64_t tip_h = height - 1;
    uint8_t tip[32];
    store.tip_hash(tip);
    std::array<uint8_t, 32> block_hash{};
    std::memcpy(block_hash.data(), tip, 32);

    // Attack: feed a full quorum of WITNESS-FREE votes (default witnesses do
    // not verify against any root). The membership gate passes — the ids are
    // real members — but verify-before-store drops every vote.
    const auto &committee = vx::blockchain::gqc_epoch_committee();
    const uint32_t kValidators = static_cast<uint32_t>(committee.members.size());
    for (const auto &m : committee.members) {
        gqc.collect_vote(tip_h, block_hash, vx::consensus::gqc::GqcVote{m.validator_id, {}});
    }
    const auto cert = gqc.finalize_block(tip_h, block_hash, kValidators);

    // The closed gate: no key, no certificate. The error names the missing
    // votes, and the checkpoint is never cemented.
    EXPECT_FALSE(cert.certified) << "a witness-free quorum must not certify";
    EXPECT_EQ(cert.share_count, 0u);
    EXPECT_NE(cert.error.find("no votes"), std::string::npos);
    EXPECT_EQ(gqc.finalized_checkpoint_height(), 0u);
    std::filesystem::remove_all(tmp_dir);
}

// ── Phase C accountability: equivocation, forged-id gate, bitmap ────────────

// Equivocation: a member that signs TWO DIFFERENT block hashes at the same
// height is provably guilty. The proof carries both verified witnesses and
// is recorded once (the first valid evidence); further conflicting votes
// from the same guilty member are O(1) drops.
TEST(VortexGqcRingStealthTest, GqcEquivocationProofRecordedAndDeduped) {
    const std::string tmp_dir =
        (std::filesystem::temp_directory_path() / ("vx_gqc_equiv_" + std::to_string(::getpid())))
            .string();
    std::filesystem::create_directories(tmp_dir);

    vx::storage::BlockStore store(tmp_dir + "/gqc_equiv.vxb", "genesis.bin", 1);
    ASSERT_TRUE(mine_one_block(store)) << "test block rejected";
    vx::state::LedgerState ledger;
    vx::state::UndoEngine undo(tmp_dir, store, ledger);
    GqcFinality gqc(undo, store);

    const uint64_t height = store.chain_height();
    ASSERT_GE(height, 1u);
    const uint64_t tip_h = height - 1;
    uint8_t tip[32];
    store.tip_hash(tip);
    std::array<uint8_t, 32> hash_a{};
    std::memcpy(hash_a.data(), tip, 32);
    std::array<uint8_t, 32> hash_b = hash_a;
    hash_b[0] ^= 0x01;

    vx::crypto::pq::PqLeafLedger vote_ledger;
    const auto guilty_id = vx::blockchain::gqc_epoch_committee().members[0].validator_id;
    // Fork A: the member votes for the canonical tip.
    gqc.collect_vote(tip_h, hash_a, member_vote(guilty_id, tip_h, hash_a, vote_ledger));
    // Fork B: the same member votes for a DIFFERENT hash at the same height.
    gqc.collect_vote(tip_h, hash_b, member_vote(guilty_id, tip_h, hash_b, vote_ledger));
    // A third conflicting vote — the proof is already recorded: O(1) drop.
    std::array<uint8_t, 32> hash_c = hash_a;
    hash_c[1] ^= 0x01;
    gqc.collect_vote(tip_h, hash_c, member_vote(guilty_id, tip_h, hash_c, vote_ledger));

    const auto proofs = gqc.take_equivocations();
    ASSERT_EQ(proofs.size(), 1u) << "the first valid evidence is the proof; the rest drop";
    EXPECT_EQ(proofs[0].validator_id, guilty_id);
    EXPECT_EQ(proofs[0].height, tip_h);
    EXPECT_EQ(proofs[0].block_hash_a, hash_a);
    EXPECT_EQ(proofs[0].block_hash_b, hash_b);
    // Both witnesses are real evidence: they verify under the member root.
    const auto member_root = vx::blockchain::gqc_epoch_committee().members[0].root;
    EXPECT_TRUE(vx::consensus::gqc::verify_vote(member_root,
                                                vx::blockchain::gqc_epoch_committee().epoch, tip_h,
                                                hash_a, {guilty_id, proofs[0].witness_a}));
    EXPECT_TRUE(vx::consensus::gqc::verify_vote(member_root,
                                                vx::blockchain::gqc_epoch_committee().epoch, tip_h,
                                                hash_b, {guilty_id, proofs[0].witness_b}));
    // The pool is empty: the proof drained.
    EXPECT_TRUE(gqc.take_equivocations().empty());

    std::filesystem::remove_all(tmp_dir);
}

// The membership gate: a vote from a validator_id NOT on the whitelist is
// forged — it never pools, so the certificate can never reach a quorum.
TEST(VortexGqcRingStealthTest, GqcForgedIdVoteRefused) {
    const std::string tmp_dir =
        (std::filesystem::temp_directory_path() / ("vx_gqc_forge_id_" + std::to_string(::getpid())))
            .string();
    std::filesystem::create_directories(tmp_dir);

    vx::storage::BlockStore store(tmp_dir + "/gqc_forge_id.vxb", "genesis.bin", 1);
    ASSERT_TRUE(mine_one_block(store)) << "test block rejected";
    vx::state::LedgerState ledger;
    vx::state::UndoEngine undo(tmp_dir, store, ledger);
    GqcFinality gqc(undo, store);

    const uint64_t tip_h = store.chain_height() - 1;
    uint8_t tip[32];
    store.tip_hash(tip);
    std::array<uint8_t, 32> block_hash{};
    std::memcpy(block_hash.data(), tip, 32);

    // A foreign id (9999) with a perfectly valid witness from a REAL member
    // key: the id gate fires first — the id, not the witness, is the pool key.
    vx::crypto::pq::PqLeafLedger vote_ledger;
    auto forged = member_vote(0, tip_h, block_hash, vote_ledger);
    forged.validator_id = 9999;
    gqc.collect_vote(tip_h, block_hash, forged);
    // A real member id with a WITNESS-FREE vote: verify-before-store drops it.
    gqc.collect_vote(tip_h, block_hash, vx::consensus::gqc::GqcVote{0, {}});

    const auto cert = gqc.finalize_block(
        tip_h, block_hash,
        static_cast<uint32_t>(vx::blockchain::gqc_epoch_committee().members.size()));
    EXPECT_FALSE(cert.certified);
    EXPECT_EQ(cert.share_count, 0u);
    EXPECT_TRUE(gqc.take_equivocations().empty());
    std::filesystem::remove_all(tmp_dir);
}

// The certificate records exactly WHO signed: the bitmap over the
// canonically-ordered whitelist, and the aggregate commits to that set.
TEST(VortexGqcRingStealthTest, GqcCertBitmapCoversFullQuorum) {
    const std::string tmp_dir =
        (std::filesystem::temp_directory_path() / ("vx_gqc_bitmap_" + std::to_string(::getpid())))
            .string();
    std::filesystem::create_directories(tmp_dir);

    vx::storage::BlockStore store(tmp_dir + "/gqc_bitmap.vxb", "genesis.bin", 1);
    ASSERT_TRUE(mine_one_block(store)) << "test block rejected";
    vx::state::LedgerState ledger;
    vx::state::UndoEngine undo(tmp_dir, store, ledger);
    GqcFinality gqc(undo, store);

    const uint64_t tip_h = store.chain_height() - 1;
    uint8_t tip[32];
    store.tip_hash(tip);
    std::array<uint8_t, 32> block_hash{};
    std::memcpy(block_hash.data(), tip, 32);

    const auto &committee = vx::blockchain::gqc_epoch_committee();
    vx::crypto::pq::PqLeafLedger vote_ledger;
    for (const auto &m : committee.members) {
        gqc.collect_vote(tip_h, block_hash,
                         member_vote(m.validator_id, tip_h, block_hash, vote_ledger));
    }
    const auto cert =
        gqc.finalize_block(tip_h, block_hash, static_cast<uint32_t>(committee.members.size()));
    ASSERT_TRUE(cert.certified) << cert.error;
    EXPECT_EQ(cert.share_count, committee.members.size());
    // Every member is a signer: a 4-member committee sets exactly 4 bits.
    EXPECT_EQ(cert.signers_bitmap, (1u << committee.members.size()) - 1);
    // The aggregate is a commitment to the exact signer set: the same
    // (height, bitmap, votes) folds deterministically, and the persisted
    // sidecar record matches the certified aggregate.
    uint8_t persisted[32];
    ASSERT_TRUE(store.gqc_stamp(tip_h, persisted)) << "sidecar record missing";
    EXPECT_EQ(std::memcmp(persisted, cert.gqc_signature_agg.data(), 32), 0);
    std::filesystem::remove_all(tmp_dir);
}

// ── 2. Lock-free ring pipeline ──────────────────────────────────────────────

namespace {
Transaction ring_tx(uint32_t fee, uint64_t amount, uint32_t nonce) {
    Transaction tx{};
    std::memset(&tx, 0, sizeof(tx));
    vx::blockchain::set_nfa_field(tx.sender_nfa, "RING_PIPELINE_TEST_SENDER_0000000000000000");
    vx::blockchain::set_nfa_field(tx.receiver_nfa, "RING_PIPELINE_TEST_RECV_000000000000000000");
    vx::blockchain::tx_set_amount(tx, amount);
    vx::blockchain::tx_set_fee(tx, fee);
    vx::blockchain::tx_set_nonce(tx, nonce);
    return tx;
}
} // namespace

TEST(VortexGqcRingStealthTest, RingPipelineThroughputNoAllocs) {
    RingPipeline pipe(/*min_tdi=*/1000);

    constexpr size_t kN = 100'000;
    // Push/consume in batches below CAPACITY: a single-threaded test cannot
    // drain the ring while it is full (the producer would spin on slots the
    // consumer has not reached yet).
    constexpr size_t kBatch = 4096;
    uint64_t spam = 0;
    Transaction out{};
    uint64_t consumed = 0;
    uint32_t last_nonce = 0;
    bool ordered = true;
    const auto t0 = std::chrono::steady_clock::now();
    for (size_t i = 0; i < kN; i += kBatch) {
        const size_t end = std::min(i + kBatch, kN);
        for (size_t j = i; j < end; ++j) {
            // Every 10th tx is zero-fee spam: (1 * 1024) / 112 = 9 < 1000.
            const bool is_spam = (j % 10 == 0);
            spam += is_spam ? 1 : 0;
            const uint32_t fee = is_spam ? 1u : 400u; // 400*1024/112 = 3657 >= 1000
            EXPECT_EQ(pipe.push(ring_tx(fee, 100 + j, static_cast<uint32_t>(j))), !is_spam);
        }
        while (pipe.consume(out)) {
            const uint32_t nonce = vx::blockchain::tx_nonce(out);
            if (consumed > 0 && nonce < last_nonce) ordered = false;
            last_nonce = nonce;
            ++consumed;
        }
    }
    const auto t1 = std::chrono::steady_clock::now();

    // All legit txs consumed, all spam annihilated before the ring.
    EXPECT_EQ(consumed, kN - spam);
    const auto st = pipe.stats();
    EXPECT_EQ(st.spam_filtered, spam);
    EXPECT_EQ(st.pushed, kN - spam);
    EXPECT_EQ(st.consumed, consumed);
    EXPECT_EQ(st.heap_allocations, 0u); // structural: no allocator on the path

    // FIFO ticket order preserved for single producer/consumer.
    EXPECT_TRUE(ordered);

    const double seconds = std::chrono::duration<double>(t1 - t0).count();
    const double tps = static_cast<double>(kN) / seconds;
    // The 500k tps floor is a RELEASE-build directive. Under TSan the
    // instrumentation itself is a ~3-5x multiplier, and a soft lane runs
    // ctest -j4 beside other instrumented suites on a small laptop — the
    // timing assertion there measures machine load, not the pipeline (the
    // P3 flake that blocked two lanes on 2026-11-15). Sanitizer builds
    // keep every STRUCTURAL assertion (ordering, filtering, zero allocs)
    // and drop only the wall-clock floor.
#if defined(__SANITIZE_THREAD__) || (defined(__has_feature) && __has_feature(thread_sanitizer))
    const double kTpsFloor = 50'000.0;
    EXPECT_GT(tps, kTpsFloor) << "pipeline throughput below sanitizer floor: " << tps;
#else
    EXPECT_GT(tps, 500'000.0) << "pipeline throughput below directive floor: " << tps;
#endif
}

TEST(VortexGqcRingStealthTest, RingPipelineWrapAround) {
    RingPipeline pipe(/*min_tdi=*/0); // no spam filtering
    // Push/consume more than CAPACITY to exercise the ring wrap-around.
    Transaction out{};
    for (size_t round = 0; round < 3; ++round) {
        for (size_t i = 0; i < RingPipeline::CAPACITY / 4; ++i) {
            ASSERT_TRUE(pipe.push(ring_tx(100u, i, static_cast<uint32_t>(round * 1000 + i))));
        }
        for (size_t i = 0; i < RingPipeline::CAPACITY / 4; ++i) {
            ASSERT_TRUE(pipe.consume(out));
            EXPECT_EQ(vx::blockchain::tx_nonce(out), round * 1000 + i);
        }
    }
}

// ── 3. Stealth Ring Envelopes 1-of-16 ───────────────────────────────────────

TEST(VortexGqcRingStealthTest, StealthEnvelopeOneOfSixteen) {
    using namespace vx::crypto;

    std::array<uint8_t, 32> recipient_seed{};
    for (size_t i = 0; i < 32; ++i) recipient_seed[i] = static_cast<uint8_t>(0x11 * i + 3);
    const auto recv_keys = derive_stealth_hierarchy(recipient_seed);

    // Hierarchy properties: all four keys distinct, IVK != SK.
    EXPECT_NE(recv_keys.sk, recv_keys.fvk);
    EXPECT_NE(recv_keys.fvk, recv_keys.ivk);
    EXPECT_NE(recv_keys.ivk, recv_keys.ovk);

    std::array<uint8_t, 32> sender_seed{};
    for (size_t i = 0; i < 32; ++i) sender_seed[i] = static_cast<uint8_t>(0xA5 ^ i);

    std::vector<std::array<uint8_t, 42>> decoys;
    for (int i = 0; i < 15; ++i) {
        std::array<uint8_t, 42> d{};
        vx::blockchain::set_nfa_field(d, "LEDGER_DECOY_ADDR_000000000000000000000000");
        d[18] = static_cast<uint8_t>(i);
        decoys.push_back(d);
    }

    const auto env = create_stealth_envelope(sender_seed, recv_keys.ivk, decoys);
    EXPECT_EQ(env.ring_members.size(), 16u);
    EXPECT_LT(env.real_index, 16u);
    EXPECT_EQ(std::memcmp(env.ring_members[env.real_index].data(),
                          env.stealth_addr.data(), 42), 0);
    EXPECT_EQ(std::memcmp(env.stealth_addr.data(), "NFA_ST_", 7), 0);

    // Stamp the envelope into a transaction and hide it among 578 noise txs
    // (a full VXC7 block: 1 stealth + 578 noise = MAX_TX_PER_BLOCK).
    Transaction stealth{};
    vx::blockchain::set_nfa_field(stealth.sender_nfa, "STEALTH_TEST_SENDER_0000000000000000000000");
    vx::blockchain::tx_set_amount(stealth, 999'999);
    vx::blockchain::tx_set_fee(stealth, 750);
    stamp_stealth_envelope(env, stealth);

    std::vector<Transaction> block(579);
    std::mt19937 rng(0xFEED);
    for (auto& tx : block) {
        std::memset(&tx, 0, sizeof(tx));
        vx::blockchain::set_nfa_field(tx.sender_nfa, "NOISE_SENDER_00000000000000000000000000000");
        vx::blockchain::set_nfa_field(tx.receiver_nfa, "NOISE_RECV_0000000000000000000000000000000");
        tx.receiver_nfa[9] = static_cast<uint8_t>(rng() & 0xFF);
        vx::blockchain::tx_set_amount(tx, rng());
        vx::blockchain::tx_set_fee(tx, 300);
    }
    const size_t stealth_pos = env.ephemeral_pub[0] % block.size();
    block[stealth_pos] = stealth;

    // Own IVK: exactly one incoming transfer found, at the stamped position.
    const auto hits = scan_transactions_with_ivk(recv_keys.ivk, std::span<const Transaction>(block));
    ASSERT_EQ(hits.size(), 1u);
    EXPECT_EQ(hits[0], stealth_pos);

    // A foreign IVK observes only random one-time strings: zero hits.
    std::array<uint8_t, 32> foreign_seed{};
    for (size_t i = 0; i < 32; ++i) foreign_seed[i] = static_cast<uint8_t>(0xEE ^ i);
    const auto foreign = derive_stealth_hierarchy(foreign_seed);
    const auto foreign_hits = scan_transactions_with_ivk(foreign.ivk, std::span<const Transaction>(block));
    EXPECT_EQ(foreign_hits.size(), 0u);

    // Envelope determinism: same inputs -> same stealth address & key image.
    const auto env2 = create_stealth_envelope(sender_seed, recv_keys.ivk, decoys);
    EXPECT_EQ(env2.stealth_addr, env.stealth_addr);
    EXPECT_EQ(env2.key_image, env.key_image);
    EXPECT_EQ(env2.scan_tag, env.scan_tag);
}
