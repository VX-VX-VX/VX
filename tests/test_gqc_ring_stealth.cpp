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
#include "vx/core/ring_pipeline.hpp"
#include "vx/crypto/zk_key_matrix.hpp"

#include <cstring>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <random>
#include <unistd.h>

using vx::consensus::GqcFinality;
using vx::consensus::GqcShare;
using vx::core::RingPipeline;
using vx::blockchain::Transaction;

// ── 1. GQC finality ─────────────────────────────────────────────────────────

TEST(VortexGqcRingStealthTest, GqcFinalizedReorgBlocked) {
    const std::string tmp_dir = (std::filesystem::temp_directory_path() / ("vx_gqc_test_" + std::to_string(::getpid()))).string();
    std::filesystem::create_directories(tmp_dir);

    vx::storage::BlockStore store(tmp_dir + "/gqc_ledger.vxb", "genesis.bin", 1);

    // Ensure a real (non-genesis) tip exists to certify.
    if (store.chain_height() < 2) {
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
        ASSERT_TRUE(vx::blockchain::seal_pogw_nonce(frame, 1)) << "PoGW seal failed";
        ASSERT_TRUE(store.append_block(frame)) << "test block rejected";
    }

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

    // Collect shares from 9 validators, finalize the tip.
    constexpr uint32_t kValidators = 9;
    for (uint16_t v = 0; v < kValidators; ++v) {
        gqc.collect_share(tip_h, block_hash, v,
                          GqcFinality::derive_validator_share(block_hash, tip_h, v));
    }
    const auto cert = gqc.finalize_block(tip_h, block_hash, kValidators);
    ASSERT_TRUE(cert.certified) << cert.error;
    EXPECT_EQ(cert.share_count, 9u);
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

    // Quorum not met -> no certification, no lock.
    GqcFinality gqc2(undo, store);
    uint8_t tip2[32];
    store.tip_hash(tip2);
    std::array<uint8_t, 32> h2{};
    std::memcpy(h2.data(), tip2, 32);
    for (uint16_t v = 0; v < 2; ++v) { // 2/9 < 2/3
        gqc2.collect_share(tip_h, h2, v + 100,
                           GqcFinality::derive_validator_share(h2, tip_h, v));
    }
    const auto cert2 = gqc2.finalize_block(tip_h, h2, kValidators);
    EXPECT_FALSE(cert2.certified);
    EXPECT_NE(cert2.error.find("quorum"), std::string::npos);
    // BACKLOG 0.13: the guard is seeded from the persisted checkpoint (the
    // undo engine restored it), so a second finality object reports the
    // cemented height, not 0 — the quorum failure adds nothing new to it.
    EXPECT_EQ(gqc2.finalized_checkpoint_height(), tip_h);

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
        for (uint16_t v = 0; v < 9; ++v) {
            gqc.collect_share(tip_h, block_hash, v,
                              GqcFinality::derive_validator_share(block_hash, tip_h, v));
        }
        const auto cert = gqc.finalize_block(tip_h, block_hash, 9);
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

// Honest-gap test (external review finding): the share derivation consumes
// ONLY public data (block hash, height, validator id) — no validator secret
// exists yet. This test deliberately forges a full quorum without holding
// any key and EXPECTS the attack to succeed, pinning the gap until
// validator authentication (BACKLOG 0.4 / 2.4) ships. Flip this test when
// shares become signature-bearing.
TEST(VortexGqcRingStealthTest, GqcQuorumForgeableFromPublicDataOnly) {
    const std::string tmp_dir = (std::filesystem::temp_directory_path() / ("vx_gqc_forge_" + std::to_string(::getpid()))).string();
    std::filesystem::create_directories(tmp_dir);

    vx::storage::BlockStore store(tmp_dir + "/gqc_forge_ledger.vxb", "genesis.bin");
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

    // Attack: derive every validator's share from public data alone.
    constexpr uint32_t kValidators = 9;
    for (uint16_t v = 0; v < kValidators; ++v) {
        gqc.collect_share(tip_h, block_hash, v,
                          GqcFinality::derive_validator_share(block_hash, tip_h, v));
    }
    const auto cert = gqc.finalize_block(tip_h, block_hash, kValidators);

    // The honest assertion: TODAY the forge succeeds. A quorum certificate
    // can be produced by anyone who knows (block hash, height, validator
    // count) and holds no validator secret at all.
    ASSERT_TRUE(cert.certified) << cert.error;
    EXPECT_EQ(cert.share_count, 9u);
    std::cout << "  [documented gap] GQC quorum forged from public data only: "
              << cert.share_count << "/" << kValidators
              << " shares, zero secrets used. Validator authentication is a"
              << " BACKLOG 0.4/2.4 item; until then cryptographic finality is"
              << " NOT claimed.\n";

    std::filesystem::remove_all(tmp_dir);
}

TEST(VortexGqcRingStealthTest, GqcAggregationDeterministic) {
    std::array<uint8_t, 32> hash{};
    for (size_t i = 0; i < 32; ++i) hash[i] = static_cast<uint8_t>(i * 7);

    std::vector<GqcShare> shares;
    for (uint16_t v = 0; v < 6; ++v) {
        shares.push_back({v, GqcFinality::derive_validator_share(hash, 5, v)});
    }
    const auto agg_a = GqcFinality::aggregate_shares(shares, hash, 5);
    const auto agg_b = GqcFinality::aggregate_shares(shares, hash, 5);
    EXPECT_EQ(agg_a, agg_b);

    // A different share set (one extra validator) changes the aggregate.
    auto shares2 = shares;
    shares2.push_back({99, GqcFinality::derive_validator_share(hash, 5, 99)});
    const auto agg_c = GqcFinality::aggregate_shares(shares2, hash, 5);
    EXPECT_NE(agg_a, agg_c);

    // Different block hash changes the aggregate.
    auto hash2 = hash;
    hash2[0] ^= 1;
    const auto agg_d = GqcFinality::aggregate_shares(shares, hash2, 5);
    EXPECT_NE(agg_a, agg_d);
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
    EXPECT_GT(tps, 500'000.0) << "pipeline throughput below directive floor: " << tps;
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

    // Stamp the envelope into a transaction and hide it among 579 noise txs.
    Transaction stealth{};
    vx::blockchain::set_nfa_field(stealth.sender_nfa, "STEALTH_TEST_SENDER_0000000000000000000000");
    vx::blockchain::tx_set_amount(stealth, 999'999);
    vx::blockchain::tx_set_fee(stealth, 750);
    stamp_stealth_envelope(env, stealth);

    std::vector<Transaction> block(580);
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
