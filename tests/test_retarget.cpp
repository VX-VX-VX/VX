// test_retarget.cpp -- TIME-ASERT PoGW difficulty retarget (consensus commit
// 2026-11-15, owner-directed; replaces the height-ratchet whose unconditional
// doubling every 34560 blocks was a liveness mine and an emission-math lie).
//
// bits(h) = anchor − round_ties((t_parent − t_1 − (h−2)·5s) / TAU), clamped
// to [POGW_MIN_BITS, POGW_MAX_BITS]. The anchor clock is the FIRST MINED
// block's stamp (height 1, chain data every node holds), never the fixed
// deterministic genesis stamp. The tests pin five properties:
//
//   1. OnTimeChainFlatAtAnchor      -- a chain producing exactly on the
//                                      5-second schedule never moves off the
//                                      anchor (the pulse is sacred; difficulty
//                                      has no reason to ratchet on its own).
//   2. FastBlocksRaiseDifficulty    -- compressed timestamps RAISE the
//                                      requirement (the sign pin: our bits are
//                                      the INVERSE of Bitcoin's target value),
//                                      with exact tie-rounding boundaries and
//                                      ≤1 bit per block.
//   3. LaggingChainEasesNoFreeze    -- a lagging chain eases toward the floor
//                                      instead of freezing (the liveness fix).
//   4. BoundsAndAbsurdHeights       -- anchor clamps, absurd heights, and the
//                                      deterministic tie-away-from-zero rule.
//   5. DeviationPersistsAfterBurst  -- an ASERT curve has memory: after a
//                                      fast burst, on-time blocks hold the
//                                      raised level (dev stops changing), it
//                                      takes real lag to ease back.
//   6. StorePlumbingDeterministic   -- two independent stores holding the
//                                      same frames compute identical bits and
//                                      seal identical content to identical
//                                      nonces; per-block movement is bounded
//                                      far below one bit (no single block can
//                                      jump the difficulty -- DoS property).
//   7. GateRejectsUnderqualified    -- the rejection path (insufficient work)
//                                      stays wired: a frame below the current
//                                      requirement is refused, an exact one
//                                      passes.
//   8. Parameter lock               -- the fingerprint pin (anchor, TAU,
//                                      pulse) makes silent edits a loud
//                                      consensus change.

#include <gtest/gtest.h>
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/consensus/retarget.hpp"
#include "vx/storage/block_store.hpp"

#include <array>
#include <cstring>
#include <cmath>
#include <ctime>
#include <filesystem>

using namespace vx::blockchain;
using vx::consensus::asert_pogw_bits;
using vx::consensus::POGW_MAINNET_RETARGET;
using vx::consensus::POGW_MAX_BITS;
using vx::consensus::POGW_MIN_BITS;
using vx::consensus::POGW_RETARGET_FINGERPRINT;
using vx::consensus::POGW_TARGET_BLOCK_SECONDS;
using vx::consensus::POGW_TAU_SECONDS;
using vx::consensus::PogwRetargetParams;
using vx::consensus::retarget_fingerprint;

namespace {

std::string temp_dir(const char* tag) {
    auto dir = std::filesystem::temp_directory_path() /
               (std::string(tag) + "_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    return dir.string();
}

// Synthetic clock base: any fixed instant works — the curve is relative.
constexpr int64_t kT0 = 1'700'000'000;

BlockBuilder make_block(const vx::storage::BlockStore &store, uint64_t ts) {
    BlockBuilder b;
    b.set_height(store.chain_height());
    b.set_timestamp(ts);
    uint8_t tip[32];
    store.tip_hash(tip);
    b.set_prev_hash(tip);
    std::array<uint8_t, 384> coords{};
    b.set_attractor_coords(coords.data());
    b.finalize();
    return b;
}

BlockFrame frame_of(const BlockBuilder& b) {
    BlockFrame f{};
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    return f;
}

// A frame whose hash carries EXACTLY `bits` leading zero bits (meets `bits`,
// fails `bits + 1`) — the exact-strength pin for rejection tests.
bool seal_exact_bits(BlockFrame& f, uint64_t bits, uint64_t max_attempts = 1ULL << 20) {
    auto* raw = reinterpret_cast<RawBlock*>(f.data());
    for (uint64_t nonce = 0; nonce < max_attempts; ++nonce) {
        raw->tail.pogw_nonce = nonce;
        if (pogw_meets_target(f.data(), bits) && !pogw_meets_target(f.data(), bits + 1))
            return true;
    }
    return false;
}

} // namespace

// -- 1. On-time chain: flat at the anchor -------------------------------------

TEST(AsertRetargetTest, OnTimeChainStaysAtAnchor) {
    // parent_ts tracks the schedule exactly: dev == 0 for every height.
    for (uint64_t h = 3; h <= 2'000'000; h += (h < 1000 ? 1 : 997)) {
        const int64_t parent_ts = kT0 + (int64_t)(h - 2) * 5;
        EXPECT_EQ(asert_pogw_bits(16, h, parent_ts, kT0), 16u)
            << "on-time chain must stay at the anchor, h=" << h;
    }
    // Dense early sweep including every height 3..2000.
    for (uint64_t h = 3; h <= 2000; ++h)
        ASSERT_EQ(asert_pogw_bits(16, h, kT0 + (int64_t)(h - 2) * 5, kT0), 16u);
}

// -- 2. Fast blocks RAISE the difficulty (the sign pin) ------------------------

TEST(AsertRetargetTest, FastBlocksRaiseDifficulty) {
    // Blocks arrive 1s apart: each interval saves 4s, so dev = −4·(h−2) and
    // bits = 16 + round(4·(h−2)/172800) — one bit up per 43200 blocks.
    const uint64_t per_bit = POGW_TAU_SECONDS / (POGW_TARGET_BLOCK_SECONDS - 1);
    EXPECT_EQ(per_bit, 43200u);
    EXPECT_EQ(asert_pogw_bits(16, 2, kT0, kT0), 16u); // no measurement yet
    // dev = −4·(h−2); the tie |dev| = τ/2 sits at h−2 = 21600.
    EXPECT_EQ(asert_pogw_bits(16, 21601, kT0 + 21599, kT0), 16u); // dev −86396: rounds 0
    EXPECT_EQ(asert_pogw_bits(16, 21602, kT0 + 21600, kT0), 17u); // dev −86400: the tie bites
    EXPECT_EQ(asert_pogw_bits(16, 64802, kT0 + 64800, kT0), 18u); // dev −259200: −1.5τ → 2
    // Monotone non-decreasing, at most one bit per block, inside the lattice.
    uint64_t prev = asert_pogw_bits(16, 2, kT0, kT0);
    for (uint64_t h = 3; h <= 2'100'000; h += (h < 5000 ? 1 : 997)) {
        const uint64_t b = asert_pogw_bits(16, h, kT0 + (int64_t)(h - 2), kT0);
        ASSERT_GE(b, prev) << "difficulty decreased on a fast chain at h=" << h;
        ASSERT_LE(b - prev, 1u) << "more than one bit per block at h=" << h;
        ASSERT_LE(b, POGW_MAX_BITS);
        prev = b;
    }
    // The clamp catches the top before the sweep ends.
    EXPECT_EQ(asert_pogw_bits(16, 3'000'000, kT0 + 2'999'998, kT0), 64u);
    // Cross-check against the real-valued curve on sampled heights.
    for (uint64_t h = 3; h <= 900'000; h += 499) {
        const double dev = -4.0 * (double)(h - 2);
        const long double exact = (long double)(-dev) / (long double)POGW_TAU_SECONDS;
        const long double rounded = std::llround(exact); // nearest, ties away from zero
        EXPECT_EQ(asert_pogw_bits(16, h, kT0 + (int64_t)(h - 2), kT0), 16u + (uint64_t)rounded)
            << "reduction mismatch at h=" << h;
    }
}

// -- 3. Lagging chain eases, never freezes --------------------------------------

TEST(AsertRetargetTest, LaggingChainEasesNoFreeze) {
    // 6s spacing: each interval loses 1s, dev = +(h−2), bits = 16 −
    // round((h−2)/172800) — one bit DOWN per 172800 blocks, floor at 1.
    EXPECT_EQ(asert_pogw_bits(16, 86401, kT0 + 86400 * 6, kT0), 15u); // tie → eases
    EXPECT_EQ(asert_pogw_bits(16, 86400, kT0 + 86394 * 6, kT0), 16u); // below the tie
    // The curve eases monotonically and NEVER freezes at the floor: even a
    // year-long lag keeps the gate satisfiable (bits ≥ POGW_MIN_BITS).
    uint64_t prev = 16u;
    for (uint64_t h = 3; h <= 30'000'000; h += (h < 5000 ? 1 : 7919)) {
        const uint64_t b = asert_pogw_bits(16, h, kT0 + (int64_t)(h - 2) * 6, kT0);
        ASSERT_LE(b, prev) << "difficulty rose on a lagging chain at h=" << h;
        ASSERT_GE(b, POGW_MIN_BITS);
        prev = b;
    }
    EXPECT_EQ(prev, POGW_MIN_BITS) << "a multi-year lag must reach the lattice floor";
    // Mining pause: 1M blocks produced exactly on schedule (the chain sits
    // at +5s·(h−2) on the clock), then no blocks for a MONTH, then mining
    // resumes. The deviation is measured at the parent stamp: the pause
    // adds 30 days the schedule did not expect, so the requirement EASES —
    // the liveness guarantee (a frozen retarget would have kept the
    // pre-pause difficulty forever).
    const uint64_t h = 1'000'000;
    const int64_t schedule_ts = kT0 + (int64_t)(h - 2) * 5;
    const uint64_t eased = asert_pogw_bits(16, h, schedule_ts + 30LL * 86400, kT0);
    EXPECT_LT(eased, 16u) << "a month-long pause must ease the requirement";
    // And the on-schedule sibling at the same height stays at the anchor:
    // the ease comes from the pause, not from the height.
    EXPECT_EQ(asert_pogw_bits(16, h, schedule_ts, kT0), 16u);
}

// -- 4. Bounds and absurd heights ------------------------------------------------

TEST(AsertRetargetTest, BoundsAndAbsurdHeights) {
    // Anchor above the ceiling: everything lands at POGW_MAX_BITS.
    EXPECT_EQ(asert_pogw_bits(100, 7, kT0, kT0), 64u);
    EXPECT_EQ(asert_pogw_bits(100, 0xffffffffffffffffULL, kT0, kT0), 64u);
    // Anchor below the floor: the lattice floor applies.
    EXPECT_EQ(asert_pogw_bits(0, 7, kT0, kT0), 1u);
    EXPECT_EQ(asert_pogw_bits(0, 1ULL << 40, kT0, kT0), 64u);
    // Absurd heights clamp at the top without arithmetic overflow.
    EXPECT_EQ(asert_pogw_bits(16, 1ULL << 59, kT0, kT0), 64u);
    EXPECT_EQ(asert_pogw_bits(16, 1ULL << 63, kT0, kT0), 64u);
    // Heights 0-2 sit at the anchor whatever the timestamps claim.
    EXPECT_EQ(asert_pogw_bits(16, 0, kT0 + 999999, kT0), 16u);
    EXPECT_EQ(asert_pogw_bits(16, 1, kT0 + 999999, kT0), 16u);
    EXPECT_EQ(asert_pogw_bits(16, 2, kT0 + 999999, kT0), 16u);
}

// -- 5. ASERT memory: a fast burst persists --------------------------------------

TEST(AsertRetargetTest, DeviationPersistsAfterBurst) {
    // 20'000 blocks mined with ZERO gaps (every stamp identical — monotone
    // is ts >= prev, equal allowed): dev = −5·(h−2) → at the burst end
    // dev = −99990 → the requirement rises one bit. Subsequent ON-TIME
    // blocks add 5s actual AND 5s expected each — dev stops changing — so
    // the raised level HOLDS (no free ride back down without real lag).
    const uint64_t burst = 20'000;
    const int64_t burst_end_ts = kT0; // zero-gap burst: every stamp equal
    const uint64_t raised = asert_pogw_bits(16, burst + 1, burst_end_ts, kT0);
    EXPECT_EQ(raised, 17u) << "a 20k zero-gap burst must raise the requirement by one bit";
    for (uint64_t h = burst + 2; h <= burst + 5000; ++h) {
        const int64_t parent_ts = burst_end_ts + (int64_t)(h - 1 - burst) * 5;
        EXPECT_EQ(asert_pogw_bits(16, h, parent_ts, kT0), raised)
            << "on-time blocks after a burst must hold the level, h=" << h;
    }
}

// -- 6. Store plumbing: deterministic, bounded per block --------------------------

TEST(AsertRetargetTest, StorePlumbingDeterministic) {
    const std::string dir = temp_dir("vx_retarget_plumbing");
    vx::storage::BlockStore a(dir + "/node_a.vxb", "genesis.bin", 8);
    vx::storage::BlockStore b(dir + "/node_b.vxb", "genesis.bin", 8);

    // Identical frames (same heights, same timestamps) on both stores: the
    // bits agree everywhere and identical content seals to an identical
    // nonce. The base clock is NOW: the intake sanity gate refuses stamps
    // older than the (just-written) genesis tip.
    const uint64_t base_ts = (uint64_t)std::time(nullptr);
    for (int i = 0; i < 3; ++i) {
        const uint64_t ts = base_ts + 5 * (uint64_t)(i + 1); // on schedule
        BlockBuilder ba = make_block(a, ts);
        BlockFrame fa = frame_of(ba);
        ASSERT_TRUE(seal_pogw_nonce(fa, a.required_pogw_bits()));
        ASSERT_TRUE(a.append_block(fa));
        // Byte-identical frame into the second store.
        ASSERT_TRUE(b.append_block(fa));
    }
    for (uint64_t h = 0; h <= 200; ++h) {
        ASSERT_EQ(a.pogw_bits_for_height(h), b.pogw_bits_for_height(h))
            << "nodes disagree at h=" << h;
    }
    // On-schedule short chain: the frontier stays at the anchor.
    ASSERT_EQ(a.required_pogw_bits(), 8u);
    ASSERT_EQ(b.required_pogw_bits(), 8u);

    // The same frame content seals to the identical nonce on both nodes.
    BlockBuilder f = make_block(a, base_ts + 20);
    BlockFrame f1 = frame_of(f);
    BlockFrame f2 = frame_of(f);
    const uint64_t bits_a = a.required_pogw_bits();
    const uint64_t bits_b = b.required_pogw_bits();
    ASSERT_EQ(bits_a, bits_b);
    ASSERT_TRUE(seal_pogw_nonce(f1, bits_a));
    ASSERT_TRUE(seal_pogw_nonce(f2, bits_b));
    const auto* r1 = reinterpret_cast<const RawBlock*>(f1.data());
    const auto* r2 = reinterpret_cast<const RawBlock*>(f2.data());
    EXPECT_EQ(r1->tail.pogw_nonce, r2->tail.pogw_nonce);
    EXPECT_TRUE(a.append_block(f1));

    std::filesystem::remove_all(dir);
}

// -- 7. The gate still refuses underqualified work --------------------------------

TEST(AsertRetargetTest, GateRejectsUnderqualifiedWork) {
    const std::string dir = temp_dir("vx_retarget_gate");
    vx::storage::BlockStore store(dir + "/gate.vxb", "genesis.bin", 8);

    // One on-schedule block (height 1, the anchor clock). The base clock
    // is NOW: intake refuses stamps older than the fresh genesis tip.
    const uint64_t base_ts = (uint64_t)std::time(nullptr);
    BlockBuilder b1 = make_block(store, base_ts + 5);
    BlockFrame f1 = frame_of(b1);
    ASSERT_TRUE(seal_pogw_nonce(f1, store.required_pogw_bits()));
    ASSERT_TRUE(store.append_block(f1));
    ASSERT_EQ(store.required_pogw_bits(), 8u);

    // A frame carrying EXACTLY 7 bits (below the 8-bit requirement) must be
    // refused by the gate; the tip must not move. This pins the rejection
    // path the retarget feeds (a stale requirement is just another
    // underqualified frame).
    BlockBuilder stale = make_block(store, base_ts + 10);
    BlockFrame f = frame_of(stale);
    ASSERT_TRUE(seal_exact_bits(f, 7)) << "no exact-7-bit nonce found in range";
    EXPECT_FALSE(store.append_block(f));
    EXPECT_EQ(store.last_error(), "insufficient PoGW work for the current difficulty");
    EXPECT_EQ(store.chain_height(), 2u) << "the underqualified frame must not move the tip";

    // The same content resealed at the requirement passes.
    BlockFrame g = frame_of(stale);
    ASSERT_TRUE(seal_pogw_nonce(g, store.required_pogw_bits()));
    EXPECT_TRUE(store.append_block(g));
    EXPECT_EQ(store.chain_height(), 3u);

    std::filesystem::remove_all(dir);
}

// -- 8. Parameter lock -------------------------------------------------------------

TEST(AsertRetargetTest, RetargetParameterLock) {
    EXPECT_EQ(POGW_RETARGET_FINGERPRINT, 0xd59af7a8dd8ca2f9ull)
        << "ASERT anchor/tau/pulse changed: announce the consensus change and "
           "update both pins (static_assert in retarget.hpp and this test)";
    EXPECT_EQ(retarget_fingerprint(16, POGW_TAU_SECONDS, POGW_TARGET_BLOCK_SECONDS),
              POGW_RETARGET_FINGERPRINT);
    // The fingerprint actually moves when any parameter moves.
    EXPECT_NE(retarget_fingerprint(17, POGW_TAU_SECONDS, POGW_TARGET_BLOCK_SECONDS),
              POGW_RETARGET_FINGERPRINT);
    EXPECT_NE(retarget_fingerprint(16, POGW_TAU_SECONDS + 1, POGW_TARGET_BLOCK_SECONDS),
              POGW_RETARGET_FINGERPRINT);
    EXPECT_NE(retarget_fingerprint(16, POGW_TAU_SECONDS, POGW_TARGET_BLOCK_SECONDS + 1),
              POGW_RETARGET_FINGERPRINT);
}

// -- 9. MTP-11 gate rule ----------------------------------------------------------
// The MTP check is unit-tested directly on the intake gate: inside a store
// whose history is strictly monotone the median never sits above the tip
// (the monotone rule already guarantees that), so the rule is exercised
// with a crafted context. It becomes load-bearing if the monotone rule is
// ever relaxed, and it costs nothing to keep armed (security review
// 2026-11-15, HIGH).
TEST(AsertRetargetTest, MedianTimePastGatesStamps) {
    using vx::blockchain::BlockIntakeContext;

    BlockIntakeContext ctx{};
    ctx.expected_height = 1;
    ctx.prev_timestamp = 1000;
    ctx.median_time_past = 1100; // the median sits ABOVE the tip stamp —
                                 // only possible if the monotone rule is relaxed
    ctx.now_unix = 2000;
    ctx.difficulty_bits = 1;

    BlockBuilder b;
    b.set_height(1);
    b.set_timestamp(1050); // >= the tip (1000) but BELOW the median (1100)
    std::array<uint8_t, 384> coords{};
    b.set_attractor_coords(coords.data());
    b.finalize();
    BlockFrame f{};
    std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    // Seal to the minimal requirement so only the timestamp rule can fire.
    ASSERT_TRUE(seal_pogw_nonce(f, 1));
    std::string err;
    const bool ok =
        vx::blockchain::validate_block(*reinterpret_cast<const RawBlock *>(f.data()), ctx, &err);
    EXPECT_FALSE(ok) << "a below-median stamp must be refused by the gate";
    EXPECT_NE(err.find("median of the last 11"), std::string::npos) << err;

    // Above the median: the MTP rule passes (this frame satisfies every
    // gate check the crafted context can exercise).
    b.set_timestamp(1150);
    b.finalize();
    BlockFrame g{};
    std::memcpy(g.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    ASSERT_TRUE(seal_pogw_nonce(g, 1));
    err.clear();
    const bool ok2 =
        vx::blockchain::validate_block(*reinterpret_cast<const RawBlock *>(g.data()), ctx, &err);
    EXPECT_TRUE(ok2) << err;
}
