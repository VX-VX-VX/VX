// test_retarget.cpp -- ASERT PoGW difficulty retarget (BACKLOG 0.9 remainder).
//
// The retarget replaces the constant live-intake difficulty with a
// height-derived ASERT curve: bits(h) = anchor + round((h-1)/half_life),
// clamped to [POGW_MIN_BITS, POGW_MAX_BITS]. Difficulty is never stored in
// any frame -- every node recomputes it from the shared genesis anchor -- so
// the tests below pin five properties instead of stored bytes:
//
//   1. AsertMonotonicGrowth        -- bits never decrease, never jump more
//                                     than one bit per block, and pin the
//                                     exact half-life tie-rounding points.
//   2. AsertBoundsClamped          -- extreme anchors, zero half-life and
//                                     extreme heights all land inside the
//                                     protocol clamp (no wrap, no division
//                                     by zero).
//   3. AsertDeterministicAcrossNodes -- two independent stores with
//                                     divergent chains agree on the bits for
//                                     every height, and the same frame
//                                     content seals to the identical nonce
//                                     against both (difficulty is a pure
//                                     function of height, never of chain
//                                     state).
//   4. StaleDifficultyRejected     -- a frame sealed at the anchor strength
//                                     is refused once the retarget raises
//                                     the requirement past it.
//   5. AsertAnchorIsGenesis        -- heights 0, 1 and 2 sit exactly at the
//                                     anchor: the genesis frame is the
//                                     anchor and is exempt from the gate.

#include <gtest/gtest.h>
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/consensus/retarget.hpp"
#include "vx/storage/block_store.hpp"

#include <array>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <cmath>

using namespace vx::blockchain;
using vx::consensus::asert_pogw_bits;
using vx::consensus::POGW_MAINNET_RETARGET;
using vx::consensus::PogwRetargetParams;
using vx::consensus::POGW_MAX_BITS;
using vx::consensus::POGW_RETARGET_FINGERPRINT;
using vx::consensus::retarget_fingerprint;

namespace {

std::string temp_dir(const char* tag) {
    auto dir = std::filesystem::temp_directory_path() /
               (std::string(tag) + "_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    return dir.string();
}

// Minimal chain-block helper: an otherwise empty frame bound to the store's
// tip (no transactions -- the gate judges structure, binding and work).
BlockBuilder make_block(const vx::storage::BlockStore& store) {
    BlockBuilder b;
    b.set_height(store.chain_height());
    b.set_timestamp(static_cast<uint64_t>(std::time(nullptr)));
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

// Seal helper used by the stale-difficulty pin: finds a nonce whose frame
// hash carries EXACTLY `bits` leading zero bits (it meets `bits` and would
// NOT meet `bits + 1`). A plain seal at `bits` could accidentally satisfy a
// higher requirement (prob ~1/2), which would make the stale rejection
// nondeterministic; pinning the exact strength makes the test exact.
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

// -- 1. Monotonic growth ------------------------------------------------------

TEST(AsertRetargetTest, AsertMonotonicGrowth) {
    const PogwRetargetParams& p = POGW_MAINNET_RETARGET; // anchor 16, half-life 34560
    const uint64_t hl = p.half_life_blocks;

    // Dense sweep: non-decreasing, at most one bit per block, always >= anchor.
    uint64_t prev = asert_pogw_bits(p, 1);
    ASSERT_EQ(prev, 16u);
    for (uint64_t h = 2; h <= 1000000; ++h) {
        const uint64_t b = asert_pogw_bits(p, h);
        ASSERT_GE(b, prev) << "difficulty decreased at height " << h;
        ASSERT_LE(b - prev, 1u) << "difficulty jumped more than one bit at height " << h;
        ASSERT_LE(b, POGW_MAX_BITS);
        prev = b;
    }

    // Exact pins of the tie-rounding points: the exponent shift is h-1, so
    // with an even half-life the tie (shift == half_life / 2) sits at height
    // half_life / 2 + 1 and rounds UP.
    EXPECT_EQ(asert_pogw_bits(p, 2), 16u);           // shift 1: far below the tie
    EXPECT_EQ(asert_pogw_bits(p, hl / 2), 16u);      // shift hl/2-1: still rounds down
    EXPECT_EQ(asert_pogw_bits(p, hl / 2 + 1), 17u);  // shift hl/2: the tie rounds up
    EXPECT_EQ(asert_pogw_bits(p, hl + 1), 17u);      // shift hl: exactly one doubling
    EXPECT_EQ(asert_pogw_bits(p, 2 * hl + 1), 18u);  // shift 2*hl: two doublings
    EXPECT_EQ(asert_pogw_bits(p, 3 * hl + 1), 19u);  // shift 3*hl: three doublings

    // Independent cross-check of the reduction on sampled heights: the
    // integer bit increment must equal round-to-nearest (ties up) of the
    // real-valued exponent (h-1)/half_life. llround rounds halves away from
    // zero, i.e. up for positive values -- the same tie rule.
    for (uint64_t h = 1; h <= 40 * hl; h += 97) {
        const double real_delta = static_cast<double>(h - 1) / static_cast<double>(hl);
        EXPECT_EQ(asert_pogw_bits(p, h), 16u + static_cast<uint64_t>(std::llround(real_delta)))
            << "reduction mismatch at height " << h;
    }

    // Far heights: the early ceiling keeps everything well-defined to 2^64-1.
    EXPECT_EQ(asert_pogw_bits(p, 1ULL << 32), 64u);
    EXPECT_EQ(asert_pogw_bits(p, 1ULL << 63), 64u);
    EXPECT_EQ(asert_pogw_bits(p, 0xffffffffffffffffULL), 64u);
    // Exactly at the 64th doubling the clamp bites.
    EXPECT_EQ(asert_pogw_bits(p, 64 * hl + 1), 64u);
}

// -- 2. Bounds ----------------------------------------------------------------

TEST(AsertRetargetTest, AsertBoundsClamped) {
    // Anchor above the clamp ceiling: every height sits at POGW_MAX_BITS.
    const PogwRetargetParams hot{100, 34560};
    EXPECT_EQ(asert_pogw_bits(hot, 0), 64u);
    EXPECT_EQ(asert_pogw_bits(hot, 7), 64u);
    EXPECT_EQ(asert_pogw_bits(hot, 0xffffffffffffffffULL), 64u);

    // Anchor below the clamp floor: the lattice floor of 1 bit applies.
    const PogwRetargetParams cold{0, 34560};
    EXPECT_EQ(asert_pogw_bits(cold, 0), 1u);
    EXPECT_EQ(asert_pogw_bits(cold, 2), 1u);
    EXPECT_EQ(asert_pogw_bits(cold, 1ULL << 40), 64u);

    // Zero half-life must degrade to 1 (no division by zero, no UB) and grow
    // one bit per block until the ceiling.
    const PogwRetargetParams fast{1, 0};
    EXPECT_EQ(asert_pogw_bits(fast, 64), 64u);  // anchor 1 + 63 increments
    EXPECT_EQ(asert_pogw_bits(fast, 65), 64u);  // clamped forever after
    for (uint64_t h = 1; h <= 200000; ++h) {
        const uint64_t b = asert_pogw_bits(fast, h);
        ASSERT_GE(b, 1u);
        ASSERT_LE(b, 64u);
    }

    // Height 1 never leaves the anchor, whatever the parameters are.
    EXPECT_EQ(asert_pogw_bits(fast, 1), 1u);
    EXPECT_EQ(asert_pogw_bits(hot, 1), 64u);
}

// -- 3. Determinism across nodes ----------------------------------------------

TEST(AsertRetargetTest, AsertDeterministicAcrossNodes) {
    const std::string dir = temp_dir("vx_retarget_determinism");
    const PogwRetargetParams params{8, 4}; // fast half-life so growth shows up

    vx::storage::BlockStore a(dir + "/node_a.vxb", "genesis.bin", 8, params);
    vx::storage::BlockStore b(dir + "/node_b.vxb", "genesis.bin", 8, params);

    // Divergent chains: same heights, different block content (timestamps
    // differ), so the tips (and full-frame hashes) differ from height 1 on.
    for (int i = 0; i < 2; ++i) {
        BlockBuilder ba = make_block(a);
        BlockFrame fa = frame_of(ba);
        ASSERT_TRUE(seal_pogw_nonce(fa, a.required_pogw_bits()));
        ASSERT_TRUE(a.append_block(fa));

        BlockBuilder bb = make_block(b);
        bb.set_timestamp(static_cast<uint64_t>(std::time(nullptr)) + 7);
        bb.finalize();
        BlockFrame fb = frame_of(bb);
        ASSERT_TRUE(seal_pogw_nonce(fb, b.required_pogw_bits()));
        ASSERT_TRUE(b.append_block(fb));
    }
    uint8_t tip_a[32], tip_b[32];
    a.tip_hash(tip_a);
    b.tip_hash(tip_b);
    ASSERT_NE(std::memcmp(tip_a, tip_b, 32), 0) << "the chains really diverged";

    // Identical bits per height on both nodes, across and beyond the tips.
    for (uint64_t h = 0; h <= 200; ++h) {
        ASSERT_EQ(a.pogw_bits_for_height(h), b.pogw_bits_for_height(h))
            << "nodes disagree on the difficulty at height " << h;
    }
    ASSERT_EQ(a.pogw_bits_for_height(3), 9u); // 8 + one tie-round-up increment
    ASSERT_EQ(a.required_pogw_bits(), b.required_pogw_bits());

    // The same frame content, sealed against each node's own requirement,
    // must find the identical nonce: the difficulty -- and therefore the
    // seal -- depends only on the height, never on chain state.
    BlockBuilder f = make_block(a); // bound to A's tip; content is irrelevant here
    BlockFrame f1 = frame_of(f);
    BlockFrame f2 = frame_of(f);
    const uint64_t bits_a = a.required_pogw_bits();
    const uint64_t bits_b = b.required_pogw_bits();
    ASSERT_EQ(bits_a, bits_b);
    ASSERT_TRUE(seal_pogw_nonce(f1, bits_a));
    ASSERT_TRUE(seal_pogw_nonce(f2, bits_b));
    const auto* r1 = reinterpret_cast<const RawBlock*>(f1.data());
    const auto* r2 = reinterpret_cast<const RawBlock*>(f2.data());
    EXPECT_EQ(r1->tail.pogw_nonce, r2->tail.pogw_nonce)
        << "identical frames and identical bits must seal to the identical nonce";

    // A's gate accepts the frame sealed to its own frontier.
    EXPECT_TRUE(a.append_block(f1));

    std::filesystem::remove_all(dir);
}

// -- 4. Stale difficulty rejected ----------------------------------------------

TEST(AsertRetargetTest, StaleDifficultyRejected) {
    const std::string dir = temp_dir("vx_retarget_stale");
    const PogwRetargetParams params{8, 4}; // one bit up every ~4 blocks
    vx::storage::BlockStore store(dir + "/stale.vxb", "genesis.bin", 8, params);

    // Heights 1 and 2 still sit at the anchor: plain seals are accepted.
    for (int i = 0; i < 2; ++i) {
        ASSERT_EQ(store.required_pogw_bits(), 8u);
        BlockBuilder b = make_block(store);
        BlockFrame f = frame_of(b);
        ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
        ASSERT_TRUE(store.append_block(f));
    }
    // Height 3 is the first increment past the anchor (shift 2 of 4 = the tie).
    ASSERT_EQ(store.pogw_bits_for_height(3), 9u);
    ASSERT_EQ(store.required_pogw_bits(), 9u);

    // A frame carrying EXACTLY the stale anchor strength (8 bits, so it
    // cannot accidentally satisfy 9) must be refused by the gate.
    BlockBuilder stale = make_block(store);
    BlockFrame f = frame_of(stale);
    ASSERT_TRUE(seal_exact_bits(f, 8)) << "no exact-8-bit nonce found in range";
    EXPECT_FALSE(store.append_block(f));
    EXPECT_EQ(store.last_error(), "insufficient PoGW work for the current difficulty");
    EXPECT_EQ(store.chain_height(), 3u) << "the stale frame must not move the tip";

    // The same block content resealed at the retargeted frontier is accepted.
    BlockFrame g = frame_of(stale);
    ASSERT_TRUE(seal_pogw_nonce(g, store.required_pogw_bits()));
    EXPECT_TRUE(store.append_block(g));
    EXPECT_EQ(store.chain_height(), 4u);

    std::filesystem::remove_all(dir);
}

// -- 5. Anchor is genesis -------------------------------------------------------

TEST(AsertRetargetTest, AsertAnchorIsGenesis) {
    // Protocol anchor: the default difficulty at heights 0, 1 and 2.
    EXPECT_EQ(asert_pogw_bits(POGW_MAINNET_RETARGET, 0), 16u);
    EXPECT_EQ(asert_pogw_bits(POGW_MAINNET_RETARGET, 1), 16u);
    EXPECT_EQ(asert_pogw_bits(POGW_MAINNET_RETARGET, 2), 16u);

    const std::string dir = temp_dir("vx_retarget_anchor");
    vx::storage::BlockStore store(dir + "/anchor.vxb", "genesis.bin", 8);

    // Height 0 is the genesis frame: the anchor itself, exempt from the gate
    // (it is seeded directly by the store, never appended).
    ASSERT_EQ(store.chain_height(), 1u);
    const RawBlock* g = store.get_block(0);
    ASSERT_NE(g, nullptr);
    EXPECT_EQ(g->header.block_height, 0u);

    // The frontier for the next height sits exactly at the anchor and stays
    // there across a short chain: every sealing caller (miner, RPC, tests)
    // keeps seeing the anchor strength for heights within the first
    // half-life.
    EXPECT_EQ(store.pogw_bits_for_height(0), 8u);
    EXPECT_EQ(store.pogw_bits_for_height(1), 8u);
    EXPECT_EQ(store.pogw_bits_for_height(2), 8u);
    EXPECT_EQ(store.required_pogw_bits(), 8u);

    BlockBuilder b = make_block(store);
    BlockFrame f = frame_of(b);
    ASSERT_TRUE(seal_pogw_nonce(f, store.required_pogw_bits()));
    ASSERT_TRUE(store.append_block(f));
    EXPECT_EQ(store.chain_height(), 2u);
    EXPECT_EQ(store.required_pogw_bits(), 8u)
        << "height 2 must still sit at the anchor, not one bit above it";

    std::filesystem::remove_all(dir);
}

// -- 6. Parameter lock (F2) -----------------------------------------------------

// The ASERT anchor and half-life are code constants OUTSIDE the genesis
// frame hash: "same genesis" enforces nothing about them, so a silent edit
// forks every peer with no visible disagreement. The fingerprint pin makes
// such an edit a loud, deliberate consensus change.
TEST(AsertRetargetTest, RetargetParameterLock) {
    EXPECT_EQ(POGW_RETARGET_FINGERPRINT, 0xc45e282bf67c611aull)
        << "ASERT anchor/half-life changed: announce the consensus change and "
           "update both pins (static_assert in retarget.hpp and this test)";
    EXPECT_EQ(retarget_fingerprint(16, 34560), POGW_RETARGET_FINGERPRINT);
    // Sanity: the fingerprint actually moves when either parameter moves.
    EXPECT_NE(retarget_fingerprint(17, 34560), POGW_RETARGET_FINGERPRINT);
    EXPECT_NE(retarget_fingerprint(16, 34561), POGW_RETARGET_FINGERPRINT);
}

// -- 7. Math-audit hardening ----------------------------------------------------

// Odd half-lives exercise the tie threshold (hl>>1)+(hl&1) in its odd
// parity branch, which the hl=1 degenerate case never really tests.
TEST(AsertRetargetTest, AsertOddHalfLifeNearestRounding) {
    for (uint64_t hl : {3ull, 5ull, 7ull}) {
        const PogwRetargetParams p{16, hl};
        for (uint64_t h = 2; h <= 20 * hl; ++h) {
            const uint64_t shift = h - 1;
            const long double exact =
                static_cast<long double>(shift) / static_cast<long double>(hl);
            const uint64_t expected =
                16 + static_cast<uint64_t>(std::llround(exact)); // nearest, ties up
            EXPECT_EQ(asert_pogw_bits(p, h), expected)
                << "hl=" << hl << " h=" << h;
        }
    }
    // Exact boundary heights for hl=5: shift 2 rounds DOWN ((2/5)<0.5),
    // shift 3 rounds UP ((3/5)>0.5).
    const PogwRetargetParams p{16, 5};
    EXPECT_EQ(asert_pogw_bits(p, 3), 16u); // shift 2 -> down
    EXPECT_EQ(asert_pogw_bits(p, 4), 17u); // shift 3 -> up
}

// Saturation behavior at both anchors: anchor=64 must never move (the
// lattice top), anchor=1 must clamp at 64 from the exact height onward.
TEST(AsertRetargetTest, AsertClampBoundaryExact) {
    const PogwRetargetParams top{64, 4};
    for (uint64_t h = 0; h < 1000; ++h)
        ASSERT_EQ(asert_pogw_bits(top, h), 64u);

    // anchor=1, hl=4: bits = 1 + round((h-1)/4), clamped at 64.
    const PogwRetargetParams low{1, 4};
    EXPECT_EQ(asert_pogw_bits(low, 249), 63u); // shift 248: 62 exact -> 63
    EXPECT_EQ(asert_pogw_bits(low, 250), 63u); // shift 249: 62.25 -> 62 -> 63
    EXPECT_EQ(asert_pogw_bits(low, 253), 64u); // shift 252: 63 exact -> 64 (== max)
    EXPECT_EQ(asert_pogw_bits(low, 254), 64u); // shift 253: 63.25 -> 63 -> 64
    EXPECT_EQ(asert_pogw_bits(low, 255), 64u); // shift 254: 63.5 ties UP -> 65 -> clamped
    // And the curve never dips back down.
    for (uint64_t h = 2; h < 100000; ++h) {
        const uint64_t bits = asert_pogw_bits(low, h);
        ASSERT_GE(bits, asert_pogw_bits(low, h - 1));
        ASSERT_LE(bits, 64u);
    }
}
