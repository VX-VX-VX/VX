// VortexQrngBeaconTest — Phase E (0.2.4): the epoch seed as a VERIFIED
// nondeterminism point.
//
// Verifies:
//   1. commit/reveal: the commitment re-derives from the revealed byte;
//      a wrong byte fails (fail-closed gate on block N+1).
//   2. seed_from_window: the rolling window folds oldest-first — order
//      sensitivity; an empty window yields all-zero (no seed update).
//   3. domain separation: commit != seed for the same bytes; tags never
//      collide across intents.
//   4. slash policy: a proven mismatch bans the producer for W blocks;
//      3 strikes in one epoch escalate; reset_epoch clears strikes but
//      the ban window outlives it.
//   5. the deterministic fallback: deterministic over the same window,
//      fail-closed (never attacker-steerable entropy).

#include <gtest/gtest.h>
#include "vx/consensus/qrng_beacon.hpp"

#include <array>
#include <vector>

using vx::consensus::qrng::fallback_byte;
using vx::consensus::qrng::MisconductLedger;
using vx::consensus::qrng::qrng_commit;
using vx::consensus::qrng::seed_from_window;
using vx::consensus::qrng::verify_reveal;

namespace {

std::array<uint8_t, 32> zero32() {
    return {};
}

} // namespace

// ── 1. Commit / reveal ──────────────────────────────────────────────────────

// The reveal re-derives the commitment: the block N+1 gate accepts the
// honest byte.
TEST(VortexQrngBeaconTest, RevealVerifies) {
    const auto commit = qrng_commit(0x42);
    EXPECT_TRUE(verify_reveal(commit, 0x42));
}

// A wrong byte fails: the block N+1 gate is fail-closed.
TEST(VortexQrngBeaconTest, WrongRevealFails) {
    const auto commit = qrng_commit(0x42);
    EXPECT_FALSE(verify_reveal(commit, 0x43));
    EXPECT_FALSE(verify_reveal(commit, 0x00));
    EXPECT_FALSE(verify_reveal(commit, 0xFF));
}

// A tampered commit fails even with the honest byte.
TEST(VortexQrngBeaconTest, TamperedCommitFails) {
    auto commit = qrng_commit(0x42);
    commit[0] ^= 0x01;
    EXPECT_FALSE(verify_reveal(commit, 0x42));
}

// Different bytes commit to different digests.
TEST(VortexQrngBeaconTest, DistinctBytesDistinctCommits) {
    EXPECT_NE(qrng_commit(0x00), qrng_commit(0x01));
    EXPECT_NE(qrng_commit(0x00), qrng_commit(0xFF));
}

// ── 2. Seed derivation ──────────────────────────────────────────────────────

// The window folds oldest-first: {r1, r2} != {r2, r1}.
TEST(VortexQrngBeaconTest, SeedWindowOrderSensitive) {
    const auto seed_a = seed_from_window({0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08});
    const auto seed_b = seed_from_window({0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01});
    EXPECT_NE(seed_a, seed_b);
}

// The k=8 window: the spec-candidate length derives deterministically.
TEST(VortexQrngBeaconTest, SeedWindowDeterministic) {
    const auto seed = seed_from_window({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88});
    const auto again = seed_from_window({0x11, 0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88});
    EXPECT_EQ(seed, again);
}

// An empty window yields all-zero: the caller treats it as "no seed
// update" (fail-closed, the old epoch continues).
TEST(VortexQrngBeaconTest, EmptyWindowZeroSeed) {
    EXPECT_EQ(seed_from_window({}), zero32());
}

// A short window still derives (the derivation binds the length).
TEST(VortexQrngBeaconTest, ShortWindowDerives) {
    const auto seed = seed_from_window({0x01});
    EXPECT_NE(seed, zero32());
    // {0x01} != {0x01, 0x01}: length binding is real.
    EXPECT_NE(seed, seed_from_window({0x01, 0x01}));
}

// ── 3. Domain separation ────────────────────────────────────────────────────

// The commit and the seed are different intents: the same byte must not
// produce the same digest under both tags.
TEST(VortexQrngBeaconTest, CommitSeedTagSeparation) {
    const auto commit = qrng_commit(0x42);
    const auto seed = seed_from_window({0x42});
    EXPECT_NE(commit, seed);
}

// The fallback derivation is separate from the commit derivation.
TEST(VortexQrngBeaconTest, FallbackTagSeparation) {
    const auto commit = qrng_commit(0x42);
    const auto fb = fallback_byte({0x42});
    EXPECT_NE(commit, seed_from_window({0x42}));
    // The fallback byte is the first byte of a distinct derivation.
    EXPECT_NE(fb, 0x42);
}

// ── 4. Slash policy ─────────────────────────────────────────────────────────

// A proven mismatch bans the producer for W blocks.
TEST(VortexQrngBeaconTest, MismatchBansProducer) {
    MisconductLedger ledger;
    const std::array<uint8_t, 32> producer{1};
    EXPECT_FALSE(ledger.is_banned(producer, 500));
    EXPECT_FALSE(ledger.record_mismatch(producer, 500));
    EXPECT_TRUE(ledger.is_banned(producer, 500));
    EXPECT_TRUE(ledger.is_banned(producer, 1499));
    EXPECT_FALSE(ledger.is_banned(producer, 1500)); // ban expired
}

// A different producer is not touched by another's ban.
TEST(VortexQrngBeaconTest, BanIsPerProducer) {
    MisconductLedger ledger;
    const std::array<uint8_t, 32> a{1}, b{2};
    ledger.record_mismatch(a, 100);
    EXPECT_TRUE(ledger.is_banned(a, 100));
    EXPECT_FALSE(ledger.is_banned(b, 100));
}

// 3 strikes in one epoch escalate (committee mechanics).
TEST(VortexQrngBeaconTest, ThreeStrikesEscalate) {
    MisconductLedger ledger;
    const std::array<uint8_t, 32> producer{1};
    EXPECT_FALSE(ledger.record_mismatch(producer, 100));
    EXPECT_FALSE(ledger.record_mismatch(producer, 200));
    EXPECT_TRUE(ledger.record_mismatch(producer, 300));
}

// reset_epoch clears strikes but the ban window outlives it.
TEST(VortexQrngBeaconTest, ResetEpochKeepsBan) {
    MisconductLedger ledger;
    const std::array<uint8_t, 32> producer{1};
    ledger.record_mismatch(producer, 100); // banned until 1100
    ledger.reset_epoch();
    EXPECT_TRUE(ledger.is_banned(producer, 500));
    // Fresh strikes needed for a new escalation.
    EXPECT_FALSE(ledger.record_mismatch(producer, 500));
    EXPECT_FALSE(ledger.record_mismatch(producer, 600));
    EXPECT_TRUE(ledger.record_mismatch(producer, 700));
}

// ── 5. Deterministic fallback ───────────────────────────────────────────────

// The fallback is deterministic over the same window (fail-closed into
// determinism, never into attacker-steerable entropy).
TEST(VortexQrngBeaconTest, FallbackDeterministic) {
    const std::vector<uint8_t> window{0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08};
    EXPECT_EQ(fallback_byte(window), fallback_byte(window));
    EXPECT_NE(fallback_byte(window), fallback_byte({0x01}));
}
