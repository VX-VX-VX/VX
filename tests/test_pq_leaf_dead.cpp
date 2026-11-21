// VortexPqLeafDeadTreeTest — Phase D (0.2.3): the old tree never signs
// again after a rollover. mark_tree_dead() closes EVERY further
// reservation for that root (tx leaves AND the cert leaf) — durable,
// fail-closed — and never blocks a fresh tree.
//
// Spec: vx-phase-d-pq-threshold-spec-draft §2.2 step 3 ("the old tree
// NEVER signs again after a rollover — a ledger flag, fail-closed").

#include <gtest/gtest.h>
#include "vx/crypto/pq_signature.hpp"

#include <cstring>
#include <filesystem>

using vx::crypto::pq::PqLeafLedger;

namespace {

std::array<uint8_t, 32> test_root(uint8_t salt) {
    std::array<uint8_t, 32> r{};
    r[0] = salt;
    r[31] = salt ^ 0xA5;
    return r;
}

struct TempDir {
    std::filesystem::path dir;
    TempDir()
        : dir(std::filesystem::temp_directory_path() /
              ("vx_leaf_dead_" + std::to_string(::getpid()))) {
        std::filesystem::create_directories(dir);
    }
    ~TempDir() {
        std::filesystem::remove_all(dir);
    }
};

} // namespace

// A dead tree refuses every reservation: tx leaves (0..14) and the
// reserved cert leaf 15 alike.
TEST(VortexPqLeafDeadTreeTest, DeadTreeRefusesAllReservations) {
    const auto dead_root = test_root(1);
    const auto fresh_root = test_root(2);

    PqLeafLedger ledger; // memory-only
    // A live tree reserves normally first.
    EXPECT_GE(ledger.reserve_for_tx(dead_root, 0), 0);
    // Then it dies: every further reservation fails.
    ASSERT_TRUE(ledger.mark_tree_dead(dead_root));
    EXPECT_TRUE(ledger.is_tree_dead(dead_root));
    EXPECT_EQ(ledger.reserve_for_tx(dead_root, 1), -1);
    EXPECT_EQ(ledger.reserve_for_tx(dead_root, 0), -1);
    EXPECT_EQ(ledger.reserve(dead_root, 3), -1);
    EXPECT_EQ(ledger.reserve_cert_leaf(dead_root), -1);
    // The fresh tree is untouched.
    EXPECT_FALSE(ledger.is_tree_dead(fresh_root));
    EXPECT_GE(ledger.reserve_for_tx(fresh_root, 0), 0);
}

// The dead mark is durable: a reopened ledger still refuses the dead tree.
TEST(VortexPqLeafDeadTreeTest, DeadMarkSurvivesReopen) {
    TempDir tmp;
    const auto dead_root = test_root(3);
    const auto fresh_root = test_root(4);
    const auto path = tmp.dir / "leaf_dead.pqll";

    {
        PqLeafLedger ledger(path.string());
        ASSERT_TRUE(ledger.durable_ok());
        EXPECT_GE(ledger.reserve_for_tx(dead_root, 0), 0);
        ASSERT_TRUE(ledger.mark_tree_dead(dead_root));
    }
    {
        PqLeafLedger reopened(path.string());
        ASSERT_TRUE(reopened.durable_ok());
        EXPECT_TRUE(reopened.is_tree_dead(dead_root));
        EXPECT_EQ(reopened.reserve_for_tx(dead_root, 1), -1);
        EXPECT_EQ(reopened.reserve_cert_leaf(dead_root), -1);
        // The fresh tree never marked dead still reserves after reopen.
        EXPECT_FALSE(reopened.is_tree_dead(fresh_root));
        EXPECT_GE(reopened.reserve_for_tx(fresh_root, 0), 0);
    }
}

// Double-marking is idempotent: the second mark does not corrupt the log.
TEST(VortexPqLeafDeadTreeTest, DoubleMarkIdempotent) {
    TempDir tmp;
    const auto dead_root = test_root(5);
    const auto path = tmp.dir / "leaf_dead2.pqll";

    PqLeafLedger ledger(path.string());
    ASSERT_TRUE(ledger.durable_ok());
    ASSERT_TRUE(ledger.mark_tree_dead(dead_root));
    ASSERT_TRUE(ledger.mark_tree_dead(dead_root));
    EXPECT_TRUE(ledger.is_tree_dead(dead_root));
    EXPECT_EQ(ledger.reserve_for_tx(dead_root, 0), -1);
}
