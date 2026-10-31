#include <gtest/gtest.h>
#include "vx/consensus/pogw_miner.hpp"
#include "vx/storage/block_store.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/state/undo_engine.hpp"
#include "vx/net/swarm_node.hpp"

TEST(VortexChainReorgTest, EmergencyStop) {
    auto swarm_node = std::make_unique<vx::net::SwarmNode>();

    // Verify emergency stop can be called (doesn't crash)
    swarm_node->emergency_stop();

    // In a real test we'd verify threads are stopped, sockets closed, etc.
    // For now, just verify it doesn't crash
    SUCCEED();
}