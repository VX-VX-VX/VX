#include <gtest/gtest.h>
#include "vx/state/mempool.hpp"
#include "vx/core/u128.hpp"

TEST(VortexMempoolTest, StaticAssertGeometry) {
    static_assert(sizeof(vx::blockchain::RawBlock) == 65536, "RawBlock must be 64KB");
    static_assert(sizeof(vx::blockchain::BlockHeader) == 472, "BlockHeader must be 472 bytes");
    static_assert(sizeof(vx::blockchain::Transaction) == 112, "Transaction must be 112 bytes");
    static_assert(sizeof(vx::blockchain::VortexFrameTail) == 104, "VortexFrameTail must be 104 bytes");
}

TEST(VortexMempoolTest, MempoolConstruction) {
    vx::state::Mempool mempool;
    EXPECT_EQ(mempool.stats().count, 0);
    EXPECT_EQ(mempool.stats().byte_occupancy, 0);
}