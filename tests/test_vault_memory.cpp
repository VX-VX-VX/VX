#include <gtest/gtest.h>
#include "vx/core/memory_vault.hpp"
#include "vx/core/rt_scheduler.hpp"
#include <cstring>

TEST(VortexVaultMemoryTest, PageStateTransitionsAndBurning) {
    vx::core::MemoryCore core(vx::core::MemoryCore::DEFAULT_ARENA_SIZE);
    core.initialize(0x123456789ABCDEF0ULL);

    const char* secret = "TOP_SECRET_VAULT_DATA_2026";
    size_t secret_len = std::strlen(secret);

    // Commit secure data -> LOCKED
    auto hash = core.commit_secure_data(reinterpret_cast<const uint8_t*>(secret), secret_len);
    auto stats = core.get_stats();
    EXPECT_EQ(stats.locked_pages, 1);
    EXPECT_EQ(stats.burned_pages, 0);

    // Consume data -> BURNED
    uint8_t out_buf[256] = {0};
    bool ok = core.consume_data(hash, out_buf);
    EXPECT_TRUE(ok);
    EXPECT_STREQ(reinterpret_cast<const char*>(out_buf), secret);

    stats = core.get_stats();
    EXPECT_EQ(stats.locked_pages, 0);
    EXPECT_EQ(stats.burned_pages, 1);
}

TEST(VortexVaultMemoryTest, HardwareUuidBindingSeed) {
    uint64_t seed = vx::core::MemoryCore::get_hardware_uuid_seed();
    EXPECT_NE(seed, 0ULL);
}

TEST(VortexVaultMemoryTest, EmergencyBurnAll) {
    vx::core::MemoryCore core(vx::core::MemoryCore::DEFAULT_ARENA_SIZE);
    core.initialize(0x9999999999999999ULL);

    const char* data1 = "DATA_BLOCK_1";
    const char* data2 = "DATA_BLOCK_2";
    core.commit_secure_data(reinterpret_cast<const uint8_t*>(data1), std::strlen(data1));
    core.commit_secure_data(reinterpret_cast<const uint8_t*>(data2), std::strlen(data2));

    EXPECT_EQ(core.get_stats().locked_pages, 2);

    core.emergency_burn_all();
    EXPECT_EQ(core.get_stats().locked_pages, 0);
    EXPECT_EQ(core.get_stats().burned_pages, 2);
}

TEST(VortexVaultMemoryTest, RegisterScrubbing) {
    char sensitive[64] = "SENSITIVE_KEY_MATERIAL_123456789";
    vx::core::LockStepScheduler::scrub_execution_state(sensitive, sizeof(sensitive));

    for (size_t i = 0; i < sizeof(sensitive); ++i) {
        EXPECT_EQ(sensitive[i], 0);
    }
}
