#include <gtest/gtest.h>
#include "vx/core/memory_vault.hpp"
#include "vx/core/rt_scheduler.hpp"
#include <cstring>

TEST(VortexVaultMemoryTest, PageStateTransitionsAndBurning) {
    if (!vx::core::MemoryCore::mlock_supported()) {
        GTEST_SKIP() << "mlock unavailable in this environment (CI container); "
                        "locked-arena coverage requires RLIMIT_MEMLOCK >= arena size";
    }
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
    if (!vx::core::MemoryCore::mlock_supported()) {
        GTEST_SKIP() << "mlock unavailable in this environment (CI container); "
                        "locked-arena coverage requires RLIMIT_MEMLOCK >= arena size";
    }
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

// v0.0.11 shared-state audit regression: the vault page paths
// (commit/consume/burn) are check-then-claim on shared state and are now
// serialized by the internal vault_mutex_. Before the fix, concurrent
// RPC handlers could claim the same VOID page and overwrite each other's
// secrets. Stress: 8 threads commit+consume unique payloads on ONE core
// instance; every consume must return ITS OWN payload, and the pool
// accounting must stay coherent throughout.
#include <gtest/gtest.h>
#include <atomic>
#include <string>
#include <thread>
#include <vector>

TEST(VortexVaultMemoryTest, ConcurrentCommitConsumeStress) {
    if (!vx::core::MemoryCore::mlock_supported()) {
        GTEST_SKIP() << "mlock unavailable in this environment (CI container); "
                        "locked-arena coverage requires RLIMIT_MEMLOCK >= arena size";
    }
    vx::core::MemoryCore core(vx::core::MemoryCore::DEFAULT_ARENA_SIZE);
    core.initialize(0xA11CEC0DEC0DEULL);

    constexpr int kThreads = 8;
    constexpr int kIters = 200;
    std::atomic<int> failures{0};
    std::atomic<int> consumed_ok{0};

    std::vector<std::thread> workers;
    for (int t = 0; t < kThreads; ++t) {
        workers.emplace_back([&, t]() {
            uint8_t out[256];
            for (int i = 0; i < kIters; ++i) {
                const std::string payload =
                    "T" + std::to_string(t) + "_I" + std::to_string(i) +
                    "_SECRET_VAULT_PAYLOAD_0123456789ABCDEF";
                try {
                    auto h = core.commit_secure_data(
                        reinterpret_cast<const uint8_t*>(payload.data()),
                        payload.size());
                    std::memset(out, 0, sizeof(out));
                    if (!core.consume_data(h, out)) {
                        ++failures; // token lost or page clobbered
                        continue;
                    }
                    if (std::memcmp(out, payload.data(), payload.size()) != 0) {
                        ++failures; // cross-contamination: another thread's data
                        continue;
                    }
                    ++consumed_ok;
                } catch (const std::exception&) {
                    ++failures; // pool exhaustion is impossible at this load
                }
            }
        });
    }
    for (auto& w : workers) w.join();

    EXPECT_EQ(failures.load(), 0);
    EXPECT_EQ(consumed_ok.load(), kThreads * kIters);

    // Coherent final accounting: every page consumed, none stranded LOCKED.
    const auto stats = core.get_stats();
    EXPECT_EQ(stats.locked_pages, 0);
}
