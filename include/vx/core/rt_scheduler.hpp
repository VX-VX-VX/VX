#pragma once

#include <cstdint>
#include <pthread.h>
#include <sched.h>
#include <atomic>
#include <thread>

namespace vx::core {

class LockStepScheduler {
public:
    static constexpr int CPU_ISOLATION_MASK = 0x03; // CPUs 0-1 for crypto workers

    explicit LockStepScheduler() = default;
    ~LockStepScheduler() = default;

    LockStepScheduler(const LockStepScheduler&) = delete;
    LockStepScheduler& operator=(const LockStepScheduler&) = delete;

    // Pin thread to isolated CPU core
    bool bind_to_cpu(int cpu_id);

    // Attempt to set SCHED_FIFO real-time scheduling
    bool set_realtime_priority(int priority = 99);

    // Check if debugger is attached
    static bool check_debugger_attached() noexcept;

    // Scrub execution state (memory barrier + cache flush + secure zero)
    static void scrub_execution_state(void* sensitive_buf, size_t len) noexcept;

    // Lock-step transaction signing workflow
    template<typename SignFunc>
    bool execute_lock_step(SignFunc&& signer, void* seed_data, size_t seed_len);

    // Get scheduler statistics
    struct Stats {
        int bound_cpu;
        int realtime_priority;
        bool debugger_detected;
        size_t lock_step_cycles;
        uint64_t total_cycles_burned;
    };
    Stats get_stats() const noexcept;

private:
    std::atomic<int> bound_cpu_{-1};
    std::atomic<int> realtime_priority_{-1};
    std::atomic<size_t> lock_step_cycles_{0};
    std::atomic<uint64_t> total_cycles_burned_{0};
};

} // namespace vx::core