#include "vx/core/rt_scheduler.hpp"
#include "vx/core/memory_vault.hpp"

#include <pthread.h>
#include <sched.h>
#include <unistd.h>
#include <sys/syscall.h>
#include <sys/prctl.h>
#include "vx/core/hw_intrinsics.hpp"
#include <fstream>
#include <sstream>
#include <cstring>

namespace vx::core {

bool LockStepScheduler::bind_to_cpu(int cpu_id) {
    cpu_set_t cpuset;
    CPU_ZERO(&cpuset);
    CPU_SET(cpu_id, &cpuset);

    pthread_t thread = pthread_self();
    int result = pthread_setaffinity_np(thread, sizeof(cpu_set_t), &cpuset);

    if (result == 0) {
        bound_cpu_.store(cpu_id, std::memory_order_relaxed);
        return true;
    }
    return false;
}

bool LockStepScheduler::set_realtime_priority(int priority) {
    struct sched_param param;
    param.sched_priority = priority;

    int result = sched_setscheduler(0, SCHED_FIFO, &param);
    if (result == 0) {
        realtime_priority_.store(priority, std::memory_order_relaxed);
        return true;
    }

    // Graceful fallback
    realtime_priority_.store(-1, std::memory_order_relaxed);
    return false;
}

bool LockStepScheduler::check_debugger_attached() noexcept {
    std::ifstream status("/proc/self/status");
    std::string line;
    while (std::getline(status, line)) {
        if (line.find("TracerPid:") == 0) {
            int tracer_pid = 0;
            std::istringstream iss(line.substr(10));
            iss >> tracer_pid;
            if (tracer_pid != 0) return true;
        }
    }

    if (prctl(PR_GET_DUMPABLE, 0, 0, 0, 0) == 0) {
        return true;
    }

    return false;
}

void LockStepScheduler::scrub_execution_state(void* sensitive_buf, size_t len) noexcept {
    if (!sensitive_buf || len == 0) return;

    std::atomic_signal_fence(std::memory_order_seq_cst);

    volatile uint8_t* p = static_cast<volatile uint8_t*>(sensitive_buf);
    for (size_t i = 0; i < len; ++i) {
        p[i] = 0;
    }

    // Cache line flush via the portable hardware primitive
    hw::flush_cache_range(sensitive_buf, len);

    std::atomic_signal_fence(std::memory_order_seq_cst);
    asm volatile("" ::: "memory");
}

template<typename SignFunc>
bool LockStepScheduler::execute_lock_step(SignFunc&& signer, void* seed_data, size_t seed_len) {
    if (check_debugger_attached()) {
        return false;
    }

    MemoryCore core(MemoryCore::DEFAULT_ARENA_SIZE);
    core.initialize(0xdeadbeefcafebabeULL);

    // Unpack Seed
    auto hash = core.commit_secure_data(
        static_cast<const uint8_t*>(seed_data),
        seed_len
    );

    // Compute 1000-Round Attractor (placeholder for actual crypto)
    // In real implementation, this would call Galois Attractor
    volatile uint64_t dummy_result = 0;
    for (int i = 0; i < 1000; ++i) {
        dummy_result += static_cast<uint8_t*>(seed_data)[i % seed_len] * (i + 1);
    }

    // Sign Payload
    bool signed_ok = signer(dummy_result);

    // Burn MemoryPage
    uint8_t dummy_out[256];
    core.consume_data(hash, dummy_out);

    // Scrub Registers & Cache
    scrub_execution_state(seed_data, seed_len);

    lock_step_cycles_.fetch_add(1, std::memory_order_relaxed);
    total_cycles_burned_.fetch_add(1000, std::memory_order_relaxed);

    return signed_ok;
}

LockStepScheduler::Stats LockStepScheduler::get_stats() const noexcept {
    Stats stats;
    stats.bound_cpu = bound_cpu_.load(std::memory_order_relaxed);
    stats.realtime_priority = realtime_priority_.load(std::memory_order_relaxed);
    stats.debugger_detected = check_debugger_attached();
    stats.lock_step_cycles = lock_step_cycles_.load(std::memory_order_relaxed);
    stats.total_cycles_burned = total_cycles_burned_.load(std::memory_order_relaxed);
    return stats;
}

} // namespace vx::core