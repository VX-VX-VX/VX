#pragma once

// rdtsc Bare-Metal Profiler — hardware telemetry at CPU-cycle
// granularity (__rdtsc()).
//
// Six kernel contours are profiled in directive order:
//   1. solinas_fast_reduction_1024b  — division-free Solinas reduction
//   2. avx2_sponge_4way_hash         — SIMD sponge over 4 blocks
//   3. tensor_v6_arx_step            — one ARX step of the 16384-bit matrix
//   4. vortex_vm_opcode_dispatch     — one VM instruction with Landauer meter
//   5. vault_ephemeral_sign_and_burn — LOCKED -> SIGN -> clflush -> BURNED
//   6. sgmt_merkle_proof_verify      — Galois trie witness verification

#include <cstdint>
#include <functional>
#include <vector>

namespace vx::core {

struct RdtscSample {
    const char* op_name = nullptr;
    uint64_t iterations = 0;
    uint64_t min_cycles = 0;
    uint64_t p50_cycles = 0;
    uint64_t p99_cycles = 0;
    uint64_t max_cycles = 0;
    double cycles_per_iter = 0.0;
    double estimated_ns = 0.0; // wall-clock nanoseconds per invocation
};

class RdtscProfiler {
public:
    struct Iterations {
        uint64_t solinas = 1000;
        uint64_t sponge = 1000;
        uint64_t tensor = 1000;
        uint64_t vm = 1000;
        uint64_t vault = 256; // full sign+burn cycle costs ~1.4 ms
        uint64_t sgmt = 1000;
    };

    RdtscProfiler() = default;
    explicit RdtscProfiler(Iterations iters) : iters_(iters) {}

    // Runs all six contours; the result is ordered as in the directive.
    std::vector<RdtscSample> run_full_profile() const;

    // Times one contour: per-invocation __rdtsc deltas sorted into
    // min/p50/p99/max plus a wall-clock ns estimate.
    static RdtscSample profile(const char* name, uint64_t iters,
                               const std::function<void()>& op);

private:
    Iterations iters_;
};

} // namespace vx::core
