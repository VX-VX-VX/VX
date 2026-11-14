#include "bench_sponge_cpu.h"

#include "vx/blockchain/crypto_sponge.hpp"

#include <chrono>
#include <array>

namespace vx::gpu {

double sponge256_cpu_bench_ms(const uint8_t *packed, uint32_t frames, uint32_t frame_len,
                              uint64_t &checksum) {
    const auto t0 = std::chrono::steady_clock::now();
    std::array<uint8_t, 32> d{};
    for (uint32_t i = 0; i < frames; ++i) {
        vx::blockchain::VortexSponge256::compute(packed + static_cast<size_t>(i) * frame_len,
                                                 frame_len, d.data());
        // Fold the digest so the loop is observable (no dead-code removal):
        // the printed checksum also lets a human spot silent divergence.
        for (int b = 0; b < 32; ++b)
            checksum = (checksum << 1 | checksum >> 63) ^ d[static_cast<size_t>(b)];
    }
    const auto t1 = std::chrono::steady_clock::now();
    return std::chrono::duration<double, std::milli>(t1 - t0).count() / static_cast<double>(frames);
}

} // namespace vx::gpu
