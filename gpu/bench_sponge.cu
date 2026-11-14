// VortexSponge256 GPU benchmark (standalone; CUDA track, 2026-11-14).
// Reports: device, batch time for full 64 KiB block frames (the PoGW
// hashing shape) including H2D/D2H transfer, plus the CPU single-thread
// reference (bench_sponge_cpu.cpp — the .cu translation unit must not
// include the C++26 consensus headers nvcc cannot parse).
// Honest numbers only: both transfer classes are printed, neither hidden.
#include "bench_sponge_cpu.h"
#include "vortex_sponge_cuda.cuh"

#include <chrono>
#include <cstdio>
#include <cstring>
#include <random>
#include <vector>

int main() {
    int dev = 0;
    char name[256] = {0};
    int sms = 0;
    if (!vx::gpu::device_info(&dev, name, sizeof(name), &sms)) {
        std::fprintf(stderr, "no CUDA device\n");
        return 1;
    }
    std::printf("device: %s (%d SMs)\n", name, sms);

    constexpr uint32_t kFrames = 4096;      // messages
    constexpr uint32_t kFrame = 65536;      // bytes (the block frame size)
    std::vector<uint8_t> packed(static_cast<size_t>(kFrames) * kFrame);
    std::mt19937_64 rng(42);
    for (auto &b : packed) b = static_cast<uint8_t>(rng() & 0xFF);
    std::vector<uint32_t> lens(kFrames, kFrame);
    std::vector<uint8_t> digests(static_cast<size_t>(kFrames) * 32);

    // Warm-up (module load, clocks).
    if (vx::gpu::sponge256_batch(packed.data(), lens.data(), 64, digests.data()) !=
        cudaSuccess) {
        std::fprintf(stderr, "warm-up launch failed: %s\n", cudaGetErrorString(cudaGetLastError()));
        return 1;
    }

    // GPU, transfer included.
    auto t0 = std::chrono::steady_clock::now();
    if (vx::gpu::sponge256_batch(packed.data(), lens.data(), kFrames, digests.data()) !=
        cudaSuccess) {
        std::fprintf(stderr, "launch failed: %s\n", cudaGetErrorString(cudaGetLastError()));
        return 1;
    }
    auto t1 = std::chrono::steady_clock::now();
    const double gpu_total =
        std::chrono::duration<double, std::milli>(t1 - t0).count();
    const double gpu_gbps =
        static_cast<double>(kFrames) * kFrame / (gpu_total / 1000.0) / 1e9;
    std::printf("GPU  %6u frames x 64KiB: %8.2f ms  (%7.2f GB/s incl. transfer)\n", kFrames,
                gpu_total, gpu_gbps);

    // CPU reference, single thread (256 frames to keep the run short).
    uint64_t cpu_checksum = 0;
    const double cpu_ms = vx::gpu::sponge256_cpu_bench_ms(packed.data(), 256, kFrame, cpu_checksum);
    std::printf("CPU checksum (fold of 256 digests): %016llx\n",
               static_cast<unsigned long long>(cpu_checksum));
    std::printf("CPU  1 thread,  per 64KiB frame: %8.4f ms  (%7.2f GB/s)\n", cpu_ms,
               kFrame / (cpu_ms / 1000.0) / 1e9);
    std::printf("GPU speedup vs 1 CPU thread (incl. transfer): %8.2fx\n",
               (static_cast<double>(kFrames) * cpu_ms) / gpu_total);
    return 0;
}
