// GPU/CPU bit-exact parity for VortexSponge256 (CUDA track, 2026-11-14).
//
// The no-stub rule: the GPU port ships ONLY if its digests are
// byte-identical with the CPU consensus sponge across thousands of
// vectors, including the production shape (full 64 KiB block frames).
// A digest mismatch here is a shipped-bug alarm, not a tolerance issue.
#include <gtest/gtest.h>

#include "vx/blockchain/crypto_sponge.hpp"
#if __has_include("vortex_sponge_cuda.cuh")
#include "vortex_sponge_cuda.cuh"
#define VX_CUDA_AVAILABLE 1
#else
#define VX_CUDA_AVAILABLE 0
#endif

#include <array>
#include <cstring>
#include <random>
#include <vector>

namespace {

std::vector<uint8_t> pseudo_bytes(uint64_t seed, size_t n) {
    std::mt19937_64 rng(seed);
    std::vector<uint8_t> v(n);
    for (auto &b : v)
        b = static_cast<uint8_t>(rng() & 0xFF);
    return v;
}

} // namespace

TEST(VortexCudaParity, Sponge256BatchMatchesCpuBitExact) {
#if !VX_CUDA_AVAILABLE
    GTEST_SKIP() << "CUDA track not configured (VX_CUDA=OFF or no toolkit)";
#else
    int dev = 0;
    char name[256] = {0};
    int sms = 0;
    ASSERT_TRUE(vx::gpu::device_info(&dev, name, sizeof(name), &sms))
        << "CUDA configured but no usable device";
    std::printf("[ GPU ] device %d: %s (%d SMs)\n", dev, name, sms);

    // Deterministic corpus: varied lengths (empty, tiny, rate-boundaries,
    // multi-chunk, and full 64 KiB frames), pseudo-random content.
    std::vector<std::vector<uint8_t>> corpus;
    corpus.push_back({});
    for (size_t len : {1u, 31u, 32u, 33u, 63u, 64u, 65u, 127u, 1000u, 4096u, 65536u})
        corpus.push_back(pseudo_bytes(0xC0FFEE + len, len));
    for (int i = 0; i < 2048; ++i)
        corpus.push_back(pseudo_bytes(1000 + i, 1 + (i % 97)));

    std::vector<uint8_t> packed;
    std::vector<uint32_t> lens(corpus.size());
    std::vector<int64_t> offsets(corpus.size() + 1);
    int64_t acc = 0;
    for (size_t i = 0; i < corpus.size(); ++i) {
        offsets[i] = acc;
        lens[i] = static_cast<uint32_t>(corpus[i].size());
        packed.insert(packed.end(), corpus[i].begin(), corpus[i].end());
        acc += static_cast<int64_t>(lens[i]);
    }
    offsets.back() = acc;

    std::vector<uint8_t> gpu_digests(corpus.size() * 32);
    // sponge256_batch computes its own prefix sum from `lens`; the explicit
    // offsets here only prove the packing is consistent.
    ASSERT_EQ(acc, offsets.back());
    ASSERT_EQ(cudaSuccess,
              vx::gpu::sponge256_batch(packed.data(), lens.data(),
                                       static_cast<uint32_t>(corpus.size()), gpu_digests.data()));

    for (size_t i = 0; i < corpus.size(); ++i) {
        std::array<uint8_t, 32> cpu{};
        vx::blockchain::VortexSponge256::compute(corpus[i].data(), corpus[i].size(), cpu.data());
        ASSERT_EQ(0, std::memcmp(cpu.data(), gpu_digests.data() + i * 32, 32))
            << "GPU/CPU divergence at corpus index " << i << " (len " << corpus[i].size() << ")";
    }
#endif
}

TEST(VortexCudaParity, Sponge256BatchRejectsBadArgs) {
#if !VX_CUDA_AVAILABLE
    GTEST_SKIP() << "CUDA track not configured";
#else
    EXPECT_EQ(cudaErrorInvalidValue, vx::gpu::sponge256_batch(nullptr, nullptr, 4, nullptr));
    // n == 0 is a success no-op, never an error.
    EXPECT_EQ(cudaSuccess, vx::gpu::sponge256_batch(nullptr, nullptr, 0, nullptr));
#endif
}
