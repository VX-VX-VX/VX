// GPU/GMP bit-exact parity for the 1024-bit Solinas field (CUDA track
// deliverable 2, 2026-11-14). The no-stub rule: the GPU fold-reduction
// ships ONLY if its results are bit-identical with GMP `(a*b) % N` on
// every input — thousands of random pairs per modulus, the pow3 chain
// the attractor's cubic map actually performs, and the edge elements
// (0, 1, N-1) that historically break fold implementations.
#include <gtest/gtest.h>

#include "vx/core/types.hpp"
#if __has_include("vortex_field_cuda.cuh")
#include "vortex_field_cuda.cuh"
#define VX_CUDA_AVAILABLE 1
#else
#define VX_CUDA_AVAILABLE 0
#endif

#include <gmpxx.h>

#include <cstring>
#include <random>
#include <vector>

namespace {

struct ModInfo {
    int sel;
    unsigned k;
    unsigned long c;
};

// The ACTIVE moduli set: AttractorModuli::secure_crt (galois_attractor
// active_default). If the CPU core ever switches its default, this table
// and the device constants must move with it — the test will fail loudly
// the moment they disagree.
constexpr ModInfo kMods[3] = {{vx::gpu::FIELD_MOD_P, 64, 1747},
                              {vx::gpu::FIELD_MOD_Q, 888, 3943},
                              {vx::gpu::FIELD_MOD_R, 512, 267799}};

mpz_class modulus_mpz(const ModInfo &m) {
    mpz_class one = 1;
    return (one << 1024) - (one << m.k) - mpz_class(m.c);
}

// 16 little-endian uint64 limbs <-> mpz. GMP's order convention:
// -1 = least significant word first (1 would be MSW-first — the wrong
// direction for our little-endian limb layout).
mpz_class limbs_to_mpz(const uint64_t *l) {
    mpz_class v;
    mpz_import(v.get_mpz_t(), 16, -1, sizeof(uint64_t), 0, 0, l);
    return v;
}

void mpz_to_limbs(const mpz_class &v, uint64_t *l) {
    std::memset(l, 0, 16 * sizeof(uint64_t));
    size_t words = 0;
    mpz_export(l, &words, -1, sizeof(uint64_t), 0, 0, v.get_mpz_t());
    ASSERT_LE(words, 16u);
}

std::vector<uint64_t> random_reduced_elems(const mpz_class &N, uint32_t n, std::mt19937_64 &rng) {
    std::vector<uint64_t> out(static_cast<size_t>(n) * 16);
    for (uint32_t i = 0; i < n; ++i) {
        uint64_t raw[16];
        for (auto &w : raw)
            w = rng();
        mpz_class v = limbs_to_mpz(raw) % N;
        mpz_to_limbs(v, out.data() + static_cast<size_t>(i) * 16);
    }
    return out;
}

} // namespace

TEST(VortexCudaFieldParity, MulModMatchesGmpBitExact) {
#if !VX_CUDA_AVAILABLE
    GTEST_SKIP() << "CUDA track not configured (VX_CUDA=OFF or no toolkit)";
#else
    std::mt19937_64 rng(0x5EED);
    constexpr uint32_t kPairs = 1024;
    for (const auto &m : kMods) {
        const mpz_class N = modulus_mpz(m);
        const auto a = random_reduced_elems(N, kPairs, rng);
        const auto b = random_reduced_elems(N, kPairs, rng);
        std::vector<uint64_t> gpu_out(static_cast<size_t>(kPairs) * 16, 0xABADBABEULL);

        ASSERT_EQ(cudaSuccess,
                  vx::gpu::field_mulmod_batch(a.data(), b.data(), m.sel, kPairs, gpu_out.data()));

        for (uint32_t i = 0; i < kPairs; ++i) {
            const mpz_class A = limbs_to_mpz(a.data() + static_cast<size_t>(i) * 16);
            const mpz_class B = limbs_to_mpz(b.data() + static_cast<size_t>(i) * 16);
            const mpz_class expect = (A * B) % N;
            uint64_t exp_limbs[16];
            mpz_to_limbs(expect, exp_limbs);
            EXPECT_EQ(0, std::memcmp(exp_limbs, gpu_out.data() + static_cast<size_t>(i) * 16,
                                     16 * sizeof(uint64_t)))
                << "GPU/GMP divergence: modulus " << m.sel << " pair " << i;
        }
    }
#endif
}

TEST(VortexCudaFieldParity, Pow3ChainMatchesGmpBitExact) {
#if !VX_CUDA_AVAILABLE
    GTEST_SKIP() << "CUDA track not configured";
#else
    // The attractor's cubic map: Z^3 = (Z^2) * Z — two chained GPU calls
    // must land where GMP's powm lands.
    std::mt19937_64 rng(0xC0DE);
    constexpr uint32_t kElems = 512;
    for (const auto &m : kMods) {
        const mpz_class N = modulus_mpz(m);
        const auto z = random_reduced_elems(N, kElems, rng);
        std::vector<uint64_t> sq(static_cast<size_t>(kElems) * 16);
        std::vector<uint64_t> cube(static_cast<size_t>(kElems) * 16);

        ASSERT_EQ(cudaSuccess,
                  vx::gpu::field_mulmod_batch(z.data(), z.data(), m.sel, kElems, sq.data()));
        ASSERT_EQ(cudaSuccess,
                  vx::gpu::field_mulmod_batch(sq.data(), z.data(), m.sel, kElems, cube.data()));

        for (uint32_t i = 0; i < kElems; ++i) {
            const mpz_class Z = limbs_to_mpz(z.data() + static_cast<size_t>(i) * 16);
            const mpz_class expect = (Z * Z * Z) % N;
            uint64_t exp_limbs[16];
            mpz_to_limbs(expect, exp_limbs);
            EXPECT_EQ(0, std::memcmp(exp_limbs, cube.data() + static_cast<size_t>(i) * 16,
                                     16 * sizeof(uint64_t)))
                << "pow3 chain divergence: modulus " << m.sel << " elem " << i;
        }
    }
#endif
}

TEST(VortexCudaFieldParity, InvalidModulusSelectorRejected) {
#if !VX_CUDA_AVAILABLE
    GTEST_SKIP() << "CUDA track not configured";
#else
    // Review P3: the host-side mod_sel validation is part of the contract.
    uint64_t a[16] = {1}, out[16];
    EXPECT_EQ(cudaErrorInvalidValue, vx::gpu::field_mulmod_batch(a, a, -1, 1, out));
    EXPECT_EQ(cudaErrorInvalidValue, vx::gpu::field_mulmod_batch(a, a, 3, 1, out));
#endif
}

TEST(VortexCudaFieldParity, EdgeElementsExact) {
#if !VX_CUDA_AVAILABLE
    GTEST_SKIP() << "CUDA track not configured";
#else
    for (const auto &m : kMods) {
        const mpz_class N = modulus_mpz(m);
        // 0*0=0, 1*1=1, (N-1)*(N-1)=1, (N-1)*1=N-1, 0*(N-1)=0.
        const std::vector<mpz_class> cases = {0, 1, N - 1};
        std::vector<uint64_t> a16(16), b16(16), out(16);
        for (const auto &A : cases) {
            for (const auto &B : cases) {
                mpz_to_limbs(A % N, a16.data());
                mpz_to_limbs(B % N, b16.data());
                ASSERT_EQ(cudaSuccess, vx::gpu::field_mulmod_batch(a16.data(), b16.data(), m.sel, 1,
                                                                   out.data()));
                uint64_t exp[16];
                mpz_to_limbs((A * B) % N, exp);
                EXPECT_EQ(0, std::memcmp(exp, out.data(), 16 * sizeof(uint64_t)))
                    << "edge case divergence: mod " << m.sel;
            }
        }
    }
#endif
}
