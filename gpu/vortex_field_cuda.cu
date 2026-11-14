// 1024-bit Solinas field kernels — see vortex_field_cuda.cuh for the
// parity contract and the modulus table. Every helper below operates on
// little-endian uint64 limb arrays; N < 2^1024, products ≤ 2^2048 (32
// limbs), fold intermediates stay < 2^1913 in the worst case (k = 888),
// so the 64-limb scratch cannot overflow its own domain:
//   fold step: lo (≤ 2^1024) + hi<<k (≤ 2^(1024+k)) + c*hi (≤ 2^(1024+18))
//   → next hi ≤ 2^(k+19)  → the excess shrinks by (1024-k) bits per round.
#include "vortex_field_cuda.cuh"

#include <cuda_runtime.h>

#include <vector>

namespace vx::gpu {
namespace {

constexpr int kLimbs = 16;    // 1024 bits
constexpr int kBigLimbs = 64; // fold scratch: up to 4096 bits (generous)

struct ModulusSpec {
    uint32_t k;  // exponent of the subtracted power of two
    uint64_t c;  // small additive constant
};

__device__ __constant__ ModulusSpec kModuli[3] = {
    {64, 1747},   // p = 2^1024 - 2^64  - 1747  (secure_crt)
    {888, 3943},  // q = 2^1024 - 2^888 - 3943
    {512, 267799} // r = 2^1024 - 2^512 - 267799
};

__device__ __forceinline__ void big_zero(uint64_t *x, int n) {
    for (int i = 0; i < n; ++i) x[i] = 0;
}

__device__ __forceinline__ void big_copy(const uint64_t *src, uint64_t *dst, int n) {
    for (int i = 0; i < n; ++i) dst[i] = src[i];
}

// x -= y (n limbs, x >= y); returns the borrow out of the top limb.
__device__ __forceinline__ uint64_t big_sub(uint64_t *x, const uint64_t *y, int n) {
    uint64_t borrow = 0;
    for (int i = 0; i < n; ++i) {
        // signed-style borrow: negative t means the subtraction underflowed
        const __int128 t = (__int128)x[i] - y[i] - borrow;
        x[i] = (uint64_t)t;
        borrow = (t < 0) ? 1u : 0u;
    }
    return borrow;
}

// x += (y << k_bits), y: 16-limb value, x: 64-limb accumulator with room.
// Full carry discipline: the add carry AND the shift residue both chain.
__device__ __forceinline__ void big_add_shifted(uint64_t *x, const uint64_t *y,
                                                const int k_bits) {
    const int limb_shift = k_bits >> 6;
    const int bit_shift = k_bits & 63;
    unsigned __int128 carry = 0;
    for (int i = 0; i < kLimbs; ++i) {
        uint64_t v;
        if (bit_shift) {
            const uint64_t lo = y[i] << bit_shift;
            const uint64_t hi = i ? (y[i - 1] >> (64 - bit_shift)) : 0;
            v = lo | hi;
        } else {
            v = y[i];
        }
        const unsigned __int128 t = (unsigned __int128)x[limb_shift + i] + v + carry;
        x[limb_shift + i] = (uint64_t)t;
        carry = t >> 64;
    }
    // The shift residue of y[15] plus any pending add carry lands past
    // the loop's range and propagates.
    const uint64_t residue = bit_shift ? (y[kLimbs - 1] >> (64 - bit_shift)) : 0;
    unsigned __int128 acc = (unsigned __int128)residue + carry;
    int idx = limb_shift + kLimbs;
    while (acc && idx < kBigLimbs) {
        const unsigned __int128 t = (unsigned __int128)x[idx] + (uint64_t)acc;
        x[idx] = (uint64_t)t;
        acc = (acc >> 64) + (t >> 64);
        ++idx;
    }
}

// x += y * c (y: 16 limbs, c < 2^32) with a full carry chain.
// 128-bit intermediate: the 64x64->128 product must never be assembled
// from a uint64 `mid` that can itself overflow (the original bug — the
// parity hunt found it: mid = p01 + p10 + p00>>32 overflows for full
// limbs, losing carries and corrupting every fold round).
__device__ __forceinline__ void big_add_mul_small(uint64_t *x, const uint64_t *y, uint64_t c) {
    unsigned __int128 carry = 0;
    for (int i = 0; i < kLimbs; ++i) {
        const unsigned __int128 p = (unsigned __int128)y[i] * c;
        const unsigned __int128 t = (unsigned __int128)x[i] + p + carry;
        x[i] = (uint64_t)t;
        carry = t >> 64;
    }
    int idx = kLimbs;
    while (carry && idx < kBigLimbs) {
        const unsigned __int128 t = (unsigned __int128)x[idx] + (uint64_t)carry;
        x[idx] = (uint64_t)t;
        carry = t >> 64;
        ++idx;
    }
}

// x >= N? (both ≤ 16 limbs significant at call time.)
__device__ __forceinline__ bool big_ge(const uint64_t *x, const uint64_t *n16) {
    for (int i = kLimbs - 1; i >= 0; --i) {
        if (x[i] != n16[i]) return x[i] > n16[i];
    }
    return true; // equal
}

// N = 2^1024 - 2^k - c as 16 limbs: two's complement of (2^k + c) below
// 2^1024. t's significant bits sit far below 1024 (k ≤ 888), so the
// truncated subtraction IS the full subtraction.
__device__ __forceinline__ void modulus_limbs(const ModulusSpec &m, uint64_t *n16) {
    uint64_t t[kBigLimbs];
    big_zero(t, kBigLimbs);
    t[m.k >> 6] |= 1ULL << (m.k & 63);
    t[0] += m.c; // no carry-out: limb 0 gains at most 2^32 on a zero limb
    big_zero(n16, kLimbs);
    const uint64_t borrow = big_sub(n16, t, kLimbs); // 0 - t (mod 2^1024)
    (void)borrow;
}

// Schoolbook 16x16 → 32 limbs, full carry chain.
__device__ __forceinline__ void mul_1024(const uint64_t *a, const uint64_t *b, uint64_t *out32) {
    big_zero(out32, 2 * kLimbs);
    for (int i = 0; i < kLimbs; ++i) {
        if (!a[i]) continue;
        unsigned __int128 carry = 0;
        for (int j = 0; j < kLimbs; ++j) {
            const unsigned __int128 p = (unsigned __int128)a[i] * b[j];
            const unsigned __int128 t = (unsigned __int128)out32[i + j] + p + carry;
            out32[i + j] = (uint64_t)t;
            carry = t >> 64;
        }
        int idx = i + kLimbs;
        while (carry && idx < 2 * kLimbs) {
            const unsigned __int128 t = (unsigned __int128)out32[idx] + (uint64_t)carry;
            out32[idx] = (uint64_t)t;
            carry = t >> 64;
            ++idx;
        }
    }
}

__global__ void field_mulmod_kernel(const uint64_t *a, const uint64_t *b, int mod_sel,
                                    uint32_t n, uint64_t *out) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    const ModulusSpec m = kModuli[mod_sel];
    uint64_t n16[kLimbs];
    modulus_limbs(m, n16);

    const uint64_t *ae = a + static_cast<size_t>(i) * kLimbs;
    const uint64_t *be = b + static_cast<size_t>(i) * kLimbs;

    // x = a * b  (≤ 2^2048 → 32 limbs; limbs 32..63 stay zero because the
    // fold's worst case is 1913 bits — see the file header).
    uint64_t x[kBigLimbs];
    big_zero(x, kBigLimbs);
    mul_1024(ae, be, x);

    // Division-free fold: replace the excess above 2^1024 with
    // (hi << k) + c*hi until no limb ≥ 16 survives; a final conditional
    // subtract finishes (x < 2^1024 < 2N after the fold, so ≤ 1 subtract).
    uint64_t hi[kLimbs];
    uint64_t lo[kLimbs];
    for (;;) {
        bool any = false;
        for (int j = kLimbs; j < 2 * kLimbs; ++j)
            if (x[j]) { any = true; break; }
        if (!any) break;

        big_copy(x + kLimbs, hi, kLimbs);
        big_copy(x, lo, kLimbs);
big_zero(x, kBigLimbs);
        big_copy(lo, x, kLimbs);
        big_add_shifted(x, hi, static_cast<int>(m.k));
big_add_mul_small(x, hi, m.c);
}

    while (big_ge(x, n16)) big_sub(x, n16, kLimbs);
    big_copy(x, out + static_cast<size_t>(i) * kLimbs, kLimbs);
}

} // namespace

cudaError_t field_mulmod_batch(const uint64_t *a_elems, const uint64_t *b_elems, int mod_sel,
                               uint32_t n, uint64_t *out_elems, cudaStream_t stream) {
    if (n == 0) return cudaSuccess;
    if (mod_sel < FIELD_MOD_P || mod_sel > FIELD_MOD_R) return cudaErrorInvalidValue;
    if (!a_elems || !b_elems || !out_elems) return cudaErrorInvalidValue;

    uint64_t *d_a = nullptr, *d_b = nullptr, *d_out = nullptr;
    const size_t bytes = static_cast<size_t>(n) * kLimbs * sizeof(uint64_t);
    cudaError_t err = cudaMalloc(&d_a, bytes);
    if (err == cudaSuccess) err = cudaMalloc(&d_b, bytes);
    if (err == cudaSuccess) err = cudaMalloc(&d_out, bytes);
    if (err == cudaSuccess)
        err = cudaMemcpyAsync(d_a, a_elems, bytes, cudaMemcpyHostToDevice, stream);
    if (err == cudaSuccess)
        err = cudaMemcpyAsync(d_b, b_elems, bytes, cudaMemcpyHostToDevice, stream);
    if (err == cudaSuccess) {
        const int block = 128;
        const int grid = static_cast<int>((n + block - 1) / block);
        field_mulmod_kernel<<<grid, block, 0, stream>>>(d_a, d_b, mod_sel, n, d_out);
        err = cudaGetLastError();
    }
    if (err == cudaSuccess)
        err = cudaMemcpyAsync(out_elems, d_out, bytes, cudaMemcpyDeviceToHost, stream);
    if (err == cudaSuccess) err = cudaStreamSynchronize(stream);

    const cudaError_t e1 = cudaFree(d_a), e2 = cudaFree(d_b), e3 = cudaFree(d_out);
    if (err == cudaSuccess && (e1 || e2 || e3)) err = e1 ? e1 : (e2 ? e2 : e3);
    return err;
}

} // namespace vx::gpu
