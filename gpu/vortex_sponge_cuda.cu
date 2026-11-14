#include "vortex_sponge_cuda.cuh"

#include <cuda_runtime.h>

#include <vector>

// VortexSponge256 CUDA kernel + host wrapper. See vortex_sponge_cuda.cuh
// for the parity contract. Every constant and every step below mirrors
// include/vx/blockchain/crypto_sponge.hpp EXACTLY; the parity test is
// what proves it, this comment is not.
#include "vortex_sponge_cuda.cuh"

#include <cuda_runtime.h>

#include <cstdio>
#include <cstring>

namespace vx::gpu {
namespace {

__device__ __forceinline__ uint64_t rotl64_dev(uint64_t x, unsigned r) {
    const unsigned s = r & 63u;
    return (x << s) | (x >> ((64u - s) & 63u));
}

// ChaCha-style ARX quarter-round — identical to the CPU quarter_round.
__device__ __forceinline__ void quarter_round_dev(uint64_t &a, uint64_t &b, uint64_t &c,
                                                  uint64_t &d) {
    a += b; d ^= a; d = rotl64_dev(d, 16);
    c += d; b ^= c; b = rotl64_dev(b, 12);
    a += b; d ^= a; d = rotl64_dev(d, 8);
    c += d; b ^= c; b = rotl64_dev(b, 7);
}

// Golden-Phi initial state (crypto_sponge.hpp reset()).
__device__ __constant__ uint64_t kInitState[8] = {
    0x9e3779b97f4a7c15ULL, 0xf39cc0605cedc834ULL, 0x1082276bf3a27251ULL,
    0xf86c6a11d0c18e95ULL, 0x276707e7869666c0ULL, 0x7166e4a2e5576ac6ULL,
    0xc5a08e06385cfd4fULL, 0x54d4f87a0229c15dULL,
};

__device__ __forceinline__ void sponge256_one(const uint8_t *msg, uint32_t len,
                                              uint8_t out[32]) {
    uint64_t s0 = kInitState[0], s1 = kInitState[1], s2 = kInitState[2],
             s3 = kInitState[3], s4 = kInitState[4], s5 = kInitState[5],
             s6 = kInitState[6], s7 = kInitState[7];

    // Parity rule (2026-11-14): a ZERO-length message performs NO absorb
    // mixes on the CPU path (the absorb loop never runs) — the digest is
    // pad-mix only. The GPU must skip the loop entirely for len == 0, or
    // it mixes one all-zero rate block the CPU never mixes (found by the
    // parity test at corpus index 0).
    if (len != 0u) {
    uint32_t off = 0;
    for (;;) {
        const uint32_t chunk = min(len - off, 32u);
        // Zero-padded 32-byte block, loaded as 4 little-endian uint64
        // words (the CPU loads the buffer the same way; both targets are
        // little-endian by contract).
        uint64_t w0 = 0, w1 = 0, w2 = 0, w3 = 0;
        uint8_t blk[32];
        for (uint32_t i = 0; i < chunk; ++i) blk[i] = msg[off + i];
        for (uint32_t i = chunk; i < 32; ++i) blk[i] = 0;
        memcpy(&w0, blk, 8);
        memcpy(&w1, blk + 8, 8);
        memcpy(&w2, blk + 16, 8);
        memcpy(&w3, blk + 24, 8);
        s4 ^= w0; s5 ^= w1; s6 ^= w2; s7 ^= w3;

        #pragma unroll
        for (int r = 0; r < 12; ++r) {
            quarter_round_dev(s0, s4, s1, s5);
            quarter_round_dev(s2, s6, s3, s7);
            quarter_round_dev(s0, s2, s4, s6);
            quarter_round_dev(s1, s3, s5, s7);
        }

        off += chunk;
        if (off >= len) break;
    }
    } // len != 0

    // Finalize pad: absorb a single 0x80 byte (block = 0x80 then zeros;
    // little-endian word 0 == 0x80), same as the CPU path.
    s4 ^= 0x80ULL;
    #pragma unroll
    for (int r = 0; r < 12; ++r) {
        quarter_round_dev(s0, s4, s1, s5);
        quarter_round_dev(s2, s6, s3, s7);
        quarter_round_dev(s0, s2, s4, s6);
        quarter_round_dev(s1, s3, s5, s7);
    }

    // Squeeze words 0..3 as little-endian bytes.
    const uint64_t ws[4] = {s0, s1, s2, s3};
    #pragma unroll
    for (int i = 0; i < 4; ++i)
        for (int b = 0; b < 8; ++b) out[i * 8 + b] = (uint8_t)((ws[i] >> (b * 8)) & 0xFF);
}

// One thread per message. offsets[i] is the byte offset of message i in
// the packed buffer (host-computed prefix sum, n+1 entries).
__global__ void sponge256_kernel(const uint8_t *msgs, const int64_t *offsets,
                                 const uint32_t *lens, uint32_t n, uint8_t *digests) {
    const uint32_t i = blockIdx.x * blockDim.x + threadIdx.x;
    if (i >= n) return;
    sponge256_one(msgs + offsets[i], lens[i], digests + static_cast<size_t>(i) * 32);
}

} // namespace

cudaError_t sponge256_batch(const uint8_t *msgs, const uint32_t *lens, uint32_t n,
                            uint8_t *digests_out, cudaStream_t stream) {
    if (n == 0) return cudaSuccess;
    if (!lens || !digests_out) return cudaErrorInvalidValue;
    // A packed buffer of only-empty messages is legitimately nullptr.
    size_t acc = 0;
    for (uint32_t i = 0; i < n; ++i) acc += lens[i];
    if (acc != 0 && !msgs) return cudaErrorInvalidValue;

    // Host-side prefix sum (n is small; a device scan is a later
    // optimization, not a semantic one).
    std::vector<int64_t> offsets(static_cast<size_t>(n) + 1);
    int64_t acc64 = 0;
    for (uint32_t i = 0; i < n; ++i) {
        offsets[i] = acc64;
        acc64 += lens[i];
    }
    offsets[n] = acc64;
    acc = static_cast<size_t>(acc64);

    uint8_t *d_msgs = nullptr;
    int64_t *d_offsets = nullptr;
    uint32_t *d_lens = nullptr;
    uint8_t *d_digests = nullptr;
    cudaError_t err = cudaMalloc(&d_msgs, static_cast<size_t>(acc));
    if (err != cudaSuccess) return err;
    err = cudaMalloc(&d_offsets, offsets.size() * sizeof(int64_t));
    if (err == cudaSuccess)
        err = cudaMalloc(&d_lens, static_cast<size_t>(n) * sizeof(uint32_t));
    if (err == cudaSuccess)
        err = cudaMalloc(&d_digests, static_cast<size_t>(n) * 32);
    if (err == cudaSuccess && acc != 0)
        // Review P3: an all-empty batch is legal with msgs == nullptr —
        // skip the H2D copy entirely (a null-src memcpy is unspecified for
        // size 0 on some toolkits).
        err = cudaMemcpyAsync(d_msgs, msgs, static_cast<size_t>(acc), cudaMemcpyHostToDevice,
                              stream);
    if (err == cudaSuccess)
        err = cudaMemcpyAsync(d_offsets, offsets.data(), offsets.size() * sizeof(int64_t),
                              cudaMemcpyHostToDevice, stream);
    if (err == cudaSuccess)
        err = cudaMemcpyAsync(d_lens, lens, static_cast<size_t>(n) * sizeof(uint32_t),
                              cudaMemcpyHostToDevice, stream);
    if (err == cudaSuccess) {
        const int block = 256;
        const int grid = static_cast<int>((n + block - 1) / block);
        sponge256_kernel<<<grid, block, 0, stream>>>(d_msgs, d_offsets, d_lens, n, d_digests);
        err = cudaGetLastError();
    }
    if (err == cudaSuccess)
        err = cudaMemcpyAsync(digests_out, d_digests, static_cast<size_t>(n) * 32,
                              cudaMemcpyDeviceToHost, stream);
    if (err == cudaSuccess)
        err = cudaStreamSynchronize(stream);

    // Free regardless; the first error above is the one reported.
    const cudaError_t free_err_1 = cudaFree(d_msgs);
    const cudaError_t free_err_2 = cudaFree(d_offsets);
    const cudaError_t free_err_3 = cudaFree(d_lens);
    const cudaError_t free_err_4 = cudaFree(d_digests);
    if (err == cudaSuccess && (free_err_1 || free_err_2 || free_err_3 || free_err_4))
        err = free_err_1 ? free_err_1 : (free_err_2 ? free_err_2
                                                    : (free_err_3 ? free_err_3 : free_err_4));
    return err;
}

bool device_info(int *device_id, char *name_out, int name_len, int *sm_count) {
    int dev = 0;
    if (cudaGetDevice(&dev) != cudaSuccess) return false;
    cudaDeviceProp prop{};
    if (cudaGetDeviceProperties(&prop, dev) != cudaSuccess) return false;
    if (device_id) *device_id = dev;
    if (name_out && name_len > 0) std::strncpy(name_out, prop.name, name_len - 1);
    if (sm_count) *sm_count = prop.multiProcessorCount;
    return true;
}

} // namespace vx::gpu
