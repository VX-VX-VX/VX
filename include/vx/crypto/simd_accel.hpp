#pragma once

#include "vx/blockchain/crypto_sponge.hpp"
#include <cstdint>
#include <immintrin.h>

namespace vx::crypto {

// Compile-time feature detection
inline constexpr bool has_avx2() noexcept {
#if defined(__AVX2__)
    return true;
#else
    return false;
#endif
}

inline constexpr bool has_sse42() noexcept {
#if defined(__SSE4_2__)
    return true;
#else
    return false;
#endif
}

inline constexpr const char* simd_isa_name() noexcept {
    if (has_avx2() && has_sse42()) return "AVX2+SSE4.2";
    if (has_sse42()) return "SSE4.2";
    return "scalar";
}

// 4-way parallel VortexSponge256 using AVX2
// Processes 4 independent 128-byte blocks simultaneously
// Each block produces 32-byte digest (256 bits)
void sponge256_4way_avx2(
    const uint8_t* __restrict in0,
    const uint8_t* __restrict in1,
    const uint8_t* __restrict in2,
    const uint8_t* __restrict in3,
    uint8_t* __restrict out0,
    uint8_t* __restrict out1,
    uint8_t* __restrict out2,
    uint8_t* __restrict out3
) noexcept;

// Scalar fallback (bit-identical to crypto_sponge.hpp)
void sponge256_scalar(
    const uint8_t* __restrict in,
    size_t len,
    uint8_t* __restrict out
) noexcept;

// Hardware CRC32C using SSE4.2
// Computes CRC32C (Castagnoli polynomial) of a 64KB buffer
// Returns 0 if hardware acceleration unavailable
uint32_t crc32c_hw(const uint8_t* data, size_t len) noexcept;

// Scalar CRC32C fallback
uint32_t crc32c_scalar(const uint8_t* data, size_t len) noexcept;

// Verify all 580 transaction proofs in a frame using OpenMP
// Returns number of invalid proofs found
int verify_frame_parallel(
    const vx::blockchain::Transaction* txs,
    uint32_t tx_count
) noexcept;

} // namespace vx::crypto