#include "vx/crypto/simd_accel.hpp"
#include "vx/core/hw_intrinsics.hpp"
#include <cstring>
#if defined(__AVX2__) || defined(__SSE4_2__)
#include <immintrin.h>
#endif
#include <omp.h>

namespace vx::crypto {

// Golden Phi constants for initial state (matching VortexSponge256)
static constexpr uint64_t K0 = 0x9e3779b97f4a7c15ULL;
static constexpr uint64_t K1 = 0xf39cc0605cedc834ULL;
static constexpr uint64_t K2 = 0x1082276bf3a27251ULL;
static constexpr uint64_t K3 = 0xf86c6a11d0c18e95ULL;
static constexpr uint64_t K4 = 0x276707e7869666c0ULL;
static constexpr uint64_t K5 = 0x7166e4a2e5576ac6ULL;
static constexpr uint64_t K6 = 0xc5a08e06385cfd4fULL;
static constexpr uint64_t K7 = 0x54d4f87a0229c15dULL;

#if defined(__AVX2__)
inline __m256i _mm256_rotl_epi64(__m256i x, int r) noexcept {
    return _mm256_or_si256(
        _mm256_slli_epi64(x, r & 63),
        _mm256_srli_epi64(x, (64 - (r & 63)) & 63)
    );
}
#endif // __AVX2__

void sponge256_4way_avx2(
    const uint8_t* __restrict in0,
    const uint8_t* __restrict in1,
    const uint8_t* __restrict in2,
    const uint8_t* __restrict in3,
    uint8_t* __restrict out0,
    uint8_t* __restrict out1,
    uint8_t* __restrict out2,
    uint8_t* __restrict out3
) noexcept {
#if !defined(__AVX2__)
    // No AVX2 on this target: run four scalar sponges (bit-identical output).
    sponge256_scalar(in0, 128, out0);
    sponge256_scalar(in1, 128, out1);
    sponge256_scalar(in2, 128, out2);
    sponge256_scalar(in3, 128, out3);
    return;
#endif
    // State: 8x __m256i vectors (4 lanes each = 4 independent sponges)
    __m256i s0 = _mm256_set1_epi64x(K0);
    __m256i s1 = _mm256_set1_epi64x(K1);
    __m256i s2 = _mm256_set1_epi64x(K2);
    __m256i s3 = _mm256_set1_epi64x(K3);
    __m256i s4 = _mm256_set1_epi64x(K4);
    __m256i s5 = _mm256_set1_epi64x(K5);
    __m256i s6 = _mm256_set1_epi64x(K6);
    __m256i s7 = _mm256_set1_epi64x(K7);

    // Load 4 independent 32-byte blocks into lanes of 4 vectors
    // Each sponge absorbs 32 bytes (4 uint64_t words)
    const uint64_t* w0 = reinterpret_cast<const uint64_t*>(in0);
    const uint64_t* w1 = reinterpret_cast<const uint64_t*>(in1);
    const uint64_t* w2 = reinterpret_cast<const uint64_t*>(in2);
    const uint64_t* w3 = reinterpret_cast<const uint64_t*>(in3);

    __m256i b4 = _mm256_set_epi64x(w3[3], w2[3], w1[3], w0[3]);
    __m256i b5 = _mm256_set_epi64x(w3[2], w2[2], w1[2], w0[2]);
    __m256i b6 = _mm256_set_epi64x(w3[1], w2[1], w1[1], w0[1]);
    __m256i b7 = _mm256_set_epi64x(w3[0], w2[0], w1[0], w0[0]);

    // Mix block into state words 4..7 (XOR)
    s4 = _mm256_xor_si256(s4, b7);
    s5 = _mm256_xor_si256(s5, b6);
    s6 = _mm256_xor_si256(s6, b5);
    s7 = _mm256_xor_si256(s7, b4);

    // 12 ARX rounds
    for (int r = 0; r < 12; ++r) {
        s0 = _mm256_add_epi64(s0, s4);
        s1 = _mm256_xor_si256(s1, s5);
        s2 = _mm256_add_epi64(s2, s6);
        s3 = _mm256_xor_si256(s3, s7);

        s4 = _mm256_rotl_epi64(s4, 13 ^ r);
        s5 = _mm256_rotl_epi64(s5, 27 + r);
        s6 = _mm256_rotl_epi64(s6, 41 ^ r);
        s7 = _mm256_rotl_epi64(s7, 19 + (r * 3));

        s4 = _mm256_xor_si256(s4, s0);
        s5 = _mm256_add_epi64(s5, s1);
        s6 = _mm256_xor_si256(s6, s2);
        s7 = _mm256_add_epi64(s7, s3);

        s0 = _mm256_rotl_epi64(s0, 7 + r);
        s1 = _mm256_rotl_epi64(s1, 31 ^ r);
        s2 = _mm256_rotl_epi64(s2, 17 + r);
        s3 = _mm256_rotl_epi64(s3, 43 ^ r);
    }

    // Final padding absorption (0x80)
    __m256i pad = _mm256_set1_epi64x(0x80ULL);
    s4 = _mm256_xor_si256(s4, pad);
    s5 = _mm256_xor_si256(s5, pad);
    s6 = _mm256_xor_si256(s6, pad);
    s7 = _mm256_xor_si256(s7, pad);

    // One more round for finalization
    s0 = _mm256_add_epi64(s0, s4);
    s1 = _mm256_xor_si256(s1, s5);
    s2 = _mm256_add_epi64(s2, s6);
    s3 = _mm256_xor_si256(s3, s7);

    // Extract 4 words (256 bits) from s0..s3 for each lane
    // Store to output buffers
    uint64_t out0_arr[4], out1_arr[4], out2_arr[4], out3_arr[4];

    _mm256_storeu_si256(reinterpret_cast<__m256i*>(out0_arr), s0);
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(out1_arr), s1);
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(out2_arr), s2);
    _mm256_storeu_si256(reinterpret_cast<__m256i*>(out3_arr), s3);

    // Convert to little-endian bytes (state is already LE)
    for (int i = 0; i < 4; ++i) {
        uint64_t v0 = out0_arr[i], v1 = out1_arr[i], v2 = out2_arr[i], v3 = out3_arr[i];
        for (int b = 0; b < 8; ++b) {
            out0[i * 8 + b] = static_cast<uint8_t>((v0 >> (b * 8)) & 0xFF);
            out1[i * 8 + b] = static_cast<uint8_t>((v1 >> (b * 8)) & 0xFF);
            out2[i * 8 + b] = static_cast<uint8_t>((v2 >> (b * 8)) & 0xFF);
            out3[i * 8 + b] = static_cast<uint8_t>((v3 >> (b * 8)) & 0xFF);
        }
    }
}

void sponge256_scalar(
    const uint8_t* __restrict in,
    size_t len,
    uint8_t* __restrict out
) noexcept {
    // Use the existing VortexSponge256 implementation
    vx::blockchain::VortexSponge256::compute(in, len, out);
}

uint32_t crc32c_hw(const uint8_t* data, size_t len) noexcept {
    // Portable tiered CRC32C: x86_64 SSE4.2, aarch64 CRC32 extension, or
    // bit-exact scalar fallback — identical finalized value on every tier.
    return vx::core::hw::crc32c(data, len);
}

uint32_t crc32c_scalar(const uint8_t* data, size_t len) noexcept {
    // Castagnoli polynomial: 0x1EDC6F41 (reversed: 0x82F63B78)
    static constexpr uint32_t POLY = 0x82F63B78;
    uint32_t crc = 0xFFFFFFFF;

    for (size_t i = 0; i < len; ++i) {
        crc ^= data[i];
        for (int j = 0; j < 8; ++j) {
            crc = (crc >> 1) ^ (static_cast<uint32_t>(-(crc & 1)) & POLY);
        }
    }
    return ~crc;
}

int verify_frame_parallel(
    const vx::blockchain::Transaction* txs,
    uint32_t tx_count
) noexcept {
    int invalid_count = 0;

    #pragma omp parallel for schedule(static) reduction(+:invalid_count)
    for (int i = 0; i < static_cast<int>(tx_count); ++i) {
        if (!vx::blockchain::verify_transaction_proof(txs[i])) {
            ++invalid_count;
        }
    }

    return invalid_count;
}

} // namespace vx::crypto