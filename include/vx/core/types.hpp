#pragma once

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <span>
#include <concepts>
#include <gmpxx.h>

namespace vx::core {

// Alignment to standard CPU cache line (64 bytes)
inline constexpr size_t CACHE_LINE_SIZE = 64;

// 1024-bit Golden Phi Fractional Expansion limbs (16 x uint64 = 1024 bits)
inline constexpr std::array<uint64_t, 16> PHI_1024_WORDS {
    0x9e3779b97f4a7c15ULL, 0xf39cc0605cedc834ULL, 0x1082276bf3a27251ULL, 0xf86c6a11d0c18e95ULL,
    0x276707e7869666c0ULL, 0x7166e4a2e5576ac6ULL, 0xc5a08e06385cfd4fULL, 0x54d4f87a0229c15dULL,
    0x3459c36c6e7804eeULL, 0x9e54d688cf861f22ULL, 0xe70c5717e4a83ec0ULL, 0x22513f8d3886f443ULL,
    0xe46cf295f7ef0a88ULL, 0x7a0acb2f56747eb1ULL, 0x0013892790757a79ULL, 0x6a40a34a810842e4ULL
};

inline constexpr uint64_t GOLDEN_PHI_64 = 0x9E3779B97F4A7C15ULL;

inline constexpr std::string_view PHI_1024_HEX = 
    "9e3779b97f4a7c15f39cc0605cedc8341082276bf3a27251f86c6a11d0c18e95"
    "276707e7869666c07166e4a2e5576ac6c5a08e06385cfd4f54d4f87a0229c15d"
    "3459c36c6e7804ee9e54d688cf861f22e70c5717e4a83ec022513f8d3886f443"
    "e46cf295f7ef0a887a0acb2f56747eb10013892790757a796a40a34a810842e4";

// 256-bit hash representation
using Hash256 = std::array<uint8_t, 32>;

// 1024-bit raw byte block (128 bytes)
using ByteBlock1024 = std::array<uint8_t, 128>;

// 2048-bit raw byte block (256 bytes)
using ByteBlock2048 = std::array<uint8_t, 256>;

/**
 * @brief Represents coordinate state in the 3-Trunk attractor field.
 */
struct alignas(CACHE_LINE_SIZE) AttractorCoordinates {
    mpz_class x;
    mpz_class y;
    mpz_class z;
};

/**
 * @brief Dynamic moduli parameters for the 3 Galois field barrels.
 */
struct AttractorModuli {
    mpz_class p; // MOD_P = 2^1024 - 2^64 - 1397
    mpz_class q; // MOD_Q = 2^1024 - 2^888 - 105
    mpz_class r; // MOD_R = 2^1024 - 2^512 - 265049
    std::string label;

    static AttractorModuli secure_crt() {
        mpz_class one = 1;
        return AttractorModuli{
            .p = (one << 1024) - (one << 64) - 1747,
            .q = (one << 1024) - (one << 888) - 3943,
            .r = (one << 1024) - (one << 512) - 267799,
            .label = "Secure CRT-Optimized Moduli (Prime-Proven)"
        };
    }

    static AttractorModuli classic() {
        mpz_class one = 1;
        return AttractorModuli{
            .p = (one << 1024) - (one << 64) - 1397,
            .q = (one << 1024) - (one << 888) - 105,
            .r = (one << 1024) - (one << 512) - 265049,
            .label = "Classic Attractor Moduli"
        };
    }

    static AttractorModuli active_default() {
        return secure_crt();
    }
};

} // namespace vx::core
