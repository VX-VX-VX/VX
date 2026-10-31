#pragma once

// ── VX portable hardware intrinsics ──────────────────────────────────────────
// Three tiers, resolved at compile time:
//   1. x86_64 / MSVC-x64 : __rdtsc, _mm_clflush, SSE4.2 CRC32C
//   2. aarch64           : cntvct_el0 counter, __builtin___clear_cache,
//                          CRC32 ARMv8 instructions (optional, runtime-safe
//                          via __ARM_FEATURE_CRC32)
//   3. fallback          : std::chrono::steady_clock cycle estimate,
//                          atomic_thread_fence clobber, scalar CRC32C
//
// Everything is inline; no TUs other than this header are needed.

#include <cstdint>
#include <cstddef>
#include <cstring>
#include <chrono>
#include <atomic>

#if defined(_M_X64) || defined(__x86_64__)
#   define VX_HW_X86_64 1
#   include <x86intrin.h>
#elif defined(__aarch64__) || defined(_M_ARM64)
#   define VX_HW_AARCH64 1
#   if defined(__ARM_FEATURE_CRC32)
#       include <arm_acle.h>
#   endif
#endif

namespace vx::core::hw {

// ── Cycle counter ────────────────────────────────────────────────────────────

/// Monotonic hardware cycle counter where available (x86: TSC; ARM64: virtual
/// counter), otherwise a steady-clock nanosecond estimate. Cycle values are
/// only comparable within one process and one tier.
[[nodiscard]] inline uint64_t cycle_counter() noexcept {
#if defined(VX_HW_X86_64)
    return __rdtsc();
#elif defined(VX_HW_AARCH64)
    uint64_t v;
    asm volatile("mrs %0, cntvct_el0" : "=r"(v) ::);
    return v;
#else
    return static_cast<uint64_t>(
        std::chrono::duration_cast<std::chrono::nanoseconds>(
            std::chrono::steady_clock::now().time_since_epoch()).count());
#endif
}

/// Small epsilon appended to fallback-delta zeros so profilers never record
/// a zero cycle count on the chrono tier. Meaningless on real cycle tiers.
[[nodiscard]] inline constexpr uint64_t cycle_floor() noexcept {
#if defined(VX_HW_X86_64) || defined(VX_HW_AARCH64)
    return 0;
#else
    return 1;
#endif
}

// ── Cache-line flush ─────────────────────────────────────────────────────────

/// Evicts one cache line (64-byte aligned address) from all CPU cache levels.
/// On the fallback tier this degrades to a compiler + CPU fence: the data
/// still leaves the store buffer, though no explicit eviction happens.
inline void flush_cache_line(const void* p) noexcept {
#if defined(VX_HW_X86_64)
    _mm_clflush(p);
    asm volatile("" ::: "memory");
#elif defined(VX_HW_AARCH64)
    // No per-line user-mode eviction on aarch64; the architectural cache
    // maintenance intrinsic covers the whole range for the address region.
    (void)p;
    __builtin___clear_cache(reinterpret_cast<char*>(const_cast<void*>(p)),
                            reinterpret_cast<char*>(const_cast<void*>(p)) + 64);
    std::atomic_thread_fence(std::memory_order_seq_cst);
#else
    (void)p;
    std::atomic_thread_fence(std::memory_order_seq_cst);
    asm volatile("" ::: "memory");
#endif
}

/// Flush [p, p+len) cache lines (step 64 bytes, clflush semantics).
inline void flush_cache_range(const void* p, size_t len) noexcept {
    const uint8_t* base = static_cast<const uint8_t*>(p);
#if defined(VX_HW_X86_64)
    for (size_t i = 0; i < len; i += 64) {
        _mm_clflush(static_cast<const void*>(base + i));
    }
    asm volatile("" ::: "memory");
#elif defined(VX_HW_AARCH64)
    __builtin___clear_cache(
        reinterpret_cast<char*>(const_cast<uint8_t*>(base)),
        reinterpret_cast<char*>(const_cast<uint8_t*>(base + len)));
    std::atomic_thread_fence(std::memory_order_seq_cst);
#else
    (void)base;
    std::atomic_thread_fence(std::memory_order_seq_cst);
    asm volatile("" ::: "memory");
#endif
}

// ── CRC32C (Castagnoli 0x1EDC6F41, reflected 0x82F63B78) ────────────────────

/// Hardware CRC32C running seed state. Seed must start at 0xFFFFFFFF.
namespace detail {

[[nodiscard]] inline uint32_t crc32c_scalar_update(
    uint32_t crc, const uint8_t* data, size_t len) noexcept {
    // Reflected Castagnoli polynomial, bitwise (no division, no tables).
    while (len--) {
        crc ^= *data++;
        for (int k = 0; k < 8; ++k) {
            crc = (crc >> 1) ^ (0x82F63B78u & (0u - (crc & 1u)));
        }
    }
    return crc;
}

} // namespace detail

/// One-shot CRC32C over [data, data+len). Returns the finalized value
/// (post-complement), matching the existing call sites' semantics.
[[nodiscard]] inline uint32_t crc32c(const uint8_t* data, size_t len) noexcept {
    uint32_t crc = 0xFFFFFFFFu;
#if defined(VX_HW_X86_64) && defined(__SSE4_2__)
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        uint64_t word;
        std::memcpy(&word, data + i, 8);
        crc = _mm_crc32_u64(crc, word);
    }
    if (i + 4 <= len) {
        uint32_t word;
        std::memcpy(&word, data + i, 4);
        crc = _mm_crc32_u32(crc, word);
        i += 4;
    }
    for (; i < len; ++i) {
        crc = _mm_crc32_u8(crc, data[i]);
    }
    return static_cast<uint32_t>(~crc);
#elif defined(VX_HW_AARCH64) && defined(__ARM_FEATURE_CRC32)
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        uint64_t word;
        std::memcpy(&word, data + i, 8);
        crc = __crc32cd(crc, word);
    }
    for (; i < len; ++i) {
        crc = __crc32cb(crc, data[i]);
    }
    return static_cast<uint32_t>(~crc);
#else
    crc = detail::crc32c_scalar_update(crc, data, len);
    return static_cast<uint32_t>(~crc);
#endif
}

/// Streaming CRC32C update for call sites that feed a running state.
/// Pass crc in raw (uncomplemented) form; finalize with crc32c_finalize.
[[nodiscard]] inline uint32_t crc32c_update(uint32_t raw_crc,
                                            const uint8_t* data,
                                            size_t len) noexcept {
#if defined(VX_HW_X86_64) && defined(__SSE4_2__)
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        uint64_t word;
        std::memcpy(&word, data + i, 8);
        raw_crc = _mm_crc32_u64(raw_crc, word);
    }
    if (i + 4 <= len) {
        uint32_t word;
        std::memcpy(&word, data + i, 4);
        raw_crc = _mm_crc32_u32(raw_crc, word);
        i += 4;
    }
    for (; i < len; ++i) {
        raw_crc = _mm_crc32_u8(raw_crc, data[i]);
    }
    return raw_crc;
#elif defined(VX_HW_AARCH64) && defined(__ARM_FEATURE_CRC32)
    size_t i = 0;
    for (; i + 8 <= len; i += 8) {
        uint64_t word;
        std::memcpy(&word, data + i, 8);
        raw_crc = __crc32cd(raw_crc, word);
    }
    for (; i < len; ++i) {
        raw_crc = __crc32cb(raw_crc, data[i]);
    }
    return raw_crc;
#else
    return detail::crc32c_scalar_update(raw_crc, data, len);
#endif
}

[[nodiscard]] inline constexpr uint32_t crc32c_finalize(uint32_t raw_crc) noexcept {
    return ~raw_crc;
}

/// Single-word CRC32C mixing primitive (raw state in/out). Semantically the
/// standard reflected CRC32C update over the 8 little-endian bytes of `word`;
/// on x86_64 this is exactly _mm_crc32_u64, on aarch64+CRC32 __crc32cd.
[[nodiscard]] inline uint32_t crc32c_word_update(uint32_t raw_crc,
                                                 uint64_t word) noexcept {
#if defined(VX_HW_X86_64) && defined(__SSE4_2__)
    return static_cast<uint32_t>(_mm_crc32_u64(raw_crc, word));
#elif defined(VX_HW_AARCH64) && defined(__ARM_FEATURE_CRC32)
    return __crc32cd(raw_crc, word);
#else
    uint8_t bytes[8];
    std::memcpy(bytes, &word, 8);
    return detail::crc32c_scalar_update(raw_crc, bytes, 8);
#endif
}

/// Single-byte CRC32C update (raw state in/out). x86: _mm_crc32_u8,
/// aarch64+CRC32: __crc32cb, fallback: bitwise scalar step.
[[nodiscard]] inline uint32_t crc32c_byte_update(uint32_t raw_crc,
                                                 uint8_t byte) noexcept {
#if defined(VX_HW_X86_64) && defined(__SSE4_2__)
    return _mm_crc32_u8(raw_crc, byte);
#elif defined(VX_HW_AARCH64) && defined(__ARM_FEATURE_CRC32)
    return __crc32cb(raw_crc, byte);
#else
    return detail::crc32c_scalar_update(raw_crc, &byte, 1);
#endif
}

} // namespace vx::core::hw
