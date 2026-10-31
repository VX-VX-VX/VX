#pragma once

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

namespace vx::core {

/**
 * @brief Portable unsigned 128-bit integer (two 64-bit limbs, no compiler
 * extensions) for native atomic balances. Avoids __int128 so the code stays
 * clean under -Wpedantic / strict -std=c++26.
 */
struct U128 {
    uint64_t lo = 0;
    uint64_t hi = 0;

    constexpr U128() = default;
    constexpr U128(uint64_t v) noexcept : lo(v), hi(0) {}
    constexpr U128(uint64_t l, uint64_t h) noexcept : lo(l), hi(h) {}

    static U128 from_le_bytes(const uint8_t a[16]) noexcept {
        uint64_t lo = 0, hi = 0;
        for (int i = 7; i >= 0; --i)  lo = (lo << 8) | a[i];
        for (int i = 15; i >= 8; --i) hi = (hi << 8) | a[i];
        return {lo, hi};
    }

    void to_le_bytes(uint8_t a[16]) const noexcept {
        uint64_t l = lo;
        for (int i = 0; i < 8; ++i) { a[i] = static_cast<uint8_t>(l & 0xFF); l >>= 8; }
        uint64_t h = hi;
        for (int i = 8; i < 16; ++i) { a[i] = static_cast<uint8_t>(h & 0xFF); h >>= 8; }
    }

    constexpr bool is_zero() const noexcept { return lo == 0 && hi == 0; }
    constexpr bool operator==(const U128&) const = default;

    friend constexpr bool operator<(const U128& x, const U128& y) noexcept {
        return x.hi == y.hi ? x.lo < y.lo : x.hi < y.hi;
    }
    friend constexpr bool operator>=(const U128& x, const U128& y) noexcept { return !(x < y); }
    friend constexpr bool operator>(const U128& x, const U128& y) noexcept { return y < x; }
    friend constexpr bool operator<=(const U128& x, const U128& y) noexcept { return !(y < x); }

    constexpr U128 operator+(U128 o) const noexcept {
        uint64_t l = lo + o.lo;
        uint64_t carry = (l < lo) ? 1u : 0u;
        return {l, hi + o.hi + carry};
    }

    // Requires *this >= o (pre-checked by ledger balance verification).
    constexpr U128 operator-(U128 o) const noexcept {
        uint64_t l = lo - o.lo;
        uint64_t borrow = (lo < o.lo) ? 1u : 0u;
        return {l, hi - o.hi - borrow};
    }

    constexpr U128 operator/(U128 o) const noexcept {
        // Simple division for small divisors (o <= 2^63)
        // For full 128/128 division, would need more complex algorithm
        // This handles the common case of dividing by small numbers like 2
        if (o.hi == 0 && o.lo > 0) {
            uint64_t rem;
            return div64(*this, o.lo, rem);
        }
        // Fallback for general case (not used in our code)
        return U128{0, 0};
    }

    constexpr U128 operator/(uint64_t d) const noexcept {
        uint64_t rem;
        return div64(*this, d, rem);
    }

    /**
     * @brief 128-bit / 64-bit long division. Requires d < 2^63 (single-pass
     * remainder invariant). Used only for decimal formatting and VX units.
     */
    static U128 div64(U128 v, uint64_t d, uint64_t& rem) noexcept {
        U128 q{0, 0};
        uint64_t r = 0;
        for (int i = 127; i >= 0; --i) {
            uint64_t bit = (i >= 64) ? ((v.hi >> (i - 64)) & 1u) : ((v.lo >> i) & 1u);
            r = (r << 1) | bit;
            if (r >= d) {
                r -= d;
                if (i >= 64) q.hi |= (1ull << (i - 64));
                else         q.lo |= (1ull << i);
            }
        }
        rem = r;
        return q;
    }

    std::string to_string() const {
        if (hi == 0) return std::to_string(lo);
        static constexpr uint64_t BASE = 1000000000000000000ull; // 10^18 < 2^63 ✓
        std::vector<uint64_t> parts;
        U128 v = *this;
        while (!v.is_zero()) {
            uint64_t rem;
            v = div64(v, BASE, rem);
            parts.push_back(rem);
        }
        std::string out = std::to_string(parts.back());
        for (size_t i = parts.size() - 1; i-- > 0;) {
            std::string chunk = std::to_string(parts[i]);
            out += std::string(18 - chunk.length(), '0') + chunk;
        }
        return out;
    }
};

} // namespace vx::core
