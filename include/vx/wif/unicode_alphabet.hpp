#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// GENERATED TABLE — do not edit by hand. The enumeration below is the FULL
// Unicode scalar-value range U+0000..U+10FFF0 filtered per the rules that
// follow; it is checked exhaustively by the WIF roundtrip tests.
//
// The FULL Unicode alphabet: every valid Unicode scalar value in
// U+0000..U+10FFFF except surrogates (D800..DFFF), C0/C1 controls and
// noncharacters (FDD0..FDEF, xFFFE/xFFFF). Private-use, assigned and
// unassigned planes are all included — every character that can be a symbol
// is a symbol. Each one is a digit of the VX compact rune base.
//
// Alphabet size: 1111933 symbols over 20 contiguous ranges.
// Bits per symbol: 20.0846 — a 2048-bit key encodes in 102 runes.
// ─────────────────────────────────────────────────────────────────────────────

#include <array>
#include <cstddef>
#include <cstdint>
#include <string_view>
#include <string>

namespace vx::wif {

struct UnicodeRange {
    uint32_t first;
    uint32_t last;
};

// Contiguous code-point ranges of the full alphabet, ascending.
// Entries are typed (UnicodeRange{...}) — GCC 16 rejects brace-elided
// inner aggregates for std::array members.
inline constexpr std::array<UnicodeRange, 20> kUnicodeRanges = {
    UnicodeRange{0x000020u, 0x00007Eu},
    UnicodeRange{0x0000A0u, 0x00D7FFu},
    UnicodeRange{0x00E000u, 0x00FDCFu},
    UnicodeRange{0x00FDF0u, 0x00FFFDu},
    UnicodeRange{0x010000u, 0x01FFFDu},
    UnicodeRange{0x020000u, 0x02FFFDu},
    UnicodeRange{0x030000u, 0x03FFFDu},
    UnicodeRange{0x040000u, 0x04FFFDu},
    UnicodeRange{0x050000u, 0x05FFFDu},
    UnicodeRange{0x060000u, 0x06FFFDu},
    UnicodeRange{0x070000u, 0x07FFFDu},
    UnicodeRange{0x080000u, 0x08FFFDu},
    UnicodeRange{0x090000u, 0x09FFFDu},
    UnicodeRange{0x0A0000u, 0x0AFFFDu},
    UnicodeRange{0x0B0000u, 0x0BFFFDu},
    UnicodeRange{0x0C0000u, 0x0CFFFDu},
    UnicodeRange{0x0D0000u, 0x0DFFFDu},
    UnicodeRange{0x0E0000u, 0x0EFFFDu},
    UnicodeRange{0x0F0000u, 0x0FFFFDu},
    UnicodeRange{0x100000u, 0x10FFFDu},

};

// Total number of symbols in the full Unicode alphabet.
inline constexpr uint64_t kUnicodeAlphabetSize = 1111933u;

inline constexpr bool unicode_cp_valid(uint32_t cp) noexcept {
    return cp <= 0x10FFFF
        && !((cp >= 0xD800) && (cp <= 0xDFFF))                 // surrogates
        && !(cp <= 0x001F || cp == 0x007F ||                   // C0 + DEL
             (cp >= 0x0080 && cp <= 0x009F))                   // C1
        && !(cp >= 0xFDD0 && cp <= 0xFDEF)                     // nonchars
        && !(((cp & 0xFFFF) == 0xFFFE) || ((cp & 0xFFFF) == 0xFFFF));
}

// Bijective index -> code point (the alphabet, in ascending order).
inline uint32_t unicode_cp_from_index(uint64_t idx) noexcept {
    uint64_t remaining = idx;
    for (const auto& r : kUnicodeRanges) {
        const uint64_t span = uint64_t(r.last) - r.first + 1;
        if (remaining < span) return r.first + static_cast<uint32_t>(remaining);
        remaining -= span;
    }
    return 0; // out of range (caller must keep idx < kUnicodeAlphabetSize)
}

// Bijective code point -> index; returns SIZE_MAX when cp is not a symbol.
inline uint64_t unicode_index_from_cp(uint32_t cp) noexcept {
    if (!unicode_cp_valid(cp)) return static_cast<uint64_t>(-1);
    uint64_t idx = 0;
    for (const auto& r : kUnicodeRanges) {
        if (cp < r.first) return static_cast<uint64_t>(-1);
        if (cp <= r.last) return idx + (cp - r.first);
        idx += uint64_t(r.last) - r.first + 1;
    }
    return static_cast<uint64_t>(-1);
}

// UTF-8 encode one scalar value; appends to `out`.
inline void unicode_utf8_append(std::string& out, uint32_t cp) {
    if (cp <= 0x7F) {
        out.push_back(static_cast<char>(cp));
    } else if (cp <= 0x7FF) {
        out.push_back(static_cast<char>(0xC0 | (cp >> 6)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else if (cp <= 0xFFFF) {
        out.push_back(static_cast<char>(0xE0 | (cp >> 12)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    } else {
        out.push_back(static_cast<char>(0xF0 | (cp >> 18)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 12) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | ((cp >> 6) & 0x3F)));
        out.push_back(static_cast<char>(0x80 | (cp & 0x3F)));
    }
}

// UTF-8 decode one scalar value starting at `pos`; advances `pos` past it.
// Returns UINT32_MAX on malformed input (kept as a value, not an exception,
// so decoders can stay noexcept).
inline uint32_t unicode_utf8_next(std::string_view s, size_t& pos) noexcept {
    if (pos >= s.size()) return UINT32_MAX;
    const auto b0 = static_cast<uint8_t>(s[pos]);
    if (b0 < 0x80) { ++pos; return b0; }
    const auto cont = [&s, &pos](size_t i) -> int {
        if (i >= s.size()) return -1;
        const auto b = static_cast<uint8_t>(s[i]);
        return (b & 0xC0) == 0x80 ? (b & 0x3F) : -1;
    };
    if ((b0 & 0xE0) == 0xC0) {
        const int c1 = cont(pos + 1);
        if (c1 < 0) return UINT32_MAX;
        const uint32_t cp = (uint32_t(b0 & 0x1F) << 6) | uint32_t(c1);
        pos += 2;
        return cp < 0x80 ? UINT32_MAX : cp; // reject overlong
    }
    if ((b0 & 0xF0) == 0xE0) {
        const int c1 = cont(pos + 1), c2 = cont(pos + 2);
        if (c1 < 0 || c2 < 0) return UINT32_MAX;
        const uint32_t cp = (uint32_t(b0 & 0x0F) << 12) | (uint32_t(c1) << 6) | uint32_t(c2);
        pos += 3;
        return (cp < 0x800 || (cp >= 0xD800 && cp <= 0xDFFF)) ? UINT32_MAX : cp;
    }
    if ((b0 & 0xF8) == 0xF0) {
        const int c1 = cont(pos + 1), c2 = cont(pos + 2), c3 = cont(pos + 3);
        if (c1 < 0 || c2 < 0 || c3 < 0) return UINT32_MAX;
        const uint32_t cp = (uint32_t(b0 & 0x07) << 18) | (uint32_t(c1) << 12)
                          | (uint32_t(c2) << 6) | uint32_t(c3);
        pos += 4;
        return (cp < 0x10000 || cp > 0x10FFFF) ? UINT32_MAX : cp;
    }
    return UINT32_MAX;
}

// Number of 2048-bit key runes in the compact formats.
inline constexpr uint64_t kUnicodeKeyRunes = 102u;

} // namespace vx::wif
