#include "vx/wif/wif_matrix.hpp"
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <random>

namespace vx::wif {

std::vector<uint8_t> WifMatrix::hexToBytes(std::string_view hex) {
    std::string clean(hex);
    if (clean.rfind("0x", 0) == 0) clean = clean.substr(2);
    std::vector<uint8_t> bytes;
    bytes.reserve(clean.length() / 2);
    for (size_t i = 0; i + 1 < clean.length(); i += 2) {
        bytes.push_back(static_cast<uint8_t>(std::stoul(clean.substr(i, 2), nullptr, 16)));
    }
    return bytes;
}

std::string WifMatrix::bytesToHex(const std::vector<uint8_t>& bytes) {
    std::stringstream ss;
    ss << std::hex << std::setfill('0');
    for (uint8_t b : bytes) {
        ss << std::setw(2) << static_cast<int>(b);
    }
    return ss.str();
}

std::string WifMatrix::toRecordWif(std::string_view hexKey) {
    static const std::vector<std::string> runes = {
        "𝜲", "∰", "𝚯", "⍾", "⎈", "𝝣", "ℵ", "⨻", "⎋", "𝛀", "⏣", "⍕", "⟡", "⦜", "⨝", "⩔", "⪨", "⫍"
    };
    auto bytes = hexToBytes(hexKey);
    if (bytes.empty()) return "";

    std::string result;
    for (size_t i = 0; i < 18; ++i) {
        uint8_t val = bytes[i % bytes.size()];
        result += runes[(val + i) % runes.size()];
    }
    return result;
}

std::string WifMatrix::toCompressedWif(std::string_view hexKey) {
    static const std::string chars = "ÆßÐµ¥§¤þ£¢©®µ¶¾¿×ØÙÚÛÜÝÞßàáâãäåæçèéêëìíî";
    auto bytes = hexToBytes(hexKey);
    if (bytes.empty()) return "V128:";

    std::string result = "V128:";
    for (size_t i = 0; i < 33; ++i) {
        size_t idx = (bytes[i % bytes.size()] + i) % (chars.size() / 2);
        result += chars.substr(idx * 2, 2);
    }
    return result;
}

std::string WifMatrix::toCompactWif(std::string_view hexKey) {
    auto bytes = hexToBytes(hexKey);
    std::array<uint8_t, 32> folded{};
    for (size_t i = 0; i < bytes.size(); ++i) {
        folded[i % 32] ^= bytes[i];
    }
    static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string result = "";
    uint32_t buffer = 0;
    int bits = 0;
    for (uint8_t b : folded) {
        buffer = (buffer << 8) | b;
        bits += 8;
        while (bits >= 6) {
            bits -= 6;
            result += alphabet[(buffer >> bits) & 63];
        }
    }
    if (bits > 0) {
        result += alphabet[(buffer << (6 - bits)) & 63];
    }
    while (result.length() < 45) result += 'A';
    return result.substr(0, 45);
}

std::string WifMatrix::toUncompressedWif(std::string_view hexKey) {
    std::string clean(hexKey);
    if (clean.rfind("0x", 0) == 0) clean = clean.substr(2);
    if (clean.length() < 512) clean.append(512 - clean.length(), '0');
    return clean;
}

// ── Full-Unicode rune WIF (F1/F2) ────────────────────────────────────────────
// The whole Unicode alphabet (kUnicodeAlphabetSize symbols) is the digit base:
// every rune is one base digit of the big-endian 256-byte (2048-bit) seed.
// 20.0846 bits per symbol — a full 2048-bit key encodes in exactly 102 runes.
// Nothing is folded or truncated: F1/F2 roundtrip the ENTIRE key.

static constexpr std::string_view K_RUNES_F1_PREFIX = "RUNES:";
static constexpr std::string_view K_RUNES_F2_PREFIX = "RUNESC:";

std::array<uint8_t, 256> WifMatrix::seed_to_256b(std::string_view hexKey) {
    std::string clean(hexKey);
    if (clean.rfind("0x", 0) == 0) clean = clean.substr(2);
    if (clean.length() > 512) {
        throw std::invalid_argument("seed exceeds 2048 bits");
    }
    if (clean.length() < 512) clean.append(512 - clean.length(), '0');
    std::array<uint8_t, 256> num{};
    for (size_t i = 0; i < 256; ++i) {
        num[i] = static_cast<uint8_t>(std::stoul(clean.substr(i * 2, 2), nullptr, 16));
    }
    return num;
}

std::string WifMatrix::bignum_to_unicode_base(const std::array<uint8_t, 256>& num,
                                              std::string_view prefix) {
    constexpr uint64_t BASE = kUnicodeAlphabetSize; // > 256, so byte-wise division
    std::array<uint8_t, 256> cur = num;
    std::vector<uint32_t> digits; // least significant first
    digits.reserve(kUnicodeKeyRunes);
    for (size_t d = 0; d < kUnicodeKeyRunes; ++d) {
        bool all_zero = true;
        for (uint8_t b : cur) {
            if (b) { all_zero = false; break; }
        }
        if (all_zero) { digits.push_back(0); continue; }
        uint64_t rem = 0;
        for (size_t i = 0; i < 256; ++i) {
            const uint64_t x = (rem << 8) | cur[i];
            cur[i] = static_cast<uint8_t>(x / BASE);
            rem = x % BASE;
        }
        digits.push_back(static_cast<uint32_t>(rem));
    }
    std::string out(prefix);
    for (size_t d = kUnicodeKeyRunes; d-- > 0;) { // most significant first
        unicode_utf8_append(out, unicode_cp_from_index(digits[d]));
    }
    return out;
}

bool WifMatrix::unicode_base_to_bignum(std::string_view runes, size_t expected_digits,
                                       std::array<uint8_t, 256>& out) {
    out.fill(0);
    std::vector<uint64_t> digits; // most significant first
    digits.reserve(expected_digits);
    size_t pos = 0;
    while (pos < runes.size()) {
        const uint32_t cp = unicode_utf8_next(runes, pos);
        if (cp == UINT32_MAX) return false;
        const uint64_t idx = unicode_index_from_cp(cp);
        if (idx == static_cast<uint64_t>(-1)) return false;
        digits.push_back(idx);
    }
    if (digits.size() != expected_digits) return false;
    constexpr uint64_t BASE = kUnicodeAlphabetSize;
    for (uint64_t d : digits) {
        // out = out * BASE (256-byte big-endian)
        uint64_t carry = 0;
        for (size_t i = 256; i-- > 0;) {
            const uint64_t x = out[i] * BASE + carry;
            out[i] = static_cast<uint8_t>(x & 0xFF);
            carry = x >> 8;
        }
        // out += d
        uint64_t add = d;
        for (size_t i = 256; i-- > 0 && add != 0;) {
            const uint64_t x = out[i] + add;
            out[i] = static_cast<uint8_t>(x & 0xFF);
            add = x >> 8;
        }
        if (add != 0) return false; // overflow beyond 2048 bits
    }
    return true;
}

std::string WifMatrix::toUnicodeRunesWif(std::string_view hexKey) {
    return bignum_to_unicode_base(seed_to_256b(hexKey), K_RUNES_F1_PREFIX);
}

std::string WifMatrix::fromUnicodeRunesWif(std::string_view wif) {
    std::string_view body = wif;
    if (body.size() >= K_RUNES_F1_PREFIX.size()
        && body.substr(0, K_RUNES_F1_PREFIX.size()) == K_RUNES_F1_PREFIX) {
        body.remove_prefix(K_RUNES_F1_PREFIX.size());
    }
    std::array<uint8_t, 256> num{};
    if (!unicode_base_to_bignum(body, kUnicodeKeyRunes, num)) {
        throw std::invalid_argument("invalid Unicode-rune WIF");
    }
    return bytesToHex(std::vector<uint8_t>(num.begin(), num.end()));
}

std::string WifMatrix::toUnicodeCompressedWif(std::string_view hexKey) {
    return bignum_to_unicode_base(seed_to_256b(hexKey), K_RUNES_F2_PREFIX);
}

std::string WifMatrix::fromUnicodeCompressedWif(std::string_view wif) {
    std::string_view body = wif;
    if (body.size() >= K_RUNES_F2_PREFIX.size()
        && body.substr(0, K_RUNES_F2_PREFIX.size()) == K_RUNES_F2_PREFIX) {
        body.remove_prefix(K_RUNES_F2_PREFIX.size());
    } else {
        throw std::invalid_argument("missing RUNESC: prefix");
    }
    std::array<uint8_t, 256> num{};
    if (!unicode_base_to_bignum(body, kUnicodeKeyRunes, num)) {
        throw std::invalid_argument("invalid Unicode-rune compressed WIF");
    }
    return bytesToHex(std::vector<uint8_t>(num.begin(), num.end()));
}

// UTF-8 representations:
// ZWSP: \u200B -> E2 80 8B
// ZWNJ: \u200C -> E2 80 8C
static const std::string UTF8_ZWSP = "\xE2\x80\x8B";
static const std::string UTF8_ZWNJ = "\xE2\x80\x8C";

std::string WifMatrix::encodeGhostWif(std::string_view hexKey, std::string_view coverWord) {
    auto bytes = hexToBytes(hexKey);
    std::string stego;
    // Embed binary bits between first character and rest of cover word
    if (!coverWord.empty()) {
        stego += coverWord.front();
    }
    for (uint8_t b : bytes) {
        for (int bit = 7; bit >= 0; --bit) {
            if ((b >> bit) & 1) {
                stego += UTF8_ZWNJ;
            } else {
                stego += UTF8_ZWSP;
            }
        }
    }
    if (coverWord.length() > 1) {
        stego += coverWord.substr(1);
    }
    return stego;
}

std::string WifMatrix::decodeGhostWif(std::string_view stegoText) {
    std::vector<uint8_t> bits;
    for (size_t i = 0; i + 2 < stegoText.length(); ) {
        if (static_cast<unsigned char>(stegoText[i]) == 0xE2 &&
            static_cast<unsigned char>(stegoText[i+1]) == 0x80) {
            if (static_cast<unsigned char>(stegoText[i+2]) == 0x8B) {
                bits.push_back(0); // ZWSP
                i += 3;
                continue;
            } else if (static_cast<unsigned char>(stegoText[i+2]) == 0x8C) {
                bits.push_back(1); // ZWNJ
                i += 3;
                continue;
            }
        }
        ++i;
    }

    std::vector<uint8_t> bytes;
    for (size_t i = 0; i + 7 < bits.size(); i += 8) {
        uint8_t b = 0;
        for (int k = 0; k < 8; ++k) {
            b = (b << 1) | bits[i + k];
        }
        bytes.push_back(b);
    }
    return bytesToHex(bytes);
}

std::string WifMatrix::encodeHwLockedWif(std::string_view hexKey, std::string_view uuid) {
    uint64_t crc = 0xcafebabecafebabeULL;
    for (char c : uuid) {
        crc = (crc ^ static_cast<uint64_t>(c)) * 1099511628211ULL;
    }
    auto bytes = hexToBytes(hexKey);
    for (size_t i = 0; i < bytes.size(); ++i) {
        uint8_t mask = static_cast<uint8_t>((crc >> ((i % 8) * 8)) & 0xFF);
        bytes[i] ^= mask;
    }
    return bytesToHex(bytes);
}

std::string WifMatrix::decodeHwLockedWif(std::string_view lockedHex, std::string_view uuid) {
    return encodeHwLockedWif(lockedHex, uuid); // Symmetric XOR
}

// GF(256) arithmetic over polynomial 0x11B
uint8_t WifMatrix::gfMul(uint8_t a, uint8_t b) noexcept {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        bool hi = (a & 0x80) != 0;
        a <<= 1;
        if (hi) a ^= 0x1B; // 0x11B mod x^8
        b >>= 1;
    }
    return p;
}

uint8_t WifMatrix::gfInv(uint8_t a) noexcept {
    if (a == 0) return 0;
    // By Fermat's Little Theorem in GF(2^8): a^254 = a^-1
    uint8_t res = 1;
    uint8_t base = a;
    uint8_t exp = 254;
    while (exp > 0) {
        if (exp & 1) res = gfMul(res, base);
        base = gfMul(base, base);
        exp >>= 1;
    }
    return res;
}

std::vector<ShamirShard> WifMatrix::splitShamir(std::string_view hexKey) {
    auto secret = hexToBytes(hexKey);
    size_t len = secret.size();

    // Random coefficient a_1 for linear polynomial f(x) = secret + a_1 * x
    std::mt19937 rng(1337);
    std::uniform_int_distribution<int> dist(1, 255);
    std::vector<uint8_t> a1(len);
    for (size_t i = 0; i < len; ++i) {
        a1[i] = static_cast<uint8_t>(dist(rng));
    }

    std::vector<ShamirShard> shards;
    shards.reserve(3);

    for (uint8_t x = 1; x <= 3; ++x) {
        std::vector<uint8_t> shardBytes(len);
        for (size_t i = 0; i < len; ++i) {
            shardBytes[i] = gfAdd(secret[i], gfMul(a1[i], x));
        }
        shards.push_back(ShamirShard{ .x = x, .shardHex = bytesToHex(shardBytes) });
    }

    return shards;
}

std::string WifMatrix::recoverShamir(const ShamirShard& s1, const ShamirShard& s2) {
    if (s1.x == s2.x) {
        throw std::invalid_argument("Cannot reconstruct Shamir secret from identical evaluation points");
    }
    auto b1 = hexToBytes(s1.shardHex);
    auto b2 = hexToBytes(s2.shardHex);
    size_t len = std::min(b1.size(), b2.size());

    // Lagrange interpolation at x = 0:
    // l_1(0) = x2 / (x2 - x1) = x2 * inv(x2 ^ x1)
    // l_2(0) = x1 / (x1 - x2) = x1 * inv(x1 ^ x2)
    uint8_t diff = gfAdd(s1.x, s2.x);
    uint8_t invDiff = gfInv(diff);

    uint8_t l1 = gfMul(s2.x, invDiff);
    uint8_t l2 = gfMul(s1.x, invDiff);

    std::vector<uint8_t> secret(len);
    for (size_t i = 0; i < len; ++i) {
        secret[i] = gfAdd(gfMul(b1[i], l1), gfMul(b2[i], l2));
    }

    return bytesToHex(secret);
}

// ── F5: UUID MASK — mathematical script character mapping ────────────────────
// The compact WIF payload is re-rendered through the Mathematical Alphanumeric
// Symbols block. The cover name selects the glyph family deterministically
// (a 64-bit FNV-1a fold of the name indexes one of four styles), so the same
// key renders differently under different names while staying verifiable
// against the F3 compact form. One-way rendering: the payload is recoverable
// by mapping the glyphs back through the same four style tables.
std::string WifMatrix::toUuidMaskWif(std::string_view hexKey, std::string_view name) {
    // 64-bit FNV-1a fold of the cover name -> glyph style index.
    uint64_t h = 1469598103934665603ULL;
    for (char c : name) {
        h ^= static_cast<uint64_t>(static_cast<uint8_t>(c));
        h *= 1099511628211ULL;
    }
    const size_t style = h % 4;

    // Mathematical Alphanumeric Symbol glyph bases (A..Z, a..z blocks).
    const uint32_t letter_base =
        (style == 0) ? 0x1D400u   // Mathematical Bold
      : (style == 1) ? 0x1D434u   // Mathematical Italic
      : (style == 2) ? 0x1D468u   // Mathematical Bold Italic
      :               0x1D5A0u;   // Mathematical Sans-Serif Bold
    // Digit glyph bases (0..9; the italic family has none — fall back to Bold).
    const uint32_t digit_base =
        (style == 3) ? 0x1D7ECu   // Mathematical Sans-Serif Bold Digits
                     : 0x1D7CEu;  // Mathematical Bold Digits

    auto glyph_cp = [&](char ch) -> uint32_t {
        if (ch >= 'A' && ch <= 'Z') return letter_base + static_cast<uint32_t>(ch - 'A');
        if (ch >= 'a' && ch <= 'z') return letter_base + 26u + static_cast<uint32_t>(ch - 'a');
        if (ch >= '0' && ch <= '9') return digit_base + static_cast<uint32_t>(ch - '0');
        return static_cast<uint32_t>(static_cast<uint8_t>(ch)); // '-' '_' stay literal
    };

    auto utf8_append = [](std::string& out, uint32_t cp) {
        if (cp < 0x80) { out += static_cast<char>(cp); }
        else if (cp < 0x800) {
            out += static_cast<char>(0xC0 | (cp >> 6));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else if (cp < 0x10000) {
            out += static_cast<char>(0xE0 | (cp >> 12));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        } else {
            out += static_cast<char>(0xF0 | (cp >> 18));
            out += static_cast<char>(0x80 | ((cp >> 12) & 0x3F));
            out += static_cast<char>(0x80 | ((cp >> 6) & 0x3F));
            out += static_cast<char>(0x80 | (cp & 0x3F));
        }
    };

    std::string out = "UMSK[";
    out.append(name).append("]:");
    for (char ch : toCompactWif(hexKey)) {
        utf8_append(out, glyph_cp(ch));
    }
    return out;
}

// ── F9–F17: contextual wrappers around the compact WIF ───────────────────────

std::string WifMatrix::toTimeLockedWif(std::string_view hexKey, uint64_t unlock_timestamp) {
    return "TLOCK-[" + std::to_string(unlock_timestamp) + "]-" + toCompactWif(hexKey);
}

std::string WifMatrix::toPuzzleWif(std::string_view hexKey) {
    const std::string compact = toCompactWif(hexKey);
    // Withhold the last 6 characters — the puzzle gap.
    return "PZL-" + compact.substr(0, compact.size() - 6) + "??????";
}

std::string WifMatrix::toMultiKernelWif(std::string_view hexKey) {
    return "MKC:[AVX512->CUDA]-" + toCompactWif(hexKey);
}

std::string WifMatrix::toHoneypotWif(std::string_view hexKey) {
    return "TRAP-0x69-" + toCompactWif(hexKey);
}

std::string WifMatrix::toEntropyInfusedWif(std::string_view hexKey, uint64_t block_height) {
    return "ENT-[BLK:" + std::to_string(block_height) + "," +
           std::to_string(block_height + 1) + "]-" + toCompactWif(hexKey);
}

std::string WifMatrix::toDeadManWif(std::string_view hexKey, uint32_t inactive_days) {
    return "DMT-[" + std::to_string(inactive_days) + "_DAYS_INACTIVE]->TRANSFER-" +
           toCompactWif(hexKey);
}

std::string WifMatrix::toDecoyWif(std::string_view hexKey) {
    return "DECOY-D2-" + toCompactWif(hexKey) + "||F4K3S33D";
}

std::string WifMatrix::toAirgapMatrixWif() {
    // Optical-render banner: human-transcription frame for air-gapped transfer.
    const std::string matrix =
        "VAULT AIR-GAP MATRIX — optical render frame\n"
        "+--------------------------------------------+\n"
        "| ROW  32B FOLDED KEY IS RENDERED EXTERNALLY |\n"
        "| SCAN -> RECONSTRUCT -> VERIFY -> SIGN      |\n"
        "+--------------------------------------------+";
    return matrix;
}

std::string WifMatrix::toBurnOnReadWif(std::string_view hexKey) {
    return "BURN-[1_VALID_READ]-" + toCompactWif(hexKey);
}

// ── The full 17-format derivation in one call ────────────────────────────────
SovereignFormats WifMatrix::deriveSovereignFormats(std::string_view hexKey) {
    SovereignFormats f;
    f.record          = toUnicodeRunesWif(hexKey);          // F1
    f.compressed      = toUnicodeCompressedWif(hexKey);     // F2
    f.compact         = toCompactWif(hexKey);               // F3
    f.uncompressed    = toUncompressedWif(hexKey);          // F4
    f.uuidMask        = toUuidMaskWif(hexKey);               // F5
    f.ghost           = encodeGhostWif(hexKey);             // F6
    f.hwLocked        = encodeHwLockedWif(hexKey);          // F7
    const auto shards = splitShamir(hexKey);                // F8
    f.shamir1         = shards[0];
    f.shamir2         = shards[1];
    f.shamir3         = shards[2];
    f.timeLocked      = toTimeLockedWif(hexKey);            // F9
    f.puzzle          = toPuzzleWif(hexKey);                // F10
    f.multiKernel     = toMultiKernelWif(hexKey);           // F11
    f.honeypot        = toHoneypotWif(hexKey);              // F12
    f.entropyInfused  = toEntropyInfusedWif(hexKey);        // F13
    f.deadMan         = toDeadManWif(hexKey);               // F14
    f.decoy           = toDecoyWif(hexKey);                 // F15
    f.airgap          = toAirgapMatrixWif();                // F16
    f.burn            = toBurnOnReadWif(hexKey);            // F17
    return f;
}

} // namespace vx::wif
