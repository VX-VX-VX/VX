#pragma once

#include "vx/core/secure_memory.hpp"
#include "vx/wif/unicode_alphabet.hpp"
#include <string>
#include <vector>
#include <array>
#include <string_view>

namespace vx::wif {

struct ShamirShard {
    uint8_t x; // Evaluation point (1, 2, 3)
    std::string shardHex; // Shard payload
};

// ── The 17 Sovereign Wallet Import Formats ───────────────────────────────────
// Derived deterministically from the 2048-bit canonical seed. Formats 1 and 2
// are the compact runic pair: they encode the FULL 2048-bit key over the full
// Unicode alphabet (kUnicodeAlphabetSize symbols, each one a digit).
struct SovereignFormats {
    std::string record;          // F1  RECORD WIF — full-Unicode runes (102)
    std::string compressed;      // F2  COMPRESSED WIF — full-Unicode base
    std::string compact;         // F3  COMPACT WIF — 32B fold + Base64URL
    std::string uncompressed;    // F4  UNCOMPRESSED WIF — 512 hex chars
    std::string uuidMask;        // F5  UUID MASK (script mask)
    std::string ghost;           // F6  GHOST-WIF — zero-width steganography
    std::string hwLocked;        // F7  HW-LOCKED WIF — UUID XOR + HWL prefix
    ShamirShard shamir1;         // F8  SHAMIR SPLIT 2-of-3
    ShamirShard shamir2;
    ShamirShard shamir3;
    std::string timeLocked;      // F9  TIME-LOCKED WIF
    std::string puzzle;          // F10 PUZZLE-WIF — trailing ??????
    std::string multiKernel;     // F11 MULTI-KERNEL CHAINED WIF
    std::string honeypot;        // F12 EPHEMERAL HONEYPOT trap
    std::string entropyInfused;  // F13 ENTROPY-INFUSED (block-range bound)
    std::string deadMan;         // F14 DEAD-MAN'S TRIGGER
    std::string decoy;           // F15 DECOY DUAL-ENTROPY
    std::string airgap;          // F16 AIR-GAPPED MATRIX (optical render)
    std::string burn;            // F17 BURN-ON-READ single-use wrapper
};

class WifMatrix {
public:
    // D1: Record WIF (Mathematical Runes)
    static std::string toRecordWif(std::string_view hexKey);

    // D1 (full): Record WIF over the FULL Unicode alphabet — the complete
    // 2048-bit key as 102 runes, each rune one digit of the ~1.11M-symbol
    // alphabet. Roundtrip-exact with fromUnicodeRunesWif.
    static std::string toUnicodeRunesWif(std::string_view hexKey);
    static std::string fromUnicodeRunesWif(std::string_view wif);

    // D2: Compressed WIF (Base128 Extended Latin)
    static std::string toCompressedWif(std::string_view hexKey);

    // D2 (full): Compressed WIF over the FULL Unicode alphabet.
    static std::string toUnicodeCompressedWif(std::string_view hexKey);
    static std::string fromUnicodeCompressedWif(std::string_view wif);

    // D3: Compact WIF (XOR folding into 32 bytes + Base64)
    static std::string toCompactWif(std::string_view hexKey);

    // D4: Uncompressed WIF (512 hex characters)
    static std::string toUncompressedWif(std::string_view hexKey);

    // D5: UUID MASK — mathematical script character mapping of the compact
    // WIF payload; the cover name selects the glyph family deterministically.
    static std::string toUuidMaskWif(std::string_view hexKey,
                                     std::string_view name = "SOVEREIGN");

    // D6: Ghost WIF (Steganography with Zero-Width Unicode U+200B / U+200C)
    static std::string encodeGhostWif(std::string_view hexKey, std::string_view coverWord = "Vortex");
    static std::string decodeGhostWif(std::string_view stegoText);

    // D7: Hardware-Locked WIF (XOR with hardware UUID bytes).
    // SYNTHETIC_PUBLIC_FALLBACK_UUID — hardware binding is active only in the
    // Sovereign Vault build; the public build uses this neutral test vector.
    static std::string encodeHwLockedWif(std::string_view hexKey,
        std::string_view uuid = "00000000-0000-0000-0000-000000000001");
    static std::string decodeHwLockedWif(std::string_view lockedHex,
        std::string_view uuid = "00000000-0000-0000-0000-000000000001");

    // D8: Shamir's Secret Sharing 2-of-3 (over GF(256))
    static std::vector<ShamirShard> splitShamir(std::string_view hexKey);
    static std::string recoverShamir(const ShamirShard& s1, const ShamirShard& s2);

    // D9: Time-Locked WIF — TLOCK-[<unix_ts>]-<compact>
    static std::string toTimeLockedWif(std::string_view hexKey, uint64_t unlock_timestamp = 1781520000);

    // D10: Puzzle WIF — PZL-<compact head>??????  (last 6 chars withheld)
    static std::string toPuzzleWif(std::string_view hexKey);

    // D11: Multi-Kernel Chained WIF — MKC:[AVX512->CUDA]-<compact>
    static std::string toMultiKernelWif(std::string_view hexKey);

    // D12: Ephemeral Honeypot trap — TRAP-0x69-<compact>
    static std::string toHoneypotWif(std::string_view hexKey);

    // D13: Entropy-Infused WIF — ENT-[BLK:<h>,<h+1>]-<compact>
    static std::string toEntropyInfusedWif(std::string_view hexKey, uint64_t block_height = 842000);

    // D14: Dead-Man's Trigger — DMT-[<n>_DAYS_INACTIVE]->TRANSFER-<compact>
    static std::string toDeadManWif(std::string_view hexKey, uint32_t inactive_days = 365);

    // D15: Decoy Dual-Entropy — DECOY-D2-<compact>||F4K3S33D
    static std::string toDecoyWif(std::string_view hexKey);

    // D16: Air-Gapped Matrix (optical render banner)
    static std::string toAirgapMatrixWif();

    // D17: Burn-on-Read single-use wrapper — BURN-[1_VALID_READ]-<compact>
    static std::string toBurnOnReadWif(std::string_view hexKey);

    // ── The full 17-format derivation in one call ──
    static SovereignFormats deriveSovereignFormats(std::string_view hexKey);

    // Helper utilities
    static std::vector<uint8_t> hexToBytes(std::string_view hex);
    static std::string bytesToHex(const std::vector<uint8_t>& bytes);
    static std::string base64UrlSafe(const std::vector<uint8_t>& bytes);

private:
    // Big-endian 256-byte bignum <-> full-Unicode base conversion (F1/F2).
    static std::string bignum_to_unicode_base(const std::array<uint8_t, 256>& num,
                                              std::string_view prefix);
    static bool unicode_base_to_bignum(std::string_view runes, size_t expected_digits,
                                       std::array<uint8_t, 256>& out);

    // Normalizes a hex seed to exactly 256 bytes (right-padded with 0x00).
    static std::array<uint8_t, 256> seed_to_256b(std::string_view hexKey);

    // GF(256) field arithmetic for Shamir polynomials
    static uint8_t gfAdd(uint8_t a, uint8_t b) noexcept { return a ^ b; }
    static uint8_t gfMul(uint8_t a, uint8_t b) noexcept;
    static uint8_t gfInv(uint8_t a) noexcept;
};

} // namespace vx::wif
