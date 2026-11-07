#pragma once

#include "vx/blockchain/crypto_sponge.hpp"

#include <gmpxx.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <string_view>
#include <vector>

namespace vx::math {

/**
 * @brief VX2: the generation-2 address format (owner directive 2026-11-06,
 * "better than Bitcoin's"; design + rationale in
 * docs/ADDRESS_FORMATS_V2.md). ADDITIVE PRIMITIVE - NOT wired into
 * consensus or the frozen v1 wire; adoption goes through the genesis
 * migration protocol (docs/DERIVATION_MIGRATION.md) bundled with the
 * address-v2 fold (BACKLOG 2.17 remedy).
 *
 * Structure:
 *   digest = VortexSponge1024( tag || X || Y || Z ), tag domain-separates
 *   the address type ("VX_ADDR_V2_NFA_V1" / "VX_ADDR_V2_OFA_V1") so NFA
 *   and OFA digests are unrelated by construction (fixes the BACKLOG 2.18
 *   body-sharing linkability defect), and the fold runs over ALL 3072
 *   bits of the final state (fixes the 2.17 narrow-window defect).
 *
 *   payload = core (digest bytes 0..31, 256 bits, displayed) + span
 *   (digest bytes 32..36, 40 bits, binds the display to the full digest).
 *   Displayed space 2^296; the full 1024-bit digest is the wire-binding
 *   home. Reserved digest bytes 37..127 are never displayed.
 *
 *   Encoding (91 chars): "vx2" + version symbol + 52 core symbols + 8
 *   span symbols + 27 checksum symbols, over the VX-OWN single-case
 *   alphabet (digits 2-9, letters minus i/l/o lookalikes, '-'). The
 *   checksum is the VX-OWN 135-bit BCH code: field GF(2^9)
 *   (GF(2)[x]/(x^9 + x^4 + 1)), root alpha = x of ORDER 511 = 2^9 - 1
 *   (primitive). The checksummed stream is 92 symbols = 460 bits, and
 *   460 < 511, so the bit exponents are DISTINCT mod ord(alpha) and the
 *   Vandermonde/BCH argument is valid - the code is a SHORTENED cyclic
 *   code of length 511 over GF(2) (the intermediate design used alpha of
 *   order 93 with exponents reaching 404 > 93, where aliasing x^(a+93k)
 *   == x^a mod g yields weight-2 holes - found empirically (1794
 *   undetected weight-2 pairs) and redesigned 2026-11-06). Generator
 *   g(x) = product of the minimal polynomials of
 *   alpha^1,3,5,7,9,11,13,15,17,19,21,23,25,27,29 =
 *   0x93bc9c6a8f56b4973961ccc8e4411bb683 (degree 135, roots
 *   alpha^1..alpha^30 CONSECUTIVE). Provable guarantees: every error of
 *   weight <= 30 BITS detected (= every substitution of <= 6 whole
 *   symbols - bech32m guarantees 4, cashaddr 6 at ~2^-40), every burst
 *   of <= 26 consecutive symbols detected, ~2^-135 residual for random
 *   heavier errors (bech32m: ~2^-30). Empirical confirmation: zero
 *   weight-2 holes (2852 single-symbol residues, no collisions),
 *   exhaustive bit weight <= 2 clean, 0/30000 sampled weight 3..30.
 *   Convention: polymod over ALL checksummed symbols must equal the
 *   init constant (the bech32 fixed-target convention; the raw-register
 *   convention has a structural weight-2 hole at payload/checksum
 *   distance 50 - same finding). Mixed-case inputs are rejected.
 */
class VortexAddressV2 {
public:
    enum class Kind : uint8_t { NFA = 0, OFA = 1 };

    static constexpr size_t CORE_BYTES = 32;       // 256-bit displayed core
    static constexpr size_t SPAN_BYTES = 5;        // 40-bit display-to-wire binding
    static constexpr size_t DIGEST_BYTES = 128;    // full 1024-bit sponge digest
    static constexpr size_t CORE_SYMBOLS = 52;     // 260 bits: core + 4 zero pad bits
    static constexpr size_t SPAN_SYMBOLS = 8;      // 40 bits
    static constexpr size_t CHECKSUM_SYMBOLS = 27; // 135-bit BCH checksum
    static constexpr size_t TOTAL_CHARS = 3 + 1 + CORE_SYMBOLS + SPAN_SYMBOLS + CHECKSUM_SYMBOLS;

    struct Derived {
        Kind kind;
        std::array<uint8_t, CORE_BYTES> core;
        std::array<uint8_t, SPAN_BYTES> span;
        std::array<uint8_t, DIGEST_BYTES> digest; // full digest: the wire-binding home
    };

    struct Decoded {
        Kind kind;
        std::array<uint8_t, CORE_BYTES> core;
        std::array<uint8_t, SPAN_BYTES> span;
    };

    /// The domain-separated 1024-bit digest over all 3072 final-state bits.
    static Derived derive(Kind kind, const mpz_class &x, const mpz_class &y, const mpz_class &z) {
        Derived out{};
        out.kind = kind;
        out.digest = computeDigest(kind, x, y, z);
        std::memcpy(out.core.data(), out.digest.data(), CORE_BYTES);
        std::memcpy(out.span.data(), out.digest.data() + CORE_BYTES, SPAN_BYTES);
        return out;
    }

    // The VX-own checksum register: 135 bits (deg g = 135), three limbs.
    // Exposed for the contract suite's KAT pin (the C++ evaluation must
    // equal the field-theory computation). w[0] = bits 0..63, w[1] =
    // bits 64..127, w[2] = bits 128..134. Serves as BOTH the register
    // init and the decode target constant.
    struct Reg {
        uint64_t w[3];
        bool operator==(const Reg &) const = default;
    };

    // Register init AND decode target: the Golden Phi constant
    // (0x9e3779b97f4a7c15 - the same constant that seeds every sponge
    // state word 0), zero-extended to the 135-bit register width.
    static constexpr Reg kChecksumInit{0x9e3779b97f4a7c15ULL, 0, 0};

    /// The 5-bit field of the register at bit position pos. The field's
    /// LSB sits at the LOWEST exponent (symbol bit j lives at exponent
    /// pos+j - the same convention the polymod shift-in uses).
    static uint8_t regField5(const Reg &r, size_t pos) {
        uint8_t v = 0;
        for (size_t b = 0; b < 5; ++b) {
            const size_t idx = pos + b;
            const uint64_t limb = idx < 64 ? r.w[0] : (idx < 128 ? r.w[1] : r.w[2]);
            v |= static_cast<uint8_t>(((limb >> (idx & 63)) & 1) << b);
        }
        return v;
    }

    static Reg regXor(const Reg &a, const Reg &b) {
        return Reg{a.w[0] ^ b.w[0], a.w[1] ^ b.w[1], a.w[2] ^ b.w[2]};
    }

    static Reg polymod(const std::vector<uint8_t> &syms, Reg init) {
        // GEN[i] = x^(135+i) mod g, i = 0..4
        // (g = 0x93bc9c6a8f56b4973961ccc8e4411bb683, computed from the
        // field theory in docs/ADDRESS_FORMATS_V2.md section 3.3 and
        // pinned by the contract suite). XORing the terms for the
        // spilled top 5 bits keeps the register equal to the CANONICAL
        // remainder of the message polynomial mod g at every step -
        // which is what makes the undetected-error set exactly
        // {E : g | E} and the BCH bound applicable.
        static constexpr uint64_t GEN[5][3] = {
            {0x61ccc8e4411bb683ULL, 0xbc9c6a8f56b49739ULL, 0x13ULL},
            {0xc39991c882376d06ULL, 0x7938d51ead692e72ULL, 0x27ULL},
            {0x87332391046eda0cULL, 0xf271aa3d5ad25ce5ULL, 0x4eULL},
            {0x6faa8fc649c6029bULL, 0x587f3ef5e3102ef2ULL, 0x0eULL},
            {0xdf551f8c938c0536ULL, 0xb0fe7debc6205de4ULL, 0x1cULL},
        };
        Reg c = init;
        for (const uint8_t d : syms) {
            // c <- (c * x^5 + d) mod g: shift the 135-bit register left
            // by 5, then fold the 5 spilled bits (positions 135..139)
            // back in through GEN.
            const uint64_t lo = c.w[0], mid = c.w[1], hi = c.w[2];
            uint64_t nLo = (lo << 5) ^ d;
            uint64_t nMid = (mid << 5) | (lo >> 59);
            uint64_t nHi = (hi << 5) | (mid >> 59); // bits 128..139
            const uint64_t top = nHi >> 7;          // bits 135..139
            nHi &= 127;                             // keep bits 128..134
            for (int i = 0; i < 5; ++i) {
                if ((top >> i) & 1) {
                    nLo ^= GEN[i][0];
                    nMid ^= GEN[i][1];
                    nHi ^= GEN[i][2];
                }
            }
            c = Reg{nLo, nMid, nHi};
        }
        return c;
    }

    /// Canonical lowercase encoding. Total length is exactly TOTAL_CHARS.
    static std::string encode(const Derived &a) {
        std::vector<uint8_t> syms;
        syms.reserve(TOTAL_CHARS);
        pushPrefix(syms);
        syms.push_back(versionSymbol(a.kind));
        // ONE continuous bit stream: core (256 bits) then span (40 bits)
        // packed together - 296 bits -> 60 symbols (59 full + 1 symbol
        // carrying the last real bit + 4 zero pad bits). Decode reads the
        // same continuous stream, so the packing MUST be continuous; two
        // separate packers would shift the span by the pad width (found
        // and fixed 2026-11-06).
        std::array<uint8_t, CORE_BYTES + SPAN_BYTES> buf{};
        std::memcpy(buf.data(), a.core.data(), CORE_BYTES);
        std::memcpy(buf.data() + CORE_BYTES, a.span.data(), SPAN_BYTES);
        pushBits(syms, buf.data(), buf.size(), 0); // 37 bytes -> exactly 60 symbols
        // Checksum (bech32 fixed-target convention): feed 27 zero symbols,
        // XOR the resulting register with the init constant, and emit those
        // 135 bits as the 27 checksum symbols. Decode then verifies
        // polymod(ALL checksummed symbols, init) == init, which makes the
        // undetected-error set exactly {E : g | E} - the shortened
        // length-511 cyclic BCH code with min distance >= 31 (30-bit
        // guarantee = every substitution of <= 6 whole symbols).
        {
            std::vector<uint8_t> probe(syms);
            probe.insert(probe.end(), CHECKSUM_SYMBOLS, 0);
            const Reg v = regXor(polymod(probe, kChecksumInit), kChecksumInit);
            for (size_t i = 0; i < CHECKSUM_SYMBOLS; ++i) {
                syms.push_back(regField5(v, CHECKSUM_SYMBOLS * 5 - 5 * (i + 1)));
            }
        }
        std::string s;
        s.reserve(TOTAL_CHARS);
        s += "vx2";
        for (size_t i = 0; i < syms.size(); ++i) {
            if (i < 4)
                continue; // prefix "vx2" + separator: not displayed
            s.push_back(kCharset[syms[i]]);
        }
        return s;
    }

    /// Fail-closed decoder. Accepts all-lowercase or all-uppercase only.
    /// Checks: exact length, prefix, charset, case rule, checksum, the
    /// reserved version/length-class bits, and the core's zero padding.
    static bool decode(std::string_view in, Decoded &out) {
        if (in.size() != TOTAL_CHARS)
            return false;

        // Case detection looks at LETTERS only: digits and '-' are shared
        // by both case variants, so scanning the full charsets would flag
        // every digit-bearing address as "mixed case" (found 2026-11-06).
        const bool hasLower = in.find_first_of(kLowerLetters) != std::string_view::npos;
        const bool hasUpper = in.find_first_of(kUpperLetters) != std::string_view::npos;
        if (hasLower && hasUpper)
            return false; // mixed case: reject (cashaddr rule)

        std::string s(in);
        if (hasUpper) {
            for (char &c : s) {
                if (c >= 'A' && c <= 'Z')
                    c = static_cast<char>(c - 'A' + 'a');
            }
        }
        if (s.compare(0, 3, "vx2") != 0)
            return false;

        std::vector<uint8_t> syms;
        syms.reserve(TOTAL_CHARS);
        pushPrefix(syms);
        for (size_t i = 3; i < s.size(); ++i) {
            const int8_t v = charValue(s[i]);
            if (v < 0)
                return false;
            syms.push_back(static_cast<uint8_t>(v));
        }
        // syms layout: [0..3] prefix+separator, [4] version,
        // [5..64] payload (52 core + 8 span), [65..80] checksum (16 symbols).
        if (syms.size() != 4 + 1 + CORE_SYMBOLS + SPAN_SYMBOLS + CHECKSUM_SYMBOLS)
            return false;

        const uint8_t version = syms[4];
        if (version != 3 && version != 4)
            return false; // reserved: fail-closed
        out.kind = version == 3 ? Kind::NFA : Kind::OFA;

        // Payload: syms[5..64] = 60 symbols = ONE continuous 300-bit stream:
        // core (256 bits, bytes 0..31) then span (40 bits, bytes 32..36),
        // then 4 zero pad bits (enforced by pullBits' leftover check).
        std::array<uint8_t, CORE_BYTES + SPAN_BYTES> bytes{};
        if (!pullBits(syms, 5, CORE_SYMBOLS + SPAN_SYMBOLS, bytes.data(), CORE_BYTES + SPAN_BYTES))
            return false;
        std::memcpy(out.core.data(), bytes.data(), CORE_BYTES);
        std::memcpy(out.span.data(), bytes.data() + CORE_BYTES, SPAN_BYTES);

        // Checksum: polymod over ALL checksummed symbols (prefix, version,
        // payload AND the 16 checksum symbols) must equal the init constant
        // (fixed-target convention; undetected errors are exactly the
        // multiples of g, so the BCH bound applies).
        return polymod(syms, kChecksumInit) == kChecksumInit;
    }

private:
    // VX-OWN single-case alphabet, value = index. 8 digits (2-9) + 23 letters
    // (a-z minus the lookalikes i, l, o) + '-'. 'o'/'O', 'l'/'I'/'1', 'i'
    // typed by a misreading human are INVALID characters -> fail-closed.
    static constexpr char kCharset[] = "23456789-abcdefghjkmnpqrstuvwxyz";
    static constexpr char kCharsetUpper[] = "23456789-ABCDEFGHJKMNPQRSTUVWXYZ";
    static constexpr char kLowerLetters[] = "abcdefghjkmnpqrstuvwxyz";
    static constexpr char kUpperLetters[] = "ABCDEFGHJKMNPQRSTUVWXYZ";

    static int8_t charValue(char c) {
        for (int8_t i = 0; i < 32; ++i) {
            if (kCharset[i] == c)
                return i;
        }
        return -1;
    }

    // VX-OWN 135-bit BCH code (the field, the root order, the generator and
    // the constants are ours - computed from field theory, see
    // docs/ADDRESS_FORMATS_V2.md section 3.3):
    //   root field  GF(2^9) = GF(2)[x]/(x^9 + x^4 + 1); alpha = x has
    //               ORDER 511 = 2^9 - 1 (primitive). The checksummed
    //               stream is 92 symbols = 460 bits and 460 < 511, so the
    //               bit exponents are DISTINCT mod ord(alpha) and the
    //               Vandermonde/BCH argument is valid: the code is a
    //               SHORTENED cyclic code of length 511 over GF(2). (An
    //               intermediate design used an order-93 alpha with
    //               exponents reaching 404 > 93, where aliasing
    //               x^(a+93k) == x^a mod g yields weight-2 holes - found
    //               empirically, 1794 undetected weight-2 pairs, and
    //               redesigned 2026-11-06.)
    //   generator   g(x) = m_1 * m_3 * m_5 * m_7 * m_9 * m_11 * m_13 *
    //               m_15 * m_17 * m_19 * m_21 * m_23 * m_25 * m_27 * m_29
    //               = 0x93bc9c6a8f56b4973961ccc8e4411bb683 (degree 135 =
    //               27 symbols exactly); its roots cover alpha^1..alpha^30
    //               CONSECUTIVELY -> min distance >= 31 -> EVERY error of
    //               weight <= 30 BITS is detected (= every substitution
    //               of <= 6 whole symbols; bech32m guarantees 4, cashaddr
    //               6 at ~2^-40).
    //   burst       any burst of <= 26 consecutive symbols detected
    //               (a burst is a 2-term polynomial of degree <= 5*26+4
    //               = 134 < deg g = 135, forcing it to 0).
    //   residual    ~2^-135 for random heavier errors (bech32m ~2^-30).
    //               Empirical: 0/30000 sampled weight 3..30 bit errors;
    //               zero weight-2 symbol holes (2852 residues, no
    //               collisions); exhaustive bit weight <= 2 clean.
    //   init/target 0x9e3779b97f4a7c15 - the Golden Phi constant (the same
    //               constant that seeds every sponge state word 0),
    //               zero-extended to the 135-bit register; the decode
    //               target equals the init, bech32-style.
    // The decode path evaluates polymod over ALL checksummed symbols and
    // compares against the constant - the raw-register convention has a
    // structural weight-2 hole (payload symbol i + checksum symbol i-50,
    // same delta) and is NOT used. polymod and kChecksumInit live in the
    // public section (the contract suite pins the evaluation).

    static void pushPrefix(std::vector<uint8_t> &syms) {
        // The prefix characters are themselves alphabet symbols (v, x, 2
        // are all in the VX charset), then the separator (one zero group)
        // that feeds the checksum but never appears in the display.
        syms.push_back(static_cast<uint8_t>(charValue('v')));
        syms.push_back(static_cast<uint8_t>(charValue('x')));
        syms.push_back(static_cast<uint8_t>(charValue('2')));
        syms.push_back(0);
    }

    static uint8_t versionSymbol(Kind kind) {
        // VX-own constants: 3 = NFA (format v0, length class 60), 4 = OFA.
        // Every other 5-bit value is reserved and fails closed on decode.
        return kind == Kind::NFA ? 0x03 : 0x04;
    }

    /// Byte stream -> 5-bit symbols, MSB-first bit concatenation, zero pad.
    static void pushBits(std::vector<uint8_t> &syms, const uint8_t *data, size_t n, int) {
        uint32_t acc = 0;
        int bits = 0;
        for (size_t i = 0; i < n; ++i) {
            acc = (acc << 8) | data[i];
            bits += 8;
            while (bits >= 5) {
                bits -= 5;
                syms.push_back(static_cast<uint8_t>((acc >> bits) & 31));
            }
        }
        if (bits > 0)
            syms.push_back(static_cast<uint8_t>((acc << (5 - bits)) & 31));
    }

    /// Inverse of pushBits for a known byte count; rejects nonzero pad.
    static bool pullBits(const std::vector<uint8_t> &syms, size_t offset, size_t count,
                         uint8_t *out, size_t outBytes) {
        uint32_t acc = 0;
        int bits = 0;
        size_t oi = 0;
        for (size_t i = offset; i < offset + count; ++i) {
            acc = (acc << 5) | syms[i];
            bits += 5;
            while (bits >= 8 && oi < outBytes) {
                bits -= 8;
                out[oi++] = static_cast<uint8_t>((acc >> bits) & 0xFF);
            }
        }
        if (oi != outBytes)
            return false;
        // leftover bits (2 for 52 symbols -> 260 bits) must be zero padding
        return (acc & ((1u << bits) - 1)) == 0;
    }

    static std::array<uint8_t, DIGEST_BYTES> computeDigest(Kind kind, const mpz_class &x,
                                                           const mpz_class &y, const mpz_class &z) {
        const char *tag = kind == Kind::NFA ? "VX_ADDR_V2_NFA_V1" : "VX_ADDR_V2_OFA_V1";

        std::array<uint8_t, 384> trunks{};
        toBytes1024(x, trunks.data());
        toBytes1024(y, trunks.data() + 128);
        toBytes1024(z, trunks.data() + 256);

        vx::blockchain::VortexSponge1024 sponge;
        sponge.absorb(reinterpret_cast<const uint8_t *>(tag), std::strlen(tag));
        sponge.absorb(trunks.data(), trunks.size());

        std::array<uint8_t, DIGEST_BYTES> digest{};
        sponge.finalize(digest.data());
        return digest;
    }

    /// 1024-bit mpz -> 128 bytes, most-significant byte first, zero-padded.
    static void toBytes1024(const mpz_class &v, uint8_t *out) {
        std::memset(out, 0, 128);
        // Security fix (2026-11-07, in-repo security review): the size
        // check MUST precede mpz_export, which writes count bytes into
        // the caller buffer BEFORE count is known - exporting a value
        // wider than 1024 bits into tmp[128] would be a stack overflow.
        // Values here are residues mod 1024-bit moduli; a larger export
        // is a caller contract violation, not a runtime condition to
        // absorb.
        if (mpz_sgn(v.get_mpz_t()) < 0 || mpz_sizeinbase(v.get_mpz_t(), 256) > 128) {
            std::fputs("VortexAddressV2: trunk exceeds 1024 bits\n", stderr);
            std::abort();
        }
        const size_t n = mpz_sizeinbase(v.get_mpz_t(), 256);
        size_t count = 0;
        mpz_export(out + (128 - n), &count, 1 /* MSB first */, 1, 1, 0, v.get_mpz_t());
    }
};

} // namespace vx::math
