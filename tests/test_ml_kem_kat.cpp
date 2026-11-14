// ML-KEM-768 KATs — official NIST ACVP vectors (FIPS 203), embedded from
// ml_kem_kat_vectors.inc. The no-stub gate: every vector must match
// bit-for-bit or the implementation does not ship.
#include <gtest/gtest.h>

#include "vx/crypto/ml_kem.hpp"

#include "ml_kem_kat_vectors.inc"

#include <cctype>
#include <cstring>
#include <string>
#include <vector>

namespace {

std::string uppercase_normalize(const char *hex) {
    std::string s(hex);
    for (auto &ch : s)
        ch = static_cast<char>(tolower(static_cast<unsigned char>(ch)));
    return s;
}

std::vector<uint8_t> from_hex(const char *hex) {
    auto nib = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    std::vector<uint8_t> out;
    while (*hex) {
        const int hi = nib(hex[0]);
        const int lo = hex[1] ? nib(hex[1]) : -1;
        if (hi < 0 || lo < 0)
            break;
        out.push_back(static_cast<uint8_t>((hi << 4) | lo));
        hex += 2;
    }
    return out;
}

std::string to_hex(const uint8_t *d, size_t n) {
    static const char *kHex = "0123456789abcdef";
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        s += kHex[d[i] >> 4];
        s += kHex[d[i] & 0xF];
    }
    return s;
}

} // namespace

TEST(VortexMlKem768Kat, KeyGenMatchesAcvp) {
    for (unsigned i = 0; i < vx_mlkem_kat::KEYGEN_N; ++i) {
        const auto &tc = vx_mlkem_kat::KEYGEN[i];
        std::vector<uint8_t> d = from_hex(tc.d);
        std::vector<uint8_t> z = from_hex(tc.z);
        ASSERT_EQ(d.size(), 32u);
        ASSERT_EQ(z.size(), 32u);
        uint8_t seed64[64];
        std::memcpy(seed64, d.data(), 32);
        std::memcpy(seed64 + 32, z.data(), 32);

        vx::crypto::mlkem::PublicKey ek;
        vx::crypto::mlkem::SecretKey dk;
        vx::crypto::mlkem::keygen_derand(seed64, ek, dk);

        // ACVP vectors are UPPERCASE hex; normalize before comparing.
        const std::string ek_got = to_hex(ek.data(), ek.size());
        const std::string dk_got = to_hex(dk.data(), dk.size());
        const std::string ek_exp = [&] {
            std::string s(tc.ek);
            for (auto &ch : s)
                ch = tolower((unsigned char)ch);
            return s;
        }();
        const std::string dk_exp = [&] {
            std::string s(tc.dk);
            for (auto &ch : s)
                ch = tolower((unsigned char)ch);
            return s;
        }();
        EXPECT_EQ(ek_exp, ek_got) << "keygen tcId=" << tc.tc << " ek";
        EXPECT_EQ(dk_exp, dk_got) << "keygen tcId=" << tc.tc << " dk";
    }
}

TEST(VortexMlKem768Kat, EncapsMatchesAcvp) {
    for (unsigned i = 0; i < vx_mlkem_kat::ENCAP_N; ++i) {
        const auto &tc = vx_mlkem_kat::ENCAP[i];
        const std::vector<uint8_t> ek = from_hex(tc.ek);
        const std::vector<uint8_t> m = from_hex(tc.m);
        ASSERT_EQ(ek.size(), vx::crypto::mlkem::PK_SIZE);
        ASSERT_EQ(m.size(), 32u);

        vx::crypto::mlkem::Ciphertext ct;
        vx::crypto::mlkem::SharedSecret ss;
        vx::crypto::mlkem::encaps(
            *reinterpret_cast<const vx::crypto::mlkem::PublicKey *>(ek.data()), m.data(), ct, ss);

        EXPECT_EQ(uppercase_normalize(tc.c), to_hex(ct.data(), ct.size()))
            << "encap tcId=" << tc.tc << " ct";
        EXPECT_EQ(uppercase_normalize(tc.k), to_hex(ss.data(), ss.size()))
            << "encap tcId=" << tc.tc << " ss";
    }
}

TEST(VortexMlKem768Kat, DecapsRecoversSharedSecret) {
    for (unsigned i = 0; i < vx_mlkem_kat::ENCAP_N; ++i) {
        const auto &tc = vx_mlkem_kat::ENCAP[i];
        const std::vector<uint8_t> ek = from_hex(tc.ek);
        const std::vector<uint8_t> dk = from_hex(tc.dk);
        const std::vector<uint8_t> c = from_hex(tc.c);
        ASSERT_EQ(dk.size(), vx::crypto::mlkem::SK_SIZE);
        ASSERT_EQ(c.size(), vx::crypto::mlkem::CT_SIZE);

        vx::crypto::mlkem::SharedSecret ss;
        vx::crypto::mlkem::decaps(
            *reinterpret_cast<const vx::crypto::mlkem::SecretKey *>(dk.data()),
            *reinterpret_cast<const vx::crypto::mlkem::Ciphertext *>(c.data()), ss);
        EXPECT_EQ(uppercase_normalize(tc.k), to_hex(ss.data(), ss.size()))
            << "decaps tcId=" << tc.tc;
    }
}

TEST(VortexMlKem768Kat, RoundTripAndImplicitRejection) {
    vx::crypto::mlkem::PublicKey ek;
    vx::crypto::mlkem::SecretKey dk;
    uint8_t seed[64];
    for (unsigned i = 0; i < 64; ++i)
        seed[i] = static_cast<uint8_t>(i * 5 + 1);
    vx::crypto::mlkem::keygen_derand(seed, ek, dk);

    // Determinism: the same seed produces the same keypair.
    vx::crypto::mlkem::PublicKey ek2;
    vx::crypto::mlkem::SecretKey dk2;
    vx::crypto::mlkem::keygen_derand(seed, ek2, dk2);
    EXPECT_EQ(0, std::memcmp(ek.data(), ek2.data(), ek.size()));
    EXPECT_EQ(0, std::memcmp(dk.data(), dk2.data(), dk.size()));

    uint8_t m[32];
    for (unsigned i = 0; i < 32; ++i)
        m[i] = static_cast<uint8_t>(0xA0 + i);
    vx::crypto::mlkem::Ciphertext ct;
    vx::crypto::mlkem::SharedSecret ss1, ss2;
    vx::crypto::mlkem::encaps(ek, m, ct, ss1);
    vx::crypto::mlkem::decaps(dk, ct, ss2);
    EXPECT_EQ(0, std::memcmp(ss1.data(), ss2.data(), ss1.size())) << "roundtrip";

    // Deterministic encaps: the same (ek, m) pair produces the same ct/ss.
    vx::crypto::mlkem::Ciphertext ct2;
    vx::crypto::mlkem::SharedSecret ss3;
    vx::crypto::mlkem::encaps(ek, m, ct2, ss3);
    EXPECT_EQ(0, std::memcmp(ct.data(), ct2.data(), ct.size()));
    EXPECT_EQ(0, std::memcmp(ss1.data(), ss3.data(), ss1.size()));

    // Implicit rejection: a single flipped ciphertext bit yields a DIFFERENT
    // pseudorandom secret (never an error, never the original secret).
    vx::crypto::mlkem::Ciphertext bad = ct;
    bad[0] ^= 0x01;
    vx::crypto::mlkem::SharedSecret ss_bad;
    vx::crypto::mlkem::decaps(dk, bad, ss_bad);
    EXPECT_NE(0, std::memcmp(ss1.data(), ss_bad.data(), ss1.size()));
}
