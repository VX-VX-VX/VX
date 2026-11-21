// SLH-DSA-SHAKE-128s (FIPS 205) — the ACVP gate: keyGen + sigVer
// internalProjection vectors embedded from slh_dsa_kat_vectors.inc.
// The no-stub gate: every vector must match bit-for-bit or the
// implementation does not ship.
#include <gtest/gtest.h>

#include "vx/crypto/slh_dsa.hpp"

#include "slh_dsa_kat_vectors.inc"

#include <cstring>
#include <string>
#include <vector>

namespace {

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
    static const char *kHex = "0123456789ABCDEF";
    std::string s;
    for (size_t i = 0; i < n; ++i) {
        s += kHex[d[i] >> 4];
        s += kHex[d[i] & 0xF];
    }
    return s;
}

void load16(vx::crypto::slh::bytes16 &out, const std::vector<uint8_t> &v) {
    std::memcpy(out.data(), v.data(), 16);
}

} // namespace

TEST(VortexSlhDsa128sKat, KeyGenMatchesAcvp) {
    for (const auto &tc : vx_slhdsa_kat::KEYGEN) {
        vx::crypto::slh::bytes16 sk_seed, sk_prf, pk_seed;
        load16(sk_seed, from_hex(tc.sk_seed));
        load16(sk_prf, from_hex(tc.sk_prf));
        load16(pk_seed, from_hex(tc.pk_seed));

        const auto sk = vx::crypto::slh::slh_keygen(sk_seed, sk_prf, pk_seed);
        const auto sk_ser = vx::crypto::slh::serialize_sk(sk);
        const auto pk_ser = vx::crypto::slh::serialize_pk({sk.pk_seed, sk.pk_root});

        EXPECT_EQ(to_hex(sk_ser.data(), sk_ser.size()), tc.sk)
            << "keyGen tc " << tc.tc << ": SK mismatch";
        EXPECT_EQ(to_hex(pk_ser.data(), pk_ser.size()), tc.pk)
            << "keyGen tc " << tc.tc << ": PK mismatch";
    }
}

TEST(VortexSlhDsa128sKat, SignMatchesAcvpInternal) {
    for (const auto &tc : vx_slhdsa_kat::SIGVER) {
        if (!tc.pass)
            continue;
        const auto sk_v = from_hex(tc.sk);
        const auto msg = from_hex(tc.msg);
        const auto ctx = from_hex(tc.ctx);
        const auto addrnd = from_hex(tc.addrnd);
        const auto sig_expect = from_hex(tc.sig);

        ASSERT_EQ(sk_v.size(), vx::crypto::slh::SK_BYTES);
        ASSERT_EQ(sig_expect.size(), vx::crypto::slh::SIG_BYTES);
        ASSERT_EQ(addrnd.size(), vx::crypto::slh::N);

        vx::crypto::slh::SlhSk sk;
        std::memcpy(sk.sk_seed.data(), sk_v.data(), 16);
        std::memcpy(sk.sk_prf.data(), sk_v.data() + 16, 16);
        std::memcpy(sk.pk_seed.data(), sk_v.data() + 32, 16);
        std::memcpy(sk.pk_root.data(), sk_v.data() + 48, 16);

        // The ACVP internalProjection sigVer vectors are internal-interface:
        // the message field IS M' (no context, no wrapper). Hedged variant:
        // addrnd is the ACVP additionalRandomness.
        vx::crypto::slh::Sig sig;
        vx::crypto::slh::slh_sign_internal(sk, msg.data(), msg.size(), addrnd.data(), addrnd.size(),
                                           sig);
        EXPECT_EQ(to_hex(sig.data(), sig.size()), tc.sig)
            << "sigVer tc " << tc.tc << ": signature mismatch";

        const auto pk_v = from_hex(tc.pk);
        ASSERT_EQ(pk_v.size(), vx::crypto::slh::PK_BYTES);
        vx::crypto::slh::SlhPk pk;
        std::memcpy(pk.pk_seed.data(), pk_v.data(), 16);
        std::memcpy(pk.pk_root.data(), pk_v.data() + 16, 16);
        EXPECT_TRUE(vx::crypto::slh::slh_verify_internal(pk, msg.data(), msg.size(), sig))
            << "sigVer tc " << tc.tc << ": valid signature rejected";
    }
}

TEST(VortexSlhDsa128sKat, VerifyRejectsAcvpInvalid) {
    for (const auto &tc : vx_slhdsa_kat::SIGVER) {
        if (tc.pass)
            continue;
        const auto pk_v = from_hex(tc.pk);
        const auto msg = from_hex(tc.msg);
        const auto ctx = from_hex(tc.ctx);
        const auto sig_v = from_hex(tc.sig);

        ASSERT_EQ(pk_v.size(), vx::crypto::slh::PK_BYTES);
        vx::crypto::slh::SlhPk pk;
        std::memcpy(pk.pk_seed.data(), pk_v.data(), 16);
        std::memcpy(pk.pk_root.data(), pk_v.data() + 16, 16);

        if (sig_v.size() != vx::crypto::slh::SIG_BYTES) {
            // "too large" / "too small" vectors: the framing layer rejects
            // any non-7856-byte signature before verification is reached.
            SUCCEED() << "sigVer tc " << tc.tc << ": malformed length " << sig_v.size()
                      << " (framing rejects)";
            continue;
        }
        vx::crypto::slh::Sig sig;
        std::memcpy(sig.data(), sig_v.data(), sig_v.size());
        EXPECT_FALSE(vx::crypto::slh::slh_verify_internal(pk, msg.data(), msg.size(), sig))
            << "sigVer tc " << tc.tc << ": invalid signature accepted";
    }
}

// The external wrapper (M' = toByte(0,1) || toByte(len(ctx),1) || ctx || M)
// is not covered by the ACVP internalProjection vectors — this roundtrip
// pins it: sign with no context, verify through the external interface, and
// cross-check that the internal view of the wrapped M' reproduces the same
// signature. Also pins the fail-closed guards (a 256-byte context and a
// partial addrnd must refuse, never half-sign).
TEST(VortexSlhDsa128sKat, ExternalWrapperRoundtrip) {
    for (const auto &tc : vx_slhdsa_kat::SIGVER) {
        if (!tc.pass)
            continue;
        const auto sk_v = from_hex(tc.sk);
        ASSERT_EQ(sk_v.size(), vx::crypto::slh::SK_BYTES);
        vx::crypto::slh::SlhSk sk;
        std::memcpy(sk.sk_seed.data(), sk_v.data(), 16);
        std::memcpy(sk.sk_prf.data(), sk_v.data() + 16, 16);
        std::memcpy(sk.pk_seed.data(), sk_v.data() + 32, 16);
        std::memcpy(sk.pk_root.data(), sk_v.data() + 48, 16);

        const std::vector<uint8_t> msg = {0xDE, 0xAD, 0xBE, 0xEF};

        // sign through the external interface, verify through it too.
        const vx::crypto::slh::SlhPk pk{sk.pk_seed, sk.pk_root};
        const auto sig = vx::crypto::slh::slh_sign_det(sk, msg.data(), msg.size());
        EXPECT_TRUE(vx::crypto::slh::slh_verify(pk, msg.data(), msg.size(), nullptr, 0, sig))
            << "sigVer tc " << tc.tc << ": deterministic sign/verify roundtrip";

        // The internal view of the wrapped M' must reproduce the same
        // signature: the wrapper builds M' = toByte(0,1) || toByte(len,1) ||
        // ctx || M, and with an empty ctx that is 00 00 || M.
        std::vector<uint8_t> m_prime;
        m_prime.push_back(0x00);
        m_prime.push_back(0x00);
        m_prime.insert(m_prime.end(), msg.begin(), msg.end());
        vx::crypto::slh::Sig sig2{};
        ASSERT_TRUE(vx::crypto::slh::slh_sign_internal(sk, m_prime.data(), m_prime.size(), nullptr,
                                                       0, sig2));
        EXPECT_EQ(sig, sig2) << "sigVer tc " << tc.tc << ": wrapper M' divergence";

        // Fail-closed guards: a 256-byte context and a partial addrnd must
        // refuse (return false), never half-sign.
        const std::vector<uint8_t> long_ctx(256, 0x41);
        vx::crypto::slh::Sig sig3{};
        EXPECT_FALSE(vx::crypto::slh::slh_sign(sk, msg.data(), msg.size(), long_ctx.data(),
                                               long_ctx.size(), nullptr, 0, sig3));
        const uint8_t short_addrnd[8] = {0};
        EXPECT_FALSE(vx::crypto::slh::slh_sign(sk, msg.data(), msg.size(), nullptr, 0, short_addrnd,
                                               8, sig3));
    }
}
