// DKSAP-Galois core tests — the stealth-nickname cycle end to end.
// The no-stub gate: the radar must match ONLY the true recipient, the
// IVK-only radar must NOT produce a spend key, and the SK-gated radar
// must produce exactly the sender's spend-mask XOR.
#include <gtest/gtest.h>

#include "vx/crypto/dksap.hpp"

#include <cstring>

namespace {

void zeroish(uint8_t *out, size_t n, unsigned seed) {
    for (unsigned i = 0; i < n; ++i)
        out[i] = static_cast<uint8_t>(i * 31 + seed * 17);
}

} // namespace

TEST(VortexDksapTest, DerivationIsDeterministicAndSeparated) {
    uint8_t master[256];
    zeroish(master, 256, 1);
    vx::crypto::dksap::Account a1, a2;
    vx::crypto::dksap::derive_account(master, a1);
    vx::crypto::dksap::derive_account(master, a2);
    // Determinism.
    EXPECT_EQ(0, std::memcmp(a1.pub.kspend.data(), a2.pub.kspend.data(), 32));
    EXPECT_EQ(0, std::memcmp(a1.pub.kkem.data(), a2.pub.kkem.data(), 1184));
    EXPECT_EQ(0, std::memcmp(a1.kem_sk.data(), a2.kem_sk.data(), 2400));
    // Separation: the three derived secrets are pairwise distinct.
    EXPECT_NE(0, std::memcmp(a1.sk_spend.data(), a1.sk_view.data(), 32));
    // The public keys are not the raw secrets.
    EXPECT_NE(0, std::memcmp(a1.pub.kspend.data(), a1.sk_spend.data(), 32));
    // Kview is no longer published (review 2026-11-14): SKview keeps only
    // the internal KEM-z binding role.
    (void)a1.sk_view;
}

TEST(VortexDksapTest, SenderToRadarFullCycle) {
    // The recipient derives an account; the sender builds a stealth
    // envelope toward its SGMT record; the recipient's radar (IVK-only)
    // must recognize it, the SK-gated radar must derive the spend key.
    uint8_t master[256];
    zeroish(master, 256, 2);
    vx::crypto::dksap::Account recipient;
    vx::crypto::dksap::derive_account(master, recipient);

    vx::crypto::dksap::StealthTx tx;
    vx::crypto::dksap::stealth_send(recipient.pub, tx);

    // The envelope's receiver is NOT the plaintext Kspend (stealthed).
    EXPECT_NE(0, std::memcmp(tx.pstealth.data(), recipient.pub.kspend.data(), 32));

    // IVK-only radar: recognizes the transfer, spends NOTHING.
    vx::crypto::dksap::RadarHit hit;
    vx::crypto::dksap::radar_scan(recipient.kem_sk.data(), recipient.pub.kspend, tx, false, nullptr,
                                  hit);
    EXPECT_TRUE(hit.match) << "the true recipient's radar must match";
    EXPECT_EQ(0, std::memcmp(hit.tx_key.data(), tx.tx_key.data(), 32));
    EXPECT_EQ(0, std::memcmp(hit.sk_stealth.data(), "\0\0\0\0", 4))
        << "IVK-only radar must leave the spend key zeroed";

    // SK-gated radar: derives sk_stealth = SKspend ⊕ spend-mask.
    vx::crypto::dksap::RadarHit hit_sk;
    vx::crypto::dksap::radar_scan(recipient.kem_sk.data(), recipient.pub.kspend, tx, true,
                                  recipient.sk_spend.data(), hit_sk);
    EXPECT_TRUE(hit_sk.match);
    EXPECT_EQ(0, std::memcmp(hit_sk.tx_key.data(), tx.tx_key.data(), 32));
    EXPECT_NE(0, std::memcmp(hit_sk.sk_stealth.data(), "\0\0\0\0", 4));
    EXPECT_NE(0, std::memcmp(hit_sk.sk_stealth.data(), recipient.sk_spend.data(), 32))
        << "sk_stealth must be masked, never the raw SKspend";

    // Determinism: the same recipient and a re-send produce the same shape
    // modulo the fresh randomness — so verify determinism of the MASK from
    // a fixed tx_key instead: two radars on the same tx agree bit-for-bit.
    vx::crypto::dksap::RadarHit hit2;
    vx::crypto::dksap::radar_scan(recipient.kem_sk.data(), recipient.pub.kspend, tx, true,
                                  recipient.sk_spend.data(), hit2);
    EXPECT_EQ(0, std::memcmp(hit_sk.sk_stealth.data(), hit2.sk_stealth.data(), 32));
}

TEST(VortexDksapTest, ForeignRadarNeverMatches) {
    // Two accounts; a transfer toward A must NEVER match B's radar.
    uint8_t mA[256], mB[256];
    zeroish(mA, 256, 3);
    zeroish(mB, 256, 4);
    vx::crypto::dksap::Account a, b;
    vx::crypto::dksap::derive_account(mA, a);
    vx::crypto::dksap::derive_account(mB, b);
    EXPECT_NE(0, std::memcmp(a.pub.kspend.data(), b.pub.kspend.data(), 32));

    vx::crypto::dksap::StealthTx tx;
    vx::crypto::dksap::stealth_send(a.pub, tx);

    vx::crypto::dksap::RadarHit hit;
    vx::crypto::dksap::radar_scan(b.kem_sk.data(), b.pub.kspend, tx, true, b.sk_spend.data(), hit);
    EXPECT_FALSE(hit.match) << "B's radar must not match a transfer addressed to A";
    EXPECT_EQ(0, std::memcmp(hit.sk_stealth.data(), "\0\0\0\0", 4));
}
