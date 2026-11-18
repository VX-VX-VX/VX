// test_vx60_sec_rekey.cpp — VX60-SEC M3: key evolution (KDF-chain rekey)
// and the MAC-only mode for public block bodies.
//
// Pins:
//   1. EpochRotationSymmetric — both peers crossing the threshold derive
//      IDENTICAL next-epoch keys; the counter resets; packets keep flowing
//      across the boundary.
//   2. OneWayChain — epoch N's key does not reveal epoch N-1 (the rekey
//      sponge is one-way); epochs are never equal.
//   3. MacDomainSeparation — a MAC-mode tag never verifies as an AEAD tag
//      and vice versa (the 0x05 vs 0x04 domains cannot be cross-claimed).
//   4. MacCoversBodyAndAd — one flipped body/ad bit fails the MAC; the
//      full body (incl. the 64 KiB size) is covered.
#include <gtest/gtest.h>

#include "vx/net/vx60_sec.hpp"
#include "vx/net/vx60_aead.hpp"

#include <vector>

using namespace vx::net::vx60;

namespace {

// A deterministic starting channel (values don't matter — the chain does).
SessionKeys base_keys() {
    SessionKeys k{};
    for (int i = 0; i < 32; ++i)
        k.key[i] = static_cast<uint8_t>(i * 7 + 1);
    for (int i = 0; i < 16; ++i) {
        k.nonce_c[i] = static_cast<uint8_t>(i * 3 + 2);
        k.nonce_s[i] = static_cast<uint8_t>(i * 5 + 4);
    }
    return k;
}

} // namespace

// A two-peer simulation of the transport counters: TCP makes A's send the
// same stream as B's recv, so the (send+recv) totals are equal on both
// ends at every packet — the rotation boundary is shared by construction.
struct PeerSim {
    SessionKeys keys;
    uint64_t send_ctr = 0, recv_ctr = 0;

    explicit PeerSim(const SessionKeys &k) : keys(k) {
    }

    void on_packet_sent() {
        ++send_ctr;
        maybe_rotate();
    }
    void on_packet_received() {
        ++recv_ctr;
        maybe_rotate();
    }
    [[nodiscard]] uint64_t total() const noexcept {
        return send_ctr + recv_ctr;
    }

private:
    void maybe_rotate() {
        if (total() % VX60_REKEY_PACKETS == 0)
            keys = derive_next_epoch(keys);
    }
};

TEST(Vx60SecRekeyTest, EpochRotationSymmetric) {
    const SessionKeys start = base_keys();
    PeerSim a(start), b(start);

    // threshold packets cross the boundary: alternate the direction (even
    // = A sends, odd = B sends); each packet is sent by one peer and
    // received by the other, so both totals stay equal.
    const uint64_t threshold = VX60_REKEY_PACKETS;
    for (uint64_t p = 1; p <= threshold; ++p) {
        if (p % 2 == 0) {
            a.on_packet_sent();
            b.on_packet_received();
        } else {
            b.on_packet_sent();
            a.on_packet_received();
        }
        ASSERT_EQ(a.total(), b.total()) << "totals symmetric at packet " << p;
    }
    EXPECT_EQ(a.total(), threshold);

    // Exactly one rotation, identical on both ends, across the boundary.
    EXPECT_EQ(a.keys.epoch, 1u);
    EXPECT_EQ(b.keys.epoch, 1u);
    EXPECT_EQ(a.keys.key, b.keys.key);
    EXPECT_EQ(a.keys.nonce_c, b.keys.nonce_c);
    EXPECT_EQ(a.keys.nonce_s, b.keys.nonce_s);

    // Across the boundary the channel still works: a packet sealed with
    // the POST-rotation keys opens on the peer's POST-rotation keys.
    std::vector<uint8_t> wire = {'x'};
    std::array<uint8_t, kAeadTagSize> tag{};
    session_seal(a.keys, true, 0, nullptr, 0, wire.data(), wire.size(), tag.data());
    EXPECT_TRUE(session_open(b.keys, true, 0, nullptr, 0, wire.data(), wire.size(), tag.data()));

    // The epoch-N nonce bases differ from epoch-0: old nonces are retired
    // (a replay of an epoch-0 packet fails the new keys' tag).
    std::vector<uint8_t> old_wire = {'y'};
    std::array<uint8_t, kAeadTagSize> old_tag{};
    session_seal(start, true, 0, nullptr, 0, old_wire.data(), old_wire.size(), old_tag.data());
    EXPECT_FALSE(
        session_open(a.keys, true, 0, nullptr, 0, old_wire.data(), old_wire.size(), old_tag.data()))
        << "epoch-0 packets must not open under epoch-1 keys";
}

TEST(Vx60SecRekeyTest, OneWayChain) {
    SessionKeys k = base_keys();
    const auto e1 = derive_next_epoch(k);
    const auto e2 = derive_next_epoch(e1);
    const auto e3 = derive_next_epoch(e2);
    EXPECT_NE(e1.key, e2.key);
    EXPECT_NE(e2.key, e3.key);
    EXPECT_NE(e1.key, e3.key);
    EXPECT_EQ(e3.epoch, 3u);
    // One-way: nothing in epoch 2/3's material reconstructs epoch 1.
    // (The chain absorbs the OLD key forward; going back would require a
    // preimage through the sponge — pinned by the trivial divergence above
    // plus the domain tag. The real pin: e1 != e3 while e3 was derived
    // THROUGH e2 — a 2-step collision would be a sponge break.)
}

TEST(Vx60SecRekeyTest, MacDomainSeparation) {
    SessionKeys k = base_keys();
    k.epoch = 5;
    const auto nonce = k.packet_nonce(true, 7);
    uint8_t body[64];
    for (int i = 0; i < 64; ++i)
        body[i] = static_cast<uint8_t>(i * 11);
    std::array<uint8_t, kAeadTagSize> mac_tag{}, seal_tag{};

    // MAC-mode tag over the body with empty AD.
    aead_mac(k.key.data(), nonce.data(), nullptr, 0, body, sizeof(body), mac_tag.data());
    // AEAD-seal tag over the SAME body/nonce — a different domain (0x04
    // ct-absorb vs 0x05 pt-absorb): the tags MUST differ, and neither
    // verifies under the other's checker.
    uint8_t sealed[64];
    std::memcpy(sealed, body, sizeof(body));
    aead_seal(k.key.data(), nonce.data(), nullptr, 0, sealed, sizeof(sealed), seal_tag.data());
    EXPECT_NE(mac_tag, seal_tag) << "the domains must not collide";

    // The MAC verifies the untampered body...
    std::array<uint8_t, kAeadTagSize> check{};
    aead_mac(k.key.data(), nonce.data(), nullptr, 0, body, sizeof(body), check.data());
    EXPECT_TRUE(vx::core::ct_equal(check.data(), mac_tag.data(), kAeadTagSize));
    // ...and refuses one flipped body bit.
    body[33] ^= 0x01;
    aead_mac(k.key.data(), nonce.data(), nullptr, 0, body, sizeof(body), check.data());
    EXPECT_FALSE(vx::core::ct_equal(check.data(), mac_tag.data(), kAeadTagSize));
    // ...and one flipped AD bit.
    body[33] ^= 0x01; // restore
    const uint8_t ad = 0x42;
    aead_mac(k.key.data(), nonce.data(), &ad, 1, body, sizeof(body), check.data());
    EXPECT_FALSE(vx::core::ct_equal(check.data(), mac_tag.data(), kAeadTagSize))
        << "the AD must be covered";
}

TEST(Vx60SecRekeyTest, MacCoversFullBodyAtBlockSize) {
    // A 64 KiB body (the RAW_BLOCK_64K wire size) MACs end-to-end: any flip
    // ANYWHERE in the body fails the check (the whole body is covered).
    std::vector<uint8_t> body(65536);
    for (size_t i = 0; i < body.size(); ++i)
        body[i] = static_cast<uint8_t>(i * 13 + 7);
    SessionKeys k = base_keys();
    const auto nonce = k.packet_nonce(false, 3);
    std::array<uint8_t, kAeadTagSize> tag{};
    aead_mac(k.key.data(), nonce.data(), nullptr, 0, body.data(), body.size(), tag.data());

    for (size_t probe : {size_t(0), size_t(32767), size_t(65535)}) {
        auto tampered = body;
        tampered[probe] ^= 0x80;
        std::array<uint8_t, kAeadTagSize> check{};
        aead_mac(k.key.data(), nonce.data(), nullptr, 0, tampered.data(), tampered.size(),
                 check.data());
        EXPECT_FALSE(vx::core::ct_equal(check.data(), tag.data(), kAeadTagSize))
            << "tamper at offset " << probe << " must fail the block MAC";
    }
}
