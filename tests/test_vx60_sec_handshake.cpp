// test_vx60_sec_handshake.cpp — VX60-SEC M2 handshake state machine
// (whitebook §4.3). Pins: happy WARM/COLD, key equality both sides,
// transcript binding (tamper anywhere → keys diverge → session dies),
// COLD MITM (pk not hashing to the expected node_id → refused), the
// KEM-PoP property (a server without dk_static cannot establish the
// session the client derives), and strict frame parsing.
#include <gtest/gtest.h>

#include "vx/net/vx60_sec.hpp"
#include "vx/net/vx60_identity.hpp"

#include <cstring>
#include <filesystem>
#include <string>

using namespace vx::net::vx60;

namespace {

std::string tmp_dir(const char *tag) {
    auto dir = std::filesystem::temp_directory_path() /
               (std::string(tag) + "_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    return dir.string();
}

// A booted identity in a throwaway dir.
struct IdFixture {
    TransportIdentity id{};
    std::string dir;
    std::string err;

    explicit IdFixture(const char *tag) : dir(tmp_dir(tag)) {
        if (!TransportIdentityStore::load_or_create(dir, id, err))
            ADD_FAILURE() << err;
    }
    ~IdFixture() {
        std::filesystem::remove_all(dir);
    }
};

} // namespace

// ── WARM happy path: keys equal on both sides ───────────────────────────────
TEST(Vx60SecHandshakeTest, WarmHandshakeKeysMatch) {
    IdFixture srv_id("vx_sec_warm_srv");
    ServerHandshake server;
    server.set_static_keys(srv_id.id.static_ek, srv_id.id.static_dk, srv_id.id.node_id);

    ClientHandshake client;
    std::string err;
    ASSERT_TRUE(client.begin_warm(srv_id.id.static_ek, err)) << err;

    std::vector<uint8_t> server_hello;
    ASSERT_TRUE(server.begin_from_client_hello(client.my_hello, server_hello, err)) << err;

    ASSERT_TRUE(client.finish_warm(server_hello, err)) << err;
    ASSERT_TRUE(server.have_keys);
    ASSERT_TRUE(client.have_keys);

    // Key equality: the whole point of the exchange.
    EXPECT_EQ(client.keys.key, server.keys.key);
    EXPECT_EQ(client.keys.nonce_c, server.keys.nonce_c);
    EXPECT_EQ(client.keys.nonce_s, server.keys.nonce_s);

    // The channel works: a client-sealed packet opens on the server side,
    // and a server-sealed packet opens on the client side (counter 0).
    const std::vector<uint8_t> plain = {'p', 'i', 'n', 'g'};
    std::vector<uint8_t> wire = plain; // sealed in place
    std::array<uint8_t, kAeadTagSize> tag{};
    session_seal(client.keys, /*from_client=*/true, 0, nullptr, 0, wire.data(), wire.size(),
                 tag.data());
    EXPECT_TRUE(
        session_open(server.keys, true, 0, nullptr, 0, wire.data(), wire.size(), tag.data()));
    EXPECT_EQ(wire, plain) << "the client-sealed packet must open on the server";

    // The responder's own direction uses its nonce base.
    const std::vector<uint8_t> resp_plain = {'o', 'k'};
    std::vector<uint8_t> resp_wire = resp_plain;
    session_seal(server.keys, false, 0, nullptr, 0, resp_wire.data(), resp_wire.size(), tag.data());
    EXPECT_TRUE(session_open(client.keys, false, 0, nullptr, 0, resp_wire.data(), resp_wire.size(),
                             tag.data()));
    EXPECT_EQ(resp_wire, resp_plain) << "the server-sealed packet must open on the client";
}

// ── COLD happy path: sealed pk transfer + sponge check ──────────────────────
TEST(Vx60SecHandshakeTest, ColdHandshakeKeysMatch) {
    IdFixture srv_id("vx_sec_cold_srv");
    ServerHandshake server;
    server.set_static_keys(srv_id.id.static_ek, srv_id.id.static_dk, srv_id.id.node_id);

    ClientHandshake client;
    std::string err;
    ASSERT_TRUE(client.begin_cold(err)) << err;

    std::vector<uint8_t> server_hello;
    ASSERT_TRUE(server.begin_from_client_hello(client.my_hello, server_hello, err)) << err;
    ASSERT_EQ(server_hello.size(), kServerColdSize);

    // The client knows the peer's node_id from ADDRS/seeds.
    // The transport id is known here (the test pinned it) and the legacy
    // id must match what the server announced.
    ASSERT_TRUE(
        client.finish_cold_pk_received(server_hello, srv_id.id.node_id, srv_id.id.node_id, err))
        << err;
    ASSERT_TRUE(client.have_keys);

    // The response rides back and completes the server side.
    ASSERT_TRUE(server.finish_cold(client.pk_response, err)) << err;
    ASSERT_TRUE(server.have_keys);

    EXPECT_EQ(client.keys.key, server.keys.key);
    EXPECT_EQ(client.keys.nonce_c, server.keys.nonce_c);
    EXPECT_EQ(client.keys.nonce_s, server.keys.nonce_s);
}

// ── COLD MITM: a pk that does not hash to the expected node_id dies ─────────
TEST(Vx60SecHandshakeTest, ColdMitmPkSubstitutionRefused) {
    IdFixture srv_a("vx_sec_mitm_a");
    IdFixture srv_b("vx_sec_mitm_b"); // the MITM's own identity (B in place of A)

    ServerHandshake attacker; // B answers where the client expects A
    attacker.set_static_keys(srv_b.id.static_ek, srv_b.id.static_dk, srv_b.id.node_id);

    ClientHandshake client;
    std::string err;
    ASSERT_TRUE(client.begin_cold(err)) << err;
    std::vector<uint8_t> server_hello;
    ASSERT_TRUE(attacker.begin_from_client_hello(client.my_hello, server_hello, err)) << err;

    // The client expects A's node_id (from ADDRS/seed); B's sealed pk opens
    // fine (the AEAD key is this connection's ss_ephem — B did encapsulate
    // under the client's ek_I) but fails the sponge check.
    // A MITM relays B's sealed pk where the client dialed A: BOTH the
    // sponge pin and the legacy-id binding die.
    EXPECT_FALSE(
        client.finish_cold_pk_received(server_hello, srv_a.id.node_id, srv_a.id.node_id, err));
    EXPECT_NE(err.find("does not hash to the expected node_id"), std::string::npos) << err;
    EXPECT_FALSE(client.have_keys);
}

// ── Transcript binding: any tampered handshake byte kills the session ───────
TEST(Vx60SecHandshakeTest, TranscriptTamperKillsSession) {
    IdFixture srv_id("vx_sec_tamper_srv");
    ServerHandshake server;
    server.set_static_keys(srv_id.id.static_ek, srv_id.id.static_dk, srv_id.id.node_id);

    ClientHandshake client;
    std::string err;
    ASSERT_TRUE(client.begin_warm(srv_id.id.static_ek, err)) << err;

    std::vector<uint8_t> server_hello;
    ASSERT_TRUE(server.begin_from_client_hello(client.my_hello, server_hello, err)) << err;

    // The client finishes over the ORIGINAL hello; the server processed a
    // TAMPERED copy (one ek byte flipped — as if a MITM edited it in flight).
    ASSERT_TRUE(client.finish_warm(server_hello, err)) << err;
    ParsedClientHello ch;
    ASSERT_TRUE(parse_client_hello(client.my_hello, ch));
    auto tampered = client.my_hello;
    tampered[1 + 1184 + 100] ^= 0x01; // inside ct_static: parses fine,
                                      // decaps diverges (implicit rejection)
    std::vector<uint8_t> server_hello_t;
    ServerHandshake server_t;
    server_t.set_static_keys(srv_id.id.static_ek, srv_id.id.static_dk, srv_id.id.node_id);
    ASSERT_TRUE(server_t.begin_from_client_hello(tampered, server_hello_t, err)) << err;
    ASSERT_TRUE(server_t.have_keys);

    // Keys diverged (different transcripts): a client-sealed packet fails
    // to open on the tampered-server side.
    std::vector<uint8_t> payload = {'x'};
    std::array<uint8_t, kAeadTagSize> tag{};
    session_seal(client.keys, true, 0, nullptr, 0, payload.data(), payload.size(), tag.data());
    EXPECT_FALSE(session_open(server_t.keys, true, 0, nullptr, 0, payload.data(), payload.size(),
                              tag.data()));
}

// ── KEM-PoP: no dk_static, no session ───────────────────────────────────────
TEST(Vx60SecHandshakeTest, KemPopRequiresTheStaticKey) {
    IdFixture srv_id("vx_sec_pop_srv");
    ClientHandshake client;
    std::string err;
    ASSERT_TRUE(client.begin_warm(srv_id.id.static_ek, err)) << err;

    // An impostor WITHOUT dk_static decaps the client's ct_static with a
    // random key: it yields a garbage ss_static, so ITS session keys differ
    // from the client's — the impostor can read nothing and can inject
    // nothing (every packet fails the AEAD tag).
    vx::crypto::mlkem::SecretKey wrong_dk;
    wrong_dk.fill(0x77);
    vx::crypto::mlkem::SharedSecret ss_fake;
    ParsedClientHello ch;
    ASSERT_TRUE(parse_client_hello(client.my_hello, ch));
    ASSERT_TRUE(ch.ct_static.has_value());
    vx::crypto::mlkem::decaps(wrong_dk, *ch.ct_static, ss_fake);
    const auto tx = transcript_hash(client.my_hello, {}); // impostor's transcript attempt
    const auto fake_keys = derive_session_keys(ss_fake, ss_fake, tx);
    EXPECT_NE(fake_keys.key, client.keys.key) << "the impostor must not derive the session key";

    // And the REAL server (holding dk_static) derives the SAME keys as the
    // client — the PoP property in the positive direction.
    ServerHandshake server;
    server.set_static_keys(srv_id.id.static_ek, srv_id.id.static_dk, srv_id.id.node_id);
    std::vector<uint8_t> server_hello;
    ASSERT_TRUE(server.begin_from_client_hello(client.my_hello, server_hello, err)) << err;
    ASSERT_TRUE(client.finish_warm(server_hello, err)) << err;
    EXPECT_EQ(client.keys.key, server.keys.key);
}

// ── Strict parsers: wrong sizes/types/flags are refused ─────────────────────
TEST(Vx60SecHandshakeTest, FrameParsersStrict) {
    ParsedClientHello ch;
    EXPECT_FALSE(parse_client_hello({}, ch));
    EXPECT_FALSE(parse_client_hello(std::vector<uint8_t>(2300, 0x10), ch)); // wrong size
    std::vector<uint8_t> cold_bad = build_client_hello_cold({});
    cold_bad[0] = 0x07; // valid size, invalid flag
    EXPECT_FALSE(parse_client_hello(cold_bad, ch));

    ParsedServerHello sh;
    EXPECT_FALSE(parse_server_hello({}, sh));
    auto warm = build_server_hello_warm({});
    warm.push_back(0x00); // trailing slack → exact-size rule fires
    EXPECT_FALSE(parse_server_hello(warm, sh));
    vx::crypto::mlkem::Ciphertext ct{};
    EXPECT_FALSE(parse_pk_response({}, ct));
    EXPECT_FALSE(parse_pk_response(std::vector<uint8_t>(1087, 0x12), ct)); // short
    // The wire TYPE rides in the header: the parser is type-agnostic by design.
    EXPECT_TRUE(parse_pk_response(std::vector<uint8_t>(1088, 0x12), ct));
}

// ── Session counters: per-direction nonces differ, counters advance ─────────
TEST(Vx60SecHandshakeTest, PacketNonceDirectionAndCounter) {
    SessionKeys k{};
    k.nonce_c.fill(0xAA);
    k.nonce_s.fill(0xBB);
    const auto nc0 = k.packet_nonce(true, 0);
    const auto nc1 = k.packet_nonce(true, 1);
    const auto ns0 = k.packet_nonce(false, 0);
    EXPECT_NE(nc0, ns0) << "directions must not share a nonce space";
    EXPECT_NE(nc0, nc1) << "the counter must move the nonce";
    for (int i = 0; i < 8; ++i) {
        EXPECT_EQ(nc0[8 + i], 0x00) << "counter bytes are the low half";
        EXPECT_EQ(nc0[i], 0xAA) << "the base is the high half";
    }
}
