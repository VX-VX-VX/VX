#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// VX60-SEC M2 — the 1-RTT static-ephemeral ML-KEM-768 handshake state machine
// (whitebook §4.3, owner-approved design). PURE layer: frame construction /
// parsing / key derivation with strict bounds — no sockets, fully testable.
// The swarm integration (per-packet AEAD, enforcement flip) is the next
// commit; this layer is complete and real, not a stub.
//
// Flows (I = initiator, R = responder):
//   WARM (R's static pk is in the PEX cache):
//     I → [0x10 flags=0x01 ‖ ek_I(1184) ‖ ct_static(1088)]
//     R → [0x11 flags=0x01 ‖ ct_ephem(1088)]
//     ss_static = encaps(R_pk)/decaps(dk_R); ss_ephem = encaps(ek_I)/decaps(dk_I)
//   COLD (only ip:port:node_id known — no pk cached):
//     I → [0x10 flags=0x02 ‖ ek_I(1184)]
//     R → [0x11 flags=0x02 ‖ ct_ephem(1088) ‖ AEAD(Kkem_static)]
//     I verifies sponge(pk) == node_id (from ADDRS/seed), then:
//     I → [0x12 ‖ ct_static(1088)]
//     (R decaps with dk_static → ss_static; identical KDF)
//
//   session keys = sponge("VX60-SEC-KDF-V1" ‖ ss_ephem ‖ ss_static ‖ transcript)
//   The transcript is the running hash of every handshake frame's RAW bytes
//   in order — anti-reflection, anti-downgrade (§4.3.4).
//
//   The COLD pk transfer is sealed under a domain-separated AEAD key derived
//   from ss_ephem alone: only the holder of dk_I can open it, so a MITM
//   cannot substitute its own pk without detection (and the sponge check
//   against the known node_id catches a substituted honest-looking pk).
// ─────────────────────────────────────────────────────────────────────────────

#pragma once

#include "vx/crypto/ml_kem.hpp"
#include "vx/net/vx60_identity.hpp"
#include "vx/net/vx60_aead.hpp"
#include "vx/blockchain/crypto_sponge.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <optional>
#include <vector>

namespace vx::net::vx60 {

// ── Wire type constants (consensus-critical; registered in swarm_node.hpp) ──
inline constexpr uint8_t kSecClientHello = 0x10;
inline constexpr uint8_t kSecServerHello = 0x11;
inline constexpr uint8_t kSecPkResponse = 0x12;
inline constexpr uint8_t kSecKemRotate = 0x13; // reserved for M4: strike + drop
inline constexpr uint8_t kHsFlagWarm = 0x01;
inline constexpr uint8_t kHsFlagCold = 0x02;

// SEC protocol version (hygiene 2a, owner-directed 19.11): the hello payload
// carries [flag, version(u32 LE), ...]. Rules (downgrade protection):
//   version < ours → strike + drop (an old build claiming older than ours is
//   the classic lever to force a legacy/no-SEC downgrade);
//   version > ours → neutral drop, NO strike (a newer build is not the
//   peer's fault — it just cannot interop with us yet).
inline constexpr uint32_t kSecProtoVer = 1;

// Frame sizes (fixed; parsed strictly, no trailing slack):
//   CLIENT_HELLO WARM: flags(1) ‖ ver(4) ‖ ek_I(1184) ‖ ct_static(1088) = 2277
//   CLIENT_HELLO COLD: flags(1) ‖ ver(4) ‖ ek_I(1184)                   = 1189
//   SERVER_HELLO WARM: flags(1) ‖ ver(4) ‖ ct_ephem(1088)               = 1093
//   SERVER_HELLO COLD: flags(1) ‖ ver(4) ‖ ct_ephem ‖ nonce(16) ‖
//                      sealed(pk ‖ legacy_id)(1216) ‖ tag(32)          = 2357
//   PK_RESPONSE:       ct_static(1088)                          = 1088
inline constexpr size_t kHelloWarmSize = 5 + 1184 + 1088;
inline constexpr size_t kHelloColdSize = 5 + 1184;
inline constexpr size_t kServerWarmSize = 5 + 1088;
inline constexpr size_t kServerColdSize = 5 + 1088 + 16 + 1216 + 32;
inline constexpr size_t kPkResponseSize = 1088;

// ── Domain-separated key material ───────────────────────────────────────────

inline void sponge_absorb_bytes(vx::blockchain::VortexSponge256 &s, const void *p, size_t n) {
    s.absorb(reinterpret_cast<const uint8_t *>(p), n);
}

/// The PK-seal key/nonce for the COLD flow — derived from ss_ephem ALONE
/// (the initiator's ephemeral secret is the only thing both sides hold at
/// that point).
inline void pk_seal_keys(const vx::crypto::mlkem::SharedSecret &ss_ephem, uint8_t key[32],
                         uint8_t nonce[16]) noexcept {
    vx::blockchain::VortexSponge256 s;
    sponge_absorb_bytes(s, "VX60-SEC-PKSEAL-V1", 18);
    sponge_absorb_bytes(s, ss_ephem.data(), ss_ephem.size());
    uint8_t out[48];
    s.finalize(out);
    std::memcpy(key, out, 32);
    std::memcpy(nonce, out + 32, 16);
}

/// The session keys: 32B AEAD key + per-direction 16B nonce bases, all drawn
/// from one sponge over the domain tag, BOTH shared secrets, and the
/// transcript hash. A transcript mismatch on either side yields different
/// keys — the session dies before any payload moves.
/// M3 key evolution: after VX60_REKEY_PACKETS packets in TOTAL (both
/// directions summed — symmetric on both sides by construction), both
/// peers derive the next epoch's keys from the old ones. No wire frames:
/// the rotation point is identical on both ends, counters reset per epoch,
/// and fresh nonces come from fresh bases. (Full PFS rekey with fresh KEM
/// material is the M4 rotation track.)
inline constexpr uint64_t VX60_REKEY_PACKETS = 8192;

struct SessionKeys {
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 16> nonce_c{}; // initiator → responder base
    std::array<uint8_t, 16> nonce_s{}; // responder → initiator base
    uint64_t epoch = 0;

    /// Per-packet AEAD nonce: base ‖ counter (64-bit LE, monotonic per
    /// direction). Counter exhaustion = fail-closed drop (M3 wiring).
    std::array<uint8_t, 16> packet_nonce(bool from_client, uint64_t counter) const noexcept {
        std::array<uint8_t, 16> n = from_client ? nonce_c : nonce_s;
        for (int i = 0; i < 8; ++i)
            n[8 + i] = static_cast<uint8_t>(counter >> (8 * i));
        return n;
    }
};

inline SessionKeys derive_session_keys(const vx::crypto::mlkem::SharedSecret &ss_ephem,
                                       const vx::crypto::mlkem::SharedSecret &ss_static,
                                       const std::array<uint8_t, 32> &transcript) noexcept {
    vx::blockchain::VortexSponge256 s;
    sponge_absorb_bytes(s, "VX60-SEC-KDF-V1", 15);
    sponge_absorb_bytes(s, ss_ephem.data(), ss_ephem.size());
    sponge_absorb_bytes(s, ss_static.data(), ss_static.size());
    sponge_absorb_bytes(s, transcript.data(), transcript.size());
    SessionKeys k;
    uint8_t out[64];
    s.finalize(out);
    std::memcpy(k.key.data(), out, 32);
    std::memcpy(k.nonce_c.data(), out + 32, 16);
    std::memcpy(k.nonce_s.data(), out + 48, 16);
    return k;
}

/// The next epoch's keys: domain-separated sponge chain over the old key
/// material and the epoch number. Compromising epoch N's key does NOT
/// reveal epoch N-1 (one-way sponge chain); the fresh bases retire all
/// epoch-N nonces.
inline SessionKeys derive_next_epoch(const SessionKeys &old) noexcept {
    vx::blockchain::VortexSponge256 s;
    sponge_absorb_bytes(s, "VX60-SEC-REKEY-V1", 16);
    sponge_absorb_bytes(s, old.key.data(), 32);
    sponge_absorb_bytes(s, old.nonce_c.data(), 16);
    sponge_absorb_bytes(s, old.nonce_s.data(), 16);
    const uint64_t next = old.epoch + 1;
    sponge_absorb_bytes(s, &next, 8);
    SessionKeys k;
    uint8_t out[64];
    s.finalize(out);
    std::memcpy(k.key.data(), out, 32);
    std::memcpy(k.nonce_c.data(), out + 32, 16);
    std::memcpy(k.nonce_s.data(), out + 48, 16);
    k.epoch = next;
    return k;
}

inline std::array<uint8_t, 32> transcript_hash(const std::vector<uint8_t> &a,
                                               const std::vector<uint8_t> &b,
                                               const std::vector<uint8_t> &c = {}) noexcept {
    vx::blockchain::VortexSponge256 s;
    sponge_absorb_bytes(s, "VX60-SEC-TX-V1", 14);
    sponge_absorb_bytes(s, a.data(), a.size());
    sponge_absorb_bytes(s, b.data(), b.size());
    if (!c.empty())
        sponge_absorb_bytes(s, c.data(), c.size());
    std::array<uint8_t, 32> out{};
    s.finalize(out.data());
    return out;
}

// ── Frame builders (raw bytes, exact sizes) ─────────────────────────────────

/// CLIENT_HELLO, WARM flavor: [0x10] ‖ ver(4) ‖ ek_I ‖ ct_static.
inline std::vector<uint8_t>
build_client_hello_warm(const vx::crypto::mlkem::PublicKey &ek_I,
                        const vx::crypto::mlkem::Ciphertext &ct_static) {
    std::vector<uint8_t> out;
    out.reserve(kHelloWarmSize);
    out.push_back(kHsFlagWarm);
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>(kSecProtoVer >> (8 * i)));
    out.insert(out.end(), ek_I.begin(), ek_I.end());
    out.insert(out.end(), ct_static.begin(), ct_static.end());
    return out;
}

/// CLIENT_HELLO, COLD flavor: [0x10] ‖ ver(4) ‖ ek_I.
inline std::vector<uint8_t> build_client_hello_cold(const vx::crypto::mlkem::PublicKey &ek_I) {
    std::vector<uint8_t> out;
    out.reserve(kHelloColdSize);
    out.push_back(kHsFlagCold);
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>(kSecProtoVer >> (8 * i)));
    out.insert(out.end(), ek_I.begin(), ek_I.end());
    return out;
}

/// SERVER_HELLO WARM: [0x11] ‖ ver(4) ‖ ct_ephem.
inline std::vector<uint8_t> build_server_hello_warm(const vx::crypto::mlkem::Ciphertext &ct_ephem) {
    std::vector<uint8_t> out;
    out.reserve(kServerWarmSize);
    out.push_back(kHsFlagWarm);
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>(kSecProtoVer >> (8 * i)));
    out.insert(out.end(), ct_ephem.begin(), ct_ephem.end());
    return out;
}

/// SERVER_HELLO COLD: [0x11] ‖ ver(4) ‖ ct_ephem ‖ AEAD-sealed static pk.
inline std::vector<uint8_t>
build_server_hello_cold(const vx::crypto::mlkem::Ciphertext &ct_ephem,
                        const vx::crypto::mlkem::PublicKey &static_ek,
                        const std::array<uint8_t, 32> &legacy_node_id,
                        const vx::crypto::mlkem::SharedSecret &ss_ephem) {
    uint8_t key[32], nonce[16];
    pk_seal_keys(ss_ephem, key, nonce);
    std::vector<uint8_t> out;
    out.reserve(kServerColdSize);
    out.push_back(kHsFlagCold);
    for (int i = 0; i < 4; ++i)
        out.push_back(static_cast<uint8_t>(kSecProtoVer >> (8 * i)));
    out.insert(out.end(), ct_ephem.begin(), ct_ephem.end());
    out.insert(out.end(), nonce, nonce + 16);
    // Sealed blob = the static pk BOUND to the server's legacy node_id:
    // the client verifies the binding against the id the legacy handshake
    // announced — a MITM's re-sealed pk cannot claim the victim's id.
    std::vector<uint8_t> plain;
    plain.reserve(1184 + 32);
    plain.insert(plain.end(), static_ek.begin(), static_ek.end());
    plain.insert(plain.end(), legacy_node_id.begin(), legacy_node_id.end());
    std::array<uint8_t, kAeadTagSize> tag{};
    vx60::aead_seal(key, nonce, nullptr, 0, plain.data(), plain.size(), tag.data());
    out.insert(out.end(), plain.begin(), plain.end());
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

/// PK_RESPONSE: [0x12] ‖ ct_static.
inline std::vector<uint8_t> build_pk_response(const vx::crypto::mlkem::Ciphertext &ct_static) {
    std::vector<uint8_t> out;
    out.reserve(kPkResponseSize);
    out.insert(out.end(), ct_static.begin(), ct_static.end());
    return out;
}

// ── Frame parsers (strict: exact size, exact flag) ─────────────────────────

struct ParsedClientHello {
    uint8_t flags{};
    // Filled on size+flag match even when the version check fails, so the
    // caller can distinguish "older" (strike) from "newer" (neutral drop).
    uint32_t version{};
    // True when the frame size+flag matched (version was actually read).
    // Without it, version==0 is indistinguishable from "parse never got far
    // enough" — and a zero version must map to "older" (strike), not to a
    // generic parse failure (that would recreate the downgrade lever).
    bool size_matched{};
    vx::crypto::mlkem::PublicKey ek_I{};
    std::optional<vx::crypto::mlkem::Ciphertext> ct_static;
};

// The wire TYPE rides in the 24-byte WireHeader (the swarm dispatch); the
// payload carries the FLAG byte first, then the version (u32 LE).
// Parsers validate size + flag; a different version fails the parse with
// out.version set, so the caller applies the asymmetric rule (hygiene 2a):
// peer version < ours → strike + drop (downgrade lever);
// peer version > ours → neutral drop, no strike (not the peer's fault).
inline bool parse_client_hello(const std::vector<uint8_t> &raw, ParsedClientHello &out) noexcept {
    if (raw.size() == kHelloWarmSize && raw[0] == kHsFlagWarm) {
        out.size_matched = true;
        std::memcpy(&out.version, raw.data() + 1, 4);
        if (out.version != kSecProtoVer)
            return false;
        std::memcpy(out.ek_I.data(), raw.data() + 5, 1184);
        out.ct_static.emplace();
        std::memcpy(out.ct_static->data(), raw.data() + 5 + 1184, 1088);
        out.flags = raw[0];
        return true;
    }
    if (raw.size() == kHelloColdSize && raw[0] == kHsFlagCold) {
        out.size_matched = true;
        std::memcpy(&out.version, raw.data() + 1, 4);
        if (out.version != kSecProtoVer)
            return false;
        std::memcpy(out.ek_I.data(), raw.data() + 5, 1184);
        out.ct_static.reset();
        out.flags = raw[0];
        return true;
    }
    return false;
}

struct ParsedServerHello {
    uint8_t flags{};
    // Filled on size+flag match even when the version check fails.
    uint32_t version{};
    // See ParsedClientHello::size_matched.
    bool size_matched{};
    vx::crypto::mlkem::Ciphertext ct_ephem{};
    // COLD only: the sealed blob (pk ‖ legacy_id = 1216) + AEAD nonce + tag.
    std::optional<std::array<uint8_t, 1216>> sealed_blob;
    std::array<uint8_t, 16> seal_nonce{};
    std::array<uint8_t, 32> seal_tag{};
};

inline bool parse_server_hello(const std::vector<uint8_t> &raw, ParsedServerHello &out) noexcept {
    if (raw.size() == kServerWarmSize && raw[0] == kHsFlagWarm) {
        out.size_matched = true;
        std::memcpy(&out.version, raw.data() + 1, 4);
        if (out.version != kSecProtoVer)
            return false;
        out.flags = raw[0];
        std::memcpy(out.ct_ephem.data(), raw.data() + 5, 1088);
        out.sealed_blob.reset();
        return true;
    }
    if (raw.size() == kServerColdSize && raw[0] == kHsFlagCold) {
        out.size_matched = true;
        std::memcpy(&out.version, raw.data() + 1, 4);
        if (out.version != kSecProtoVer)
            return false;
        out.flags = raw[0];
        std::memcpy(out.ct_ephem.data(), raw.data() + 5, 1088);
        std::memcpy(out.seal_nonce.data(), raw.data() + 5 + 1088, 16);
        out.sealed_blob.emplace();
        std::memcpy(out.sealed_blob->data(), raw.data() + 5 + 1088 + 16, 1216);
        std::memcpy(out.seal_tag.data(), raw.data() + 5 + 1088 + 16 + 1216, 32);
        return true;
    }
    return false;
}

inline bool parse_pk_response(const std::vector<uint8_t> &raw,
                              vx::crypto::mlkem::Ciphertext &ct_static) noexcept {
    if (raw.size() != kPkResponseSize)
        return false;
    std::memcpy(ct_static.data(), raw.data(), 1088);
    return true;
}

// ── Session establishment flows (composes frames + KDF) ─────────────────────

/// The initiator's handshake state (one per outbound attempt).
struct ClientHandshake {
    uint8_t mode = 0; // kHsFlagWarm or kHsFlagCold
    vx::crypto::mlkem::PublicKey ek_I{};
    vx::crypto::mlkem::SecretKey dk_I{};
    vx::crypto::mlkem::SharedSecret ss_static{};
    std::vector<uint8_t> my_hello;
    std::vector<uint8_t> pk_response;
    vx::crypto::mlkem::PublicKey peer_pk{}; // the VERIFIED static pk of the peer
    SessionKeys keys{};
    bool have_keys = false;

    /// WARM begin: fresh ephemeral keypair + encapsulation under R's static pk.
    bool begin_warm(const vx::crypto::mlkem::PublicKey &r_static_ek, std::string &err) {
        mode = kHsFlagWarm;
        vx::crypto::mlkem::keygen(ek_I, dk_I);
        uint8_t m32[32];
        if (::getentropy(m32, 32) != 0) {
            err = "vx60 client: CSPRNG failed";
            return false;
        }
        vx::crypto::mlkem::Ciphertext ct_static{};
        vx::crypto::mlkem::SharedSecret ss;
        if (!vx::crypto::mlkem::encaps(r_static_ek, m32, ct_static, ss)) {
            err = "vx60 client: encaps failed (bad static pk)";
            return false;
        }
        ss_static = ss;
        peer_pk = r_static_ek;
        my_hello = build_client_hello_warm(ek_I, ct_static);
        return true;
    }

    /// COLD begin: ephemeral keypair only; the static pk arrives sealed.
    bool begin_cold(std::string &err) {
        mode = kHsFlagCold;
        vx::crypto::mlkem::keygen(ek_I, dk_I);
        my_hello = build_client_hello_cold(ek_I);
        err.clear();
        return true;
    }

    /// WARM finish: decaps ct_ephem with dk_I -> ss_ephem; KDF over
    /// (my_hello || server_hello). Any parse/flag failure = no keys.
    bool finish_warm(const std::vector<uint8_t> &server_hello_raw, std::string &err) {
        ParsedServerHello sh;
        if (!parse_server_hello(server_hello_raw, sh) || sh.flags != kHsFlagWarm) {
            if (sh.size_matched && sh.version != kSecProtoVer)
                err = sh.version < kSecProtoVer ? "vx60 client: server hello version older"
                                                : "vx60 client: server hello version newer";
            else
                err = "vx60 client: server hello parse/flag failure";
            return false;
        }
        vx::crypto::mlkem::SharedSecret ss_ephem;
        vx::crypto::mlkem::decaps(dk_I, sh.ct_ephem, ss_ephem);
        const auto tx = transcript_hash(my_hello, server_hello_raw);
        keys = derive_session_keys(ss_ephem, ss_static, tx);
        have_keys = true;
        err.clear();
        return true;
    }

    /// COLD step 2: open the sealed pk from the server hello, verify
    /// sponge(pk) == expected node_id, encapsulate under it, derive keys.
    /// Returns the PK_RESPONSE frame the caller sends next.
    bool finish_cold_pk_received(const std::vector<uint8_t> &server_hello_raw,
                                 const std::array<uint8_t, 32> &expected_node_id,
                                 const std::array<uint8_t, 32> &expected_legacy_id,
                                 std::string &err) {
        ParsedServerHello sh;
        if (!parse_server_hello(server_hello_raw, sh) || sh.flags != kHsFlagCold ||
            !sh.sealed_blob.has_value()) {
            if (sh.size_matched && sh.version != kSecProtoVer)
                err = sh.version < kSecProtoVer ? "vx60 client: server hello version older"
                                                : "vx60 client: server hello version newer";
            else
                err = "vx60 client: server hello parse/flag failure (cold)";
            return false;
        }
        vx::crypto::mlkem::SharedSecret ss_ephem;
        vx::crypto::mlkem::decaps(dk_I, sh.ct_ephem, ss_ephem);
        // Open the sealed pk: the AEAD key/nonce derive from ss_ephem alone;
        // the 32-byte tag rides at the frame tail (extracted by the parser).
        uint8_t key[32], nonce[16];
        pk_seal_keys(ss_ephem, key, nonce);
        std::vector<uint8_t> plain(sh.sealed_blob->begin(), sh.sealed_blob->end());
        if (!vx60::aead_open(key, nonce, nullptr, 0, plain.data(), plain.size(),
                             sh.seal_tag.data())) {
            err = "vx60 client: sealed pk failed AEAD open";
            return false;
        }
        // The opened pk must hash to the node_id the network gave us — the
        // MITM's substituted pk fails the sponge check here. A ZERO
        // expected id = trust-on-first-use: the AEAD seal itself proves the
        // pk came from THIS connection's responder (a MITM cannot forge
        // the seal without ss_ephem), and the id gets pinned on success.
        // The sealed blob = pk(1184) ‖ legacy_id(32).
        vx::crypto::mlkem::PublicKey r_pk{};
        std::memcpy(r_pk.data(), plain.data(), 1184);
        std::array<uint8_t, 32> legacy_id{};
        std::memcpy(legacy_id.data(), plain.data() + 1184, 32);
        const bool tofu = expected_node_id == std::array<uint8_t, 32>{};
        if (!tofu && node_id_for(r_pk) != expected_node_id) {
            err = "vx60 client: pk does not hash to the expected node_id (MITM or stale)";
            return false;
        }
        // The legacy-id binding: the pk inside the sealed blob must belong
        // to the identity the legacy handshake announced — a MITM's own pk
        // (re-sealed under this connection's ss_ephem) carries ITS legacy
        // id, not the victim's, and dies here.
        const bool legacy_tofu = expected_legacy_id == std::array<uint8_t, 32>{};
        if (!legacy_tofu && legacy_id != expected_legacy_id) {
            err = "vx60 client: sealed legacy_id mismatch (MITM relay)";
            return false;
        }
        // Encapsulate under the VERIFIED pk.
        uint8_t m32[32];
        if (::getentropy(m32, 32) != 0) {
            err = "vx60 client: CSPRNG failed";
            return false;
        }
        vx::crypto::mlkem::Ciphertext ct_static{};
        vx::crypto::mlkem::SharedSecret ss;
        if (!vx::crypto::mlkem::encaps(r_pk, m32, ct_static, ss)) {
            err = "vx60 client: encaps under the sealed pk failed";
            return false;
        }
        ss_static = ss;
        peer_pk = r_pk;
        pk_response = build_pk_response(ct_static);
        const auto tx = transcript_hash(my_hello, server_hello_raw, pk_response);
        keys = derive_session_keys(ss_ephem, ss_static, tx);
        have_keys = true;
        err.clear();
        return true;
    }

    /// The client is DONE after finish_cold_pk_received: the caller sends
    /// pk_response; the keys are already derived (the transcript covers the
    /// response frame the client built itself).
};

/// The responder's handshake state (one per inbound SEC connection).
struct ServerHandshake {
    uint8_t mode = 0;
    vx::crypto::mlkem::PublicKey static_ek{}; // from the identity store
    vx::crypto::mlkem::SecretKey static_dk{};
    vx::crypto::mlkem::PublicKey ek_R{};
    vx::crypto::mlkem::SecretKey dk_R{};
    vx::crypto::mlkem::SharedSecret ss_static{};
    std::vector<uint8_t> server_hello;
    SessionKeys keys{};
    bool have_keys = false;

    std::array<uint8_t, 32> legacy_node_id_{};

    void set_static_keys(const vx::crypto::mlkem::PublicKey &ek,
                         const vx::crypto::mlkem::SecretKey &dk,
                         const std::array<uint8_t, 32> &legacy_node_id) noexcept {
        static_ek = ek;
        static_dk = dk;
        legacy_node_id_ = legacy_node_id;
    }

    /// Parse the CLIENT_HELLO and answer: WARM decaps immediately; COLD
    /// seals the static pk under the ss_ephem-derived AEAD. Returns the
    /// SERVER_HELLO frame to send. For COLD the flow is two-step: the
    /// server waits for PK_RESPONSE and calls finish_cold().
    bool begin_from_client_hello(const std::vector<uint8_t> &client_hello_raw,
                                 std::vector<uint8_t> &server_hello_out, std::string &err) {
        ParsedClientHello ch;
        if (!parse_client_hello(client_hello_raw, ch)) {
            if (ch.size_matched && ch.version != kSecProtoVer)
                err = ch.version < kSecProtoVer ? "vx60 server: client hello version older"
                                                : "vx60 server: client hello version newer";
            else
                err = "vx60 server: client hello parse failure";
            return false;
        }
        mode = ch.flags;
        vx::crypto::mlkem::keygen(ek_R, dk_R);
        if (::getentropy(m32_buf_, sizeof(m32_buf_)) != 0) {
            err = "vx60 server: CSPRNG failed";
            return false;
        }
        vx::crypto::mlkem::SharedSecret ss_ephem;
        if (!vx::crypto::mlkem::encaps(ch.ek_I, m32_buf_, ss_ephem_ct_, ss_ephem)) {
            err = "vx60 server: encaps under the client's ek_I failed";
            return false;
        }
        if (mode == kHsFlagWarm) {
            // Decaps the client's ct_static with our dk_static -> ss_static.
            if (!ch.ct_static.has_value()) {
                err = "vx60 server: warm hello without ct_static";
                return false;
            }
            vx::crypto::mlkem::decaps(static_dk, *ch.ct_static, ss_static);
            server_hello = build_server_hello_warm(ss_ephem_ct_);
            const auto tx = transcript_hash(client_hello_raw, server_hello);
            keys = derive_session_keys(ss_ephem, ss_static, tx);
            have_keys = true;
        } else {
            // Seal our static pk under the ss_ephem-derived AEAD and send it.
            server_hello =
                build_server_hello_cold(ss_ephem_ct_, static_ek, legacy_node_id_, ss_ephem);
            ss_ephem_saved_ = ss_ephem;
            my_hello_stored_ = client_hello_raw;
        }
        server_hello_out = server_hello;
        err.clear();
        return true;
    }

    /// COLD finish: decaps the PK_RESPONSE with dk_static -> ss_static; KDF.
    bool finish_cold(const std::vector<uint8_t> &pk_response_raw, std::string &err) {
        vx::crypto::mlkem::Ciphertext ct_static{};
        if (!parse_pk_response(pk_response_raw, ct_static)) {
            err = "vx60 server: pk response parse failure";
            return false;
        }
        vx::crypto::mlkem::decaps(static_dk, ct_static, ss_static);
        const auto tx = transcript_hash(my_hello_stored_, server_hello, pk_response_raw);
        keys = derive_session_keys(ss_ephem_saved_, ss_static, tx);
        have_keys = true;
        err.clear();
        return true;
    }

private:
    uint8_t m32_buf_[32]{};
    vx::crypto::mlkem::Ciphertext ss_ephem_ct_{};
    vx::crypto::mlkem::SharedSecret ss_ephem_saved_{};
    std::vector<uint8_t> my_hello_stored_{};
};

// ── Session AEAD wrappers (per-direction nonce + counter; M3 wires the
// counter discipline into the transport loops — the primitives are real) ────
inline void session_seal(const SessionKeys &k, bool from_client, uint64_t counter,
                         const uint8_t *ad, size_t ad_len, uint8_t *payload, size_t len,
                         uint8_t tag[kAeadTagSize]) noexcept {
    const auto nonce = k.packet_nonce(from_client, counter);
    aead_seal(k.key.data(), nonce.data(), ad, ad_len, payload, len, tag);
}

inline bool session_open(const SessionKeys &k, bool from_client, uint64_t counter,
                         const uint8_t *ad, size_t ad_len, uint8_t *payload, size_t len,
                         const uint8_t tag[kAeadTagSize]) noexcept {
    const auto nonce = k.packet_nonce(from_client, counter);
    // Zero-on-tag-failure is inside aead_open (M1's RUP guarantee).
    return aead_open(k.key.data(), nonce.data(), ad, ad_len, payload, len, tag);
}

} // namespace vx::net::vx60
