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
#include "vx/core/ct_equal.hpp"

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

// Frame sizes (fixed; parsed strictly, no trailing slack):
//   CLIENT_HELLO WARM: flags(1) ‖ ek_I(1184) ‖ ct_static(1088) = 2273
//   CLIENT_HELLO COLD: flags(1) ‖ ek_I(1184)                   = 1185
//   SERVER_HELLO WARM: flags(1) ‖ ct_ephem(1088)               = 1089
//   SERVER_HELLO COLD: flags(1) ‖ ct_ephem ‖ nonce(16) ‖
//                      sealed_pk(1184) ‖ tag(32)               = 2321
//   PK_RESPONSE:       ct_static(1088)                          = 1088
inline constexpr size_t kHelloWarmSize = 1 + 1184 + 1088;
inline constexpr size_t kHelloColdSize = 1 + 1184;
inline constexpr size_t kServerWarmSize = 1 + 1088;
inline constexpr size_t kServerColdSize = 1 + 1088 + 16 + 1184 + 32;
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
struct SessionKeys {
    std::array<uint8_t, 32> key{};
    std::array<uint8_t, 16> nonce_c{}; // initiator → responder base
    std::array<uint8_t, 16> nonce_s{}; // responder → initiator base

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

/// CLIENT_HELLO, WARM flavor: [0x10] ‖ [0x01] ‖ ek_I ‖ ct_static.
inline std::vector<uint8_t>
build_client_hello_warm(const vx::crypto::mlkem::PublicKey &ek_I,
                        const vx::crypto::mlkem::Ciphertext &ct_static) {
    std::vector<uint8_t> out;
    out.reserve(1 + kHelloWarmSize);
    out.push_back(kSecClientHello);
    out.push_back(kHsFlagWarm);
    out.insert(out.end(), ek_I.begin(), ek_I.end());
    out.insert(out.end(), ct_static.begin(), ct_static.end());
    return out;
}

/// CLIENT_HELLO, COLD flavor: [0x10] ‖ [0x02] ‖ ek_I.
inline std::vector<uint8_t> build_client_hello_cold(const vx::crypto::mlkem::PublicKey &ek_I) {
    std::vector<uint8_t> out;
    out.reserve(1 + kHelloColdSize);
    out.push_back(kSecClientHello);
    out.push_back(kHsFlagCold);
    out.insert(out.end(), ek_I.begin(), ek_I.end());
    return out;
}

/// SERVER_HELLO WARM: [0x11] ‖ [0x01] ‖ ct_ephem.
inline std::vector<uint8_t> build_server_hello_warm(const vx::crypto::mlkem::Ciphertext &ct_ephem) {
    std::vector<uint8_t> out;
    out.reserve(1 + kServerWarmSize);
    out.push_back(kSecServerHello);
    out.push_back(kHsFlagWarm);
    out.insert(out.end(), ct_ephem.begin(), ct_ephem.end());
    return out;
}

/// SERVER_HELLO COLD: [0x11] ‖ [0x02] ‖ ct_ephem ‖ AEAD-sealed static pk.
inline std::vector<uint8_t>
build_server_hello_cold(const vx::crypto::mlkem::Ciphertext &ct_ephem,
                        const vx::crypto::mlkem::PublicKey &static_ek,
                        const vx::crypto::mlkem::SharedSecret &ss_ephem) {
    uint8_t key[32], nonce[16];
    pk_seal_keys(ss_ephem, key, nonce);
    std::vector<uint8_t> out;
    out.reserve(1 + kServerColdSize);
    out.push_back(kSecServerHello);
    out.push_back(kHsFlagCold);
    out.insert(out.end(), ct_ephem.begin(), ct_ephem.end());
    out.insert(out.end(), nonce, nonce + 16);
    std::vector<uint8_t> plain(static_ek.begin(), static_ek.end());
    std::array<uint8_t, kAeadTagSize> tag{};
    vx60::aead_seal(key, nonce, nullptr, 0, plain.data(), plain.size(), tag.data());
    out.insert(out.end(), plain.begin(), plain.end());
    out.insert(out.end(), tag.begin(), tag.end());
    return out;
}

/// PK_RESPONSE: [0x12] ‖ ct_static.
inline std::vector<uint8_t> build_pk_response(const vx::crypto::mlkem::Ciphertext &ct_static) {
    std::vector<uint8_t> out;
    out.reserve(1 + kPkResponseSize);
    out.push_back(kSecPkResponse);
    out.insert(out.end(), ct_static.begin(), ct_static.end());
    return out;
}

// ── Frame parsers (strict: exact size, exact flag) ─────────────────────────

struct ParsedClientHello {
    uint8_t flags{};
    vx::crypto::mlkem::PublicKey ek_I{};
    std::optional<vx::crypto::mlkem::Ciphertext> ct_static;
};

inline bool parse_client_hello(const std::vector<uint8_t> &raw, ParsedClientHello &out) noexcept {
    if (raw.empty() || raw[0] != kSecClientHello)
        return false;
    if (raw.size() == 1 + kHelloWarmSize && raw[1] == kHsFlagWarm) {
        std::memcpy(out.ek_I.data(), raw.data() + 2, 1184);
        out.ct_static.emplace();
        std::memcpy(out.ct_static->data(), raw.data() + 2 + 1184, 1088);
        out.flags = raw[1];
        return true;
    }
    if (raw.size() == 1 + kHelloColdSize && raw[1] == kHsFlagCold) {
        std::memcpy(out.ek_I.data(), raw.data() + 2, 1184);
        out.ct_static.reset();
        out.flags = raw[1];
        return true;
    }
    return false;
}

struct ParsedServerHello {
    uint8_t flags{};
    vx::crypto::mlkem::Ciphertext ct_ephem{};
    // COLD only: the sealed static pk + AEAD nonce + tag.
    std::optional<vx::crypto::mlkem::PublicKey> sealed_pk;
    std::array<uint8_t, 16> seal_nonce{};
    std::array<uint8_t, 32> seal_tag{};
};

inline bool parse_server_hello(const std::vector<uint8_t> &raw, ParsedServerHello &out) noexcept {
    if (raw.empty() || raw[0] != kSecServerHello)
        return false;
    if (raw.size() == 1 + kServerWarmSize && raw[1] == kHsFlagWarm) {
        out.flags = raw[1];
        std::memcpy(out.ct_ephem.data(), raw.data() + 2, 1088);
        out.sealed_pk.reset();
        return true;
    }
    if (raw.size() == 1 + kServerColdSize && raw[1] == kHsFlagCold) {
        out.flags = raw[1];
        std::memcpy(out.ct_ephem.data(), raw.data() + 2, 1088);
        std::memcpy(out.seal_nonce.data(), raw.data() + 2 + 1088, 16);
        out.sealed_pk.emplace();
        std::memcpy(out.sealed_pk->data(), raw.data() + 2 + 1088 + 16, 1184);
        std::memcpy(out.seal_tag.data(), raw.data() + 2 + 1088 + 16 + 1184, 32);
        return true;
    }
    return false;
}

inline bool parse_pk_response(const std::vector<uint8_t> &raw,
                              vx::crypto::mlkem::Ciphertext &ct_static) noexcept {
    if (raw.size() != 1 + kPkResponseSize || raw[0] != kSecPkResponse)
        return false;
    std::memcpy(ct_static.data(), raw.data() + 1, 1088);
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
                                 std::string &err) {
        ParsedServerHello sh;
        if (!parse_server_hello(server_hello_raw, sh) || sh.flags != kHsFlagCold ||
            !sh.sealed_pk.has_value()) {
            err = "vx60 client: server hello parse/flag failure (cold)";
            return false;
        }
        vx::crypto::mlkem::SharedSecret ss_ephem;
        vx::crypto::mlkem::decaps(dk_I, sh.ct_ephem, ss_ephem);
        // Open the sealed pk: the AEAD key/nonce derive from ss_ephem alone;
        // the 32-byte tag rides at the frame tail (extracted by the parser).
        uint8_t key[32], nonce[16];
        pk_seal_keys(ss_ephem, key, nonce);
        std::vector<uint8_t> plain(sh.sealed_pk->begin(), sh.sealed_pk->end());
        if (!vx60::aead_open(key, nonce, nullptr, 0, plain.data(), plain.size(),
                             sh.seal_tag.data())) {
            err = "vx60 client: sealed pk failed AEAD open";
            return false;
        }
        // The opened pk must hash to the node_id the network gave us — the
        // MITM's substituted pk fails the sponge check here.
        vx::crypto::mlkem::PublicKey r_pk{};
        std::memcpy(r_pk.data(), plain.data(), 1184);
        if (node_id_for(r_pk) != expected_node_id) {
            err = "vx60 client: pk does not hash to the expected node_id (MITM or stale)";
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

    void set_static_keys(const vx::crypto::mlkem::PublicKey &ek,
                         const vx::crypto::mlkem::SecretKey &dk) noexcept {
        static_ek = ek;
        static_dk = dk;
    }

    /// Parse the CLIENT_HELLO and answer: WARM decaps immediately; COLD
    /// seals the static pk under the ss_ephem-derived AEAD. Returns the
    /// SERVER_HELLO frame to send. For COLD the flow is two-step: the
    /// server waits for PK_RESPONSE and calls finish_cold().
    bool begin_from_client_hello(const std::vector<uint8_t> &client_hello_raw,
                                 std::vector<uint8_t> &server_hello_out, std::string &err) {
        ParsedClientHello ch;
        if (!parse_client_hello(client_hello_raw, ch)) {
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
            server_hello = build_server_hello_cold(ss_ephem_ct_, static_ek, ss_ephem);
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
