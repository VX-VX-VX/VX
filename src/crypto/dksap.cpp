// DKSAP-Galois implementation — see dksap.hpp for the design contract.
//
// Crypto layers:
//   - ML-KEM-768 (FIPS 203, ACVP-KAT-gated) — the PQ key agreement.
//   - VortexSponge256 — the domain-separated KDF and the masking function
//     (the attractor lives in the KEY DERIVATION, once per account; the
//     per-transaction radar path is sponge-only, per the speed contract).
//   - The Galois attractor commitment for Kspend/Kview via
//     VortexAttractor::run — ONE 1000-round run per derivation.
#include "vx/crypto/dksap.hpp"

#include "vx/crypto/fips202.hpp"
#include "vx/crypto/ml_kem.hpp"
#include "vx/core/memory_vault.hpp"
#include "vx/math/galois_attractor.hpp"
#include "vx/blockchain/crypto_sponge.hpp"

#include <cstdio>
#include <cstring>

namespace vx::crypto::dksap {
namespace {

// Domain-separated sponge digest over a tag-prefixed buffer.
std::array<uint8_t, 32> sponge_tagged(const char *tag, size_t tag_len, const uint8_t *data,
                                      size_t len) {
    vx::blockchain::VortexSponge256 s;
    s.absorb(reinterpret_cast<const uint8_t *>(tag), tag_len);
    s.absorb(data, len);
    std::array<uint8_t, 32> out{};
    s.finalize(out.data());
    return out;
}

// The attractor commitment of a 32-byte secret: ONE 1000-round run, folded
// to 32 bytes by the address fold. Slow by design — key derivation only.
// The attractor's input is a HEX seed (canonical demo-seed shape), so the
// 32 secret bytes are hex-encoded first (64 chars).
std::array<uint8_t, 32> attractor_commit(const std::array<uint8_t, 32> &secret) {
    static const char *kHex = "0123456789abcdef";
    std::string hex;
    hex.reserve(64);
    for (const uint8_t b : secret) {
        hex += kHex[b >> 4];
        hex += kHex[b & 0xF];
    }
    auto res = vx::math::VortexAttractor::run(hex, 1000, false);
    // finalX folded to 32 bytes (the same fold the address path uses)
    std::array<uint8_t, 32> out{};
    mpz_class temp = res.finalX;
    mpz_class m = 255;
    for (int i = 0; i < 32; ++i) {
        out[i] = static_cast<uint8_t>(mpz_class(temp & m).get_ui());
        temp >>= 8;
    }
    return out;
}

} // namespace

// ── Key derivation ──────────────────────────────────────────────────────────

void derive_account(const uint8_t master_sk[256], Account &out) {
    // Domain-separated draws from the master seed (the sponge as the KDF).
    auto sk_spend = sponge_tagged("VX_DKSAP_SPEND_V1", 18, master_sk, 256);
    auto sk_view = sponge_tagged("VX_DKSAP_VIEW_V1", 17, master_sk, 256);
    auto kem_seed = sponge_tagged("VX_DKSAP_KEM_V1", 16, master_sk, 256);
    // Security review HIGH (2026-11-14): the ML-KEM z half feeds the
    // implicit-rejection path — it MUST stay secret. The first draft
    // bound it to the PUBLISHED Kview commitment, making the rejection
    // secret attacker-computable (IND-CCA2 break). z derives from SKview
    // (the spec's view capability — never published since this fix),
    // keeping SKview a real internal role.
    auto kem_z = sponge_tagged("VX_DKSAP_KEM_Z_V1", 18, sk_view.data(), 32);

    // Kspend/Kview: attractor commitments of the spend/view secrets
    // (ONE 1000-round run each — the slow part is deliberate and rare).
    auto kspend = attractor_commit(sk_spend);
    auto kview = attractor_commit(sk_view);

    // The ML-KEM pair from the 64-byte KEM seed (d = KEM seed, z = secret).
    uint8_t seed64[64];
    std::memcpy(seed64, kem_seed.data(), 32);
    std::memcpy(seed64 + 32, kem_z.data(), 32);
    mlkem::keygen_derand(seed64, out.pub.kkem, out.kem_sk);
    // Citadel hygiene: the keygen inputs burn the moment the pair exists
    // (the signer's scrub discipline).
    vx::core::MemoryCore::scrub_execution_state(seed64, sizeof(seed64));
    vx::core::MemoryCore::scrub_execution_state(kem_seed.data(), kem_seed.size());
    vx::core::MemoryCore::scrub_execution_state(kem_z.data(), kem_z.size());

    std::memcpy(out.sk_spend.data(), sk_spend.data(), 32);
    std::memcpy(out.sk_view.data(), sk_view.data(), 32);
    std::memcpy(out.pub.kspend.data(), kspend.data(), KEY_COMMIT_SIZE);
    // Kview is NOT published (review 2026-11-14): the external reviewer
    // flagged it as dead weight in the SGMT payload. SKview keeps its
    // internal role as the KEM-z source above.
    (void)kview;
}

// ── Sender ──────────────────────────────────────────────────────────────────

void stealth_send(const PublicKeys &recipient, StealthTx &out) {
    // 1. ML-KEM encapsulation toward the recipient's published Kkem.
    uint8_t m32[32];
    {
        FILE *f = std::fopen("/dev/urandom", "rb");
        if (!f || std::fread(m32, 1, 32, f) != 32)
            std::abort();
        if (f)
            std::fclose(f);
    }
    mlkem::SharedSecret ss;
    if (!mlkem::encaps(recipient.kkem, m32, out.kem_ct, ss))
        std::abort(); // the SGMT-published key failed validation

    // 2. The shared traffic key: sponge(ss ‖ Kspend). Kspend is the
    //    SGMT-published value BOTH sides hold — the radar (IVK-only)
    //    recomputes the same key without any secret. A mis-delivered ct
    //    decapsulates to a different ss, so foreign radars never match.
    //    (Kview stays in the key hierarchy — the KEM seed binding.)
    uint8_t tk_in[32 + KEY_COMMIT_SIZE];
    std::memcpy(tk_in, ss.data(), 32);
    std::memcpy(tk_in + 32, recipient.kspend.data(), KEY_COMMIT_SIZE);
    auto s = sponge_tagged("VX_DKSAP_TXKEY_V1", 18, tk_in, sizeof(tk_in));
    std::memcpy(out.tx_key.data(), s.data(), 32);

    // 3. The stealth mask. (The ephemeral 32-byte tag from the first
    // draft was dropped — external review: ballast. The radar matches
    // via Pstealth alone; a pre-decaps filter is impossible here.)
    auto mask = sponge_tagged("VX_DKSAP_MASK_V1", 17, s.data(), 32);
    for (unsigned i = 0; i < KEY_COMMIT_SIZE; ++i)
        out.pstealth[i] = static_cast<uint8_t>(recipient.kspend[i] ^ mask[i]);
}

// ── Radar (IVK) ─────────────────────────────────────────────────────────────

void radar_scan(const uint8_t kem_sk[KEM_SK_SIZE],
                const std::array<uint8_t, KEY_COMMIT_SIZE> &kspend, const StealthTx &tx,
                bool spend_sk_present, const uint8_t sk_spend[32], RadarHit &out) {
    out.match = false;
    std::memset(out.sk_stealth.data(), 0, out.sk_stealth.size());

    // 1. Decapsulate: only the true recipient's KEM key yields the
    //    sender's ss (ML-KEM's implicit rejection gives a pseudorandom
    //    ss' for everyone else — the mask check below fails for them).
    mlkem::SharedSecret ss;
    mlkem::Ciphertext ct;
    std::memcpy(ct.data(), tx.kem_ct.data(), KEM_CT_SIZE);
    mlkem::decaps(*reinterpret_cast<const mlkem::SecretKey *>(static_cast<const void *>(kem_sk)),
                  ct, ss);

    // 2. Rebuild the traffic key with OUR Kview... we don't hold Kview on
    //    the radar path — the traffic key binds via Kspend's mask check:
    //    the sender's mask = sponge(tx_key) and tx_key = sponge(ss‖Kview);
    //    the radar recomputes from its OWN Kview (the SGMT record of the
    //    scanned nickname is public — the radar iterates the nicknames it
    //    watches; here the caller passes OUR kspend, so the tx_key must be
    //    rebuilt with OUR kview — supplied through the kem_sk derivation).
    //    For the standalone core, the radar recomputes the tx_key from ss
    //    and OUR kview passed via kspend's twin: to keep the API honest,
    //    the tx_key reconstruction uses ss ‖ kspend (the public half the
    //    radar always has) — the sender uses the same kspend (it's the
    //    SGMT-published value), so both sides derive the same key.
    uint8_t tk_in[32 + KEY_COMMIT_SIZE];
    std::memcpy(tk_in, ss.data(), 32);
    std::memcpy(tk_in + 32, kspend.data(), KEY_COMMIT_SIZE);
    auto s = sponge_tagged("VX_DKSAP_TXKEY_V1", 18, tk_in, sizeof(tk_in));

    auto mask = sponge_tagged("VX_DKSAP_MASK_V1", 17, s.data(), 32);
    for (unsigned i = 0; i < 32; ++i)
        out.tx_key[i] = s[i];

    // 3. The match: pstealth == kspend ⊕ mask.
    bool match = true;
    for (unsigned i = 0; i < KEY_COMMIT_SIZE; ++i)
        match &= (tx.pstealth[i] == (kspend[i] ^ mask[i]));
    out.match = match;
    if (!match)
        return;

    // 4. Spend key: PRF keyed with SKspend — ONLY with SKspend present.
    //    Security review (2026-11-14): the first draft XORed SKspend with
    //    a mask the IVK holder can compute (mask ← ss → tx_key). One
    //    leaked sk_stealth would then expose SKspend by a single XOR —
    //    the whole account gone. The PRF is one-way: a leaked sk_stealth
    //    reveals nothing about SKspend, and the IVK holder (who knows
    //    tx_key) still cannot evaluate it.
    std::memcpy(out.tx_key.data(), s.data(), 32);
    if (spend_sk_present && sk_spend) {
        vx::crypto::fips202::Shaker prf(136, 0x1f); // SHAKE256
        prf.absorb(sk_spend, 32);
        prf.absorb(s.data(), 32);
        prf.squeeze(out.sk_stealth.data(), out.sk_stealth.size());
    }
}

} // namespace vx::crypto::dksap
