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
#include "vx/core/ct_equal.hpp"
#include "vx/core/memory_vault.hpp"
#include "vx/math/galois_attractor.hpp"
#include "vx/blockchain/crypto_sponge.hpp"

#include <cstdio>
#include <cstring>

namespace vx::crypto::dksap {
namespace {

// Uniform ring sampling (SampleNTT-style rejection): 12-bit candidates
// < q from a continuous SHAKE128 stream. Security review HIGH (2026-11-14):
// â MUST be uniform — a small-coefficient (CBD) â collapses the RLWE
// hardness assumption and breaks stealth unlinkability.
void sample_ring_uniform(const uint8_t *domain32, mlkem::RingPoly &out) {
    vx::crypto::fips202::Shaker xof(168, 0x1f); // SHAKE128
    xof.absorb(domain32, 32);
    unsigned count = 0;
    while (count < mlkem::RING_N) {
        uint8_t buf[168];
        xof.squeeze(buf, sizeof(buf));
        for (unsigned i = 0; i + 3 <= sizeof(buf) && count < mlkem::RING_N; i += 3) {
            const uint16_t d0 = static_cast<uint16_t>(buf[i] | ((buf[i + 1] & 0x0F) << 8));
            const uint16_t d1 =
                static_cast<uint16_t>((buf[i + 1] >> 4) | (static_cast<uint16_t>(buf[i + 2]) << 4));
            if (d0 < mlkem::RING_Q)
                out[count++] = d0;
            if (count < mlkem::RING_N && d1 < mlkem::RING_Q)
                out[count++] = d1;
        }
    }
}

// GF(3329) add/sub over ring coefficients (matching ML-KEM's branchless
// arithmetic — the DKSAP ring ops must stay div-free too).
inline uint16_t fq_add_pub(uint16_t a, uint16_t b) {
    constexpr uint16_t Q = 3329;
    return static_cast<uint16_t>((uint32_t)a + b - Q * (((uint32_t)a + b) >= Q));
}
inline uint16_t fq_sub_pub(uint16_t a, uint16_t b) {
    constexpr uint16_t Q = 3329;
    return static_cast<uint16_t>((uint32_t)a + Q - b - Q * ((uint32_t)a >= b));
}

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
// Security review (2026-11-14): the attractor's canonical seed is 512 hex
// chars (256 bytes) — a 64-char direct encoding is a DEGENERATE seed class
// (the tree's own fail-closed discipline from the degeneracy hunt). The
// secret is XOF-expanded to the canonical shape, domain-separated, and
// validated with canonicalSeedError before the run (abort on failure).
std::array<uint8_t, 32> attractor_commit(const std::array<uint8_t, 32> &secret) {
    static const char *kHex = "0123456789abcdef";
    std::string hex;
    hex.reserve(512);
    uint8_t attr_seed[256];
    {
        vx::crypto::fips202::Shaker xof(136, 0x1f); // SHAKE256
        xof.absorb(reinterpret_cast<const uint8_t *>("VX_DKSAP_ATTR_V1"), 17);
        xof.absorb(secret.data(), secret.size());
        xof.squeeze(attr_seed, sizeof(attr_seed));
    }
    for (const uint8_t b : attr_seed) {
        hex += kHex[b >> 4];
        hex += kHex[b & 0xF];
    }
    vx::core::MemoryCore::scrub_execution_state(attr_seed, sizeof(attr_seed));
    if (!vx::math::VortexAttractor::canonicalSeedError(hex).empty())
        std::abort(); // the expansion produced a degenerate seed — fail closed
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
    // implicit-rejection path — it MUST stay secret. It derives from
    // SKview (the spec's view capability — never published).
    auto kem_z = sponge_tagged("VX_DKSAP_KEM_Z_V1", 18, sk_view.data(), 32);

    // ── Variant A (external review, 2026-11-14): the spend commitment is
    // an R_q LWE public key t̂_spend = â∘ŝ_spend + ê_spend. The additive
    // homomorphism of the ring is what makes the stealth blinding
    // invertible by ADDITION at the Citadel (the PQ analogue of Monero's
    // P = B + H(rA)G). â is the fixed protocol ring element (RLWE with a
    // public â is standard); ŝ/ê from CBD over PRF draws of SKspend.

    mlkem::RingPoly a_hat;
    {
        // Uniform â (security review HIGH: a CBD-small â collapses the
        // RLWE hardness assumption — stealth unlinkability breaks).
        uint8_t a_dom[32];
        vx::crypto::fips202::Shaker xof(136, 0x1f);
        xof.absorb(reinterpret_cast<const uint8_t *>("VX_DKSAP_RING_A_V1"), 21);
        xof.squeeze(a_dom, sizeof(a_dom));
        sample_ring_uniform(a_dom, a_hat);
        mlkem::ring_ntt(a_hat);
        vx::core::MemoryCore::scrub_execution_state(a_dom, sizeof(a_dom));
    }

    mlkem::RingPoly s_spend_hat, e_spend_hat;
    mlkem::RingPoly s_spend_time;
    {
        uint8_t prf_buf[128];
        vx::crypto::fips202::Shaker xof(136, 0x1f);
        xof.absorb(sk_spend.data(), 32);
        const uint8_t n0 = 0;
        xof.absorb(&n0, 1);
        xof.squeeze(prf_buf, sizeof(prf_buf));
        mlkem::ring_cbd2(prf_buf, s_spend_time);
        s_spend_hat = s_spend_time;
        mlkem::ring_ntt(s_spend_hat);
    }
    {
        uint8_t prf_buf[128];
        vx::crypto::fips202::Shaker xof(136, 0x1f);
        xof.absorb(sk_spend.data(), 32);
        const uint8_t n1 = 1;
        xof.absorb(&n1, 1);
        xof.squeeze(prf_buf, sizeof(prf_buf));
        mlkem::ring_cbd2(prf_buf, e_spend_hat);
        mlkem::ring_ntt(e_spend_hat);
    }

    // t̂_spend = â∘ŝ_spend + ê_spend
    mlkem::RingPoly t_spend_hat;
    mlkem::ring_mul_ntt(a_hat, s_spend_hat, t_spend_hat);
    for (unsigned i = 0; i < mlkem::RING_N; ++i)
        t_spend_hat[i] = fq_add_pub(t_spend_hat[i], e_spend_hat[i]);
    mlkem::ring_pack12(t_spend_hat, out.pub.t_spend.data());

    // The ML-KEM pair (d = KEM seed, z = secret SKview draw).
    uint8_t seed64[64];
    std::memcpy(seed64, kem_seed.data(), 32);
    std::memcpy(seed64 + 32, kem_z.data(), 32);
    mlkem::keygen_derand(seed64, out.pub.kkem, out.kem_sk);
    // Citadel hygiene: burn the keygen inputs (the signer's discipline).
    vx::core::MemoryCore::scrub_execution_state(seed64, sizeof(seed64));
    vx::core::MemoryCore::scrub_execution_state(kem_seed.data(), kem_seed.size());
    vx::core::MemoryCore::scrub_execution_state(kem_z.data(), kem_z.size());

    std::memcpy(out.sk_spend.data(), sk_spend.data(), 32);
    std::memcpy(out.sk_view.data(), sk_view.data(), 32);
}

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

    // 2. TXKEY = sponge(ss ‖ handle); handle = sponge(t̂_spend) — the
    //    account handle both sides derive from the SGMT record.
    uint8_t handle[32];
    {
        vx::blockchain::VortexSponge256 sp;
        const uint8_t tag[] = "VX_DKSAP_HANDLE_V1";
        sp.absorb(tag, sizeof(tag) - 1);
        sp.absorb(recipient.t_spend.data(), recipient.t_spend.size());
        sp.finalize(handle);
    }
    uint8_t tk_in[64];
    std::memcpy(tk_in, ss.data(), 32);
    std::memcpy(tk_in + 32, handle, 32);
    auto s = sponge_tagged("VX_DKSAP_TXKEY_V1", 18, tk_in, sizeof(tk_in));
    std::memcpy(out.tx_key.data(), s.data(), 32);

    // 3. The blinding vectors from TXKEY (the radar recomputes the same
    //    draws after decaps — both sides hold TXKEY).
    mlkem::RingPoly s_mask_hat, e_mask_hat, a_hat;
    {
        uint8_t prf_buf[128];
        vx::crypto::fips202::Shaker xof(136, 0x1f);
        xof.absorb(s.data(), 32);
        const uint8_t n0 = 0;
        xof.absorb(&n0, 1);
        xof.squeeze(prf_buf, sizeof(prf_buf));
        mlkem::ring_cbd2(prf_buf, s_mask_hat);
        mlkem::ring_ntt(s_mask_hat);
    }
    {
        uint8_t prf_buf[128];
        vx::crypto::fips202::Shaker xof(136, 0x1f);
        xof.absorb(s.data(), 32);
        const uint8_t n1 = 1;
        xof.absorb(&n1, 1);
        xof.squeeze(prf_buf, sizeof(prf_buf));
        mlkem::ring_cbd2(prf_buf, e_mask_hat);
        mlkem::ring_ntt(e_mask_hat);
    }
    {
        // Uniform â (security review HIGH: a CBD-small â collapses the
        // RLWE hardness assumption — stealth unlinkability breaks).
        uint8_t a_dom[32];
        vx::crypto::fips202::Shaker xof(136, 0x1f);
        xof.absorb(reinterpret_cast<const uint8_t *>("VX_DKSAP_RING_A_V1"), 21);
        xof.squeeze(a_dom, sizeof(a_dom));
        sample_ring_uniform(a_dom, a_hat);
        mlkem::ring_ntt(a_hat);
        vx::core::MemoryCore::scrub_execution_state(a_dom, sizeof(a_dom));
    }

    // 4. t̂_stealth = t̂_spend + â∘ŝ_mask + ê_mask — a VALID public key of
    //    s_stealth = s_spend + s_mask (the ring's additive homomorphism).
    mlkem::RingPoly t_spend_hat{}, t_stealth_hat{}, blind{};
    mlkem::ring_unpack12(recipient.t_spend.data(), t_spend_hat);
    mlkem::ring_mul_ntt(a_hat, s_mask_hat, blind);
    // Security review HIGH (2026-11-14): compute FROM t_spend — the first
    // draft folded into an uninitialized accumulator (stack garbage in
    // the published one-time public key).
    for (unsigned i = 0; i < mlkem::RING_N; ++i)
        t_stealth_hat[i] = fq_add_pub(fq_add_pub(t_spend_hat[i], blind[i]), e_mask_hat[i]);
    mlkem::ring_pack12(t_stealth_hat, out.t_stealth.data());

    // 5. Pstealth = sponge(t̂_stealth) — the on-chain tracker.
    vx::blockchain::VortexSponge256 sp;
    const uint8_t tag[] = "VX_DKSAP_PSTEALTH_V1";
    sp.absorb(tag, sizeof(tag) - 1);
    sp.absorb(out.t_stealth.data(), out.t_stealth.size());
    sp.finalize(out.pstealth.data());
}

void radar_scan(const uint8_t kem_sk[KEM_SK_SIZE],
                const std::array<uint8_t, T_COMMIT_SIZE> &t_spend, const StealthTx &tx,
                bool spend_sk_present, const uint8_t sk_spend[32], RadarHit &out) {
    out.match = false;
    std::memset(out.sk_stealth.data(), 0, out.sk_stealth.size());

    // 1. Decapsulate: the true recipient's KEM key yields the sender's ss
    //    (implicit rejection gives everyone else pseudorandom noise).
    mlkem::SharedSecret ss;
    mlkem::Ciphertext ct;
    std::memcpy(ct.data(), tx.kem_ct.data(), KEM_CT_SIZE);
    mlkem::decaps(*reinterpret_cast<const mlkem::SecretKey *>(static_cast<const void *>(kem_sk)),
                  ct, ss);

    // 2. TXKEY from ss + the account handle (identical to the sender).
    uint8_t handle[32];
    {
        vx::blockchain::VortexSponge256 sp;
        const uint8_t tag[] = "VX_DKSAP_HANDLE_V1";
        sp.absorb(tag, sizeof(tag) - 1);
        sp.absorb(t_spend.data(), t_spend.size());
        sp.finalize(handle);
    }
    uint8_t tk_in[64];
    std::memcpy(tk_in, ss.data(), 32);
    std::memcpy(tk_in + 32, handle, 32);
    auto s = sponge_tagged("VX_DKSAP_TXKEY_V1", 18, tk_in, sizeof(tk_in));

    // 3. The mask vectors (identical to the sender's draws).
    mlkem::RingPoly s_mask_hat, e_mask_hat, a_hat;
    {
        uint8_t prf_buf[128];
        vx::crypto::fips202::Shaker xof(136, 0x1f);
        xof.absorb(s.data(), 32);
        const uint8_t n0 = 0;
        xof.absorb(&n0, 1);
        xof.squeeze(prf_buf, sizeof(prf_buf));
        mlkem::ring_cbd2(prf_buf, s_mask_hat);
        mlkem::ring_ntt(s_mask_hat);
    }
    {
        uint8_t prf_buf[128];
        vx::crypto::fips202::Shaker xof(136, 0x1f);
        xof.absorb(s.data(), 32);
        const uint8_t n1 = 1;
        xof.absorb(&n1, 1);
        xof.squeeze(prf_buf, sizeof(prf_buf));
        mlkem::ring_cbd2(prf_buf, e_mask_hat);
        mlkem::ring_ntt(e_mask_hat);
    }
    {
        // Uniform â (security review HIGH: a CBD-small â collapses the
        // RLWE hardness assumption — stealth unlinkability breaks).
        uint8_t a_dom[32];
        vx::crypto::fips202::Shaker xof(136, 0x1f);
        xof.absorb(reinterpret_cast<const uint8_t *>("VX_DKSAP_RING_A_V1"), 21);
        xof.squeeze(a_dom, sizeof(a_dom));
        sample_ring_uniform(a_dom, a_hat);
        mlkem::ring_ntt(a_hat);
        vx::core::MemoryCore::scrub_execution_state(a_dom, sizeof(a_dom));
    }

    // 4. UNBLIND: t̂_unblinded = t̂_stealth − â∘ŝ_mask − ê_mask == t̂_spend?
    mlkem::RingPoly t_stealth_hat{}, blind{}, t_unblinded{};
    mlkem::ring_unpack12(tx.t_stealth.data(), t_stealth_hat);
    // Canonical-form check (security review MEDIUM): reject non-canonical
    // coefficients (>= q) in the submitted blinding — the first draft
    // compared 384 bytes of a 512-byte array, leaving the tail 64
    // coefficients unchecked.
    for (unsigned i = 0; i < mlkem::RING_N; ++i)
        if (t_stealth_hat[i] >= mlkem::RING_Q)
            return; // non-canonical input: not a valid blinded key
    mlkem::ring_mul_ntt(a_hat, s_mask_hat, blind);
    for (unsigned i = 0; i < mlkem::RING_N; ++i)
        t_unblinded[i] = fq_sub_pub(fq_sub_pub(t_stealth_hat[i], blind[i]), e_mask_hat[i]);

    // Canonical comparison: pack the unblinded poly to its 12-bit wire
    // form and compare the full 384 bytes against the commitment — the
    // packed form is THE canonical identity (no partial-array compare).
    mlkem::RingPoly t_spend_hat{};
    mlkem::ring_unpack12(t_spend.data(), t_spend_hat);
    uint8_t unblinded_packed[T_COMMIT_SIZE];
    mlkem::ring_pack12(t_unblinded, unblinded_packed);
    const bool match = vx::core::ct_equal(unblinded_packed, t_spend.data(), T_COMMIT_SIZE);
    out.match = match;
    if (!match)
        return;
    std::memcpy(out.tx_key.data(), s.data(), 32);

    // 5. The one-time spend secret by ADDITION (Variant A): the full
    //    vector s_stealth = s_spend + s_mask. The 32-byte field carries
    //    the COMMITMENT of the regeneration recipe (sk_spend ‖ tx_key) —
    //    the Citadel layer regenerates the full vector from both inputs
    //    (deterministic CBD draws, exactly as above). Both the one-time
    //    keypair consistency (t̂_stealth = â∘(ŝ_spend + ŝ_mask) + …) and
    //    the sender's inability to know s_spend (LWE) are pinned here.
    if (spend_sk_present && sk_spend) {
        uint8_t recipe[64];
        std::memcpy(recipe, sk_spend, 32);
        std::memcpy(recipe + 32, s.data(), 32);
        auto c = sponge_tagged("VX_DKSAP_ONETIME_V1", 20, recipe, sizeof(recipe));
        std::memcpy(out.sk_stealth.data(), c.data(), 32);
    }
}

} // namespace vx::crypto::dksap
