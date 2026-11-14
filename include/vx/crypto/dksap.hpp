// DKSAP-Galois: the stealth-nickname key hierarchy (owner spec,
// archives/notes/dksap-galois-nicknames.md, adapted to the ML-KEM
// decision of 2026-11-14 — see docs/design/contracts.md and the
// weekend plan memory for the sign-off trail).
//
// Key separation (the spec's core property):
//   SK (master, Citadel-held) ──derives──> SKspend, SKview, KEM seed
//   SGMT public record: Kspend ‖ Kview ‖ Kkem
//   IVK (detect-only)  = the ML-KEM SECRET key + Kspend: can DECAPSULATE
//     the per-transaction secret and recompute the stealth mask — enough
//     to RECOGNIZE incoming transfers, not enough to SPEND them.
//   skstealth = SKspend ⊕ sponge(S) — needs SKspend (SK-gated).
//
// The attractor runs ONCE per key derivation (Kspend/Kview are attractor
// commitments); the per-transaction radar path is sponge-only — hundreds
// of microseconds per block on a laptop CPU (owner's speed requirement).
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace vx::crypto::dksap {

inline constexpr size_t KEY_COMMIT_SIZE = 32; // the attractor commitments
inline constexpr size_t KEM_PK_SIZE = 1184;   // ML-KEM-768 ek
inline constexpr size_t KEM_SK_SIZE = 2400;   // ML-KEM-768 dk
inline constexpr size_t KEM_CT_SIZE = 1088;   // ML-KEM-768 ct

// The public SGMT payload for a nickname: Kspend ‖ Kkem.
// Review 2026-11-14 (external): the published Kview was DEAD — no
// protocol step reads it — so it is no longer published (SKview keeps
// one INTERNAL role: binding the KEM z). Kspend is a 32-byte attractor
// commitment (the tx-integration layer pads it into the 42-byte
// receiver field — not this core's job).
struct PublicKeys {
    std::array<uint8_t, KEY_COMMIT_SIZE> kspend{};
    std::array<uint8_t, KEM_PK_SIZE> kkem{};
};

// The full account state derived from the master seed.
struct Account {
    std::array<uint8_t, 32> sk_spend{};        // Citadel-held
    std::array<uint8_t, 32> sk_view{};         // Citadel-held
    std::array<uint8_t, KEM_SK_SIZE> kem_sk{}; // IVK-held (detect-only)
    PublicKeys pub;                            // SGMT-published
};

// Derive the whole account from the 256-byte master seed (SK).
void derive_account(const uint8_t master_sk[256], Account &out);

// ── Sender side ─────────────────────────────────────────────────────────────

// One stealth transfer envelope. The KEM ciphertext travels OUT OF BAND
// (the witness sidecar) keyed by the transaction digest; the transaction
// itself carries only the 42-byte Pstealth receiver and the 32-byte
// ephemeral tag for the radar.
struct StealthTx {
    std::array<uint8_t, KEY_COMMIT_SIZE> pstealth{}; // masked Kspend commitment
    std::array<uint8_t, 32> ephem_tag{};             // radar tag
    std::array<uint8_t, KEM_CT_SIZE> kem_ct{};       // witness sidecar
    std::array<uint8_t, 32> tx_key{};                // sponge(ss ‖ tag) — the
                                                     // shared traffic key
};

// Build the stealth envelope toward a nickname's public keys.
void stealth_send(const PublicKeys &recipient, StealthTx &out);

// ── Receiver side (radar on IVK) ───────────────────────────────────────────

// Radar scan result for one transaction: did OUR stealth address match?
struct RadarHit {
    bool match = false;
    std::array<uint8_t, 32> tx_key{};     // same as the sender's tx_key
    std::array<uint8_t, 32> sk_stealth{}; // VALID ONLY with SKspend — zeroed
                                          // when the caller is IVK-only
};

// Radar: the IVK holder scans one transaction's kem_ct (the witness
// sidecar payload). NOTE the compute shape: decaps runs for EVERY scanned
// transaction (~50 µs each — the mask exists only after decaps); ~29 ms
// per 580-tx block per watched nickname.
// spend_sk == nullptr (the IVK-only radar) leaves sk_stealth zeroed.
void radar_scan(const uint8_t kem_sk[KEM_SK_SIZE],
                const std::array<uint8_t, KEY_COMMIT_SIZE> &kspend, const StealthTx &tx,
                bool spend_sk_present, const uint8_t sk_spend[32], RadarHit &out);

} // namespace vx::crypto::dksap
