// ML-KEM-768 (FIPS 203) — the DKSAP stealth track's key encapsulation.
// Zero dependencies; built on the KAT-gated FIPS 202 sponge (fips202.hpp).
//
// NO-STUB RULE: keygen/encaps/decaps ship ONLY when the official NIST
// KAT vectors pass bit-for-bit (tests/test_ml_kem_kat.cpp). An
// implementation that encrypts "correctly" but disagrees with NIST on
// one vector is a shipped bug, not a tolerance issue.
//
// wire sizes (ML-KEM-768): ek/pk 1184 B, dk 2400 B, ct 1088 B, ss 32 B.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace vx::crypto::mlkem {

inline constexpr size_t PK_SIZE = 1184; // ek (public key)
inline constexpr size_t SK_SIZE = 2400; // dk (secret key)
inline constexpr size_t CT_SIZE = 1088; // ciphertext
inline constexpr size_t SS_SIZE = 32;   // shared secret

using PublicKey = std::array<uint8_t, PK_SIZE>;
using SecretKey = std::array<uint8_t, SK_SIZE>;
using Ciphertext = std::array<uint8_t, CT_SIZE>;
using SharedSecret = std::array<uint8_t, SS_SIZE>;

// Deterministic keygen from a 64-byte seed (d || z) — FIPS 203 §7.1
// Algorithm 15. The random-z split lets the owner hold d for the
// implicit-rejection check and z separately if desired; the convenience
// keygen() below generates both from the tree's CSPRNG path.
void keygen_derand(const uint8_t seed64[64], PublicKey &ek, SecretKey &dk);

// Convenience: fills seed64 from the OS CSPRNG, then calls keygen_derand.
void keygen(PublicKey &ek, SecretKey &dk);

// FIPS 203 §7.2 Algorithm 16. Deterministic given (ek, m32). Returns
// false (and touches nothing) when the ek fails the modulus check —
// the public API reports the failure instead of silently proceeding.
bool encaps(const PublicKey &ek, const uint8_t m32[32], Ciphertext &ct, SharedSecret &ss);

// FIPS 203 §7.3 Algorithm 17 — implicit rejection: a corrupted ct yields
// a pseudorandom ss derived from dk's z, never an error. Verification
// must compare ss against the expected value or trust the transcript.
void decaps(const SecretKey &dk, const Ciphertext &ct, SharedSecret &ss);

// Two-phase decaps for radar scanning (reviewer optimization: the K-PKE
// decrypt phase is ~12% of the decaps cost; the FO re-encryption check is
// the remaining ~88%). decaps_filter recovers the CANDIDATE message m'
// cheaply — enough to compute a view-tag and skip foreign transactions
// without the expensive FO re-encryption. decaps_finish completes the
// full decaps (FO check + implicit rejection) for the candidate.
// Invariant: decaps(dk, ct) == decaps_finish(dk, ct, m') where
// m' = decaps_filter(dk, ct) — pinned by the KATs.
void decaps_filter(const SecretKey &dk, const Ciphertext &ct, uint8_t m32_out[32]);
void decaps_finish(const SecretKey &dk, const Ciphertext &ct, const uint8_t m32[32],
                   SharedSecret &ss);

// ── Ring primitives (exposed for the DKSAP LWE layer) ──────────────────────
// R_q = Z_3329[X]/(X^256 + 17). Coefficients in [0, q); all arithmetic
// branchless Barrett; NTT twiddles 17^brv7(i); NTT-domain products are
// per-block base multiplications (NOT pointwise).

inline constexpr size_t RING_N = 256;
inline constexpr uint16_t RING_Q = 3329;

using RingPoly = std::array<uint16_t, RING_N>;

// Forward/inverse transform (plain domain in/out).
void ring_ntt(RingPoly &a);
void ring_intt(RingPoly &a);

// NTT-domain product (per-block base multiplication).
void ring_mul_ntt(const RingPoly &a, const RingPoly &b, RingPoly &out);

// SamplePolyCBD(eta=2) over a 128-byte buffer (64*eta bytes).
void ring_cbd2(const uint8_t buf[128], RingPoly &out);

// 12-bit packing (LSB-first) — the wire encoding of ring polynomials.
void ring_pack12(const RingPoly &c, uint8_t *out);
void ring_unpack12(const uint8_t *in, RingPoly &c);

} // namespace vx::crypto::mlkem
