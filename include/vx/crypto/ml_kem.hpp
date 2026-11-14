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

// FIPS 203 §7.2 Algorithm 16. Deterministic given (ek, m32).
void encaps(const PublicKey &ek, const uint8_t m32[32], Ciphertext &ct, SharedSecret &ss);

// FIPS 203 §7.3 Algorithm 17 — implicit rejection: a corrupted ct yields
// a pseudorandom ss derived from dk's z, never an error. Verification
// must compare ss against the expected value or trust the transcript.
void decaps(const SecretKey &dk, const Ciphertext &ct, SharedSecret &ss);

} // namespace vx::crypto::mlkem
