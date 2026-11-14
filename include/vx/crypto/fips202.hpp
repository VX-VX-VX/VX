// FIPS 202: SHA3-256/512 and SHAKE128/256 — the Keccak sponge required by
// FIPS 203 (ML-KEM). Zero dependencies, per the tree's standing rule.
//
// KAT-gated: tests/test_fips202_kat.cpp pins the official NIST vectors
// (empty-string digests and SHAKE XOF outputs). No KAT, no ship.
#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

namespace vx::crypto::fips202 {

// One-shot hashes.
std::array<uint8_t, 32> sha3_256(const uint8_t *data, size_t len);
std::array<uint8_t, 64> sha3_512(const uint8_t *data, size_t len);

// SHAKE XOF: arbitrary-length output.
std::vector<uint8_t> shake128(const uint8_t *data, size_t len, size_t out_len);
std::vector<uint8_t> shake256(const uint8_t *data, size_t len, size_t out_len);

} // namespace vx::crypto::fips202
