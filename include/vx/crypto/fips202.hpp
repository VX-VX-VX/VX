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

// Streaming SHAKE/SHA3 absorb+squeeze with persistent state — the shape
// ML-KEM's sampleNTT/prf calls need (continuous XOF streams over an
// incremental absorb).
class Shaker {
public:
    // rate = block size in bytes; pad_byte = 0x06 (SHA3) or 0x1f (SHAKE).
    Shaker(size_t rate, uint8_t pad_byte) noexcept;
    void absorb(const uint8_t *data, size_t len) noexcept;
    void squeeze(uint8_t *out, size_t out_len) noexcept;

private:
    uint64_t state_[25];
    size_t pos_ = 0; // bytes absorbed into the current block
    size_t rate_;
    uint8_t pad_byte_;
    bool squeezing_ = false;
};

} // namespace vx::crypto::fips202
