// VortexSponge512 (v2 sponge) contract tests - BACKLOG 0.15, v0.0.9.
//
// The v2 sponge is NOT consensus-wired (the v1 wire is frozen); these tests
// pin the primitive's contract so any future soft migration (address
// version v2) builds on a certified construction:
//   1. KAT digests (computed once from this exact implementation; any
//      deviation later is a loud, reviewable change).
//   2. Length-encoded padding: H(m) != H(m || 0x00...) unconditionally -
//      the v1 frozen limit (trailing zeros inside the final chunk) is
//      closed for v2.
//   3. Streaming contract: absorb at 64-byte rate boundaries equals the
//      one-shot absorb.
//   4. SAC/avalanche smoke: ~50% output-bit flips per input-bit flip.
//   5. finalize() idempotence.
#include "vx/blockchain/crypto_sponge.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using vx::blockchain::VortexSponge512;

namespace {

std::string hex(const uint8_t* d, size_t n) {
    static const char* h = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(h[d[i] >> 4]);
        s.push_back(h[d[i] & 15]);
    }
    return s;
}

} // namespace

TEST(VortexSponge512Test, KatEmptyAndAbc) {
    uint8_t d[64];
    VortexSponge512::compute(nullptr, 0, d);
    EXPECT_EQ(hex(d, 64),
              "db603415db230f7166aefb912c76bc6836406708201760aa1c7c6294dceed33ef"
              "91ce4d980d4dea75d72c67ae5cb094eb1ed41a3d71d0ce4a4896eb278849dff");

    VortexSponge512::compute(reinterpret_cast<const uint8_t*>("abc"), 3, d);
    EXPECT_EQ(hex(d, 64),
              "569845f90eb28b25f14156830f24e91312d68832d6f3c21a0e539dcc943d3057"
              "42ff0c908d4b31c5090611b805e1228bd7fb1ea77beb341574d9483e60badfbc");
}

TEST(VortexSponge512Test, KatRateBoundaries) {
    uint8_t d[64];

    // 63 bytes: one byte short of a full rate block.
    uint8_t b63[63];
    for (int i = 0; i < 63; ++i) b63[i] = static_cast<uint8_t>(i);
    VortexSponge512::compute(b63, sizeof(b63), d);
    EXPECT_EQ(hex(d, 64),
              "9ac39104d7f348b02072ea4dc26e6684a20e3b5c085ffe8a9d9b8fe29597377c"
              "70366c8be87191255963ac48e2e70653f6edbd69ab80927e1e32211d6bae562c");

    // Exactly one rate block.
    uint8_t b64[64];
    for (int i = 0; i < 64; ++i) b64[i] = static_cast<uint8_t>(i);
    VortexSponge512::compute(b64, sizeof(b64), d);
    EXPECT_EQ(hex(d, 64),
              "088d041331777536e962a2855059766a25be87bcd8720fa41883906308025346"
              "e85efeb07660cdc5b6b36e759fb7265922955fd16ef01c8762859511e23e0f9c");

    // One rate block + one byte: two blocks, partial tail.
    uint8_t b65[65];
    for (int i = 0; i < 65; ++i) b65[i] = static_cast<uint8_t>(i * 7);
    VortexSponge512::compute(b65, sizeof(b65), d);
    EXPECT_EQ(hex(d, 64),
              "da97d0d7ec522e7b512d682187faf46e1fd720f9f7255d7c866897f7b65776af"
              "db39063eefd1cf81bb34d1d9859377caa15e030fc44f6f3282c2339e77a9ccb8");
}

TEST(VortexSponge512Test, LengthEncodingClosesTrailingZeroLimit) {
    // The v1 sponge (frozen by the immutable genesis frame) satisfies
    // H(m) == H(m||0...0) for trailing zeros inside the final partial
    // chunk. v2 encodes the message bit-length in the pad, so m and
    // m-with-trailing-zeros can never collide.
    uint8_t m10[10], m20[20], d1[64], d2[64];
    for (int i = 0; i < 10; ++i) m10[i] = static_cast<uint8_t>(0xA0 + i);
    std::memset(m20, 0, sizeof(m20));
    std::memcpy(m20, m10, sizeof(m10));

    VortexSponge512::compute(m10, sizeof(m10), d1);
    VortexSponge512::compute(m20, sizeof(m20), d2);
    EXPECT_NE(hex(d1, 64), hex(d2, 64));

    // Also with the message exactly at a rate boundary (the case where the
    // v1-style delimiter alone would already disambiguate - here the length
    // does the work).
    uint8_t e64[64], e65[65], f1[64], f2[64];
    std::memset(e64, 0x41, sizeof(e64));
    std::memcpy(e65, e64, sizeof(e64));
    e65[64] = 0x00;
    VortexSponge512::compute(e64, sizeof(e64), f1);
    VortexSponge512::compute(e65, sizeof(e65), f2);
    EXPECT_NE(hex(f1, 64), hex(f2, 64));
}

TEST(VortexSponge512Test, StreamingContractAtRateBoundaries) {
    // absorb(a); absorb(b) == absorb(a||b) IFF |a| is a multiple of the
    // 64-byte rate. Both sides checked, plus the negative case at a
    // non-boundary split.
    std::vector<uint8_t> big(200);
    for (size_t i = 0; i < big.size(); ++i) big[i] = static_cast<uint8_t>(i ^ 0x5A);

    uint8_t one_shot[64], split[64];

    VortexSponge512::compute(big.data(), big.size(), one_shot);
    {
        VortexSponge512 s;
        s.absorb(big.data(), 64);
        s.absorb(big.data() + 64, big.size() - 64);
        s.finalize(split);
    }
    EXPECT_EQ(hex(one_shot, 64), hex(split, 64));

    // Non-boundary split MUST differ (the documented contract, both
    // directions asserted so a silent relaxation trips a test).
    {
        VortexSponge512 s;
        s.absorb(big.data(), 63);
        s.absorb(big.data() + 63, big.size() - 63);
        s.finalize(split);
    }
    EXPECT_NE(hex(one_shot, 64), hex(split, 64));
}

TEST(VortexSponge512Test, AvalancheNearHalf) {
    // SAC smoke: flipping a single input bit must flip ~50% of the 512
    // output bits. A stuck permutation (e.g. a disconnected QR graph) would
    // pin this far below half.
    uint8_t base[64], mod[64], d1[64], d2[64];
    for (int i = 0; i < 64; ++i) base[i] = static_cast<uint8_t>(i * 3 + 1);
    VortexSponge512::compute(base, sizeof(base), d1);

    long total = 0;
    int runs = 0;
    for (int bit = 0; bit < 512; bit += 37) {
        std::memcpy(mod, base, sizeof(mod));
        mod[bit / 8] ^= static_cast<uint8_t>(1u << (bit % 8));
        VortexSponge512::compute(mod, sizeof(mod), d2);
        for (int i = 0; i < 64; ++i) {
            total += __builtin_popcount(static_cast<unsigned>(d1[i] ^ d2[i]));
        }
        ++runs;
    }
    const double avg = static_cast<double>(total) / (runs * 512.0);
    EXPECT_GT(avg, 0.40);
    EXPECT_LT(avg, 0.60);
}

TEST(VortexSponge512Test, FinalizeIsIdempotent) {
    uint8_t msg[80];
    for (int i = 0; i < 80; ++i) msg[i] = static_cast<uint8_t>(i ^ 0xC3);

    VortexSponge512 s;
    s.absorb(msg, sizeof(msg));
    uint8_t first[64], second[64], third[64];
    s.finalize(first);
    s.finalize(second);
    s.finalize(third);
    EXPECT_EQ(hex(first, 64), hex(second, 64));
    EXPECT_EQ(hex(second, 64), hex(third, 64));

    // And the one-shot path agrees with the streamed/idempotent path.
    uint8_t direct[64];
    VortexSponge512::compute(msg, sizeof(msg), direct);
    EXPECT_EQ(hex(first, 64), hex(direct, 64));
}

TEST(VortexSponge512Test, DistinctInputsDistinctDigests) {
    // Cheap structural check across a small deterministic input family:
    // no repeats among 64 distinct 32-byte inputs.
    std::vector<std::string> digests;
    digests.reserve(64);
    for (int k = 0; k < 64; ++k) {
        uint8_t msg[32];
        for (int i = 0; i < 32; ++i) msg[i] = static_cast<uint8_t>(i + k);
        uint8_t d[64];
        VortexSponge512::compute(msg, sizeof(msg), d);
        digests.push_back(hex(d, 64));
    }
    for (size_t i = 0; i < digests.size(); ++i) {
        for (size_t j = i + 1; j < digests.size(); ++j) {
            EXPECT_NE(digests[i], digests[j]) << "inputs " << i << " and " << j;
        }
    }
}
