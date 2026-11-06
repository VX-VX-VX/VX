// VortexSponge1024 (v3 sponge) contract tests - owner directive 2026-11-06
// ("pull everything up to 1024 bits"), the certified home for the
// address-format v2 fold (BACKLOG 2.17 remedy).
//
// The v3 sponge is NOT consensus-wired (the v1 wire is frozen); these tests
// pin the primitive's contract so any future migration builds on a
// certified construction:
//   1. KAT digests (computed once from this exact implementation; any
//      deviation later is a loud, reviewable change).
//   2. Length-encoded padding: H(m) != H(m || 0x00...) unconditionally.
//   3. Streaming contract: absorb at 128-byte rate boundaries equals the
//      one-shot absorb; a non-boundary split MUST differ.
//   4. SAC/avalanche smoke: ~50% output-bit flips per input-bit flip.
//   5. Full diffusion: a single input-bit flip reaches every digest word.
//   6. finalize() idempotence.
#include "vx/blockchain/crypto_sponge.hpp"

#include <gtest/gtest.h>

#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

using vx::blockchain::VortexSponge1024;

namespace {

std::string hex(const uint8_t *d, size_t n) {
    static const char *h = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(h[d[i] >> 4]);
        s.push_back(h[d[i] & 15]);
    }
    return s;
}

} // namespace

TEST(VortexSponge1024Test, KatEmptyAndAbc) {
    uint8_t d[128];
    VortexSponge1024::compute(nullptr, 0, d);
    EXPECT_EQ(hex(d, 128), "5024a8d3943dcba2f6efee6e0dd102045c25ddb6ecfca48d6cd4637d9ee1534a"
                           "b57205755668b98ec6d9c776f259604804029e9b6c6e5f5f9eac9ae03dff6f4"
                           "60e4bf2c35f46aa6e147bfa8e1468c9061a9846b470cc643e619be5cf9885f9b"
                           "ec173b1ab9a3b961c0806c426a0260310cfe38ba16bca21024320fa022e5f57d"
                           "e");

    VortexSponge1024::compute(reinterpret_cast<const uint8_t *>("abc"), 3, d);
    EXPECT_EQ(hex(d, 128), "01f197389d991949a6ee9e74cfec7d7154b40c02d79f36b1594789adddd5e59"
                           "847f07bfb65a3c4aff0ec19ffc13e2f17d45127e25a7b262a1cf07c6d03b445"
                           "5cafd4b438e09318ee793a799aad020fe5b344e2a6e8c759e88c43273dbaa3d"
                           "8dfc291e68d7516c5e2d7a8a95b7ea28424001446e27a5bdd20b3276b80ab1f"
                           "bf59");
}

TEST(VortexSponge1024Test, KatRateBoundaries) {
    uint8_t d[128];

    // 127 bytes: one byte short of a full rate block.
    uint8_t b127[127];
    for (int i = 0; i < 127; ++i)
        b127[i] = static_cast<uint8_t>(i);
    VortexSponge1024::compute(b127, sizeof(b127), d);
    EXPECT_EQ(hex(d, 128), "e2a6332112bbd8a8164bc127e5ca0c5b7b77870f167c512a12f52a7baf5a5dd4"
                           "9cbaab78dfd23e2483d29eb3f126d7a947662c2f21af655a91d866bf1ca764c"
                           "6ebc47d4fb1f267b3e19b232e9d6daced3928bd1c55466d19b26df3b8b208af"
                           "dcfb5494d5ce38d5eac0682ac612325af742a46e0b3adf957379dab2b9d405a"
                           "79c");

    // Exactly one rate block.
    uint8_t b128[128];
    for (int i = 0; i < 128; ++i)
        b128[i] = static_cast<uint8_t>(i);
    VortexSponge1024::compute(b128, sizeof(b128), d);
    EXPECT_EQ(hex(d, 128), "2abb804cc0983769f4c8b3f27a085838683ce3301f537068088c9e6360ccd7bd"
                           "0cf53764b10c3b2b9d2ab099cc3b93fbcdceb159d9d624928c84074a19388931"
                           "04df485418418f53a4be50e7b9268a218b0ce1d54f3d099985a9075f95823d3b"
                           "847c7e4efd3c98fd78267d0716605fdc5a0bda044e2218cd57a832d665a27b9e");

    // One rate block + one byte: two blocks, partial tail.
    uint8_t b129[129];
    for (int i = 0; i < 129; ++i)
        b129[i] = static_cast<uint8_t>(i * 7);
    VortexSponge1024::compute(b129, sizeof(b129), d);
    EXPECT_EQ(hex(d, 128), "4575860ab7c3012bb8a10b7556fc83630bd5c61f04d857fac4016580036b21b9"
                           "bbff8423d5a147bf734ec64718818ee58d77d1e69e9f73e6d0278e5d9d654b6e"
                           "445a58bab7aa0f28b040cfd7aa4c57a2dd151f9279d83bf029150c451fb28513"
                           "d58f8b0149cb1bde0d53691c911a3b21759c99193915ef4cf676bf5a3e87fdec");
}

TEST(VortexSponge1024Test, LengthEncodingClosesTrailingZeroLimit) {
    // m and m-with-trailing-zeros can never collide: the pad encodes the
    // message bit-length (the v1 frozen limit is closed in v2/v3).
    uint8_t m10[10], m20[20], d1[128], d2[128];
    for (int i = 0; i < 10; ++i)
        m10[i] = static_cast<uint8_t>(0xA0 + i);
    std::memset(m20, 0, sizeof(m20));
    std::memcpy(m20, m10, sizeof(m10));

    VortexSponge1024::compute(m10, sizeof(m10), d1);
    VortexSponge1024::compute(m20, sizeof(m20), d2);
    EXPECT_NE(hex(d1, 128), hex(d2, 128));

    // Also with the message exactly at a rate boundary.
    uint8_t e128[128], e129[129], f1[128], f2[128];
    std::memset(e128, 0x41, sizeof(e128));
    std::memcpy(e129, e128, sizeof(e128));
    e129[128] = 0x00;
    VortexSponge1024::compute(e128, sizeof(e128), f1);
    VortexSponge1024::compute(e129, sizeof(e129), f2);
    EXPECT_NE(hex(f1, 128), hex(f2, 128));
}

TEST(VortexSponge1024Test, StreamingContractAtRateBoundaries) {
    // absorb(a); absorb(b) == absorb(a||b) IFF |a| is a multiple of the
    // 128-byte rate. Both sides checked, plus the negative case at a
    // non-boundary split.
    std::vector<uint8_t> big(400);
    for (size_t i = 0; i < big.size(); ++i)
        big[i] = static_cast<uint8_t>(i ^ 0x5A);

    uint8_t one_shot[128], split[128];

    VortexSponge1024::compute(big.data(), big.size(), one_shot);
    {
        VortexSponge1024 s;
        s.absorb(big.data(), 128);
        s.absorb(big.data() + 128, big.size() - 128);
        s.finalize(split);
    }
    EXPECT_EQ(hex(one_shot, 128), hex(split, 128));

    // Two boundary-aligned splits also agree.
    {
        VortexSponge1024 s;
        s.absorb(big.data(), 256);
        s.absorb(big.data() + 256, big.size() - 256);
        s.finalize(split);
    }
    EXPECT_EQ(hex(one_shot, 128), hex(split, 128));

    // Non-boundary split MUST differ (the documented contract, both
    // directions asserted so a silent relaxation trips a test).
    {
        VortexSponge1024 s;
        s.absorb(big.data(), 127);
        s.absorb(big.data() + 127, big.size() - 127);
        s.finalize(split);
    }
    EXPECT_NE(hex(one_shot, 128), hex(split, 128));
}

TEST(VortexSponge1024Test, AvalancheNearHalf) {
    // SAC smoke: flipping a single input bit must flip ~50% of the 1024
    // output bits. A stuck permutation (e.g. a disconnected QR graph)
    // would pin this far below half.
    uint8_t base[128], mod[128], d1[128], d2[128];
    for (int i = 0; i < 128; ++i)
        base[i] = static_cast<uint8_t>(i * 3 + 1);
    VortexSponge1024::compute(base, sizeof(base), d1);

    long total = 0;
    int runs = 0;
    for (int bit = 0; bit < 1024; bit += 41) {
        std::memcpy(mod, base, sizeof(mod));
        mod[bit / 8] ^= static_cast<uint8_t>(1u << (bit % 8));
        VortexSponge1024::compute(mod, sizeof(mod), d2);
        for (int i = 0; i < 128; ++i) {
            total += __builtin_popcount(static_cast<unsigned>(d1[i] ^ d2[i]));
        }
        ++runs;
    }
    const double avg = static_cast<double>(total) / (runs * 1024.0);
    EXPECT_GT(avg, 0.40);
    EXPECT_LT(avg, 0.60);
}

TEST(VortexSponge1024Test, FullDiffusionReachesEveryDigestWord) {
    // Stronger than SAC: across 8 single-bit-flip probes, EVERY one of the
    // 16 digest words must change in at least 6 of them. A permutation
    // with an unreachable word (the v1 sponge's original defect class -
    // four independent 2-word chains) would pin some word at zero.
    uint8_t base[128], mod[128], d1[128], d2[128];
    for (int i = 0; i < 128; ++i)
        base[i] = static_cast<uint8_t>(i * 5 + 7);
    VortexSponge1024::compute(base, sizeof(base), d1);

    int changed[16] = {};
    const int probes = 8;
    for (int p = 0; p < probes; ++p) {
        const int bit = (p * 137) % 1024;
        std::memcpy(mod, base, sizeof(mod));
        mod[bit / 8] ^= static_cast<uint8_t>(1u << (bit % 8));
        VortexSponge1024::compute(mod, sizeof(mod), d2);
        for (int w = 0; w < 16; ++w) {
            if (std::memcmp(d1 + w * 8, d2 + w * 8, 8) != 0)
                ++changed[w];
        }
    }
    for (int w = 0; w < 16; ++w) {
        EXPECT_GE(changed[w], 6) << "digest word " << w << " barely moves";
    }
}

TEST(VortexSponge1024Test, FinalizeIsIdempotent) {
    uint8_t msg[160];
    for (int i = 0; i < 160; ++i)
        msg[i] = static_cast<uint8_t>(i ^ 0xC3);

    VortexSponge1024 s;
    s.absorb(msg, sizeof(msg));
    uint8_t first[128], second[128], third[128];
    s.finalize(first);
    s.finalize(second);
    s.finalize(third);
    EXPECT_EQ(hex(first, 128), hex(second, 128));
    EXPECT_EQ(hex(second, 128), hex(third, 128));

    // And the one-shot path agrees with the streamed/idempotent path.
    uint8_t direct[128];
    VortexSponge1024::compute(msg, sizeof(msg), direct);
    EXPECT_EQ(hex(first, 128), hex(direct, 128));
}

TEST(VortexSponge1024Test, DistinctInputsDistinctDigests) {
    // Cheap structural check across a small deterministic input family:
    // no repeats among 64 distinct 32-byte inputs.
    std::vector<std::string> digests;
    digests.reserve(64);
    for (int k = 0; k < 64; ++k) {
        uint8_t msg[32];
        for (int i = 0; i < 32; ++i)
            msg[i] = static_cast<uint8_t>(i + k);
        uint8_t d[128];
        VortexSponge1024::compute(msg, sizeof(msg), d);
        digests.push_back(hex(d, 128));
    }
    for (size_t i = 0; i < digests.size(); ++i) {
        for (size_t j = i + 1; j < digests.size(); ++j) {
            EXPECT_NE(digests[i], digests[j]) << "inputs " << i << " and " << j;
        }
    }
}
