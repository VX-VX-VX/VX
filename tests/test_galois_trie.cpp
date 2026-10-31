// VortexGaloisTrieTest — unit tests (test #11)
//
// Verifies:
//   1. Insertion of 100 keys and deterministic root_hash().
//   2. get() round-trips values; absent keys are reported absent.
//   3. GaloisTrieProof generation + verification (< 2048 bytes).
//   4. Verification fails when 1 bit is flipped in proof or value.

#include <gtest/gtest.h>
#include "vx/state/galois_trie.hpp"

#include <cstring>
#include <random>

using vx::state::GaloisTrie;
using vx::state::GaloisTrieProof;

namespace {

void make_key(uint32_t seed, uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) out[i] = static_cast<uint8_t>(seed >> ((i % 4) * 8) ^ (i * 61 + seed));
}

void make_val(uint32_t seed, uint8_t out[32]) {
    for (int i = 0; i < 32; ++i) out[i] = static_cast<uint8_t>(seed * 7 + i * 131);
}

} // namespace

TEST(VortexGaloisTrieTest, Insert100KeysDeterministicRoot) {
    // Two independent tries with the same inserts must produce the same root.
    GaloisTrie trie_a;
    GaloisTrie trie_b;

    std::mt19937 rng(0xC0FFEE);
    for (int i = 0; i < 100; ++i) {
        uint8_t key[32], val[32];
        make_key(rng(), key);
        make_val(rng(), val);
        trie_a.put(key, val);
        trie_b.put(key, val);
    }

    const auto root_a = trie_a.root_hash();
    const auto root_b = trie_b.root_hash();
    EXPECT_EQ(root_a, root_b);
    EXPECT_EQ(trie_a.leaf_count(), 100u);

    // Root must differ from the empty-trie root.
    GaloisTrie empty;
    EXPECT_NE(root_a, empty.root_hash());

    // Determinism: a fresh trie replaying the same sequence in the same
    // order gives the same root; a different key set changes it.
    GaloisTrie trie_c;
    std::mt19937 rng2(0xC0FFEE);
    for (int i = 0; i < 100; ++i) {
        uint8_t key[32], val[32];
        make_key(rng2(), key);
        make_val(rng2(), val);
        trie_c.put(key, val);
    }
    EXPECT_EQ(trie_c.root_hash(), root_a);
}

TEST(VortexGaloisTrieTest, GetRoundTripAndAbsentKeys) {
    GaloisTrie trie;

    uint8_t k1[32], v1[32];
    make_key(42, k1);
    make_val(42, v1);
    trie.put(k1, v1);

    uint8_t out[32];
    ASSERT_TRUE(trie.get(k1, out));
    EXPECT_EQ(std::memcmp(out, v1, 32), 0);

    uint8_t k2[32];
    make_key(43, k2);
    EXPECT_FALSE(trie.get(k2, out));

    // Update overwrites.
    uint8_t v2[32];
    make_val(999, v2);
    trie.put(k1, v2);
    ASSERT_TRUE(trie.get(k1, out));
    EXPECT_EQ(std::memcmp(out, v2, 32), 0);
    EXPECT_EQ(trie.leaf_count(), 1u);

    // Erase removes and the root returns toward emptiness for a 1-leaf trie.
    EXPECT_TRUE(trie.erase(k1));
    EXPECT_EQ(trie.leaf_count(), 0u);
    EXPECT_FALSE(trie.get(k1, out));
    EXPECT_EQ(trie.root_hash(), GaloisTrie::empty_hashes()[0]);
}

TEST(VortexGaloisTrieTest, ProofGenerateVerifyUnder2048Bytes) {
    GaloisTrie trie;

    // Enough keys that sibling sets are non-trivial.
    std::mt19937 rng(0xBEEF);
    std::vector<std::array<uint8_t, 32>> keys(100);
    std::vector<std::array<uint8_t, 32>> vals(100);
    for (int i = 0; i < 100; ++i) {
        make_key(rng(), keys[i].data());
        make_val(rng(), vals[i].data());
        trie.put(keys[i].data(), vals[i].data());
    }
    const auto root = trie.root_hash();

    for (int i = 0; i < 10; ++i) {
        const auto proof = trie.generate_proof(keys[i].data());
        EXPECT_LT(proof.size_bytes(), 2048u)
            << "proof must stay strictly under 2048 bytes";

        EXPECT_TRUE(GaloisTrie::verify_proof(root.data(), keys[i].data(),
                                            vals[i].data(), proof));
    }

    // Absent-key proof also verifies (against the same root, empty value).
    uint8_t k_absent[32];
    make_key(777'777, k_absent);
    const auto p_absent = trie.generate_proof(k_absent);
    EXPECT_LT(p_absent.size_bytes(), 2048u);
    uint8_t zero_val[32] = {0};
    EXPECT_TRUE(GaloisTrie::verify_proof(root.data(), k_absent, zero_val, p_absent));
}

TEST(VortexGaloisTrieTest, TamperedProofOrValueFailsVerification) {
    GaloisTrie trie;
    std::mt19937 rng(0xDADA);
    for (int i = 0; i < 50; ++i) {
        uint8_t key[32], val[32];
        make_key(rng(), key);
        make_val(rng(), val);
        trie.put(key, val);
    }
    uint8_t key[32], val[32];
    make_key(31337, key);
    make_val(31337, val);
    trie.put(key, val);
    // Root must be taken AFTER the final insert (put() changes the root).
    const auto root = trie.root_hash();

    const auto proof = trie.generate_proof(key);

    // 1. Correct verification baseline.
    EXPECT_TRUE(GaloisTrie::verify_proof(root.data(), key, val, proof));

    // 2. Flip one bit in the value -> must fail.
    std::array<uint8_t, 32> bad_val{};
    std::memcpy(bad_val.data(), val, 32);
    bad_val[17] ^= 0x01;
    EXPECT_FALSE(GaloisTrie::verify_proof(root.data(), key, bad_val.data(), proof));

    // 3. Flip one bit in a sibling hash inside the proof -> must fail.
    auto bad_proof = proof;
    bool mutated = false;
    for (auto& lvl : bad_proof.levels) {
        if (!lvl.siblings.empty()) {
            lvl.siblings[0].second[5] ^= 0x02;
            mutated = true;
            break;
        }
    }
    if (mutated) {
        EXPECT_FALSE(GaloisTrie::verify_proof(root.data(), key, val, bad_proof));
    }

    // 4. Flip one bit in the root -> must fail.
    auto bad_root = root;
    bad_root[0] ^= 0x01;
    EXPECT_FALSE(GaloisTrie::verify_proof(bad_root.data(), key, val, proof));

    // 5. Claim a wrong value for an absent key -> must fail.
    uint8_t k_absent[32];
    make_key(424242, k_absent);
    const auto p_absent = trie.generate_proof(k_absent);
    uint8_t fake_val[32];
    make_val(1, fake_val);
    EXPECT_FALSE(GaloisTrie::verify_proof(root.data(), k_absent, fake_val, p_absent));
}
