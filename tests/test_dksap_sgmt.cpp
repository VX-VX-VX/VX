// DKSAP SGMT registration tests — the nickname directory layer.
#include <gtest/gtest.h>

#include "vx/crypto/dksap_sgmt.hpp"

#include <cstring>
#include <string>

namespace {
void zeroish(uint8_t *out, size_t n, unsigned seed) {
    for (unsigned i = 0; i < n; ++i)
        out[i] = static_cast<uint8_t>(i * 31 + seed * 17);
}
vx::crypto::dksap::PublicKeys make_keys(unsigned seed) {
    vx::crypto::dksap::Account acc;
    uint8_t master[256];
    zeroish(master, 256, seed);
    vx::crypto::dksap::derive_account(master, acc);
    return acc.pub;
}
} // namespace

TEST(VortexDksapSgmtTest, RegisterResolveAuthenticate) {
    vx::state::GaloisTrie trie;
    const auto pub = make_keys(1);
    const auto root = vx::crypto::dksap::sgmt_register(trie, "IVANNA", pub);
    EXPECT_EQ(trie.leaf_count(), 1u);
    EXPECT_EQ(root, trie.root_hash());

    // The authentic record resolves.
    vx::crypto::dksap::PublicKeys claimed = pub;
    EXPECT_TRUE(vx::crypto::dksap::sgmt_resolve(trie, "IVANNA", claimed));

    // A tampered record is refused (one flipped byte in Kkem).
    claimed.kkem[0] ^= 0x01;
    EXPECT_FALSE(vx::crypto::dksap::sgmt_resolve(trie, "IVANNA", claimed));

    // The authentic one still resolves after the failed attempt.
    EXPECT_TRUE(vx::crypto::dksap::sgmt_resolve(trie, "IVANNA", pub));

    // Unknown nickname refused.
    EXPECT_FALSE(vx::crypto::dksap::sgmt_resolve(trie, "NO_SUCH_NICK", pub));
}

TEST(VortexDksapSgmtTest, DistinctNicknamesDistinctKeys) {
    vx::state::GaloisTrie trie;
    const auto pubA = make_keys(2);
    const auto pubB = make_keys(3);
    vx::crypto::dksap::sgmt_register(trie, "IVANNA", pubA);
    vx::crypto::dksap::sgmt_register(trie, "BOHDAN", pubB);
    EXPECT_EQ(trie.leaf_count(), 2u);
    EXPECT_TRUE(vx::crypto::dksap::sgmt_resolve(trie, "IVANNA", pubA));
    EXPECT_TRUE(vx::crypto::dksap::sgmt_resolve(trie, "BOHDAN", pubB));
    // Cross-claims refused: A's record under B's nickname.
    EXPECT_FALSE(vx::crypto::dksap::sgmt_resolve(trie, "BOHDAN", pubA));
    // Case sensitivity: nicknames are byte-exact.
    EXPECT_FALSE(vx::crypto::dksap::sgmt_resolve(trie, "ivanna", pubA));
}

TEST(VortexDksapSgmtTest, ReregisterRefreshesCommitment) {
    vx::state::GaloisTrie trie;
    const auto pub1 = make_keys(4);
    const auto root1 = vx::crypto::dksap::sgmt_register(trie, "NICK", pub1);
    const auto pub2 = make_keys(5);
    const auto root2 = vx::crypto::dksap::sgmt_register(trie, "NICK", pub2);
    EXPECT_EQ(trie.leaf_count(), 1u); // refreshed, not duplicated
    EXPECT_NE(root1, root2);          // the commitment changed
    EXPECT_TRUE(vx::crypto::dksap::sgmt_resolve(trie, "NICK", pub2));
    EXPECT_FALSE(vx::crypto::dksap::sgmt_resolve(trie, "NICK", pub1));
}
