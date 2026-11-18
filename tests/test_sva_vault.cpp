// test_sva_vault.cpp — SVA-8192 «Sovereign Vault» crypto core (owner-
// directed 18.11, 0.2.x). Pins: address derivation, path derivation,
// spend verification (happy + tamper + tombstone + out-of-order leaf),
// and the 8192-bit width.
#include <gtest/gtest.h>

#include "vx/blockchain/sva_vault.hpp"

#include <cstring>

using namespace vx::blockchain::sva;

namespace {

// A deterministic preimage set (values don't matter — the commitments do).
std::array<SvaPreimage, kSvaLeaves> make_set(uint8_t seed) {
    std::array<SvaPreimage, kSvaLeaves> set{};
    for (size_t i = 0; i < kSvaLeaves; ++i)
        for (size_t j = 0; j < kSvaPreimageSize; ++j)
            set[i][j] = static_cast<uint8_t>(i * 13 + j * 7 + seed);
    return set;
}

} // namespace

// Address derivation: deterministic, seed-sensitive, 256KiB set → 32B id.
TEST(SvaVaultTest, AddressDerivation) {
    const auto set = make_set(1);
    const auto a1 = sva_address_of(set);
    const auto a2 = sva_address_of(set);
    EXPECT_EQ(a1, a2);
    const auto other = make_set(2);
    EXPECT_NE(sva_address_of(other), a1);
    // The address is a sponge digest, not raw material.
    EXPECT_NE(a1[0] == 0 && a1[1] == 0 && a1[2] == 0, true);
}

// Spend verification happy path: every leaf position is spendable with its
// own preimage + path, in counter order.
TEST(SvaVaultTest, SpendVerificationHappy) {
    const auto set = make_set(5);
    const auto addr = sva_address_of(set);
    for (uint64_t counter : {uint64_t(0), uint64_t(1), uint64_t(128), uint64_t(255)}) {
        const auto path = sva_path_of(set, static_cast<uint8_t>(counter));
        EXPECT_TRUE(sva_verify_spend(addr, counter, set[counter], path))
            << "leaf " << counter << " must verify";
    }
}

// Tampering: a flipped preimage bit, a foreign path, a wrong counter.
TEST(SvaVaultTest, SpendTamperingRefused) {
    const auto set = make_set(5);
    const auto addr = sva_address_of(set);
    const auto path0 = sva_path_of(set, 0);

    // Flipped preimage bit.
    auto bad_pre = set[0];
    bad_pre[777] ^= 0x01;
    EXPECT_FALSE(sva_verify_spend(addr, 0, bad_pre, path0));

    // A path built for a DIFFERENT leaf.
    const auto path5 = sva_path_of(set, 5);
    EXPECT_FALSE(sva_verify_spend(addr, 0, set[0], path5))
        << "a path from another leaf must not walk to the root";

    // A valid preimage+path claimed at the WRONG counter (out-of-order
    // spend): leaf 1 cannot be spent as spend #0.
    const auto path1 = sva_path_of(set, 1);
    EXPECT_FALSE(sva_verify_spend(addr, 0, set[1], path1)) << "the counter binds the leaf order";
}

// Tombstone: after 256 spends the vault is dead — spend #256+ refused even
// with a perfectly valid (hypothetical) proof.
TEST(SvaVaultTest, TombstoneAfterMaxSpends) {
    const auto set = make_set(5);
    const auto addr = sva_address_of(set);
    EXPECT_FALSE(sva_verify_spend(addr, kSvaMaxSpends, set[0], sva_path_of(set, 0)));
    EXPECT_FALSE(sva_verify_spend(addr, 9999, set[0], sva_path_of(set, 0)));
    EXPECT_EQ(kSvaMaxSpends, 256u);
    EXPECT_EQ(kSvaPreimageSize * 8, 8192u) << "the 8192-bit width is the spec";
}

// The 256 KiB preimage set never leaves the owner: only 32B addresses and
// 256B paths circulate (the wire-weight pin).
TEST(SvaVaultTest, WireWeightPins) {
    EXPECT_EQ(sizeof(SvaAddress), 32u);
    EXPECT_EQ(sizeof(SvaMerklePath), 8 * 32u);
    EXPECT_EQ(sizeof(SvaPreimage), 1024u);
}
