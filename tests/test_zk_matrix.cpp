#include <gtest/gtest.h>
#include "vx/crypto/zk_key_matrix.hpp"
#include <array>
#include <vector>
#include <set>

TEST(VortexZkKeyMatrixTest, DeriveAll7KeyTiers) {
    vx::crypto::ZKKeyMatrix zk;
    std::array<uint8_t, 256> master_seed{};
    for (size_t i = 0; i < 256; ++i) master_seed[i] = static_cast<uint8_t>(i);

    auto keys = zk.derive_all_keys(master_seed);

    EXPECT_EQ(keys[0].tier_name, "SpendingKey");
    EXPECT_TRUE(keys[0].is_spending_key);
    EXPECT_TRUE(keys[0].can_sign);

    EXPECT_EQ(keys[1].tier_name, "FullViewingKey");
    EXPECT_FALSE(keys[1].is_spending_key);
    EXPECT_FALSE(keys[1].can_sign);
    EXPECT_TRUE(keys[1].can_view_inputs);
    EXPECT_TRUE(keys[1].can_view_outputs);
    EXPECT_TRUE(keys[1].can_view_balance);

    EXPECT_EQ(keys[2].tier_name, "IncomingViewingKey");
    EXPECT_TRUE(keys[2].can_view_inputs);
    EXPECT_FALSE(keys[2].can_view_outputs);

    EXPECT_EQ(keys[3].tier_name, "OutgoingViewingKey");
    EXPECT_FALSE(keys[3].can_view_inputs);
    EXPECT_TRUE(keys[3].can_view_outputs);

    EXPECT_EQ(keys[4].tier_name, "TimeLockMaintenanceKey");
    EXPECT_EQ(keys[5].tier_name, "MultiSigRecoveryKey");
    EXPECT_EQ(keys[6].tier_name, "EphemeralKey");
}

TEST(VortexZkKeyMatrixTest, All7KeysArePairwiseDistinct) {
    vx::crypto::ZKKeyMatrix zk;
    std::array<uint8_t, 256> master_seed{};
    for (size_t i = 0; i < 256; ++i) master_seed[i] = static_cast<uint8_t>(i);

    auto keys = zk.derive_all_keys(master_seed);

    std::set<std::array<uint8_t, 32>> unique_keys;
    for (int i = 0; i < 7; ++i)
        unique_keys.insert(keys[i].key_data);
    EXPECT_EQ(unique_keys.size(), 7) << "All 7 keys must be distinct";
}

TEST(VortexZkKeyMatrixTest, ShamirSecretSharingRecovery) {
    vx::crypto::ZKKeyMatrix zk;
    std::array<uint8_t, 32> secret{};
    for (size_t i = 0; i < 32; ++i) secret[i] = static_cast<uint8_t>(0xAA + i);

    auto shards = zk.generate_shamir_shards(secret, 2);
    EXPECT_EQ(shards.size(), 3);

    // Recover using shards {0,1} (x=1, x=2)
    std::vector<vx::crypto::ZKKeyMatrix::ShamirShard> subset01 = {shards[0], shards[1]};
    auto recovered01 = zk.recover_shamir_secret(subset01);
    EXPECT_EQ(recovered01, secret) << "Shards 0&1 recovery failed";

    // Recover using shards {1,2} (x=2, x=3)
    std::vector<vx::crypto::ZKKeyMatrix::ShamirShard> subset12 = {shards[1], shards[2]};
    auto recovered12 = zk.recover_shamir_secret(subset12);
    EXPECT_EQ(recovered12, secret) << "Shards 1&2 recovery failed";

    // Recover using shards {0,2} (x=1, x=3)
    std::vector<vx::crypto::ZKKeyMatrix::ShamirShard> subset02 = {shards[0], shards[2]};
    auto recovered02 = zk.recover_shamir_secret(subset02);
    EXPECT_EQ(recovered02, secret) << "Shards 0&2 recovery failed";

    // Verify all 32 bytes recovered correctly
    for (int i = 0; i < 32; ++i) {
        EXPECT_EQ(recovered01[i], secret[i]) << "Byte " << i << " mismatch in 0&1";
        EXPECT_EQ(recovered12[i], secret[i]) << "Byte " << i << " mismatch in 1&2";
        EXPECT_EQ(recovered02[i], secret[i]) << "Byte " << i << " mismatch in 0&2";
    }
}

TEST(VortexZkKeyMatrixTest, ShamirAll32BytesComputed) {
    vx::crypto::ZKKeyMatrix zk;
    std::array<uint8_t, 32> secret{};
    for (size_t i = 0; i < 32; ++i) secret[i] = static_cast<uint8_t>(i * 7 + 3);

    auto shards = zk.generate_shamir_shards(secret, 2);

    for (int s = 0; s < 3; ++s) {
        bool all_zero = true;
        for (int i = 0; i < 32; ++i)
            if (shards[s].y[i] != 0) { all_zero = false; break; }
        EXPECT_FALSE(all_zero) << "Shard " << s << " has all zero bytes";
        EXPECT_EQ(shards[s].x, s + 1);
    }
}

TEST(VortexZkKeyMatrixTest, ProofOfLifeAndAuditView) {
    vx::crypto::ZKKeyMatrix zk;
    std::array<uint8_t, 32> tlmk{};
    tlmk.fill(0x42);

    auto proof = zk.generate_proof_of_life(tlmk);
    EXPECT_TRUE(zk.verify_proof_of_life(proof)) << "Valid proof must pass";
    EXPECT_NE(proof.timestamp, 0);
    EXPECT_TRUE(proof.valid);

    // Commitment must be non-zero
    bool commitment_nonzero = false;
    for (uint8_t b : proof.commitment)
        if (b != 0) { commitment_nonzero = true; break; }
    EXPECT_TRUE(commitment_nonzero) << "Commitment must be non-zero";

    // FVK audit
    auto fvk_audit = zk.audit_view(tlmk, true, false, false);
    EXPECT_TRUE(fvk_audit.can_view_inputs);
    EXPECT_TRUE(fvk_audit.can_view_outputs);
    EXPECT_TRUE(fvk_audit.can_view_balance);

    bool audit_commit_nonzero = false;
    for (uint8_t b : fvk_audit.audit_commitment)
        if (b != 0) { audit_commit_nonzero = true; break; }
    EXPECT_TRUE(audit_commit_nonzero) << "FVK audit_commitment must be non-zero";

    // IVK audit
    auto ivk_audit = zk.audit_view(tlmk, false, true, false);
    EXPECT_TRUE(ivk_audit.can_view_inputs);
    EXPECT_FALSE(ivk_audit.can_view_outputs);
    EXPECT_FALSE(ivk_audit.can_view_balance);

    // OVK audit
    auto ovk_audit = zk.audit_view(tlmk, false, false, true);
    EXPECT_FALSE(ovk_audit.can_view_inputs);
    EXPECT_TRUE(ovk_audit.can_view_outputs);
    EXPECT_FALSE(ovk_audit.can_view_balance);
}

TEST(VortexZkKeyMatrixTest, ForgedProofHashReturnsFalse) {
    vx::crypto::ZKKeyMatrix zk;
    std::array<uint8_t, 32> tlmk{};
    tlmk.fill(0x42);

    auto proof = zk.generate_proof_of_life(tlmk);
    EXPECT_TRUE(zk.verify_proof_of_life(proof)) << "Valid proof should pass";

    // Forge the proof_hash but keep valid=true
    proof.proof_hash.fill(0xFF);
    proof.valid = true;

    bool forged_result = zk.verify_proof_of_life(proof);
    EXPECT_FALSE(forged_result) << "Forged proof_hash with valid=true must return false";

    // Restore and verify again passes
    auto original = zk.generate_proof_of_life(tlmk);
    EXPECT_TRUE(zk.verify_proof_of_life(original)) << "Original proof should still pass";
}

TEST(VortexZkKeyMatrixTest, AuditViewRejectsZeroKey) {
    vx::crypto::ZKKeyMatrix zk;
    std::array<uint8_t, 32> zero_key{};
    zero_key.fill(0);

    auto audit = zk.audit_view(zero_key, true, false, false);
    bool all_zero = true;
    for (uint8_t b : audit.audit_commitment)
        if (b != 0) { all_zero = false; break; }
    EXPECT_TRUE(all_zero) << "Zero viewing key should produce zero audit_commitment";
}

TEST(VortexZkKeyMatrixTest, ProofOfLifeTimeWindow) {
    vx::crypto::ZKKeyMatrix zk;
    std::array<uint8_t, 32> tlmk{};
    tlmk.fill(0x42);

    auto proof = zk.generate_proof_of_life(tlmk);
    EXPECT_TRUE(zk.verify_proof_of_life(proof));

    // Test future timestamp (should fail)
    proof.timestamp = proof.timestamp + 315360001;
    EXPECT_FALSE(zk.verify_proof_of_life(proof)) << "Future timestamp beyond window should fail";

    // Test very old timestamp (should fail)
    proof.timestamp = 1;
    EXPECT_FALSE(zk.verify_proof_of_life(proof)) << "Old timestamp beyond window should fail";
}

TEST(VortexZkKeyMatrixTest, ShamirThreshold3) {
    vx::crypto::ZKKeyMatrix zk;
    std::array<uint8_t, 32> secret{};
    for (size_t i = 0; i < 32; ++i) secret[i] = static_cast<uint8_t>(i * 13 + 7);

    auto shards = zk.generate_shamir_shards(secret, 3);
    EXPECT_EQ(shards.size(), 3);

    std::vector<vx::crypto::ZKKeyMatrix::ShamirShard> all_shards = {
        shards[0], shards[1], shards[2]};
    auto recovered = zk.recover_shamir_secret(all_shards);
    EXPECT_EQ(recovered, secret) << "3-of-3 recovery failed";
}

int main(int argc, char** argv) {
    ::testing::InitGoogleTest(&argc, argv);
    return RUN_ALL_TESTS();
}