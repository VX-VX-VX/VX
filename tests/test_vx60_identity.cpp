// test_vx60_identity.cpp — VX60-SEC M2 transport identity (owner-directed,
// whitebook §4.6). Pins: node_id derivation, persist roundtrip, and the
// fail-closed chain (tampered id / swapped keypair / corrupted dk → refuse).
#include <gtest/gtest.h>

#include "vx/net/vx60_identity.hpp"

#include <cstring>
#include <filesystem>
#include <string>

using namespace vx::net::vx60;

namespace {

std::string tmp_dir(const char *tag) {
    auto dir = std::filesystem::temp_directory_path() /
               (std::string(tag) + "_" + std::to_string(::getpid()));
    std::filesystem::create_directories(dir);
    return dir.string();
}

} // namespace

// node_id is a pure function of the public key (domain-tagged sponge).
TEST(Vx60IdentityTest, NodeIdDerivationDeterministic) {
    vx::crypto::mlkem::PublicKey ek;
    ek.fill(0xA5);
    const auto id1 = node_id_for(ek);
    const auto id2 = node_id_for(ek);
    EXPECT_EQ(id1, id2);
    // A different pk MUST derive a different id (domain separation sanity).
    auto ek2 = ek;
    ek2[0] ^= 0x01;
    EXPECT_NE(node_id_for(ek2), id1);
}

// Create → load roundtrip: the same identity comes back, 0600, and the
// keypair passes the encaps/decaps consistency exercise.
TEST(Vx60IdentityTest, CreateLoadRoundtrip) {
    const std::string dir = tmp_dir("vx_vx60id_roundtrip");
    TransportIdentity a, b;
    std::string err;
    ASSERT_TRUE(TransportIdentityStore::load_or_create(dir, a, err)) << err;
    EXPECT_EQ(a.node_id, node_id_for(a.static_ek));
    EXPECT_FALSE(a.prev_ek.has_value()) << "M2 never populates the M4 slot";
    ASSERT_TRUE(TransportIdentityStore::load_or_create(dir, b, err)) << err;
    EXPECT_EQ(a.node_id, b.node_id);
    EXPECT_EQ(a.static_ek, b.static_ek);
    EXPECT_EQ(a.static_dk, b.static_dk);
    // Permissions: 0600.
    struct stat st{};
    ASSERT_EQ(::stat((dir + "/vx60_identity").c_str(), &st), 0);
    EXPECT_EQ(st.st_mode & 0777, 0600) << "the identity file must be owner-only";
    std::filesystem::remove_all(dir);
}

// Fail-closed chain, id tampering: flipping one id byte is refused and the
// file is NOT rewritten (an operator decision, never a silent rekey).
TEST(Vx60IdentityTest, TamperedIdRefused) {
    const std::string dir = tmp_dir("vx_vx60id_tamper_id");
    TransportIdentity a;
    std::string err;
    ASSERT_TRUE(TransportIdentityStore::load_or_create(dir, a, err)) << err;

    std::filesystem::resize_file(dir + "/vx60_identity", 3624);
    int fd = ::open((dir + "/vx60_identity").c_str(), O_WRONLY);
    ASSERT_GE(fd, 0);
    const uint8_t flip = a.node_id[0] ^ 0x01;
    ASSERT_EQ(::pwrite(fd, &flip, 1, 8), 1); // the id field sits at offset 8
    ::close(fd);

    TransportIdentity b;
    EXPECT_FALSE(TransportIdentityStore::load_or_create(dir, b, err));
    EXPECT_NE(err.find("node_id mismatch"), std::string::npos) << err;
    std::filesystem::remove_all(dir);
}

// Fail-closed chain, dk corruption: the pair-consistency exercise refuses.
TEST(Vx60IdentityTest, TamperedSecretRefused) {
    const std::string dir = tmp_dir("vx_vx60id_tamper_dk");
    TransportIdentity a;
    std::string err;
    ASSERT_TRUE(TransportIdentityStore::load_or_create(dir, a, err)) << err;

    int fd = ::open((dir + "/vx60_identity").c_str(), O_WRONLY);
    ASSERT_GE(fd, 0);
    const off_t dk_off = 8 + 32 + 1184; // magic ‖ id ‖ ek ‖ dk
    uint8_t buf[64];
    std::memset(buf, 0x5A, sizeof(buf));
    ASSERT_EQ(::pwrite(fd, buf, sizeof(buf), dk_off), (ssize_t)sizeof(buf));
    ::close(fd);

    TransportIdentity b;
    EXPECT_FALSE(TransportIdentityStore::load_or_create(dir, b, err));
    EXPECT_NE(err.find("keypair consistency"), std::string::npos) << err;
    std::filesystem::remove_all(dir);
}

// A torn file (short read) is refused — never silently rekeyed.
TEST(Vx60IdentityTest, TornFileRefused) {
    const std::string dir = tmp_dir("vx_vx60id_torn");
    TransportIdentity a;
    std::string err;
    ASSERT_TRUE(TransportIdentityStore::load_or_create(dir, a, err)) << err;
    std::filesystem::resize_file(dir + "/vx60_identity", 1000);
    TransportIdentity b;
    EXPECT_FALSE(TransportIdentityStore::load_or_create(dir, b, err));
    EXPECT_NE(err.find("short read"), std::string::npos) << err;
    std::filesystem::remove_all(dir);
}
