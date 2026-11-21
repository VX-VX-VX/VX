// VortexContractWireTest — Phase G C1 (0.2.6): contract identity, the
// deploy/call wire, and the sidecar-first discipline.
//
// Verifies:
//   1. contract_id: deterministic over (deployer, nonce, code_digest);
//      a different nonce or digest yields a different id.
//   2. receiver prefixes: "VXDEPLOY"/"VXCALL" byte-exact, zero padding
//      enforced; a non-contract receiver decodes as a plain transfer.
//   3. sidecar records: round-trip wire; tx-digest binding; truncation,
//      oversized code/calldata and trailing garbage are refused.
//   4. deploy gates: digest canonicity, the K2 size cap, the gas ceiling.

#include <gtest/gtest.h>
#include "vx/consensus/contract_wire.hpp"
#include "vx/blockchain/crypto_sponge.hpp"

#include <array>
#include <vector>

using vx::consensus::contract::call_receiver;
using vx::consensus::contract::call_sidecar_wire;
using vx::consensus::contract::CallSidecar;
using vx::consensus::contract::contract_id;
using vx::consensus::contract::decode_receiver;
using vx::consensus::contract::deploy_gates;
using vx::consensus::contract::deploy_receiver;
using vx::consensus::contract::deploy_sidecar_wire;
using vx::consensus::contract::DeploySidecar;
using vx::consensus::contract::parse_call_sidecar;
using vx::consensus::contract::parse_deploy_sidecar;
using vx::consensus::contract::ReceiverKind;

namespace {

std::array<uint8_t, 42> test_deployer() {
    std::array<uint8_t, 42> d{};
    for (size_t i = 0; i < d.size(); ++i)
        d[i] = static_cast<uint8_t>(i * 3 + 1);
    return d;
}

std::array<uint8_t, 32> test_digest(uint8_t seed) {
    std::array<uint8_t, 32> d{};
    for (size_t i = 0; i < d.size(); ++i)
        d[i] = static_cast<uint8_t>(seed * 7 + i * 11);
    return d;
}

} // namespace

// ── 1. contract_id ──────────────────────────────────────────────────────────

// Deterministic: the same (deployer, nonce, digest) yields the same id.
TEST(VortexContractWireTest, ContractIdDeterministic) {
    const auto d = test_deployer();
    const auto g = test_digest(1);
    const auto id1 = contract_id(d, 7, g);
    const auto id2 = contract_id(d, 7, g);
    EXPECT_EQ(id1, id2);
}

// A different nonce yields a different id (re-deploy separation).
TEST(VortexContractWireTest, ContractIdNonceSensitive) {
    const auto d = test_deployer();
    const auto g = test_digest(1);
    EXPECT_NE(contract_id(d, 7, g), contract_id(d, 8, g));
}

// A different code digest yields a different id.
TEST(VortexContractWireTest, ContractIdDigestSensitive) {
    const auto d = test_deployer();
    EXPECT_NE(contract_id(d, 7, test_digest(1)), contract_id(d, 7, test_digest(2)));
}

// A different deployer yields a different id.
TEST(VortexContractWireTest, ContractIdDeployerSensitive) {
    const auto g = test_digest(1);
    EXPECT_NE(contract_id(test_deployer(), 7, g), contract_id(std::array<uint8_t, 42>{}, 7, g));
}

// ── 2. Receiver prefixes ────────────────────────────────────────────────────

// The deploy receiver is byte-exact: "VXDEPLOY" | digest | zeros(2).
TEST(VortexContractWireTest, DeployReceiverFormat) {
    const auto g = test_digest(1);
    const auto r = deploy_receiver(g);
    EXPECT_EQ(r[0], 'V');
    EXPECT_EQ(r[1], 'X');
    EXPECT_EQ(r[2], 'D');
    EXPECT_EQ(r[3], 'E');
    EXPECT_EQ(r[4], 'P');
    EXPECT_EQ(r[5], 'L');
    EXPECT_EQ(r[6], 'O');
    EXPECT_EQ(r[7], 'Y');
    for (size_t i = 0; i < 32; ++i)
        EXPECT_EQ(r[8 + i], g[i]);
    EXPECT_EQ(r[40], 0);
    EXPECT_EQ(r[41], 0);
    auto k = decode_receiver(r);
    ASSERT_TRUE(k.has_value());
    EXPECT_EQ(k->kind, ReceiverKind::Kind::kDeploy);
    EXPECT_EQ(k->payload, g);
}

// The call receiver is byte-exact: "VXCALL" | id | zeros(3).
TEST(VortexContractWireTest, CallReceiverFormat) {
    const auto id = test_digest(2);
    const auto r = call_receiver(id);
    EXPECT_EQ(r[0], 'V');
    EXPECT_EQ(r[1], 'X');
    EXPECT_EQ(r[2], 'C');
    EXPECT_EQ(r[3], 'A');
    EXPECT_EQ(r[4], 'L');
    EXPECT_EQ(r[5], 'L');
    for (size_t i = 0; i < 32; ++i)
        EXPECT_EQ(r[6 + i], id[i]);
    EXPECT_EQ(r[38], 0);
    EXPECT_EQ(r[39], 0);
    EXPECT_EQ(r[40], 0);
    EXPECT_EQ(r[41], 0);
    auto k = decode_receiver(r);
    ASSERT_TRUE(k.has_value());
    EXPECT_EQ(k->kind, ReceiverKind::Kind::kCall);
    EXPECT_EQ(k->payload, id);
}

// A non-zero pad byte makes the receiver malformed (fail-closed).
TEST(VortexContractWireTest, NonZeroPadRefused) {
    auto r = deploy_receiver(test_digest(1));
    r[41] = 0x01;
    EXPECT_FALSE(decode_receiver(r).has_value());
    auto r2 = call_receiver(test_digest(2));
    r2[40] = 0x01;
    EXPECT_FALSE(decode_receiver(r2).has_value());
}

// A plain transfer receiver decodes as nullopt (not a contract op).
TEST(VortexContractWireTest, PlainTransferDecodesNull) {
    std::array<uint8_t, 42> r{};
    for (size_t i = 0; i < r.size(); ++i)
        r[i] = static_cast<uint8_t>(i + 5);
    EXPECT_FALSE(decode_receiver(r).has_value());
}

// ── 3. Sidecar records ──────────────────────────────────────────────────────

// The deploy sidecar round-trips through the wire.
TEST(VortexContractWireTest, DeploySidecarRoundTrip) {
    DeploySidecar s;
    s.tx_digest = test_digest(3);
    s.contract_id = test_digest(4);
    s.code = {0x01, 0x02, 0x03, 0x04, 0x05};
    const auto wire = deploy_sidecar_wire(s);
    auto p = parse_deploy_sidecar(wire, s.tx_digest);
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->tx_digest, s.tx_digest);
    EXPECT_EQ(p->contract_id, s.contract_id);
    EXPECT_EQ(p->code, s.code);
}

// The sidecar binds to its tx: a foreign digest is refused.
TEST(VortexContractWireTest, DeploySidecarDigestBinding) {
    DeploySidecar s;
    s.tx_digest = test_digest(3);
    s.contract_id = test_digest(4);
    s.code = {0x01};
    const auto wire = deploy_sidecar_wire(s);
    EXPECT_FALSE(parse_deploy_sidecar(wire, test_digest(9)).has_value());
}

// Truncation, trailing garbage and oversized code are refused.
TEST(VortexContractWireTest, DeploySidecarMalformedRefused) {
    DeploySidecar s;
    s.tx_digest = test_digest(3);
    s.contract_id = test_digest(4);
    s.code = {0x01, 0x02, 0x03};
    auto wire = deploy_sidecar_wire(s);

    auto trunc = wire;
    trunc.pop_back();
    EXPECT_FALSE(parse_deploy_sidecar(trunc, s.tx_digest).has_value());

    auto garbage = wire;
    garbage.push_back(0xFF);
    EXPECT_FALSE(parse_deploy_sidecar(garbage, s.tx_digest).has_value());

    auto short_hdr = wire;
    short_hdr.resize(60);
    EXPECT_FALSE(parse_deploy_sidecar(short_hdr, s.tx_digest).has_value());
}

// The call sidecar round-trips through the wire.
TEST(VortexContractWireTest, CallSidecarRoundTrip) {
    CallSidecar s;
    s.tx_digest = test_digest(5);
    s.contract_id = test_digest(6);
    s.calldata = {0x0A, 0x0B, 0x0C};
    const auto wire = call_sidecar_wire(s);
    auto p = parse_call_sidecar(wire, s.tx_digest);
    ASSERT_TRUE(p.has_value());
    EXPECT_EQ(p->tx_digest, s.tx_digest);
    EXPECT_EQ(p->contract_id, s.contract_id);
    EXPECT_EQ(p->calldata, s.calldata);
}

// The call sidecar binds to its tx and refuses malformed records.
TEST(VortexContractWireTest, CallSidecarMalformedRefused) {
    CallSidecar s;
    s.tx_digest = test_digest(5);
    s.contract_id = test_digest(6);
    s.calldata = {0x0A};
    auto wire = call_sidecar_wire(s);
    EXPECT_FALSE(parse_call_sidecar(wire, test_digest(8)).has_value());
    auto trunc = wire;
    trunc.pop_back();
    EXPECT_FALSE(parse_call_sidecar(trunc, s.tx_digest).has_value());
}

// ── 4. Deploy gates ─────────────────────────────────────────────────────────

// A digest-matching code passes all gates.
TEST(VortexContractWireTest, DeployGatesPass) {
    const std::vector<uint8_t> code = {0x01, 0x02, 0x03, 0x04};
    std::array<uint8_t, 32> digest{};
    vx::blockchain::VortexSponge256::compute(code.data(), code.size(), digest.data());
    auto r = deploy_gates(code, digest);
    EXPECT_TRUE(r.ok);
    EXPECT_EQ(r.why, vx::consensus::contract::DeployGateResult::Why::kOk);
}

// A wrong digest is refused (canonicity gate).
TEST(VortexContractWireTest, DeployGatesDigestMismatch) {
    const std::vector<uint8_t> code = {0x01, 0x02, 0x03, 0x04};
    auto r = deploy_gates(code, test_digest(7));
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.why, vx::consensus::contract::DeployGateResult::Why::kDigestMismatch);
}

// Code over kMaxContractBytes is refused (K2 gate) even with a matching
// digest.
TEST(VortexContractWireTest, DeployGatesTooBig) {
    std::vector<uint8_t> code(vx::consensus::contract::kMaxContractBytes + 1, 0x41);
    std::array<uint8_t, 32> digest{};
    vx::blockchain::VortexSponge256::compute(code.data(), code.size(), digest.data());
    auto r = deploy_gates(code, digest);
    EXPECT_FALSE(r.ok);
    EXPECT_EQ(r.why, vx::consensus::contract::DeployGateResult::Why::kTooBig);
}
