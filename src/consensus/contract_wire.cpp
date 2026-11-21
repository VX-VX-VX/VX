// Contract wire — Phase G C1 (0.2.6): implementation of the pure layer.
//
// Discipline notes:
//  - contract_id is deterministic: Sponge256 over the canonical fields
//    (tag | deployer | nonce LE | code_digest).
//  - Receiver prefixes are byte-exact: "VXDEPLOY" | digest | zeros(2)
//    and "VXCALL" | id | zeros(3). The zero padding is part of the
//    format — a non-zero pad byte is a malformed receiver.
//  - Sidecar records are parsed fail-closed: truncation, a tx-digest
//    mismatch, or an oversized code/calldata is a nullopt.
//  - Deploy gates run BEFORE any state mutation (sidecar-first
//    discipline, C0 §2.2).

#include "vx/consensus/contract_wire.hpp"

#include <cstring>

namespace vx::consensus::contract {

namespace {

inline void put_u32_le(std::vector<uint8_t> &out, uint32_t v) {
    out.push_back(static_cast<uint8_t>(v));
    out.push_back(static_cast<uint8_t>(v >> 8));
    out.push_back(static_cast<uint8_t>(v >> 16));
    out.push_back(static_cast<uint8_t>(v >> 24));
}

inline bool get_u32_le(const uint8_t *p, uint32_t &v) {
    v = static_cast<uint32_t>(p[0]) | (static_cast<uint32_t>(p[1]) << 8) |
        (static_cast<uint32_t>(p[2]) << 16) | (static_cast<uint32_t>(p[3]) << 24);
    return true;
}

} // namespace

std::array<uint8_t, 32> contract_id(const std::array<uint8_t, 42> &deployer, uint32_t deploy_nonce,
                                    const std::array<uint8_t, 32> &code_digest) noexcept {
    blockchain::VortexSponge256 sponge;
    const uint8_t tag[] = "VX_CONTRACT_ID_V1";
    sponge.absorb(tag, sizeof(tag) - 1);
    sponge.absorb(deployer.data(), deployer.size());
    const uint8_t nonce_le[4] = {
        static_cast<uint8_t>(deploy_nonce), static_cast<uint8_t>(deploy_nonce >> 8),
        static_cast<uint8_t>(deploy_nonce >> 16), static_cast<uint8_t>(deploy_nonce >> 24)};
    sponge.absorb(nonce_le, 4);
    sponge.absorb(code_digest.data(), code_digest.size());
    std::array<uint8_t, 32> out{};
    sponge.finalize(out.data());
    return out;
}

std::array<uint8_t, 42> deploy_receiver(const std::array<uint8_t, 32> &code_digest) noexcept {
    std::array<uint8_t, 42> r{};
    ::memcpy(r.data(), "VXDEPLOY", 8);
    ::memcpy(r.data() + 8, code_digest.data(), 32);
    // r[40..41] stay zero.
    return r;
}

std::array<uint8_t, 42> call_receiver(const std::array<uint8_t, 32> &id) noexcept {
    std::array<uint8_t, 42> r{};
    ::memcpy(r.data(), "VXCALL", 6);
    ::memcpy(r.data() + 6, id.data(), 32);
    // r[38..41] stay zero.
    return r;
}

std::optional<ReceiverKind> decode_receiver(const std::array<uint8_t, 42> &receiver) noexcept {
    ReceiverKind out;
    if (::memcmp(receiver.data(), "VXDEPLOY", 8) == 0) {
        if (receiver[40] != 0 || receiver[41] != 0)
            return std::nullopt; // non-zero pad: malformed
        ::memcpy(out.payload.data(), receiver.data() + 8, 32);
        out.kind = ReceiverKind::Kind::kDeploy;
        return out;
    }
    if (::memcmp(receiver.data(), "VXCALL", 6) == 0) {
        if (receiver[38] != 0 || receiver[39] != 0 || receiver[40] != 0 || receiver[41] != 0)
            return std::nullopt;
        ::memcpy(out.payload.data(), receiver.data() + 6, 32);
        out.kind = ReceiverKind::Kind::kCall;
        return out;
    }
    return std::nullopt; // a normal transfer
}

std::vector<uint8_t> deploy_sidecar_wire(const DeploySidecar &s) noexcept {
    std::vector<uint8_t> out;
    out.reserve(32 + 32 + 4 + s.code.size());
    out.insert(out.end(), s.tx_digest.begin(), s.tx_digest.end());
    out.insert(out.end(), s.contract_id.begin(), s.contract_id.end());
    put_u32_le(out, static_cast<uint32_t>(s.code.size()));
    out.insert(out.end(), s.code.begin(), s.code.end());
    return out;
}

std::optional<DeploySidecar>
parse_deploy_sidecar(const std::vector<uint8_t> &wire,
                     const std::array<uint8_t, 32> &tx_digest) noexcept {
    if (wire.size() < 32 + 32 + 4)
        return std::nullopt;
    DeploySidecar s;
    ::memcpy(s.tx_digest.data(), wire.data(), 32);
    if (s.tx_digest != tx_digest)
        return std::nullopt; // the sidecar binds to another tx
    ::memcpy(s.contract_id.data(), wire.data() + 32, 32);
    uint32_t code_len = 0;
    get_u32_le(wire.data() + 64, code_len);
    if (code_len > kMaxContractBytes)
        return std::nullopt; // oversized code: fail-closed
    if (wire.size() != 32 + 32 + 4 + code_len)
        return std::nullopt; // truncation or trailing garbage
    s.code.assign(wire.begin() + 68, wire.end());
    return s;
}

std::vector<uint8_t> call_sidecar_wire(const CallSidecar &s) noexcept {
    std::vector<uint8_t> out;
    out.reserve(32 + 32 + 4 + s.calldata.size());
    out.insert(out.end(), s.tx_digest.begin(), s.tx_digest.end());
    out.insert(out.end(), s.contract_id.begin(), s.contract_id.end());
    put_u32_le(out, static_cast<uint32_t>(s.calldata.size()));
    out.insert(out.end(), s.calldata.begin(), s.calldata.end());
    return out;
}

std::optional<CallSidecar> parse_call_sidecar(const std::vector<uint8_t> &wire,
                                              const std::array<uint8_t, 32> &tx_digest) noexcept {
    if (wire.size() < 32 + 32 + 4)
        return std::nullopt;
    CallSidecar s;
    ::memcpy(s.tx_digest.data(), wire.data(), 32);
    if (s.tx_digest != tx_digest)
        return std::nullopt; // the sidecar binds to another tx
    ::memcpy(s.contract_id.data(), wire.data() + 32, 32);
    uint32_t calldata_len = 0;
    get_u32_le(wire.data() + 64, calldata_len);
    if (calldata_len > kMaxCalldataBytes)
        return std::nullopt; // oversized calldata: fail-closed
    if (wire.size() != 32 + 32 + 4 + calldata_len)
        return std::nullopt; // truncation or trailing garbage
    s.calldata.assign(wire.begin() + 68, wire.end());
    return s;
}

DeployGateResult deploy_gates(const std::vector<uint8_t> &code,
                              const std::array<uint8_t, 32> &code_digest) noexcept {
    DeployGateResult r;
    std::array<uint8_t, 32> actual{};
    blockchain::VortexSponge256::compute(code.data(), code.size(), actual.data());
    if (actual != code_digest) {
        r.why = DeployGateResult::Why::kDigestMismatch;
        return r;
    }
    if (code.size() > kMaxContractBytes) {
        r.why = DeployGateResult::Why::kTooBig;
        return r;
    }
    // The static gas ceiling: code_len * kGasPerByteCeil. The exact table
    // is pinned at C2; the ceiling is coarse and fail-closed.
    constexpr uint64_t kGasPerByteCeil = 1000;
    const uint64_t est = code.size() * kGasPerByteCeil;
    if (est > kMaxGasPerBlockConst) {
        r.why = DeployGateResult::Why::kGasCeilBreach;
        return r;
    }
    r.ok = true;
    return r;
}

} // namespace vx::consensus::contract
