#pragma once

// Contract wire — Phase G C1 (0.2.6): contract identity, deploy/call
// wire formats, and the sidecar-first discipline (C0 spec §2).
//
// Everything here is the PURE layer: identity derivation, wire parsing,
// and the deploy-gate checks that run BEFORE any state mutation. The
// ledger wiring (CODE-namespace leaf, .contr sidecar body, undo records)
// is the next normative step.

#include "vx/blockchain/crypto_sponge.hpp"

#include <array>
#include <cstdint>
#include <optional>
#include <vector>

namespace vx::consensus::contract {

// ── Constants (C0 spec, K2 candidate) ───────────────────────────────────────

/// Max contract code bytes (OPEN K2, candidate 16384).
inline constexpr uint32_t kMaxContractBytes = 16384;
/// Max calldata bytes (C0 §2.3: calldata always travels as a sidecar;
/// the cap is pinned at C1 against the real tx format).
inline constexpr uint32_t kMaxCalldataBytes = 112;
/// Max gas per block for the deploy gas-ceiling gate (C0 §3.3, OPEN —
/// the exact table is pinned at C2; this is the coarse fail-closed
/// ceiling used at C1).
inline constexpr uint64_t kMaxGasPerBlockConst = 1'000'000'000;

// ── Identity (C0 §2.1) ──────────────────────────────────────────────────────

/// contract_id = Sponge256("VX_CONTRACT_ID_V1" | deployer(42B) |
///                         deploy_nonce(u32 LE) | code_digest(32)).
/// Deterministic; a re-deploy at the same nonce yields the same id
/// (idempotent, conflict-free).
std::array<uint8_t, 32> contract_id(const std::array<uint8_t, 42> &deployer, uint32_t deploy_nonce,
                                    const std::array<uint8_t, 32> &code_digest) noexcept;

// ── Receiver prefixes (C0 §2.2/§2.3) ────────────────────────────────────────

/// The 42-byte receiver for a deploy: "VXDEPLOY" (8B) | code_digest(32) |
/// zeros(2). The digest is the SPONGE256(code) — the canonical digest.
std::array<uint8_t, 42> deploy_receiver(const std::array<uint8_t, 32> &code_digest) noexcept;

/// The 42-byte receiver for a call: "VXCALL" (7B) | contract_id(32) |
/// zeros(3).
std::array<uint8_t, 42> call_receiver(const std::array<uint8_t, 32> &id) noexcept;

/// Decodes a 42-byte receiver into its kind and payload. Returns nullopt
/// if the prefix is neither a deploy nor a call (the tx is a normal
/// transfer — not a contract operation).
struct ReceiverKind {
    enum class Kind : uint8_t { kTransfer, kDeploy, kCall };
    Kind kind = Kind::kTransfer;
    std::array<uint8_t, 32> payload{}; // code_digest or contract_id
};
std::optional<ReceiverKind> decode_receiver(const std::array<uint8_t, 42> &receiver) noexcept;

// ── Sidecar records (C0 §2.2/§2.3) ─────────────────────────────────────────

/// The deploy sidecar record (.contr): digest(tx)(32) | contract_id(32) |
/// code_len(4) | code_bytes. The tx digest binds the sidecar to the tx.
struct DeploySidecar {
    std::array<uint8_t, 32> tx_digest{};
    std::array<uint8_t, 32> contract_id{};
    std::vector<uint8_t> code;
};
/// Serializes the deploy sidecar exactly as the C0 §2.2 wire says.
std::vector<uint8_t> deploy_sidecar_wire(const DeploySidecar &s) noexcept;
/// Parses the deploy sidecar from the wire. Returns nullopt on any
/// malformed record (truncation, digest mismatch, oversized code).
std::optional<DeploySidecar>
parse_deploy_sidecar(const std::vector<uint8_t> &wire,
                     const std::array<uint8_t, 32> &tx_digest) noexcept;

/// The call sidecar record: digest(tx)(32) | contract_id(32) |
/// calldata_len(4) | calldata.
struct CallSidecar {
    std::array<uint8_t, 32> tx_digest{};
    std::array<uint8_t, 32> contract_id{};
    std::vector<uint8_t> calldata;
};
/// Serializes the call sidecar exactly as the C0 §2.3 wire says.
std::vector<uint8_t> call_sidecar_wire(const CallSidecar &s) noexcept;
/// Parses the call sidecar from the wire. Returns nullopt on any
/// malformed record (truncation, digest mismatch, oversized calldata).
std::optional<CallSidecar> parse_call_sidecar(const std::vector<uint8_t> &wire,
                                              const std::array<uint8_t, 32> &tx_digest) noexcept;

// ── Deploy gates (C0 §2.2) — run BEFORE any state mutation ────────────────

/// The deploy gates:
///   1) Sponge256(code) == code_digest (canonicity);
///   2) code_len <= kMaxContractBytes (K2);
///   3) the static gas estimate <= kMaxGasPerBlock (the exact table is
///      pinned at C2 — here a coarse ceiling: code_len * kGasPerByteCeil).
struct DeployGateResult {
    bool ok = false;
    enum class Why : uint8_t {
        kOk,
        kDigestMismatch,
        kTooBig,
        kGasCeilBreach,
    };
    Why why = Why::kOk;
};
DeployGateResult deploy_gates(const std::vector<uint8_t> &code,
                              const std::array<uint8_t, 32> &code_digest) noexcept;

} // namespace vx::consensus::contract
