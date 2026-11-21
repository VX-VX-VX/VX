#pragma once

#include "vx/blockchain/block.hpp"
#include "vx/crypto/pq_signature.hpp"
#include <array>
#include <string>
#include <vector>

namespace vx::blockchain {

// ── Deterministic genesis builder ────────────────────────────────────────────
// Block #0 is not shipped as a file: it is derived deterministically, in
// process, from the published canonical attractor seed (see the seed constant
// in the implementation). Every node and every test reconstructs the exact
// same 64 KiB frame bit-for-bit — "always regenerate, never copy" by design.

/// Builds the deterministic 64 KiB genesis frame (#0) in memory.
/// 1000-round Tri-Barrel attractor run (secure CRT moduli) → 504 B header (VXC7)
/// with the real attractor coordinates + 1 signed coinbase transaction.
BlockFrame build_genesis_frame();

/// Writes the deterministic genesis frame to `path` (exactly 65536 B).
/// Overwrites atomically-safe local files only; callers use it to materialize
/// genesis.bin next to a fresh ledger.
void write_genesis_file(const std::string& path);

/// Returns true if a genesis file exists at `path` or has just been written
/// there by the deterministic builder. Never reads network state.
bool ensure_genesis_file(const std::string& path);

/// The NFA address of the genesis coinbase receiver (deterministic).
std::string genesis_coinbase_receiver();

// ── PQ seed bindings (BACKLOG 0.7) ───────────────────────────────────────────

/// A protocol-level binding of a genesis-era address to the XMSS root of
/// the post-quantum key authorized to spend from it.
struct PqSeedBinding {
    Address addr{};
    std::array<uint8_t, 32> root{};
};

/// The deterministic binding table every node computes identically at boot:
///   - the genesis receiver is bound to an OFFLINE key: its root is a
///     protocol constant derived from a public tag ("VX_PQ_GENESIS_OFFLINE_
///     ROOT_V1"); the corresponding secret key is held offline by the
///     operator and is NOT in this repository — the 2.54M VX faucet is
///     effectively locked until the operator moves it with a real witness;
///   - the demo spender address (Address #2 of the canonical demo run) is
///     bound to the PUBLIC demo spender key ("VX_DEMO_SPENDER_SK_V1") — a
///     documented testnet test key, so the PQ authorization path is
///     exercised end-to-end by the demo and the cookbook;
///   - the demo receiver address is bound to its own offline root.
/// Every OTHER user address must be a self-certifying PQ address (payload
/// "PQA..." derived from its own key root) to spend at all.
const std::vector<PqSeedBinding>& pq_seed_bindings();

/// Canonical demo seeds/addresses (previously local to the demo binary, now
/// protocol constants so every node binds the same demo economy):
const std::string& demo_spender_seed_hex();   // Address #2 (spender)
const std::string& demo_receiver_seed_hex();  // Address #3 (target)
std::string demo_spender_address_nfa();       // "NFA_V6_..." (deterministic)
std::string demo_receiver_address_nfa();      // "NFA_V6_..." (deterministic)

// ── GQC epoch committee (plan step 3) ────────────────────────────────────────
// The first-epoch GQC validator whitelist: a protocol constant every node
// derives identically at boot. localhost topology (owner decision 18.11:
// "try it locally"): 4 deterministic test node_ids; the P4/VPS phase swaps
// in the real machine node_ids and the real master key's signature (the sk
// never ships).
struct GqcEpochMember {
    uint16_t validator_id;
    std::array<uint8_t, 32> node_id;
    // Phase C (0.2.2): the member's XMSS root. Every vote is verified
    // against THIS root — never against a root carried inside the witness
    // itself (a hostile peer cannot substitute an identity by claiming a
    // root it controls). The list is canonically sorted by root bytes, so
    // the bitmap bit index is deterministic across nodes.
    std::array<uint8_t, 32> root;
};

struct GqcEpochConfig {
    std::vector<GqcEpochMember> members;
    vx::crypto::pq::PqSignatureWitness master_sig; // the architect's master key signs the whitelist
    std::array<uint8_t, 32> master_root;           // the root the sig must verify against
    uint64_t epoch = 1;                            // bound into every vote message
};

/// The deterministic first-epoch committee: 4 localhost validators (ids 0..3)
/// with deterministic test node_ids and XMSS roots, master-signed and
/// self-checked at boot (fail-closed: an edited list breaks the self-check
/// at node start). Members are canonically sorted by root bytes.
const GqcEpochConfig &gqc_epoch_committee();

/// The domain-separated whitelist message the master signature commits to:
/// sponge("VX_GQC_EPOCH1_WHITELIST_V1" ‖ Σ validator_id(2 LE) ‖ node_id(32) ‖ root(32)).
/// Exposed so the node (and tests) verify the shipped (list, sig) pair
/// without re-deriving the tag.
std::array<uint8_t, 32> gqc_epoch_whitelist_msg(const std::vector<GqcEpochMember> &members);

/// True when `validator_id` is a member of the first-epoch committee.
/// The GQC vote-collection gate: a vote from a non-member id is forged.
bool gqc_epoch_committee_contains(uint16_t validator_id);

/// The member's root, canonical member index (bitmap bit), or npos when the
/// id is not on the whitelist. The vote verifier uses the root; the bitmap
/// builder uses the index.
size_t gqc_epoch_member_index(uint16_t validator_id);

/// The deterministic test secret key of epoch-1 validator `id`
/// ("VX_GQC_EPOCH1_VALIDATOR_<id>_SK_V1"). localhost topology only: the
/// P4/VPS phase replaces these with real per-machine keys held off-repo.
std::array<uint8_t, 32> gqc_epoch_validator_sk(uint16_t id);

// ── The one-time secondary genesis mint (review round 5, P1) ────────────────
// The mint's authorization used to be the keyless cocoon digest with only a
// height gate — whoever mined block 1 could mint ANY amount to ANY untracked
// receiver and capture the remaining supply at height 1. The mint is now
// bound to its exact protocol shape: 100,000 VX to the demo spender address
// (Address #2 of the canonical demo run), once, at height 1.
inline constexpr uint64_t GENESIS_2_MINT_ATOMICS = 100'000ULL * 100'000'000ULL;

/// The exact 42-byte receiver payload the one-time GENESIS_2 mint must pay
/// (the demo spender address, deterministic; computed once per process).
const Address& genesis2_mint_receiver_payload();

} // namespace vx::blockchain
