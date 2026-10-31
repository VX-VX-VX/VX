#pragma once

#include <cstdint>
#include <array>
#include <vector>
#include <string>
#include <optional>
#include <span>

#include "vx/blockchain/block.hpp"

namespace vx::crypto {

// 7-Tier Zero-Knowledge Key Matrix
class ZKKeyMatrix {
public:
    static constexpr size_t MASTER_SEED_BITS = 2048;
    static constexpr size_t SHAMIR_SHARDS = 3;
    static constexpr size_t SHAMIR_THRESHOLD = 2;
    static constexpr size_t HASH_SIZE = 32;

    struct KeyTier {
        std::array<uint8_t, 32> key_data;
        std::string tier_name;
        bool is_spending_key;
        bool can_sign;
        bool can_view_inputs;
        bool can_view_outputs;
        bool can_view_balance;
    };

    struct ShamirShard {
        uint8_t x;
        std::array<uint8_t, 32> y;
    };

    struct ZKProof {
        std::array<uint8_t, 32> proof_hash;
        std::array<uint8_t, 32> commitment;
        uint64_t timestamp;
        bool valid;
    };

    explicit ZKKeyMatrix() = default;

    // Derive all 7 key tiers from master seed
    std::array<KeyTier, 7> derive_all_keys(const std::array<uint8_t, 256>& master_seed);

    // Generate Shamir secret sharing shards (2-of-3)
    std::array<ShamirShard, SHAMIR_SHARDS> generate_shamir_shards(
        const std::array<uint8_t, 32>& secret, uint8_t threshold);

    // Recover secret from threshold shards
    std::array<uint8_t, 32> recover_shamir_secret(
        const std::vector<ShamirShard>& shards);

    // Generate Proof-of-Life (TLMK)
    ZKProof generate_proof_of_life(const std::array<uint8_t, 32>& tlmk);

    // Verify Proof-of-Life
    bool verify_proof_of_life(const ZKProof& proof);

    // Audit view: FVK (all), IVK (inputs only), OVK (outputs only)
    struct AuditResult {
        bool can_view_inputs;
        bool can_view_outputs;
        bool can_view_balance;
        std::array<uint8_t, 32> audit_commitment;
        std::vector<std::string> visible_transactions;
    };
    AuditResult audit_view(const std::array<uint8_t, 32>& viewing_key, bool is_fvk, bool is_ivk, bool is_ovk);

private:
    // Helper: polynomial evaluation at point x over GF(2^256)
    std::array<uint8_t, 32> poly_eval(const std::vector<std::array<uint8_t, 32>>& coeffs, uint8_t x);
    // Helper: Lagrange interpolation
    std::array<uint8_t, 32> lagrange_interpolate(const std::vector<ShamirShard>& shards);
};

} // namespace vx::crypto

// ════════════════════════════════════════════════════════════════════════════
// Stealth Ring Envelopes 1-of-16
// ════════════════════════════════════════════════════════════════════════════

namespace vx::crypto {

inline constexpr size_t STEALTH_RING_SIZE = 16;  // 1 real + 15 decoys
inline constexpr size_t STEALTH_ADDR_BYTES = 42; // "NFA_ST_" + 35 one-time bytes

/// SK -> FVK -> IVK -> OVK hierarchy. The IVK is derived exclusively through
/// even-iteration (2n) sponge projections of the FVK, so holding it proves
/// incoming-visibility without ever revealing Z0 or the spending key SK.
struct StealthKeyHierarchy {
    std::array<uint8_t, 32> sk{};   // spending key (never leaves the wallet)
    std::array<uint8_t, 32> fvk{};  // full viewing key
    std::array<uint8_t, 32> ivk{};  // incoming viewing key (can_spend: false)
    std::array<uint8_t, 32> ovk{};  // outgoing viewing key
};

/// One-time stealth ring envelope: a 42-byte NFA_ST_ destination address, the
/// double-spend-proof key image and the 16-member anonymity ring.
struct StealthEnvelope {
    std::array<uint8_t, STEALTH_ADDR_BYTES> stealth_addr{};
    std::array<uint8_t, 32> key_image{};
    std::vector<std::array<uint8_t, STEALTH_ADDR_BYTES>> ring_members; // exactly 16
    uint32_t real_index = 0;                    // decoys hide the real receiver
    std::array<uint8_t, 32> ephemeral_pub{};    // one-time ephemeral key EK
    // 12-byte public scan tag bound to (recipient IVK projection, one-time
    // address). The recipient's published identifier IS their IVK — the IVK
    // proves incoming visibility with can_spend: false by construction.
    std::array<uint8_t, 12> scan_tag{};
};

/// Derive the full key hierarchy from a 32-byte master seed.
StealthKeyHierarchy derive_stealth_hierarchy(const std::array<uint8_t, 32>& master_seed);

/// Build a 1-of-16 stealth envelope: one-time NFA_ST_ address for the real
/// receiver plus 15 phantom decoys drawn from the ledger.
/// recipient_ivk: the recipient's published incoming viewing key (32 bytes) —
/// the sender binds the envelope to this public value.
StealthEnvelope create_stealth_envelope(
    const std::array<uint8_t, 32>& sender_seed,
    const std::array<uint8_t, 32>& recipient_ivk,
    const std::vector<std::array<uint8_t, STEALTH_ADDR_BYTES>>& ledger_decoys);

/// Write the envelope into a 112-byte transaction: receiver[42] becomes the
/// one-time NFA_ST_ address, the 12-byte scan tag lands in cocoon_proof.
void stamp_stealth_envelope(const StealthEnvelope& env, blockchain::Transaction& tx);

/// 12-byte scan tag bound to (ivk_pub, one-time address) — public data only.
std::array<uint8_t, 12> stealth_scan_tag(const std::array<uint8_t, 32>& ivk,
                                         const std::array<uint8_t, 42>& stealth_addr);

/// Ultra-fast IVK scan over a block worth of transactions: recomputes the
/// public IVK projection (even iterations 2n, Z0/SK never revealed) and flags
/// every transaction whose one-time address + tag matches this viewer.
/// Foreign IVKs observe only random one-time strings.
std::vector<size_t> scan_transactions_with_ivk(
    const std::array<uint8_t, 32>& ivk,
    std::span<const blockchain::Transaction> txs);

} // namespace vx::crypto