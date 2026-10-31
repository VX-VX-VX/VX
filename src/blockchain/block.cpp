#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/crypto/pq_signature.hpp"
#include <cstring>
#include <iostream>

namespace vx::blockchain {

void hash_header(const BlockHeader& header, uint8_t out[32]) noexcept {
    VortexSponge256::compute(reinterpret_cast<const uint8_t*>(&header), HEADER_SIZE_BYTES, out);
}

// ── Merkle root logic using Sponge ──────────────────────────────────────────

void hash_tx(const Transaction& tx, uint8_t out[32]) noexcept {
    VortexSponge256::compute(reinterpret_cast<const uint8_t*>(&tx), TX_SIZE_BYTES, out);
}

static void hash_pair(const uint8_t left[32], const uint8_t right[32], uint8_t out[32]) noexcept {
    uint8_t buffer[64];
    std::memcpy(buffer, left, 32);
    std::memcpy(buffer + 32, right, 32);
    VortexSponge256::compute(buffer, 64, out);
}

void BlockBuilder::compute_merkle_root() noexcept {
    uint32_t count = block_.header.tx_count;
    if (count == 0) {
        std::memset(block_.header.merkle_root, 0, 32);
        return;
    }

    uint8_t hashes[MAX_TX_PER_BLOCK][32];
    for (uint32_t i = 0; i < count; ++i) {
        hash_tx(block_.transactions[i], hashes[i]);
    }

    uint32_t level_size = count;
    while (level_size > 1) {
        uint32_t next_size = (level_size + 1) / 2;
        for (uint32_t i = 0; i < next_size; ++i) {
            uint32_t left = i * 2;
            uint32_t right = (left + 1 < level_size) ? left + 1 : left;
            hash_pair(hashes[left], hashes[right], hashes[i]);
        }
        level_size = next_size;
    }
    std::memcpy(block_.header.merkle_root, hashes[0], 32);
}

// Chain ID for replay protection across networks
inline constexpr uint64_t CHAIN_ID = 0x58564336; // "VXC6"

// ── Transaction Proof System V2 ──────────────────────────────────────────────
// Preimage: sender(42) || receiver(42) || amount(8) || fee(4) || nonce(4) || chain_id(8) = 108 bytes

static void build_tx_preimage(const Transaction& tx, uint8_t out[108]) noexcept {
    std::memcpy(out, tx.sender_nfa, 42);
    std::memcpy(out + 42, tx.receiver_nfa, 42);
    std::memcpy(out + 84, tx.amount, 8);
    std::memcpy(out + 92, tx.fee, 4);
    std::memcpy(out + 96, tx.nonce, 4);
    // Chain ID as 8 bytes LE
    for (int i = 0; i < 8; ++i) {
        out[100 + i] = static_cast<uint8_t>((CHAIN_ID >> (i * 8)) & 0xFF);
    }
}

void sign_transaction(Transaction& tx) noexcept {
    uint8_t preimage[108];
    build_tx_preimage(tx, preimage);

    uint8_t digest[32];
    VortexSponge256::compute(preimage, 108, digest);

    // Cocoon proof is the first 12 bytes of the digest.
    std::memcpy(tx.cocoon_proof, digest, 12);
}

bool verify_transaction_proof(const Transaction& tx) noexcept {
    // ── Tier 1: SegPQ — the sender is backed by a WOTS+/XMSS post-quantum key.
    // A registered sender MUST carry a valid PqSignatureWitness: a MITM that
    // mutates amount/receiver and re-runs the keyless sign_transaction() only
    // recomputes the checksum — it cannot produce the WOTS+ chains (Winternitz
    // checksum barrier) nor match the registered XMSS root.
    if (vx::crypto::pq::PqWitnessRegistry::instance().is_pq_sender(tx.sender_nfa)) {
        const auto msg = vx::crypto::pq::tx_msg_digest(tx);
        vx::crypto::pq::PqSignatureWitness w;
        if (!vx::crypto::pq::PqWitnessRegistry::instance().lookup(msg, w)) return false;
        return vx::crypto::pq::pq_verify_transaction(tx, w);
    }

    // ── Tier 2: legacy keyless integrity check (unregistered test senders).
    uint8_t preimage[108];
    build_tx_preimage(tx, preimage);

    uint8_t digest[32];
    VortexSponge256::compute(preimage, 108, digest);

    return std::memcmp(tx.cocoon_proof, digest, 12) == 0;
}

} // namespace vx::blockchain
