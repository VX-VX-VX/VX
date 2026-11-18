#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// SVA-8192 «Sovereign Vault» — the cold-custody address class
// (owner-directed 18.11; 0.2.x, first address class with its own wire
// semantics — the foundation for the C1-C5 contract treasury/escrow).
//
// The address carries NO spendable private key in the ledger. It is a
// SPONGE COMMITMENT to a Merkle root over 256 one-time leaves, each leaf
// committing an 8192-bit (1024-byte) preimage:
//
//     leaf_i   := VortexSponge256("VX_SVA_LEAF_V1" ‖ preimage_i ‖ i)
//     address  := VortexSponge256("VX_SVA_V1"     ‖ Merkle_root(leaves))
//
// Spending leaf i REVEALS its 1024-byte preimage on-chain; the ledger
// recomputes the leaf, walks the 8-node Merkle path to the root, and
// binds the spend to the vault's spend counter (leaf i is spendable ONLY
// as spend #i — a revealed preimage can never be reused, and leaves out
// of counter order are refused). After 256 spends the vault is a
// TOMBSTONE: closing spend #255 leaves an address that can never move
// value again.
//
// The 8192-bit width is the "paranoid tier" margin: a revealed 1024-byte
// preimage gives a quantum adversary one burned leaf per spend, with 255
// fresh commitments still standing. Prior art: Solana's Winternitz Vault
// (one-shot), Qvault (SLH-DSA approvals) — SVA is the Merkle-counter
// generalization on the tree's own sponge.
//
// PURE layer: commitment / derivation / verification only. Ledger wiring
// (balance gates, the 1000 VX minimum, burn-fee registration) is the
// 0.2.x integration commit. NO-STUB: everything here is complete.
// ─────────────────────────────────────────────────────────────────────────────

#pragma once

#include "vx/blockchain/crypto_sponge.hpp"

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>

namespace vx::blockchain::sva {

inline constexpr size_t kSvaLeaves = 256;          // one-time leaves
inline constexpr size_t kSvaPreimageSize = 1024;   // 8192 bits per leaf
inline constexpr size_t kSvaMerkleLevels = 8;      // 256 = 2^8
inline constexpr uint64_t kSvaMaxSpends = 256;     // after: tombstone
inline constexpr uint64_t kSvaMinBalanceVx = 1000; // ledger gate (0.2.x wire)

using SvaPreimage = std::array<uint8_t, kSvaPreimageSize>;
using SvaAddress = std::array<uint8_t, 32>;
using SvaMerklePath = std::array<std::array<uint8_t, 32>, kSvaMerkleLevels>;

namespace detail {

inline void sva_hash(const char *tag, size_t tag_len, const uint8_t *a, size_t a_len,
                     const uint8_t *b, size_t b_len, std::array<uint8_t, 32> &out) noexcept {
    VortexSponge256 s;
    s.absorb(reinterpret_cast<const uint8_t *>(tag), tag_len);
    if (a)
        s.absorb(a, a_len);
    if (b)
        s.absorb(b, b_len);
    s.finalize(out.data());
}

// One Merkle node: Sponge(tag ‖ left ‖ right) — order-sensitive, no
// ambiguous sibling sorting (the tree shape is fixed by the leaf count).
inline std::array<uint8_t, 32> merkle_pair(const std::array<uint8_t, 32> &left,
                                           const std::array<uint8_t, 32> &right) noexcept {
    std::array<uint8_t, 32> out{};
    VortexSponge256 s;
    s.absorb(reinterpret_cast<const uint8_t *>("VX_SVA_NODE_V1"), 15);
    s.absorb(left.data(), 32);
    s.absorb(right.data(), 32);
    s.finalize(out.data());
    return out;
}

} // namespace detail

/// Leaf commitment: Sponge("VX_SVA_LEAF_V1" ‖ preimage(1024) ‖ index).
/// The index binds the leaf to its position — preimages cannot be shuffled
/// between leaves.
inline std::array<uint8_t, 32> sva_leaf_commit(const SvaPreimage &preimage, uint8_t leaf_index) {
    std::array<uint8_t, 32> out{};
    VortexSponge256 s;
    s.absorb(reinterpret_cast<const uint8_t *>("VX_SVA_LEAF_V1"), 15);
    s.absorb(preimage.data(), preimage.size());
    s.absorb(&leaf_index, 1);
    s.finalize(out.data());
    return out;
}

/// Derives the vault address from the full preimage set (the OWNER's
/// offline operation — the 256 KiB set never touches the network).
inline SvaAddress sva_address_of(const std::array<SvaPreimage, kSvaLeaves> &preimages) {
    std::array<std::array<uint8_t, 32>, kSvaLeaves> leaves{};
    for (size_t i = 0; i < kSvaLeaves; ++i)
        leaves[i] = sva_leaf_commit(preimages[i], static_cast<uint8_t>(i));
    // Merkle collapse: 256 → 1.
    std::array<std::array<uint8_t, 32>, kSvaLeaves> level = leaves;
    size_t width = kSvaLeaves;
    while (width > 1) {
        for (size_t i = 0; i < width / 2; ++i)
            level[i] = detail::merkle_pair(level[2 * i], level[2 * i + 1]);
        width /= 2;
    }
    SvaAddress addr{};
    detail::sva_hash("VX_SVA_V1", 10, level[0].data(), 32, nullptr, 0, addr);
    return addr;
}

/// The Merkle path for leaf i (the OWNER precomputes this offline per
/// planned spend — 256 bytes).
inline SvaMerklePath sva_path_of(const std::array<SvaPreimage, kSvaLeaves> &preimages,
                                 uint8_t leaf_index) {
    std::array<std::array<uint8_t, 32>, kSvaLeaves> level{};
    for (size_t i = 0; i < kSvaLeaves; ++i)
        level[i] = sva_leaf_commit(preimages[i], static_cast<uint8_t>(i));
    SvaMerklePath path{};
    size_t width = kSvaLeaves;
    size_t pos = leaf_index;
    for (size_t lvl = 0; lvl < kSvaMerkleLevels; ++lvl) {
        const size_t sibling = (pos % 2 == 0) ? pos + 1 : pos - 1;
        path[lvl] = level[sibling];
        for (size_t i = 0; i < width / 2; ++i)
            level[i] = detail::merkle_pair(level[2 * i], level[2 * i + 1]);
        width /= 2;
        pos /= 2;
    }
    return path;
}

/// SPEND VERIFICATION (the ledger calls this at apply time): the revealed
/// preimage must (a) commit to the leaf at position spend_counter, (b) walk
/// the Merkle path to the vault address root. The counter binds the leaf
/// order — a revealed preimage is dead after its one spend, and an
/// out-of-order leaf is refused even with a valid path.
inline bool sva_verify_spend(const SvaAddress &vault, uint64_t spend_counter,
                             const SvaPreimage &preimage, const SvaMerklePath &path) noexcept {
    if (spend_counter >= kSvaMaxSpends)
        return false; // tombstone: the vault closed
    const uint8_t idx = static_cast<uint8_t>(spend_counter);
    std::array<uint8_t, 32> level_node = sva_leaf_commit(preimage, idx);
    // Re-derive the root: walk the sibling path up (the leaf binds to its
    // position; the path was built for this index — a path from another
    // leaf fails the root comparison).
    size_t pos = idx;
    for (size_t lvl = 0; lvl < kSvaMerkleLevels; ++lvl) {
        const std::array<uint8_t, 32> &sib = path[lvl];
        std::array<uint8_t, 32> next{};
        if (pos % 2 == 0)
            next = detail::merkle_pair(level_node, sib);
        else
            next = detail::merkle_pair(sib, level_node);
        level_node = next;
        pos /= 2;
    }
    SvaAddress derived{};
    detail::sva_hash("VX_SVA_V1", 10, level_node.data(), 32, nullptr, 0, derived);
    return derived == vault;
}

} // namespace vx::blockchain::sva
