#pragma once

// Sparse Galois Merkle Trie (SGMT).
//
// A 256-ary sparse state tree over GF(2^8) (irreducible polynomial 0x11B).
// Keys are 32 bytes = 32 levels of 1 byte each. Internal node hashing uses the
// AVX2-capable VortexSponge256 plus GF(2^8) polynomial mixing — with no
// hardware division anywhere (directive invariant #3).
//
// Empty subtrees collapse into precomputed constant zero-hashes of depth d
// (DEFAULT_EMPTY_HASH[33]), giving O(log256 N) updates: at most 32 node
// touches per put/get, each holding a child_bitmap[4] of active branches.
//
// Merkle-Galois Witness proofs (GaloisTrieProof) carry per-level sibling
// hashes and bitmasks, strictly < 2048 bytes, and verify against the root
// without any access to the tree itself.

#include <array>
#include <cstdint>
#include <cstring>
#include <memory>
#include <string>
#include <vector>

namespace vx::state {

inline constexpr size_t SGMT_KEY_BYTES = 32;   // 256-bit key = 32 levels
inline constexpr size_t SGMT_VAL_BYTES = 32;
inline constexpr size_t SGMT_DEPTH = 32;       // 1 byte per level
inline constexpr size_t SGMT_BRANCHES = 256;   // 256-ary

/// Galois field GF(2^8) with irreducible polynomial 0x11B — multiply (no /).
uint8_t gf256_mul(uint8_t a, uint8_t b) noexcept;

/// Galois field GF(2^8) inverse via Fermat (a^254), only squarings/multiplies.
uint8_t gf256_inv(uint8_t a) noexcept;

/// Merkle-Galois witness: compressed per-level branch records.
///
/// Proof compression (keeps every witness strictly < 2048 bytes):
///   - PASS level: the node has exactly one child and it is the path branch
///     -> its hash equals the child's hash, so the level carries no hash data.
///   - BRANCH level: children are hashed in chunks of 8 consecutive indices;
///     the chunk containing the path branch is expanded (sibling hashes),
///     other chunks ride along as pre-hashed (first_idx, chunk_hash) pairs.
///     A node with 256 children therefore costs at most ~32 chunk hashes,
///     never 256 sibling hashes.
struct GaloisTrieProof {
    struct Level {
        uint8_t kind = 0;        // 0 = PASS, 1 = BRANCH
        uint8_t depth = 0;
        uint8_t nibble = 0;      // path branch index at this depth
        bool path_present = false;       // BRANCH: path child exists here
        bool path_chunk_present = false; // BRANCH: children exist in the nibble's 8-wide group
        // Path chunk entries (idx, hash) except the path child itself.
        std::vector<std::pair<uint8_t, std::array<uint8_t, 32>>> siblings;
        // Other chunks as (first_idx, chunk_hash) pairs.
        std::vector<std::pair<uint8_t, std::array<uint8_t, 32>>> other_chunks;
    };
    std::vector<Level> levels;   // root -> deepest, depth == index
    std::array<uint8_t, 32> leaf_value{}; // value if present, zeros if absent
    bool present = false;

    size_t size_bytes() const noexcept {
        size_t s = 1 + sizeof(leaf_value); // present flag + value
        for (const auto& lv : levels) {
            s += 6; // kind, depth, nibble, flags, two counts
            if (lv.kind == 1) {
                s += lv.siblings.size() * 33;
                s += lv.other_chunks.size() * 33;
            }
        }
        return s;
    }
};

/**
 * @brief Sparse Galois Merkle Trie over GF(2^8).
 *
 * put(key32, val32) updates a leaf and recomputes the root in O(log256 N).
 * generate_proof(key32) produces a Merkle-Galois witness < 2048 bytes.
 * verify_proof(root32, key32, val32, proof) statically re-derives the root.
 */
class GaloisTrie {
public:
    GaloisTrie();

    /// Insert/update a 32-byte value under a 32-byte key. Returns new root.
    std::array<uint8_t, 32> put(const uint8_t key[32], const uint8_t val[32]);

    /// Read a value. Returns false if the key is absent.
    bool get(const uint8_t key[32], uint8_t out_val[32]) const;

    /// Remove a key (leaf becomes empty; empty branches collapse upward).
    bool erase(const uint8_t key[32]);

    /// Current root hash (32 bytes).
    std::array<uint8_t, 32> root_hash() const noexcept { return root_; }

    /// Number of active leaves.
    uint64_t leaf_count() const noexcept { return leaf_count_; }

    /// Total number of allocated nodes (arena size).
    uint64_t node_count() const noexcept { return node_count_; }

    /// Generate a Merkle-Galois witness for a key (empty value if absent).
    GaloisTrieProof generate_proof(const uint8_t key[32]) const;

    /// Verify a witness against a root, key and claimed value. Static —
    /// no trie access needed. Any 1-bit change in val32 or proof -> false.
    static bool verify_proof(const uint8_t root[32], const uint8_t key[32],
                             const uint8_t val[32], const GaloisTrieProof& proof);

    /// Precomputed constant empty-hash chain: DEFAULT_EMPTY_HASH[d] = hash of
    /// a fully-empty subtree at depth d. [32] = leaf-domain tag.
    static const std::array<std::array<uint8_t, 32>, SGMT_DEPTH + 1>& empty_hashes() noexcept;

private:
    struct Node {
        uint64_t child_bitmap[4]{0, 0, 0, 0}; // 256 branches = 4 x 64-bit masks
        std::array<uint8_t, 32> self_hash{};  // sponge(bm || children hashes)
        // Child storage: sparse vector parallel to the bitmap
        std::vector<std::pair<uint8_t, std::unique_ptr<Node>>> children;
        // Leaf payload (only meaningful at depth 32)
        std::array<uint8_t, 32> value{};
        bool is_leaf = false;
        bool has_value = false;

        Node* find_child(uint8_t idx) noexcept {
            for (auto& [k, ptr] : children)
                if (k == idx) return ptr.get();
            return nullptr;
        }
        Node* make_child(uint8_t idx) {
            if (find_child(idx)) return find_child(idx);
            child_bitmap[idx >> 6] |= (1ULL << (idx & 63));
            // Insert keeping children sorted by idx (hash absorb order).
            auto it = children.begin();
            while (it != children.end() && it->first < idx) ++it;
            it = children.emplace(it, idx, std::make_unique<Node>());
            return it->second.get();
        }
        bool drop_child(uint8_t idx) {
            child_bitmap[idx >> 6] &= ~(1ULL << (idx & 63));
            for (auto it = children.begin(); it != children.end(); ++it)
                if (it->first == idx) { children.erase(it); return true; }
            return false;
        }
    };

    Node root_node_{};
    std::array<uint8_t, 32> root_{};
    uint64_t leaf_count_ = 0;
    uint64_t node_count_ = 1;

    // Recompute a node's hash from its bitmap + children (bottom-up).
    static void rehash(Node& n, uint8_t depth);
    // Hash a leaf domain record: 0x02 || key || value
    static std::array<uint8_t, 32> hash_leaf(const uint8_t key[32], const uint8_t val[32]);
};

} // namespace vx::state
