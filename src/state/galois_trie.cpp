#include "vx/state/galois_trie.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include <algorithm>

namespace vx::state {

// ── GF(2^8) arithmetic (irreducible polynomial 0x11B, no division) ──────────

uint8_t gf256_mul(uint8_t a, uint8_t b) noexcept {
    uint8_t p = 0;
    while (b) {
        if (b & 1) p ^= a;
        const bool hi = a & 0x80;
        a = static_cast<uint8_t>(a << 1);
        if (hi) a ^= 0x1B; // low byte of the 0x11B modulus
        b >>= 1;
    }
    return p;
}

uint8_t gf256_inv(uint8_t a) noexcept {
    if (a == 0) return 0;
    // Fermat: a^(2^8 - 2) = a^254 via square-and-multiply only.
    uint8_t r = 1;
    uint8_t base = a;
    uint16_t e = 254;
    while (e) {
        if (e & 1) r = gf256_mul(r, base);
        base = gf256_mul(base, base);
        e >>= 1;
    }
    return r;
}

// ════════════════════════════════════════════════════════════════════════════
// Canonical SGMT node hashing (single scheme for trie + proofs)
//
//   node_hash(depth) = Sponge( 0x01 || depth || kind ||
//                              [PASS] child_hash ||
//                              [BRANCH] chunk_hash per 8-wide child group, ascending )
//
//   kind = 0 (PASS): exactly one child, the node's hash IS that child's hash
//            (sponge still re-absorbs it for domain separation).
//   kind = 1 (BRANCH): two or more children; children are grouped into
//            8-wide index chunks [8k .. 8k+7]; each non-empty chunk is
//            sponge-hashed over its (idx || hash) members in ascending order.
//
// This keeps proofs compact: a BRANCH level needs only the chunk containing
// the path branch expanded — at most 7 sibling hashes — plus the other
// chunks as single 32-byte digests (<= 31 chunks + 7 siblings per level).
// ════════════════════════════════════════════════════════════════════════════

namespace {

constexpr uint8_t kNodeTag = 0x01;
constexpr uint8_t kLeafTag = 0x02;
constexpr size_t  kChunkWidth = 8; // children per hash chunk

std::array<std::array<uint8_t, 32>, SGMT_DEPTH + 1> build_empty_hashes() {
    std::array<std::array<uint8_t, 32>, SGMT_DEPTH + 1> h{};
    for (size_t d = 0; d <= SGMT_DEPTH; ++d) {
        blockchain::VortexSponge256 sponge;
        const uint8_t tag[3] = {kNodeTag, static_cast<uint8_t>(d), /*kind=*/0};
        sponge.absorb(tag, 3);
        const uint8_t zero_hash[32] = {0};
        sponge.absorb(zero_hash, 32); // PASS child = zero constant
        sponge.finalize(h[d].data());
    }
    return h;
}

const auto& empty_hash_table() {
    static const auto table = build_empty_hashes();
    return table;
}

// Sponge over one 8-wide chunk of children: (idx || hash) in ascending order.
std::array<uint8_t, 32> chunk_hash(const std::vector<std::pair<uint8_t, std::array<uint8_t, 32>>>& members) {
    blockchain::VortexSponge256 sponge;
    const uint8_t cnt = static_cast<uint8_t>(members.size());
    sponge.absorb(&cnt, 1);
    for (const auto& [idx, hash] : members) { // ascending idx order
        sponge.absorb(&idx, 1);
        sponge.absorb(hash.data(), 32);
    }
    std::array<uint8_t, 32> out{};
    sponge.finalize(out.data());
    return out;
}

} // namespace

const std::array<std::array<uint8_t, 32>, SGMT_DEPTH + 1>& GaloisTrie::empty_hashes() noexcept {
    return empty_hash_table();
}

// ── Hashing ─────────────────────────────────────────────────────────────────

std::array<uint8_t, 32> GaloisTrie::hash_leaf(const uint8_t key[32], const uint8_t val[32]) {
    std::array<uint8_t, 32> out{};
    blockchain::VortexSponge256 sponge;
    const uint8_t tag = kLeafTag;
    sponge.absorb(&tag, 1);
    sponge.absorb(key, 32);
    sponge.absorb(val, 32);
    sponge.finalize(out.data());
    return out;
}

void GaloisTrie::rehash(Node& n, uint8_t depth) {
    // Children are kept idx-sorted by make_child().
    if (n.children.empty()) {
        // Empty subtree: exactly the precomputed depth-tagged constant.
        n.self_hash = empty_hash_table()[depth];
        return;
    }
    if (n.children.size() == 1) {
        // PASS node: hash = domain-separated pass-through of the child hash.
        blockchain::VortexSponge256 sponge;
        const uint8_t tag[3] = {kNodeTag, depth, /*kind=*/0};
        sponge.absorb(tag, 3);
        sponge.absorb(n.children.front().second->self_hash.data(), 32);
        sponge.finalize(n.self_hash.data());
        return;
    }

    // BRANCH node: chunk the children into 8-wide index groups. Chunks are
    // addressed by their 8-aligned base index, both here and in proofs.
    blockchain::VortexSponge256 sponge;
    const uint8_t tag[3] = {kNodeTag, depth, /*kind=*/1};
    sponge.absorb(tag, 3);
    size_t i = 0;
    while (i < n.children.size()) {
        const size_t chunk_addr =
            (static_cast<size_t>(n.children[i].first) / kChunkWidth) * kChunkWidth;
        const size_t chunk_last = chunk_addr + kChunkWidth - 1;
        std::vector<std::pair<uint8_t, std::array<uint8_t, 32>>> members;
        while (i < n.children.size() &&
               static_cast<size_t>(n.children[i].first) <= chunk_last) {
            members.emplace_back(n.children[i].first, n.children[i].second->self_hash);
            ++i;
        }
        const auto ch = chunk_hash(members);
        const uint8_t addr_byte = static_cast<uint8_t>(chunk_addr);
        sponge.absorb(&addr_byte, 1);
        sponge.absorb(ch.data(), 32);
    }
    sponge.finalize(n.self_hash.data());
}

GaloisTrie::GaloisTrie() {
    root_ = empty_hash_table()[0];
}

// ── Core operations ─────────────────────────────────────────────────────────

std::array<uint8_t, 32> GaloisTrie::put(const uint8_t key[32], const uint8_t val[32]) {
    Node* path[SGMT_DEPTH + 1];
    Node* n = &root_node_;
    path[0] = n;
    for (uint8_t d = 0; d < SGMT_DEPTH; ++d) {
        Node* child = n->find_child(key[d]);
        if (!child) {
            child = n->make_child(key[d]);
            child->is_leaf = (d + 1 == SGMT_DEPTH);
            ++node_count_;
        }
        path[d + 1] = child;
        n = child;
    }

    if (!n->has_value) ++leaf_count_;
    n->has_value = true;
    std::memcpy(n->value.data(), val, 32);
    n->self_hash = hash_leaf(key, val);

    for (int d = SGMT_DEPTH - 1; d >= 0; --d) {
        rehash(*path[d], static_cast<uint8_t>(d));
    }
    root_ = root_node_.self_hash;
    return root_;
}

bool GaloisTrie::get(const uint8_t key[32], uint8_t out_val[32]) const {
    const Node* n = &root_node_;
    for (uint8_t d = 0; d < SGMT_DEPTH; ++d) {
        const Node* found = nullptr;
        for (const auto& [k, ptr] : n->children)
            if (k == key[d]) { found = ptr.get(); break; }
        if (!found) return false;
        n = found;
    }
    if (!n->has_value) return false;
    std::memcpy(out_val, n->value.data(), 32);
    return true;
}

bool GaloisTrie::erase(const uint8_t key[32]) {
    Node* path[SGMT_DEPTH + 1];
    Node* n = &root_node_;
    path[0] = n;
    for (uint8_t d = 0; d < SGMT_DEPTH; ++d) {
        Node* child = n->find_child(key[d]);
        if (!child) return false;
        path[d + 1] = child;
        n = child;
    }
    if (!path[SGMT_DEPTH]->has_value) return false;

    path[SGMT_DEPTH]->has_value = false;
    --leaf_count_;

    for (int d = SGMT_DEPTH; d >= 1; --d) {
        Node* parent = path[d - 1];
        const uint8_t idx = key[d - 1];
        Node* child = parent->find_child(idx);
        if (child && !child->has_value && child->children.empty()) {
            parent->drop_child(idx);
            if (node_count_ > 1) --node_count_;
        }
        rehash(*parent, static_cast<uint8_t>(d - 1));
    }
    root_ = root_node_.self_hash;
    return true;
}

// ── Merkle-Galois Witness ───────────────────────────────────────────────────

GaloisTrieProof GaloisTrie::generate_proof(const uint8_t key[32]) const {
    GaloisTrieProof proof;
    const Node* n = &root_node_;
    uint8_t break_depth = SGMT_DEPTH; // first level where the path breaks

    for (uint8_t d = 0; d < SGMT_DEPTH; ++d) {
        GaloisTrieProof::Level lvl;
        lvl.depth = d;
        lvl.nibble = key[d];

        const Node* path_child = nullptr;
        for (const auto& [idx, child] : n->children) {
            if (idx == key[d]) { path_child = child.get(); break; }
        }

        // Mirror rehash() node classification exactly.
        if (n->children.empty()) {
            lvl.kind = 2; // EMPTY node: precomputed depth constant
            lvl.path_present = false;
        } else if (n->children.size() == 1) {
            lvl.kind = 0; // PASS node: no chunk material
            lvl.path_present = (path_child != nullptr);
            if (!path_child) {
                // The only child is a sibling: hand its hash over so the
                // verifier can PASS-roll through this node.
                lvl.siblings.emplace_back(n->children.front().first,
                                          n->children.front().second->self_hash);
            }
        } else {
            // BRANCH node: expand only the path nibble's 8-wide chunk.
            lvl.kind = 1;
            lvl.path_present = (path_child != nullptr);
            const size_t chunk_first = (static_cast<size_t>(key[d]) / kChunkWidth) * kChunkWidth;
            size_t i = 0;
            while (i < n->children.size()) {
                const size_t chunk_addr =
                    (static_cast<size_t>(n->children[i].first) / kChunkWidth) * kChunkWidth;
                const size_t chunk_last = chunk_addr + kChunkWidth - 1;
                std::vector<std::pair<uint8_t, std::array<uint8_t, 32>>> members;
                while (i < n->children.size() &&
                       static_cast<size_t>(n->children[i].first) <= chunk_last) {
                    members.emplace_back(n->children[i].first, n->children[i].second->self_hash);
                    ++i;
                }
                if (chunk_addr == chunk_first) {
                    lvl.path_chunk_present = true;
                    for (const auto& [idx, hash] : members) {
                        if (idx != key[d]) lvl.siblings.emplace_back(idx, hash);
                    }
                } else {
                    lvl.other_chunks.emplace_back(static_cast<uint8_t>(chunk_addr),
                                                  chunk_hash(members));
                }
            }
        }

        proof.levels.push_back(std::move(lvl));

        if (!path_child) {
            break_depth = d;
            // Levels below the break are strict empty markers.
            for (uint8_t dd = static_cast<uint8_t>(d + 1); dd < SGMT_DEPTH; ++dd) {
                GaloisTrieProof::Level marker;
                marker.depth = dd;
                marker.nibble = key[dd];
                marker.kind = 2;
                marker.path_present = false;
                proof.levels.push_back(std::move(marker));
            }
            break;
        }
        n = path_child;
    }

    proof.present = (break_depth == SGMT_DEPTH) && n->has_value;
    if (proof.present) proof.leaf_value = n->value;
    else proof.leaf_value.fill(0);
    return proof;
}

bool GaloisTrie::verify_proof(const uint8_t root[32], const uint8_t key[32],
                              const uint8_t val[32], const GaloisTrieProof& proof) {
    if (proof.levels.size() != SGMT_DEPTH) return false;

    const auto& eh = empty_hash_table();

    // Locate the path break: first level where the path branch is absent.
    uint8_t break_depth = SGMT_DEPTH;
    for (uint8_t d = 0; d < SGMT_DEPTH; ++d) {
        const auto& lvl = proof.levels[d];
        if (lvl.depth != d || lvl.nibble != key[d]) return false;
        if (!lvl.path_present) { break_depth = d; break; }
    }
    // Levels below the break must be strict empty markers.
    for (uint8_t d = static_cast<uint8_t>(break_depth + 1); d < SGMT_DEPTH; ++d) {
        const auto& lvl = proof.levels[d];
        if (lvl.kind != 2 || lvl.path_present ||
            !lvl.siblings.empty() || !lvl.other_chunks.empty()) return false;
    }

    // Bottom-up roll-up.
    std::array<uint8_t, 32> acc{};
    if (break_depth == SGMT_DEPTH) {
        if (!proof.present) return false;
        // Present key: start from the keyed leaf hash.
        blockchain::VortexSponge256 sponge;
        const uint8_t tag = kLeafTag;
        sponge.absorb(&tag, 1);
        sponge.absorb(key, 32);
        sponge.absorb(val, 32);
        sponge.finalize(acc.data());
    } else if (proof.present) {
        return false; // claimed present but the path breaks
    } else {
        // Absent-key witness: the claimed value must be the canonical zero —
        // anything else would let a fake value "verify" against an empty path.
        static const std::array<uint8_t, 32> kZero{};
        if (std::memcmp(val, kZero.data(), 32) != 0) return false;
    }

    for (int d = SGMT_DEPTH - 1; d >= 0; --d) {
        const auto& lvl = proof.levels[static_cast<size_t>(d)];

        if (lvl.kind == 2) {
            // EMPTY node at this depth (also every marker below the break).
            acc = eh[d];
            continue;
        }

        if (lvl.kind == 0) {
            // PASS: node hash = sponge(tag, depth, child_hash).
            std::array<uint8_t, 32> child{};
            if (lvl.path_present) {
                child = acc; // single path child rolled from below
            } else {
                // Break level: the single child is the handed-over sibling.
                if (d != break_depth || lvl.siblings.size() != 1) return false;
                child = lvl.siblings[0].second;
            }
            blockchain::VortexSponge256 sponge;
            const uint8_t tag[3] = {kNodeTag, static_cast<uint8_t>(d), 0};
            sponge.absorb(tag, 3);
            sponge.absorb(child.data(), 32);
            sponge.finalize(acc.data());
            continue;
        }

        if (lvl.kind == 1) {
            const size_t chunk_first = (static_cast<size_t>(key[d]) / kChunkWidth) * kChunkWidth;

            // Rebuild the path chunk: expanded siblings (+ path child).
            std::array<uint8_t, 32> path_chunk{};
            bool path_chunk_used = false;
            {
                std::vector<std::pair<uint8_t, std::array<uint8_t, 32>>> members;
                for (const auto& sib : lvl.siblings) {
                    if ((static_cast<size_t>(sib.first) / kChunkWidth) * kChunkWidth != chunk_first)
                        return false; // siblings must sit in the path chunk
                    members.push_back(sib);
                }
                if (lvl.path_present) members.emplace_back(key[d], acc);
                std::sort(members.begin(), members.end(),
                          [](const auto& a, const auto& b) { return a.first < b.first; });
                if (!members.empty()) {
                    path_chunk = chunk_hash(members);
                    path_chunk_used = true;
                }
            }

            // Assemble the full chunk stream (other chunks must not collide
            // with the path chunk address and must be 8-aligned).
            std::vector<std::pair<uint8_t, std::array<uint8_t, 32>>> chunks;
            if (path_chunk_used) chunks.emplace_back(static_cast<uint8_t>(chunk_first), path_chunk);
            for (const auto& [addr, ch] : lvl.other_chunks) {
                const size_t cf = (static_cast<size_t>(addr) / kChunkWidth) * kChunkWidth;
                if (static_cast<size_t>(addr) != cf) return false;
                if (cf == chunk_first) return false;
                chunks.emplace_back(addr, ch);
            }
            std::sort(chunks.begin(), chunks.end(),
                      [](const auto& a, const auto& b) { return a.first < b.first; });

            blockchain::VortexSponge256 sponge;
            const uint8_t tag[3] = {kNodeTag, static_cast<uint8_t>(d), 1};
            sponge.absorb(tag, 3);
            for (const auto& [addr, ch] : chunks) {
                sponge.absorb(&addr, 1);
                sponge.absorb(ch.data(), 32);
            }
            sponge.finalize(acc.data());
            continue;
        }

        return false; // unknown kind
    }

    return std::memcmp(acc.data(), root, 32) == 0;
}

} // namespace vx::state
