#pragma once
// ─────────────────────────────────────────────────────────────────────────────
// SVA-8192 spend-witness registry (0.2.x phase A wiring).
//
// The spend witness travels OUT OF BAND, digest-keyed like the PQ witness
// (BACKLOG 2.11) and the SGMT sidecar: the 1358-byte witness (preimage
// 1024 + path 256 + index 4 + the 32-byte tx digest it is bound to) can
// never fit the 112-byte transaction frame, and it must be present on
// every node BEFORE the dependent block applies (backfill-before-apply —
// a node without the witness refuses the spend, never guesses).
//
// Verify-before-store: nothing enters the registry (or the durable
// sidecar) unless the witness derives the claimed vault encoding —
// sva_root_of(index, preimage, path) must re-derive the vault root and
// derive_sva_address(root) must equal the claimed sender. Only the vault
// owner can produce a passing witness (the preimages are the secret), so
// the registry is owner-gated by construction: a hostile first-arriver
// cannot poison a digest, and the ledger re-derives everything from the
// stored entry at apply time (the registry is a transport cache, never a
// trusted oracle).
//
// Determinism: one canonical entry per digest. A witness's index is bound
// to its leaf (the path derives the root only for that index), so for a
// given digest + vault exactly one (preimage, path, index) triple verifies
// — the owner's. First-come-wins with identical-content dedup keeps every
// node's entry byte-identical regardless of arrival order.
// ─────────────────────────────────────────────────────────────────────────────

#include "vx/blockchain/block.hpp"
#include "vx/blockchain/sva_vault.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <mutex>
#include <string>
#include <unordered_map>

namespace vx::blockchain::sva {

/// One stored spend witness: the Merkle root it derives, plus the full
/// material the ledger re-verifies at apply time. root is DERIVED at
/// registration (sva_root_of) — never taken from the wire.
struct SvaWitnessEntry {
    SvaAddress root{};
    SvaPreimage preimage{};
    SvaMerklePath path{};
    uint32_t spend_index = 0;
};

/// Wire payload layout for the SVA_WITNESS VX60 message (0x14):
///   digest(32) | sender_nfa(42) | preimage(1024) | path(8 x 32) | index(u32 LE)
inline constexpr size_t kSvaWitnessWireSize =
    32 + 42 + kSvaPreimageSize + kSvaMerkleLevels * 32 + 4;

inline constexpr size_t kSvaMaxWitnessEntries = 16384; // ~22 MB worst case

struct SvaDigestHash {
    size_t operator()(const std::array<uint8_t, 32> &a) const noexcept {
        uint64_t h = 1469598103934665603ull;
        for (uint8_t b : a) {
            h ^= b;
            h *= 1099511628211ull;
        }
        return static_cast<size_t>(h);
    }
};

class SvaWitnessRegistry {
public:
    static SvaWitnessRegistry &instance() noexcept {
        static SvaWitnessRegistry reg;
        return reg;
    }

    // Wire/store registration: verify-before-store, then store the
    // canonical entry for the digest. Returns false when the witness does
    // not derive the claimed vault encoding (garbage never reaches memory
    // or the durable sidecar), or when the registry is full.
    bool register_witness_bytes(const std::array<uint8_t, 32> &digest, const uint8_t sender_nfa[42],
                                const SvaPreimage &preimage, const SvaMerklePath &path,
                                uint32_t spend_index) {
        // Verify-before-store: the root is derived from the witness alone.
        const SvaAddress root = sva_root_of(spend_index, preimage, path);
        // The all-zero root is the tombstone sentinel — it cannot equal a
        // real vault encoding (the "SVA" prefix makes the encoding
        // non-zero by construction).
        Address chk{};
        derive_sva_address(root.data(), chk.data());
        if (std::memcmp(chk.data(), sender_nfa, 42) != 0)
            return false;

        std::lock_guard<std::mutex> lock(mutex_);
        auto it = by_digest_.find(digest);
        if (it != by_digest_.end()) {
            // Dedup identical content; a conflicting witness for the same
            // digest is refused (first-come-wins: the canonical entry is
            // the owner's — see the file header).
            const SvaWitnessEntry &e = it->second;
            if (e.root == root && e.spend_index == spend_index && e.preimage == preimage &&
                e.path == path)
                return true;
            return false;
        }
        if (by_digest_.size() >= kSvaMaxWitnessEntries)
            return false;
        SvaWitnessEntry e;
        e.root = root;
        e.preimage = preimage;
        e.path = path;
        e.spend_index = spend_index;
        by_digest_.emplace(digest, e);
        append_durable_locked(digest, sender_nfa, e);
        return true;
    }

    // The ledger's apply-time lookup: the entry must exist for the digest
    // (backfill-before-apply) and derive the claimed sender encoding.
    bool lookup(const std::array<uint8_t, 32> &digest, const uint8_t sender_nfa[42],
                SvaWitnessEntry &out) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = by_digest_.find(digest);
        if (it == by_digest_.end())
            return false;
        Address chk{};
        derive_sva_address(it->second.root.data(), chk.data());
        if (std::memcmp(chk.data(), sender_nfa, 42) != 0)
            return false;
        out = it->second;
        return true;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return by_digest_.size();
    }

    // Durable sidecar (mirror of the PQ witness log): every registration
    // is fsync'd so a node restart can replay the witnesses its applied
    // blocks depended on. A busy log falls back to memory-only mode —
    // durability is an optimization here (reorg replay / restart replay
    // re-request the witness from the network), never a consensus
    // invariant.
    void attach_durable_log(const std::string &path);

private:
    mutable std::mutex mutex_;
    std::unordered_map<std::array<uint8_t, 32>, SvaWitnessEntry, SvaDigestHash> by_digest_;
    int durable_fd_ = -1;
    std::string durable_path_;

    // Record layout: magic(8) | digest(32) | sender(42) | entry(32+1024+256+4)
    static constexpr size_t kDurableRecSize =
        8 + 32 + 42 + (32 + kSvaPreimageSize + kSvaMerkleLevels * 32 + 4);
    bool append_durable_locked(const std::array<uint8_t, 32> &digest, const uint8_t sender_nfa[42],
                               const SvaWitnessEntry &e);
};

} // namespace vx::blockchain::sva
