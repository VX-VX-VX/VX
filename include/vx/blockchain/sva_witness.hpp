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
// the registry is owner-gated by construction, and the ledger
// re-derives everything from the stored entry at apply time (the registry
// is a transport cache, never a trusted oracle).
//
// Keying: entries are keyed by (digest, sender). A witness's index is
// bound to its leaf (the path derives the root only for that index), so
// for a given digest + sender exactly one (preimage, path, index) triple
// verifies — that sender's. Several senders may hold a witness for one
// digest; the ledger's apply-time lookup selects by the claimed sender.
// A hostile first-arriver with its own vault therefore cannot lock the
// digest slot against the owner (zeroday hunt 2026-11-21, CWE-345).
//
// Flood limits (zeroday hunt 2026-11-21, CWE-400): a sender is capped
// (kSvaMaxWitnessesPerSender = the vault leaf count: one witness per leaf
// is the natural maximum, so a legitimate owner is never capped) so one
// peer cannot fill the map cheaply, and when
// the global cap is reached the OLDEST entry is evicted to admit a fresh
// verify-passing witness — the registry never permanently blocks honest
// witnesses. The wallet re-registers an evicted witness (durability is an
// optimization, never a consensus guarantee).
// ─────────────────────────────────────────────────────────────────────────────

#include "vx/blockchain/block.hpp"
#include "vx/blockchain/sva_vault.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <deque>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

namespace vx::blockchain::sva {

/// One stored spend witness: the Merkle root it derives, plus the full
/// material the ledger re-verifies at apply time. root is DERIVED at
/// registration (sva_root_of) — never taken from the wire. sender is the
/// claimed vault address the entry was registered under (the apply-time
/// lookup key: digest + sender).
struct SvaWitnessEntry {
    SvaAddress root{};
    SvaPreimage preimage{};
    SvaMerklePath path{};
    uint32_t spend_index = 0;
    std::array<uint8_t, 42> sender{};
};

/// Wire payload layout for the SVA_WITNESS VX60 message (0x14):
///   digest(32) | sender_nfa(42) | preimage(1024) | path(8 x 32) | index(u32 LE)
inline constexpr size_t kSvaWitnessWireSize =
    32 + 42 + kSvaPreimageSize + kSvaMerkleLevels * 32 + 4;

inline constexpr size_t kSvaMaxWitnessEntries = 16384; // ~22 MB worst case
// Flood limits (zeroday hunt 2026-11-21, CWE-400): one sender cannot fill
// the map, and one digest slot cannot be packed beyond this many
// (different-sender) witnesses.
inline constexpr size_t kSvaMaxWitnessesPerDigest = 8;
// A vault has exactly kSvaMaxSpends = 256 leaves, so 256 pending witnesses
// per sender is the natural ceiling — a legitimate owner (which may exhaust
// the whole vault) can never be capped, while a flood from one vault is
// bounded to 256 entries and filling the global cap needs 64 distinct
// vaults. The global cap + oldest-first eviction below is the liveness
// guarantee; this cap only raises the flood cost.
inline constexpr size_t kSvaMaxWitnessesPerSender = 256;

// FNV-1a over a byte array; parameterized so both the 32-byte digest key
// and the 42-byte sender key can use it.
template <size_t Sz> struct SvaByteHash {
    size_t operator()(const std::array<uint8_t, Sz> &a) const noexcept {
        uint64_t h = 1469598103934665603ull;
        for (uint8_t b : a) {
            h ^= b;
            h *= 1099511628211ull;
        }
        return static_cast<size_t>(h);
    }
};

struct SvaDigestHash : SvaByteHash<32> {};
using SvaSenderHash = SvaByteHash<42>;

class SvaWitnessRegistry {
public:
    static SvaWitnessRegistry &instance() noexcept {
        static SvaWitnessRegistry reg;
        return reg;
    }

    // Wire/store registration: verify-before-store, then store the entry
    // under (digest, sender). Returns false when the witness does not
    // derive the claimed vault encoding (garbage never reaches memory or
    // the durable sidecar), or when a cap refuses it.
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
        SvaWitnessEntry e;
        e.root = root;
        e.preimage = preimage;
        e.path = path;
        e.spend_index = spend_index;
        std::memcpy(e.sender.data(), sender_nfa, 42);
        bool fresh = false;
        if (!insert_locked(digest, e, &fresh))
            return false;
        if (fresh)
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
        for (const SvaWitnessEntry &e : it->second) {
            Address chk{};
            derive_sva_address(e.root.data(), chk.data());
            if (std::memcmp(chk.data(), sender_nfa, 42) != 0)
                continue;
            out = e;
            return true;
        }
        return false;
    }

    size_t size() const {
        std::lock_guard<std::mutex> lock(mutex_);
        return entries_;
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
    // digest -> the witnesses registered for it, keyed by sender (at most
    // kSvaMaxWitnessesPerDigest, each deriving its own vault encoding).
    std::unordered_map<std::array<uint8_t, 32>, std::vector<SvaWitnessEntry>, SvaDigestHash>
        by_digest_;
    std::unordered_map<std::array<uint8_t, 42>, uint32_t, SvaSenderHash> per_sender_;
    // Insertion order for oldest-first eviction at the global cap.
    std::deque<std::pair<std::array<uint8_t, 32>, std::array<uint8_t, 42>>> fifo_;
    size_t entries_ = 0;
    int durable_fd_ = -1;
    std::string durable_path_;
    // The logical end of the durable log (the last good record boundary).
    // Appends go here via pwrite; anything the OS appended past this point
    // (a crash-torn tail) is truncated away — the heal the header
    // documents (zeroday hunt 2026-11-21, CWE-367).
    off_t durable_end_ = 0;

    // Shared by registration and the sidecar replay (both hold the mutex):
    // identical-content dedup, same-sender conflict refusal, per-sender
    // and per-digest caps, and oldest-first eviction at the global cap.
    // Returns false on conflict or cap refusal; *fresh (when given) is set
    // to false for a dedup hit (the durable log must not re-append it).
    bool insert_locked(const std::array<uint8_t, 32> &digest, const SvaWitnessEntry &e,
                       bool *fresh = nullptr);

    // Record layout: magic(8) | digest(32) | sender(42) | entry(32+1024+256+4)
    static constexpr size_t kDurableRecSize =
        8 + 32 + 42 + (32 + kSvaPreimageSize + kSvaMerkleLevels * 32 + 4);
    bool append_durable_locked(const std::array<uint8_t, 32> &digest, const uint8_t sender_nfa[42],
                               const SvaWitnessEntry &e);
};

} // namespace vx::blockchain::sva
