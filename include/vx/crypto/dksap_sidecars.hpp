// DKSAP sidecar registry — out-of-band bulk payloads keyed by the
// transaction digest (tx_msg_digest).
//
// Two payload kinds (see the SGMT-tx wiring design note):
//   SGMT_REG  — nickname + PublicKeys record backing an on-chain
//     "SGMTLEAF" registration transaction. CONSENSUS-VISIBLE: apply_block
//     refuses the leaf unless sponge(record) matches the frame-committed
//     leaf, so the record must be durably replayed on restart (the same
//     shape as the PQ witness durable log) or a node could never re-apply
//     its own history.
//   STEALTH — the StealthTx envelope (blinded one-time key + KEM ct) for
//     an on-chain "STEALTH" transfer. Radar-only: consensus never needs
//     it, so it lives in a capped in-memory LRU and is not persisted.
//
// HEADER-ONLY by construction: the ledger's inline apply_block references
// the receiver helpers, the nickname validator and the registry lookup, so
// every target that links the ledger resolves them without an extra lib.
#pragma once

#include "vx/crypto/dksap.hpp"
#include "vx/crypto/dksap_sgmt.hpp"
#include "vx/crypto/ml_kem.hpp"
#include "vx/core/ct_equal.hpp"

#include <array>
#include <cstdint>
#include <cstring>
#include <iostream>
#include <mutex>
#include <string>
#include <unordered_map>
#include <vector>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

namespace vx::crypto::dksap {

// ── Receiver-prefix tx classes (consensus receiver payloads) ────────────────
// Same discipline as the NFA_V6_ prefix: tag copied whole, tail zero-
// padded, extraction asserts the padding is zero.

inline constexpr size_t STEALTH_PREFIX_LEN = 7;  // "STEALTH"
inline constexpr size_t SGMTLEAF_PREFIX_LEN = 8; // "SGMTLEAF"
inline constexpr size_t STEALTH_PSTEALTH_LEN = 32;
inline constexpr size_t SGMT_LEAF_LEN = 32;

inline constexpr uint8_t kStealthTag[STEALTH_PREFIX_LEN] = {'S', 'T', 'E', 'A', 'L', 'T', 'H'};
inline constexpr uint8_t kSgmtLeafTag[SGMTLEAF_PREFIX_LEN] = {'S', 'G', 'M', 'T',
                                                              'L', 'E', 'A', 'F'};

/// Receiver payload = "STEALTH" + pstealth[32] + zero pad (42 bytes).
inline void make_stealth_receiver(const uint8_t pstealth[STEALTH_PSTEALTH_LEN],
                                  uint8_t out_receiver[42]) noexcept {
    static_assert(42 - STEALTH_PREFIX_LEN - STEALTH_PSTEALTH_LEN == 3, "pad size");
    std::memcpy(out_receiver, kStealthTag, STEALTH_PREFIX_LEN);
    std::memcpy(out_receiver + STEALTH_PREFIX_LEN, pstealth, STEALTH_PSTEALTH_LEN);
    std::memset(out_receiver + STEALTH_PREFIX_LEN + STEALTH_PSTEALTH_LEN, 0, 3);
}

/// Receiver payload = "SGMTLEAF" + leaf[32] + zero pad (42 bytes).
inline void make_sgmtleaf_receiver(const uint8_t leaf[SGMT_LEAF_LEN],
                                   uint8_t out_receiver[42]) noexcept {
    static_assert(42 - SGMTLEAF_PREFIX_LEN - SGMT_LEAF_LEN == 2, "pad size");
    std::memcpy(out_receiver, kSgmtLeafTag, SGMTLEAF_PREFIX_LEN);
    std::memcpy(out_receiver + SGMTLEAF_PREFIX_LEN, leaf, SGMT_LEAF_LEN);
    std::memset(out_receiver + SGMTLEAF_PREFIX_LEN + SGMT_LEAF_LEN, 0, 2);
}

inline bool receiver_is_stealth(const uint8_t receiver[42]) noexcept {
    return std::memcmp(receiver, kStealthTag, STEALTH_PREFIX_LEN) == 0;
}

inline bool receiver_is_sgmtleaf(const uint8_t receiver[42]) noexcept {
    return std::memcmp(receiver, kSgmtLeafTag, SGMTLEAF_PREFIX_LEN) == 0;
}

/// Extracts the 32-byte tracker; false when the padding bytes are non-zero
/// (non-canonical receiver — fail closed).
inline bool stealth_pstealth_of(const uint8_t receiver[42], uint8_t out_pstealth[32]) noexcept {
    if (!receiver_is_stealth(receiver))
        return false;
    for (unsigned i = STEALTH_PREFIX_LEN + STEALTH_PSTEALTH_LEN; i < 42; ++i)
        if (receiver[i] != 0)
            return false; // non-canonical padding
    std::memcpy(out_pstealth, receiver + STEALTH_PREFIX_LEN, STEALTH_PSTEALTH_LEN);
    return true;
}

/// Extracts the frame-committed 32-byte leaf; false on non-canonical padding.
inline bool sgmtleaf_of(const uint8_t receiver[42], uint8_t out_leaf[32]) noexcept {
    if (!receiver_is_sgmtleaf(receiver))
        return false;
    for (unsigned i = SGMTLEAF_PREFIX_LEN + SGMT_LEAF_LEN; i < 42; ++i)
        if (receiver[i] != 0)
            return false;
    std::memcpy(out_leaf, receiver + SGMTLEAF_PREFIX_LEN, SGMT_LEAF_LEN);
    return true;
}

/// Nickname consensus rules: 1..32 bytes, printable ASCII 0x21..0x7E
/// (no whitespace ambiguity — the whole range is non-space). false = the
/// registration sidecar is malformed.
inline bool nickname_valid(const std::string &nickname) noexcept {
    if (nickname.empty() || nickname.size() > 32)
        return false;
    for (const char ch : nickname)
        if (ch < 0x21 || ch > 0x7E)
            return false;
    return true;
}

// ── Registry ────────────────────────────────────────────────────────────────

struct SgmtRecord {
    std::string nickname;
    PublicKeys pub{};
};

struct StealthBundle {
    StealthTx tx{};
};

struct Array32Hash {
    size_t operator()(const std::array<uint8_t, 32> &d) const noexcept {
        size_t h = 1469598103934665603ull;
        for (uint8_t b : d) {
            h ^= b;
            h *= 1099511628211ull;
        }
        return h;
    }
};

// Durable SGMT record log: the same versioned append-only discipline as
// the PQ witness log. One record = magic(8) + digest(32) + nlen(1) +
// nickname(n) + t_spend(384) + kkem(1184). The digest rides IN the
// record — it is not derivable from the record alone, and the replay must
// restore the exact digest key the original registration used.
inline constexpr uint8_t kSgmtLogMagic[8] = {'V', 'X', 'D', 'S', 'G', 'R', '0', '1'};

namespace detail {

inline bool sgmt_write_all(int fd, const uint8_t *p, size_t n) {
    while (n > 0) {
        const ssize_t w = ::write(fd, p, n);
        if (w <= 0)
            return false;
        p += static_cast<size_t>(w);
        n -= static_cast<size_t>(w);
    }
    return true;
}

/// Unpack a 12-bit-packed commitment and verify every coefficient is
/// canonical (< q). Mirrors ml_kem's unpack12 layout: three bytes yield
/// two coefficients (d0 = b0 | (b1 & 0xF) << 8, d1 = b1 >> 4 | b2 << 4).
inline bool unpack12_canonical(const std::array<uint8_t, T_COMMIT_SIZE> &packed) noexcept {
    static_assert(T_COMMIT_SIZE == 384, "12-bit packing size");
    for (unsigned i = 0, b = 0; i < mlkem::RING_N; i += 2, b += 3) {
        const uint16_t d0 = static_cast<uint16_t>(packed[b] | ((packed[b + 1] & 0x0F) << 8));
        const uint16_t d1 = static_cast<uint16_t>((packed[b + 1] >> 4) |
                                                  (static_cast<uint16_t>(packed[b + 2]) << 4));
        if (d0 >= mlkem::RING_Q || d1 >= mlkem::RING_Q)
            return false;
    }
    return true;
}

} // namespace detail

class DksapSidecarRegistry {
public:
    // Bounded candidate set per digest (gossip is unauthenticated; a bogus
    // candidate cannot displace an honest one, it can only fill a slot).
    // RAM bounds: STEALTH is radar-only (LRU); SGMT is consensus-visible
    // and durable — an evicted committed record is re-replayed from the log.
    static constexpr size_t kMaxCandidatesPerDigest = 4;
    static constexpr size_t kStealthCap = 32768;
    static constexpr size_t kSgmtMemCap = 32768;

    static DksapSidecarRegistry &instance() noexcept {
        static DksapSidecarRegistry reg;
        return reg;
    }

    /// Attach the durable SGMT record log (consensus requirement). Every
    /// register_sgmt_record call appends the record before returning;
    /// attach replays the existing file. Re-attaching the same path is
    /// idempotent; a DIFFERENT path is refused (single-node ownership).
    void attach_sgmt_durable_log(const std::string &path) {
        std::lock_guard<std::mutex> lock(mutex_);
        if (sgmt_log_attached_) {
            if (sgmt_log_path_ != path)
                std::abort(); // single ownership: the node owns exactly one ledger
            return;
        }
        sgmt_log_path_ = path;
        sgmt_log_attached_ = true;
        replay_sgmt_durable_tail(kSgmtMemCap);
    }

    // ── Candidate model (security review 2026-11-15) ────────────────────────
    // Gossip is UNAUTHENTICATED: the first record that arrives for a digest
    // may be bogus, so nothing is keyed "one record per digest" and nothing
    // is persisted before it is verified against a frame-committed leaf.
    // register_*_candidate stores a bounded candidate set; resolve_* returns
    // the candidate that ACTUALLY commits the frame leaf (deterministic —
    // every node holding the honest record resolves identically); the
    // durable log is appended ONLY from commit_sgmt_record, which the
    // ledger calls after the commitment check passed.

    /// Intake: a bounded candidate for the digest. Shape checks only —
    /// the commitment check happens at resolve time against the frame.
    bool register_sgmt_candidate(const std::array<uint8_t, 32> &digest, const SgmtRecord &rec) {
        if (!nickname_valid(rec.nickname))
            return false;
        // Canonical-form intake hygiene: a commitment no honest derivation
        // could have produced never occupies a candidate slot.
        if (!detail::unpack12_canonical(rec.pub.t_spend))
            return false;
        std::lock_guard<std::mutex> lock(mutex_);
        return insert_candidate(digest, rec, /*committed=*/false);
    }

    bool register_stealth_candidate(const std::array<uint8_t, 32> &digest, const StealthBundle &b) {
        std::lock_guard<std::mutex> lock(mutex_);
        insert_candidate(digest, b, /*committed=*/false);
        return true;
    }

    /// Resolve the candidate whose record commits exactly the frame leaf.
    /// Deterministic: arrival order cannot change the outcome, so honest
    /// nodes holding the same honest record (plus any bogus candidates)
    /// compute the same registration.
    bool resolve_sgmt_record(const std::array<uint8_t, 32> &digest,
                             const std::array<uint8_t, 32> &expected_leaf, SgmtRecord &out) const {
        std::lock_guard<std::mutex> lock(mutex_);
        // Scans one digest's candidate set for the record that commits the
        // frame leaf; replays the durable tail and re-scans when the set
        // cannot serve (entry missing, or only gossip candidates held —
        // e.g. the honest committed candidate was displaced and the log
        // still anchors it). One replay attempt, then fail closed.
        const auto scan = [&](const std::unordered_map<std::array<uint8_t, 32>, SgmtEntry,
                                                       Array32Hash>::const_iterator entry) {
            for (const auto &c : entry->second.sg) {
                const auto commit = sgmt_commit(c.rec.nickname, c.rec.pub);
                if (vx::core::ct_equal(commit.data(), expected_leaf.data(), 32)) {
                    out = c.rec;
                    return true;
                }
            }
            return false;
        };
        auto it = sgmt_.find(digest);
        if (it != sgmt_.end() && scan(it))
            return true;
        const_cast<DksapSidecarRegistry *>(this)->replay_sgmt_durable_tail(kSgmtMemCap);
        it = sgmt_.find(digest);
        return it != sgmt_.end() && scan(it);
    }

    /// Resolve the bundle whose Pstealth matches the frame receiver.
    bool resolve_stealth_bundle(const std::array<uint8_t, 32> &digest,
                                const uint8_t expected_pstealth[32], StealthBundle &out) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stealth_.find(digest);
        if (it == stealth_.end())
            return false;
        for (const auto &c : it->second.sb) {
            if (vx::core::ct_equal(c.bundle.tx.pstealth.data(), expected_pstealth, 32)) {
                out = c.bundle;
                return true;
            }
        }
        return false;
    }

    /// PERSISTENT commit: called by the ledger AFTER sgmt_commit(record) ==
    /// frame leaf passed. fsync-append to the durable log, then stamp the
    /// entry committed — replayed records restore as committed candidates.
    /// Returns false ONLY on a durable-append failure while attached: the
    /// caller must refuse the block (a memory-only committed record would
    /// brick the node against its own history after restart — review P3-13).
    /// An idempotent re-commit under the SAME digest (resync replay of an
    /// already-applied block) skips the append: an in-memory committed
    /// candidate under this digest implies its row is already fsync'd (it
    /// was written by an earlier commit or restored from the log itself).
    /// Security review 2026-11-15 (HIGH): the previous cross-digest dedup
    /// anchored a re-registered (nickname, keys) pair in memory ONLY —
    /// after a restart, resolve_sgmt_record under the new digest had no
    /// log row to replay and the node refused its own history. Every
    /// digest therefore gets its own durable row; log growth stays bounded
    /// by the number of registration transactions in the chain (one row
    /// per digest, and byte-identical re-commits under a digest append
    /// nothing).
    bool commit_sgmt_record(const std::array<uint8_t, 32> &digest, const SgmtRecord &rec) {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sgmt_.find(digest);
        if (it != sgmt_.end())
            for (const auto &c : it->second.sg)
                if (c.committed && c.rec.nickname == rec.nickname &&
                    c.rec.pub.t_spend == rec.pub.t_spend && c.rec.pub.kkem == rec.pub.kkem)
                    return true; // same digest, same record: row already durable
        insert_candidate(digest, rec, /*committed=*/true);
        return append_sgmt_durable(digest, rec);
    }

    /// Relay helper: every candidate for a digest (bounded; the relayer is
    /// not an authority — receivers re-resolve against the frame leaf).
    std::vector<SgmtRecord> copy_sgmt_candidates(const std::array<uint8_t, 32> &digest) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = sgmt_.find(digest);
        if (it == sgmt_.end())
            return {};
        std::vector<SgmtRecord> out;
        for (const auto &c : it->second.sg)
            out.push_back(c.rec);
        return out;
    }
    std::vector<StealthBundle>
    copy_stealth_candidates(const std::array<uint8_t, 32> &digest) const {
        std::lock_guard<std::mutex> lock(mutex_);
        auto it = stealth_.find(digest);
        if (it == stealth_.end())
            return {};
        std::vector<StealthBundle> out;
        for (const auto &c : it->second.sb)
            out.push_back(c.bundle);
        return out;
    }

    /// Records restored from the durable log on attach (diagnostics).
    size_t durable_replayed() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return durable_replayed_;
    }
    size_t sgmt_size() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return sgmt_.size();
    }
    size_t stealth_size() const noexcept {
        std::lock_guard<std::mutex> lock(mutex_);
        return stealth_.size();
    }

private:
    DksapSidecarRegistry() = default;

    struct SgmtCand {
        SgmtRecord rec;
        uint64_t stamp;
        bool committed;
    };
    struct StealthCand {
        StealthBundle bundle;
        uint64_t stamp;
    };
    struct SgmtEntry {
        std::vector<SgmtCand> sg;
        uint64_t stamp;
    };
    struct StealthEntry {
        std::vector<StealthCand> sb;
        uint64_t stamp;
    };

    /// Insert one candidate under the digest, bounded per digest (evict the
    /// oldest UNCOMMITTED candidate when full — a committed candidate is
    /// anchored by the durable log and never displaced by late gossip).
    /// Returns true when the candidate set was mutated (a byte-identical
    /// re-arrival is a no-op).
    bool insert_candidate(const std::array<uint8_t, 32> &digest, const SgmtRecord &rec,
                          bool committed) {
        // SGMT path
        SgmtCand c;
        c.rec = rec;
        c.stamp = ++stamp_;
        c.committed = committed;
        auto &e = sgmt_[digest];
        e.stamp = c.stamp;
        for (auto &old : e.sg)
            if (old.rec.nickname == rec.nickname && old.rec.pub.t_spend == rec.pub.t_spend &&
                old.rec.pub.kkem == rec.pub.kkem) {
                // Same record already held for this digest. A GOSSIPED
                // candidate (uncommitted) that now arrives through the
                // COMMIT path must be upgraded in place — a blind no-op
                // would leave the honest candidate evictable by late
                // gossip and duplicate the durable row on re-commit
                // (security review 2026-11-15, MEDIUM).
                if (committed && !old.committed) {
                    old.committed = true;
                    return true;
                }
                return false; // byte-identical re-arrival
            }
        if (e.sg.size() >= kMaxCandidatesPerDigest) {
            auto worst = e.sg.begin();
            for (auto it = e.sg.begin(); it != e.sg.end(); ++it)
                if (!it->committed && (worst->committed || it->stamp < worst->stamp))
                    worst = it;
            if (worst->committed)
                return false; // all slots committed: late gossip is dropped
            e.sg.erase(worst);
        }
        e.sg.push_back(std::move(c));
        trim_global();
        return true;
    }
    bool insert_candidate(const std::array<uint8_t, 32> &digest, const StealthBundle &b,
                          bool committed) {
        (void)committed; // stealth bundles are never committed/persisted
        StealthCand c;
        c.bundle = b;
        c.stamp = ++stamp_;
        auto &e = stealth_[digest];
        e.stamp = c.stamp;
        for (const auto &old : e.sb)
            if (old.bundle.tx.pstealth == b.tx.pstealth &&
                old.bundle.tx.view_tag == b.tx.view_tag &&
                old.bundle.tx.t_stealth == b.tx.t_stealth && old.bundle.tx.kem_ct == b.tx.kem_ct)
                return false; // byte-identical re-arrival
        if (e.sb.size() >= kMaxCandidatesPerDigest) {
            auto worst = e.sb.begin();
            for (auto it = e.sb.begin(); it != e.sb.end(); ++it)
                if (it->stamp < worst->stamp)
                    worst = it;
            e.sb.erase(worst);
        }
        e.sb.push_back(std::move(c));
        trim_global();
        return true;
    }

    /// Global RAM bounds: LRU eviction of whole digest entries (a committed
    /// SGMT record is servable again from the durable log).
    void trim_global() {
        if (sgmt_.size() > kSgmtMemCap) {
            auto worst = sgmt_.begin();
            for (auto it = sgmt_.begin(); it != sgmt_.end(); ++it)
                if (it->second.stamp < worst->second.stamp)
                    worst = it;
            sgmt_.erase(worst);
        }
        if (stealth_.size() > kStealthCap) {
            auto worst = stealth_.begin();
            for (auto it = stealth_.begin(); it != stealth_.end(); ++it)
                if (it->second.stamp < worst->second.stamp)
                    worst = it;
            stealth_.erase(worst);
        }
    }

    bool append_sgmt_durable(const std::array<uint8_t, 32> &digest, const SgmtRecord &rec) {
        if (!sgmt_log_attached_)
            return true; // pre-attach callers (unit tests) skip persistence
        const int fd = ::open(sgmt_log_path_.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
        if (fd < 0) {
            std::cerr << "[DksapSidecars] durable log open failed — refusing the commit\n";
            return false; // fail closed: a memory-only committed record bricks the restart
        }
        struct stat st{};
        bool ok = ::fstat(fd, &st) == 0;
        if (ok && st.st_size == 0)
            ok = detail::sgmt_write_all(fd, kSgmtLogMagic, 8);
        if (ok) {
            const uint8_t nlen = static_cast<uint8_t>(rec.nickname.size());
            ok = detail::sgmt_write_all(fd, digest.data(), digest.size()) &&
                 detail::sgmt_write_all(fd, &nlen, 1) &&
                 detail::sgmt_write_all(fd, reinterpret_cast<const uint8_t *>(rec.nickname.data()),
                                        rec.nickname.size()) &&
                 detail::sgmt_write_all(fd, rec.pub.t_spend.data(), rec.pub.t_spend.size()) &&
                 detail::sgmt_write_all(fd, rec.pub.kkem.data(), rec.pub.kkem.size());
        }
        if (ok)
            ok = ::fsync(fd) == 0;
        ::close(fd);
        if (!ok)
            std::cerr << "[DksapSidecars] durable log append failed — refusing the commit"
                         " (the dependent block replay must stay possible)\n";
        return ok;
    }

    bool replay_sgmt_durable_tail(size_t max_records) {
        if (!sgmt_log_attached_)
            return false;
        const int fd = ::open(sgmt_log_path_.c_str(), O_RDONLY);
        if (fd < 0)
            return false;
        struct stat st{};
        if (::fstat(fd, &st) != 0 || st.st_size < 8) {
            ::close(fd);
            return false;
        }
        // Whole-file replay: one record is 32 + 1 + 32 + 1568 = 1633 bytes
        // plus the nickname — a real testnet holds hundreds of nicknames,
        // not millions; the cap bounds pathological logs.
        const auto fsize = static_cast<size_t>(st.st_size);
        std::vector<uint8_t> buf(fsize);
        const ssize_t got = ::pread(fd, buf.data(), buf.size(), 0);
        ::close(fd);
        if (got != static_cast<ssize_t>(buf.size()))
            return false;
        if (std::memcmp(buf.data(), kSgmtLogMagic, 8) != 0)
            return false;
        size_t off = 8;
        size_t loaded = 0;
        while (loaded < max_records) {
            // Record frame: digest(32) + nlen(1) + nickname(n) + keys(1568).
            if (off + 32 + 1 > buf.size())
                break;
            std::array<uint8_t, 32> digest{};
            std::memcpy(digest.data(), buf.data() + off, 32);
            off += 32;
            const uint8_t nlen = buf[off++];
            if (nlen == 0 || nlen > 32)
                break; // torn/corrupt tail — everything past it is ignored
            if (off + size_t(nlen) + T_COMMIT_SIZE + KEM_PK_SIZE > buf.size())
                break;
            SgmtRecord rec;
            rec.nickname.assign(reinterpret_cast<const char *>(buf.data() + off), nlen);
            off += nlen;
            std::memcpy(rec.pub.t_spend.data(), buf.data() + off, T_COMMIT_SIZE);
            off += T_COMMIT_SIZE;
            std::memcpy(rec.pub.kkem.data(), buf.data() + off, KEM_PK_SIZE);
            off += KEM_PK_SIZE;
            if (!detail::unpack12_canonical(rec.pub.t_spend))
                break; // corrupt record: the replay stops, the log is rebuildable
            // Replayed records are COMMITTED candidates — they were
            // fsync'd only after the leaf gate passed on the original node.
            if (insert_candidate(digest, rec, /*committed=*/true)) {
                ++durable_replayed_;
                ++loaded;
            }
        }
        return loaded > 0;
    }

    mutable std::mutex mutex_;
    std::unordered_map<std::array<uint8_t, 32>, SgmtEntry, Array32Hash> sgmt_;
    std::unordered_map<std::array<uint8_t, 32>, StealthEntry, Array32Hash> stealth_;
    uint64_t stamp_ = 0;
    size_t durable_replayed_ = 0;
    std::string sgmt_log_path_;
    bool sgmt_log_attached_ = false;
};

} // namespace vx::crypto::dksap
