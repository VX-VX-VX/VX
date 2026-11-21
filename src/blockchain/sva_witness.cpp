// SVA-8192 spend-witness registry — durable sidecar (0.2.x phase A).
//
// The in-memory map is owner-gated (verify-before-store: only a witness
// that derives the claimed vault encoding is accepted, and only the vault
// owner knows a preimage), so the sidecar's job is REPLAY, not trust:
// a node restart re-applies its own history, and a vault spend already in
// the chain must not orphan when the ledger re-applies the block. Every
// registration is fsync'd; the replay re-verifies each record (a tampered
// sidecar is refused, never imported). A torn tail is healed by truncating
// to the last complete record; a corrupted record stops the replay
// fail-closed and the witness re-registers from the wallet.

#include "vx/blockchain/sva_witness.hpp"

#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <cstring>

namespace vx::blockchain::sva {

bool SvaWitnessRegistry::insert_locked(const std::array<uint8_t, 32> &digest,
                                       const SvaWitnessEntry &e, bool *fresh) {
    if (fresh)
        *fresh = false;
    auto it = by_digest_.find(digest);
    if (it != by_digest_.end()) {
        for (const SvaWitnessEntry &x : it->second) {
            if (x.sender != e.sender)
                continue;
            // Same sender: for a given digest + sender exactly one
            // (preimage, path, index) triple derives the claimed encoding,
            // so identical content is a re-delivery (dedup) and anything
            // else is a conflict — refuse it.
            if (x.root == e.root && x.spend_index == e.spend_index && x.preimage == e.preimage &&
                x.path == e.path)
                return true;
            return false;
        }
        if (it->second.size() >= kSvaMaxWitnessesPerDigest)
            return false;
    }
    auto s_it = per_sender_.find(e.sender);
    if (s_it != per_sender_.end() && s_it->second >= kSvaMaxWitnessesPerSender)
        return false;
    if (entries_ >= kSvaMaxWitnessEntries) {
        // Global cap: evict the OLDEST entry to admit this fresh
        // verify-passing witness. Every entry passed verify-before-store,
        // so an eviction can never introduce a bad state — a pending
        // block re-requests the witness from the network (the wallet
        // re-registers; durability is an optimization).
        while (!fifo_.empty()) {
            const auto victim = fifo_.front();
            fifo_.pop_front();
            auto v_it = by_digest_.find(victim.first);
            if (v_it == by_digest_.end())
                continue;
            auto &vec = v_it->second;
            for (size_t i = 0; i < vec.size(); ++i) {
                if (vec[i].sender != victim.second)
                    continue;
                if (auto s2 = per_sender_.find(vec[i].sender); s2 != per_sender_.end())
                    --s2->second;
                vec.erase(vec.begin() + static_cast<ptrdiff_t>(i));
                --entries_;
                break;
            }
            if (vec.empty())
                by_digest_.erase(v_it);
            break;
        }
        if (entries_ >= kSvaMaxWitnessEntries)
            return false;
    }
    // Re-find after eviction: the evicted victim may have been the last
    // entry of THIS digest, invalidating the earlier iterator.
    it = by_digest_.find(digest);
    if (it == by_digest_.end())
        it = by_digest_.emplace(digest, std::vector<SvaWitnessEntry>{}).first;
    it->second.push_back(e);
    ++entries_;
    ++per_sender_[e.sender];
    fifo_.emplace_back(digest, e.sender);
    if (fresh)
        *fresh = true;
    return true;
}

bool SvaWitnessRegistry::append_durable_locked(const std::array<uint8_t, 32> &digest,
                                               const uint8_t sender_nfa[42],
                                               const SvaWitnessEntry &e) {
    if (durable_fd_ < 0)
        return true; // memory-only mode (durability is an optimization)
    uint8_t rec[kDurableRecSize];
    std::memcpy(rec, "VXSVWT1", 8);
    std::memcpy(rec + 8, digest.data(), 32);
    std::memcpy(rec + 40, sender_nfa, 42);
    std::memcpy(rec + 82, e.root.data(), 32);
    std::memcpy(rec + 114, e.preimage.data(), e.preimage.size());
    std::memcpy(rec + 114 + e.preimage.size(), e.path.data(), e.path.size() * 32);
    const uint32_t idx_le = e.spend_index;
    std::memcpy(rec + 114 + e.preimage.size() + e.path.size() * 32, &idx_le, 4);

    // Write at the LOGICAL end (the last good record boundary), not at the
    // O_APPEND tail: if a crash tore a half-record, the tear would sit
    // between the last good record and every later append, and the replay
    // (which stops at the tear) would strand all of them behind it
    // (zeroday hunt 2026-11-21, CWE-367). The exclusive flock makes
    // mid-file writes from a sibling process impossible.
    size_t off = 0;
    while (off < sizeof(rec)) {
        const ssize_t n = ::pwrite(durable_fd_, rec + off, sizeof(rec) - off,
                                   durable_end_ + static_cast<off_t>(off));
        if (n <= 0)
            return false;
        off += static_cast<size_t>(n);
    }
    // Truncate anything past the record we just wrote — this is the
    // torn-tail heal, applied at the first append after a crash.
    if (::ftruncate(durable_fd_, durable_end_ + static_cast<off_t>(sizeof(rec))) != 0)
        return false;
    if (::fsync(durable_fd_) != 0)
        return false;
    durable_end_ += static_cast<off_t>(sizeof(rec));
    return true;
}

void SvaWitnessRegistry::attach_durable_log(const std::string &path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (durable_fd_ >= 0 && durable_path_ == path)
        return; // already attached
    if (durable_fd_ >= 0) {
        ::close(durable_fd_);
        durable_fd_ = -1;
    }
    durable_path_ = path;
    // O_RDWR without O_APPEND: appends are positioned by durable_end_ (the
    // logical end), never by the raw file tail — a crash-torn half-record
    // must not strand later appends behind it (CWE-367).
    const int fd = ::open(path.c_str(), O_RDWR | O_CREAT, 0600);
    if (fd < 0)
        return; // memory-only fallback; the node never fails here
    // Exclusive flock: two node processes sharing a data directory must
    // not interleave records into torn halves. A busy log falls back to
    // memory-only mode (the witness re-registers from the wallet).
    if (::flock(fd, LOCK_EX | LOCK_NB) != 0) {
        ::close(fd);
        return;
    }
    durable_fd_ = fd;
    // Replay full records only; a short or corrupt record stops the replay
    // (fail-closed). The flock makes mid-file torn writes from a sibling
    // process impossible; only a hand-corrupted or crash-torn tail stops
    // early — and the tail is healed by truncating to the last good record
    // (or by the next append's pwrite+ftruncate).
    uint8_t rec[kDurableRecSize];
    off_t good_offset = 0;
    for (;;) {
        // No entry-count break here: insert_locked evicts oldest-first at
        // the global cap, so a full sidecar replay ends with the NEWEST
        // kSvaMaxWitnessEntries records in RAM (the pre-fix break kept the
        // oldest — backwards from the eviction semantics).
        ssize_t got = 0;
        while (got < static_cast<ssize_t>(sizeof(rec))) {
            const ssize_t n =
                ::read(fd, rec + static_cast<size_t>(got), sizeof(rec) - static_cast<size_t>(got));
            if (n <= 0)
                break;
            got += n;
        }
        if (got != static_cast<ssize_t>(sizeof(rec))) {
            // Torn tail (a crash mid-append): truncate to the last fully
            // read good record boundary so later honest appends are not
            // stranded behind the torn bytes. A clean EOF truncates nothing.
            if (got > 0)
                ::ftruncate(fd, good_offset);
            break;
        }
        if (std::memcmp(rec, "VXSVWT1", 8) != 0)
            break; // corrupt -> stop (fail-closed)
        std::array<uint8_t, 32> digest{};
        std::memcpy(digest.data(), rec + 8, 32);
        SvaWitnessEntry e;
        std::memcpy(e.root.data(), rec + 82, 32);
        std::memcpy(e.preimage.data(), rec + 114, e.preimage.size());
        std::memcpy(e.path.data(), rec + 114 + e.preimage.size(), e.path.size() * 32);
        uint32_t idx_le;
        std::memcpy(&idx_le, rec + 114 + e.preimage.size() + e.path.size() * 32, 4);
        e.spend_index = idx_le;
        std::memcpy(e.sender.data(), rec + 40, 42);
        // Replay re-verifies: the record must still derive the root it
        // claims AND the vault encoding it was registered under. A tampered
        // or hand-corrupted sidecar is refused, never imported into
        // consensus state.
        if (sva_root_of(e.spend_index, e.preimage, e.path) != e.root)
            break;
        Address chk{};
        derive_sva_address(e.root.data(), chk.data());
        if (std::memcmp(chk.data(), rec + 40, 42) != 0)
            break;
        good_offset += static_cast<off_t>(sizeof(rec));
        // Same insertion rules as a live registration: dedup, conflict
        // refusal, per-sender/digest caps, oldest-first eviction. A record
        // refused by a cap is skipped (structurally valid, verified), not
        // a replay stop.
        (void)insert_locked(digest, e);
    }
    durable_end_ = good_offset;
}

} // namespace vx::blockchain::sva
