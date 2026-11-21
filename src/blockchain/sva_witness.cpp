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

    size_t off = 0;
    while (off < sizeof(rec)) {
        const ssize_t n = ::write(durable_fd_, rec + off, sizeof(rec) - off);
        if (n <= 0)
            return false;
        off += static_cast<size_t>(n);
    }
    return ::fsync(durable_fd_) == 0;
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
    // O_APPEND: every record lands at the current end regardless of the
    // file offset any other code path left behind.
    const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_APPEND, 0600);
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
    // early — and the tail is healed by truncating to the last good record.
    uint8_t rec[kDurableRecSize];
    off_t good_offset = 0;
    for (;;) {
        if (by_digest_.size() >= kSvaMaxWitnessEntries)
            break; // cap the RAM too
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
        by_digest_.emplace(digest, e);
    }
}

} // namespace vx::blockchain::sva
