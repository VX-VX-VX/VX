#include "vx/storage/block_store.hpp"
#include "vx/blockchain/genesis.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace vx::storage {

using blockchain::BlockFrame;
using blockchain::BlockView;
using blockchain::RawBlock;
using blockchain::BLOCK_SIZE_BYTES;

// ── Helpers ──────────────────────────────────────────────────────────────────

static uint64_t file_size(int fd) {
    struct stat st {};
    if (fstat(fd, &st) != 0) return 0;
    return static_cast<uint64_t>(st.st_size);
}

/// Reads a whole file into a frame buffer. Returns false if size != 64 KB.
static bool load_frame(const std::string& path, BlockFrame& out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f) return false;
    if (f.tellg() != static_cast<std::streamoff>(BLOCK_SIZE_BYTES)) return false;
    f.seekg(0);
    f.read(reinterpret_cast<char*>(out.data()), BLOCK_SIZE_BYTES);
    return f.gcount() == static_cast<std::streamsize>(BLOCK_SIZE_BYTES);
}

/// Validates every frame in [start, end): magic, strictly increasing height,
/// tx_count bound and a merkle commitment recomputed from the body — the
/// deterministic subset of blockchain::validate_block (BACKLOG 0.9). The
/// time-dependent checks (PoGW target, timestamp sanity) are meaningless
/// against historical blocks: a block was mined for its own moment, and
/// re-judging it against today's clock would make every old ledger fail.
/// Genesis (height 0) must be the very first frame exactly once.
static bool validate_region(const uint8_t* base, uint64_t from, uint64_t to) {
    for (uint64_t h = from; h < to; ++h) {
        const RawBlock* raw = reinterpret_cast<const RawBlock*>(base + h * BLOCK_SIZE_BYTES);
        if (raw->header.magic != blockchain::BLOCK_MAGIC) return false;
        if (raw->header.block_height != h) return false;
        if (raw->header.tx_count > blockchain::MAX_TX_PER_BLOCK) return false;
        if (!blockchain::verify_block_merkle(*raw)) return false;
    }
    return true;
}

// ── BlockStore ───────────────────────────────────────────────────────────────

BlockStore::BlockStore(const std::string& path, const std::string& genesis_path,
                       uint64_t required_pogw_bits) : path_(path), required_pogw_bits_(required_pogw_bits) {
    fd_ = ::open(path.c_str(), O_RDWR | O_CREAT, 0644);
    if (fd_ < 0) {
        throw std::runtime_error("BlockStore: cannot open '" + path + "': " + std::strerror(errno));
    }

    uint64_t size = file_size(fd_);

    // Auto-init empty ledger from genesis.bin (deterministically regenerated
    // in-process when the file is absent — never shipped, never copied).
    if (size == 0) {
        BlockFrame genesis{};
        if (!load_frame(genesis_path, genesis)) {
            try {
                blockchain::write_genesis_file(genesis_path);
            } catch (const std::exception& e) {
                ::close(fd_);
                fd_ = -1;
                throw std::runtime_error(std::string("BlockStore: cannot regenerate '") +
                                         genesis_path + "': " + e.what());
            }
            if (!load_frame(genesis_path, genesis)) {
                ::close(fd_);
                fd_ = -1;
                throw std::runtime_error("BlockStore: regenerated '" + genesis_path +
                                         "' is not exactly 65536 bytes");
            }
        }
        BlockView gv{std::span<const uint8_t, BLOCK_SIZE_BYTES>(genesis)};
        if (!gv.valid_magic() || gv.header().block_height != 0) {
            ::close(fd_);
            fd_ = -1;
            throw std::runtime_error("BlockStore: genesis.bin is not a valid height-0 VXC6 frame");
        }
        ssize_t wrote = ::pwrite(fd_, genesis.data(), BLOCK_SIZE_BYTES, 0);
        if (wrote != static_cast<ssize_t>(BLOCK_SIZE_BYTES)) {
            ::close(fd_);
            fd_ = -1;
            throw std::runtime_error("BlockStore: failed to seed genesis: " + std::string(std::strerror(errno)));
        }
        ::fsync(fd_);
        size = BLOCK_SIZE_BYTES;
    }

    // Reject a torn tail (file size not a multiple of the frame)
    if (size % BLOCK_SIZE_BYTES != 0) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("BlockStore: '" + path + "' size " + std::to_string(size) +
                                 " is not a multiple of 65536 — corrupted ledger");
    }

    count_ = size / BLOCK_SIZE_BYTES;
    if (!ensure_mapping(size)) {
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("BlockStore: mmap of '" + path + "' failed: " + std::strerror(errno));
    }

    if (!validate_region(static_cast<const uint8_t*>(mapped_), 0, count_)) {
        throw std::runtime_error("BlockStore: ledger '" + path +
                                 "' contains frames with bad magic, non-sequential heights, "
                                 "oversized tx_count or a broken merkle commitment");
    }
}

BlockStore::~BlockStore() noexcept {
    if (mapped_) ::munmap(mapped_, mapped_bytes_);
    if (fd_ >= 0) ::close(fd_);
}

/// Extends (or creates) the read-only shared mapping so it covers new_bytes.
/// Uses mremap so already-faulted pages are preserved — amortized O(1).
bool BlockStore::ensure_mapping(uint64_t new_bytes) {
    if (new_bytes == 0) return true;
    if (mapped_bytes_ >= new_bytes && mapped_) return true;

    if (mapped_) {
        void* moved = ::mremap(mapped_, mapped_bytes_, new_bytes, MREMAP_MAYMOVE);
        if (moved != MAP_FAILED) {
            mapped_ = moved;
            mapped_bytes_ = new_bytes;
            return true;
        }
        ::munmap(mapped_, mapped_bytes_);
        mapped_ = nullptr;
        mapped_bytes_ = 0;
    }

    void* p = ::mmap(nullptr, new_bytes, PROT_READ, MAP_SHARED, fd_, 0);
    if (p == MAP_FAILED) return false;
    mapped_ = p;
    mapped_bytes_ = new_bytes;
    return true;
}

bool BlockStore::append_block(const BlockFrame& frame) {
    last_error_.clear();
    BlockView v{std::span<const uint8_t, BLOCK_SIZE_BYTES>(frame)};
    const uint64_t expected_height = count_; // next after tip
    if (!v.valid_magic() || v.header().block_height != expected_height) {
        last_error_ = "bad magic or height != tip + 1";
        return false;
    }

    // Single intake gate (BACKLOG 0.9): every production intake path —
    // RPC transfer/mine, P2P apply_remote_frame, the background miner and
    // any future producer — appends through this method, so this is the one
    // place the full consensus gate runs. Cheap rejections happen inside
    // validate_block first; the expensive full-frame PoGW hash runs last.
    blockchain::BlockIntakeContext ctx{};
    ctx.expected_height = expected_height;
    if (count_ == 0) {
        std::memset(ctx.expected_prev_hash, 0, 32);
        ctx.prev_timestamp = 0;
    } else {
        tip_hash(ctx.expected_prev_hash);
        const RawBlock* tip = get_block(count_ - 1);
        ctx.prev_timestamp = tip ? tip->header.timestamp : 0;
    }
    ctx.now_unix = static_cast<uint64_t>(std::time(nullptr));
    ctx.difficulty_bits = required_pogw_bits_;
    if (!blockchain::validate_block(*reinterpret_cast<const blockchain::RawBlock*>(frame.data()),
                                    ctx, &last_error_)) {
        return false;
    }

    // Grow the file by one frame, then pwrite it atomically at the tip offset.
    const off_t offset = static_cast<off_t>(expected_height * BLOCK_SIZE_BYTES);
    if (::ftruncate(fd_, offset + BLOCK_SIZE_BYTES) != 0) return false;
    ssize_t wrote = ::pwrite(fd_, frame.data(), BLOCK_SIZE_BYTES, offset);
    if (wrote != static_cast<ssize_t>(BLOCK_SIZE_BYTES)) {
        ::ftruncate(fd_, offset); // roll back the torn frame
        return false;
    }
    // Durability is part of the append contract: a reported success must
    // mean the frame survived a power cut. An fsync error is treated like
    // any other failed write - the frame is rolled back and the caller
    // sees a rejection, never a phantom acknowledgment.
    if (::fsync(fd_) != 0) {
        ::ftruncate(fd_, offset);
        return false;
    }

    ++count_;
    return ensure_mapping(count_ * BLOCK_SIZE_BYTES);
}

bool BlockStore::rollback_last_append() noexcept {
    if (count_ <= 1) return false; // the genesis frame is never rolled back
    const off_t offset = static_cast<off_t>((count_ - 1) * BLOCK_SIZE_BYTES);
    if (::ftruncate(fd_, offset) != 0) return false;
    // Persist the shrink immediately (review round 5, P2): append_block
    // fsyncs only successes, so an unfsynced truncate left a refused frame
    // recoverable on disk after a power loss — the replay then throws on
    // the ledger refusal and the node cannot start until an operator
    // truncates the file by hand.
    ::fsync(fd_);
    --count_;
    last_error_ = "last append rolled back";
    return ensure_mapping(count_ * BLOCK_SIZE_BYTES);
}

const RawBlock* BlockStore::get_block(uint64_t height) const noexcept {
    if (height >= count_ || !mapped_) return nullptr;
    // O(1): pure pointer arithmetic, zero parsing.
    return reinterpret_cast<const RawBlock*>(
        static_cast<const uint8_t*>(mapped_) + height * BLOCK_SIZE_BYTES);
}

void BlockStore::tip_hash(uint8_t out[32]) const noexcept {
    if (count_ == 0 || !mapped_) {
        std::memset(out, 0, 32);
        return;
    }
    const RawBlock* tip = get_block(count_ - 1);
    // Full-frame commitment (external review round 5): the header alone does
    // not cover the tail's VM/PoGW metadata, so chain binding commits both.
    blockchain::hash_block(*tip, out);
}

bool BlockStore::stamp_gqc(uint64_t height, const uint8_t agg[32]) {
    if (height >= count_ || fd_ < 0) return false;
    // Sidecar certificate record (external review round 5): the 104-byte
    // tail has no free bytes — vm_state_root, vm_gas_used, pogw_nonce and
    // vm_bytecode occupy all of them — so stamping into the frame would
    // physically destroy consensus metadata of a certified block. The
    // aggregate is stored as a versioned record in <ledger>.gqc instead;
    // the frame itself never changes after append.
    const int gfd = ::open((path_ + ".gqc").c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (gfd < 0) return false;
    uint8_t rec[48];
    std::memcpy(rec, "VXGQCRT1", 8);
    const uint64_t h = height; // little-endian on LE hosts; read back via memcmp of height bytes
    std::memcpy(rec + 8, &h, 8);
    std::memcpy(rec + 16, agg, 32);
    // Full-write loop (review round 5, P2): a partial ::write of the 48-byte
    // record left corrupt bytes mid-file, which the reader can never heal
    // (it only truncates a torn TAIL) — every later restart then took the
    // fail-closed branch and silently reset the finality guard to 0. A
    // complete record (or none) is the only durable outcome.
    size_t written = 0;
    bool ok = true;
    while (written < sizeof(rec)) {
        const ssize_t n = ::write(gfd, rec + written, sizeof(rec) - written);
        if (n < 0 && errno == EINTR) continue;
        if (n <= 0) { ok = false; break; }
        written += static_cast<size_t>(n);
    }
    if (ok && ::fsync(gfd) != 0) ok = false;
    ::close(gfd);
    return ok;
}

bool BlockStore::gqc_stamp(uint64_t height, uint8_t out[32]) const {    if (height >= count_) return false;
    const int gfd = ::open((path_ + ".gqc").c_str(), O_RDONLY);
    if (gfd < 0) return false;
    bool found = false;
    bool corrupt = false;
    uint8_t rec[48];
    // Records are appended in certification order; the LAST record for a
    // height wins (re-certification after a re-stamp is legitimate). A
    // corrupt record fails the whole read closed — a partially trusted
    // certificate store is worse than none.
    while (::read(gfd, rec, sizeof(rec)) == static_cast<ssize_t>(sizeof(rec))) {
        if (std::memcmp(rec, "VXGQCRT1", 8) != 0) {
            corrupt = true;
            break;
        }
        uint64_t h = 0;
        std::memcpy(&h, rec + 8, 8);
        if (h == height) {
            std::memcpy(out, rec + 16, 32);
            found = true;
        }
    }
    ::close(gfd);
    return found && !corrupt;
}

uint64_t BlockStore::highest_gqc_stamp(bool& clean) const {
    clean = true;
    const int gfd = ::open((path_ + ".gqc").c_str(), O_RDONLY);
    if (gfd < 0) return 0; // no sidecar yet: nothing was ever cemented

    struct stat st{};
    if (::fstat(gfd, &st) < 0 || st.st_size == 0) {
        ::close(gfd);
        return 0;
    }
    std::vector<uint8_t> buf(static_cast<size_t>(st.st_size));
    const ssize_t got = ::read(gfd, buf.data(), buf.size());
    ::close(gfd);
    if (got != static_cast<ssize_t>(buf.size())) {
        clean = false;
        return 0;
    }

    // Records are fixed 48 bytes ("VXGQCRT1" + u64 height + 32 B aggregate).
    // The highest complete record wins; a bad magic anywhere is corruption
    // (fail closed: the caller must not trust the result); a torn TAIL of
    // fewer than 48 bytes is healed by truncation, like the undo journal.
    constexpr size_t kRec = 48;
    uint64_t highest = 0;
    size_t off = 0;
    while (off + kRec <= buf.size()) {
        if (std::memcmp(buf.data() + off, "VXGQCRT1", 8) != 0) {
            clean = false;
            return highest;
        }
        uint64_t h = 0;
        std::memcpy(&h, buf.data() + off + 8, 8);
        if (h > highest) highest = h;
        off += kRec;
    }
    if (off != buf.size()) {
        // Torn tail: heal by truncating to the last complete record.
        std::filesystem::resize_file(path_ + ".gqc", static_cast<uintmax_t>(off));
    }
    return highest;
}

} // namespace vx::storage
