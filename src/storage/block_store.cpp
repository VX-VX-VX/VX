#include "vx/storage/block_store.hpp"
#include "vx/blockchain/genesis.hpp"

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
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

/// Validates every frame in [start, end): magic + strictly increasing height.
/// Genesis (height 0) must be the very first frame exactly once.
static bool validate_region(const uint8_t* base, uint64_t from, uint64_t to) {
    for (uint64_t h = from; h < to; ++h) {
        BlockView v(std::span<const uint8_t, BLOCK_SIZE_BYTES>(
            base + h * BLOCK_SIZE_BYTES, BLOCK_SIZE_BYTES));
        if (!v.valid_magic()) return false;
        if (v.header().block_height != h) return false;
    }
    return true;
}

// ── BlockStore ───────────────────────────────────────────────────────────────

BlockStore::BlockStore(const std::string& path, const std::string& genesis_path) : path_(path) {
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
                                 "' contains frames with bad magic or non-sequential heights");
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
    BlockView v{std::span<const uint8_t, BLOCK_SIZE_BYTES>(frame)};
    const uint64_t expected_height = count_; // next after tip

    if (!v.valid_magic() || v.header().block_height != expected_height) return false;

    // Chain binding: prev_block_hash must equal the commitment of the current tip,
    // and the genesis prev-hash must be all zeros.
    uint8_t want_prev[32];
    if (count_ == 0) {
        std::memset(want_prev, 0, 32);
    } else {
        tip_hash(want_prev);
    }
    if (std::memcmp(want_prev, v.header().prev_block_hash, 32) != 0) return false;

    // Grow the file by one frame, then pwrite it atomically at the tip offset.
    const off_t offset = static_cast<off_t>(expected_height * BLOCK_SIZE_BYTES);
    if (::ftruncate(fd_, offset + BLOCK_SIZE_BYTES) != 0) return false;
    ssize_t wrote = ::pwrite(fd_, frame.data(), BLOCK_SIZE_BYTES, offset);
    if (wrote != static_cast<ssize_t>(BLOCK_SIZE_BYTES)) {
        ::ftruncate(fd_, offset); // roll back the torn frame
        return false;
    }
    ::fsync(fd_);

    ++count_;
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
    blockchain::hash_header(tip->header, out);
}

void BlockStore::stamp_gqc_into_tail(uint64_t height, const uint8_t agg[32]) {
    if (height >= count_ || !mapped_ || fd_ < 0) return;
    // The read-only mapping stays read-only — stamp through the fd instead.
    const off_t at = static_cast<off_t>(height * blockchain::BLOCK_SIZE_BYTES +
                                        blockchain::GQC_TAIL_OFFSET);
    if (::pwrite(fd_, agg, 32, at) != 32) return;
    ::fsync(fd_); // MS_SYNC equivalent: certified finality must survive reboot
}

} // namespace vx::storage
