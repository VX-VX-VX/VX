#include "vx/storage/block_store.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/net/swarm_node.hpp" // compute_wire_crc32c (GQC record integrity)

#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>

#include <cerrno>
#include <cstdio>
#include <cstring>
#include <ctime>
#include <filesystem>
#include <fstream>
#include <stdexcept>

namespace vx::storage {

using blockchain::BLOCK_SIZE_BYTES;
using blockchain::BlockFrame;
using blockchain::BlockView;
using blockchain::RawBlock;

// ── Helpers ──────────────────────────────────────────────────────────────────

static uint64_t file_size(int fd) {
    struct stat st{};
    if (fstat(fd, &st) != 0)
        return 0;
    return static_cast<uint64_t>(st.st_size);
}

/// Reads a whole file into a frame buffer. Returns false if size != 64 KB.
static bool load_frame(const std::string &path, BlockFrame &out) {
    std::ifstream f(path, std::ios::binary | std::ios::ate);
    if (!f)
        return false;
    if (f.tellg() != static_cast<std::streamoff>(BLOCK_SIZE_BYTES))
        return false;
    f.seekg(0);
    f.read(reinterpret_cast<char *>(out.data()), BLOCK_SIZE_BYTES);
    return f.gcount() == static_cast<std::streamsize>(BLOCK_SIZE_BYTES);
}

/// Validates every frame in [start, end): magic, strictly increasing height,
/// tx_count bound and a merkle commitment recomputed from the body — the
/// deterministic subset of blockchain::validate_block (BACKLOG 0.9). The
/// time-dependent checks (PoGW target, timestamp sanity) are meaningless
/// against historical blocks: a block was mined for its own moment, and
/// re-judging it against today's clock would make every old ledger fail.
/// Genesis (height 0) must be the very first frame exactly once.
static bool validate_region(const uint8_t *base, uint64_t from, uint64_t to) {
    for (uint64_t h = from; h < to; ++h) {
        const RawBlock *raw = reinterpret_cast<const RawBlock *>(base + h * BLOCK_SIZE_BYTES);
        if (raw->header.magic != blockchain::BLOCK_MAGIC)
            return false;
        if (raw->header.block_height != h)
            return false;
        if (raw->header.tx_count > blockchain::MAX_TX_PER_BLOCK)
            return false;
        if (!blockchain::verify_block_merkle(*raw))
            return false;
    }
    return true;
}

// ── Write-ahead intent marker (crash-consistent append) ─────────────────────
// Record layout (32 B, host-order memcpy like every other sidecar here):
//   [0..7)   magic "VXWALMK1"
//   [8..12)  state: 1 = INTENT, 2 = COMMITTED
//   [12..20) height the marker speaks about
//   [20..24) CRC32C of the full 65536-byte frame the writer intended
//   [24..28) reserved (zero)
//   [28..32) CRC32C over bytes [0..28)
// Exactly ONE record lives in the sidecar at a time; recovery truncates the
// file to zero once it has resolved the marker.
namespace {

constexpr size_t kWalRec = 32;
constexpr size_t kWalBody = 28; // everything covered by the record CRC
const uint8_t kWalMagic[8] = {'V', 'X', 'W', 'A', 'L', 'M', 'K', '1'};

uint32_t wal_body_crc(const uint8_t *rec) {
    return vx::net::compute_wire_crc32c(rec, kWalBody);
}

// noinline: GCC 15 mis-tracks the 65536-byte frame region when this is
// inlined into append_block (false-positive -Wstringop-overread claiming a
// size-4 region); keeping it out of line restores the obvious facts.
__attribute__((noinline)) uint32_t wal_frame_crc(const uint8_t *frame) {
    return vx::net::compute_wire_crc32c(frame, BLOCK_SIZE_BYTES);
}

/// Full-write loop (the review round 5 P2 lesson: a partial write must never
/// leave half a record in a file whose readers cannot heal anything but a
/// torn TAIL — here the record is always at offset 0, so even a torn record
/// is detectable by the record CRC, but the full loop keeps the writer's
/// contract uniform with the GQC sidecar).
// noinline: GCC 15 mis-tracks the 65536-byte frame region when this is
// inlined into append_block (false-positive -Wstringop-overread claiming a
// size-4 region); keeping the syscall wrappers out of line restores the
// obvious facts at both call sites.
__attribute__((noinline)) bool write_full(int fd, const uint8_t *buf, size_t len, off_t offset) {
    size_t done = 0;
    while (done < len) {
        const ssize_t n = ::pwrite(fd, buf + done, len - done, offset + static_cast<off_t>(done));
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0)
            return false;
        done += static_cast<size_t>(n);
    }
    return true;
}

void wal_fsync_dir_of(const std::string &path) {
    const size_t slash = path.find_last_of('/');
    const std::string dir = (slash == std::string::npos) ? std::string(".") : path.substr(0, slash);
    const int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        return;
    ::fsync(fd);
    ::close(fd);
}

} // namespace

bool BlockStore::wal_write_record_(uint32_t state, uint64_t height, uint32_t frame_crc) noexcept {
    if (wal_fd_ < 0)
        return false;
    uint8_t rec[kWalRec] = {};
    std::memcpy(rec, kWalMagic, 8);
    std::memcpy(rec + 8, &state, 4);
    std::memcpy(rec + 12, &height, 8);
    std::memcpy(rec + 20, &frame_crc, 4);
    const uint32_t crc = wal_body_crc(rec);
    std::memcpy(rec + kWalBody, &crc, 4);
    if (!write_full(wal_fd_, rec, sizeof(rec), 0))
        return false;
    return ::fsync(wal_fd_) == 0;
}

bool BlockStore::wal_clear_() noexcept {
    if (wal_fd_ < 0)
        return false;
    if (::ftruncate(wal_fd_, 0) != 0)
        return false;
    return ::fsync(wal_fd_) == 0;
}

// Resolves a leftover WAL marker BEFORE the ledger is validated/mmap'd.
// `size` is the ledger's byte size; the caller guarantees it is a whole
// number of frames (the byte-accurate torn-tail gate runs first). Returns
// the frame count to seed count_ with: the input count, except on the one
// healing path (torn tip frame under an INTENT marker), where it is the
// healed count.
uint64_t BlockStore::wal_recover_(uint64_t size) {
    const uint64_t frames = size / BLOCK_SIZE_BYTES;

    const int rfd = ::open((path_ + ".walmark").c_str(), O_RDONLY);
    if (rfd < 0)
        return frames; // no sidecar: nothing was ever in flight

    uint8_t rec[kWalRec];
    const ssize_t got = ::read(rfd, rec, sizeof(rec));
    ::close(rfd);
    // Corrupt / absent / torn sidecar record: fail-closed fallback — no
    // healing based on untrusted metadata, the pre-marker behavior (size
    // check + full validate_region, torn frame = refuse to start) governs.
    if (got != static_cast<ssize_t>(sizeof(rec)))
        return frames;
    if (std::memcmp(rec, kWalMagic, 8) != 0)
        return frames;
    uint32_t stored_crc = 0;
    std::memcpy(&stored_crc, rec + kWalBody, 4);
    if (stored_crc != wal_body_crc(rec))
        return frames;
    uint32_t state = 0;
    uint64_t h = 0;
    uint32_t frame_crc = 0;
    std::memcpy(&state, rec + 8, 4);
    std::memcpy(&h, rec + 12, 8);
    std::memcpy(&frame_crc, rec + 20, 4);
    if (state != WAL_STATE_INTENT && state != WAL_STATE_COMMITTED)
        return frames;

    // From here the marker is authentic: its verdicts about the TIP are
    // binding - but the marker only ever speaks about the append frontier
    // (one record, always the live tip), and LEGITIMATE ledger truncations
    // below it exist (reorg heal via truncate_store_to, operator surgery):
    // the crash-torture gate caught the first draft failing those reopens
    // closed. The surviving chain is always re-judged by validate_region,
    // so the marker's only real authority is the tip frame.
    if (h >= frames || h + 1 < frames) {
        // h >= frames: the named frame is not on disk - the ledger was
        // truncated after the marker was written (reorg heal, rollback by
        // hand, operator). h + 1 < frames: a stale record naming history -
        // later appends always overwrite the single record, so a marker
        // this old means its COMMITTED/INTENT flips were lost; the frame
        // it names has long been validated by earlier opens. Neither state
        // authorizes healing: clear the marker and let validate_region
        // judge the ledger.
        wal_clear_();
        return frames;
    }
    // h == frames - 1: the marked frame is the tip - is it whole?
    std::vector<uint8_t> frame(BLOCK_SIZE_BYTES);
    const ssize_t fr =
        ::pread(fd_, frame.data(), BLOCK_SIZE_BYTES, static_cast<off_t>(h * BLOCK_SIZE_BYTES));
    if (fr != static_cast<ssize_t>(BLOCK_SIZE_BYTES)) {
        throw std::runtime_error("BlockStore: cannot read the WAL-marked frame at height " +
                                 std::to_string(h));
    }
    if (wal_frame_crc(frame.data()) == frame_crc) {
        // The frame is whole: either the crash hit between the ledger fsync
        // and the COMMITTED fsync (INTENT), or everything completed and only
        // the marker fsync was lost. The frame stays either way.
        wal_clear_();
        return frames;
    }
    if (state == WAL_STATE_COMMITTED) {
        // The marker says this frame was fsynced complete; the disk says
        // otherwise. That is corruption (bit rot, tampering), not a torn
        // write - silently truncating a durable block would fabricate a
        // shorter chain. Fail closed.
        throw std::runtime_error("BlockStore: WAL marker COMMITTED at height " + std::to_string(h) +
                                 " but the on-disk frame fails its CRC — "
                                 "corrupted ledger, refusing to start");
    }
    // INTENT + CRC mismatch: the classic torn append (crash between the
    // ftruncate and the ledger fsync). Heal by truncating the partial frame
    // and report the healed count - only here does recovery own the count.
    if (::ftruncate(fd_, static_cast<off_t>(h * BLOCK_SIZE_BYTES)) != 0) {
        throw std::runtime_error("BlockStore: WAL healing truncate failed: " +
                                 std::string(std::strerror(errno)));
    }
    ::fsync(fd_);
    wal_clear_();
    return h;
}

// ── BlockStore ───────────────────────────────────────────────────────────────

BlockStore::BlockStore(const std::string &path, const std::string &genesis_path,
                       uint64_t required_pogw_bits, const consensus::PogwRetargetParams &retarget)
    : path_(path), retarget_(retarget) {
    // The ctor parameter is the ASERT anchor/genesis difficulty; the
    // retarget parameters supply the half-life. The anchor from the caller
    // wins, so tests can keep passing a low seal strength while pinning a
    // fast test half-life alongside it.
    // Math-audit F10: this override is deliberate — but it means the
    // retarget_.anchor_bits field of a passed struct is IGNORED. Production
    // must pass consistent values (POGW_MAINNET_RETARGET's anchor equals
    // the default seal strength), and the fingerprint pin covers the
    // production pair. A caller passing a disagreeing custom struct gets
    // the ctor anchor, never a mixed curve.
    retarget_.anchor_bits = required_pogw_bits;
    fd_ = ::open(path.c_str(), O_RDWR | O_CREAT, 0644);
    if (fd_ < 0) {
        throw std::runtime_error("BlockStore: cannot open '" + path + "': " + std::strerror(errno));
    }

    // WAL marker sidecar (crash-consistent append): opened before recovery so
    // the heal path can clear the resolved record. The directory is fsynced
    // once here so a freshly created sidecar's directory entry is durable -
    // without it, a crash could lose BOTH the marker and the healing hint
    // at once (the pre-marker fail-closed behavior would then govern a torn
    // frame: refuse to start until an operator truncates by hand).
    wal_fd_ = ::open((path + ".walmark").c_str(), O_RDWR | O_CREAT, 0644);
    if (wal_fd_ < 0) {
        const int werrno = errno;
        ::close(fd_);
        fd_ = -1;
        ::close(wal_fd_);
        wal_fd_ = -1;
        throw std::runtime_error("BlockStore: cannot open '" + path +
                                 ".walmark': " + std::strerror(werrno));
    }
    wal_fsync_dir_of(path + ".walmark");

    // Torn-tail gate FIRST, byte-accurate (pre-marker semantics preserved):
    // our writer never leaves a non-multiple size (ftruncate extends whole
    // frames, and the WAL marker covers the torn-frame window), so a
    // non-multiple size is external corruption - refuse exactly as before,
    // BEFORE any marker-based healing could run.
    uint64_t size = file_size(fd_);
    if (size % BLOCK_SIZE_BYTES != 0) {
        ::close(wal_fd_);
        wal_fd_ = -1;
        ::close(fd_);
        fd_ = -1;
        throw std::runtime_error("BlockStore: '" + path + "' size " + std::to_string(size) +
                                 " is not a multiple of 65536 — corrupted ledger");
    }

    // Recovery may heal the ledger (truncate a torn frame) or throw on the
    // fail-closed paths - on a throw both descriptors must be released
    // before the exception leaves the constructor (no destructor runs).
    try {
        size = wal_recover_(size) * BLOCK_SIZE_BYTES;
    } catch (...) {
        ::close(wal_fd_);
        wal_fd_ = -1;
        ::close(fd_);
        fd_ = -1;
        throw;
    }

    // Auto-init empty ledger from genesis.bin (deterministically regenerated
    // in-process when the file is absent — never shipped, never copied).
    if (size == 0) {
        BlockFrame genesis{};
        if (!load_frame(genesis_path, genesis)) {
            try {
                blockchain::write_genesis_file(genesis_path);
            } catch (const std::exception &e) {
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
            throw std::runtime_error("BlockStore: failed to seed genesis: " +
                                     std::string(std::strerror(errno)));
        }
        ::fsync(fd_);
        size = BLOCK_SIZE_BYTES;
    }

    // Reject a torn tail (file size not a multiple of the frame)
    if (size % BLOCK_SIZE_BYTES != 0) {
        ::close(fd_);
        fd_ = -1;
        ::close(wal_fd_);
        wal_fd_ = -1;
        throw std::runtime_error("BlockStore: '" + path + "' size " + std::to_string(size) +
                                 " is not a multiple of 65536 — corrupted ledger");
    }

    count_ = size / BLOCK_SIZE_BYTES;
    if (!ensure_mapping(size)) {
        ::close(fd_);
        fd_ = -1;
        ::close(wal_fd_);
        wal_fd_ = -1;
        throw std::runtime_error("BlockStore: mmap of '" + path +
                                 "' failed: " + std::strerror(errno));
    }

    if (!validate_region(static_cast<const uint8_t *>(mapped_), 0, count_)) {
        ::close(fd_);
        fd_ = -1;
        ::close(wal_fd_);
        wal_fd_ = -1;
        throw std::runtime_error("BlockStore: ledger '" + path +
                                 "' contains frames with bad magic, non-sequential heights, "
                                 "oversized tx_count or a broken merkle commitment");
    }
}

BlockStore::~BlockStore() noexcept {
    if (mapped_)
        ::munmap(mapped_, mapped_bytes_);
    if (wal_fd_ >= 0)
        ::close(wal_fd_);
    if (fd_ >= 0)
        ::close(fd_);
}

/// Extends (or creates) the read-only shared mapping so it covers new_bytes.
/// Uses mremap so already-faulted pages are preserved — amortized O(1).
bool BlockStore::ensure_mapping(uint64_t new_bytes) {
    if (new_bytes == 0)
        return true;
    if (mapped_bytes_ >= new_bytes && mapped_)
        return true;

    if (mapped_) {
        void *moved = ::mremap(mapped_, mapped_bytes_, new_bytes, MREMAP_MAYMOVE);
        if (moved != MAP_FAILED) {
            mapped_ = moved;
            mapped_bytes_ = new_bytes;
            return true;
        }
        ::munmap(mapped_, mapped_bytes_);
        mapped_ = nullptr;
        mapped_bytes_ = 0;
    }

    void *p = ::mmap(nullptr, new_bytes, PROT_READ, MAP_SHARED, fd_, 0);
    if (p == MAP_FAILED)
        return false;
    mapped_ = p;
    mapped_bytes_ = new_bytes;
    return true;
}

bool BlockStore::append_block(const BlockFrame &frame) {
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
        const RawBlock *tip = get_block(count_ - 1);
        ctx.prev_timestamp = tip ? tip->header.timestamp : 0;
    }
    ctx.now_unix = static_cast<uint64_t>(std::time(nullptr));
    // ASERT retarget (BACKLOG 0.9 remainder): the gate demands the height's
    // own difficulty, recomputed from the genesis anchor -- never read from
    // the frame, never stored, identical on every node with the same anchor.
    ctx.difficulty_bits = pogw_bits_for_height(expected_height);
    if (!blockchain::validate_block(*reinterpret_cast<const blockchain::RawBlock *>(frame.data()),
                                    ctx, &last_error_)) {
        return false;
    }

    // Grow the file by one frame, then pwrite it atomically at the tip offset.
    // The WAL marker makes the append crash-consistent (see the class comment
    // on wal_recover_): INTENT (height + frame CRC) is durable BEFORE the
    // ledger is touched, so recovery can always tell a torn append from a
    // complete one - including the case the size check alone cannot see,
    // where the ftruncate already extended the file but the frame bytes never
    // finished landing. Cost: 3 fsyncs per append instead of 1 (marker fsync,
    // ledger fsync, COMMITTED fsync) - the honest price of "a reported
    // success survived a power cut" for every byte of the frame, not just
    // the happy path.
    const uint32_t frame_crc = wal_frame_crc(frame.data());
    if (!wal_write_record_(WAL_STATE_INTENT, expected_height, frame_crc)) {
        last_error_ = "WAL intent record failed";
        return false;
    }
    const off_t offset = static_cast<off_t>(expected_height * BLOCK_SIZE_BYTES);
    if (::ftruncate(fd_, offset + BLOCK_SIZE_BYTES) != 0) {
        wal_clear_(); // best effort; recovery would heal the same state anyway
        return false;
    }
    const bool frame_landed = write_full(fd_, frame.data(), BLOCK_SIZE_BYTES, offset);
    if (!frame_landed) {
        ::ftruncate(fd_, offset); // roll back the torn frame
        wal_clear_();
        return false;
    }
    // Durability is part of the append contract: a reported success must
    // mean the frame survived a power cut. An fsync error is treated like
    // any other failed write - the frame is rolled back and the caller
    // sees a rejection, never a phantom acknowledgment.
    if (::fsync(fd_) != 0) {
        ::ftruncate(fd_, offset);
        wal_clear_();
        return false;
    }

    ++count_;
    if (!ensure_mapping(count_ * BLOCK_SIZE_BYTES))
        return false;
    // The frame is durable and mapped: flip the marker to COMMITTED. A
    // failure here is deliberately NOT an append failure - the marker stays
    // INTENT and recovery keeps a CRC-matching frame, so the ledger is
    // already in its final state either way.
    wal_write_record_(WAL_STATE_COMMITTED, expected_height, frame_crc);
    return true;
}

bool BlockStore::rollback_last_append() noexcept {
    if (count_ <= 1)
        return false; // the genesis frame is never rolled back
    const off_t offset = static_cast<off_t>((count_ - 1) * BLOCK_SIZE_BYTES);
    if (::ftruncate(fd_, offset) != 0)
        return false;
    // Persist the shrink immediately (review round 5, P2): append_block
    // fsyncs only successes, so an unfsynced truncate left a refused frame
    // recoverable on disk after a power loss — the replay then throws on
    // the ledger refusal and the node cannot start until an operator
    // truncates the file by hand.
    ::fsync(fd_);
    --count_;
    // The removed frame may still be named by a COMMITTED marker (the append
    // being rolled back completed normally); a leftover marker would fail the
    // NEXT open ("marker height beyond the ledger"), so clear it.
    wal_clear_();
    last_error_ = "last append rolled back";
    return ensure_mapping(count_ * BLOCK_SIZE_BYTES);
}

const RawBlock *BlockStore::get_block(uint64_t height) const noexcept {
    if (height >= count_ || !mapped_)
        return nullptr;
    // O(1): pure pointer arithmetic, zero parsing.
    return reinterpret_cast<const RawBlock *>(static_cast<const uint8_t *>(mapped_) +
                                              height * BLOCK_SIZE_BYTES);
}

void BlockStore::tip_hash(uint8_t out[32]) const noexcept {
    if (count_ == 0 || !mapped_) {
        std::memset(out, 0, 32);
        return;
    }
    const RawBlock *tip = get_block(count_ - 1);
    // Full-frame commitment (external review round 5): the header alone does
    // not cover the tail's VM/PoGW metadata, so chain binding commits both.
    blockchain::hash_block(*tip, out);
}

// ── GQC sidecar record integrity (crash-torture finding 1, 2026-11-04) ──────
// The v1 record ("VXGQCRT1", 48 B) carried no integrity over the height and
// aggregate bytes: a flipped height byte read back clean and INFLATED the
// finality guard, a flipped aggregate byte was served as a valid certificate.
// The v2 record ("VXGQCRT2", 52 B) appends a CRC32C over height+aggregate.
// Legacy v1 files are migrated once on first open (the rewrite trusts the
// existing content a single time — documented bootstrap); afterwards any
// checksum mismatch fails the whole read closed, like a bad magic tag.
namespace {

constexpr uint8_t kGqcRec = 52;
constexpr size_t kGqcBody = 48; // tag(8) + height(8) + aggregate(32)
constexpr size_t kGqcCrcOff = 48;

uint32_t gqc_body_crc(const uint8_t *rec) {
    return vx::net::compute_wire_crc32c(rec + 8, kGqcBody - 8);
}

void gqc_fsync_file(const std::string &path) {
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0)
        return;
    ::fsync(fd);
    ::close(fd);
}

void gqc_fsync_dir_of(const std::string &path) {
    const size_t slash = path.find_last_of('/');
    const std::string dir = (slash == std::string::npos) ? std::string(".") : path.substr(0, slash);
    const int fd = ::open(dir.c_str(), O_RDONLY | O_DIRECTORY);
    if (fd < 0)
        return;
    ::fsync(fd);
    ::close(fd);
}

bool gqc_migrate_rt1_locked(const std::string &path, const std::vector<uint8_t> &buf,
                            uint64_t chain_height) {
    // Security review F1 (2026-11-04): the migration may trust only what a
    // legitimate v1 writer could have produced. stamp_gqc has always
    // enforced height < chain_height, and the v1 writer only ever wrote the
    // RT1 tag — any 48-byte block that violates either is not a legacy
    // record but corruption (or a crafted file), and blessing it with a
    // fresh CRC would fabricate an inflated finality guard. Fail closed
    // instead: no rewrite, the callers report an untrusted sidecar.
    const size_t records = buf.size() / 48;
    for (size_t r = 0; r < records; ++r) {
        const uint8_t *blk = buf.data() + r * 48;
        if (std::memcmp(blk, "VXGQCRT1", 8) != 0)
            return false;
        uint64_t h = 0;
        std::memcpy(&h, blk + 8, 8);
        if (h >= chain_height)
            return false;
    }
    // Rewrite every 48-byte v1 record as a 52-byte v2 record with a CRC.
    // The file is rewritten atomically enough for a sidecar: write the new
    // content to a temp file, fsync, rename over the original.
    std::vector<uint8_t> out;
    out.reserve(records * kGqcRec);
    for (size_t r = 0; r < records; ++r) {
        const uint8_t *blk = buf.data() + r * 48;
        uint8_t rec[kGqcRec] = {};
        std::memcpy(rec, "VXGQCRT2", 8);
        std::memcpy(rec + 8, blk + 8, 40); // height + aggregate
        const uint32_t crc = gqc_body_crc(rec);
        std::memcpy(rec + kGqcCrcOff, &crc, 4);
        out.insert(out.end(), rec, rec + kGqcRec);
    }
    const std::string tmp = path + ".gqc.mig";
    const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0)
        return false;
    size_t written = 0;
    while (written < out.size()) {
        const ssize_t n = ::write(fd, out.data() + written, out.size() - written);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            ::close(fd);
            return false;
        }
        written += static_cast<size_t>(n);
    }
    if (::fsync(fd) != 0) {
        ::close(fd);
        return false;
    }
    ::close(fd);
    std::error_code ec;
    std::filesystem::rename(tmp, path + ".gqc", ec);
    if (ec)
        return false;
    // Durability (review F7): the rename itself must survive a power cut,
    // or the next boot re-runs an idempotent migration on the still-v1 file.
    gqc_fsync_dir_of(path + ".gqc");
    return true;
}

} // namespace

bool BlockStore::gqc_ensure_integrity() const {
    const int gfd = ::open((path_ + ".gqc").c_str(), O_RDONLY);
    if (gfd < 0)
        return true; // no sidecar: nothing to migrate
    struct stat st{};
    if (::fstat(gfd, &st) < 0 || st.st_size == 0) {
        ::close(gfd);
        return true;
    }
    std::vector<uint8_t> buf(static_cast<size_t>(st.st_size));
    const ssize_t got = ::read(gfd, buf.data(), buf.size());
    ::close(gfd);
    if (got != static_cast<ssize_t>(buf.size()))
        return false;

    bool has_rt1 = false;
    bool has_rt2 = false;
    bool has_unknown = false;
    size_t off = 0;
    while (off + 48 <= buf.size()) {
        if (std::memcmp(buf.data() + off, "VXGQCRT1", 8) == 0)
            has_rt1 = true;
        else if (std::memcmp(buf.data() + off, "VXGQCRT2", 8) == 0)
            has_rt2 = true;
        else
            has_unknown = true;
        off += 48;
    }
    if (!has_rt1)
        return true; // already v2 (validated per-record by the callers)
    if (has_rt2) {
        // Mixed versions can never be a legitimately written file (review
        // F3): it means v1 records appeared after a v2 migration — a
        // rolling-upgrade or two-writers-on-one-dir accident. Fail closed
        // loudly; only an operator can resolve it.
        std::fprintf(stderr,
                     "[VX][GQC] %s.gqc: mixed RT1/RT2 records — refusing to "
                     "read or migrate; remove the sidecar or restore a "
                     "consistent version\n",
                     path_.c_str());
        return false;
    }
    if (has_unknown) {
        // v1-classified file with a block that is neither RT1 nor RT2: not
        // a record the v1 writer could have produced (review F1). Migration
        // must not bless it — fail closed like every other reader path.
        return false;
    }
    if (has_rt2) {
        // Mixed versions can never be a legitimately written file (review
        // F3): it means v1 records appeared after a v2 migration — a
        // rolling-upgrade or two-writers-on-one-dir accident. Fail closed
        // loudly; only an operator can resolve it.
        std::fprintf(stderr,
                     "[VX][GQC] %s.gqc: mixed RT1/RT2 records — refusing to "
                     "read or migrate; remove the sidecar or restore a "
                     "consistent version\n",
                     path_.c_str());
        return false;
    }
    // All-v1 file: drop a torn tail to the record boundary, then rewrite.
    if (buf.size() % 48 != 0) {
        std::error_code ec;
        std::filesystem::resize_file(path_ + ".gqc", static_cast<uintmax_t>(off), ec);
        if (ec)
            return false;
        gqc_fsync_file(path_ + ".gqc");
    }
    return gqc_migrate_rt1_locked(path_, buf, count_);
}

bool BlockStore::stamp_gqc(uint64_t height, const uint8_t agg[32]) {
    if (height >= count_ || fd_ < 0)
        return false;
    // The sidecar carries integrity metadata, so stamping must never mix
    // record generations on one file (review F2/F3): migrate any legacy
    // v1 content first, then refuse to append to anything that is not a
    // clean 52-stride v2 file (a torn tail is healed here too — healing
    // can only lower what the readers trust, never inflate it).
    if (!gqc_ensure_integrity())
        return false;
    {
        std::error_code ec;
        const uintmax_t sz = std::filesystem::file_size(path_ + ".gqc", ec);
        if (!ec && sz % kGqcRec != 0) {
            std::error_code tec;
            std::filesystem::resize_file(path_ + ".gqc", sz - (sz % kGqcRec), tec);
            if (tec)
                return false;
            gqc_fsync_file(path_ + ".gqc");
        }
    }
    // Sidecar certificate record (external review round 5): the 104-byte
    // tail has no free bytes — vm_state_root, vm_gas_used, pogw_nonce and
    // vm_bytecode occupy all of them — so stamping into the frame would
    // physically destroy consensus metadata of a certified block. The
    // aggregate is stored as a versioned record in <ledger>.gqc instead;
    // the frame itself never changes after append.
    const int gfd = ::open((path_ + ".gqc").c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (gfd < 0)
        return false;
    uint8_t rec[kGqcRec] = {};
    std::memcpy(rec, "VXGQCRT2", 8);
    const uint64_t h = height; // host-order memcpy; read back via memcpy + numeric compare
    std::memcpy(rec + 8, &h, 8);
    std::memcpy(rec + 16, agg, 32);
    const uint32_t crc = gqc_body_crc(rec);
    std::memcpy(rec + kGqcCrcOff, &crc, 4);
    // Full-write loop (review round 5, P2): a partial ::write of the record
    // left corrupt bytes mid-file, which the reader can never heal
    // (it only truncates a torn TAIL) — every later restart then took the
    // fail-closed branch and silently reset the finality guard to 0. A
    // complete record (or none) is the only durable outcome.
    size_t written = 0;
    bool ok = true;
    while (written < sizeof(rec)) {
        const ssize_t n = ::write(gfd, rec + written, sizeof(rec) - written);
        if (n < 0 && errno == EINTR)
            continue;
        if (n <= 0) {
            ok = false;
            break;
        }
        written += static_cast<size_t>(n);
    }
    if (ok && ::fsync(gfd) != 0)
        ok = false;
    ::close(gfd);
    return ok;
}

bool BlockStore::gqc_stamp(uint64_t height, uint8_t out[32]) const {
    if (height >= count_)
        return false;
    if (!gqc_ensure_integrity())
        return false;
    const int gfd = ::open((path_ + ".gqc").c_str(), O_RDONLY);
    if (gfd < 0)
        return false;
    bool found = false;
    bool corrupt = false;
    uint8_t rec[kGqcRec];
    // Records are appended in certification order; the LAST record for a
    // height wins (re-certification after a re-stamp is legitimate). A
    // corrupt record fails the whole read closed — a partially trusted
    // certificate store is worse than none.
    while (::read(gfd, rec, sizeof(rec)) == static_cast<ssize_t>(sizeof(rec))) {
        if (std::memcmp(rec, "VXGQCRT2", 8) != 0) {
            corrupt = true;
            break;
        }
        uint32_t crc = 0;
        std::memcpy(&crc, rec + kGqcCrcOff, 4);
        if (crc != gqc_body_crc(rec)) {
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

uint64_t BlockStore::highest_gqc_stamp(bool &clean) const {
    clean = true;
    if (!gqc_ensure_integrity()) {
        clean = false;
        return 0;
    }
    const int gfd = ::open((path_ + ".gqc").c_str(), O_RDONLY);
    if (gfd < 0)
        return 0; // no sidecar yet: nothing was ever cemented

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

    // Records are fixed 52 bytes ("VXGQCRT2" + u64 height + 32 B aggregate
    // + CRC32C over height+aggregate). The highest complete record wins;
    // a bad magic, a checksum mismatch, or a torn tail that does not land
    // on a record boundary is corruption (fail closed: the caller must not
    // trust the result); a torn TAIL is healed by truncation, like the
    // undo journal.
    constexpr size_t kRec = kGqcRec;
    uint64_t highest = 0;
    size_t off = 0;
    while (off + kRec <= buf.size()) {
        const uint8_t *rec = buf.data() + off;
        if (std::memcmp(rec, "VXGQCRT2", 8) != 0) {
            clean = false;
            return highest;
        }
        uint32_t crc = 0;
        std::memcpy(&crc, rec + kGqcCrcOff, 4);
        if (crc != gqc_body_crc(rec)) {
            clean = false;
            return highest;
        }
        uint64_t h = 0;
        std::memcpy(&h, rec + 8, 8);
        if (h > highest)
            highest = h;
        off += kRec;
    }
    if (off != buf.size()) {
        // Torn tail: heal by truncating to the last complete record.
        std::filesystem::resize_file(path_ + ".gqc", static_cast<uintmax_t>(off));
        // Durability (review F7): an unfsynced heal can resurrect after a
        // power cut behind records appended later, shifting the record
        // grid — sync the truncation before returning.
        gqc_fsync_file(path_ + ".gqc");
    }
    return highest;
}

} // namespace vx::storage
