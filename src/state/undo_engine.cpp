#include "vx/state/undo_engine.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/storage/block_store.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <iostream>
#include <unordered_map>
#include <vector>

namespace vx::state {

namespace {

// ── Journal wire format (BACKLOG 0.11: no raw pointers on disk) ─────────────
// The external round-4 review found the journal writing `sizeof(UndoRecord)`
// — serializing std::string/vector/time_point HEAP POINTERS, so any replay
// dereferenced freed or garbage memory. The journal is now a versioned,
// fixed-width byte format: every field is written byte-wise, the reader
// refuses unknown versions, and a torn or malformed file is never replayed
// into memory as pointers.
//
//   header:  magic "VXUNDOJL" (8 B) + u32 LE format version
//   record:  u64 height | i64 timestamp_ns | 32 B prev_tip_hash |
//            16 B prev_supply (lo, hi) | u64 prev_accounts_count |
//            u64 tx_count | tx_count x (42 B sender | 42 B receiver |
//                                        16 B amount | 16 B fee |
//                                        4 B prev_sender_nonce) |
//            u64 created_count | created_count x 42 B address
//
// Version 2 (BACKLOG 0.12) added prev_sender_nonce to every undo
// transaction and the created-address list, so a rollback restores sender
// nonces and the tracked-account state alongside balances.
// All integers are little-endian. Loss of the journal never endangers
// consensus (it only costs reorg capability): a file with a wrong
// magic/version or a malformed record is discarded and rebuilt from live
// block application; only a TORN TAIL (a crash mid-append) is healed by
// truncating to the last complete record.

constexpr char kUndoMagic[8] = {'V', 'X', 'U', 'N', 'D', 'O', 'J', 'L'};
constexpr uint32_t kUndoVersion = 2;
constexpr size_t kUndoHeaderSize = 12;
constexpr size_t kUndoTxSize = 42 + 42 + 16 + 16 + 4;
// A zero-tx record: the smallest possible complete record (height, time,
// tip, supply, accounts count, zero tx count, zero created addresses).
// Fewer bytes than this at the end of a file cannot start a valid record —
// that is a torn tail, not corruption.
constexpr size_t kMinRecordSize = 88;
// A safety cap on replay input, not a real limit: 64 MiB covers roughly
// 400k single-tx records; larger files are treated as malformed.
constexpr size_t kUndoFileCap = 64ULL * 1024 * 1024;

// ── Displaced-frame side file (BACKLOG 0.12) ────────────────────────────────
// When a rollback displaces fork blocks, their 64 KiB frames are preserved
// in a second versioned byte file so the reorg stays replayable in both
// directions:
//
//   header:  magic "VXDISPLC" (8 B) + u32 LE format version
//   record:  u64 height | u32 frame_len | frame_len frame bytes
//
constexpr char kDisplacedMagic[8] = {'V', 'X', 'D', 'I', 'S', 'P', 'L', 'C'};
constexpr uint32_t kDisplacedVersion = 1;
constexpr size_t kDisplacedHeaderSize = 12;
constexpr size_t kDisplacedRecordOverhead = 8 + 4;
// Same policy as the journal: a safety cap on replay input, not a real
// limit — 64 MiB holds about a thousand displaced frames. Appending past
// the cap simply stops preserving (reorg capability, never consensus).
constexpr size_t kDisplacedFileCap = 64ULL * 1024 * 1024;

void put_u32(std::vector<uint8_t>& out, uint32_t v) {
    for (int i = 0; i < 4; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
void put_u64(std::vector<uint8_t>& out, uint64_t v) {
    for (int i = 0; i < 8; ++i) out.push_back(static_cast<uint8_t>(v >> (8 * i)));
}
void put_u128(std::vector<uint8_t>& out, const U128& v) {
    put_u64(out, v.lo);
    put_u64(out, v.hi);
}
void put_bytes(std::vector<uint8_t>& out, const uint8_t* p, size_t n) {
    out.insert(out.end(), p, p + n);
}

size_t record_bytes(const UndoRecord& r) {
    return 8 + 8 + 32 + 16 + 8 + 8 + r.transactions.size() * kUndoTxSize +
           8 + r.created_addresses.size() * 42;
}
void serialize_record(const UndoRecord& r, std::vector<uint8_t>& out) {
    put_u64(out, r.height);
    put_u64(out, static_cast<uint64_t>(
                     std::chrono::duration_cast<std::chrono::nanoseconds>(
                         r.timestamp.time_since_epoch()).count()));
    // Fixed 32-byte field: pad a short hash with zeros, never write the
    // std::string's heap internals.
    uint8_t tip[32] = {0};
    std::memcpy(tip, r.prev_tip_hash.data(),
                std::min(r.prev_tip_hash.size(), size_t(32)));
    put_bytes(out, tip, 32);
    put_u128(out, r.prev_supply);
    put_u64(out, r.prev_accounts_count);
    put_u64(out, r.transactions.size());
    for (const auto& tx : r.transactions) {
        uint8_t addr[42] = {0};
        std::memcpy(addr, tx.sender.data(), std::min(tx.sender.size(), size_t(42)));
        put_bytes(out, addr, 42);
        std::memset(addr, 0, sizeof(addr));
        std::memcpy(addr, tx.receiver.data(), std::min(tx.receiver.size(), size_t(42)));
        put_bytes(out, addr, 42);
        put_u128(out, tx.amount);
        put_u128(out, tx.fee);
        put_u32(out, tx.prev_sender_nonce);
    }
    put_u64(out, r.created_addresses.size());
    for (const auto& created : r.created_addresses) {
        uint8_t addr[42] = {0};
        std::memcpy(addr, created.data(), std::min(created.size(), size_t(42)));
        put_bytes(out, addr, 42);
    }
}

struct ByteReader {
    const uint8_t* p;
    const uint8_t* end;
    bool ok = true;

    bool take(size_t n, const uint8_t** out) {
        if (!ok || static_cast<size_t>(end - p) < n) {
            ok = false;
            return false;
        }
        *out = p;
        p += n;
        return true;
    }
    uint32_t get_u32() {
        const uint8_t* b;
        if (!take(4, &b)) return 0;
        return uint32_t(b[0]) | (uint32_t(b[1]) << 8) |
               (uint32_t(b[2]) << 16) | (uint32_t(b[3]) << 24);
    }
    uint64_t get_u64() {
        const uint8_t* b;
        if (!take(8, &b)) return 0;
        uint64_t v = 0;
        for (int i = 7; i >= 0; --i) v = (v << 8) | b[i];
        return v;
    }
    U128 get_u128() {
        const uint64_t lo = get_u64();
        const uint64_t hi = get_u64();
        return U128(lo, hi);
    }
    void get_bytes(uint8_t* dst, size_t n) {
        const uint8_t* b;
        if (!take(n, &b)) return;
        std::memcpy(dst, b, n);
    }
};

bool parse_record(ByteReader& r, UndoRecord& out) {
    out = UndoRecord{};
    out.height = r.get_u64();
    const uint64_t ns = r.get_u64();
    out.timestamp = std::chrono::system_clock::time_point(
        std::chrono::duration_cast<std::chrono::system_clock::duration>(
            std::chrono::nanoseconds(static_cast<int64_t>(ns))));
    uint8_t tip[32] = {0};
    r.get_bytes(tip, 32);
    out.prev_tip_hash.assign(reinterpret_cast<const char*>(tip), 32);
    out.prev_supply = r.get_u128();
    out.prev_accounts_count = r.get_u64();
    const uint64_t tx_count = r.get_u64();
    if (!r.ok) return false;
    if (tx_count > blockchain::MAX_TX_PER_BLOCK) return false; // malformed
    out.transactions.reserve(tx_count);
    for (uint64_t i = 0; i < tx_count; ++i) {
        UndoRecord::UndoTransaction tx;
        uint8_t addr[42] = {0};
        r.get_bytes(addr, 42);
        tx.sender.assign(reinterpret_cast<const char*>(addr), 42);
        std::memset(addr, 0, sizeof(addr));
        r.get_bytes(addr, 42);
        tx.receiver.assign(reinterpret_cast<const char*>(addr), 42);
        tx.amount = r.get_u128();
        tx.fee = r.get_u128();
        tx.prev_sender_nonce = r.get_u32();
        if (!r.ok) return false;
        out.transactions.push_back(std::move(tx));
    }
    const uint64_t created_count = r.get_u64();
    if (!r.ok) return false;
    // The block cannot create more addresses than it has txs (senders and
    // receivers together, so twice the tx count is the honest bound).
    if (created_count > 2 * blockchain::MAX_TX_PER_BLOCK) return false; // malformed
    out.created_addresses.reserve(created_count);
    for (uint64_t i = 0; i < created_count; ++i) {
        uint8_t addr[42] = {0};
        r.get_bytes(addr, 42);
        if (!r.ok) return false;
        out.created_addresses.emplace_back(reinterpret_cast<const char*>(addr), 42);
    }
    return r.ok;
}

bool write_all(int fd, const uint8_t* data, size_t len) {
    size_t off = 0;
    while (off < len) {
        const ssize_t n = ::write(fd, data + off, len - off);
        if (n <= 0) return false;
        off += static_cast<size_t>(n);
    }
    return true;
}

bool write_header(int fd) {
    std::vector<uint8_t> header;
    header.reserve(kUndoHeaderSize);
    put_bytes(header, reinterpret_cast<const uint8_t*>(kUndoMagic), 8);
    put_u32(header, kUndoVersion);
    return write_all(fd, header.data(), header.size());
}

} // namespace

UndoEngine::UndoEngine(const std::string& data_dir, storage::BlockStore& store, LedgerState& ledger)
    : data_dir_(data_dir), store_(&store), ledger_(ledger) {
    // Ensure undo directory exists
    std::filesystem::path undo_path = std::filesystem::path(data_dir_) / "undo";
    std::filesystem::create_directories(undo_path);
    undo_file_ = undo_path / "undo.vxl";
    displaced_file_ = undo_path / "displaced.vxd";
    load_latest_undo_journal();
    restore_finalized_checkpoint();
}

UndoEngine::~UndoEngine() {
    // Auto-commit current state on destruction
    commit_undo_point();
}

void UndoEngine::apply_block(const blockchain::BlockView& block) {
    // Record state changes before applying block
    UndoRecord record;
    record.height = block.header().block_height;
    record.timestamp = std::chrono::system_clock::now();
    // The pre-state tip is the block's own prev_hash — true no matter
    // whether the caller journaled before or after the store append
    // (BACKLOG 0.12: the journal must not depend on call ordering).
    const uint8_t* prev_hash = block.header().prev_block_hash;
    record.prev_tip_hash.assign(reinterpret_cast<const char*>(prev_hash), 32);
    record.prev_supply = ledger_.total_supply();
    record.prev_accounts_count = ledger_.accounts().size();

    // Record transaction effects FROM THE FRAME BEING APPLIED (BACKLOG
    // 0.12). The resync path journals before the store append, so reading
    // the store at this height used to capture the DISPLACED block's
    // transactions — the rollback then reversed effects that never
    // happened on this fork.
    if (block.header().tx_count > blockchain::MAX_TX_PER_BLOCK) return; // malformed frame: nothing to record
    std::unordered_map<std::string, uint32_t> pre_nonces; // first sight per sender
    std::vector<std::string> created; // addresses untracked before this block
    for (uint32_t i = 0; i < block.header().tx_count; ++i) {
        const auto& tx = block.tx(i);
        UndoRecord::UndoTransaction undo_tx;
        undo_tx.sender.assign(reinterpret_cast<const char*>(tx.sender_nfa), 42);
        undo_tx.receiver.assign(reinterpret_cast<const char*>(tx.receiver_nfa), 42);
        undo_tx.amount = core::U128(blockchain::tx_amount(tx));
        undo_tx.fee = core::U128(blockchain::tx_fee(tx));
        // Sender nonce snapshot (BACKLOG 0.12): the next-nonce value
        // before this block applies. Coinbase senders never take part in
        // nonce accounting, so they are not recorded (nor restored).
        const bool is_coinbase =
            (std::strncmp(undo_tx.sender.c_str(), "GENESIS", 7) == 0) ||
            (std::strncmp(undo_tx.sender.c_str(), "MINER_", 6) == 0);
        if (!is_coinbase) {
            auto it = pre_nonces.find(undo_tx.sender);
            if (it == pre_nonces.end()) {
                Address sender{};
                std::memcpy(sender.data(), tx.sender_nfa, 42);
                undo_tx.prev_sender_nonce = ledger_.get_next_nonce(sender);
                pre_nonces.emplace(undo_tx.sender, undo_tx.prev_sender_nonce);
            } else {
                undo_tx.prev_sender_nonce = it->second;
            }
        }
        // Created-address detection (BACKLOG 0.12): any endpoint the
        // ledger did not track before this block becomes tracked by it.
        // At most 2 x tx_count such addresses exist per block.
        if (created.size() < 2 * size_t(block.header().tx_count)) {
            Address endpoint{};
            std::memcpy(endpoint.data(), tx.sender_nfa, 42);
            if (!ledger_.tracked_addresses_containing(endpoint)) {
                created.emplace_back(undo_tx.sender);
            }
            std::memcpy(endpoint.data(), tx.receiver_nfa, 42);
            if (!ledger_.tracked_addresses_containing(endpoint)) {
                created.emplace_back(undo_tx.receiver);
            }
        }
        record.transactions.push_back(std::move(undo_tx));
    }
    record.created_addresses = std::move(created);

    // Store record in undo journal
    undo_journal_.push_back(record);
}

void UndoEngine::commit_undo_point() {
    // Only records not yet on disk are appended. A reloaded journal must
    // never be re-committed: that used to duplicate every record in the
    // file, and a later rollback then reversed each effect twice.
    if (undo_journal_.size() <= committed_upto_) return;
    if (committed_upto_ > undo_journal_.size()) committed_upto_ = undo_journal_.size();

    // Append the pending records byte-wise (BACKLOG 0.11). The file gains
    // its versioned header on first write; a pre-existing file keeps its
    // header. A torn tail from a crash is healed on the next load.
    int fd = ::open(undo_file_.string().c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        std::cerr << "Failed to open undo file" << std::endl;
        return;
    }

    struct stat st{};
    bool ok = ::fstat(fd, &st) == 0;
    if (ok && st.st_size == 0) ok = write_header(fd);

    std::vector<uint8_t> buf;
    if (ok) {
        for (size_t i = committed_upto_; i < undo_journal_.size(); ++i) {
            const auto& record = undo_journal_[i];
            buf.clear();
            buf.reserve(record_bytes(record));
            serialize_record(record, buf);
            if (!write_all(fd, buf.data(), buf.size())) {
                ok = false;
                break;
            }
        }
    }
    if (ok) ok = ::fsync(fd) == 0;
    ::close(fd);
    if (!ok) {
        std::cerr << "Failed to append undo journal" << std::endl;
        return;
    }

    committed_upto_ = undo_journal_.size();

    // Also update undo.vxl metadata
    update_undo_metadata();
}

void UndoEngine::load_latest_undo_journal() {
    if (!std::filesystem::exists(undo_file_)) return;

    int fd = ::open(undo_file_.string().c_str(), O_RDONLY);
    if (fd < 0) return;

    struct stat st{};
    if (fstat(fd, &st) < 0) {
        ::close(fd);
        return;
    }
    if (static_cast<uint64_t>(st.st_size) > kUndoFileCap) {
        // Oversized input is malformed by policy: discard and rebuild.
        ::close(fd);
        std::filesystem::remove(undo_file_);
        return;
    }

    std::vector<uint8_t> buffer(static_cast<size_t>(st.st_size));
    const ssize_t got = ::read(fd, buffer.data(), buffer.size());
    ::close(fd);
    if (got != static_cast<ssize_t>(buffer.size())) return;

    // Header check: wrong magic or version is never replayed — the journal
    // is rebuilt from live block application instead (reject-or-migrate,
    // BACKLOG 0.11; this also rejects every pre-0.11 raw-pointer file).
    if (buffer.size() < kUndoHeaderSize ||
        std::memcmp(buffer.data(), kUndoMagic, 8) != 0) {
        std::filesystem::remove(undo_file_);
        return;
    }
    const uint8_t* vp = buffer.data() + 8;
    const uint32_t version = uint32_t(vp[0]) | (uint32_t(vp[1]) << 8) |
                             (uint32_t(vp[2]) << 16) | (uint32_t(vp[3]) << 24);
    if (version != kUndoVersion) {
        std::filesystem::remove(undo_file_);
        return;
    }

    // Parse records sequentially. A record that does not parse cleanly
    // mid-file is corruption, not a torn tail — discard everything (the
    // journal rebuilds from live application; consensus never depends on
    // it). Only a torn TAIL is healed by truncation. A torn tail is also
    // detectable for real (multi-tx) records (review round 5, P3): the
    // record header's tx_count is readable ahead of the transaction array,
    // so if the remaining bytes cannot possibly hold that record's
    // minimum body, the crash happened mid-append and everything up to
    // the previous record boundary is healed instead of discarded.
    ByteReader r{buffer.data() + kUndoHeaderSize, buffer.data() + buffer.size()};
    size_t good_end = kUndoHeaderSize; // offset after the last complete record
    bool corrupt = false;
    while (r.p != r.end) {
        UndoRecord rec;
        // A record's length is not self-delimiting, so parse a copy first.
        // Failure with fewer bytes left than a minimal (zero-tx) record is
        // a torn tail from a crash mid-append; anything else is corruption.
        ByteReader probe = r;
        if (!parse_record(probe, rec)) {
            const size_t remaining = static_cast<size_t>(r.end - r.p);
            if (remaining < kMinRecordSize) break; // torn tail (zero-tx shape)
            // Torn multi-tx record: the header up to tx_count is 80 bytes
            // (height 8 | ts 8 | prev_tip 32 | supply 16 | accounts 8 |
            // tx_count 8). If tx_count is sane and the remaining bytes are
            // fewer than the record's minimum body, this is a crash
            // mid-append — heal; otherwise the file is truly corrupt.
            if (remaining >= 80) {
                ByteReader hdr_probe = r;
                const uint8_t* skipped = nullptr;
                const bool readable = hdr_probe.take(72, &skipped);
                const uint64_t torn_tx_count = readable ? hdr_probe.get_u64() : 0;
                if (readable && torn_tx_count <= blockchain::MAX_TX_PER_BLOCK &&
                    remaining < 88 + torn_tx_count * kUndoTxSize) {
                    break; // torn tail of a multi-tx record
                }
            }
            corrupt = true;
            break;
        }
        undo_journal_.push_back(std::move(rec));
        r = probe;
        good_end = static_cast<size_t>(r.p - buffer.data());
    }

    if (corrupt) {
        undo_journal_.clear();
        std::filesystem::remove(undo_file_);
        return;
    }
    if (r.p != r.end) {
        // Torn tail: truncate the file to the last complete record.
        std::filesystem::resize_file(undo_file_, static_cast<uintmax_t>(good_end));
    }
    // Everything loaded (or healed) is durable on disk — a later commit
    // must append only records applied after this load.
    committed_upto_ = undo_journal_.size();
}

bool UndoEngine::rollback_to_height(uint64_t target_height) {
 // GQC-cemented checkpoints are absolute — no reorg (not even a
    // 51% majority) may ever unwind a finalized block.
    if (target_height < finalized_checkpoint_height_) {
        last_error_ = "ERR_FINALIZED_BY_GQC";
        return false;
    }
    last_error_.clear();
    // Roll back every block ABOVE target_height, newest first.
    // The journal stores one record per applied block, keyed by that block's
    // height — so "rollback to 0" means undoing all records with height > 0.
    if (undo_journal_.empty()) return false;

    // Coverage guard (review round 5, P2): the ledger may be AHEAD of the
    // journal — blocks applied without an undo record (a live intake path
    // that bypasses UndoEngine::apply_block) cannot be reversed, and a
    // rollback that regresses the height over their un-reversed effects
    // silently corrupts the state. Refuse unless the journal covers every
    // height above the target, up to the ledger's current tip.
    const uint64_t ledger_tip = ledger_.next_expected_height(); // next block height = tip + 1
    if (ledger_tip > 0) {
        const uint64_t first_needed = target_height + 1;
        const uint64_t last_needed = ledger_tip - 1;
        if (first_needed <= last_needed) {
            size_t covered = 0;
            for (const auto& r : undo_journal_) {
                if (r.height >= first_needed && r.height <= last_needed) ++covered;
            }
            if (covered != static_cast<size_t>(last_needed - first_needed + 1)) {
                last_error_ = "ERR_UNDO_JOURNAL_GAP";
                return false;
            }
        }
    }

    // Collect records above the target, in reverse (newest-first) order.
    std::vector<UndoRecord> to_remove;
    for (auto it = undo_journal_.rbegin(); it != undo_journal_.rend(); ++it) {
        if (it->height > target_height) to_remove.push_back(*it);
    }
    if (to_remove.empty()) return true; // nothing above target — already there

    // Preserve the displaced fork frames BEFORE any mutation (BACKLOG
    // 0.12): the caller may truncate the store file right after this
    // rollback, and a reorg is only replayable in both directions if the
    // displaced frames survive in the side journal.
    journal_displaced_frames(target_height);

    // Reverse transaction effects, newest block first.
    for (const auto& record : to_remove) {
        // ── Phase A: net the per-address deltas of this block (review
        // round 5, P1). The old code reversed transaction-by-transaction
        // with a clamp-at-zero adjust_balance, so an address whose
        // intra-block credit was reversed before its intra-block debit
        // went negative mid-stream — the debit was silently lost and the
        // next reversal resurrected the money as phantom supply. Netting
        // per record removes the order dependence entirely: pre_block =
        // post_block − (Σ apply-credits − Σ apply-debits), one exact
        // adjustment per address. `net` accumulates the REVERSAL deltas:
        // a reversal credit re-funds a sender (apply debited it), a
        // reversal debit un-credits a receiver or un-mints a coinbase.
        struct NetDelta {
            core::U128 credit{0};
            core::U128 debit{0};
        };
        std::unordered_map<Address, NetDelta, AddressHash> net;
        net.reserve(record.transactions.size() * 2 + 1);
        core::U128 coinbase_sum{0};
        core::U128 record_fees{0};
        for (const auto& tx : record.transactions) {
            vx::blockchain::Address sender, receiver;
            std::memset(sender.data(), 0, 42);
            std::memset(receiver.data(), 0, 42);
            std::memcpy(sender.data(), tx.sender.data(), std::min(tx.sender.size(), size_t(42)));
            std::memcpy(receiver.data(), tx.receiver.data(), std::min(tx.receiver.size(), size_t(42)));

            const char* s = reinterpret_cast<const char*>(sender.data());
            const bool is_coinbase = (std::strncmp(s, "GENESIS", 7) == 0) ||
                                     (std::strncmp(s, "MINER_", 6) == 0);
            if (is_coinbase) {
                // Coinbase reversal: remove the receiver credit (un-mint).
                net[receiver].debit = net[receiver].debit + tx.amount;
                coinbase_sum = coinbase_sum + tx.amount;
            } else {
                // Regular transfer: sender gets back amount + fee,
                // receiver loses the credited amount.
                net[sender].credit = net[sender].credit + tx.amount + tx.fee;
                net[receiver].debit = net[receiver].debit + tx.amount;
                record_fees = record_fees + tx.fee;
                // Nonce restore (BACKLOG 0.12): put the sender's next-nonce
                // counter back where it stood before this block applied.
                // Records unwind newest-first, so the oldest pre-block
                // snapshot wins for senders that spent in several of the
                // rolled-back blocks — exactly the pre-reorg state.
                ledger_.set_next_nonce(sender, tx.prev_sender_nonce);
            }
        }

        // ── Phase B: apply the net exactly (no clamp). A valid rollback
        // cannot underflow: the pre-block state was real, so post − delta
        // ≥ 0 by construction. An underflow means the ledger and the
        // journal disagree — abort instead of fabricating supply.
        bool mismatch = false;
        for (const auto& [addr, d] : net) {
            if (d.credit >= d.debit) {
                ledger_.adjust_balance(addr, d.credit - d.debit, true);
            } else if (!ledger_.revert_balance_exact(addr, d.debit - d.credit)) {
                std::fprintf(stderr,
                             "[UNDO] state/journal mismatch: exact reversal underflow at height %llu\n",
                             static_cast<unsigned long long>(record.height));
                mismatch = true;
            }
        }
        if (mismatch) {
            last_error_ = "ERR_UNDO_STATE_MISMATCH";
            return false;
        }

        // Issuance reversal (emission schedule, 2026-11-03): recompute
        // the block's issuance exactly as apply_block priced it — all
        // coinbase credits minus the fee share re-credited to the
        // producer — and take it back out of the issued-supply counter
        // so the 7,000,000,000 VX cap gate stays exact after a reorg.
        {
            const core::U128 fee_share = record_fees - record_fees / core::U128(2);
            const core::U128 recredited =
                (coinbase_sum < fee_share) ? coinbase_sum : fee_share;
            if (coinbase_sum > recredited) {
                ledger_.adjust_issued_supply(coinbase_sum - recredited, false);
            }
        }
        // Burned-supply reversal (review round 5, P3): apply_block burned
        // floor(total_fees / 2) from the same fees this record carries —
        // recompute it instead of adding a field to the journal format.
        if (!ledger_.revert_burned(record_fees / core::U128(2))) {
            std::fprintf(stderr,
                         "[UNDO] state/journal mismatch: burned-supply reversal underflow at height %llu\n",
                         static_cast<unsigned long long>(record.height));
            last_error_ = "ERR_UNDO_STATE_MISMATCH";
            return false;
        }

        // Untrack the addresses this block CREATED (BACKLOG 0.12): after
        // the reversal their balance is zero, so they return to the
        // untracked pre-fork state — the account map converges with a
        // fresh apply (a re-applied GENESIS_2 mint demands an untracked
        // receiver).
        for (const auto& created : record.created_addresses) {
            Address created_addr{};
            std::memcpy(created_addr.data(), created.data(),
                        std::min(created.size(), size_t(42)));
            ledger_.forget_empty_address(created_addr);
        }
    }

    // Drop the rolled-back records from the journal (AFTER the reversal
    // succeeds — an abort mid-rollback must leave the records in place so
    // the state stays diagnosable and the operation can be retried or
    // investigated).
    undo_journal_.erase(
        std::remove_if(undo_journal_.begin(), undo_journal_.end(),
                       [target_height](const UndoRecord& r) {
                           return r.height > target_height;
                       }),
        undo_journal_.end());

    // Restore the ledger height pointer to target + 1.
    ledger_.set_next_height(target_height + 1);

    // Truncate undo file to the rolled-back state.
    truncate_undo_file();

    return true;
}

void UndoEngine::truncate_undo_file() {
    // Get current undo journal size
    size_t current_size = undo_journal_.size();
    if (current_size == 0) {
        // Remove undo file entirely
        std::filesystem::remove(undo_file_);
        return;
    }

    // Rewrite undo file from scratch: versioned header + byte-wise records.
    int fd = ::open(undo_file_.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;

    bool ok = write_header(fd);
    std::vector<uint8_t> buf;
    if (ok) {
        for (const auto& record : undo_journal_) {
            buf.clear();
            buf.reserve(record_bytes(record));
            serialize_record(record, buf);
            if (!write_all(fd, buf.data(), buf.size())) {
                ok = false;
                break;
            }
        }
    }
    if (ok) ok = ::fsync(fd) == 0;
    ::close(fd);
    if (!ok) {
        std::cerr << "Failed to rewrite undo journal" << std::endl;
        return;
    }
    committed_upto_ = undo_journal_.size();
}

size_t UndoEngine::journal_displaced_frames(uint64_t target_height) {
    if (!store_) return 0;
    const uint64_t top = store_->chain_height();
    if (top == 0 || target_height + 1 >= top) return 0;

    // Existing size (the cap applies to the whole side file).
    std::error_code ec;
    const auto cur = std::filesystem::file_size(displaced_file_, ec);
    uint64_t file_size = ec ? 0 : static_cast<uint64_t>(cur);

    int fd = ::open(displaced_file_.string().c_str(),
                    O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) return 0;

    struct stat st{};
    bool ok = ::fstat(fd, &st) == 0;
    if (ok && st.st_size == 0) {
        std::vector<uint8_t> header;
        header.reserve(kDisplacedHeaderSize);
        put_bytes(header, reinterpret_cast<const uint8_t*>(kDisplacedMagic), 8);
        put_u32(header, kDisplacedVersion);
        ok = write_all(fd, header.data(), header.size());
    }

    size_t preserved = 0;
    std::vector<uint8_t> buf;
    for (uint64_t h = target_height + 1; ok && h < top; ++h) {
        const auto* raw = store_->get_block(h);
        if (!raw) continue; // sparse store: nothing to preserve at h
        if (file_size + kDisplacedRecordOverhead + blockchain::BLOCK_SIZE_BYTES >
            kDisplacedFileCap) {
            // Cap reached: stop preserving (reorg capability, never
            // consensus). Whatever fit stays, all of it complete records.
            break;
        }
        buf.clear();
        put_u64(buf, h);
        put_u32(buf, static_cast<uint32_t>(blockchain::BLOCK_SIZE_BYTES));
        ok = write_all(fd, buf.data(), buf.size()) &&
             write_all(fd, reinterpret_cast<const uint8_t*>(raw),
                       blockchain::BLOCK_SIZE_BYTES);
        if (ok) {
            file_size += kDisplacedRecordOverhead + blockchain::BLOCK_SIZE_BYTES;
            ++preserved;
        }
    }
    if (ok) ok = ::fsync(fd) == 0;
    ::close(fd);
    if (!ok) {
        std::cerr << "Failed to append displaced-frame journal" << std::endl;
        return preserved;
    }
    return preserved;
}

std::vector<DisplacedFrame> UndoEngine::load_displaced_frames() const {
    std::vector<DisplacedFrame> out;
    if (!std::filesystem::exists(displaced_file_)) return out;

    int fd = ::open(displaced_file_.string().c_str(), O_RDONLY);
    if (fd < 0) return out;

    struct stat st{};
    if (::fstat(fd, &st) < 0 || static_cast<uint64_t>(st.st_size) > kDisplacedFileCap) {
        // Oversized input is malformed by policy: trust nothing.
        ::close(fd);
        return out;
    }
    std::vector<uint8_t> buffer(static_cast<size_t>(st.st_size));
    const ssize_t got = ::read(fd, buffer.data(), buffer.size());
    ::close(fd);
    if (got != static_cast<ssize_t>(buffer.size())) return out;

    if (buffer.size() < kDisplacedHeaderSize ||
        std::memcmp(buffer.data(), kDisplacedMagic, 8) != 0) {
        return out;
    }
    const uint8_t* vp = buffer.data() + 8;
    const uint32_t version = uint32_t(vp[0]) | (uint32_t(vp[1]) << 8) |
                             (uint32_t(vp[2]) << 16) | (uint32_t(vp[3]) << 24);
    if (version != kDisplacedVersion) return out;

    ByteReader r{buffer.data() + kDisplacedHeaderSize, buffer.data() + buffer.size()};
    while (r.ok) {
        DisplacedFrame f;
        f.height = r.get_u64();
        const uint32_t len = r.get_u32();
        if (!r.ok) break;
        if (len != blockchain::BLOCK_SIZE_BYTES) break; // unknown shape: stop
        r.get_bytes(f.frame.data(), len);
        if (!r.ok) break;
        out.push_back(std::move(f));
    }
    return out;
}

void UndoEngine::update_undo_metadata() {
    // Update undo.vxl metadata header
    // This allows quick identification and versioning
}

void UndoEngine::restore_finalized_checkpoint() {
    // BACKLOG 0.13: the finalized checkpoint lives only in RAM no longer —
    // on open the guard is restored from the store's GQC sidecar (the
    // highest height whose aggregate was stamped by a successful
    // certification), monotonically: a restart must never report a height
    // LOWER than the persisted one.
    if (!store_) {
        finalized_sidecar_trusted_ = false;
        return;
    }
    bool clean = true;
    const uint64_t highest = store_->highest_gqc_stamp(clean);
    if (!clean) {
        // Fail closed on trust, open on capability: a sidecar that does
        // not parse cleanly is not trusted, so nothing is restored (the
        // guard protects only what this process cemented); consensus
        // never depends on the guard, and re-certification re-stamps the
        // sidecar.
        finalized_sidecar_trusted_ = false;
        std::cerr << "GQC sidecar does not parse cleanly; the persisted"
                     " finalized checkpoint was not restored"
                  << std::endl;
        return;
    }
    if (highest > finalized_checkpoint_height_) {
        finalized_checkpoint_height_ = highest;
    }
    finalized_sidecar_trusted_ = true;
}

bool UndoEngine::emergency_rollback() {
    // Rollback to genesis (height 0)
    return rollback_to_height(0);
}

} // namespace vx::state
