#include "vx/state/undo_engine.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/storage/block_store.hpp"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <filesystem>
#include <iostream>

namespace vx::state {

UndoEngine::UndoEngine(const std::string& data_dir, storage::BlockStore& store, LedgerState& ledger)
    : data_dir_(data_dir), store_(&store), ledger_(ledger) {
    // Ensure undo directory exists
    std::filesystem::path undo_path = std::filesystem::path(data_dir_) / "undo";
    std::filesystem::create_directories(undo_path);
    undo_file_ = undo_path / "undo.vxl";
    load_latest_undo_journal();
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
    uint8_t tip_hash[32];
    store_->tip_hash(tip_hash);
    record.prev_tip_hash = std::string(reinterpret_cast<const char*>(tip_hash), 32);
    record.prev_supply = ledger_.total_supply();
    record.prev_accounts_count = ledger_.accounts().size();

    // Record transaction effects
    if (block.header().tx_count > blockchain::MAX_TX_PER_BLOCK) return; // malformed frame: nothing to record
    for (uint32_t i = 0; i < block.header().tx_count; ++i) {
        auto* raw = store_->get_block(record.height);
        if (!raw) break;
        blockchain::BlockView v{std::span<const uint8_t, 65536>(reinterpret_cast<const uint8_t*>(raw), 65536)};
        const auto& tx = v.tx(i);
        UndoRecord::UndoTransaction undo_tx;
        undo_tx.sender = std::string(reinterpret_cast<const char*>(tx.sender_nfa), 42);
        undo_tx.receiver = std::string(reinterpret_cast<const char*>(tx.receiver_nfa), 42);
        undo_tx.amount = core::U128(blockchain::tx_amount(tx));
        undo_tx.fee = core::U128(blockchain::tx_fee(tx));
        record.transactions.push_back(undo_tx);
    }

    // Store record in undo journal
    undo_journal_.push_back(record);
}

void UndoEngine::commit_undo_point() {
    if (undo_journal_.empty()) return;

    // Write undo journal to file (append mode)
    int fd = ::open(undo_file_.string().c_str(), O_WRONLY | O_CREAT | O_APPEND, 0644);
    if (fd < 0) {
        std::cerr << "Failed to open undo file" << std::endl;
        return;
    }

    // Write journal size and records
    uint64_t count = undo_journal_.size();
    ssize_t written = ::write(fd, &count, sizeof(count));
    if (written != (ssize_t)sizeof(count)) {
        ::close(fd);
        return;
    }

    for (const auto& record : undo_journal_) {
        // Write record structure
        ssize_t written = ::write(fd, &record, sizeof(record));
        if (written != (ssize_t)sizeof(record)) {
            ::close(fd);
            return;
        }
    }

    ::close(fd);

    // Clear journal in memory
    undo_journal_.clear();

    // Also update undo.vxl metadata
    update_undo_metadata();
}

void UndoEngine::load_latest_undo_journal() {
    if (!std::filesystem::exists(undo_file_)) return;

    int fd = ::open(undo_file_.string().c_str(), O_RDONLY);
    if (fd < 0) return;

    // Read file size
    struct stat st{};
    if (fstat(fd, &st) < 0) {
        ::close(fd);
        return;
    }

    // Read entire file into memory (max 64KB for safety)
    size_t file_size = st.st_size;
    std::vector<uint8_t> buffer(file_size);
    ssize_t read = ::read(fd, buffer.data(), file_size);
    ::close(fd);
    if (read != (ssize_t)file_size) return;

    // Parse undo records
    size_t offset = 0;
    while (offset < file_size) {
        if (offset + sizeof(uint64_t) > file_size) break;
        uint64_t count;
        std::memcpy(&count, buffer.data() + offset, sizeof(count));
        offset += sizeof(count);
        if (offset + count * sizeof(UndoRecord) > file_size) break;

        for (uint64_t i = 0; i < count; ++i) {
            UndoRecord record;
            std::memcpy(&record, buffer.data() + offset, sizeof(record));
            undo_journal_.push_back(record);
            offset += sizeof(record);
        }
    }
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

    // Collect records above the target, in reverse (newest-first) order.
    std::vector<UndoRecord> to_remove;
    for (auto it = undo_journal_.rbegin(); it != undo_journal_.rend(); ++it) {
        if (it->height > target_height) to_remove.push_back(*it);
    }
    if (to_remove.empty()) return true; // nothing above target — already there

    // Drop them from the journal.
    undo_journal_.erase(
        std::remove_if(undo_journal_.begin(), undo_journal_.end(),
                       [target_height](const UndoRecord& r) {
                           return r.height > target_height;
                       }),
        undo_journal_.end());

    // Reverse transaction effects, newest block first.
    for (const auto& record : to_remove) {
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
                // Coinbase reversal: only remove the receiver credit (un-mint).
                ledger_.adjust_balance(receiver, tx.amount, false);
            } else {
                // Regular transfer: sender gets back amount + fee,
                // receiver loses the credited amount.
                ledger_.adjust_balance(sender, tx.amount + tx.fee, true);
                ledger_.adjust_balance(receiver, tx.amount, false);
            }
        }
    }

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

    // Rewrite undo file with current journal
    int fd = ::open(undo_file_.string().c_str(), O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) return;

    // Write current journal
    uint64_t count = current_size;
    ssize_t written = ::write(fd, &count, sizeof(count));
    if (written == (ssize_t)sizeof(count)) {
        for (const auto& record : undo_journal_) {
            written = ::write(fd, &record, sizeof(record));
            if (written != (ssize_t)sizeof(record)) break;
        }
    }

    ::close(fd);
}

void UndoEngine::update_undo_metadata() {
    // Update undo.vxl metadata header
    // This allows quick identification and versioning
}

bool UndoEngine::emergency_rollback() {
    // Rollback to genesis (height 0)
    return rollback_to_height(0);
}

} // namespace vx::state