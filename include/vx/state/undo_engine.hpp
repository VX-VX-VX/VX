#pragma once

#include "vx/blockchain/block.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/storage/block_store.hpp"
#include <filesystem>
#include <span>
#include <string>
#include <vector>

namespace vx::state {

struct UndoRecord {
    uint64_t height;
    std::chrono::system_clock::time_point timestamp;
    std::string prev_tip_hash;
    U128 prev_supply;
    size_t prev_accounts_count;
    struct UndoTransaction {
        std::string sender;
        std::string receiver;
        U128 amount;
        U128 fee;
    };
    std::vector<UndoTransaction> transactions;
};

struct UndoEngine {
public:
    UndoEngine(const std::string& data_dir, storage::BlockStore& store, LedgerState& ledger);
    ~UndoEngine();

    // Re-point the journal at a reopened block store. The chain can close
    // and reopen its store file (e.g. ledger truncation during a reorg)
    // while the journal object — and its in-memory state — must survive;
    // a reference member would silently dangle across that reopen.
    void attach_store(storage::BlockStore& store) noexcept { store_ = &store; }

    // Delete copy/move
    UndoEngine(const UndoEngine&) = delete;
    UndoEngine& operator=(const UndoEngine&) = delete;

    // Record state changes before applying a block
    void apply_block(const blockchain::BlockView& block);

    // Drop the newest in-memory record: the caller recorded a pre-state
    // entry but the block did NOT enter the ledger (apply refused), so a
    // later rollback must not reverse effects that never happened. Only
    // uncommitted records can be dropped.
    void drop_last_record() noexcept {
        if (undo_journal_.size() > committed_upto_ && !undo_journal_.empty()) {
            undo_journal_.pop_back();
        }
    }

    // Commit undo point to journal file
    void commit_undo_point();

    // Rollback to target height
    bool rollback_to_height(uint64_t target_height);

  // ── GQC finality checkpoint ─────────────────────────────────
    // Cement a GQC-certified block: any later rollback_to_height(h) with
    // h below this checkpoint is refused with ERR_FINALIZED_BY_GQC.
    void lock_finalized_height(uint64_t height) noexcept {
        if (height > finalized_checkpoint_height_) finalized_checkpoint_height_ = height;
    }
    uint64_t finalized_checkpoint_height() const noexcept {
        return finalized_checkpoint_height_;
    }
    /// Last refusal reason (e.g. "ERR_FINALIZED_BY_GQC") after a failed op.
    const std::string& last_error() const noexcept { return last_error_; }

    // Emergency rollback to genesis
    bool emergency_rollback();

    // Get current height
    uint64_t current_height() const;

private:
    std::string data_dir_;
    storage::BlockStore* store_;
    LedgerState& ledger_;
    std::filesystem::path undo_file_;
    std::vector<UndoRecord> undo_journal_;
    // Records [0, committed_upto_) are already durable in the file; a
    // commit appends only the tail. Reloaded records are durable by
    // definition, so the baseline starts at the loaded size — re-committing
    // them would duplicate every record and double-revert on rollback.
    size_t committed_upto_ = 0;
 uint64_t finalized_checkpoint_height_ = 0; // GQC cement
    std::string last_error_;

    void truncate_undo_file();
    void update_undo_metadata();
    void load_latest_undo_journal();
};

} // namespace vx::state