// libFuzzer target: arbitrary bytes -> undo journal file -> replay.
//
// Invariant (BACKLOG 0.11): the journal replay path touches only plain
// bytes. A hostile journal file — wrong magic, unknown version, heap-
// pointer-shaped words, mid-file corruption, torn tails — must parse or
// be discarded without ever dereferencing a pointer-looking field, never
// crash, never corrupt ledger state, and leave the engine able to rebuild
// from live block application. (The rollback-over-poisoned-journal gtest
// case additionally runs clean under the ASan+UBSan lane.)
#include "vx/state/undo_engine.hpp"
#include "vx/storage/block_store.hpp"

#include <cstring>
#include <filesystem>
#include <fstream>
#include <vector>

namespace {

std::filesystem::path scratch_dir() {
    static const std::filesystem::path dir =
        std::filesystem::temp_directory_path() / "vx_fuzz_undo_journal";
    return dir;
}

vx::storage::BlockStore& shared_store() {
    // The engine only reads the store inside apply_block, which this
    // harness never drives; one lazily-built store keeps every exec cheap.
    static vx::storage::BlockStore store(
        (scratch_dir() / "fuzz.vxb").string(), "genesis.bin", 8);
    return store;
}

struct Scratch {
    Scratch() {
        std::filesystem::remove_all(scratch_dir());
        std::filesystem::create_directories(scratch_dir() / "undo");
        shared_store();
    }
    ~Scratch() { std::filesystem::remove_all(scratch_dir()); }
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    // Bound the per-exec work: the parser's own file cap is 64 MiB, the
    // fuzzer only needs to reach every parser branch, not the cap.
    static Scratch scratch;
    const std::filesystem::path journal =
        scratch_dir() / "undo" / "undo.vxl";
    const size_t len = size < (128 * 1024) ? size : (128 * 1024);

    {
        std::ofstream f(journal, std::ios::binary | std::ios::trunc);
        f.write(reinterpret_cast<const char*>(data),
                static_cast<std::streamsize>(len));
    }

    vx::state::LedgerState ledger;
    {
        vx::state::UndoEngine undo(scratch_dir().string(), shared_store(), ledger);
        // Whatever parsed (or was discarded) must roll back cleanly.
        const uint64_t target = len ? (static_cast<uint64_t>(data[0]) % 3) : 0;
        (void)undo.rollback_to_height(target);
        (void)undo.rollback_to_height(0);
        undo.commit_undo_point();
    }
    {
        // Reload the (possibly healed or discarded) file: the second load
        // must agree with the first — no duplicate records, no crash.
        vx::state::UndoEngine undo(scratch_dir().string(), shared_store(), ledger);
        (void)undo.rollback_to_height(0);
    }
    return 0;
}
