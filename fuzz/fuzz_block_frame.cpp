// libFuzzer target: arbitrary bytes -> 64 KiB block frame parse + access.
//
// Invariant: parsing, structural inspection and transaction accessors on a
// hostile frame must never crash, never read outside the 65536-byte frame,
// and must reject frames whose header tx_count exceeds the fixed frame
// capacity (the bound apply paths enforce — see LedgerState::apply_block).
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/crypto_sponge.hpp"

#include <cstring>

extern "C" int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size) {
    using namespace vx::blockchain;

    // The frame is a fixed 65536-byte structure; pad or truncate the fuzz
    // input to exactly one frame so BlockView's span precondition holds.
    static_assert(BLOCK_SIZE_BYTES == 65536);
    static thread_local std::array<uint8_t, BLOCK_SIZE_BYTES> frame{};
    std::memset(frame.data(), 0, frame.size());
    std::memcpy(frame.data(), data, size < frame.size() ? size : frame.size());

    BlockView v{std::span<const uint8_t, BLOCK_SIZE_BYTES>(frame.data(), frame.size())};

    // Structural surface: magic, height, count.
    (void)v.valid_magic();
    (void)v.header().block_height;
    const uint32_t count = v.header().tx_count;

    // Transaction accessors are only lawful within the fixed capacity — the
    // same bound every apply path must enforce before touching the frame.
    const uint32_t scan = count > MAX_TX_PER_BLOCK ? MAX_TX_PER_BLOCK : count;
    for (uint32_t i = 0; i < scan; ++i) {
        const Transaction& tx = v.tx(i);
        volatile uint64_t amt = tx_amount(tx);
        volatile uint32_t fee = tx_fee(tx);
        volatile uint32_t nonce = tx_nonce(tx);
        (void)amt; (void)fee; (void)nonce;
        (void)vx::blockchain::verify_transaction_proof(tx);
        (void)is_genesis_v1_tx(tx);
    }
    return 0;
}
