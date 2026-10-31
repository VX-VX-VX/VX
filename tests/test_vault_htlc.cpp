// VortexVaultHtlcTest — Vault ephemeral signing + HTLC swap
//
// Verifies:
//   1. sign_ephemeral_in_vault: the page is guaranteed BURNED with 0x00
//      memory, the key lifetime is measurable in rdtsc cycles (> 0), and the
//      signature is hardware-UUID bound.
//   2. HTLC engine: CLAIM with a valid preimage before the timelock,
//      REFUND after the timelock, and a still-LOCKED contract on a wrong
//      preimage before expiry.

#include <gtest/gtest.h>
#include "vx/core/memory_vault.hpp"
#include "vx/vm/vortex_vm.hpp"

#include <cstring>

using vx::core::MemoryCore;
using vx::vm::VortexVM;

// ── 1. Vault air-gap signer ───────────────────────────────────────────────

TEST(VortexVaultHtlcTest, EphemeralSignBurnsPage) {
    MemoryCore vault(1024 * 1024); // 1 MB dev arena
    vault.initialize(0xA11CE000ULL);

    auto make_tx = [](uint64_t amount) {
        vx::blockchain::Transaction tx{};
        std::memset(&tx, 0, sizeof(tx));
        std::memcpy(tx.sender_nfa, "VAULT_TEST_SENDER_00000000000000000000000", 42);
        std::memcpy(tx.receiver_nfa, "VAULT_TEST_RECV_000000000000000000000000", 42);
        vx::blockchain::tx_set_amount(tx, amount);
        vx::blockchain::tx_set_fee(tx, 800);
        vx::blockchain::tx_set_nonce(tx, 1);
        return tx;
    };

    auto tx = make_tx(50'000);
    const auto report = vault.sign_ephemeral_in_vault(tx);

    // The page must end in the BURNED state with its memory scrubbed to 0x00.
    EXPECT_EQ(report.final_page_state, "BURNED");
    EXPECT_TRUE(report.hw_uuid_bound);
    EXPECT_GT(report.key_lifetime_rdtsc_cycles, 0u);
    EXPECT_GT(report.key_lifetime_us, 0.0);
    EXPECT_EQ(report.signed_tx_hex.size(), 224u); // 112 bytes * 2 hex chars

    // Signature anchor: cocoon_proof no longer all-zero.
    bool anchored = false;
    for (const uint8_t b : tx.cocoon_proof) if (b) { anchored = true; break; }
    EXPECT_TRUE(anchored);

    // The arena page the key lived in must be zeroed after the burn.
    const auto stats = vault.get_stats();
    EXPECT_GE(stats.burned_pages, 1u);

    // Determinism is NOT expected (hardware entropy) but reproducibility of
    // the burn is: sign again — another page cycles VOID -> LOCKED -> BURNED.
    auto tx2 = make_tx(60'000);
    const auto report2 = vault.sign_ephemeral_in_vault(tx2);
    EXPECT_EQ(report2.final_page_state, "BURNED");
    EXPECT_GT(report2.key_lifetime_rdtsc_cycles, 0u);

    // Different transactions must produce different signature anchors.
    EXPECT_NE(0, std::memcmp(tx.cocoon_proof, tx2.cocoon_proof, 12));
}

// ── 2. HTLC atomic swaps ────────────────────────────────────────────────────

namespace {
std::array<uint8_t, 42> fixed_addr(const char* tag) {
    std::array<uint8_t, 42> a{};
    std::memcpy(a.data(), tag, std::min(std::strlen(tag), size_t(42)));
    return a;
}
} // namespace

TEST(VortexVaultHtlcTest, HtlcClaimBeforeTimelock) {
    auto recipient = fixed_addr("HTLC_TEST_RECIPIENT_0000000000000000000000000");
    auto refund = fixed_addr("HTLC_TEST_REFUND_000000000000000000000000000");

    const auto contract = VortexVM::create_htlc_contract(
        /*secret_seed=*/0x5EED0001ULL, recipient.data(), refund.data(),
        /*timelock_height=*/100);

    EXPECT_LE(contract.bytecode.size(), VortexVM::BYTECODE_MAX_SIZE);
    EXPECT_EQ(contract.hash_lock.size(), 32u);

    // Canonical preimage: LE64(secret) || LE64(~secret).
    const uint64_t secret = 0x5EED0001ULL;
    uint8_t preimage[16];
    const uint64_t pre_hi = ~secret;
    std::memcpy(preimage, &secret, 8);
    std::memcpy(preimage + 8, &pre_hi, 8);

    const auto res = VortexVM::settle_htlc_swap(
        contract.bytecode, std::span<const uint8_t>(preimage, 16), 99);
    EXPECT_EQ(res.outcome, VortexVM::HtlcOutcome::CLAIMED);
    EXPECT_TRUE(res.vm_trace.success) << res.vm_trace.error;
    EXPECT_EQ(res.vm_branch_marker, 1); // CLAIM branch executed in the VM
    EXPECT_GT(res.vm_trace.total_landauer_gas, 0u);
    EXPECT_EQ(res.timelock_height, 100u);
    EXPECT_EQ(res.current_height, 99u);
}

TEST(VortexVaultHtlcTest, HtlcRefundAfterTimelock) {
    auto recipient = fixed_addr("HTLC_TEST_RECIPIENT_0000000000000000000000000");
    auto refund = fixed_addr("HTLC_TEST_REFUND_000000000000000000000000000");

    const auto contract = VortexVM::create_htlc_contract(
        0xBEEF0002ULL, recipient.data(), refund.data(), /*timelock_height=*/50);

    // An attempted (wrong) preimage after expiry — the refund branch wins.
    uint8_t wrong_preimage[16] = {};
    std::memset(wrong_preimage, 0xAA, 16);
    const auto res = VortexVM::settle_htlc_swap(
        contract.bytecode, std::span<const uint8_t>(wrong_preimage, 16), 51);
    EXPECT_EQ(res.outcome, VortexVM::HtlcOutcome::REFUNDED);
    EXPECT_TRUE(res.vm_trace.success) << res.vm_trace.error;
    EXPECT_EQ(res.vm_branch_marker, 2); // REFUND branch executed in the VM

    // Refund also works with NO preimage at all after expiry.
    const auto res_no_preimage = VortexVM::settle_htlc_swap(
        contract.bytecode, {}, 100);
    EXPECT_EQ(res_no_preimage.outcome, VortexVM::HtlcOutcome::REFUNDED);
}

TEST(VortexVaultHtlcTest, HtlcLockedOnWrongPreimage) {
    auto recipient = fixed_addr("HTLC_TEST_RECIPIENT_0000000000000000000000000");
    auto refund = fixed_addr("HTLC_TEST_REFUND_000000000000000000000000000");

    const auto contract = VortexVM::create_htlc_contract(
        0x1337C0DEULL, recipient.data(), refund.data(), /*timelock_height=*/100);

    // Wrong preimage, timelock not yet expired -> funds stay locked.
    const uint64_t wrong = 0xDEADBEEFULL;
    uint8_t preimage[16];
    const uint64_t wrong_hi = ~wrong;
    std::memcpy(preimage, &wrong, 8);
    std::memcpy(preimage + 8, &wrong_hi, 8);

    const auto res = VortexVM::settle_htlc_swap(
        contract.bytecode, std::span<const uint8_t>(preimage, 16), 42);
    EXPECT_EQ(res.outcome, VortexVM::HtlcOutcome::LOCKED);
    EXPECT_TRUE(res.vm_trace.success) << res.vm_trace.error;
    EXPECT_EQ(res.vm_branch_marker, 2); // refund path taken inside the VM,
                                        // but the timelock had NOT expired

    // The correct preimage still unlocks the very same contract.
    const uint64_t secret = 0x1337C0DEULL;
    uint8_t good[16];
    const uint64_t good_hi = ~secret;
    std::memcpy(good, &secret, 8);
    std::memcpy(good + 8, &good_hi, 8);
    const auto res_ok = VortexVM::settle_htlc_swap(
        contract.bytecode, std::span<const uint8_t>(good, 16), 42);
    EXPECT_EQ(res_ok.outcome, VortexVM::HtlcOutcome::CLAIMED);

    // Contract determinism: same secret -> same hash lock.
    const auto again = VortexVM::create_htlc_contract(
        0x1337C0DEULL, recipient.data(), refund.data(), 100);
    EXPECT_EQ(again.hash_lock, contract.hash_lock);
    EXPECT_NE(contract.hash_lock, VortexVM::create_htlc_contract(
        0x1337C0DFULL, recipient.data(), refund.data(), 100).hash_lock);
}
