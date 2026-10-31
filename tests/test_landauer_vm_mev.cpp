// VortexLandauerMevTest — Landauer VM, Dandelion++, MEV shield
//
// Verifies:
//   1. Two-pass VX-ASM compilation with text labels (loop_start:).
//   2. Landauer heat formula via __builtin_popcountll:
//        step_gas = base_cost + erased_bits * LANDAUER_KT_LN2_SCALED + flips * 3
//   3. Dandelion++ Stem -> Fluff routing (TxCocoon 128B, TDI spam gate).
//   4. Hamiltonian MEV sandwich neutralization via canonical Galois ordering.

#include <gtest/gtest.h>
#include "vx/vm/vortex_vm.hpp"
#include "vx/net/swarm_node.hpp"
#include "vx/state/mempool.hpp"

#include <cstring>
#include <random>

using vx::vm::VortexVM;
using vx::net::SwarmNode;
using vx::net::TxCocoon;
using vx::blockchain::Transaction;

// ── 1. VX-ASM with labels ───────────────────────────────────────────────────

TEST(VortexLandauerMevTest, AssembleWithLabelsTwoPass) {
    // Countdown loop: R0 = 3; decrement until zero; HALT.
    const std::string src =
        "LOAD R0 3\n"          // LOAD_IMM alias
        "loop_start:\n"
        "LOAD R1 1\n"
        "SUB R0 R1\n"
        "MOV R5 R0\n"
        "JNZ loop_start\n"
        "HALT\n";
    const auto bc = VortexVM::assemble(src);
    ASSERT_FALSE(bc.empty());
    ASSERT_LE(bc.size(), VortexVM::BYTECODE_MAX_SIZE);

    VortexVM vm;
    const auto result = vm.execute(bc.data(), {});
    ASSERT_TRUE(result.success) << result.error;
    EXPECT_EQ(result.final_registers[0], 0u); // loop ran to zero
    EXPECT_EQ(result.final_registers[5], 0u);
    EXPECT_GT(result.cycles_used, 8u);        // loop actually iterated

    // Forward label also resolves.
    const auto bc_fwd = VortexVM::assemble(
        "JMP skip_over\n"
        "LOAD R7 0xAAAA\n"
        "skip_over:\n"
        "HALT\n");
    VortexVM vm2;
    const auto r2 = vm2.execute(bc_fwd.data(), {});
    ASSERT_TRUE(r2.success) << r2.error;
    EXPECT_EQ(r2.final_registers[7], 0u); // LOAD was skipped
}

TEST(VortexLandauerMevTest, LandauerFormulaExactness) {
    // LOAD R0 0xFFFFFFFFFFFFFFFF then AND R0 R1 (R1 = 0x0F) erases 60 bits.
    const auto bc = VortexVM::assemble(
        "LOAD_IMM R0 0xFFFFFFFFFFFFFFFF\n"
        "LOAD_IMM R1 0x0F\n"
        "AND R0 R1\n"
        "HALT\n");
    ASSERT_FALSE(bc.empty());

    VortexVM vm;
    const auto result = vm.execute(bc.data(), {});
    ASSERT_TRUE(result.success) << result.error;

    // Recompute the formula independently from the trace.
    uint64_t expected_total = 0;
    for (const auto& t : result.landauer_trace) {
        const uint64_t expected_step =
            /* base cost by opcode */ [&] {
                switch (t.opcode) {
                    case 0x00: return 1;  // NOP
                    case 0x04: return 2;  // LOAD_IMM
                    case 0x09: return 1;  // AND
                    case 0x18: return 1;  // HALT
                    default: return 1;
                }
            }() +
            t.erased_bits * VortexVM::LANDAUER_KT_LN2_SCALED +
            t.hamming_flips * 3;
        EXPECT_EQ(t.step_landauer_gas, expected_step)
            << "step " << t.step_index << " heat formula mismatch";
        expected_total += expected_step;
    }
    EXPECT_EQ(result.total_landauer_gas, expected_total);

    // The AND step must erase exactly 60 bits (0xFF..FF & ~0x0F): the four
    // low bits survive, the top 60 are forced 1 -> 0.
    const auto& and_step = result.landauer_trace[2];
    EXPECT_EQ(and_step.mnemonic, "AND");
    EXPECT_EQ(and_step.erased_bits, 60u);

    // NOP erases nothing: heat = base cost only.
    const auto nop_bc = VortexVM::assemble("NOP\nHALT\n");
    VortexVM vm3;
    const auto nop_result = vm3.execute(nop_bc.data(), {});
    ASSERT_TRUE(nop_result.success);
    ASSERT_GE(nop_result.landauer_trace.size(), 2u);
    EXPECT_EQ(nop_result.landauer_trace[0].erased_bits, 0u);
    EXPECT_EQ(nop_result.landauer_trace[0].step_landauer_gas, 1u);
}

TEST(VortexLandauerMevTest, NewOpcodesGaloisMulSolinasStackOps) {
    // GALOIS_MUL in GF(2^8): 0x57 * 0x83 = 0xC1 (classic AES test vector).
    {
        const auto bc = VortexVM::assemble(
            "LOAD_IMM R0 0x57\n"
            "LOAD_IMM R1 0x83\n"
            "GALOIS_MUL R0 R1\n"
            "HALT\n");
        VortexVM vm;
        const auto r = vm.execute(bc.data(), {});
        ASSERT_TRUE(r.success) << r.error;
        EXPECT_EQ(r.final_registers[0] & 0xFF, 0xC1);
    }
    // SOLINAS_RED mod (2^61 - 1): 2^61 == 1 -> v = (1<<61) reduces to 1.
    {
        const auto bc = VortexVM::assemble(
            "LOAD_IMM R0 0x2000000000000000\n"  // 2^61
            "SOLINAS_RED R1 R0\n"
            "HALT\n");
        VortexVM vm;
        const auto r = vm.execute(bc.data(), {});
        ASSERT_TRUE(r.success) << r.error;
        EXPECT_EQ(r.final_registers[1], 1u); // 2^61 mod (2^61-1) = 1
    }
    // DUP/SWAP/STORE/LOAD_MEM/ASSERT_EQ.
    {
        const auto bc = VortexVM::assemble(
            "PUSH 0x55\n"
            "DUP\n"
            "SWAP\n"
            "POP R2\n"
            "POP R3\n"
            "LOAD_IMM R4 10\n"
            "STORE R2 R4\n"
            "LOAD R5 R4\n"
            "ASSERT_EQ R5 R2\n"
            "ASSERT_EQ R3 R2\n"  // after SWAP both popped values are 0x55
            "HALT\n");
        VortexVM vm;
        const auto r = vm.execute(bc.data(), {});
        ASSERT_TRUE(r.success) << r.error;
        EXPECT_EQ(r.final_registers[2], 0x55u);
        EXPECT_EQ(r.final_registers[3], 0x55u);
        EXPECT_EQ(r.final_registers[5], 0x55u);
    }
}

// ── 3. Dandelion++ Stem -> Fluff ────────────────────────────────────────────

namespace {

vx::blockchain::Transaction make_test_tx(uint64_t amount, uint32_t fee, uint32_t nonce) {
    vx::blockchain::Transaction tx{};
    std::memset(tx.sender_nfa, 0, 42);
    std::memset(tx.receiver_nfa, 0, 42);
    std::memcpy(tx.sender_nfa, "TEST_SENDER_DANDELION_ROUTE_0000000000000", 42);
    std::memcpy(tx.receiver_nfa, "TEST_RECEIVER_DANDELION_ROUTE_000000000000", 42);
    vx::blockchain::tx_set_amount(tx, amount);
    vx::blockchain::tx_set_fee(tx, fee);
    vx::blockchain::tx_set_nonce(tx, nonce);
    return tx;
}

} // namespace

TEST(VortexLandauerMevTest, DandelionStemToFluffCycle) {
    SwarmNode node;

    // Legit transaction: TDI score above the spam gate.
    const auto tx = make_test_tx(1'000'000, 500, 1);
    const auto report = node.relay_cocoon_full_cycle(tx, 250 /* tdi_fp */);

    ASSERT_TRUE(report.ok) << report.error;
    ASSERT_FALSE(report.hops.empty());

    // Exactly one FLUFF hop at the end; everything before is STEM.
    const auto& last = report.hops.back();
    EXPECT_EQ(last.phase, "FLUFF");
    EXPECT_EQ(last.action, "broadcast");
    for (size_t i = 0; i + 1 < report.hops.size(); ++i) {
        EXPECT_EQ(report.hops[i].phase, "STEM");
        EXPECT_EQ(report.hops[i].action, "relayed");
        EXPECT_TRUE(report.hops[i].ip_source_erased);
    }

    // Stem length within the directive bounds (3..7 hardware hops).
    const size_t stem_hops = report.hops.size() - 1;
    EXPECT_GE(stem_hops, 3u);
    EXPECT_LE(stem_hops, 7u);

    // Stats updated.
    const auto stats = node.dandelion_stats();
    EXPECT_GE(stats.stem_relays, stem_hops);
    EXPECT_EQ(stats.fluff_broadcasts, 1u);
    EXPECT_EQ(stats.tdi_spam_annihilated, 0u);
    EXPECT_GE(stats.anonymity_set_size, 1u);

    // Cocoon binary invariants.
    const auto cocoon = SwarmNode::seal_cocoon(tx, 250);
    static_assert(sizeof(TxCocoon) == 128, "cocoon invariant");
    EXPECT_EQ(sizeof(TxCocoon), 128u);
    EXPECT_EQ(cocoon.phase, vx::net::COCOON_PHASE_STEM);
    EXPECT_GE(cocoon.stem_hops_remaining, 3u);
    EXPECT_LE(cocoon.stem_hops_remaining, 7u);

    // Seal/open round-trip: unmasking recovers the exact transaction.
    const auto opened = SwarmNode::open_cocoon(cocoon);
    EXPECT_EQ(std::memcmp(&opened, &tx, 112), 0);

    // Per-hop re-mask changes the masked payload and the salt.
    TxCocoon hop_cocoon = cocoon;
    vx::net::CocoonHopTrace trace;
    ASSERT_TRUE(node.relay_cocoon_step(hop_cocoon, trace));
    if (hop_cocoon.phase == vx::net::COCOON_PHASE_STEM) {
        EXPECT_NE(hop_cocoon.ephemeral_salt, cocoon.ephemeral_salt);
        EXPECT_EQ(hop_cocoon.stem_hops_remaining, cocoon.stem_hops_remaining - 1);
    }
}

TEST(VortexLandauerMevTest, DandelionTdiSpamAnnihilated) {
    SwarmNode node;
    // Spam: TDI fixed-point score below MIN_TDI_THRESHOLD (100).
    const auto spam = make_test_tx(1, 0, 1);
    const auto report = node.relay_cocoon_full_cycle(spam, 5 /* tdi_fp */);

    EXPECT_FALSE(report.ok);
    ASSERT_FALSE(report.hops.empty());
    EXPECT_EQ(report.hops[0].phase, "BURNED_TDI");
    EXPECT_EQ(report.hops[0].forwarded, false);
    EXPECT_EQ(node.dandelion_stats().tdi_spam_annihilated, 1u);

    // CRC corruption: flip a bit inside the cocoon payload -> burned.
    SwarmNode node2;
    auto cocoon = SwarmNode::seal_cocoon(make_test_tx(100, 10, 2), 250);
    cocoon.encrypted_tx[50] ^= 0x80;
    vx::net::CocoonHopTrace trace;
    EXPECT_FALSE(node2.relay_cocoon_step(cocoon, trace));
    EXPECT_EQ(trace.phase, "BURNED_CRC");
}

// ── 4. Hamiltonian MEV shield ───────────────────────────────────────────────

TEST(VortexLandauerMevTest, HamiltonianNeutralizesSandwich) {
    vx::state::Mempool mempool;

    auto make_tx = [](const char* sender, const char* receiver,
                      uint64_t amount, uint32_t fee, uint32_t nonce) {
        vx::blockchain::Transaction tx{};
        std::memset(tx.sender_nfa, 0, 42);
        std::memset(tx.receiver_nfa, 0, 42);
        std::memcpy(tx.sender_nfa, sender, std::min(std::strlen(sender), size_t(42)));
        std::memcpy(tx.receiver_nfa, receiver, std::min(std::strlen(receiver), size_t(42)));
        vx::blockchain::tx_set_amount(tx, amount);
        vx::blockchain::tx_set_fee(tx, fee);
        vx::blockchain::tx_set_nonce(tx, nonce);
        return tx;
    };

    // Classic sandwich bundle: high-fee buy, victim, low-fee sell — same pool.
    std::vector<vx::blockchain::Transaction> bundle;
    bundle.push_back(make_tx("VICTIM_ALICE_HAM_MEV_000000000000000000000", "POOL_XY_000000000000000000000000000000000000", 5'000'000, 100, 1));
    bundle.push_back(make_tx("ATTACKER EVE HAM MEV 00000000000000000000", "POOL_XY_000000000000000000000000000000000000", 50'000'000, 10000, 1));
    bundle.push_back(make_tx("ATTACKER EVE HAM MEV 00000000000000000000", "POOL_XY_000000000000000000000000000000000000", 45'000'000, 10, 2));
    bundle.push_back(make_tx("FILLER CHARLIE 000000000000000000000000000", "UNRELATED_R_00000000000000000000000000000000", 1'000, 50, 1));

    // Snapshot the ORIGINAL order before the first audit: the audit
    // permutes its input span in place.
    const std::vector<vx::blockchain::Transaction> original = bundle;

    std::span<vx::blockchain::Transaction> view(bundle);
    const auto report = mempool.audit_and_neutralize_mev(view, 0xDEADBEEF);

    // Sandwich vector detected and neutralized.
    EXPECT_GE(report.sandwich_vectors_detected, 1u);
    EXPECT_TRUE(report.neutralized);

    // Canonical reorder must not lose transactions.
    ASSERT_EQ(report.order_after.size(), bundle.size());

    // Determinism: same bundle + same prev CRC (fresh copies of the
    // ORIGINAL bundle — the audit permutes its input span in place).
    std::vector<vx::blockchain::Transaction> bundle2 = original;
    std::span<vx::blockchain::Transaction> view2(bundle2);
    const auto report2 = mempool.audit_and_neutralize_mev(view2, 0xDEADBEEF);
    EXPECT_EQ(report.order_after, report2.order_after);

    // Different prev CRC -> different canonical key stream (still valid).
    std::vector<vx::blockchain::Transaction> bundle3 = original;
    std::span<vx::blockchain::Transaction> view3(bundle3);
    const auto report3 = mempool.audit_and_neutralize_mev(view3, 0x12345678);
    EXPECT_EQ(report3.order_after.size(), bundle.size());

    // A clean bundle (no fee anomaly, no receiver collision) is untouched.
    std::vector<vx::blockchain::Transaction> clean;
    clean.push_back(make_tx("CLEAN_SENDER_A_000000000000000000000000000", "CLEAN_R_A_000000000000000000000000000000000", 100, 10, 1));
    clean.push_back(make_tx("CLEAN_SENDER_B_000000000000000000000000000", "CLEAN_R_B_000000000000000000000000000000000", 200, 10, 1));
    std::span<vx::blockchain::Transaction> clean_view(clean);
    const auto clean_report = mempool.audit_and_neutralize_mev(clean_view, 7);
    EXPECT_EQ(clean_report.sandwich_vectors_detected, 0u);
    EXPECT_FALSE(clean_report.neutralized);
    EXPECT_EQ(clean_report.initial_hamiltonian_energy, 0.0);
}
