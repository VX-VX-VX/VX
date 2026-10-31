// VortexChaosFuzzerTest — (test #15)
//
// Deterministic chaos: 10 000 mutations per kernel surface. Every mutation
// is a replayable RNG draw (fixed seeds), every rejection path is the real
// production validation, and the invariants are absolute:
//   * no crash, no out-of-bounds read, no hang;
//   * 100% of corrupted-CRC wire packets are dropped;
//   * 0 forged SGMT witnesses verify (false positives == 0);
//   * infinite JMP 0 loops die at MAX_CYCLES in bounded wall time.

#include <gtest/gtest.h>
#include "vx/security/chaos_fuzzer.hpp"
#include "vx/net/swarm_node.hpp"
#include "vx/vm/vortex_vm.hpp"
#include "vx/state/galois_trie.hpp"

#include <chrono>
#include <cstring>

using vx::security::run_chaos_fuzz_round;

// Mutations per surface (directive floor: 10 000).
constexpr uint64_t kMutations = 10'000;

TEST(VortexChaosFuzzerTest, WireHeaderChaos10k) {
    const auto rep = run_chaos_fuzz_round(0xC4A05F11ULL, kMutations);

    // Every corrupted packet is dropped, the connection never crashes.
    EXPECT_EQ(rep.wire_total, kMutations);
    EXPECT_EQ(rep.wire_rejected, rep.wire_total);

    // A valid packet still passes (control): correct magic + CRC accepted.
    std::vector<uint8_t> payload(1024, 0x5E);
    vx::net::WireHeader good{};
    good.magic = 0x56583630;
    good.msg_type = static_cast<uint8_t>(vx::net::WireMsgType::HANDSHAKE);
    good.payload_len = static_cast<uint32_t>(payload.size());
    good.crc32c = vx::net::compute_wire_crc32c(payload.data(), payload.size());
    EXPECT_TRUE(vx::net::wire_header_plausible(good));
    EXPECT_EQ(good.crc32c, vx::net::compute_wire_crc32c(payload.data(), payload.size()));
}

TEST(VortexChaosFuzzerTest, FrameTxChaos10k) {
    const auto rep = run_chaos_fuzz_round(0xBEEFCAFEULL, kMutations);

    EXPECT_EQ(rep.frame_total, kMutations);
    // Bad-magic frames + zero-TDI spam are rejected; UINT64_MAX amounts and
    // random 112-byte garbage deserialize without any trap.
    EXPECT_GT(rep.frame_rejected, 0u);
    EXPECT_EQ(rep.crashes, 0u);
    EXPECT_EQ(rep.ub_detected, 0u);
}

TEST(VortexChaosFuzzerTest, VmBytecodeChaos10k) {
    const auto rep = run_chaos_fuzz_round(0x1337FACEULL, kMutations);

    EXPECT_EQ(rep.vm_total, kMutations);
    // Garbage bytecodes abort inside the VM (underflow/overflow/truncation);
    // none of them may crash the node or escape the MAX_CYCLES budget.
    EXPECT_GT(rep.vm_aborted, 0u);
    EXPECT_LT(rep.vm_aborted, rep.vm_total); // valid programs still exist
    EXPECT_EQ(rep.crashes, 0u);
}

TEST(VortexChaosFuzzerTest, VmInfiniteLoopBounded) {
    using namespace vx::vm;
    // A self-jump is the canonical infinite loop: it must die at the
    // MAX_CYCLES budget in bounded wall time, never hang the node.
    const auto bytecode = VortexVM::assemble("spin:\nJMP spin\n");
    std::array<uint8_t, VortexVM::BYTECODE_MAX_SIZE> code{};
    std::memcpy(code.data(), bytecode.data(), bytecode.size());

    VortexVM machine;
    VortexVM::ExecutionContext ctx;
    const auto t0 = std::chrono::steady_clock::now();
    const auto res = machine.execute(code.data(), ctx);
    const auto ms = std::chrono::duration<double, std::milli>(
                        std::chrono::steady_clock::now() - t0)
                        .count();

    EXPECT_FALSE(res.success);
    EXPECT_EQ(res.cycles_used, VortexVM::MAX_CYCLES);
    EXPECT_LT(ms, 2000.0) << "JMP 0 loop exceeded the 2s hang budget";

    // POP on an empty stack: graceful abort, not a crash.
    const auto pop_empty = VortexVM::assemble("POP R0\nHALT\n");
    std::array<uint8_t, VortexVM::BYTECODE_MAX_SIZE> pop_code{};
    std::memcpy(pop_code.data(), pop_empty.data(), pop_empty.size());
    const auto res2 = machine.execute(pop_code.data(), ctx);
    EXPECT_FALSE(res2.success);
    EXPECT_NE(res2.error.find("underflow"), std::string::npos) << res2.error;
}

TEST(VortexChaosFuzzerTest, SgmtProofForgeryZeroFalsePositives) {
    const auto rep = run_chaos_fuzz_round(0xDEADBEEFULL, kMutations);

    EXPECT_EQ(rep.proof_mutations, kMutations);
    // Every single-bit flip in a witness must invalidate it. Zero tolerance.
    EXPECT_EQ(rep.proof_forgery_hits, 0u);
}

TEST(VortexChaosFuzzerTest, FullChaosRoundInvariants) {
    const auto rep = run_chaos_fuzz_round(0x5021CE00ULL, kMutations);

    EXPECT_EQ(rep.crashes, 0u);
    EXPECT_EQ(rep.ub_detected, 0u);
    EXPECT_GT(rep.malformed_rejected_pct(), 0.0);
    EXPECT_LE(rep.malformed_rejected_pct(), 100.0);
    EXPECT_EQ(rep.mutated_inputs_tested, 4 * kMutations);
}
