#pragma once

// Deterministic Chaos Fuzzer.
//
// One shared fuzz engine used by both test #15 (VortexChaosFuzzerTest) and
// the live RPC express round POST /api/security/chaos_fuzz. Every surface
// mirrors a real kernel boundary:
//
//   1. VX60 wire frame: WireHeader + payload, validated with
//      wire_header_plausible() + hardware CRC32C (bit flips, fake magic,
//      oversized payload_len, truncated buffers).
//   2. BlockFrame 65536 B / Transaction 112 B: magic + TDI spam gate with
//      zero and UINT64_MAX amounts/fees.
//   3. VortexVM: random bytecodes — POP on empty stack, stack overflow,
//      infinite JMP 0 loops (bounded by MAX_CYCLES / gas exhaustion).
//   4. SGMT GaloisTrieProof: random bit flips — a forged witness must
//      never verify (false positives == 0).
//
// Everything is deterministic: the RNG is seeded, so a failing seed can be
// replayed bit-for-bit.

#include <cstdint>

namespace vx::security {

struct ChaosReport {
    uint64_t mutated_inputs_tested = 0;

    // Surface 1: VX60 wire
    uint64_t wire_total = 0;
    uint64_t wire_rejected = 0;

    // Surface 2: block frames + transactions
    uint64_t frame_total = 0;
    uint64_t frame_rejected = 0;

    // Surface 3: VortexVM
    uint64_t vm_total = 0;
    uint64_t vm_aborted = 0; // bytecode rejected/aborted by the VM

    // Surface 4: SGMT proofs
    uint64_t proof_mutations = 0;
    uint64_t proof_forgery_hits = 0; // MUST stay 0

    // Hard invariants
    uint64_t crashes = 0;   // structurally impossible; kept for the report
    uint64_t ub_detected = 0;

    double malformed_rejected_pct() const noexcept {
        const uint64_t total = wire_total + frame_total + vm_total + proof_mutations;
        if (total == 0) return 100.0;
        const uint64_t rejected = wire_rejected + frame_rejected + vm_aborted +
                                  (proof_mutations - proof_forgery_hits);
        return 100.0 * static_cast<double>(rejected) / static_cast<double>(total);
    }
};

/// Run one deterministic chaos round: `mutations` fuzz inputs per surface.
/// seed drives the RNG (same seed -> same mutations).
ChaosReport run_chaos_fuzz_round(uint64_t seed, uint64_t mutations);

} // namespace vx::security
