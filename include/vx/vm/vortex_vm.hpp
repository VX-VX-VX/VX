#pragma once

// VortexVM: Stateful VX-ASM VM with Landauer thermodynamic gas metering
// ().
//
// Every executed instruction records a hardware-level state snapshot
// (registers R0..R7 + top-of-stack) BEFORE and AFTER the operation, counts
// physically erased bits (1 -> 0 transitions) via __builtin_popcountll, and
// charges Landauer heat:
//
//     step_landauer_gas = base_opcode_cost
//                       + erased_bits * LANDAUER_KT_LN2_SCALED
//                       + hamming_flips * 3
//
// A two-pass assembler supports all 24 canonical opcodes (plus the legacy
// mnemonic aliases), ; / # comments, 0x hex literals, decimal literals and
// text jump labels (loop_start:).

#include "vx/blockchain/block.hpp"
#include <cstdint>
#include <vector>
#include <string>
#include <array>
#include <span>
#include <optional>
#include <functional>

namespace vx::vm {

/**
 * @brief VortexVM: 104-byte tail execution engine for VX L1.
 * 64-bit register + stack machine with 8 registers and 256-slot stack.
 */
class VortexVM {
public:
    static constexpr uint32_t MAX_CYCLES = 10000;
    static constexpr size_t STACK_SIZE = 256;
    static constexpr size_t NUM_REGISTERS = 8;
    static constexpr size_t BYTECODE_MAX_SIZE = 56;
    /// Landauer constant scaled: kT*ln2 per erased bit in micro-units.
    static constexpr uint64_t LANDAUER_KT_LN2_SCALED = 960;

    enum class Opcode : uint8_t {
        OP_NOP            = 0x00,
        OP_PUSH_IMM       = 0x01,
        OP_POP            = 0x02,
        OP_MOV            = 0x03,
        OP_LOAD_IMM       = 0x04,
        OP_ADD            = 0x05,
        OP_SUB            = 0x06,
        OP_MUL            = 0x07,
        OP_XOR            = 0x08,
        OP_AND            = 0x09,
 OP_OR = 0x0A,
        OP_ROTL           = 0x0B,
        OP_CMP            = 0x0C,
        OP_JMP            = 0x0D,
        OP_JZ             = 0x0E,
        OP_JNZ            = 0x0F,
        OP_SPONGE256      = 0x10, // SPONGE_HASH
        OP_GALOIS_PROJ    = 0x11,
        OP_VERIFY_COCOON  = 0x12,
        OP_BLOCK_HEIGHT   = 0x13,
        OP_TIMESTAMP      = 0x14,
        OP_CHECK_TDI      = 0x15,
        OP_HTLC_VERIFY    = 0x16,
        OP_ASSERT         = 0x17,
        OP_HALT           = 0x18,
 // additions (beyond the legacy 24-slot set)
        OP_DUP            = 0x19,
        OP_SWAP           = 0x1A,
        OP_GALOIS_MUL     = 0x1B, // GF(2^8) polynomial multiply, no division
        OP_SOLINAS_RED    = 0x1C, // Solinas modular reduction via shifts/masks
        OP_LOAD           = 0x1D, // LOAD Rn [addr-reg]: read VM scratch memory
        OP_STORE          = 0x1E, // STORE Rn [addr-reg]: write VM scratch memory
        OP_ASSERT_EQ      = 0x1F, // ASSERT_EQ Rn Rm: fail unless equal
    };

    struct VmStepTrace {
        uint32_t ip;
        Opcode op;
        uint64_t registers[NUM_REGISTERS];
        uint32_t stack_ptr;
        bool zf;
        bool cf;
        uint32_t cycles;
    };

 /// per-instruction thermodynamic trace record.
    struct InstructionTrace {
        uint32_t step_index;
        uint32_t pc;
        uint8_t opcode;
        std::string mnemonic;
        uint64_t r_snapshot[NUM_REGISTERS]; // registers BEFORE the step
        uint64_t stack_top;                 // top-of-stack BEFORE the step
        uint64_t erased_bits;               // 1->0 transitions (Landauer)
        uint64_t hamming_flips;             // total bit flips
        uint64_t cumulative_landauer_gas;   // running heat total
        uint64_t step_landauer_gas;         // heat charged for this step
    };

    struct ExecutionContext {
        uint64_t block_height = 0;
        uint64_t timestamp = 0;
        const blockchain::BlockView* block_view = nullptr;
        // Callback to check TDI for an amount
        std::function<bool(uint64_t)> check_tdi_fn;
 // preloaded register file (e.g. HTLC preimage in R0/R1).
        std::array<uint64_t, NUM_REGISTERS> initial_registers{};
    };

    struct ExecutionResult {
        bool success;
        uint32_t cycles_used;
        uint8_t state_root[32];
        std::string error;
        std::vector<VmStepTrace> trace;
 // extensions
        std::vector<InstructionTrace> landauer_trace;
        uint64_t total_landauer_gas = 0;    // sum of all step heat
        uint64_t total_erased_bits = 0;     // sum of all 1->0 transitions
        uint64_t total_hamming_flips = 0;   // sum of all bit flips
        uint64_t final_registers[NUM_REGISTERS]{0};
    };

    VortexVM() = default;

    ExecutionResult execute(const uint8_t bytecode[BYTECODE_MAX_SIZE], const ExecutionContext& ctx);

    // VX-ASM Assembler (two-pass: labels first, encode second)
    static std::vector<uint8_t> assemble(const std::string& source);
    // VX-ASM Disassembler
    static std::string disassemble(const uint8_t* bytecode, size_t len);

    // Canonical mnemonic for an opcode (used by trace + disassembler)
    static const char* mnemonic(Opcode op) noexcept;

 // ══ Atomic Cross-Shard HTLC Engine ══════════════════════════

    enum class HtlcOutcome : uint8_t {
        CLAIMED  = 1, // valid preimage, height <= timelock
        REFUNDED = 2, // timelock expired — funds return to the sender
        LOCKED   = 3, // no valid preimage and the timelock has not expired
    };

    struct HtlcContract {
        std::array<uint8_t, 32> hash_lock{};  // 4-act Galois attractor lock
        uint64_t timelock_height = 0;
        std::array<uint8_t, 42> recipient{};
        std::array<uint8_t, 42> refund{};
        std::vector<uint8_t> bytecode;        // canonical VX-ASM (<= 56 bytes)
        std::string asm_source;
        uint64_t secret_seed = 0;             // demo/scalar anchor of the preimage
    };

    struct HtlcSettleResult {
        HtlcOutcome outcome = HtlcOutcome::LOCKED;
        uint8_t vm_branch_marker = 0;   // R6 left by the executed contract branch
        ExecutionResult vm_trace;       // full Landauer trace of the branch
        std::array<uint8_t, 32> hash_lock{};
        uint64_t timelock_height = 0;
        uint64_t current_height = 0;
    };

    /// Build a hash time-locked contract: the 32-byte hash_lock is derived
    /// through the 4-act Galois attractor (Act I..IV over the secret, the
    /// recipient, the refund address and the timelock), then the canonical
    /// VX-ASM claim/refund contract is compiled to <= 56 bytes of bytecode.
    static HtlcContract create_htlc_contract(
        uint64_t secret_seed,
        const uint8_t recipient_addr[42],
        const uint8_t refund_addr[42],
        uint64_t timelock_height);

    /// Settle an HTLC swap: execute the contract bytecode in the VortexVM and
    /// classify the outcome —
    ///   valid preimage + current_height <= timelock  -> CLAIMED
    ///   current_height > timelock                    -> REFUNDED
    ///   otherwise                                    -> LOCKED (no branch).
    static HtlcSettleResult settle_htlc_swap(
        const std::vector<uint8_t>& contract_bytecode,
        std::span<const uint8_t> preimage_or_empty,
        uint64_t current_block_height);

private:
    uint64_t registers_[NUM_REGISTERS]{0};
    uint64_t stack_[STACK_SIZE]{0};
 uint64_t memory_[64]{0}; // VM scratch memory for LOAD/STORE
    uint32_t sp_ = 0;
    uint32_t ip_ = 0;
    bool zf_ = false;
    bool cf_ = false;
    uint32_t cycles_ = 0;

    void reset();
    void push(uint64_t val);
    uint64_t pop();
};

} // namespace vx::vm
