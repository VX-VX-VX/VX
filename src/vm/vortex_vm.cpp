#include "vx/vm/vortex_vm.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/state/galois_trie.hpp" // gf256_mul over GF(2^8) for the HTLC acts
#include <cstring>
#include <cstdio>
#include <sstream>
#include <iomanip>
#include <algorithm>
#include <array>
#include <map>
#include <iostream>

namespace vx::vm {

namespace {
// 4-act Galois attractor digest (definition below, next to the
// HTLC engine) — shared by the VM opcode and the host-side settle logic.
std::array<uint8_t, 32> htlc_acts_digest(const uint8_t preimage[16]);
} // namespace

const char* VortexVM::mnemonic(Opcode op) noexcept {
    switch (op) {
        case Opcode::OP_NOP: return "NOP";
        case Opcode::OP_PUSH_IMM: return "PUSH";
        case Opcode::OP_POP: return "POP";
        case Opcode::OP_MOV: return "MOV";
        case Opcode::OP_LOAD_IMM: return "LOAD";
        case Opcode::OP_ADD: return "ADD";
        case Opcode::OP_SUB: return "SUB";
        case Opcode::OP_MUL: return "MUL";
        case Opcode::OP_XOR: return "XOR";
        case Opcode::OP_AND: return "AND";
        case Opcode::OP_OR: return "OR";
        case Opcode::OP_ROTL: return "ROTL";
        case Opcode::OP_CMP: return "CMP";
        case Opcode::OP_JMP: return "JMP";
        case Opcode::OP_JZ: return "JZ";
        case Opcode::OP_JNZ: return "JNZ";
        case Opcode::OP_SPONGE256: return "SPONGE_HASH";
        case Opcode::OP_GALOIS_PROJ: return "GALOIS_PROJ";
        case Opcode::OP_VERIFY_COCOON: return "VERIFY";
        case Opcode::OP_BLOCK_HEIGHT: return "HEIGHT";
        case Opcode::OP_TIMESTAMP: return "TIME";
        case Opcode::OP_CHECK_TDI: return "TDI";
        case Opcode::OP_HTLC_VERIFY: return "HTLC_VERIFY";
        case Opcode::OP_ASSERT: return "ASSERT";
        case Opcode::OP_HALT: return "HALT";
        case Opcode::OP_DUP: return "DUP";
        case Opcode::OP_SWAP: return "SWAP";
        case Opcode::OP_GALOIS_MUL: return "GALOIS_MUL";
        case Opcode::OP_SOLINAS_RED: return "SOLINAS_RED";
        case Opcode::OP_LOAD: return "LOAD_MEM";
        case Opcode::OP_STORE: return "STORE";
        case Opcode::OP_ASSERT_EQ: return "ASSERT_EQ";
    }
    return "UNKNOWN";
}

void VortexVM::reset() {
    std::memset(registers_, 0, sizeof(registers_));
    std::memset(stack_, 0, sizeof(stack_));
    std::memset(memory_, 0, sizeof(memory_));
    sp_ = 0;
    ip_ = 0;
    zf_ = false;
    cf_ = false;
    cycles_ = 0;
}

void VortexVM::push(uint64_t val) {
    if (sp_ >= STACK_SIZE) throw std::runtime_error("Stack overflow");
    stack_[sp_++] = val;
}

uint64_t VortexVM::pop() {
    if (sp_ == 0) throw std::runtime_error("Stack underflow");
    return stack_[--sp_];
}

// ── Landauer thermodynamic metering ───────────────────────────────

namespace {

// Snapshot of every mutable state word the VM can touch in one instruction.
struct LandauerSnapshot {
    uint64_t regs[VortexVM::NUM_REGISTERS];
    uint64_t stack_top;
    uint64_t sp_word; // stack pointer as a word (its changes cost flips too)
};

inline LandauerSnapshot snapshot(const uint64_t* regs, const uint64_t* stack,
                                 uint32_t sp) noexcept {
    LandauerSnapshot s{};
    std::memcpy(s.regs, regs, sizeof(s.regs));
    s.stack_top = (sp > 0) ? stack[sp - 1] : 0;
    s.sp_word = sp;
    return s;
}

// Compare two snapshots: count 1->0 transitions (physically erased bits)
// and total flips (Hamming distance). Uses only popcount — no division.
inline void landauer_delta(const LandauerSnapshot& old_s, const LandauerSnapshot& new_s,
                           uint64_t& erased_bits, uint64_t& hamming_flips) noexcept {
    uint64_t erased = 0, flips = 0;
    for (size_t i = 0; i < VortexVM::NUM_REGISTERS; ++i) {
        const uint64_t o = old_s.regs[i], n = new_s.regs[i];
        erased += static_cast<uint64_t>(__builtin_popcountll(o & ~n));
        flips += static_cast<uint64_t>(__builtin_popcountll(o ^ n));
    }
    const uint64_t os = old_s.stack_top, ns = new_s.stack_top;
    erased += static_cast<uint64_t>(__builtin_popcountll(os & ~ns));
    flips += static_cast<uint64_t>(__builtin_popcountll(os ^ ns));
    const uint64_t osp = old_s.sp_word, nsp = new_s.sp_word;
    erased += static_cast<uint64_t>(__builtin_popcountll(osp & ~nsp));
    flips += static_cast<uint64_t>(__builtin_popcountll(osp ^ nsp));
    erased_bits = erased;
    hamming_flips = flips;
}

// Base cost table per opcode (in micro-units of heat).
inline uint64_t base_opcode_cost(VortexVM::Opcode op) noexcept {
    using O = VortexVM::Opcode;
    switch (op) {
        case O::OP_NOP: return 1;
        case O::OP_PUSH_IMM: return 2;
        case O::OP_POP: return 1;
        case O::OP_MOV: return 1;
        case O::OP_LOAD_IMM: return 2;
        case O::OP_ADD: return 3;
        case O::OP_SUB: return 3;
        case O::OP_MUL: return 5;
        case O::OP_XOR: return 1;
        case O::OP_AND: return 1;
        case O::OP_OR: return 1;
        case O::OP_ROTL: return 1;
        case O::OP_CMP: return 1;
        case O::OP_JMP: return 1;
        case O::OP_JZ: return 1;
        case O::OP_JNZ: return 1;
        case O::OP_SPONGE256: return 25;
        case O::OP_GALOIS_PROJ: return 40;
        case O::OP_VERIFY_COCOON: return 30;
        case O::OP_BLOCK_HEIGHT: return 2;
        case O::OP_TIMESTAMP: return 2;
        case O::OP_CHECK_TDI: return 10;
        case O::OP_HTLC_VERIFY: return 35;
        case O::OP_ASSERT: return 1;
        case O::OP_HALT: return 1;
        case O::OP_DUP: return 1;
        case O::OP_SWAP: return 1;
        case O::OP_GALOIS_MUL: return 6;
        case O::OP_SOLINAS_RED: return 8;
        case O::OP_LOAD: return 2;
        case O::OP_STORE: return 2;
        case O::OP_ASSERT_EQ: return 1;
    }
    return 1;
}

} // namespace

VortexVM::ExecutionResult VortexVM::execute(const uint8_t bytecode[BYTECODE_MAX_SIZE], const ExecutionContext& ctx) {
    reset();
 // host-side register preload (e.g. HTLC preimage in R0/R1).
    std::memcpy(registers_, ctx.initial_registers.data(), sizeof(registers_));
    ExecutionResult result;
    result.success = true;

    uint64_t cumulative_landauer = 0;
    uint64_t total_erased = 0, total_flips = 0;

    try {
        while (cycles_ < MAX_CYCLES) {
            if (ip_ >= BYTECODE_MAX_SIZE) {
                result.success = false;
                result.error = "IP out of bounds";
                break;
            }

            Opcode op = static_cast<Opcode>(bytecode[ip_]);
            VmStepTrace step;
            step.ip = ip_;
            step.op = op;
            std::memcpy(step.registers, registers_, sizeof(registers_));
            step.stack_ptr = sp_;
            step.zf = zf_;
            step.cf = cf_;

 // BEFORE-snapshot for Landauer metering
            const LandauerSnapshot before = snapshot(registers_, stack_, sp_);

            // InstructionTrace (before-state)
            InstructionTrace lt;
            lt.step_index = static_cast<uint32_t>(result.landauer_trace.size());
            lt.pc = ip_;
            lt.opcode = static_cast<uint8_t>(op);
            lt.mnemonic = mnemonic(op);
            std::memcpy(lt.r_snapshot, registers_, sizeof(lt.r_snapshot));
            lt.stack_top = before.stack_top;
            lt.cumulative_landauer_gas = cumulative_landauer;

            uint32_t op_cycles = 1;
            ip_++;

            switch (op) {
                case Opcode::OP_NOP:
                    op_cycles = 1;
                    break;

                case Opcode::OP_PUSH_IMM: {
                    op_cycles = 2;
                    if (ip_ + 8 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_PUSH_IMM");
                    uint64_t imm;
                    std::memcpy(&imm, &bytecode[ip_], 8);
                    push(imm);
                    ip_ += 8;
                    break;
                }

                case Opcode::OP_POP: {
                    op_cycles = 1;
                    if (ip_ >= BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_POP");
                    uint8_t reg = bytecode[ip_++];
                    if (reg >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    registers_[reg] = pop();
                    break;
                }

                case Opcode::OP_DUP: {
                    op_cycles = 1;
                    if (sp_ == 0) throw std::runtime_error("Stack underflow");
                    push(stack_[sp_ - 1]);
                    break;
                }

                case Opcode::OP_SWAP: {
                    op_cycles = 1;
                    if (sp_ < 2) throw std::runtime_error("Stack underflow");
                    std::swap(stack_[sp_ - 1], stack_[sp_ - 2]);
                    break;
                }

                case Opcode::OP_MOV: {
                    op_cycles = 1;
                    if (ip_ + 2 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_MOV");
                    uint8_t dst = bytecode[ip_++];
                    uint8_t src = bytecode[ip_++];
                    if (dst >= NUM_REGISTERS || src >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    registers_[dst] = registers_[src];
                    break;
                }

                case Opcode::OP_LOAD_IMM: {
                    op_cycles = 2;
                    if (ip_ + 9 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_LOAD_IMM");
                    uint8_t reg = bytecode[ip_++];
                    uint64_t imm;
                    std::memcpy(&imm, &bytecode[ip_], 8);
                    if (reg >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    registers_[reg] = imm;
                    ip_ += 8;
                    break;
                }

                case Opcode::OP_ADD: {
                    op_cycles = 1;
                    if (ip_ + 2 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_ADD");
                    uint8_t dst = bytecode[ip_++];
                    uint8_t src = bytecode[ip_++];
                    if (dst >= NUM_REGISTERS || src >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    uint64_t a = registers_[dst];
                    uint64_t b = registers_[src];
                    registers_[dst] = a + b;
                    zf_ = (registers_[dst] == 0);
                    cf_ = (registers_[dst] < a);
                    break;
                }

                case Opcode::OP_SUB: {
                    op_cycles = 1;
                    if (ip_ + 2 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_SUB");
                    uint8_t dst = bytecode[ip_++];
                    uint8_t src = bytecode[ip_++];
                    if (dst >= NUM_REGISTERS || src >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    uint64_t a = registers_[dst];
                    uint64_t b = registers_[src];
                    registers_[dst] = a - b;
                    zf_ = (registers_[dst] == 0);
                    cf_ = (a < b);
                    break;
                }

                case Opcode::OP_MUL: {
                    op_cycles = 2;
                    if (ip_ + 2 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_MUL");
                    uint8_t dst = bytecode[ip_++];
                    uint8_t src = bytecode[ip_++];
                    if (dst >= NUM_REGISTERS || src >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    registers_[dst] = registers_[dst] * registers_[src];
                    break;
                }

                case Opcode::OP_XOR: {
                    op_cycles = 1;
                    if (ip_ + 2 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_XOR");
                    uint8_t dst = bytecode[ip_++];
                    uint8_t src = bytecode[ip_++];
                    if (dst >= NUM_REGISTERS || src >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    registers_[dst] ^= registers_[src];
                    zf_ = (registers_[dst] == 0);
                    break;
                }

                case Opcode::OP_AND: {
                    op_cycles = 1;
                    if (ip_ + 2 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_AND");
                    uint8_t dst = bytecode[ip_++];
                    uint8_t src = bytecode[ip_++];
                    if (dst >= NUM_REGISTERS || src >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    registers_[dst] &= registers_[src];
                    zf_ = (registers_[dst] == 0);
                    break;
                }

                case Opcode::OP_OR: {
                    op_cycles = 1;
                    if (ip_ + 2 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_OR");
                    uint8_t dst = bytecode[ip_++];
                    uint8_t src = bytecode[ip_++];
                    if (dst >= NUM_REGISTERS || src >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    registers_[dst] |= registers_[src];
                    zf_ = (registers_[dst] == 0);
                    break;
                }

                case Opcode::OP_ROTL: {
                    op_cycles = 1;
                    if (ip_ + 2 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_ROTL");
                    uint8_t reg = bytecode[ip_++];
                    uint8_t imm8 = bytecode[ip_++];
                    if (reg >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    uint64_t v = registers_[reg];
                    unsigned int r = imm8 & 63;
                    registers_[reg] = (v << r) | (v >> ((64 - r) & 63));
                    break;
                }

                // GF(2^8) carry-less multiply per byte-lane, no division
                // (law 3 of the directive: bit shifts + masks only).
                case Opcode::OP_GALOIS_MUL: {
                    op_cycles = 2;
                    if (ip_ + 2 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_GALOIS_MUL");
                    uint8_t dst = bytecode[ip_++];
                    uint8_t src = bytecode[ip_++];
                    if (dst >= NUM_REGISTERS || src >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    const uint64_t a = registers_[dst];
                    const uint64_t b = registers_[src];
                    uint64_t acc = 0;
                    for (int byte_i = 0; byte_i < 8; ++byte_i) {
                        const uint8_t x = static_cast<uint8_t>(a >> (byte_i * 8));
                        const uint8_t y = static_cast<uint8_t>(b >> (byte_i * 8));
                        // carry-less multiply over GF(2^8) modulus 0x11B
                        uint16_t p = 0;
                        for (int bit = 0; bit < 8; ++bit) {
                            if ((y >> bit) & 1) p ^= static_cast<uint16_t>(x) << bit;
                        }
                        // reduce by 0x11B (x^8 + x^4 + x^3 + x + 1):
                        // fold bits 8..15 down, zero-division-free
                        {
                            uint16_t t = p;
                            for (int k = 15; k >= 8; --k) {
                                if ((t >> k) & 1) {
                                    t = static_cast<uint16_t>(t ^ (0x11B << (k - 8)));
                                }
                            }
                            p = static_cast<uint16_t>(t & 0xFF);
                        }
                        acc |= static_cast<uint64_t>(p) << (byte_i * 8);
                    }
                    registers_[dst] = acc;
                    break;
                }

                // Solinas-style modular reduction using only shifts/masks
                // (directive law 3: no hardware division in hot paths).
                case Opcode::OP_SOLINAS_RED: {
                    op_cycles = 2;
                    if (ip_ + 2 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_SOLINAS_RED");
                    uint8_t dst = bytecode[ip_++];
                    uint8_t src = bytecode[ip_++];
                    if (dst >= NUM_REGISTERS || src >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    const uint64_t v = registers_[src];
                    // Solinas mod (2^61 - 1) via shifts and masks:
                    // x = hi<<61 | lo  where lo = x & (2^61-1), hi = x >> 61
                    const uint64_t lo = v & ((1ULL << 61) - 1);
                    const uint64_t hi = v >> 61;
                    registers_[dst] = lo + hi; // <= 2^61 - 1 + 7 => one fold
                    if (registers_[dst] >= (1ULL << 61) - 1) {
                        registers_[dst] -= (1ULL << 61) - 1;
                    }
                    break;
                }

                case Opcode::OP_LOAD: {
                    op_cycles = 2;
                    if (ip_ + 2 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_LOAD");
                    uint8_t dst = bytecode[ip_++];
                    uint8_t addr = bytecode[ip_++];
                    if (dst >= NUM_REGISTERS || addr >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    registers_[dst] = memory_[registers_[addr] & 63];
                    break;
                }

                case Opcode::OP_STORE: {
                    op_cycles = 2;
                    if (ip_ + 2 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_STORE");
                    uint8_t src = bytecode[ip_++];
                    uint8_t addr = bytecode[ip_++];
                    if (src >= NUM_REGISTERS || addr >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    memory_[registers_[addr] & 63] = registers_[src];
                    break;
                }

                case Opcode::OP_CMP: {
                    op_cycles = 1;
                    if (ip_ + 2 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_CMP");
                    uint8_t r1 = bytecode[ip_++];
                    uint8_t r2 = bytecode[ip_++];
                    if (r1 >= NUM_REGISTERS || r2 >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    uint64_t a = registers_[r1];
                    uint64_t b = registers_[r2];
                    zf_ = (a == b);
                    cf_ = (a < b);
                    break;
                }

                case Opcode::OP_JMP: {
                    op_cycles = 1;
                    if (ip_ >= BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_JMP");
                    int8_t offset = static_cast<int8_t>(bytecode[ip_++]);
                    ip_ = static_cast<uint32_t>(static_cast<int32_t>(ip_) + offset);
                    break;
                }

                case Opcode::OP_JZ: {
                    op_cycles = 1;
                    if (ip_ >= BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_JZ");
                    int8_t offset = static_cast<int8_t>(bytecode[ip_++]);
                    if (zf_) ip_ = static_cast<uint32_t>(static_cast<int32_t>(ip_) + offset);
                    break;
                }

                case Opcode::OP_JNZ: {
                    op_cycles = 1;
                    if (ip_ >= BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_JNZ");
                    int8_t offset = static_cast<int8_t>(bytecode[ip_++]);
                    if (!zf_) ip_ = static_cast<uint32_t>(static_cast<int32_t>(ip_) + offset);
                    break;
                }

                case Opcode::OP_SPONGE256: {
                    op_cycles = 25;
                    blockchain::VortexSponge256 sponge;
                    sponge.absorb(reinterpret_cast<const uint8_t*>(&registers_[0]), 32);
                    uint8_t digest[32];
                    sponge.finalize(digest);
                    std::memcpy(&registers_[0], digest, 32);
                    break;
                }

                case Opcode::OP_GALOIS_PROJ: {
                    op_cycles = 40;
                    uint64_t attractor_x = 0;
                    if (ctx.block_view) {
                        std::memcpy(&attractor_x, ctx.block_view->header().attractor_coords, 8);
                    }
                    registers_[1] = registers_[0] ^ attractor_x;
                    break;
                }

                case Opcode::OP_VERIFY_COCOON: {
                    op_cycles = 30;
                    uint64_t tx_idx = registers_[0];
                    registers_[1] = 0;
                    if (ctx.block_view && tx_idx < ctx.block_view->tx_count()) {
                        if (blockchain::verify_transaction_proof(ctx.block_view->tx(tx_idx))) {
                            registers_[1] = 1;
                        }
                    }
                    break;
                }

                case Opcode::OP_BLOCK_HEIGHT: {
                    op_cycles = 2;
                    if (ip_ >= BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_BLOCK_HEIGHT");
                    uint8_t reg = bytecode[ip_++];
                    if (reg >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    registers_[reg] = ctx.block_height;
                    break;
                }

                case Opcode::OP_TIMESTAMP: {
                    op_cycles = 2;
                    if (ip_ >= BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_TIMESTAMP");
                    uint8_t reg = bytecode[ip_++];
                    if (reg >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    registers_[reg] = ctx.timestamp;
                    break;
                }

                case Opcode::OP_CHECK_TDI: {
                    op_cycles = 10;
                    if (ip_ >= BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_CHECK_TDI");
                    uint8_t reg = bytecode[ip_++];
                    if (reg >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    if (ctx.check_tdi_fn) {
                        zf_ = ctx.check_tdi_fn(registers_[reg]);
                    } else {
                        zf_ = false;
                    }
                    break;
                }

                case Opcode::OP_HTLC_VERIFY: {
                    op_cycles = 35;
                    uint8_t preimage[16], hashlock[16];
                    std::memcpy(preimage, &registers_[0], 16);
                    std::memcpy(hashlock, &registers_[2], 16);
                    uint64_t timelock = registers_[4];

                    // 4-act Galois attractor (Act I..IV) over the preimage —
                    // identical chain to create_htlc_contract/settle.
                    const std::array<uint8_t, 32> digest = htlc_acts_digest(preimage);

 // HTLC engine semantics:
                    //   zf = preimage unlocks the hash lock (CLAIM possible)
                    //   cf = timelock expired (REFUND possible)
                    const bool hash_ok = (std::memcmp(digest.data(), hashlock, 16) == 0);
                    const bool time_expired = (ctx.block_height > timelock);

                    zf_ = hash_ok;
                    cf_ = time_expired;
                    break;
                }

                case Opcode::OP_ASSERT: {
                    op_cycles = 1;
                    if (!pop()) throw std::runtime_error("Assertion failed");
                    break;
                }

                case Opcode::OP_ASSERT_EQ: {
                    op_cycles = 1;
                    if (ip_ + 2 > BYTECODE_MAX_SIZE) throw std::runtime_error("Truncated OP_ASSERT_EQ");
                    uint8_t r1 = bytecode[ip_++];
                    uint8_t r2 = bytecode[ip_++];
                    if (r1 >= NUM_REGISTERS || r2 >= NUM_REGISTERS) throw std::runtime_error("Invalid register");
                    if (registers_[r1] != registers_[r2]) throw std::runtime_error("Assertion failed (ASSERT_EQ)");
                    break;
                }

                case Opcode::OP_HALT: {
                    op_cycles = 1;
                    blockchain::VortexSponge256 sponge;
                    sponge.absorb(reinterpret_cast<const uint8_t*>(registers_), NUM_REGISTERS * 8);
                    if (sp_ > 0) {
                        sponge.absorb(reinterpret_cast<const uint8_t*>(&stack_[sp_ - 1]), 8);
                    }
                    sponge.finalize(result.state_root);
                    cycles_ += op_cycles;
                    step.cycles = cycles_;
                    result.trace.push_back(step);

                    // Landauer record for the final HALT step
                    {
                        const LandauerSnapshot after = snapshot(registers_, stack_, sp_);
                        uint64_t erased = 0, flips = 0;
                        landauer_delta(before, after, erased, flips);
                        const uint64_t step_gas =
                            base_opcode_cost(op) + erased * LANDAUER_KT_LN2_SCALED + flips * 3;
                        cumulative_landauer += step_gas;
                        total_erased += erased;
                        total_flips += flips;
                        lt.erased_bits = erased;
                        lt.hamming_flips = flips;
                        lt.step_landauer_gas = step_gas;
                        lt.cumulative_landauer_gas = cumulative_landauer;
                        result.landauer_trace.push_back(lt);
                    }
                    goto done;
                }

                default:
                    throw std::runtime_error("Unknown opcode");
            }

            cycles_ += op_cycles;
            step.cycles = cycles_;
            result.trace.push_back(step);

 // AFTER-snapshot -> Landauer heat charge
            {
                const LandauerSnapshot after = snapshot(registers_, stack_, sp_);
                uint64_t erased = 0, flips = 0;
                landauer_delta(before, after, erased, flips);
                const uint64_t step_gas =
                    base_opcode_cost(op) + erased * LANDAUER_KT_LN2_SCALED + flips * 3;
                cumulative_landauer += step_gas;
                total_erased += erased;
                total_flips += flips;
                lt.erased_bits = erased;
                lt.hamming_flips = flips;
                lt.step_landauer_gas = step_gas;
                lt.cumulative_landauer_gas = cumulative_landauer;
                result.landauer_trace.push_back(lt);
            }

            if (cycles_ > MAX_CYCLES) {
                result.success = false;
                result.error = "Cycle limit exceeded";
                break;
            }
        }
    } catch (const std::exception& e) {
        result.success = false;
        result.error = e.what();
    }

    // A program that exhausts the cycle budget (e.g. an infinite JMP 0 loop)
    // must never report success — the loop condition alone exits silently.
    if (result.success && cycles_ >= MAX_CYCLES) {
        result.success = false;
        result.error = "Cycle limit exceeded";
    }

done:
    result.cycles_used = cycles_;
    result.total_landauer_gas = cumulative_landauer;
    result.total_erased_bits = total_erased;
    result.total_hamming_flips = total_flips;
    std::memcpy(result.final_registers, registers_, sizeof(result.final_registers));
    return result;
}

// ── Two-pass VX-ASM assembler ───────────────────────────────────────────────

namespace {

struct AsmError : std::runtime_error { using std::runtime_error::runtime_error; };

uint64_t parse_number(const std::string& tok) {
    if (tok.rfind("0x", 0) == 0 || tok.rfind("0X", 0) == 0) {
        return std::stoull(tok, nullptr, 16);
    }
    return std::stoull(tok, nullptr, 10);
}

uint8_t parse_reg(const std::string& s) {
    if (s.size() < 2 || (s[0] != 'R' && s[0] != 'r')) throw AsmError("Invalid register: " + s);
    const int n = std::stoi(s.substr(1));
    if (n < 0 || n > 7) throw AsmError("Register out of range R0..R7: " + s);
    return static_cast<uint8_t>(n);
}

void append_imm64(std::vector<uint8_t>& bc, uint64_t v) {
    for (int i = 0; i < 8; ++i) { bc.push_back(static_cast<uint8_t>(v & 0xFF)); v >>= 8; }
}

} // namespace

std::vector<uint8_t> VortexVM::assemble(const std::string& source) {
    // PASS 1: strip comments, tokenize, collect labels + emit opcodes with
    // fixup placeholders. PASS 2: resolve label addresses into jump offsets.
    std::vector<uint8_t> bytecode;
    std::map<std::string, uint32_t> labels;
    struct Fixup { uint32_t pos; std::string label; };
    std::vector<Fixup> fixups;

    std::stringstream ss(source);
    std::string line;
    while (std::getline(ss, line)) {
        // Both ';' and '#' start a comment
        const size_t c1 = line.find(';');
        if (c1 != std::string::npos) line = line.substr(0, c1);
        const size_t c2 = line.find('#');
        if (c2 != std::string::npos) line = line.substr(0, c2);

        std::stringstream ls(line);
        std::string token;
        if (!(ls >> token)) continue;

        if (token.back() == ':') {
            const std::string label = token.substr(0, token.size() - 1);
            if (labels.count(label)) throw AsmError("Duplicate label: " + label);
            labels[label] = static_cast<uint32_t>(bytecode.size());
            continue;
        }

        std::transform(token.begin(), token.end(), token.begin(), ::toupper);
        const uint32_t op_start = static_cast<uint32_t>(bytecode.size());

        // Canonical + legacy aliases both accepted.
        if (token == "NOP") {
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_NOP));
        } else if (token == "PUSH") {
            std::string num; ls >> num;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_PUSH_IMM));
            append_imm64(bytecode, parse_number(num));
        } else if (token == "POP") {
            std::string reg; ls >> reg;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_POP));
            bytecode.push_back(parse_reg(reg));
        } else if (token == "DUP") {
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_DUP));
        } else if (token == "SWAP") {
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_SWAP));
        } else if (token == "MOV") {
            std::string r1, r2; ls >> r1 >> r2;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_MOV));
            bytecode.push_back(parse_reg(r1));
            bytecode.push_back(parse_reg(r2));
        } else if (token == "LOAD_IMM" || token == "LOAD") {
            // LOAD takes a register + an immediate address (scratch memory);
            // LOAD_IMM takes register + 64-bit immediate. Distinguish by the
            // operand kind: if the second token is a register -> LOAD.
            std::string r1, second; ls >> r1 >> second;
            if (second.empty()) throw AsmError("LOAD requires 2 operands");
            const bool second_is_reg =
                (second[0] == 'R' || second[0] == 'r') && second.size() <= 2;
            if (token == "LOAD" && second_is_reg) {
                bytecode.push_back(static_cast<uint8_t>(Opcode::OP_LOAD));
                bytecode.push_back(parse_reg(r1));
                bytecode.push_back(parse_reg(second));
            } else if (token == "LOAD" && !second_is_reg && second.find_first_not_of("0123456789abcdefABCDEFxX") == std::string::npos && second.rfind("0x", 0) == 0) {
                // LOAD Rn 0xIMM -> treat as LOAD_IMM (directive mnemonics: LOAD)
                bytecode.push_back(static_cast<uint8_t>(Opcode::OP_LOAD_IMM));
                bytecode.push_back(parse_reg(r1));
                append_imm64(bytecode, parse_number(second));
            } else if (token == "LOAD_IMM" || (!second_is_reg)) {
                bytecode.push_back(static_cast<uint8_t>(Opcode::OP_LOAD_IMM));
                bytecode.push_back(parse_reg(r1));
                append_imm64(bytecode, parse_number(second));
            } else {
                bytecode.push_back(static_cast<uint8_t>(Opcode::OP_LOAD));
                bytecode.push_back(parse_reg(r1));
                bytecode.push_back(parse_reg(second));
            }
        } else if (token == "STORE") {
            std::string r1, r2; ls >> r1 >> r2;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_STORE));
            bytecode.push_back(parse_reg(r1));
            bytecode.push_back(parse_reg(r2));
        } else if (token == "ADD") {
            std::string r1, r2; ls >> r1 >> r2;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_ADD));
            bytecode.push_back(parse_reg(r1));
            bytecode.push_back(parse_reg(r2));
        } else if (token == "SUB") {
            std::string r1, r2; ls >> r1 >> r2;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_SUB));
            bytecode.push_back(parse_reg(r1));
            bytecode.push_back(parse_reg(r2));
        } else if (token == "MUL") {
            std::string r1, r2; ls >> r1 >> r2;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_MUL));
            bytecode.push_back(parse_reg(r1));
            bytecode.push_back(parse_reg(r2));
        } else if (token == "XOR") {
            std::string r1, r2; ls >> r1 >> r2;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_XOR));
            bytecode.push_back(parse_reg(r1));
            bytecode.push_back(parse_reg(r2));
        } else if (token == "AND") {
            std::string r1, r2; ls >> r1 >> r2;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_AND));
            bytecode.push_back(parse_reg(r1));
            bytecode.push_back(parse_reg(r2));
        } else if (token == "OR") {
            std::string r1, r2; ls >> r1 >> r2;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_OR));
            bytecode.push_back(parse_reg(r1));
            bytecode.push_back(parse_reg(r2));
        } else if (token == "ROTL") {
            std::string r1, num; ls >> r1 >> num;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_ROTL));
            bytecode.push_back(parse_reg(r1));
            bytecode.push_back(static_cast<uint8_t>(parse_number(num) & 63));
        } else if (token == "GALOIS_MUL") {
            std::string r1, r2; ls >> r1 >> r2;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_GALOIS_MUL));
            bytecode.push_back(parse_reg(r1));
            bytecode.push_back(parse_reg(r2));
        } else if (token == "SOLINAS_RED") {
            std::string r1, r2; ls >> r1 >> r2;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_SOLINAS_RED));
            bytecode.push_back(parse_reg(r1));
            bytecode.push_back(parse_reg(r2));
        } else if (token == "SPONGE_HASH" || token == "SPONGE" || token == "SPONGE256") {
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_SPONGE256));
        } else if (token == "GALOIS_PROJ" || token == "GALOIS") {
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_GALOIS_PROJ));
        } else if (token == "VERIFY") {
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_VERIFY_COCOON));
        } else if (token == "HEIGHT") {
            std::string r1; ls >> r1;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_BLOCK_HEIGHT));
            bytecode.push_back(parse_reg(r1));
        } else if (token == "TIME") {
            std::string r1; ls >> r1;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_TIMESTAMP));
            bytecode.push_back(parse_reg(r1));
        } else if (token == "TDI") {
            std::string r1; ls >> r1;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_CHECK_TDI));
            bytecode.push_back(parse_reg(r1));
        } else if (token == "JMP") {
            std::string label; ls >> label;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_JMP));
            fixups.push_back({static_cast<uint32_t>(bytecode.size()), label});
            bytecode.push_back(0);
        } else if (token == "JZ") {
            std::string label; ls >> label;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_JZ));
            fixups.push_back({static_cast<uint32_t>(bytecode.size()), label});
            bytecode.push_back(0);
        } else if (token == "JNZ") {
            std::string label; ls >> label;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_JNZ));
            fixups.push_back({static_cast<uint32_t>(bytecode.size()), label});
            bytecode.push_back(0);
        } else if (token == "HTLC_VERIFY" || token == "HTLC") {
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_HTLC_VERIFY));
        } else if (token == "ASSERT_EQ") {
            std::string r1, r2; ls >> r1 >> r2;
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_ASSERT_EQ));
            bytecode.push_back(parse_reg(r1));
            bytecode.push_back(parse_reg(r2));
        } else if (token == "ASSERT") {
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_ASSERT));
        } else if (token == "HALT") {
            bytecode.push_back(static_cast<uint8_t>(Opcode::OP_HALT));
        } else {
            throw AsmError("Unknown mnemonic: " + token);
        }
        (void)op_start;
    }

    // PASS 2: resolve label fixups into relative int8 offsets.
    for (const auto& f : fixups) {
        const auto it = labels.find(f.label);
        if (it == labels.end()) throw AsmError("Label not found: " + f.label);
        const int32_t offset =
            static_cast<int32_t>(it->second) - static_cast<int32_t>(f.pos + 1);
        if (offset < -128 || offset > 127) throw AsmError("Jump offset too large");
        bytecode[f.pos] = static_cast<uint8_t>(offset);
    }

    if (bytecode.size() > BYTECODE_MAX_SIZE) {
        throw AsmError("Bytecode exceeds 56-byte frame limit (" +
                       std::to_string(bytecode.size()) + " bytes)");
    }
    return bytecode;
}

std::string VortexVM::disassemble(const uint8_t* bytecode, size_t len) {
    std::stringstream ss;
    size_t i = 0;
    while (i < len) {
        ss << std::setw(4) << std::setfill('0') << i << ": ";
        const Opcode op = static_cast<Opcode>(bytecode[i++]);
        switch (op) {
            case Opcode::OP_NOP: ss << "NOP"; break;
            case Opcode::OP_PUSH_IMM: {
                uint64_t imm; std::memcpy(&imm, &bytecode[i], 8); i += 8;
                ss << "PUSH 0x" << std::hex << imm; break;
            }
            case Opcode::OP_POP: ss << "POP R" << (int)bytecode[i++]; break;
            case Opcode::OP_DUP: ss << "DUP"; break;
            case Opcode::OP_SWAP: ss << "SWAP"; break;
            case Opcode::OP_MOV: { uint8_t a = bytecode[i++]; uint8_t b = bytecode[i++]; ss << "MOV R" << (int)a << " R" << (int)b; break; }
            case Opcode::OP_LOAD_IMM: {
                int r = bytecode[i++];
                uint64_t imm; std::memcpy(&imm, &bytecode[i], 8); i += 8;
                ss << "LOAD R" << r << " 0x" << std::hex << imm; break;
            }
            case Opcode::OP_LOAD: { uint8_t a = bytecode[i++]; uint8_t b = bytecode[i++]; ss << "LOAD_MEM R" << (int)a << " R" << (int)b; break; }
            case Opcode::OP_STORE: { uint8_t a = bytecode[i++]; uint8_t b = bytecode[i++]; ss << "STORE R" << (int)a << " R" << (int)b; break; }
            case Opcode::OP_ADD: { uint8_t a = bytecode[i++]; uint8_t b = bytecode[i++]; ss << "ADD R" << (int)a << " R" << (int)b; break; }
            case Opcode::OP_SUB: { uint8_t a = bytecode[i++]; uint8_t b = bytecode[i++]; ss << "SUB R" << (int)a << " R" << (int)b; break; }
            case Opcode::OP_MUL: { uint8_t a = bytecode[i++]; uint8_t b = bytecode[i++]; ss << "MUL R" << (int)a << " R" << (int)b; break; }
            case Opcode::OP_XOR: { uint8_t a = bytecode[i++]; uint8_t b = bytecode[i++]; ss << "XOR R" << (int)a << " R" << (int)b; break; }
            case Opcode::OP_AND: { uint8_t a = bytecode[i++]; uint8_t b = bytecode[i++]; ss << "AND R" << (int)a << " R" << (int)b; break; }
            case Opcode::OP_OR: { uint8_t a = bytecode[i++]; uint8_t b = bytecode[i++]; ss << "OR R" << (int)a << " R" << (int)b; break; }
            case Opcode::OP_ROTL: { uint8_t a = bytecode[i++]; uint8_t b = bytecode[i++]; ss << "ROTL R" << (int)a << " " << (int)b; break; }
            case Opcode::OP_GALOIS_MUL: { uint8_t a = bytecode[i++]; uint8_t b = bytecode[i++]; ss << "GALOIS_MUL R" << (int)a << " R" << (int)b; break; }
            case Opcode::OP_SOLINAS_RED: { uint8_t a = bytecode[i++]; uint8_t b = bytecode[i++]; ss << "SOLINAS_RED R" << (int)a << " R" << (int)b; break; }
            case Opcode::OP_CMP: { uint8_t a = bytecode[i++]; uint8_t b = bytecode[i++]; ss << "CMP R" << (int)a << " R" << (int)b; break; }
            case Opcode::OP_JMP: ss << "JMP " << (int)(int8_t)bytecode[i++]; break;
            case Opcode::OP_JZ: ss << "JZ " << (int)(int8_t)bytecode[i++]; break;
            case Opcode::OP_JNZ: ss << "JNZ " << (int)(int8_t)bytecode[i++]; break;
            case Opcode::OP_SPONGE256: ss << "SPONGE_HASH"; break;
            case Opcode::OP_GALOIS_PROJ: ss << "GALOIS_PROJ"; break;
            case Opcode::OP_VERIFY_COCOON: ss << "VERIFY"; break;
            case Opcode::OP_BLOCK_HEIGHT: ss << "HEIGHT R" << (int)bytecode[i++]; break;
            case Opcode::OP_TIMESTAMP: ss << "TIME R" << (int)bytecode[i++]; break;
            case Opcode::OP_CHECK_TDI: ss << "TDI R" << (int)bytecode[i++]; break;
            case Opcode::OP_HTLC_VERIFY: ss << "HTLC_VERIFY"; break;
            case Opcode::OP_ASSERT: ss << "ASSERT"; break;
            case Opcode::OP_ASSERT_EQ: { uint8_t a = bytecode[i++]; uint8_t b = bytecode[i++]; ss << "ASSERT_EQ R" << (int)a << " R" << (int)b; break; }
            case Opcode::OP_HALT: ss << "HALT"; break;
            default: ss << "UNKNOWN (0x" << std::hex << (int)op << ")"; break;
        }
        ss << "\n";
    }
    return ss.str();
}

// ════════════════════════════════════════════════════════════════════════════
// Atomic Cross-Shard HTLC Engine
// ════════════════════════════════════════════════════════════════════════════

namespace {

// 4-act Galois attractor (Act I..IV) — the hash lock is a pure function of
// the preimage (the essence of an HTLC), folded through GF(2^8) mixing with
// no division anywhere. The VortexVM's OP_HTLC_VERIFY runs the exact same
// chain, so the contract bytecode is self-contained.
std::array<uint8_t, 32> htlc_acts_digest(const uint8_t preimage[16]) {
    const auto fold = [](std::array<uint8_t, 32>& s) {
        // GF(2^8) attractor fold: multiply every byte into its +7 neighbour.
        std::array<uint8_t, 32> out{};
        for (size_t i = 0; i < 32; ++i) {
            out[i] = vx::state::gf256_mul(s[i], s[(i + 7) & 31]);
        }
        s = out;
    };
    std::array<uint8_t, 32> s{};
    {
        blockchain::VortexSponge256 sp; // Act I — absorb the preimage
        const uint8_t dom[] = "VXHTLC_ACT1";
        sp.absorb(dom, sizeof(dom) - 1);
        sp.absorb(preimage, 16);
        sp.finalize(s.data());
    }
    {
        fold(s); // Act II
        blockchain::VortexSponge256 sp;
        const uint8_t dom[] = "VXHTLC_ACT2";
        sp.absorb(dom, sizeof(dom) - 1);
        sp.absorb(s.data(), 32);
        sp.finalize(s.data());
    }
    {
        fold(s); // Act III
        blockchain::VortexSponge256 sp;
        const uint8_t dom[] = "VXHTLC_ACT3";
        sp.absorb(dom, sizeof(dom) - 1);
        sp.absorb(s.data(), 32);
        sp.finalize(s.data());
    }
    {
        fold(s); // Act IV — the lock seals
        blockchain::VortexSponge256 sp;
        const uint8_t dom[] = "VXHTLC_ACT4";
        sp.absorb(dom, sizeof(dom) - 1);
        sp.absorb(s.data(), 32);
        sp.finalize(s.data());
    }
    return s;
}

// Canonical 55-byte contract:
//   LOAD_IMM R2/R3  <- hash lock halves (R2 = lo, R3 = hi)
//   LOAD_IMM R4     <- timelock height
//   HTLC_VERIFY       (zf = preimage ok, cf = timelock expired)
//   JZ refund_branch  (preimage invalid -> refund or still-locked)
//   LOAD_IMM R6 1     CLAIM branch marker
//   HALT
// refund_branch:
//   LOAD_IMM R6 2     REFUND branch marker (cf decides in the settle report)
//   HALT
std::vector<uint8_t> build_htlc_bytecode(uint64_t lock_lo, uint64_t lock_hi,
                                         uint64_t timelock) {
    std::vector<uint8_t> bc;
    auto imm = [&bc](uint8_t reg, uint64_t v) {
        bc.push_back(static_cast<uint8_t>(VortexVM::Opcode::OP_LOAD_IMM));
        bc.push_back(reg);
        for (int i = 0; i < 8; ++i) bc.push_back(static_cast<uint8_t>((v >> (8 * i)) & 0xFF));
    };
    imm(2, lock_lo);
    imm(3, lock_hi);
    imm(4, timelock);
    bc.push_back(static_cast<uint8_t>(VortexVM::Opcode::OP_HTLC_VERIFY)); // 30
    bc.push_back(static_cast<uint8_t>(VortexVM::Opcode::OP_JNZ));         // 31
    bc.push_back(0x0B); // 32: jump target 44 = 33 + 11 (refund branch)
    imm(6, 1);          // 33..42 CLAIM branch marker
    bc.push_back(static_cast<uint8_t>(VortexVM::Opcode::OP_HALT));        // 43
    imm(6, 2);          // 44..53 REFUND branch marker
    bc.push_back(static_cast<uint8_t>(VortexVM::Opcode::OP_HALT));        // 54
    return bc;
}

} // namespace

VortexVM::HtlcContract VortexVM::create_htlc_contract(
    uint64_t secret_seed,
    const uint8_t recipient_addr[42],
    const uint8_t refund_addr[42],
    uint64_t timelock_height) {
    HtlcContract c;
    c.secret_seed = secret_seed;
    c.timelock_height = timelock_height;
    std::memcpy(c.recipient.data(), recipient_addr, 42);
    std::memcpy(c.refund.data(), refund_addr, 42);

    // Canonical preimage: 16 bytes derived from the secret seed
    // (LE64(secret) || LE64(~secret)). The 4-act Galois attractor then
    // derives the hash lock purely from the preimage.
    uint8_t preimage[16];
    const uint64_t pre_lo = secret_seed;
    const uint64_t pre_hi = ~secret_seed;
    std::memcpy(preimage, &pre_lo, 8);
    std::memcpy(preimage + 8, &pre_hi, 8);
    c.hash_lock = htlc_acts_digest(preimage);

    // The VM compares 16 bytes: R2 = digest[0..7] LE, R3 = digest[8..15] LE.
    uint64_t lo = 0, hi = 0;
    std::memcpy(&lo, c.hash_lock.data(), 8);
    std::memcpy(&hi, c.hash_lock.data() + 8, 8);
    c.bytecode = build_htlc_bytecode(lo, hi, timelock_height);

    c.asm_source =
        "LOAD_IMM R2 0x" + /* lock lo */ [] (uint64_t v) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(v));
            return std::string(buf);
        }(lo) + "\n" +
        "LOAD_IMM R3 0x" + [] (uint64_t v) {
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%016llx", static_cast<unsigned long long>(v));
            return std::string(buf);
        }(hi) + "\n" +
        "LOAD_IMM R4 " + std::to_string(timelock_height) + "\n"
        "HTLC_VERIFY\n"
        "JNZ refund_branch\n"
        "LOAD_IMM R6 1\n"
        "HALT\n"
        "refund_branch:\n"
        "LOAD_IMM R6 2\n"
        "HALT\n";
    return c;
}

VortexVM::HtlcSettleResult VortexVM::settle_htlc_swap(
    const std::vector<uint8_t>& contract_bytecode,
    std::span<const uint8_t> preimage_or_empty,
    uint64_t current_block_height) {
    HtlcSettleResult res;

    if (contract_bytecode.size() < 44 ||
        contract_bytecode.size() > BYTECODE_MAX_SIZE ||
        contract_bytecode[0] != static_cast<uint8_t>(Opcode::OP_LOAD_IMM) ||
        contract_bytecode[10] != static_cast<uint8_t>(Opcode::OP_LOAD_IMM) ||
        contract_bytecode[20] != static_cast<uint8_t>(Opcode::OP_LOAD_IMM) ||
        contract_bytecode[30] != static_cast<uint8_t>(Opcode::OP_HTLC_VERIFY)) {
        res.outcome = HtlcOutcome::LOCKED;
        res.vm_trace.error = "malformed HTLC contract bytecode";
        return res;
    }

    // Decode the embedded hash lock + timelock back from the canonical frame.
    uint64_t lo = 0, hi = 0, timelock = 0;
    std::memcpy(&lo, &contract_bytecode[2], 8);
    std::memcpy(&hi, &contract_bytecode[12], 8);
    std::memcpy(&timelock, &contract_bytecode[22], 8);
    std::memcpy(res.hash_lock.data(), &lo, 8);
    std::memcpy(res.hash_lock.data() + 8, &hi, 8);
    res.timelock_height = timelock;
    res.current_height = current_block_height;

    // Preimage: pad/truncate to the canonical 16 bytes.
    uint8_t preimage[16] = {};
    const size_t plen = std::min<size_t>(preimage_or_empty.size(), 16);
    if (plen) std::memcpy(preimage, preimage_or_empty.data(), plen);

    // Independent outcome classification (mirrors the VM op exactly): the
    // 4-act Galois attractor digest of the preimage must match the lock.
    const std::array<uint8_t, 32> digest = htlc_acts_digest(preimage);
    uint64_t d0 = 0, d1 = 0;
    std::memcpy(&d0, digest.data(), 8);
    std::memcpy(&d1, digest.data() + 8, 8);
    const bool hash_ok = (d0 == lo && d1 == hi);
    const bool expired = (current_block_height > timelock);

    if (hash_ok && !expired) res.outcome = HtlcOutcome::CLAIMED;
    else if (expired) res.outcome = HtlcOutcome::REFUNDED;
    else res.outcome = HtlcOutcome::LOCKED;

    // Execute the branch in the VortexVM with the preimage preloaded.
    VortexVM vm;
    ExecutionContext ctx;
    ctx.block_height = current_block_height;
    uint64_t pre_lo = 0, pre_hi = 0;
    std::memcpy(&pre_lo, preimage, 8);
    std::memcpy(&pre_hi, preimage + 8, 8);
    ctx.initial_registers[0] = pre_lo; // preimage halves visible in R0/R1
    ctx.initial_registers[1] = pre_hi;
    uint8_t bc[BYTECODE_MAX_SIZE] = {};
    std::memcpy(bc, contract_bytecode.data(), contract_bytecode.size());
    res.vm_trace = vm.execute(bc, ctx);
    if (res.vm_trace.cycles_used > 0) {
        // R6 holds the executed branch marker (1 = CLAIM, 2 = REFUND path).
        res.vm_branch_marker = static_cast<uint8_t>(res.vm_trace.final_registers[6]);
    }
    return res;
}

} // namespace vx::vm
