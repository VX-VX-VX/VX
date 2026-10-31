#include <gtest/gtest.h>
#include "vx/vm/vortex_vm.hpp"
#include "vx/core/u128.hpp"

TEST(VortexVMTest, AssembleDisassembleLimits) {
    auto bytecode = vx::vm::VortexVM::assemble(
        "LOAD_IMM R0 42\n"
        "LOAD_IMM R1 13\n"
        "ADD R0 R1\n"
        "HALT"
    );

    ASSERT_FALSE(bytecode.empty());
    ASSERT_LE(bytecode.size(), vx::vm::VortexVM::BYTECODE_MAX_SIZE);
}

TEST(VortexVMTest, BasicArithmeticOps) {
    vx::vm::VortexVM vm;

    // Test ADD
    auto bytecode_add = vx::vm::VortexVM::assemble(
        "LOAD_IMM R0 10\n"
        "LOAD_IMM R1 20\n"
        "ADD R0 R1\n"
        "HALT"
    );
    ASSERT_FALSE(bytecode_add.empty());

    auto result_add = vm.execute(bytecode_add.data(), {});
    ASSERT_TRUE(result_add.success);

    // Test SUB
    auto bytecode_sub = vx::vm::VortexVM::assemble(
        "LOAD_IMM R0 30\n"
        "LOAD_IMM R1 10\n"
        "SUB R0 R1\n"
        "HALT"
    );
    ASSERT_FALSE(bytecode_sub.empty());

    auto result_sub = vm.execute(bytecode_sub.data(), {});
    ASSERT_TRUE(result_sub.success);

    // Test MUL
    auto bytecode_mul = vx::vm::VortexVM::assemble(
        "LOAD_IMM R0 7\n"
        "LOAD_IMM R1 6\n"
        "MUL R0 R1\n"
        "HALT"
    );
    ASSERT_FALSE(bytecode_mul.empty());

    auto result_mul = vm.execute(bytecode_mul.data(), {});
    ASSERT_TRUE(result_mul.success);
}

TEST(VortexVMTest, LogicalOps) {
    vx::vm::VortexVM vm;

    // Test XOR
    auto bytecode_xor = vx::vm::VortexVM::assemble(
        "LOAD_IMM R0 0xFF\n"
        "LOAD_IMM R1 0x0F\n"
        "XOR R0 R1\n"
        "HALT"
    );
    ASSERT_FALSE(bytecode_xor.empty());

    auto result_xor = vm.execute(bytecode_xor.data(), {});
    ASSERT_TRUE(result_xor.success);

    // Test AND
    auto bytecode_and = vx::vm::VortexVM::assemble(
        "LOAD_IMM R0 0xFF\n"
        "LOAD_IMM R1 0x0F\n"
        "AND R0 R1\n"
        "HALT"
    );
    ASSERT_FALSE(bytecode_and.empty());

    auto result_and = vm.execute(bytecode_and.data(), {});
    ASSERT_TRUE(result_and.success);
}

TEST(VortexVMTest, CryptoOps) {
    vx::vm::VortexVM vm;

    // Test SPONGE256
    auto bytecode_sponge = vx::vm::VortexVM::assemble(
        "LOAD_IMM R0 1\n"
        "LOAD_IMM R1 2\n"
        "LOAD_IMM R2 3\n"
        "LOAD_IMM R3 4\n"
        "SPONGE256\n"
        "HALT"
    );
    ASSERT_FALSE(bytecode_sponge.empty());

    auto result_sponge = vm.execute(bytecode_sponge.data(), {});
    ASSERT_TRUE(result_sponge.success);
    ASSERT_LT(result_sponge.cycles_used, 10000);

    // Test GALOIS_PROJ
    auto bytecode_galois = vx::vm::VortexVM::assemble(
        "LOAD_IMM R0 12345\n"
        "GALOIS_PROJ\n"
        "HALT"
    );
    ASSERT_FALSE(bytecode_galois.empty());

    auto result_galois = vm.execute(bytecode_galois.data(), {});
    ASSERT_TRUE(result_galois.success);
    ASSERT_LT(result_galois.cycles_used, 10000);
}

TEST(VortexVMTest, StateRootGeneration) {
    vx::vm::VortexVM vm;

    // Test that HALT generates non-zero state root
    auto bytecode_halt = vx::vm::VortexVM::assemble(
        "LOAD_IMM R0 0xFFFFFFFFFFFFFFFF\n"
        "LOAD_IMM R1 0\n"
        "LOAD_IMM R2 0xABCDEF\n"
        "LOAD_IMM R3 0x123456\n"
        "HALT"
    );
    ASSERT_FALSE(bytecode_halt.empty());

    auto result = vm.execute(bytecode_halt.data(), {});
    ASSERT_TRUE(result.success);
    // State root should be non-zero
    bool all_zero = true;
    for (int i = 0; i < 32; ++i) {
        if (result.state_root[i] != 0) { all_zero = false; break; }
    }
    ASSERT_FALSE(all_zero);
}