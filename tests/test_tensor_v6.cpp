#include <gtest/gtest.h>
#include "vx/math/tensor_v6.hpp"
#include "vx/math/fast_reduction.hpp"
#include "vx/neural/virtual_tensor.hpp"

TEST(VortexTensorV6Test, FastReducerAndSacEvaluation) {
    std::string seed = "e76a1d401b5c3b803d9e909a1c7d7b5893f89e991160bfea87d56b9292a9eca5"
                       "a3656ecc660111b16d81d181f69f307b864a76d5411051863d74c41f1c9b8d60"
                       "dd667f204e057ede165edc4dfdfd3ad5d31330f35667412f0a6ff87b16d55256"
                       "0a500902dda48ed0d69b37f28d4f9601a5f10b28ea08510137ccfe6a6b4c96d2";
    double sac = vx::math::FastReducer::evaluate_sac(seed, 0);
    EXPECT_GE(sac, 0.0);
    EXPECT_LE(sac, 100.0);
}

TEST(VortexTensorV6Test, MultiTensorV6Pipeline) {
    vx::math::TensorV6 tensor;
    std::array<uint64_t, 16> seed_elements{};
    for (size_t i = 0; i < 16; ++i) seed_elements[i] = 0x1234567890ABCDEFULL + i;

    auto res = tensor.run(seed_elements, 10);
    EXPECT_EQ(res.entropy_destroyed_bits, 16128.0);
    EXPECT_GT(res.landauer_heat_joules, 0.0);
    EXPECT_GT(res.landauer_heat_ev, 0.0);
    EXPECT_EQ(res.branching_complexity, 192ULL);
}

TEST(VortexTensorV6Test, TensorNoZeroCollapse) {
    vx::math::TensorV6 tensor;
    std::array<uint64_t, 16> seed_elements{};
    for (size_t i = 0; i < 16; ++i) seed_elements[i] = 0x1234567890ABCDEFULL + i;
    auto res = tensor.run(seed_elements, 1000);
    EXPECT_NE(res.final_vector[0], 0ULL);
    EXPECT_NE(res.final_vector[1], 0ULL);
    EXPECT_NE(res.final_vector[2], 0ULL);
    EXPECT_NE(res.final_vector[3], 0ULL);
    EXPECT_NE(res.jones_invariant, 0ULL);
    // Compute SAC flipped bits manually (same as RPC handler)
    uint64_t flipped = 0;
    for (size_t i = 0; i < res.final_vector.size(); ++i) flipped += __builtin_popcountll(res.final_vector[i] ^ seed_elements[i]);
    EXPECT_GT(flipped, 64ULL);
}

TEST(VortexTensorV6Test, VirtualTensorEvolution) {
    vx::neural::VirtualTensor vt;
    auto res = vt.evolve(0.123456789, 10, 0.05);

    EXPECT_EQ(res.total_iterations, 10);
    EXPECT_EQ(res.final_hamiltonian_loss, 0.05);
    EXPECT_FALSE(res.virtual_weights.empty());
}
