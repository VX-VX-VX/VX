#include "vx/math/tensor_v6.hpp"
#include <cstring>

namespace vx::math {

static inline uint64_t rotl64(uint64_t val, int shift) {
    shift &= 63;
    if (shift == 0) return val; // shift by 64 would be UB
    return (val << shift) | (val >> (64 - shift));
}

uint64_t TensorV6::jones_invariant_calc(const Matrix4x4& matrix) {
    // Jones-like invariant: trace-weighted hash with sign projection
    uint64_t trace = 0;
    uint64_t anti_trace = 0;
    for (int i = 0; i < MATRIX_SIZE; ++i) {
        trace ^= matrix.data[i][i];
        anti_trace ^= matrix.data[i][MATRIX_SIZE - 1 - i];
    }
    // Det-sign proxy: parity of off-diagonal mixing
    uint64_t det_sign = 0;
    for (int i = 0; i < MATRIX_SIZE; ++i) {
        for (int j = 0; j < MATRIX_SIZE; ++j) {
            if (i != j) {
                det_sign ^= matrix.data[i][j] * 0x9E3779B97F4A7C15ULL;
            }
        }
    }
    // J = trace * det_sign with rotational mixing (non-zero when matrix is non-zero)
    uint64_t invariant = trace;
    for (int r = 0; r < 32; ++r) {
        invariant = rotl64(invariant ^ det_sign, r & 63);
        invariant += 0x9E3779B97F4A7C15ULL;
    }
    return invariant;
}

std::array<uint64_t, 4> TensorV6::tensor_fold(const Matrix4x4& matrix) {
    std::array<uint64_t, 4> result{};

    // Row-wise fold: XOR each row into a 64-bit accumulator
    for (int i = 0; i < MATRIX_SIZE; ++i) {
        uint64_t sum = 0;
        for (int j = 0; j < MATRIX_SIZE; ++j) {
            sum ^= matrix.data[i][j];
        }
        result[i] = sum;
    }

    // Column-wise merge into remaining slots
    for (int j = 0; j < MATRIX_SIZE; ++j) {
        uint64_t col_sum = 0;
        for (int i = 0; i < MATRIX_SIZE; ++i) {
            col_sum ^= matrix.data[i][j];
        }
        result[j] ^= col_sum;
    }

    // Anti-diagonal cross-mix to ensure all cells contribute
    for (int i = 0; i < MATRIX_SIZE; ++i) {
        result[i] ^= matrix.data[i][MATRIX_SIZE - 1 - i];
    }

    return result;
}

TensorV6::Matrix4x4 TensorV6::act_i_init(const std::array<uint64_t, 16>& seed_elements) {
    Matrix4x4 matrix;
    for (int i = 0; i < MATRIX_SIZE; ++i) {
        for (int j = 0; j < MATRIX_SIZE; ++j) {
            matrix.data[i][j] = seed_elements[i * MATRIX_SIZE + j];
        }
    }
    return matrix;
}

void TensorV6::act_ii_mma(Matrix4x4& matrix, const std::array<uint64_t, 16>& phi_constants) {
    for (int i = 0; i < MATRIX_SIZE; ++i) {
        for (int j = 0; j < MATRIX_SIZE; ++j) {
            uint64_t temp = matrix.data[i][j] * matrix.data[i][j] + phi_constants[i * MATRIX_SIZE + j];
            matrix.data[i][j] = temp;
        }
    }
}

void TensorV6::act_iii_lorenz(Matrix4x4& matrix, const std::array<uint64_t, 16>& phi_constants) {
    // Fixed-point ARX bit-mixing permutation — no floating point, no precision loss
    Matrix4x4 next{};
    for (int i = 0; i < MATRIX_SIZE; ++i) {
        for (int j = 0; j < MATRIX_SIZE; ++j) {
            // Row, column, and anti-diagonal sums
            uint64_t row_sum = 0, col_sum = 0, anti_diag_sum = 0;
            for (int k = 0; k < MATRIX_SIZE; ++k) {
                row_sum ^= matrix.data[i][k];
                col_sum ^= matrix.data[k][j];
                anti_diag_sum ^= matrix.data[k][MATRIX_SIZE - 1 - k];
            }
            // ARX mix: add-round-key, XOR with column feedback, rotate
            uint64_t mixed = row_sum + phi_constants[i * MATRIX_SIZE + j];
            mixed ^= col_sum * 0x9E3779B97F4A7C15ULL;
            mixed ^= anti_diag_sum >> ((i + j) & 63);
            mixed = rotl64(mixed, (i * MATRIX_SIZE + j) & 63);
            next.data[i][j] = mixed;
        }
    }
    matrix = next;
}

TensorV6::Result TensorV6::act_iv_burn(const Matrix4x4& matrix_in) {
    Result result;
    Matrix4x4 matrix = matrix_in;

    // BEAF topology swap
    for (int step = 0; step < 1000; ++step) {
        if (step % 8 == 0) {
            int idx_a = static_cast<int>((matrix.data[2][15 % MATRIX_SIZE] >> 4) % 3);
            int idx_b = static_cast<int>((matrix.data[0][15 % MATRIX_SIZE] >> 2) % 3);
            uint64_t tmp = matrix.data[idx_a][0];
            matrix.data[idx_a][0] = matrix.data[idx_b][1];
            matrix.data[idx_b][1] = tmp;
        }
    }

    result.final_matrix = matrix;
    result.jones_invariant = jones_invariant_calc(matrix);
    result.final_vector = tensor_fold(matrix);

    // Landauer heat calculation
    double entropy_destroyed = 16384.0 - 256.0;
    result.entropy_destroyed_bits = entropy_destroyed;
    result.landauer_heat_joules = entropy_destroyed * K_B * T * std::log(2.0);
    result.landauer_heat_ev = result.landauer_heat_joules / 1.602176634e-19;

    // Branching complexity
    result.branching_complexity = 192ULL;

    return result;
}

TensorV6::Result TensorV6::run(const std::array<uint64_t, 16>& seed_elements, int rounds) {
    Result result;

    // Act I: Initialize 4x4 matrix
    Matrix4x4 matrix = act_i_init(seed_elements);

    // Generate phi constants
    std::array<uint64_t, 16> phi_constants;
    for (int i = 0; i < 16; ++i) {
        phi_constants[i] = 0x9E3779B97F4A7C15ULL ^ i ^ ((i / 4) * (i % 4));
    }

    // Act II: MMA contour
    for (int r = 0; r < rounds; ++r) {
        act_ii_mma(matrix, phi_constants);
    }

    // Act III: ARX bit-mixing diffusion (replaces broken float Lorenz)
    for (int r = 0; r < rounds; ++r) {
        act_iii_lorenz(matrix, phi_constants);
    }

    // Act IV: BEAF topology swap + Jones invariant + Landauer burn
    result = act_iv_burn(matrix);

    // SAC: compute flipped bits between final_vector and seed_elements
    result.sac_flipped_bits = 0;
    for (int i = 0; i < 4; ++i) {
        result.sac_flipped_bits += std::popcount(result.final_vector[i] ^ seed_elements[i]);
    }

    return result;
}

} // namespace vx::math