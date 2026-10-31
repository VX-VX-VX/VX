#pragma once

#include "vx/math/galois_attractor.hpp"
#include <cstdint>
#include <array>
#include <gmpxx.h>

namespace vx::math {

// Solinas/Mersenne reduction constants
struct ReductionConstants {
    // Set A: Classic v4.0 / Genesis Compatible
    static constexpr uint64_t P_C = 1381;
    static constexpr uint64_t Q_C = 7;
    static constexpr uint64_t R_C = 264575;

    // Set B: secure_crt Production True Primes
    static constexpr uint64_t P_S = 1747;
    static constexpr uint64_t Q_S = 3943;
    static constexpr uint64_t R_S = 267799;

    static constexpr int P_SHIFT = 64;
    static constexpr int Q_SHIFT = 888;
    static constexpr int R_SHIFT = 512;
};

// Fast reduction without division (Solinas/Mersenne)
class FastReducer {
public:
    static mpz_class fast_reduce_p(const mpz_class& high, const mpz_class& low, bool secure_mode);
    static mpz_class fast_reduce_q(const mpz_class& high, const mpz_class& low, bool secure_mode);
    static mpz_class fast_reduce_r(const mpz_class& high, const mpz_class& low, bool secure_mode);

    // SAC evaluation
    static double evaluate_sac(const std::string& seed_hex, int flip_bit_pos);
};

// Enhanced Vortex Attractor with CRT and SAC
class VortexAttractorV6 {
public:
    struct Result {
        mpz_class finalX, finalY, finalZ;
        mpz_class crtX;
        std::array<uint8_t, 32> addressNFA;
        uint64_t sac_score;
    };

    // 4-Act pipeline
    Result run_4act(const std::string& seed_hex, int rounds = 1000, bool secure_mode = true);

    // Act I: Seed expansion
    std::tuple<mpz_class, mpz_class, mpz_class> act_i_expand(const std::string& seed_hex);

    // Act II: 3D attractor iterations
    void act_ii_iterate(mpz_class& x, mpz_class& y, mpz_class& z, int rounds, bool secure_mode);

    // Act III: Cross-diffusion
    std::tuple<mpz_class, mpz_class, mpz_class> act_iii_diffusion(const mpz_class& cubeX, const mpz_class& cubeY, const mpz_class& cubeZ, bool secure_mode);

    // Act IV: CRT lossless unwrapping
    mpz_class act_iv_crt(const mpz_class& rp, const mpz_class& rq, const mpz_class& rr);
};

} // namespace vx::math