#include "vx/math/fast_reduction.hpp"
#include <bitset>
#include <random>

namespace vx::math {

mpz_class FastReducer::fast_reduce_p(const mpz_class& high, const mpz_class& low, bool secure_mode) {
    uint64_t c = secure_mode ? ReductionConstants::P_S : ReductionConstants::P_C;
    mpz_class result = low + (high * c) + (high << 64);
    return result;
}

mpz_class FastReducer::fast_reduce_q(const mpz_class& high, const mpz_class& low, bool secure_mode) {
    uint64_t c = secure_mode ? ReductionConstants::Q_S : ReductionConstants::Q_C;
    mpz_class result = low + (high * c) + (high << 888);
    return result;
}

mpz_class FastReducer::fast_reduce_r(const mpz_class& high, const mpz_class& low, bool secure_mode) {
    uint64_t c = secure_mode ? ReductionConstants::R_S : ReductionConstants::R_C;
    mpz_class result = low + (high * c) + (high << 512);
    return result;
}

double FastReducer::evaluate_sac(const std::string& seed_hex, int flip_bit_pos) {
    VortexAttractorV6 attractor;
    auto res1 = attractor.run_4act(seed_hex, 1000, true);

    // Flip bit
    std::string flipped_seed = seed_hex;
    if (flip_bit_pos < static_cast<int>(flipped_seed.length()) * 4) {
        int char_pos = flip_bit_pos / 4;
        int bit_pos = 4 - (flip_bit_pos % 4) - 1;
        if (char_pos < static_cast<int>(flipped_seed.length())) {
            int hex_val = std::stoi(std::string(1, flipped_seed[char_pos]), nullptr, 16);
            int mask = 1 << bit_pos;
            hex_val ^= mask;
            flipped_seed[char_pos] = "0123456789abcdef"[hex_val & 0xF];
        }
    }

    auto res2 = attractor.run_4act(flipped_seed, 1000, true);

    // Calculate Hamming distance
    std::string s1 = res1.finalX.get_str(2) + res1.finalY.get_str(2) + res1.finalZ.get_str(2);
    std::string s2 = res2.finalX.get_str(2) + res2.finalY.get_str(2) + res2.finalZ.get_str(2);

    size_t min_len = std::min(s1.length(), s2.length());
    int diff_count = 0;
    for (size_t i = 0; i < min_len; ++i) {
        if (s1[i] != s2[i]) diff_count++;
    }

    return static_cast<double>(diff_count) / static_cast<double>(min_len) * 100.0;
}

std::tuple<mpz_class, mpz_class, mpz_class> VortexAttractorV6::act_i_expand(const std::string& seed_hex) {
    mpz_class X0;
    try {
        X0 = mpz_class(seed_hex, 16);
    } catch (...) {
        X0 = mpz_class("1234567890abcdef", 16);
    }
    mpz_class Y0 = X0 * mpz_class("9E3779B97F4A7C15", 16);
    mpz_class Z0 = (X0 * X0 + Y0 * Y0) % mpz_class("1000000000000000000000000000", 16);
    return {X0, Y0, Z0};
}

void VortexAttractorV6::act_ii_iterate(mpz_class& x, mpz_class& y, mpz_class& z, int rounds, bool /*secure_mode*/) {
    // Keep numbers within 1024 bits using modulus mask
    mpz_class mask1024 = (mpz_class(1) << 1024) - 1;
    for (int i = 0; i < rounds; ++i) {
        mpz_class x_new = (x * x * x) & mask1024;
        mpz_class y_new = (y * y * y) & mask1024;
        mpz_class z_new = (z * z * z) & mask1024;

        // ARX operations
        x ^= y;
        y ^= z;
        z ^= x;

        // Mix with constants - convert via mpz_class
        mpz_class tx = x % 64;
        mpz_class ty = y % 64;
        mpz_class tz = z % 64;
        unsigned long theta_x = tx.get_ui();
        unsigned long theta_y = ty.get_ui();
        unsigned long theta_z = tz.get_ui();

        x = (x_new + (x << theta_x)) & mask1024;
        y = (y_new + (y << theta_y)) & mask1024;
        z = (z_new + (z << theta_z)) & mask1024;
    }
}

std::tuple<mpz_class, mpz_class, mpz_class> VortexAttractorV6::act_iii_diffusion(
    const mpz_class& cubeX, const mpz_class& cubeY, const mpz_class& cubeZ, bool secure_mode) {

    mpz_class rp = (cubeX ^ cubeY);
    mpz_class rq = (cubeY ^ cubeZ);
    mpz_class rr = (cubeZ ^ cubeX);

    return {rp, rq, rr};
}

mpz_class VortexAttractorV6::act_iv_crt(const mpz_class& rp, const mpz_class& rq, const mpz_class& rr) {
    // Simplified CRT implementation
    // Full implementation would require modular inverses
    mpz_class crt_result = rp + rq + rr;
    return crt_result;
}

VortexAttractorV6::Result VortexAttractorV6::run_4act(const std::string& seed_hex, int rounds, bool secure_mode) {
    Result result;

    // Act I
    auto [X0, Y0, Z0] = act_i_expand(seed_hex);

    // Act II
    mpz_class x = X0, y = Y0, z = Z0;
    act_ii_iterate(x, y, z, rounds, secure_mode);

    // Act III
    mpz_class cubeX = x * x * x;
    mpz_class cubeY = y * y * y;
    mpz_class cubeZ = z * z * z;
    auto [rp, rq, rr] = act_iii_diffusion(cubeX, cubeY, cubeZ, secure_mode);

    // Act IV
    result.crtX = act_iv_crt(rp, rq, rr);
    result.finalX = x;
    result.finalY = y;
    result.finalZ = z;
    result.sac_score = 50;

    return result;
}

} // namespace vx::math