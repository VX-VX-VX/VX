#pragma once

#include "vx/core/types.hpp"
#include <string>
#include <vector>
#include <array>
#include <chrono>

namespace vx::math {

struct StepTrace {
    mpz_class x;
    mpz_class y;
    mpz_class z;
    mpz_class cubeX;
    mpz_class cubeY;
    mpz_class cubeZ;
    mpz_class arxX;
    mpz_class arxY;
    mpz_class arxZ;
    mpz_class phi_t;
    uint32_t shiftX;
    uint32_t shiftY;
    uint32_t shiftZ;
};

struct AttractorResult {
    mpz_class finalX;
    mpz_class finalY;
    mpz_class finalZ;
    mpz_class r_p;
    mpz_class r_q;
    mpz_class r_r;
    mpz_class crtX;
    core::Hash256 foldedHash;
    std::string addressRaw;
    std::string addressNFA; // NFA_V6_...
    std::string addressOFA; // OFA_V2_...
    double executionTimeMs;
    std::vector<StepTrace> stepHistory;
};

struct SacRoundData {
    uint32_t round;
    uint32_t bitDistance;
    double percentage;
};

class VortexAttractor {
public:
    static mpz_class hexToBigInt(std::string_view hex);
    static std::string bigIntToHex1024(const mpz_class& val);
    static mpz_class rotl1024(const mpz_class& val, unsigned int shift);
    static core::Hash256 xorFold(const mpz_class& x, const mpz_class& y, const mpz_class& z);
    static std::string base64UrlSafe(const core::Hash256& bytes);
    static std::string formatAddress(std::string_view rawAddress, std::string_view type = "NFA");

    /**
     * @brief Computes Act IV Chinese Remainder Theorem (CRT) reconstruction.
     */
    static mpz_class computeCrtUnwrapping(
        const mpz_class& r_p,
        const mpz_class& r_q,
        const mpz_class& r_r,
        const core::AttractorModuli& moduli
    );

    /**
     * @brief Executes a single iteration of the Tri-Barrel Attractor.
     */
    static StepTrace step(
        const mpz_class& x,
        const mpz_class& y,
        const mpz_class& z,
        uint32_t round,
        const core::AttractorModuli& moduli,
        const mpz_class& phi1024
    );

    /**
     * @brief Runs complete Acts I–IV Chaotic Tri-Barrel Attractor.
     */
    static AttractorResult run(
        std::string_view seedHex,
        uint32_t iterations = 1000,
        bool isUnlocked = true,
        const core::AttractorModuli& moduli = core::AttractorModuli::active_default()
    );

    /**
     * @brief Calculates Strict Avalanche Criterion (SAC) diffusion when flipping 1 bit.
     */
    static std::vector<SacRoundData> calculateSac(
        std::string_view seedHex,
        uint32_t bitToFlip,
        uint32_t rounds = 20,
        const core::AttractorModuli& moduli = core::AttractorModuli::active_default()
    );

    /**
     * @brief Computes Hamming distance (bit count of XOR) between two numbers.
     */
    static uint32_t hammingDistance(const mpz_class& a, const mpz_class& b);

private:
    static mpz_class pow3_mod(const mpz_class& base, const mpz_class& mod);
};

} // namespace vx::math
