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
     * @brief Fail-closed seed canonicalization check (BACKLOG 2.8).
     *
     * The derivation itself is frozen (canonical vectors), so degenerate
     * input classes are refused at the SURFACES that feed it. Returns an
     * empty string when the seed is canonical, otherwise a short operator
     * -facing reason. Rules (mirroring the degeneracy findings):
     *  - empty, non-hex characters, or the all-zero seed: refused;
     *  - more than 512 hex chars (after the optional lowercase "0x"
     *    prefix): refused - run() would silently truncate;
     *  - an uppercase "0X" prefix: refused - it is not stripped by run()
     *    and shifts the seed window (case-asymmetric quirk).
     */
    static std::string canonicalSeedError(std::string_view seedHex);

    /**
     * @brief Algebraic extension (v0.0.15, owner-audit item I.2): the same
     * refusal pipeline, plus the degenerate classes that live INSIDE the
     * modular arithmetic rather than in the seed string.
     *
     * Additional refused classes (checked on BOTH orientations — locked
     * mode reverses the seed string, and both addresses derive from one
     * seed):
     *  - a zero trunk (X_0 == 0 or Y_0 == 0) — the string-level all-zero
     *    check cannot see a per-trunk zero;
     *  - a trunk congruent to 0 mod its modulus (X_0 % p == 0 /
     *    Y_0 % q == 0): a non-zero word that collapses to a zero residue;
     *  - a seed whose ACT I derivation produces Z_0 == 0
     *    (cube_sum == rotl1024(PHI, Y_0 % 64)) - closed-form
     *    constructible: the cube map is a BIJECTION mod r (3 does not
     *    divide r-1, docs/CRT_COLLISION_ANALYSIS.md Theorem 6), so
     *    X0 = (rotl1024(PHI, Y0 % 64) - Y0^3)^(3^-1 mod (r-1)) mod r.
     *
     * The 1-argument overload delegates with active_default() (the
     * production set, v0.0.16), so callers upgrading automatically gain
     * these checks.
     */
    static std::string canonicalSeedError(
        std::string_view seedHex, const core::AttractorModuli& moduli);

    /**
     * @brief The ACT I Z-trunk derivation, exposed as the single source of
     * truth for run() and canonicalSeedError: Z_0 = ((X_0^3 mod r +
     * Y_0^3 mod r) % r) XOR rotl1024(PHI_1024, Y_0 mod 64). Byte-identical
     * with the in-line formula it replaces in run().
     */
    static mpz_class derive_z0(const mpz_class& X0, const mpz_class& Y0,
                               const core::AttractorModuli& moduli,
                               const mpz_class& PHI_1024);

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
