#include "vx/math/galois_attractor.hpp"
#include <algorithm>
#include <iomanip>
#include <sstream>

namespace vx::math {

mpz_class VortexAttractor::hexToBigInt(std::string_view hex) {
    std::string clean(hex);
    if (clean.rfind("0x", 0) == 0) {
        clean = clean.substr(2);
    }
    if (clean.empty()) return 0;
    mpz_class res;
    res.set_str(clean, 16);
    return res;
}

std::string VortexAttractor::bigIntToHex1024(const mpz_class& val) {
    std::string hex = val.get_str(16);
    if (hex.length() < 256) {
        hex = std::string(256 - hex.length(), '0') + hex;
    }
    return "0x" + hex;
}

mpz_class VortexAttractor::rotl1024(const mpz_class& val, unsigned int shift) {
    shift %= 1024;
    if (shift == 0) return val;
    mpz_class mask = (mpz_class(1) << 1024) - 1;
    mpz_class left = (val << shift) & mask;
    mpz_class right = (val >> (1024 - shift));
    return (left | right) & mask;
}

mpz_class VortexAttractor::pow3_mod(const mpz_class& base, const mpz_class& mod) {
    mpz_class res;
    mpz_powm_ui(res.get_mpz_t(), base.get_mpz_t(), 3, mod.get_mpz_t());
    return res;
}

core::Hash256 VortexAttractor::xorFold(const mpz_class& x, const mpz_class& y, const mpz_class& z) {
    std::array<uint8_t, 128> xBytes{}, yBytes{}, zBytes{};
    mpz_class tempX = x, tempY = y, tempZ = z;
    mpz_class mask255 = 255;

    for (int i = 127; i >= 0; --i) {
        xBytes[i] = static_cast<uint8_t>(mpz_class(tempX & mask255).get_ui());
        yBytes[i] = static_cast<uint8_t>(mpz_class(tempY & mask255).get_ui());
        zBytes[i] = static_cast<uint8_t>(mpz_class(tempZ & mask255).get_ui());
        tempX >>= 8;
        tempY >>= 8;
        tempZ >>= 8;
    }

    core::Hash256 outBytes{};
    for (size_t k = 0; k < 16; ++k) {
        uint8_t mixed = xBytes[k] ^ yBytes[15 - k] ^ zBytes[(k * 7) % 16];
        outBytes[(2 * k) % 32] ^= mixed;
        uint8_t rot = static_cast<uint8_t>(((mixed >> 4) | (mixed << 4)) & 0xFF);
        outBytes[(2 * k + 1) % 32] ^= rot;
    }
    return outBytes;
}

std::string VortexAttractor::base64UrlSafe(const core::Hash256& bytes) {
    static const std::string alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_";
    std::string result = "";
    uint32_t buffer = 0;
    int bitsCollected = 0;

    for (size_t i = 0; i < bytes.size(); ++i) {
        buffer = (buffer << 8) | bytes[i];
        bitsCollected += 8;
        while (bitsCollected >= 6) {
            bitsCollected -= 6;
            uint32_t index = (buffer >> bitsCollected) & 63;
            result += alphabet[index];
        }
    }
    if (bitsCollected > 0) {
        buffer = buffer << (6 - bitsCollected);
        uint32_t index = buffer & 63;
        result += alphabet[index];
    }
    while (result.length() < 45) result += 'A';
    return result.substr(0, 45);
}

std::string VortexAttractor::formatAddress(std::string_view rawAddress, std::string_view type) {
    std::string payload(rawAddress);
    if (payload.rfind("NFA_V6_", 0) == 0) payload = payload.substr(7);
    else if (payload.rfind("OFA_V2_", 0) == 0) payload = payload.substr(7);
    else if (payload.rfind("NFA_", 0) == 0) payload = payload.substr(4);
    else if (payload.rfind("OFA_", 0) == 0) payload = payload.substr(4);
    else if (payload.rfind("NFA", 0) == 0) payload = payload.substr(3);
    else if (payload.rfind("OFA", 0) == 0) payload = payload.substr(3);

    if (type == "OFA") {
        return "OFA_V2_" + payload;
    }
    return "NFA_V6_" + payload;
}

mpz_class VortexAttractor::computeCrtUnwrapping(
    const mpz_class& r_p,
    const mpz_class& r_q,
    const mpz_class& r_r,
    const core::AttractorModuli& moduli
) {
    const mpz_class& p = moduli.p;
    const mpz_class& q = moduli.q;
    const mpz_class& r = moduli.r;

    mpz_class M = p * q * r;
    mpz_class Mp = M / p;
    mpz_class Mq = M / q;
    mpz_class Mr = M / r;

    mpz_class inv_p, inv_q, inv_r;
    mpz_invert(inv_p.get_mpz_t(), Mp.get_mpz_t(), p.get_mpz_t());
    mpz_invert(inv_q.get_mpz_t(), Mq.get_mpz_t(), q.get_mpz_t());
    mpz_invert(inv_r.get_mpz_t(), Mr.get_mpz_t(), r.get_mpz_t());

    mpz_class term1 = ((r_p * Mp % M) * inv_p) % M;
    mpz_class term2 = ((r_q * Mq % M) * inv_q) % M;
    mpz_class term3 = ((r_r * Mr % M) * inv_r) % M;

    return (term1 + term2 + term3) % M;
}

StepTrace VortexAttractor::step(
    const mpz_class& x,
    const mpz_class& y,
    const mpz_class& z,
    uint32_t round,
    const core::AttractorModuli& moduli,
    const mpz_class& phi1024
) {
    mpz_class mask1024 = (mpz_class(1) << 1024) - 1;

    uint32_t thetaX = mpz_class(x & 63).get_ui();
    uint32_t thetaY = mpz_class(y & 63).get_ui();
    uint32_t thetaZ = mpz_class(z & 63).get_ui();

    mpz_class phi_t = rotl1024(phi1024, thetaY + round);

    mpz_class arxX = rotl1024((x + y) & mask1024, thetaY) ^ y;
    mpz_class arxY = rotl1024((y + z) & mask1024, thetaZ) ^ z;
    mpz_class arxZ = rotl1024((z + x) & mask1024, thetaX) ^ x;

    mpz_class cubeX = pow3_mod(arxX, moduli.p);
    mpz_class cubeY = pow3_mod(arxY, moduli.q);
    mpz_class cubeZ = pow3_mod(arxZ, moduli.r);

    mpz_class nextX = (rotl1024(x, 13) ^ cubeY ^ phi_t) & mask1024;
    mpz_class nextY = (rotl1024(y, 29) ^ cubeZ ^ phi_t) & mask1024;
    mpz_class nextZ = (rotl1024(z, 43) ^ cubeX ^ phi_t) & mask1024;

    return StepTrace{
        .x = nextX,
        .y = nextY,
        .z = nextZ,
        .cubeX = cubeX,
        .cubeY = cubeY,
        .cubeZ = cubeZ,
        .arxX = arxX,
        .arxY = arxY,
        .arxZ = arxZ,
        .phi_t = phi_t,
        .shiftX = thetaY,
        .shiftY = thetaZ,
        .shiftZ = thetaX
    };
}

AttractorResult VortexAttractor::run(
    std::string_view seedHex,
    uint32_t iterations,
    bool isUnlocked,
    const core::AttractorModuli& moduli
) {
    auto startTime = std::chrono::high_resolution_clock::now();

    std::string clean(seedHex);
    if (clean.rfind("0x", 0) == 0) clean = clean.substr(2);
    if (!isUnlocked) {
        std::reverse(clean.begin(), clean.end());
    }
    if (clean.length() < 512) {
        clean.append(512 - clean.length(), '0');
    } else if (clean.length() > 512) {
        clean = clean.substr(0, 512);
    }

    mpz_class PHI_1024 = hexToBigInt(core::PHI_1024_HEX);

    // AKT I: Master Key Anchor & Deterministic Expansion (2048-bit -> 3072-bit)
    std::string m1 = clean.substr(0, 256);
    std::string m2 = clean.substr(256, 256);

    mpz_class X_0 = hexToBigInt(m1);
    mpz_class Y_0 = hexToBigInt(m2);

    mpz_class cube_sum = (pow3_mod(X_0, moduli.r) + pow3_mod(Y_0, moduli.r)) % moduli.r;
    unsigned int y0_mod64 = mpz_class(Y_0 % 64).get_ui();
    mpz_class Z_0 = cube_sum ^ rotl1024(PHI_1024, y0_mod64);

    mpz_class x = X_0;
    mpz_class y = Y_0;
    mpz_class z = Z_0;

    std::vector<StepTrace> history;
    history.reserve(std::min(iterations, 100u));

    // AKT II: Chaotic Attractor Loops over Galois Fields
    for (uint32_t t = 1; t <= iterations; ++t) {
        StepTrace trace = step(x, y, z, t, moduli, PHI_1024);
        x = trace.x;
        y = trace.y;
        z = trace.z;

        if (t <= 100) {
            history.push_back(trace);
        }
    }

    // AKT III: Cross-Diffusion One-Way Lock at round 1000
    uint32_t y_mod64 = mpz_class(y & 63).get_ui();
    mpz_class Phi_lock = rotl1024(PHI_1024, y_mod64 + 1000);

    mpz_class r_p = ((x ^ Phi_lock) * 7 + 13) % moduli.p;
    mpz_class r_q = ((y ^ Phi_lock) * 11 + 17) % moduli.q;
    mpz_class r_r = ((z ^ Phi_lock) * 19 + 23) % moduli.r;

    // AKT IV: Chinese Remainder Theorem (CRT) Synthesis & Symmetric Folding
    mpz_class crtX = computeCrtUnwrapping(r_p, r_q, r_r, moduli);
    core::Hash256 folded = xorFold(x, y, z);
    std::string rawAddr = "NFA" + base64UrlSafe(folded).substr(3);
    std::string nfaAddress = formatAddress(rawAddr, "NFA");
    std::string ofaAddress = formatAddress(rawAddr, "OFA");

    auto endTime = std::chrono::high_resolution_clock::now();
    double elapsedMs = std::chrono::duration<double, std::milli>(endTime - startTime).count();

    return AttractorResult{
        .finalX = x,
        .finalY = y,
        .finalZ = z,
        .r_p = r_p,
        .r_q = r_q,
        .r_r = r_r,
        .crtX = crtX,
        .foldedHash = folded,
        .addressRaw = rawAddr,
        .addressNFA = nfaAddress,
        .addressOFA = ofaAddress,
        .executionTimeMs = elapsedMs,
        .stepHistory = std::move(history)
    };
}

uint32_t VortexAttractor::hammingDistance(const mpz_class& a, const mpz_class& b) {
    mpz_class diff = a ^ b;
    return mpz_popcount(diff.get_mpz_t());
}

std::vector<SacRoundData> VortexAttractor::calculateSac(
    std::string_view seedHex,
    uint32_t bitToFlip,
    uint32_t rounds,
    const core::AttractorModuli& moduli
) {
    std::string flippedSeed(seedHex);
    if (flippedSeed.rfind("0x", 0) == 0) flippedSeed = flippedSeed.substr(2);
    if (flippedSeed.length() < 512) flippedSeed.append(512 - flippedSeed.length(), '0');

    // Flip bit
    size_t byteIdx = bitToFlip / 8;
    size_t bitOffset = bitToFlip % 8;
    if (byteIdx * 2 < flippedSeed.length()) {
        unsigned int byteVal = std::stoul(flippedSeed.substr(byteIdx * 2, 2), nullptr, 16);
        byteVal ^= (1 << bitOffset);
        std::stringstream ss;
        ss << std::hex << std::setw(2) << std::setfill('0') << byteVal;
        flippedSeed.replace(byteIdx * 2, 2, ss.str());
    }

    mpz_class PHI_1024 = hexToBigInt(core::PHI_1024_HEX);

    // Initial state A
    mpz_class X_a = hexToBigInt(std::string(seedHex).substr(0, 256));
    mpz_class Y_a = hexToBigInt(std::string(seedHex).substr(256, 256));
    mpz_class Z_a = ((pow3_mod(X_a, moduli.r) + pow3_mod(Y_a, moduli.r)) % moduli.r) 
                    ^ rotl1024(PHI_1024, mpz_class(Y_a % 64).get_ui());

    // Initial state B
    mpz_class X_b = hexToBigInt(flippedSeed.substr(0, 256));
    mpz_class Y_b = hexToBigInt(flippedSeed.substr(256, 256));
    mpz_class Z_b = ((pow3_mod(X_b, moduli.r) + pow3_mod(Y_b, moduli.r)) % moduli.r) 
                    ^ rotl1024(PHI_1024, mpz_class(Y_b % 64).get_ui());

    std::vector<SacRoundData> report;
    report.reserve(rounds);

    for (uint32_t t = 1; t <= rounds; ++t) {
        auto stepA = step(X_a, Y_a, Z_a, t, moduli, PHI_1024);
        auto stepB = step(X_b, Y_b, Z_b, t, moduli, PHI_1024);

        X_a = stepA.x; Y_a = stepA.y; Z_a = stepA.z;
        X_b = stepB.x; Y_b = stepB.y; Z_b = stepB.z;

        uint32_t dist = hammingDistance(X_a, X_b) + hammingDistance(Y_a, Y_b) + hammingDistance(Z_a, Z_b);
        double pct = (static_cast<double>(dist) / (1024.0 * 3.0)) * 100.0;
        report.push_back(SacRoundData{ .round = t, .bitDistance = dist, .percentage = pct });
    }

    return report;
}

} // namespace vx::math
