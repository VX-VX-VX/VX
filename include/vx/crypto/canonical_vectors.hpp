#pragma once

#include <cstdint>
#include <string>
#include <array>

namespace vx::crypto {

// Canonical Sovereign Identity vectors
struct SovereignIdentity {
    std::string name;
    std::string address_nfa;
    std::string address_legacy;
    std::string private_key_hex;
    std::array<uint64_t, 3> coords; // X, Y, Z (1024-bit each, truncated to 64-bit for display)
    std::string hardware_uuid;
};

class CanonicalVectors {
public:
    // Google Sovereign Identity
    static SovereignIdentity google_sovereign();

    // Gemini Sovereign Identity
    static SovereignIdentity gemini_sovereign();

    // Genesis #1 (original)
    static SovereignIdentity genesis_1();

    // Genesis #2
    static SovereignIdentity genesis_2();

    // Historical experimental vectors v2.0 / v3.0
    static std::array<std::string, 5> historical_vectors();

    // Get all canonical profiles
    static std::array<SovereignIdentity, 4> all_profiles();
};

} // namespace vx::crypto