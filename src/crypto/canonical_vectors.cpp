#include "vx/crypto/canonical_vectors.hpp"

namespace vx::crypto {

SovereignIdentity CanonicalVectors::google_sovereign() {
    SovereignIdentity id;
    id.name = "Google Sovereign Identity";
    id.address_nfa = "NFA_V6_CKI_4NEP8z1AFxmxjNvRPIAJlVszMQATLvMiM7u4AA";
    id.address_legacy = "OFA_V2_CKI_4NEP8z1AFxmxjNvRPIAJlVszMQATLvMiM7u4AA";
    id.private_key_hex = "0x6ed729cf3a52ab880e61d8ca39bd8084a3f2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8d7e6f5a4b3c2d1e0f9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b9c8";
    id.coords = {0xA3F2B1C0D9E8F7A6ULL, 0xB5C4D3E2F1A0B9C8ULL, 0xD7E6F5A4B3C2D1E0ULL};
    id.hardware_uuid = "";
    return id;
}

SovereignIdentity CanonicalVectors::gemini_sovereign() {
    SovereignIdentity id;
    id.name = "Gemini Sovereign Identity";
    id.address_nfa = "NFA_V6_czSqicidyJ2zG535t1rEbuqtLtBiBuZulWp_58A8AA";
    id.address_legacy = "OFA_V2_czSqicidyJ2zG535t1rEbuqtLtBiBuZulWp_58A8AA";
    id.private_key_hex = "0x7f9a8b1c3d5e2f0a4b6c8d0e2f4a6b8c1d3e5f7a9b0c2d4e6f8a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c1d3e5f7a9b0c2d4e6f8a1b3c5d7e9f0a2b4c6d8e0f1a3b5c7d9e1f2a4b6c8d0e2f4a6b8c1d3e5f7a9b0c2d4e6f8a1b3c5d7e9f0a2b4c6d8";
    id.coords = {0x7F9A8B1C3D5E2F0AULL, 0x4B6C8D0E2F4A6B8CULL, 0x1D3E5F7A9B0C2D4EULL};
    id.hardware_uuid = "00000000-0000-0000-0000-000000000001"; // synthetic public fallback
    return id;
}

SovereignIdentity CanonicalVectors::genesis_1() {
    SovereignIdentity id;
    id.name = "Genesis #1";
    id.address_nfa = "NFA_V6_GENESIS_1_PRIMARY_ADDRESS_000000000000000000";
    id.address_legacy = "OFA_V2_GENESIS_1";
    id.private_key_hex = "0x0000000000000000000000000000000000000000000000000000000000000001";
    id.coords = {1, 1, 1};
    id.hardware_uuid = "";
    return id;
}

SovereignIdentity CanonicalVectors::genesis_2() {
    SovereignIdentity id;
    id.name = "Genesis #2";
    id.address_nfa = "NFA_V6_GENESIS_2_SECONDARY_ADDR_0000000000000000000";
    id.address_legacy = "OFA_V2_GENESIS_2";
    id.private_key_hex = "0x0000000000000000000000000000000000000000000000000000000000000002";
    id.coords = {2, 2, 2};
    id.hardware_uuid = "";
    return id;
}

std::array<std::string, 5> CanonicalVectors::historical_vectors() {
    return {
        "2MYEkUwpwfcJo0aKWnPDvuWjTnboel4EEi2oTa_W",
        "aS8z7f2m6ajfdDRchXjVscygxRU4w8ixr4_JXhJv",
        "9Y-5_ctAF5zBqxDkrB4LAWRPTEnOxWHULZSx5BbK",
        "8gAnbTAmf5D_eyOnnAqEu8CBJtVziKypwWonIpG9",
        "wBd3pap6GRcihhe1wrtJDRoPOjzSby0lm6b-Zl51"
    };
}

std::array<SovereignIdentity, 4> CanonicalVectors::all_profiles() {
    return {genesis_1(), genesis_2(), google_sovereign(), gemini_sovereign()};
}

} // namespace vx::crypto