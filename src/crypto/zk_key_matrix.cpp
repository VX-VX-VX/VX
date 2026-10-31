#include "vx/crypto/zk_key_matrix.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include <cstring>
#include <random>
#include <algorithm>
#include <chrono>
#include <array>
#include <initializer_list>
#include <stdexcept>

namespace vx::crypto {

static inline uint8_t gf256_add(uint8_t a, uint8_t b) noexcept { return a ^ b; }
static inline uint8_t gf256_mul(uint8_t a, uint8_t b) noexcept {
    uint8_t p = 0;
    for (int i = 0; i < 8; ++i) {
        if (b & 1) p ^= a;
        bool hi = (a & 0x80) != 0;
        a <<= 1;
        if (hi) a ^= 0x1B;
        b >>= 1;
    }
    return p;
}
static inline uint8_t gf256_inv(uint8_t a) noexcept {
    if (a == 0) return 0;
    uint8_t res = 1, base = a, exp = 254;
    while (exp > 0) {
        if (exp & 1) res = gf256_mul(res, base);
        base = gf256_mul(base, base);
        exp >>= 1;
    }
    return res;
}

static std::array<uint64_t, 4> domain_constant(const char* domain) {
    std::array<uint64_t, 4> C = {0x9E3779B97F4A7C15ULL, 0xBF58476D1CE4E5B9ULL, 0x94D049BB133111EBULL, 0xC6E25B5128E7F995ULL};
    for (size_t i = 0; domain[i]; ++i) {
        uint8_t c = static_cast<uint8_t>(domain[i]);
        for (int j = 0; j < 4; ++j) { C[j] ^= c; C[j] *= 0x100000001B3ULL; }
    }
    return C;
}

static std::array<uint8_t, 32> u64_to_bytes(const std::array<uint64_t, 4>& u) {
    std::array<uint8_t, 32> out;
    for (int i = 0; i < 4; ++i) std::memcpy(out.data() + i * 8, &u[i], 8);
    return out;
}

static std::array<uint64_t, 4> bytes_to_u64(const std::array<uint8_t, 32>& b) {
    std::array<uint64_t, 4> out;
    for (int i = 0; i < 4; ++i) std::memcpy(&out[i], b.data() + i * 8, 8);
    return out;
}

static void fractal_chaos_64(std::array<uint64_t, 4>& z, const std::array<uint64_t, 4>& C, int rounds) {
    for (int r = 0; r < rounds; ++r)
        for (int i = 0; i < 4; ++i) {
            uint64_t x = z[i];
            z[i] = (x * x * x) ^ C[i];
        }
}

static std::array<uint8_t, 32> arx_compress_sk(const std::array<uint8_t, 256>& master_seed) {
    std::array<uint64_t, 4> state = {0, 0, 0, 0};
    for (int block = 0; block < 8; ++block) {
        for (int i = 0; i < 4; ++i) {
            uint64_t word = 0;
            std::memcpy(&word, master_seed.data() + block * 32 + i * 8, 8);
            state[i] ^= word;
            uint64_t x = state[i];
            uint64_t cubic = x * x * x;
            state[i] = (x + 0x9E3779B97F4A7C15ULL) ^ cubic;
        }
    }
    // 64 rounds of ARX with cubic mixing
    static constexpr uint64_t RC[64] = {
        0x428A2F98D728AE22ULL, 0x7137449123EF65CDULL, 0xB5C0FBCFEC4D3B2FULL, 0xE9B5DBA58189DBBCULL,
        0x3956C25BF348B538ULL, 0x59F111F1B605D019ULL, 0x923F82A4AF194F9BULL, 0xAB1C5ED5DA6D8118ULL,
        0xD807AA98A3030242ULL, 0x12835B0145706FBEULL, 0x243185BE4EE4B28CULL, 0x550C7DC3D5FFB4E2ULL,
        0x72BE5D74F27B896FULL, 0x80DEB1FE3B1696B1ULL, 0x9BDC06A725C71235ULL, 0xC19BF174CF692694ULL,
        0xE49B69C19EF14AD2ULL, 0xEFBE4786384F25E3ULL, 0x0FC19DC68B8CD5B5ULL, 0x240CA1CC77AC9C65ULL,
        0x2DE92C6F592B0275ULL, 0x4A7484AA6EA6E483ULL, 0x5CB0A9DCBD41FBD4ULL, 0x76F988DA831153B5ULL,
        0x983E5152EE66DFABULL, 0xA831C66D2DB43210ULL, 0xB00327C8B00327C8ULL, 0xBF597FC7BF597FC7ULL,
        0xC6E00BF3C6E00BF3ULL, 0xD5A79147D5A79147ULL, 0x06CA635106CA6351ULL, 0x1429296714292967ULL,
        0x27B70A8527B70A85ULL, 0x2E1B21382E1B2138ULL, 0x4D2C6DFC4D2C6DFCULL, 0x53380D1353380D13ULL,
        0x650A7354650A7354ULL, 0x766A0ABB766A0ABBULL, 0x81C2C92E81C2C92EULL, 0x92722C8592722C85ULL,
        0xA2BFE8A1A2BFE8A1ULL, 0xA81A664BA81A664BULL, 0xC24B8B70C24B8B70ULL, 0xC76C51A3C76C51A3ULL,
        0xD192E819D192E819ULL, 0xD6990624D6990624ULL, 0xF40E3585F40E3585ULL, 0x106AA070106AA070ULL,
        0x19A4C11619A4C116ULL, 0x1E376C081E376C08ULL, 0x2748774C2748774CULL, 0x34B0BCB534B0BCB5ULL,
        0x391C0CB3391C0CB3ULL, 0x4ED8AA4A4ED8AA4AULL, 0x5B9CCA4F5B9CCA4FULL, 0x682E6FF3682E6FF3ULL,
        0x748F82EE748F82EEULL, 0x78A5636F78A5636FULL, 0x84C8781484C87814ULL, 0x8CC702088CC70208ULL,
        0x90BEFFFA90BEFFFAULL, 0xA4506CEBA4506CEBULL, 0xBEF9A3F7BEF9A3F7ULL, 0xC67178F2C67178F2ULL
    };
    for (int r = 0; r < 64; ++r) {
        for (int i = 0; i < 4; ++i) {
            uint64_t x = state[i];
            uint64_t cubic = x * x * x;
            state[i] = (x + RC[r]) ^ cubic;
        }
        uint64_t t = state[3];
        state[3] = state[2];
        state[2] = state[1];
        state[1] = state[0];
        state[0] = t;
    }
    std::array<uint8_t, 32> sk;
    for (int i = 0; i < 4; ++i) std::memcpy(sk.data() + i * 8, &state[i], 8);
    return sk;
}

std::array<ZKKeyMatrix::KeyTier, 7> ZKKeyMatrix::derive_all_keys(const std::array<uint8_t, 256>& master_seed) {
    std::array<KeyTier, 7> keys;
    keys[0].key_data = arx_compress_sk(master_seed);
    keys[0].tier_name = "SpendingKey"; keys[0].is_spending_key = true; keys[0].can_sign = true;
    keys[0].can_view_inputs = true; keys[0].can_view_outputs = true; keys[0].can_view_balance = true;
    std::array<uint64_t, 4> z = bytes_to_u64(keys[0].key_data);
    // Tier 2: FVK
    { auto C = domain_constant("VX_FVK_BOUNDARY_MASK"); auto zf = z; fractal_chaos_64(zf, C, 64); keys[1].key_data = u64_to_bytes(zf); }
    keys[1].tier_name = "FullViewingKey"; keys[1].is_spending_key = false; keys[1].can_sign = false;
    keys[1].can_view_inputs = true; keys[1].can_view_outputs = true; keys[1].can_view_balance = true;
    // Tier 3: IVK
    { auto C = domain_constant("VX_IVK_EVEN_ORBIT"); auto zi = z; std::array<uint64_t, 4> acc = {0,0,0,0}; for(int r=1;r<=64;++r){ for(int i=0;i<4;++i) zi[i] = (zi[i]*zi[i]*zi[i])^C[i]; if((r&1)==0) for(int i=0;i<4;++i) acc[i]^=zi[i]; } keys[2].key_data = u64_to_bytes(acc); }
    keys[2].tier_name = "IncomingViewingKey"; keys[2].is_spending_key = false; keys[2].can_sign = false; keys[2].can_view_inputs = true; keys[2].can_view_outputs = false; keys[2].can_view_balance = false;
    // Tier 4: OVK
    { auto C = domain_constant("VX_OVK_ODD_ORBIT"); auto zo = z; std::array<uint64_t, 4> acc = {0,0,0,0}; for(int r=1;r<=64;++r){ for(int i=0;i<4;++i) zo[i] = (zo[i]*zo[i]*zo[i])^C[i]; if(r&1) for(int i=0;i<4;++i) acc[i]^=zo[i]; } keys[3].key_data = u64_to_bytes(acc); }
    keys[3].tier_name = "OutgoingViewingKey"; keys[3].is_spending_key = false; keys[3].can_sign = false; keys[3].can_view_inputs = false; keys[3].can_view_outputs = true; keys[3].can_view_balance = false;
    // Tier 5: TLMK
    { auto C = domain_constant("VX_TLMK_FIXED_POINT"); auto zt = z; fractal_chaos_64(zt, C, 128); keys[4].key_data = u64_to_bytes(zt); }
    keys[4].tier_name = "TimeLockMaintenanceKey"; keys[4].is_spending_key = false; keys[4].can_sign = false; keys[4].can_view_inputs = false; keys[4].can_view_outputs = false; keys[4].can_view_balance = false;
    // Tier 6: MSRK
    { auto C = domain_constant("VX_MSRK_POLYNOMIAL_C"); auto cm = C; fractal_chaos_64(cm, cm, 64); keys[5].key_data = u64_to_bytes(cm); }
    keys[5].tier_name = "MultiSigRecoveryKey"; keys[5].is_spending_key = false; keys[5].can_sign = false; keys[5].can_view_inputs = false; keys[5].can_view_outputs = false; keys[5].can_view_balance = false;
    // Tier 7: EK
    { auto C = domain_constant("VX_EK_MICRO_ORBIT_10"); auto ze = z; fractal_chaos_64(ze, C, 10); keys[6].key_data = u64_to_bytes(ze); }
    keys[6].tier_name = "EphemeralKey"; keys[6].is_spending_key = true; keys[6].can_sign = true; keys[6].can_view_inputs = false; keys[6].can_view_outputs = false; keys[6].can_view_balance = false;
    // Self-check: all keys distinct
    for(int i=0; i<7; ++i) for(int j=i+1; j<7; ++j) if(keys[i].key_data == keys[j].key_data){ keys[i].key_data.fill(0); keys[j].key_data.fill(0); }
    return keys;
}

std::array<ZKKeyMatrix::ShamirShard, 3> ZKKeyMatrix::generate_shamir_shards(const std::array<uint8_t, 32>& secret, uint8_t threshold) {
    if(threshold<2 || threshold>3) throw std::invalid_argument("Threshold");
    std::array<ShamirShard, 3> shards;
    std::random_device rd; std::mt19937_64 gen(rd()); std::uniform_int_distribution<uint8_t> dist(1,255);
    std::array<std::array<uint8_t, 32>, 3> coeffs;
    for(int b=0; b<32; ++b) coeffs[0][b]=secret[b];
    for(int c=1; c<threshold; ++c) for(int b=0; b<32; ++b) coeffs[c][b]=dist(gen);
    for(int s=0; s<3; ++s){
        uint8_t x=s+1; shards[s].x=x; std::array<uint8_t, 32> y{};
        for(int b=0; b<32; ++b){
            uint8_t sum=coeffs[0][b]; uint8_t xp=x;
            for(int c=1; c<threshold; ++c){ sum=gf256_add(sum, gf256_mul(coeffs[c][b], xp)); xp=gf256_mul(xp, x); }
            y[b]=sum;
        }
        shards[s].y=y;
    }
    return shards;
}

std::array<uint8_t, 32> ZKKeyMatrix::recover_shamir_secret(const std::vector<ShamirShard>& shards) {
    if(shards.size()<2) return {};
    std::array<uint8_t, 32> rec{};
    for(int k=0; k<32; ++k){
        uint8_t sum=0;
        for(size_t i=0; i<shards.size(); ++i){
            uint8_t xi=shards[i].x, yi=shards[i].y[k], li=1;
            for(size_t j=0; j<shards.size(); ++j) if(i!=j){ uint8_t xj=shards[j].x; li=gf256_mul(li, gf256_mul(xj, gf256_inv(gf256_add(xj, xi)))); }
            sum=gf256_add(sum, gf256_mul(yi, li));
        }
        rec[k]=sum;
    }
    return rec;
}

ZKKeyMatrix::ZKProof ZKKeyMatrix::generate_proof_of_life(const std::array<uint8_t, 32>& tlmk) {
    ZKProof proof; proof.valid=true; proof.timestamp=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    std::array<uint64_t, 4> z=bytes_to_u64(tlmk); uint64_t t=proof.timestamp;
    z[0]^=t; z[1]^=t>>32; z[2]^=t*0x9E3779B97F4A7C15ULL; z[3]^=t^0xBF58476D1CE4E5B9ULL;
    auto C=domain_constant("VX_POL_COMMITMENT"); fractal_chaos_64(z, C, 16);
    proof.commitment=u64_to_bytes(z);
    std::array<uint64_t, 4> zh=z; for(int r=0; r<32; ++r) for(int i=0; i<4; ++i){ uint64_t x=zh[i]; zh[i]=(x*x*x)^0x9E3779B97F4A7C15ULL; }
    proof.proof_hash=u64_to_bytes(zh);
    return proof;
}

bool ZKKeyMatrix::verify_proof_of_life(const ZKProof& proof) {
    constexpr uint64_t WINDOW=315360000ULL;
    uint64_t now=std::chrono::duration_cast<std::chrono::seconds>(std::chrono::system_clock::now().time_since_epoch()).count();
    if(proof.timestamp>now || now-proof.timestamp>WINDOW) return false;
    std::array<uint64_t, 4> z=bytes_to_u64(proof.commitment);
    for(int r=0; r<32; ++r) for(int i=0; i<4; ++i){ uint64_t x=z[i]; z[i]=(x*x*x)^0x9E3779B97F4A7C15ULL; }
    std::array<uint8_t, 32> h=u64_to_bytes(z);
    return (h==proof.proof_hash) && proof.valid;
}

ZKKeyMatrix::AuditResult ZKKeyMatrix::audit_view(const std::array<uint8_t, 32>& vk, bool is_fvk, bool is_ivk, bool is_ovk) {
    AuditResult result; result.can_view_inputs=is_fvk||is_ivk; result.can_view_outputs=is_fvk||is_ovk; result.can_view_balance=is_fvk; result.audit_commitment.fill(0); result.visible_transactions.clear();
    bool has=false; for(auto b:vk) if(b){has=true; break;} if(!has) return result;
    std::array<uint64_t, 4> z=bytes_to_u64(vk); auto C=domain_constant("VX_AUDIT_COMMITMENT"); fractal_chaos_64(z, C, 8);
    result.audit_commitment=u64_to_bytes(z);
    return result;
}

// ════════════════════════════════════════════════════════════════════════════
// Stealth Ring Envelopes 1-of-16
// ════════════════════════════════════════════════════════════════════════════

namespace {

void stealth_sponge(const uint8_t* domain, size_t dom_len,
                    std::initializer_list<std::pair<const uint8_t*, size_t>> parts,
                    uint8_t out[32]) {
    blockchain::VortexSponge256 sponge;
    sponge.absorb(domain, dom_len);
    for (const auto& [p, len] : parts) sponge.absorb(p, len);
    sponge.finalize(out);
}

std::array<uint8_t, 42> derive_stealth_addr(const std::array<uint8_t, 32>& ivk_pub,
                                            const std::array<uint8_t, 32>& ephemeral_pub) {
    // One-time destination: sponge over the recipient's public IVK projection
    // and the sender's ephemeral key — unlinkable across transactions.
    std::array<uint8_t, 32> one_time{};
    const uint8_t dom[] = "VXSTEALTH1";
    stealth_sponge(dom, sizeof(dom) - 1,
                   {{ivk_pub.data(), 32}, {ephemeral_pub.data(), 32}},
                   one_time.data());
    std::array<uint8_t, 42> addr{};
    std::memcpy(addr.data(), "NFA_ST_", 7);
    // 35 one-time bytes: 32 from the sponge + 3 checksum bytes.
    std::memcpy(addr.data() + 7, one_time.data(), 32);
    for (int i = 0; i < 3; ++i) addr[39 + i] = static_cast<uint8_t>(one_time[i] ^ one_time[7 + i]);
    return addr;
}

} // namespace

StealthKeyHierarchy derive_stealth_hierarchy(const std::array<uint8_t, 32>& master_seed) {
    StealthKeyHierarchy h;
    // SK: master seed directly.
    h.sk = master_seed;
    // FVK: full-view projection of SK.
    const uint8_t fvk_dom[] = "VXFVK";
    stealth_sponge(fvk_dom, sizeof(fvk_dom) - 1, {{h.sk.data(), 32}}, h.fvk.data());
    // IVK: even-iteration (2n) projection only — no Z0, no SK. Two chained
    // sponge rounds (n=2) domain-separated for incoming visibility.
    std::array<uint8_t, 32> step{};
    const uint8_t ivk_dom[] = "VXIVK2N";
    stealth_sponge(ivk_dom, sizeof(ivk_dom) - 1, {{h.fvk.data(), 32}}, step.data());
    stealth_sponge(ivk_dom, sizeof(ivk_dom) - 1, {{step.data(), 32}}, h.ivk.data());
    // OVK: outgoing-view projection.
    const uint8_t ovk_dom[] = "VXOVK";
    stealth_sponge(ovk_dom, sizeof(ovk_dom) - 1, {{h.sk.data(), 32}}, h.ovk.data());
    return h;
}

std::array<uint8_t, 12> stealth_scan_tag(const std::array<uint8_t, 32>& ivk,
                                         const std::array<uint8_t, 42>& stealth_addr) {
    // Public projection of the IVK (can_spend: false) bound to the one-time
    // address: only the holder of the true IVK can recompute this tag.
    std::array<uint8_t, 32> ivk_pub{};
    const uint8_t pub_dom[] = "VXIVKPUB";
    stealth_sponge(pub_dom, sizeof(pub_dom) - 1, {{ivk.data(), 32}}, ivk_pub.data());
    std::array<uint8_t, 32> tag32{};
    const uint8_t tag_dom[] = "VXSTTAG";
    stealth_sponge(tag_dom, sizeof(tag_dom) - 1,
                   {{ivk_pub.data(), 32}, {stealth_addr.data(), 42}}, tag32.data());
    std::array<uint8_t, 12> tag{};
    std::memcpy(tag.data(), tag32.data(), 12);
    return tag;
}

StealthEnvelope create_stealth_envelope(
    const std::array<uint8_t, 32>& sender_seed,
    const std::array<uint8_t, 32>& recipient_ivk,
    const std::vector<std::array<uint8_t, STEALTH_ADDR_BYTES>>& ledger_decoys) {
    StealthEnvelope env;

    // Sender-side hierarchy: SK -> FVK -> IVK -> OVK.
    const StealthKeyHierarchy sender_keys = derive_stealth_hierarchy(sender_seed);

    // Recipient's public IVK projection (the recipient's published identifier
    // IS their IVK — proves incoming visibility, can_spend stays false).
    std::array<uint8_t, 32> recv_ivk_pub{};
    const uint8_t dom[] = "VXIVKPUB";
    stealth_sponge(dom, sizeof(dom) - 1, {{recipient_ivk.data(), 32}}, recv_ivk_pub.data());

    // Ephemeral key EK: sender secret mixed with the recipient identity.
    const uint8_t ek_dom[] = "VXEK";
    stealth_sponge(ek_dom, sizeof(ek_dom) - 1,
                   {{sender_keys.sk.data(), 32}, {recipient_ivk.data(), 32}},
                   env.ephemeral_pub.data());

    // One-time stealth destination address.
    env.stealth_addr = derive_stealth_addr(recv_ivk_pub, env.ephemeral_pub);

    // Public scan tag bound to (recipient IVK projection, one-time address):
    // the recipient recomputes exactly this from their own IVK, while a
    // foreign IVK derives a different projection and sees only noise.
    const uint8_t tag_dom[] = "VXSTTAG";
    std::array<uint8_t, 32> tag32{};
    stealth_sponge(tag_dom, sizeof(tag_dom) - 1,
                   {{recv_ivk_pub.data(), 32}, {env.stealth_addr.data(), 42}}, tag32.data());
    std::memcpy(env.scan_tag.data(), tag32.data(), 12);

    // Key image: double-spend anchor computed over the one-time address.
    const uint8_t ki_dom[] = "VXKEYIMG";
    stealth_sponge(ki_dom, sizeof(ki_dom) - 1,
                   {{recv_ivk_pub.data(), 32}, {env.stealth_addr.data(), 42}},
                   env.key_image.data());

    // Ring of 16: 1 real + 15 ledger decoys.
    env.ring_members.push_back(env.stealth_addr); // real receiver first
    for (size_t i = 0; env.ring_members.size() < STEALTH_RING_SIZE; ++i) {
        if (i < ledger_decoys.size()) {
            env.ring_members.push_back(ledger_decoys[i]);
        } else {
            // Deterministic synthetic decoy bound to the envelope.
            std::array<uint8_t, 32> d{};
            const uint8_t d_dom[] = "VXDECOY";
            stealth_sponge(d_dom, sizeof(d_dom) - 1,
                           {{env.ephemeral_pub.data(), 32},
                            {reinterpret_cast<const uint8_t*>(&i), sizeof(i)}},
                           d.data());
            std::array<uint8_t, 42> decoy{};
            std::memcpy(decoy.data(), "NFA_ST_", 7);
            std::memcpy(decoy.data() + 7, d.data(), 35);
            env.ring_members.push_back(decoy);
        }
    }
    // Real index: deterministic mix of the ephemeral key (uniform in [0,16)).
    env.real_index = static_cast<uint32_t>(env.ephemeral_pub[0] % STEALTH_RING_SIZE);
    if (env.real_index != 0) {
        std::swap(env.ring_members[0], env.ring_members[env.real_index]);
    }
    return env;
}

void stamp_stealth_envelope(const StealthEnvelope& env, blockchain::Transaction& tx) {
    // receiver[42] <- one-time NFA_ST_ address.
    std::memcpy(tx.receiver_nfa, env.stealth_addr.data(), STEALTH_ADDR_BYTES);
    // cocoon_proof[12] <- public IVK scan tag (can_spend stays false).
    std::memcpy(tx.cocoon_proof, env.scan_tag.data(), 12);
}

std::vector<size_t> scan_transactions_with_ivk(
    const std::array<uint8_t, 32>& ivk,
    std::span<const blockchain::Transaction> txs) {
    std::vector<size_t> hits;
    std::array<uint8_t, 32> ivk_pub{};
    const uint8_t pub_dom[] = "VXIVKPUB";
    stealth_sponge(pub_dom, sizeof(pub_dom) - 1, {{ivk.data(), 32}}, ivk_pub.data());

    for (size_t i = 0; i < txs.size(); ++i) {
        const auto& tx = txs[i];
        // Quick reject: only one-time NFA_ST_ destinations can match.
        if (std::memcmp(tx.receiver_nfa, "NFA_ST_", 7) != 0) continue;
        std::array<uint8_t, 12> expect{};
        blockchain::VortexSponge256 sponge;
        const uint8_t tag_dom[] = "VXSTTAG";
        sponge.absorb(tag_dom, sizeof(tag_dom) - 1);
        sponge.absorb(ivk_pub.data(), 32);
        sponge.absorb(tx.receiver_nfa, 42);
        uint8_t tag32[32];
        sponge.finalize(tag32);
        std::memcpy(expect.data(), tag32, 12);
        if (std::memcmp(expect.data(), tx.cocoon_proof, 12) == 0) hits.push_back(i);
    }
    return hits;
}

} // namespace vx::crypto