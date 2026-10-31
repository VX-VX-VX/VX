// ─────────────────────────────────────────────────────────────────────────────
// Post-Quantum Hash-Based Signature Engine test suite.
//   WOTS+ (w=16, L=67) + XMSS (H=4) over VortexSponge256, SegPQ witness,
//   MemoryVault burn proof, sponge KATs + SAC matrix + collision smoke.
// ─────────────────────────────────────────────────────────────────────────────

#include "vx/crypto/pq_signature.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/core/memory_vault.hpp"

// Build type is Release (-DNDEBUG): force asserts ON — this suite must be a
// real tripwire, not a no-op.
#undef NDEBUG
#include <cassert>
#include <cstddef>
#include <cstring>
#include <iostream>
#include <unordered_set>
#include <vector>

using namespace vx::crypto::pq;
namespace bc = vx::blockchain;

namespace {

std::array<uint8_t, 32> test_msg(const char* tag) noexcept {
    std::array<uint8_t, 32> out{};
    bc::VortexSponge256::compute(reinterpret_cast<const uint8_t*>(tag),
                                 std::strlen(tag), out.data());
    return out;
}

bc::Transaction make_test_tx(uint32_t nonce) noexcept {
    bc::Transaction tx{};
    for (int i = 0; i < 42; ++i) {
        tx.sender_nfa[i] = static_cast<uint8_t>('P' + i % 16);
        tx.receiver_nfa[i] = static_cast<uint8_t>('R' + i % 16);
    }
    bc::tx_set_amount(tx, 12500000000ull); // 125 VX
    bc::tx_set_fee(tx, 2500);
    bc::tx_set_nonce(tx, nonce);
    return tx;
}

} // namespace

// ── TEST 1: honest sign → verify ─────────────────────────────────────────────

void test_wots_sign_verify_valid() {
    std::cout << "[TEST 1] WOTS+ (w=16, L=67) + XMSS (H=4) honest sign/verify...\n";
    const auto sk = test_msg("VX_PQ_TEST_MASTER_SK");
    const auto seed = test_msg("VX_PQ_TEST_PUB_SEED");
    const auto msg = test_msg("VX_PQ_TEST_MESSAGE_01");

    const auto root_direct = xmss_root(sk, seed);
    PqSignatureWitness w = pq_sign_message(3, 0, sk, seed, msg);
    assert(w.pq_pubkey_root == root_direct); // sign-side tree == keygen tree
    assert(w.witness_digest != std::array<uint8_t, 32>{});

    assert(pq_verify_wots_xmss(msg, w));

    // A different leaf of the same tree must also verify.
    PqSignatureWitness w7 = pq_sign_message(7, 0, sk, seed, msg);
    assert(pq_verify_wots_xmss(msg, w7));
    // ...but leaf 7's witness must NOT verify as leaf 3's.
    PqSignatureWitness w7_wrong_leaf = w7;
    w7_wrong_leaf.leaf_index = 3;
    assert(!pq_verify_wots_xmss(msg, w7_wrong_leaf));

    std::cout << "  ✓ 67-chain signature verifies; wrong leaf index rejected\n\n";
}

// ── TEST 2: Winternitz checksum barrier ──────────────────────────────────────

void test_winternitz_checksum_barrier() {
    std::cout << "[TEST 2] Winternitz checksum blocks forward-chain forgery...\n";
    const auto sk = test_msg("VX_PQ_TEST_MASTER_SK");
    const auto seed = test_msg("VX_PQ_TEST_PUB_SEED");
    const auto msg = test_msg("VX_PQ_TEST_MESSAGE_02");

    const uint32_t c_before = winternitz_checksum(msg.data());
    PqSignatureWitness w = pq_sign_message(0, 0, sk, seed, msg);

    // Bump the first message nibble that is below 15 (forward-chain attempt:
    // the attacker wants a "later" chain state without the secret).
    std::array<uint8_t, 32> forged = msg;
    size_t nibble_pos = 0;
    for (size_t i = 0; i < WOTS_MSG_NIBBLES; ++i) {
        const uint8_t nib = (forged[i >> 1] >> ((i & 1) ? 0 : 4)) & 0x0F;
        if (nib < 15) { nibble_pos = i; break; }
    }
    forged[nibble_pos >> 1] ^= static_cast<uint8_t>(0x10 >> ((nibble_pos & 1) ? 4 : 0));

    const uint32_t c_after = winternitz_checksum(forged.data());
    assert(c_after == c_before - 1); // the checksum STRICTLY falls — mathematically forced
    assert(!pq_verify_wots_xmss(forged, w)); // and the forgery is rejected

    std::cout << "  ✓ m_" << nibble_pos << " += 1 forced C: " << c_before
              << " -> " << c_after << "; verification rejected\n\n";
}

// ── TEST 3: keyless recalculation cannot fool a PQ sender ────────────────────

void test_mitm_keyless_recalculation_rejected() {
    std::cout << "[TEST 3] MITM keyless rehash rejected by SegPQ registry...\n";
    const auto sk = test_msg("VX_PQ_TEST_MASTER_SK");
    bc::Transaction tx = make_test_tx(5);
    vx::blockchain::set_nfa_field(tx.sender_nfa, "PQSENDER_TEST_ACCOUNT_PQSENDER_TEST_ACCOUN");

    pq_sign_transaction(tx, sk);
    assert(verify_transaction_proof(tx)); // honest PQ-signed tx passes
    assert(PqWitnessRegistry::instance().is_pq_sender(tx.sender_nfa));

    // The attack: mutate the amount and re-run the KEYLESS legacy signer.
    bc::Transaction stolen = tx;
    bc::tx_set_amount(stolen, 99900000000ull); // 999 VX — attacker's dream
    bc::sign_transaction(stolen); // keyless checksum recalculation
    assert(!verify_transaction_proof(stolen)); // SegPQ guard rejects it

    // Same for receiver hijack.
    bc::Transaction hijack = tx;
    hijack.receiver_nfa[0] ^= 0x20;
    bc::sign_transaction(hijack);
    assert(!verify_transaction_proof(hijack));

    std::cout << "  ✓ keyless re-sign after amount/receiver mutation rejected\n\n";
}

// ── TEST 4: witness tampering ────────────────────────────────────────────────

void test_tamper_chains_and_merkle_path() {
    std::cout << "[TEST 4] Tampered WOTS+ chains / Merkle auth path rejected...\n";
    const auto sk = test_msg("VX_PQ_TEST_MASTER_SK");
    const auto seed = test_msg("VX_PQ_TEST_PUB_SEED");
    const auto msg = test_msg("VX_PQ_TEST_MESSAGE_04");
    PqSignatureWitness w = pq_sign_message(2, 0, sk, seed, msg);
    assert(pq_verify_wots_xmss(msg, w));

    // Flip one bit in sampled chains: first, middle (checksum chain), last.
    for (const size_t ci : {size_t{0}, size_t{33}, size_t{66}}) {
        PqSignatureWitness bad = w;
        bad.wots_sig[ci][7] ^= 0x10;
        assert(!pq_verify_wots_xmss(msg, bad));
    }
    // Flip one bit in EVERY auth-path node — the root must never survive.
    for (size_t lvl = 0; lvl < XMSS_H; ++lvl) {
        PqSignatureWitness bad = w;
        bad.auth_path[lvl][0] ^= 0x40;
        assert(!pq_verify_wots_xmss(msg, bad));
    }
    // Full 67-chain sweep (every chain, bit 0 of byte 0).
    for (size_t ci = 0; ci < WOTS_CHAINS; ++ci) {
        PqSignatureWitness bad = w;
        bad.wots_sig[ci][0] ^= 0x01;
        assert(!pq_verify_wots_xmss(msg, bad));
    }

    std::cout << "  ✓ all 67 chains + all 4 auth-path nodes are tamper-evident\n\n";
}

// ── TEST 5: MemoryVault burns the secret chains ────────────────────────────

void test_vault_burn() {
    std::cout << "[TEST 5] Vault ephemeral PQ sign burns secret material...\n";
    const auto sk = test_msg("VX_PQ_TEST_MASTER_SK");
    bc::Transaction tx = make_test_tx(9);
    vx::blockchain::set_nfa_field(tx.sender_nfa, "PQBURN_TEST_ACCOUNT_PQBURN_TEST_ACCOUNT_PQ");

    PqSignTimings t;
    pq_sign_transaction(tx, sk, &t);

    assert(t.vault_burn_verified);       // the key page is provably BURNED
    assert(t.keygen_cycles > 0);
    assert(t.sign_cycles > 0);
    assert(verify_transaction_proof(tx));

    std::cout << "  ✓ burn verified; keygen " << t.keygen_cycles << " cyc, sign "
              << t.sign_cycles << " cyc\n\n";
}

// ── TEST 6: sponge KATs + SAC matrix + collision smoke ───────────────────────

void test_sponge_kat_sac_collisions() {
    std::cout << "[TEST 6] VortexSponge256 KATs, SAC matrix [45%..55%], collisions...\n";

  // ── Known Answer Tests (5 public vectors, freeze) ──
    struct Kat { const char* name; unsigned char expected[32]; };
    static const Kat kats[] = {
        {"KAT_EMPTY",
         {0x7b,0xdb,0xc2,0x00,0x2c,0x92,0xb6,0xc3,0xa7,0xab,0xd2,0x44,0x72,0x6a,0x17,0x01,
          0xbf,0xf9,0x4e,0x65,0xcb,0x6f,0x9e,0x58,0xed,0x84,0x50,0x45,0x51,0x98,0x94,0xf0}},
        {"KAT_ABC",
         {0x54,0x6d,0xc0,0xab,0xcf,0x89,0x68,0x44,0x08,0x3e,0xb2,0xe8,0x26,0xd0,0xa2,0x63,
          0x5f,0xfb,0x69,0x9f,0x47,0x30,0xbe,0xc5,0x15,0x59,0xbd,0xdc,0xb6,0x10,0xde,0x24}},
        {"KAT_HDR472",
         {0x03,0xae,0x65,0x6c,0xfe,0x29,0xe8,0xc7,0xc1,0x58,0xcc,0x49,0x5a,0x1c,0xe8,0x3c,
          0x49,0x69,0x63,0x62,0x5e,0x87,0xec,0x87,0x00,0x31,0xbc,0x65,0xc8,0x32,0x1e,0x31}},
        {"KAT_TX112",
         {0x23,0x79,0x59,0x52,0x98,0xb0,0x46,0x26,0xdc,0x17,0x07,0x35,0x86,0x02,0x8b,0x95,
          0x85,0x0d,0x30,0x59,0x4c,0x17,0x24,0xb1,0xa0,0xbf,0xcc,0xd6,0xc2,0xcf,0xb7,0xb6}},
        {"KAT_1MB",
         {0x3b,0x15,0x96,0x48,0x24,0x2e,0x69,0x7a,0x7e,0x08,0xbd,0x54,0x7b,0x85,0x2e,0xd9,
          0xff,0x5f,0x4e,0x29,0xe7,0x1e,0xc3,0x08,0x87,0x5c,0x37,0x5c,0x14,0x08,0x8e,0x0f}},
    };

    auto run_kat = [&](const std::vector<unsigned char>& data) {
        unsigned char d[32];
        bc::VortexSponge256::compute(data.empty() ? nullptr : data.data(), data.size(), d);
        return std::vector<unsigned char>(d, d + 32);
    };

    const std::vector<unsigned char> empty{};
    const std::vector<unsigned char> abc{'a', 'b', 'c'};
    std::vector<unsigned char> hdr(472);
    for (size_t i = 0; i < hdr.size(); ++i) hdr[i] = static_cast<unsigned char>((0xA5 + i * 13) & 0xFF);
    std::vector<unsigned char> tx(112);
    for (size_t i = 0; i < tx.size(); ++i) tx[i] = static_cast<unsigned char>((0x5E + i * 3) & 0xFF);
    std::vector<unsigned char> big(1u << 20);
    for (size_t i = 0; i < big.size(); ++i) big[i] = static_cast<unsigned char>((i * 31 + 7) & 0xFF);

    const std::vector<unsigned char> inputs[] = {empty, abc, hdr, tx, big};
    for (size_t k = 0; k < 5; ++k) {
        const auto got = run_kat(inputs[k]);
        assert(got == std::vector<unsigned char>(kats[k].expected, kats[k].expected + 32));
        std::cout << "  ✓ " << kats[k].name << " matches frozen digest\n";
    }

    // ── SAC matrix: flip every bit of every 64-bit input word; the average
    //    avalanche per word must sit strictly inside [45%, 55%]. ──
    std::vector<unsigned char> base(64);
    for (size_t i = 0; i < base.size(); ++i) base[i] = static_cast<unsigned char>((0xA5 + i * 13) & 0xFF);
    unsigned char base_digest[32];
    bc::VortexSponge256::compute(base.data(), base.size(), base_digest);

    for (size_t w = 0; w < 8; ++w) {
        unsigned long long changed = 0;
        for (size_t bit = 0; bit < 64; ++bit) {
            std::vector<unsigned char> flipped = base;
            flipped[w * 8 + (bit / 8)] ^= static_cast<unsigned char>(1u << (bit % 8));
            unsigned char d[32];
            bc::VortexSponge256::compute(flipped.data(), flipped.size(), d);
            for (int i = 0; i < 32; ++i)
                changed += __builtin_popcount(static_cast<unsigned char>(base_digest[i] ^ d[i]));
        }
        const double pct = 100.0 * changed / (64.0 * 256.0);
        std::cout << "  SAC word " << w << ": " << pct << "%\n";
        assert(pct >= 45.0 && pct <= 55.0);
    }

    // ── Second-preimage / collision smoke: 50 000 low-entropy inputs ──
    std::unordered_set<std::string> seen;
    seen.reserve(50000 * 2);
    for (uint64_t n = 0; n < 50000; ++n) {
        unsigned char buf[32] = {};
        std::memcpy(buf, &n, 8); // low-entropy: 32B buffer, 8B counter
        unsigned char d[32];
        bc::VortexSponge256::compute(buf, 32, d);
        assert(seen.insert(std::string(reinterpret_cast<char*>(d), 32)).second);
    }

    std::cout << "  ✓ 50 000 low-entropy inputs, zero collisions\n\n";
}

// ── TEST 7: negative-vector matrix (wycheproof-style) ────────────────────────
// Two layers, because the two verify functions consume different fields:
//   Layer A (pq_verify_wots_xmss): every byte of the signature-bearing
//   region (pub_seed, root, 67 chains, auth path) must be tamper-evident;
//   the 4-bit leaf domain is swept explicitly. The index header fields that
//   this layer does not or only partially consume (subtree_index, the high
//   bits of leaf_index) are asserted to PASS here and REJECT at layer B —
//   the layering is documented, not hidden.
//   Layer B (pq_verify_transaction): every byte of the WHOLE witness
//   (including the index header and the transported witness_digest field)
//   must be rejected — the verifier recomputes the commitment from the
//   witness content, so no transported field is trusted.

void test_negative_vector_matrix() {
    std::cout << "[TEST 7] Negative-vector matrix: exhaustive witness mutations...\n";
    const auto sk = test_msg("VX_PQ_TEST_MASTER_SK");
    const auto seed = test_msg("VX_PQ_TEST_PUB_SEED");

    // ── Layer A: pure WOTS+/XMSS ──
    const auto msg = test_msg("VX_PQ_TEST_MESSAGE_07");
    PqSignatureWitness w = pq_sign_message(5, 0, sk, seed, msg);
    assert(pq_verify_wots_xmss(msg, w));

    // The witness is a standard-layout POD with no padding (static_asserted
    // by the header); byte offsets inside it are stable.
    constexpr size_t kHeaderOff = offsetof(PqSignatureWitness, pub_seed);
    constexpr size_t kDigestOff = offsetof(PqSignatureWitness, witness_digest);
    const auto* base = reinterpret_cast<const uint8_t*>(&w);

    // Layer A sweeps the signature-bearing region: pub_seed, root, 67 chains,
    // auth path. The 8-byte index header (leaf_index, subtree_index) is
    // handled explicitly below, not by byte-flips: the verifier normalizes
    // leaf_index to its 4-bit domain and ignores subtree_index entirely —
    // both header fields are bound at layer B via the recomputed commitment.
    size_t mutations = 0, rejected = 0;
    auto reject_wots = [&](const PqSignatureWitness& bad) {
        ++mutations;
        if (!pq_verify_wots_xmss(msg, bad)) ++rejected;
    };
    for (size_t byte = kHeaderOff; byte < kDigestOff; ++byte) {
        for (const uint8_t mask : {uint8_t{0xFF}, uint8_t{0x01}}) {
            PqSignatureWitness bad = w;
            reinterpret_cast<uint8_t*>(&bad)[byte] = static_cast<uint8_t>(base[byte] ^ mask);
            reject_wots(bad);
        }
    }
    assert(mutations == rejected); // 100% of signature-region mutations rejected

    // Leaf domain is exactly 4 bits: every wrong leaf label must be rejected,
    // the honest one must verify.
    for (uint32_t leaf = 0; leaf < XMSS_LEAVES; ++leaf) {
        PqSignatureWitness bad = w;
        bad.leaf_index = leaf;
        if (leaf == 5) assert(pq_verify_wots_xmss(msg, bad));
        else assert(!pq_verify_wots_xmss(msg, bad));
    }

    // Documented layering: header fields outside the 4-bit leaf domain are
    // not consumed by pure WOTS+/XMSS — they pass here and must die at
    // layer B, where the recomputed commitment binds the whole content.
    // Byte 0 of leaf_index is the exception: its low nibble IS the leaf, so
    // it is already covered by the 16-leaf domain sweep above.
    for (size_t byte = 1; byte < kHeaderOff; ++byte) {
        PqSignatureWitness bad = w;
        reinterpret_cast<uint8_t*>(&bad)[byte] = static_cast<uint8_t>(base[byte] ^ 0xFF);
        assert(pq_verify_wots_xmss(msg, bad)); // passes layer A by design...
        // ...and must die at layer B below.
    }

    // ── Layer B: full SegPQ anchor over the whole 2376-byte witness ──
    bc::Transaction tx = make_test_tx(5);
    vx::blockchain::set_nfa_field(tx.sender_nfa, "PQNEGVEC_TEST_ACCOUNT_PQNEGVEC_TEST_ACC");
    pq_sign_transaction(tx, sk);

    bc::Transaction reg_tx{};
    PqSignatureWitness rw{};
    const auto msg_digest = tx_msg_digest(tx);
    assert(PqWitnessRegistry::instance().lookup(msg_digest, rw));
    assert(rw.witness_digest == witness_commitment(rw)); // signer/verifier agree

    size_t b_mutations = 0, b_rejected = 0;
    auto reject_tx = [&](const PqSignatureWitness& bad) {
        ++b_mutations;
        if (!pq_verify_transaction(tx, bad)) ++b_rejected;
    };
    for (size_t byte = 0; byte < sizeof(PqSignatureWitness); ++byte) {
        for (const uint8_t mask : {uint8_t{0xFF}, uint8_t{0x01}}) {
            PqSignatureWitness bad = rw;
            reinterpret_cast<uint8_t*>(&bad)[byte] = static_cast<uint8_t>(
                reinterpret_cast<const uint8_t*>(&rw)[byte] ^ mask);
            reject_tx(bad);
        }
    }
    assert(b_mutations == b_rejected); // 100% of whole-witness mutations rejected

    std::cout << "  ✓ layer A: " << mutations << "/" << mutations
              << " signature-region mutations rejected\n";
    std::cout << "  ✓ layer A: subtree_index passes (by design), layer B rejects\n";
    std::cout << "  ✓ layer B: " << b_mutations << "/" << b_mutations
              << " whole-witness mutations rejected\n\n";
}

int main() {
    std::cout << "================================================================\n";
    std::cout << "  VX PHASE 46: PQ HASH-BASED SIGNATURES (WOTS+/XMSS) TEST SUITE\n";
    std::cout << "================================================================\n\n";

    test_wots_sign_verify_valid();
    test_winternitz_checksum_barrier();
    test_mitm_keyless_recalculation_rejected();
    test_tamper_chains_and_merkle_path();
    test_vault_burn();
    test_sponge_kat_sac_collisions();
    test_negative_vector_matrix();

    std::cout << "================================================================\n";
    std::cout << "  ALL PQ SIGNATURE TESTS PASSED — SHOR-VULNERABLE OPS: 0        \n";
    std::cout << "================================================================\n";
    return 0;
}
