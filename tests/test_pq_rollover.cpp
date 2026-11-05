// PQ tree rollover regression suite (v0.0.13, BACKLOG 1.5).
//
// Pins the flat-hypertree window derivation (epoch 0 frozen), the internal
// coherence of witnesses from non-zero windows, and the rollover
// certification chain (leaf-15 policy, fail-closed refusals, ledger burn
// discipline).
#include "vx/crypto/pq_signature.hpp"
#include "vx/blockchain/crypto_sponge.hpp"

#include <cassert>
#include <chrono>
#include <cstring>
#include <iostream>
#include <set>
#include <string>
#include <vector>

using namespace vx::crypto::pq;

namespace {

std::array<uint8_t, 32> pseudo_bytes(uint64_t counter) {
    const std::string tag = "VX_PQ_ROLLOVER_TEST_V1";
    std::vector<uint8_t> bytes;
    bytes.reserve(tag.size() + 8);
    bytes.insert(bytes.end(), tag.begin(), tag.end());
    for (int i = 0; i < 8; ++i) bytes.push_back(static_cast<uint8_t>(counter >> (i * 8)));
    std::array<uint8_t, 32> out{};
    vx::blockchain::VortexSponge256::compute(bytes.data(), bytes.size(), out.data());
    return out;
}

bool roots_equal(const std::array<uint8_t, 32>& a, const std::array<uint8_t, 32>& b) {
    return std::memcmp(a.data(), b.data(), 32) == 0;
}

} // namespace

int main() {
    const auto master = pseudo_bytes(1);
    const auto pub_seed = pub_seed_from_sk(master);

    // ── 1. Epoch 0 is FROZEN: window 0 == the published account key ──────
    {
        assert(roots_equal(xmss_root_tree(master, pub_seed, 0),
                           xmss_root(master, pub_seed)));
        std::cout << "epoch 0 derivation frozen OK\n";
    }

    // ── 2. Windows are disjoint: distinct roots, deterministic rebuild ───
    {
        std::set<std::string> seen;
        seen.insert(std::string(reinterpret_cast<const char*>(xmss_root_tree(master, pub_seed, 0).data()), 32));
        for (const uint32_t t : {1u, 2u, 3u, 1000u, PQ_MAX_SUBTREE_INDEX}) {
            const auto r = xmss_root_tree(master, pub_seed, t);
            assert(!roots_equal(r, xmss_root_tree(master, pub_seed, 0)));
            assert(seen.insert(std::string(reinterpret_cast<const char*>(r.data()), 32)).second);
            assert(roots_equal(r, xmss_root_tree(master, pub_seed, t))); // determinism
        }
        std::cout << "window independence (5 windows, distinct roots) OK\n";
    }

    // ── 3. A witness from window t verifies INSIDE its own window ────────
    // The signature's secret chains and the auth path must address the same
    // global leaves (the pre-rollover incoherence that forced the nonce>15
    // refusal in pq_sign_transaction).
    {
        for (const uint32_t t : {1u, 2u, 7u}) {
            const auto w = pq_sign_message(5, t, master, pub_seed, pseudo_bytes(t));
            assert(pq_verify_wots_xmss(pseudo_bytes(t), w));
            assert(roots_equal(w.pq_pubkey_root, xmss_root_tree(master, pub_seed, t)));
            assert(w.leaf_index == 5 && w.subtree_index == t);
            assert(w.witness_digest == witness_commitment(w));
            // Cross-window forgery: the same witness must NOT authenticate
            // to window 0's root.
            assert(!roots_equal(w.pq_pubkey_root, xmss_root_tree(master, pub_seed, 0)));
        }
        std::cout << "per-window witness coherence (windows 1,2,7) OK\n";
    }

    // ── 4. Rollover certificate round trip + a 2-hop chain ───────────────
    {
        const auto r0 = xmss_root_tree(master, pub_seed, 0);
        const auto r1 = xmss_root_tree(master, pub_seed, 1);
        const auto r2 = xmss_root_tree(master, pub_seed, 2);

        // Kernel invariant: the certificate call burns leaf 15 ITSELF when
        // a ledger is supplied — reserve+fsync BEFORE the signature.
        PqLeafLedger ledger0; // memory-only
        const auto cert01 = pq_sign_rollover(master, 0, 1, &ledger0);
        assert(pq_verify_rollover(r0, 0, 1, r1, cert01));
        assert(cert01.leaf_index == PQ_ROLLOVER_CERT_LEAF);
        assert(cert01.subtree_index == 0);
        assert(roots_equal(cert01.pq_pubkey_root, r0));
        // Leaf 15 is now burned under r0; a second cert from window 0
        // cannot exist (fail-closed, nothing signed).
        assert(pq_sign_rollover(master, 0, 1, &ledger0).witness_digest ==
               std::array<uint8_t, 32>{});
        assert(ledger0.used_count(r0) == 1);

        const auto cert12 = pq_sign_rollover(master, 1, 2);
        assert(pq_verify_rollover(r1, 1, 2, r2, cert12));
        // Chain: r0 certified r1; r1 certified r2 — both links check.
        std::cout << "rollover certificates (0->1, 1->2) verify OK\n";
    }

    // ── 5. Fail-closed refusals ──────────────────────────────────────────
    {
        const auto r0 = xmss_root_tree(master, pub_seed, 0);
        const auto r1 = xmss_root_tree(master, pub_seed, 1);
        const auto r2 = xmss_root_tree(master, pub_seed, 2);
        const auto cert = pq_sign_rollover(master, 0, 1);
        const auto cert12 = pq_sign_rollover(master, 1, 2);

        // Wrong new root (substitution attack on the target window).
        assert(!pq_verify_rollover(r0, 0, 1, r2, cert));
        // Wrong target window index.
        assert(!pq_verify_rollover(r0, 0, 2, r1, cert));
        // Certificate re-attributed to another source window.
        assert(!pq_verify_rollover(r1, 1, 2, r1, cert));
        // Wrong claimed old root.
        std::array<uint8_t, 32> fake_old = r0;
        fake_old[0] ^= 1;
        assert(!pq_verify_rollover(fake_old, 0, 1, r1, cert));

        // Self-certification: signing refuses, verification refuses.
        const auto self_cert = pq_sign_rollover(master, 1, 1);
        assert(!pq_verify_rollover(r1, 1, 1, r1, self_cert));
        assert(!pq_verify_rollover(r1, 1, 1, r1, cert12));

        // Out-of-namespace indexes refuse at signing.
        assert(!roots_equal(pq_sign_rollover(master, 0, 0xFFFFFFFFu).pq_pubkey_root,
                            xmss_root_tree(master, pub_seed, PQ_MAX_SUBTREE_INDEX)));
        assert(pq_sign_rollover(master, 0, 0xFFFFFFFFu).witness_digest ==
               std::array<uint8_t, 32>{});

        // Leaf policy is checked OUTSIDE the commitment: rebuild a valid
        // commitment for a witness whose leaf was mutated to 14 — the
        // leaf check (not the commitment) must reject it.
        PqSignatureWitness mutated = cert;
        mutated.leaf_index = 14;
        mutated.witness_digest = witness_commitment(mutated);
        assert(!pq_verify_rollover(r0, 0, 1, r1, mutated));

        // Tampered WOTS signature chain (bit flip in a chain element) —
        // the commitment check catches content mutations.
        PqSignatureWitness tampered = cert;
        tampered.wots_sig[3][0] ^= 0x40;
        assert(!pq_verify_rollover(r0, 0, 1, r1, tampered));
        std::cout << "rollover refusal matrix (9 attack shapes) OK\n";
    }

    // ── 6. Kernel leaf policy: transactions live in 0..14, certs in 15 ──
    {
        PqLeafLedger ledger; // memory-only
        const auto r0 = xmss_root_tree(master, pub_seed, 0);
        // reserve_for_tx refuses leaf 15 outright and never assigns it in
        // the lowest-free search.
        assert(ledger.reserve_for_tx(r0, PQ_ROLLOVER_CERT_LEAF) < 0);
        // Leaves 0..14 exhaust one by one; 15 stays untouched.
        for (unsigned i = 0; i < 15; ++i) {
            assert(ledger.reserve_for_tx(r0, 0) == static_cast<int>(i));
        }
        assert(ledger.reserve_for_tx(r0, 0) < 0);  // 0..14 exhausted
        assert(ledger.used_count(r0) == 15);
        // The certificate leaf is still free and reserve() (generic) can
        // see it — but only reserve_cert_leaf may take it.
        assert(ledger.reserve(r0, PQ_ROLLOVER_CERT_LEAF) ==
               static_cast<int>(PQ_ROLLOVER_CERT_LEAF));
        PqLeafLedger ledger2; // fresh
        assert(ledger2.reserve(r0, PQ_ROLLOVER_CERT_LEAF) ==
               static_cast<int>(PQ_ROLLOVER_CERT_LEAF));
        assert(ledger2.reserve_cert_leaf(r0) < 0); // already burned
        std::cout << "kernel leaf policy (tx 0..14, cert 15) OK\n";
    }

    // ── 7. Verification cost stays in the one-signature envelope ─────────
    {
        const auto r0 = xmss_root_tree(master, pub_seed, 0);
        const auto r1 = xmss_root_tree(master, pub_seed, 1);
        const auto cert = pq_sign_rollover(master, 0, 1);
        const auto t0 = std::chrono::steady_clock::now();
        const bool ok = pq_verify_rollover(r0, 0, 1, r1, cert);
        const double ms = std::chrono::duration<double, std::milli>(
                              std::chrono::steady_clock::now() - t0).count();
        assert(ok);
        std::cout << "rollover verify cost: " << ms << " ms (single WOTS+ envelope)\n";
        assert(ms < 500.0);
    }

    std::cout << "PQ ROLLOVER: all checks passed\n";
    return 0;
}
