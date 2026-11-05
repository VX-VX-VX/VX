#include "vx/crypto/pq_signature.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/core/ct_equal.hpp"
#include "vx/core/memory_vault.hpp"

#include "vx/core/hw_intrinsics.hpp"
#include <fcntl.h>
#include <sys/file.h>
#include <unistd.h>

#include <chrono>
#include <cstring>
#include <string>
#include <vector>

namespace vx::crypto::pq {

using blockchain::Transaction;
using Sponge = blockchain::VortexSponge256;

namespace {

void sponge(const void* data, size_t len, uint8_t out[32]) noexcept {
    Sponge::compute(static_cast<const uint8_t*>(data), len, out);
}

// Little-endian appender for the deterministic preimage builder.
struct PreimageBuf {
    std::array<uint8_t, 128> b{};
    size_t n = 0;

    void put(const void* p, size_t len) noexcept {
        std::memcpy(b.data() + n, p, len);
        n += len;
    }
    void put_str(const char* s, size_t len) noexcept { put(s, len); }
    void put_u16(uint16_t v) noexcept {
        b[n++] = static_cast<uint8_t>(v & 0xFF);
        b[n++] = static_cast<uint8_t>(v >> 8);
    }
    void put_u32(uint32_t v) noexcept {
        for (int i = 0; i < 4; ++i) b[n++] = static_cast<uint8_t>((v >> (i * 8)) & 0xFF);
    }
};

} // namespace

// ── Canonical message digest ─────────────────────────────────────────────────

std::array<uint8_t, 32> tx_msg_digest(const Transaction& tx) noexcept {
    PreimageBuf p;
    p.put_str("VX_PQ_TX_MSG_V1", 15);
    p.put(tx.sender_nfa, 42);
    p.put(tx.receiver_nfa, 42);
    p.put(tx.amount, 8);
    p.put(tx.fee, 4);
    p.put(tx.nonce, 4);
    p.put_u32(PQ_CHAIN_ID);
    std::array<uint8_t, 32> out{};
    sponge(p.b.data(), p.n, out.data());
    return out;
}

// ── Winternitz base vector ───────────────────────────────────────────────────

uint32_t winternitz_checksum(const uint8_t msg[32]) noexcept {
    uint32_t c = 0;
    for (size_t i = 0; i < WOTS_MSG_NIBBLES; ++i) {
        const uint8_t nibble = (msg[i >> 1] >> ((i & 1) ? 0 : 4)) & 0x0F;
        c += 15u - nibble;
    }
    return c;
}

void wots_base_vector(const uint8_t msg[32], uint8_t out_b[WOTS_CHAINS]) noexcept {
    for (size_t i = 0; i < WOTS_MSG_NIBBLES; ++i) {
        out_b[i] = (msg[i >> 1] >> ((i & 1) ? 0 : 4)) & 0x0F;
    }
    const uint32_t c = winternitz_checksum(msg);
    out_b[64] = static_cast<uint8_t>((c >> 8) & 0xF);
    out_b[65] = static_cast<uint8_t>((c >> 4) & 0xF);
    out_b[66] = static_cast<uint8_t>(c & 0xF);
}

// ── Masked hash chains ───────────────────────────────────────────────────────

std::array<uint8_t, 32> chain_step(const std::array<uint8_t, 32>& x,
                                   const std::array<uint8_t, 32>& pub_seed,
                                   uint16_t chain_idx, uint8_t step) noexcept {
    // Round bitmask: multi-target protection — every (chain, step) position
    // hashes under its own mask.
    PreimageBuf m;
    m.put_str("VX_WOTS_MASK", 12);
    m.put(pub_seed.data(), 32);
    m.put_u16(chain_idx);
    m.b[m.n++] = step;
    std::array<uint8_t, 32> mask{};
    sponge(m.b.data(), m.n, mask.data());

    PreimageBuf s;
    s.put_str("VX_WOTS_STEP", 12);
    for (size_t i = 0; i < 32; ++i) s.b[s.n++] = x[i] ^ mask[i];
    s.put(pub_seed.data(), 32);
    s.put_u16(chain_idx);
    s.b[s.n++] = step;
    std::array<uint8_t, 32> out{};
    sponge(s.b.data(), s.n, out.data());
    return out;
}

std::array<uint8_t, 32> chain_run(const std::array<uint8_t, 32>& x, unsigned start,
                                  unsigned steps, const std::array<uint8_t, 32>& pub_seed,
                                  uint16_t chain_idx) noexcept {
    std::array<uint8_t, 32> cur = x;
    for (unsigned s = start; s < start + steps; ++s) {
        cur = chain_step(cur, pub_seed, chain_idx, static_cast<uint8_t>(s));
    }
    return cur;
}

// ── Key material ─────────────────────────────────────────────────────────────

std::array<uint8_t, 32> wots_leaf_pk_root(uint32_t global_leaf,
                                          const std::array<uint8_t, 32>& master_sk,
                                          const std::array<uint8_t, 32>& pub_seed) noexcept {
    std::array<std::array<uint8_t, 32>, WOTS_CHAINS> pk{};
    for (size_t i = 0; i < WOTS_CHAINS; ++i) {
        PreimageBuf k;
        k.put_str("VX_WOTS_SK", 10);
        k.put(master_sk.data(), 32);
        k.put_u32(global_leaf);
        k.put_u16(static_cast<uint16_t>(i));
        std::array<uint8_t, 32> sk_i{};
        sponge(k.b.data(), k.n, sk_i.data());
        pk[i] = chain_run(sk_i, 0, WOTS_STEPS, pub_seed, static_cast<uint16_t>(i));
        volatile uint8_t* poison = sk_i.data();
        for (size_t z = 0; z < 32; ++z) poison[z] = 0; // sk_i never lingers
        (void)poison;
    }
    // Leaf root compresses the 67 public chain ends (streamed — 2191 bytes).
    Sponge root_sponge;
    root_sponge.absorb(reinterpret_cast<const uint8_t*>("VX_WOTS_PK_ROOT"), 15);
    root_sponge.absorb(pub_seed.data(), 32);
    for (size_t i = 0; i < WOTS_CHAINS; ++i) root_sponge.absorb(pk[i].data(), 32);
    std::array<uint8_t, 32> root{};
    root_sponge.finalize(root.data());
    return root;
}

std::array<uint8_t, 32> xmss_node_hash(uint8_t level, uint16_t node_idx,
                                       const std::array<uint8_t, 32>& pub_seed,
                                       const std::array<uint8_t, 32>& left,
                                       const std::array<uint8_t, 32>& right) noexcept {
    PreimageBuf p;
    p.put_str("VX_XMSS_NODE", 12);
    p.put(pub_seed.data(), 32);
    p.b[p.n++] = level;
    p.put_u16(node_idx);
    p.put(left.data(), 32);
    p.put(right.data(), 32);
    std::array<uint8_t, 32> out{};
    sponge(p.b.data(), p.n, out.data());
    return out;
}

std::array<uint8_t, 32> pub_seed_from_sk(const std::array<uint8_t, 32>& sk) noexcept {
    // MUST stay byte-identical with the derivation inside pq_sign_transaction
    // (step 2): the account's XMSS root — and therefore its bound address —
    // depends on this exact mask seed.
    PreimageBuf ps;
    ps.put_str("VX_PQ_PUBSEED_V1", 16);
    ps.put(sk.data(), 32);
    std::array<uint8_t, 32> pub_seed{};
    sponge(ps.b.data(), ps.n, pub_seed.data());
    return pub_seed;
}

std::array<uint8_t, 32> xmss_root(const std::array<uint8_t, 32>& master_sk,
                                  const std::array<uint8_t, 32>& pub_seed) noexcept {
    std::array<std::array<uint8_t, 32>, XMSS_LEAVES> level{};
    for (size_t j = 0; j < XMSS_LEAVES; ++j) {
        level[j] = wots_leaf_pk_root(static_cast<uint32_t>(j), master_sk, pub_seed);
    }
    size_t count = XMSS_LEAVES;
    uint8_t lvl = 0;
    while (count > 1) {
        const size_t next = (count + 1) / 2;
        for (size_t i = 0; i < next; ++i) {
            const size_t l = i * 2;
            const size_t r = (l + 1 < count) ? l + 1 : l; // odd node duplicates itself
            level[i] = xmss_node_hash(lvl, static_cast<uint16_t>(l), pub_seed,
                                      level[l], level[r]);
        }
        count = next;
        ++lvl;
    }
    return level[0];
}

// ── Tree rollover (BACKLOG 1.5, v0.0.13) ─────────────────────────────────────

std::array<uint8_t, 32> xmss_root_tree(const std::array<uint8_t, 32>& master_sk,
                                       const std::array<uint8_t, 32>& pub_seed,
                                       uint32_t tree_index) noexcept {
    const uint32_t window_base = tree_index << XMSS_H;
    std::array<std::array<uint8_t, 32>, XMSS_LEAVES> level{};
    for (size_t j = 0; j < XMSS_LEAVES; ++j) {
        level[j] = wots_leaf_pk_root(window_base | static_cast<uint32_t>(j),
                                     master_sk, pub_seed);
    }
    size_t count = XMSS_LEAVES;
    uint8_t lvl = 0;
    while (count > 1) {
        const size_t next = (count + 1) / 2;
        for (size_t i = 0; i < next; ++i) {
            const size_t l = i * 2;
            const size_t r = (l + 1 < count) ? l + 1 : l; // odd node duplicates itself
            level[i] = xmss_node_hash(lvl, static_cast<uint16_t>(l), pub_seed,
                                      level[l], level[r]);
        }
        count = next;
        ++lvl;
    }
    return level[0];
}

std::array<uint8_t, 32> rollover_binding_digest(
    const std::array<uint8_t, 32>& old_root, uint32_t from_tree, uint32_t to_tree,
    const std::array<uint8_t, 32>& new_root) noexcept {
    PreimageBuf p; // 17 + 32 + 4 + 4 + 32 = 89 bytes, fits
    p.put_str("VX_PQ_ROLLOVER_V1", 17);
    p.put(old_root.data(), 32);
    p.put_u32(from_tree);
    p.put_u32(to_tree);
    p.put(new_root.data(), 32);
    std::array<uint8_t, 32> out{};
    sponge(p.b.data(), p.n, out.data());
    return out;
}

PqSignatureWitness pq_sign_rollover(const std::array<uint8_t, 32>& master_sk,
                                    uint32_t from_tree, uint32_t to_tree,
                                    PqLeafLedger* leaf_ledger) noexcept {
    if (from_tree == to_tree) return PqSignatureWitness{}; // binds nothing
    if (from_tree > PQ_MAX_SUBTREE_INDEX || to_tree > PQ_MAX_SUBTREE_INDEX) {
        return PqSignatureWitness{}; // outside the global-leaf namespace
    }
    // The account mask seed, derived exactly as pq_sign_transaction does:
    // every window lives under the same pub_seed, only the leaf window moves.
    const auto pub_seed = pub_seed_from_sk(master_sk);
    const auto old_root = xmss_root_tree(master_sk, pub_seed, from_tree);
    // Kernel invariant: THIS call burns the certificate leaf itself, with
    // the fsync BEFORE the signature (same fail-closed ordering as every
    // transaction leaf). No reservation -> no certificate.
    if (leaf_ledger &&
        leaf_ledger->reserve_cert_leaf(old_root) != static_cast<int>(PQ_ROLLOVER_CERT_LEAF)) {
        return PqSignatureWitness{};
    }
    const auto new_root = xmss_root_tree(master_sk, pub_seed, to_tree);
    const auto msg = rollover_binding_digest(old_root, from_tree, to_tree, new_root);
    return pq_sign_message(PQ_ROLLOVER_CERT_LEAF, from_tree, master_sk, pub_seed, msg);
}

bool pq_verify_rollover(const std::array<uint8_t, 32>& old_root, uint32_t from_tree,
                        uint32_t to_tree, const std::array<uint8_t, 32>& new_root,
                        const PqSignatureWitness& cert) noexcept {
    if (from_tree == to_tree) return false;
    // Certificate policy: the LAST leaf of the old tree vouches for the new
    // root. Pinned here so a certificate by any other leaf is refused before
    // any hash work (and independently of the witness commitment).
    if (cert.leaf_index != PQ_ROLLOVER_CERT_LEAF) return false;
    if (cert.subtree_index != from_tree) return false;
    // The certifying tree IS the old tree: its published root must equal the
    // root the caller is rotating away from.
    if (!vx::core::ct_equal(cert.pq_pubkey_root.data(), old_root.data(), 32)) return false;
    // Transported commitment must match the certificate content (the
    // witness_digest field is attacker-writable on the wire).
    const auto recomputed = witness_commitment(cert);
    if (!vx::core::ct_equal(cert.witness_digest.data(), recomputed.data(), 32)) return false;
    const auto msg = rollover_binding_digest(old_root, from_tree, to_tree, new_root);
    return pq_verify_wots_xmss(msg, cert);
}

// ── Sign / verify ────────────────────────────────────────────────────────────

namespace {

// 256-bit witness commitment over the witness CONTENT (streamed — 2362 bytes
// of preimage). Shared by the signer and the verifier: a digest that only
// the signer computes would be a transported, attacker-writable field; a
// recomputed one binds the anchor to what is actually being verified.
std::array<uint8_t, 32> compute_witness_digest(const PqSignatureWitness& w) noexcept {
    Sponge ws;
    ws.absorb(reinterpret_cast<const uint8_t*>("VX_SEGPQ_WITNESS_V1"), 18);
    ws.absorb_obj(w.leaf_index);
    ws.absorb_obj(w.subtree_index);
    ws.absorb(w.pub_seed.data(), 32);
    ws.absorb(w.pq_pubkey_root.data(), 32);
    for (size_t i = 0; i < WOTS_CHAINS; ++i) ws.absorb(w.wots_sig[i].data(), 32);
    for (size_t i = 0; i < XMSS_H; ++i) ws.absorb(w.auth_path[i].data(), 32);
    std::array<uint8_t, 32> out{};
    ws.finalize(out.data());
    return out;
}

} // namespace

std::array<uint8_t, 32> witness_commitment(const PqSignatureWitness& w) noexcept {
    return compute_witness_digest(w);
}

PqSignatureWitness pq_sign_message(uint32_t leaf_idx, uint32_t subtree_index,
                                   const std::array<uint8_t, 32>& master_sk,
                                   const std::array<uint8_t, 32>& pub_seed,
                                   const std::array<uint8_t, 32>& msg) noexcept {
    PqSignatureWitness w;
    w.leaf_index = leaf_idx;
    w.subtree_index = subtree_index;
    w.pub_seed = pub_seed;

    // The window this witness lives in: the signature draws its secret
    // chains from global_leaf = (subtree_index << H) | leaf_idx, so the
    // published root and the auth path must span the SAME window's leaves
    // (rollover coherence, BACKLOG 1.5; window 0 is byte-identical with the
    // frozen pre-rollover behavior).
    const uint32_t window_base = subtree_index << XMSS_H;
    w.pq_pubkey_root = xmss_root_tree(master_sk, pub_seed, subtree_index);

    const uint32_t global_leaf = window_base | leaf_idx;
    uint8_t b[WOTS_CHAINS];
    wots_base_vector(msg.data(), b);

    std::array<std::array<uint8_t, 32>, WOTS_CHAINS> sk{};
    for (size_t i = 0; i < WOTS_CHAINS; ++i) {
        PreimageBuf k;
        k.put_str("VX_WOTS_SK", 10);
        k.put(master_sk.data(), 32);
        k.put_u32(global_leaf);
        k.put_u16(static_cast<uint16_t>(i));
        sponge(k.b.data(), k.n, sk[i].data());
        w.wots_sig[i] = chain_run(sk[i], 0, b[i], pub_seed, static_cast<uint16_t>(i));
    }

    // Auth path: rebuild the window's tree from its leaves, collect H
    // siblings. Leaves are addressed in the global namespace so the signed
    // leaf is one of them.
    std::array<std::array<uint8_t, 32>, XMSS_LEAVES> level{};
    for (size_t j = 0; j < XMSS_LEAVES; ++j) {
        level[j] = wots_leaf_pk_root(window_base | static_cast<uint32_t>(j),
                                     master_sk, pub_seed);
    }
    size_t count = XMSS_LEAVES;
    size_t idx = leaf_idx;
    uint8_t lvl = 0;
    while (count > 1) {
        const size_t sib = (idx & 1) ? idx - 1 : ((idx + 1 < count) ? idx + 1 : idx);
        w.auth_path[lvl] = level[sib];
        const size_t next = (count + 1) / 2;
        for (size_t i = 0; i < next; ++i) {
            const size_t l = i * 2;
            const size_t r = (l + 1 < count) ? l + 1 : l;
            level[i] = xmss_node_hash(lvl, static_cast<uint16_t>(l), pub_seed,
                                      level[l], level[r]);
        }
        count = next;
        idx >>= 1;
        ++lvl;
    }

    // Secret chain seeds never leave this scope alive.
    for (size_t i = 0; i < WOTS_CHAINS; ++i) {
        vx::core::MemoryCore::scrub_execution_state(sk[i].data(), 32);
    }

    // 256-bit witness commitment (streamed — 2362 bytes of preimage).
    w.witness_digest = compute_witness_digest(w);
    return w;
}

bool pq_verify_wots_xmss(const std::array<uint8_t, 32>& msg,
                         const PqSignatureWitness& w) noexcept {
    uint8_t b[WOTS_CHAINS];
    wots_base_vector(msg.data(), b);

    // Recompute the leaf public key from the signature:
    // pk'_i = Chain(sig_i, B[i], 15 - B[i]).
    std::array<std::array<uint8_t, 32>, WOTS_CHAINS> pk{};
    for (size_t i = 0; i < WOTS_CHAINS; ++i) {
        const unsigned bi = b[i];
        const unsigned remaining = WOTS_STEPS - bi;
        pk[i] = chain_run(w.wots_sig[i], bi, remaining, w.pub_seed, static_cast<uint16_t>(i));
    }

    // Compress to the leaf root and walk the auth path up (streamed).
    Sponge ls;
    ls.absorb(reinterpret_cast<const uint8_t*>("VX_WOTS_PK_ROOT"), 15);
    ls.absorb(w.pub_seed.data(), 32);
    for (size_t i = 0; i < WOTS_CHAINS; ++i) ls.absorb(pk[i].data(), 32);
    std::array<uint8_t, 32> cur{};
    ls.finalize(cur.data());

    // The leaf domain is exactly 4 bits (global_leaf = subtree << H | leaf).
    // Normalize here so verification is spec-exact: the auth-path walk
    // itself only consumes the low 4 bits, and unnormalized high bits made
    // leaf_index mutations in those bytes invisible to this layer.
    size_t idx = w.leaf_index & (XMSS_LEAVES - 1);
    for (size_t lvl = 0; lvl < XMSS_H; ++lvl) {
        const size_t sib_idx = (idx & 1) ? idx - 1 : idx + 1;
        const std::array<uint8_t, 32>& left = (idx & 1) ? w.auth_path[lvl] : cur;
        const std::array<uint8_t, 32>& right = (idx & 1) ? cur : w.auth_path[lvl];
        cur = xmss_node_hash(static_cast<uint8_t>(lvl), static_cast<uint16_t>(sib_idx & ~size_t(1)),
                             w.pub_seed, left, right);
        idx >>= 1;
    }
    return vx::core::ct_equal(cur.data(), w.pq_pubkey_root.data(), cur.size());
}

void pq_set_transaction_anchor(Transaction& tx, const PqSignatureWitness& w) noexcept {
    const auto msg = tx_msg_digest(tx);
    const std::array<uint8_t, 32> digest = compute_witness_digest(w);
    PreimageBuf a;
    a.put_str("VX_SEGPQ_ANCHOR_V1", 18);
    a.put(msg.data(), 32);
    a.put(w.pq_pubkey_root.data(), 32);
    a.put(digest.data(), 32);
    std::array<uint8_t, 32> full_tag{};
    sponge(a.b.data(), a.n, full_tag.data());
    std::memcpy(tx.cocoon_proof, full_tag.data(), 12);
}

bool pq_verify_transaction(const Transaction& tx, const PqSignatureWitness& w) noexcept {
    const auto msg = tx_msg_digest(tx);
    if (!pq_verify_wots_xmss(msg, w)) return false;

    // Recompute the witness commitment from the witness CONTENT and refuse
    // any witness whose transported digest field disagrees with it — that
    // field crosses the wire, so it is attacker-writable; the recomputed
    // one is not. This also closes subtree_index, which pure WOTS+/XMSS
    // verification does not consume: lying metadata now breaks the anchor.
    const std::array<uint8_t, 32> digest = compute_witness_digest(w);
    if (!vx::core::ct_equal(digest.data(), w.witness_digest.data(), digest.size())) return false;

    // Anchor: cocoon_proof must be trunc12(Sponge("VX_SEGPQ_ANCHOR_V1" || msg || root || witness_digest)).
    PreimageBuf a; // 18 + 32*3 = 114 bytes, fits
    a.put_str("VX_SEGPQ_ANCHOR_V1", 18);
    a.put(msg.data(), 32);
    a.put(w.pq_pubkey_root.data(), 32);
    a.put(digest.data(), 32);
    std::array<uint8_t, 32> full_tag{};
    sponge(a.b.data(), a.n, full_tag.data());
    return vx::core::ct_equal(full_tag.data(), tx.cocoon_proof, 12);
}

// ── SegPQ signing with MemoryVault ─────────────────────────────────────────

bool pq_sign_transaction(Transaction& tx, const std::array<uint8_t, 32>& master_sk,
                         PqSignTimings* timings, PqLeafLedger* leaf_ledger,
                         PqSignatureWitness* out_witness) noexcept {
    namespace mc = vx::core;
    PqSignTimings local{};
    PqSignTimings& t = timings ? *timings : local;

    mc::MemoryCore vault(4 * 1024 * 1024); // isolated mlock'ed arena for this signing session

    // 1. Key material lives one consumer away from the flame: commit → the
    //    page is LOCKED under mlock; consume → read-once + BURNED.
    const size_t burned_before = vault.get_stats().burned_pages;
    const auto key_hash = vault.commit_secure_data(master_sk.data(), 32);
    uint8_t sk_buf[32];
    vault.consume_data(key_hash, sk_buf); // page -> BURNED here

    std::array<uint8_t, 32> sk{};
    std::memcpy(sk.data(), sk_buf, 32);
    mc::MemoryCore::scrub_execution_state(sk_buf, 32);

    // 2. Public mask seed (public once published, derived deterministically).
    PreimageBuf ps;
    ps.put_str("VX_PQ_PUBSEED_V1", 16);
    ps.put(sk.data(), 32);
    std::array<uint8_t, 32> pub_seed{};
    sponge(ps.b.data(), ps.n, pub_seed.data());

    // 3. Keygen: the full H=4 XMSS tree — the account's PQ public key.
    const auto kg0 = std::chrono::steady_clock::now();
    uint64_t t0 = vx::core::hw::cycle_counter();
    [[maybe_unused]] const auto root = xmss_root(sk, pub_seed);
    uint64_t t1 = vx::core::hw::cycle_counter();
    t.keygen_cycles = t1 - t0;
    t.keygen_us = std::chrono::duration<double, std::micro>(
        std::chrono::steady_clock::now() - kg0).count();

    // 4. Sign the leaf selected by the nonce.
    const uint32_t nonce = static_cast<uint32_t>(tx.nonce[0]) |
                           (static_cast<uint32_t>(tx.nonce[1]) << 8) |
                           (static_cast<uint32_t>(tx.nonce[2]) << 16) |
                           (static_cast<uint32_t>(tx.nonce[3]) << 24);
    const uint32_t leaf_idx = nonce & 0xF;
    const uint32_t subtree_index = nonce >> XMSS_H;

    // Window guard: the crypto layer now supports coherent rollover trees
    // (v0.0.13, BACKLOG 1.5) — but the consensus-layer acceptance policy for
    // a rotated root (certification-chain verification against the
    // account's published window-0 root) is NOT wired into any rule yet.
    // Until it is, a transaction whose nonce names a window above 0 would
    // emit a witness under a root no consensus rule can attribute to this
    // account — still fail-closed. Refuse before reserving anything
    // (external review finding; see VERIFICATION_EVIDENCE changelog).
    if (subtree_index != 0) return false;

    // 4a. One-time-leaf lifecycle: reserve before any signing work. `root`
    //     (computed above) is this key's XMSS root — the ledger is keyed by
    //     it, so different accounts never share leaf history. A leaf that
    //     already signed is never handed out twice: the ledger assigns the
    //     lowest free leaf instead, and exhausting the allowed leaves fails
    //     the call. Kernel invariant (owner directive, 2026-11-05): leaf 15
    //     is reserved EXCLUSIVELY for rollover certificates — in the
    //     tracked path a regular signature may not request it and the
    //     lowest-free search never assigns it. The untracked legacy path
    //     (no ledger, no reuse protection by definition) is unchanged.
    uint32_t use_leaf = leaf_idx;
    if (leaf_ledger) {
        if (leaf_idx == PqLeafLedger::kReservedCertLeaf) return false;
        const int assigned = leaf_ledger->reserve_for_tx(root, leaf_idx);
        if (assigned < 0) return false; // exhausted or log untrusted
        use_leaf = static_cast<uint32_t>(assigned);
    }
    t.used_leaf_index = use_leaf;

    t0 = vx::core::hw::cycle_counter();
    const auto sg0 = std::chrono::steady_clock::now();
    PqSignatureWitness w = pq_sign_message(use_leaf, subtree_index, sk, pub_seed,
                                           tx_msg_digest(tx));
    t1 = vx::core::hw::cycle_counter();
    t.sign_cycles = t1 - t0;
    t.sign_us = std::chrono::duration<double, std::micro>(
        std::chrono::steady_clock::now() - sg0).count();

    // 5. Anchor the witness into the 112-byte frame.
    const auto msg = tx_msg_digest(tx);
    PreimageBuf a;
    a.put_str("VX_SEGPQ_ANCHOR_V1", 18);
    a.put(msg.data(), 32);
    a.put(w.pq_pubkey_root.data(), 32);
    a.put(w.witness_digest.data(), 32);
    std::array<uint8_t, 32> full_tag{};
    sponge(a.b.data(), a.n, full_tag.data());
    std::memcpy(tx.cocoon_proof, full_tag.data(), 12);

    // 6. Register the SegPQ witness (sender_nfa → pq_pubkey_root).
    PqWitnessRegistry::instance().register_witness(tx, w);
    PqWitnessRegistry::instance().set_last(tx, w);

    // 7. Every secret trace must be ash: scrub the master key copy and prove
    //    the vault page really burned.
    mc::MemoryCore::scrub_execution_state(sk.data(), 32);
    const auto stats = vault.get_stats();
    t.vault_burn_verified = stats.burned_pages > burned_before;
    // Hand the caller the witness THIS call produced. The registry may hold
    // several valid candidates for the same digest (different keys can all
    // produce verifiable signatures for a predictable message), so a caller
    // that needs ITS OWN signature must not go back through the registry.
    if (out_witness) *out_witness = w;
    return true;
}

// ── PqLeafLedger ─────────────────────────────────────────────────────────────

namespace {
constexpr size_t kLeafRecordSize = 33; // 32-byte key root + 1-byte leaf index
constexpr size_t kLeafLogMaxBytes = 4u * 1024u * 1024u; // sane cap (~126k records)
} // namespace

PqLeafLedger::PqLeafLedger(std::string path) : path_(std::move(path)) {
    if (path_.empty()) {
        memory_only_ = true; // in-process history is the whole contract
        return;
    }

    fd_ = ::open(path_.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0600);
    if (fd_ < 0) {
        path_.clear();
        return; // durable_ok_ stays false -> reserve fails closed
    }
    if (::flock(fd_, LOCK_EX) != 0) {
        ::close(fd_);
        fd_ = -1;
        path_.clear();
        return;
    }
    const bool ok = parse_log_locked();
    ::flock(fd_, LOCK_UN);
    if (!ok) {
        ::close(fd_);
        fd_ = -1;
        path_.clear();
    } else {
        durable_ok_ = true;
    }
}

PqLeafLedger::~PqLeafLedger() {
    if (fd_ >= 0) ::close(fd_);
}

bool PqLeafLedger::parse_log_locked() {
    if (fd_ < 0) return false;
    if (::lseek(fd_, 0, SEEK_END) == static_cast<off_t>(-1)) return false;
    const off_t size = ::lseek(fd_, 0, SEEK_CUR);
    if (size < 0 || static_cast<size_t>(size) > kLeafLogMaxBytes) return false;
    if (::lseek(fd_, 0, SEEK_SET) == static_cast<off_t>(-1)) return false;

    std::vector<uint8_t> buf(static_cast<size_t>(size));
    size_t got = 0;
    while (got < buf.size()) {
        const ssize_t n = ::read(fd_, buf.data() + got, buf.size() - got);
        if (n <= 0) return false;
        got += static_cast<size_t>(n);
    }

    used_.clear();
    // Complete records only: a trailing partial record can only be a torn
    // append from a crash, which we treat as unconsumed (fail-closed for
    // that leaf happens at append time, not parse time).
    const size_t complete = buf.size() / kLeafRecordSize;
    for (size_t r = 0; r < complete; ++r) {
        const uint8_t* rec = buf.data() + r * kLeafRecordSize;
        std::array<uint8_t, 32> key{};
        std::memcpy(key.data(), rec, 32);
        const unsigned leaf = rec[32];
        if (leaf >= kLeaves) return false; // tampered record -> fail closed
        used_[key].set(leaf);
    }
    return true;
}

bool PqLeafLedger::append_locked(const std::array<uint8_t, 32>& key_root, unsigned leaf) {
    uint8_t rec[kLeafRecordSize];
    std::memcpy(rec, key_root.data(), 32);
    rec[32] = static_cast<uint8_t>(leaf);
    if (::lseek(fd_, 0, SEEK_END) == static_cast<off_t>(-1)) return false;
    size_t put = 0;
    while (put < kLeafRecordSize) {
        const ssize_t n = ::write(fd_, rec + put, kLeafRecordSize - put);
        if (n <= 0) return false;
        put += static_cast<size_t>(n);
    }
    return ::fsync(fd_) == 0;
}

size_t PqLeafLedger::used_count(const std::array<uint8_t, 32>& key_root) const {
    std::lock_guard<std::mutex> guard(mu_);
    const auto it = used_.find(key_root);
    return (it == used_.end()) ? 0u : it->second.count();
}

// Shared reservation core: `allowed` masks which leaves may be assigned.
// requested_leaf must be inside `allowed` or the call fails without
// burning anything; the lowest-free search visits only allowed leaves.
int PqLeafLedger::reserve_impl(const std::array<uint8_t, 32>& key_root,
                               unsigned requested_leaf, unsigned allowed_mask) {
    std::lock_guard<std::mutex> guard(mu_);

    if (!memory_only_) {
        if (!durable_ok_ || fd_ < 0) return -1;
        // Cross-process exclusion, then refresh from disk so a sibling
        // process that signed while we were idle is honored.
        if (::flock(fd_, LOCK_EX) != 0) return -1;
        if (!parse_log_locked()) {
            durable_ok_ = false; // fail closed from here on
            ::flock(fd_, LOCK_UN);
            return -1;
        }
    }

    const auto finish = [&](int result) -> int {
        if (!memory_only_) ::flock(fd_, LOCK_UN);
        return result;
    };

    std::bitset<kLeaves>& bits = used_[key_root];
    if (requested_leaf >= kLeaves || (allowed_mask & (1u << requested_leaf)) == 0) {
        return finish(-1); // refuse WITHOUT burning anything
    }
    unsigned assigned = requested_leaf;
    if (bits.test(assigned)) {
        int found = -1;
        for (unsigned i = 0; i < kLeaves; ++i) {
            if ((allowed_mask & (1u << i)) && !bits.test(i)) {
                found = static_cast<int>(i);
                break;
            }
        }
        if (found < 0) {
            return finish(-1); // no allowed free leaf
        }
        assigned = static_cast<unsigned>(found);
    }

    if (!memory_only_ && !append_locked(key_root, assigned)) {
        durable_ok_ = false; // fail closed from here on
        return finish(-1);
    }
    bits.set(assigned);
    return finish(static_cast<int>(assigned));
}

int PqLeafLedger::reserve(const std::array<uint8_t, 32>& key_root, unsigned requested_leaf) {
    return reserve_impl(key_root, requested_leaf, 0xFFFFu); // all 16 leaves
}

int PqLeafLedger::reserve_for_tx(const std::array<uint8_t, 32>& key_root,
                                 unsigned requested_leaf) {
    // Leaf 15 belongs to rollover certificates exclusively (kernel
    // invariant, owner directive 2026-11-05) — regular signatures live in
    // leaves 0..14.
    return reserve_impl(key_root, requested_leaf, 0x7FFFu);
}

int PqLeafLedger::reserve_cert_leaf(const std::array<uint8_t, 32>& key_root) {
    return reserve_impl(key_root, kReservedCertLeaf, 1u << kReservedCertLeaf);
}

// ── PqWitnessRegistry ────────────────────────────────────────────────────────

PqWitnessRegistry& PqWitnessRegistry::instance() noexcept {
    static PqWitnessRegistry reg;
    return reg;
}

bool PqWitnessRegistry::register_witness(const Transaction& tx, const PqSignatureWitness& w) {
    const auto digest = tx_msg_digest(tx);
    // Nothing unverified ever enters the registry (round-7 hardening): the
    // full WOTS+/XMSS + SegPQ-anchor chain must pass against THIS tx.
    if (!pq_verify_transaction(tx, w)) return false;
    Entry e;
    e.witness = w;
    std::memcpy(e.sender.data(), tx.sender_nfa, 42);
    std::lock_guard<std::mutex> lock(mutex_);
    auto& cands = by_digest_[digest];
    for (const auto& c : cands)
        if (std::memcmp(&c.witness, &w, sizeof(w)) == 0) return true; // dedup
    if (cands.size() >= kMaxWitnessesPerDigest) return false;
    if (cands.empty() && by_digest_.size() >= kMaxDigestEntries) return false;
    cands.push_back(e);
    std::array<uint8_t, 42> sender{};
    std::memcpy(sender.data(), tx.sender_nfa, 42);
    // sender_roots_ is fed ONLY from tx-verified registrations - a wire
    // registration cannot flip a sender into the PQ class (that flag gates
    // verify_transaction_proof Tier 1 for mempool admission and the VM).
    sender_roots_[sender] = w.pq_pubkey_root;
    append_durable_locked(digest, sender, w);
    return true;
}

bool PqWitnessRegistry::register_witness_bytes(const std::array<uint8_t, 32>& msg_digest,
                                               const uint8_t sender_nfa[42],
                                               const PqSignatureWitness& w) {
    // Round-7 hardening: a wire/replay registration must carry its own
    // proof - the witness commitment must match the witness content, and
    // the WOTS+/XMSS chain must verify against the CLAIMED digest. Garbage
    // never reaches memory or the durable sidecar.
    if (!(w.witness_digest == witness_commitment(w))) return false;
    if (!pq_verify_wots_xmss(msg_digest, w)) return false;
    Entry e;
    e.witness = w;
    std::memcpy(e.sender.data(), sender_nfa, 42);
    std::lock_guard<std::mutex> lock(mutex_);
    auto& cands = by_digest_[msg_digest];
    for (const auto& c : cands)
        if (std::memcmp(&c.witness, &w, sizeof(w)) == 0) return true; // dedup
    if (cands.size() >= kMaxWitnessesPerDigest) return false;
    if (cands.empty() && by_digest_.size() >= kMaxDigestEntries) return false;
    cands.push_back(e);
    append_durable_locked(msg_digest, e.sender, w);
    return true;
}

bool PqWitnessRegistry::append_durable_locked(const std::array<uint8_t, 32>& digest,
                                              const std::array<uint8_t, 42>& sender,
                                              const PqSignatureWitness& w) {
    if (durable_fd_ < 0 || !durable_locked_) return true; // memory-only mode
    uint8_t rec[8 + 32 + 42 + sizeof(PqSignatureWitness)];
    std::memcpy(rec, "VXPQWT1", 8);
    std::memcpy(rec + 8, digest.data(), 32);
    std::memcpy(rec + 40, sender.data(), 42);
    std::memcpy(rec + 82, &w, sizeof(w));
    const ssize_t total = static_cast<ssize_t>(sizeof(rec));
    ssize_t off = 0;
    while (off < total) {
        const ssize_t n = ::write(durable_fd_, rec + off, static_cast<size_t>(total - off));
        if (n <= 0) return false;
        off += n;
    }
    return ::fsync(durable_fd_) == 0;
}

void PqWitnessRegistry::attach_durable_log(const std::string& path) {
    std::lock_guard<std::mutex> lock(mutex_);
    if (durable_fd_ >= 0 && durable_path_ == path) return; // already attached
    if (durable_fd_ >= 0) { ::close(durable_fd_); durable_fd_ = -1; }
    durable_path_ = path;
    // O_APPEND: every record lands at the current end regardless of what
    // any other code path did to the file offset (round-7 hardening).
    const int fd = ::open(path.c_str(), O_RDWR | O_CREAT | O_APPEND, 0600);
    if (fd < 0) return; // memory-only fallback; nothing fails the node here
    // Exclusive flock like PqLeafLedger: two node processes sharing a data
    // directory must not interleave records into torn halves. A busy log
    // falls back to memory-only mode - the witness is re-broadcastable,
    // durability is an optimization here, not a safety invariant.
    if (::flock(fd, LOCK_EX | LOCK_NB) != 0) { ::close(fd); return; }
    durable_fd_ = fd;
    durable_locked_ = true;
    // Replay full records only; a short or corrupt record stops the replay
    // (fail-closed). The flock makes mid-file corruption from a sibling
    // process impossible; only a hand-corrupted file stops early.
    uint8_t rec[8 + 32 + 42 + sizeof(PqSignatureWitness)];
    size_t replayed = 0;
    for (;;) {
        if (by_digest_.size() >= kMaxDigestEntries) break; // cap the RAM too
        ssize_t got = 0;
        while (got < static_cast<ssize_t>(sizeof(rec))) {
            const ssize_t n = ::read(fd, rec + got, sizeof(rec) - static_cast<size_t>(got));
            if (n <= 0) break;
            got += n;
        }
        if (got != static_cast<ssize_t>(sizeof(rec))) break; // partial/no more
        if (std::memcmp(rec, "VXPQWT1", 8) != 0) break;      // corrupt -> stop
        Entry e;
        std::memcpy(&e.witness, rec + 82, sizeof(PqSignatureWitness));
        std::array<uint8_t, 32> digest{};
        std::memcpy(digest.data(), rec + 8, 32);
        std::array<uint8_t, 42> sender{};
        std::memcpy(sender.data(), rec + 40, 42);
        auto& cands = by_digest_[digest];
        bool dup = false;
        for (const auto& c : cands)
            if (std::memcmp(&c.witness, &e.witness, sizeof(e.witness)) == 0) { dup = true; break; }
        if (!dup && cands.size() < kMaxWitnessesPerDigest) {
            cands.push_back(e);
            ++replayed;
        }
    }
    (void)replayed;
    // O_APPEND writes at the end; no explicit seek needed.
}

bool PqWitnessRegistry::is_pq_sender(const uint8_t sender_nfa[42]) const {
    std::array<uint8_t, 42> sender{};
    std::memcpy(sender.data(), sender_nfa, 42);
    std::lock_guard<std::mutex> lock(mutex_);
    return sender_roots_.count(sender) != 0;
}

bool PqWitnessRegistry::lookup(const std::array<uint8_t, 32>& msg_digest,
                               PqSignatureWitness& out) const {
    std::lock_guard<std::mutex> lock(mutex_);
    const auto it = by_digest_.find(msg_digest);
    if (it == by_digest_.end() || it->second.empty()) return false;
    out = it->second.front().witness;
    return true;
}

bool PqWitnessRegistry::lookup_verifying(const Transaction& tx,
                                         PqSignatureWitness& out) const {
    // Copy the candidate witnesses out under the lock; verification runs
    // WITHOUT the registry lock (it is pure CPU over public data, and a
    // full WOTS+/XMSS pass must never serialize every consensus lookup).
    static thread_local std::vector<PqSignatureWitness> cands;
    cands.clear();
    {
        std::lock_guard<std::mutex> lock(mutex_);
        const auto it = by_digest_.find(tx_msg_digest(tx));
        if (it == by_digest_.end() || it->second.empty()) return false;
        for (const auto& c : it->second) cands.push_back(c.witness);
    }
    for (const auto& w : cands) {
        if (pq_verify_transaction(tx, w)) { out = w; return true; }
    }
    return false;
}

void PqWitnessRegistry::set_last(const Transaction& tx, const PqSignatureWitness& w) {
    std::lock_guard<std::mutex> lock(mutex_);
    last_tx_ = tx;
    last_witness_ = w;
    has_last_ = true;
}

bool PqWitnessRegistry::get_last(Transaction& tx, PqSignatureWitness& w) const {
    std::lock_guard<std::mutex> lock(mutex_);
    if (!has_last_) return false;
    tx = last_tx_;
    w = last_witness_;
    return true;
}

size_t PqWitnessRegistry::registered_count() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return by_digest_.size();
}

} // namespace vx::crypto::pq
