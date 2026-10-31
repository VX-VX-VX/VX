#include "vx/crypto/pq_signature.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/core/memory_vault.hpp"

#include "vx/core/hw_intrinsics.hpp"
#include <chrono>
#include <cstring>

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

// ── Sign / verify ────────────────────────────────────────────────────────────

PqSignatureWitness pq_sign_message(uint32_t leaf_idx, uint32_t subtree_index,
                                   const std::array<uint8_t, 32>& master_sk,
                                   const std::array<uint8_t, 32>& pub_seed,
                                   const std::array<uint8_t, 32>& msg) noexcept {
    PqSignatureWitness w;
    w.leaf_index = leaf_idx;
    w.subtree_index = subtree_index;
    w.pub_seed = pub_seed;
    w.pq_pubkey_root = xmss_root(master_sk, pub_seed);

    const uint32_t global_leaf = (subtree_index << XMSS_H) | leaf_idx;
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

    // Auth path: rebuild the tree from all leaves, collect H siblings.
    std::array<std::array<uint8_t, 32>, XMSS_LEAVES> level{};
    for (size_t j = 0; j < XMSS_LEAVES; ++j) {
        level[j] = wots_leaf_pk_root(static_cast<uint32_t>(j), master_sk, pub_seed);
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
    Sponge ws;
    ws.absorb(reinterpret_cast<const uint8_t*>("VX_SEGPQ_WITNESS_V1"), 18);
    ws.absorb_obj(w.leaf_index);
    ws.absorb_obj(w.subtree_index);
    ws.absorb(w.pub_seed.data(), 32);
    ws.absorb(w.pq_pubkey_root.data(), 32);
    for (size_t i = 0; i < WOTS_CHAINS; ++i) ws.absorb(w.wots_sig[i].data(), 32);
    for (size_t i = 0; i < XMSS_H; ++i) ws.absorb(w.auth_path[i].data(), 32);
    ws.finalize(w.witness_digest.data());
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

    size_t idx = w.leaf_index;
    for (size_t lvl = 0; lvl < XMSS_H; ++lvl) {
        const size_t sib_idx = (idx & 1) ? idx - 1 : idx + 1;
        const std::array<uint8_t, 32>& left = (idx & 1) ? w.auth_path[lvl] : cur;
        const std::array<uint8_t, 32>& right = (idx & 1) ? cur : w.auth_path[lvl];
        cur = xmss_node_hash(static_cast<uint8_t>(lvl), static_cast<uint16_t>(sib_idx & ~size_t(1)),
                             w.pub_seed, left, right);
        idx >>= 1;
    }
    return cur == w.pq_pubkey_root;
}

bool pq_verify_transaction(const Transaction& tx, const PqSignatureWitness& w) noexcept {
    const auto msg = tx_msg_digest(tx);
    if (!pq_verify_wots_xmss(msg, w)) return false;

    // Anchor: cocoon_proof must be trunc12(Sponge("VX_SEGPQ_ANCHOR_V1" || msg || root || witness_digest)).
    PreimageBuf a; // 18 + 32*3 = 114 bytes, fits
    a.put_str("VX_SEGPQ_ANCHOR_V1", 18);
    a.put(msg.data(), 32);
    a.put(w.pq_pubkey_root.data(), 32);
    a.put(w.witness_digest.data(), 32);
    std::array<uint8_t, 32> full_tag{};
    sponge(a.b.data(), a.n, full_tag.data());
    return std::memcmp(full_tag.data(), tx.cocoon_proof, 12) == 0;
}

// ── SegPQ signing with MemoryVault ─────────────────────────────────────────

void pq_sign_transaction(Transaction& tx, const std::array<uint8_t, 32>& master_sk,
                         PqSignTimings* timings) noexcept {
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

    t0 = vx::core::hw::cycle_counter();
    const auto sg0 = std::chrono::steady_clock::now();
    PqSignatureWitness w = pq_sign_message(leaf_idx, subtree_index, sk, pub_seed,
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
}

// ── PqWitnessRegistry ────────────────────────────────────────────────────────

PqWitnessRegistry& PqWitnessRegistry::instance() noexcept {
    static PqWitnessRegistry reg;
    return reg;
}

void PqWitnessRegistry::register_witness(const Transaction& tx, const PqSignatureWitness& w) {
    const auto digest = tx_msg_digest(tx);
    Entry e;
    e.witness = w;
    std::memcpy(e.sender.data(), tx.sender_nfa, 42);
    std::lock_guard<std::mutex> lock(mutex_);
    by_digest_[digest] = e;
    std::array<uint8_t, 42> sender{};
    std::memcpy(sender.data(), tx.sender_nfa, 42);
    sender_roots_[sender] = w.pq_pubkey_root;
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
    if (it == by_digest_.end()) return false;
    out = it->second.witness;
    return true;
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
