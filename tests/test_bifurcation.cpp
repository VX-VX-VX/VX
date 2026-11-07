// tests/test_bifurcation.cpp -- the bifurcation oracle (determinism test).
//
// Consensus IS determinism: any hidden nondeterminism in the state machine
// (hash-map iteration order, float math, pointer-dependent sorting,
// uninitialized memory) eventually splits the chain: two honest nodes that
// apply the same blocks must reach BYTE-IDENTICAL state after every height.
//
// This file contains NO production-code changes. It:
//   1. defines canonical_state_digest(): a total-order serialization of the
//      whole LedgerState (ALL accounts sorted by ADDRESS BYTES, never by
//      pointer or by hash-map iteration order -- sorting by address bytes is
//      the whole point: an unordered_map walked twice in one process can
//      already yield different orders), hashed with VortexSponge256;
//   2. builds a deterministic PRNG-driven chain (pinned GENESIS_2 mint at
//      height 1, then per block one MINER_ floor coinbase plus 0..5
//      post-quantum-signed transfers), digesting the ledger after EVERY
//      block;
//   3. for 5 seeds, forks a child process that builds the same chain in its
//      own temp directory, while the parent builds it independently in its
//      own; ANY digest divergence at ANY height is a bifurcation and fails
//      with the height and both digests printed.
//
// Note on fork + sanitizers: the fork-based runs target the GCC lane. If the
// translation unit is compiled with AddressSanitizer, the child inherits the
// ASan shadow and leak checks run in a process that calls _exit() mid-test;
// in that configuration the test falls back to two independent in-process
// builds (fresh temp dirs, fresh ledger/store objects) and compares their
// digest lists -- a weaker (same address space) but still useful check.
//
// Runtime budget: < 300 s on the GCC lane. See POGW_BITS / BLOCKS_PER_SEED.

#include <gtest/gtest.h>
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/blockchain/emission.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/storage/block_store.hpp"
#include "vx/state/ledger_state.hpp"

#include <algorithm>
#include <cerrno>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <string>
#include <system_error>
#include <unistd.h>
#include <sys/wait.h>

using namespace vx::blockchain;
using vx::core::U128;

namespace {

// -- Tunables (chosen for the < 300 s GCC budget; see the test report) -------

// Test-lane PoGW difficulty: the store's live-intake gate demand. Production
// is 16 bits; 8 bits keeps the per-block seal search (~2^8 full-frame sponge
// hashes on average, ~12 ms) cheap enough to run hundreds of blocks per seed
// while still exercising the exact producer path (seal_pogw_nonce) every
// block. The emission entitlement check is unaffected: the test's coinbase
// claims the 50 VX floor, which is valid for ANY frame hash.
#ifndef __SANITIZE_ADDRESS__
constexpr uint64_t POGW_BITS = 8;
#else
constexpr uint64_t POGW_BITS = 5; // ASan lane: keep the fallback short
#endif

// Blocks per seed (5 seeds). Measured on the GCC lane: ~37 ms per block
// base (seal at 8 bits + append + apply) plus ~30 ms per signed transaction
// (each pq_sign_transaction builds its own 4 MB mlock arena and re-derives
// the full XMSS tree), average ~2.8 signed txs per block -> ~125 ms/block.
// The fork run builds parent and child chains CONCURRENTLY, so the whole
// test costs roughly one pass over all seeds: 1500 blocks x ~125 ms is
// ~3 minutes, safely inside the 300 s budget. A 1000-block seed would add
// ~2 minutes on its own and does not fit alongside the other seeds.
// Under ASan the fork runs are replaced by a short in-process fallback,
// so only a few dozen blocks are used there.
#ifndef __SANITIZE_ADDRESS__
constexpr uint64_t BLOCKS_PER_SEED[5] = {200, 250, 300, 350, 400};
#else
constexpr uint64_t BLOCKS_PER_SEED[5] = {40, 40, 40, 40, 40};
#endif

// Economy shape constants (all deterministic; no floats anywhere).
//
// LEAF ECONOMY: every PQ key signs at most 15 transactions in its lifetime
// (the XMSS tree spans leaves 0..15 but leaf 15 is RESERVED for rollover
// certificates — pq_sign_transaction refuses nonce >= 15 as the kernel
// invariant). So the chain is funded through a
// three-tier tree whose leaf budgets are checked by the builder:
//
//   demo spender (100,000 VX mint) -- 12 funding txs (leaves 0..11)
//     -> 12 tier-A accounts, 800 VX each -- 14 funding txs each
//        -> up to 168 tier-B accounts, 50 VX each -- 15 transfer leaves each
//
// Transfer capacity ~2,700 + funding txs ~180 -- ample even for a
// 1000-block seed (average 2.5 transfers/block); what caps the seed length
// in practice is the runtime budget, not this economy. Sender exhaustion
// is handled by a deterministic skip, never by a hard failure.
constexpr size_t   MAX_TIER_A        = 12;                     // first tier
constexpr size_t   MAX_B_PER_A       = 14;                     // B accounts per A
constexpr size_t   SINK_POOL         = 16;                     // receive-only sinks
constexpr size_t   MINER_POOL        = 4;                      // coinbase receivers
constexpr uint64_t A_FUNDING_ATOMICS = 80'000'000'000ull;      // 800 VX
constexpr uint64_t B_FUNDING_ATOMICS = 5'000'000'000ull;       // 50 VX
constexpr uint64_t TX_MIN_ATOMICS    = 1'200'000ull;           // TDI-safe dust floor
constexpr uint64_t TX_SPREAD_ATOMICS = 48'800'000ull;          // amounts up to ~50M

// -- Deterministic PRNG (splitmix64; integer-only) ---------------------------

uint64_t splitmix64(uint64_t& state) {
    state += 0x9E3779B97F4A7C15ull;
    uint64_t z = state;
    z = (z ^ (z >> 30)) * 0xBF58476D1CE4E5B9ull;
    z = (z ^ (z >> 27)) * 0x94D049BB133111EBull;
    return z ^ (z >> 31);
}

// -- Test idioms (same shapes as tests/test_documented_gaps.cpp) -------------

std::filesystem::path unique_temp_dir(const std::string& tag) {
    auto dir = std::filesystem::temp_directory_path() /
               (tag + "_" + std::to_string(::getpid()));
    std::error_code ec;
    std::filesystem::remove_all(dir, ec);
    std::filesystem::create_directories(dir);
    return dir;
}

Address addr_of(const std::string& s) {
    Address a{};
    std::memcpy(a.data(), s.data(), s.size() < 42 ? s.size() : 42);
    return a;
}

struct PqAccount {
    std::array<uint8_t, 32> sk{};
    Address addr{};
};

PqAccount make_pq_account(const std::string& tag) {
    PqAccount acc;
    VortexSponge256::compute(reinterpret_cast<const uint8_t*>(tag.data()),
                             tag.size(), acc.sk.data());
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(acc.sk);
    const auto root = vx::crypto::pq::xmss_root(acc.sk, pub_seed);
    derive_pq_address(root.data(), acc.addr.data());
    return acc;
}

bool pq_sign(Transaction& tx, const PqAccount& acc) {
    return vx::crypto::pq::pq_sign_transaction(tx, acc.sk);
}

Transaction make_tx(const Address& sender, const Address& receiver,
                    uint64_t amount, uint32_t nonce) {
    Transaction tx{};
    std::memcpy(tx.sender_nfa, sender.data(), 42);
    std::memcpy(tx.receiver_nfa, receiver.data(), 42);
    tx_set_amount(tx, amount);
    tx_set_fee(tx, 100);
    tx_set_nonce(tx, nonce);
    return tx;
}

struct PushResult {
    bool ok = false;
    std::string error;
};

PushResult push_block(vx::storage::BlockStore& store,
                      vx::state::LedgerState& ledger, BlockBuilder& b) {
    PushResult out;
    // BACKLOG 2.11: bind the canonical witness set before sealing.
    b.bind_canonical_witnesses(
        [&ledger](const std::array<uint8_t, 42> &a, std::array<uint8_t, 32> &out) {
            return ledger.pq_root_of(a, out);
        });
    b.finalize();
    BlockFrame frame;
    std::memcpy(frame.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
    if (!seal_pogw_nonce(frame, store.required_pogw_bits())) {
        out.error = "PoGW seal exhausted";
        return out;
    }
    if (!store.append_block(frame)) {
        out.error = "store rejected the frame: " + store.last_error();
        return out;
    }
    const auto res = ledger.apply_block(BlockView(frame));
    if (!res.ok) {
        out.error = "ledger refused the block: " + res.error;
        return out;
    }
    out.ok = true;
    return out;
}

BlockBuilder next_block(vx::storage::BlockStore& store, uint64_t ts) {
    BlockBuilder b;
    b.set_height(store.chain_height());
    b.set_timestamp(ts);
    uint8_t tip[32];
    store.tip_hash(tip);
    b.set_prev_hash(tip);
    std::array<uint8_t, 384> coords{};
    b.set_attractor_coords(coords.data());
    return b;
}

// -- 1. canonical_state_digest -----------------------------------------------
//
// THE definition under test: a total-order serialization of the entire
// LedgerState, hashed with VortexSponge256.
//
//   digest = Sponge256( "VX_BIF_STATE_DIGEST_V1"
//                       || u64_le(account_count)
//                       || per account, ascending by ADDRESS BYTES:
//                            addr[42] || u128_le(balance) || u32_le(next_nonce)
//                       || u128_le(issued_supply)
//                       || u128_le(burned_supply)
//                       || u128_le(total_supply)
//                       || u64_le(next_expected_height) )
//
// Sorting by address BYTES (std::array<uint8_t,42> lexicographic <) is the
// whole point: LedgerState stores accounts in std::unordered_map, whose
// iteration order is an implementation artifact (bucket layout, insertion
// history, allocator addresses). Serializing in map order would hash a
// different byte stream for the SAME state and flag phantom bifurcations;
// serializing in sorted-byte order hashes a canonical stream and lets any
// REAL divergence (a balance, a nonce, a supply counter, a tracked-but-empty
// account) change the digest. Addresses are copied out by VALUE and compared
// byte-wise, never by pointer identity.
std::string canonical_state_digest(const vx::state::LedgerState& ledger) {
    std::vector<std::pair<Address, U128>> accounts;
    accounts.reserve(ledger.accounts().size());
    for (const auto& [addr, bal] : ledger.accounts()) accounts.emplace_back(addr, bal);
    std::sort(accounts.begin(), accounts.end(),
              [](const std::pair<Address, U128>& x,
                 const std::pair<Address, U128>& y) {
                  return x.first < y.first; // byte-wise lexicographic order
              });

    VortexSponge256 sponge;
    const char* domain = "VX_BIF_STATE_DIGEST_V1";
    sponge.absorb(reinterpret_cast<const uint8_t*>(domain), std::strlen(domain));

    const uint64_t count = static_cast<uint64_t>(accounts.size());
    sponge.absorb(reinterpret_cast<const uint8_t*>(&count), sizeof(count));

    for (const auto& [addr, bal] : accounts) {
        sponge.absorb(addr.data(), addr.size());               // 42 B, sorted order
        uint8_t bal_le[16];
        bal.to_le_bytes(bal_le);
        sponge.absorb(bal_le, sizeof(bal_le));                 // 16 B balance
        const uint32_t nonce = ledger.get_next_nonce(addr);
        sponge.absorb(reinterpret_cast<const uint8_t*>(&nonce),
                      sizeof(nonce));                          // 4 B next nonce
    }

    const auto absorb_u128 = [&sponge](const U128& v) {
        uint8_t le[16];
        v.to_le_bytes(le);
        sponge.absorb(le, sizeof(le));
    };
    absorb_u128(ledger.issued_supply());
    absorb_u128(ledger.total_burned());
    absorb_u128(ledger.total_supply());
    const uint64_t height = ledger.next_expected_height();
    sponge.absorb(reinterpret_cast<const uint8_t*>(&height), sizeof(height));

    uint8_t digest[32];
    sponge.finalize(digest);
    static const char* hexd = "0123456789abcdef";
    std::string hex;
    hex.reserve(64);
    for (uint8_t byte : digest) {
        hex.push_back(hexd[byte >> 4]);
        hex.push_back(hexd[byte & 0xF]);
    }
    return hex;
}

// -- 2. build_chain: deterministic PRNG chain builder ------------------------
//
// Builds `blocks` blocks from `seed` in an isolated directory and appends the
// canonical state digest after EVERY block to `out_digests`. Everything the
// builder consumes (PRNG stream, addresses, amounts, nonces, timestamps) is a
// pure function of (seed, height) -- wall-clock time and pointer values never
// enter the frame or the state.

struct BuildOutcome {
    bool ok = false;
    std::string error;
};

BuildOutcome build_chain(uint64_t seed, uint64_t blocks,
                         const std::filesystem::path& work_dir,
                         std::vector<std::string>& out_digests) {
    BuildOutcome out;

    // The genesis frame is rebuilt in-process (never shipped): fixed
    // attractor seed, fixed timestamp -- identical bytes on every node.
    const auto ledger_path = work_dir / "chain.vxb";
    const auto genesis_path = work_dir / "genesis.bin"; // per-run, no cwd races
    vx::storage::BlockStore store(ledger_path.string(), genesis_path.string(),
                                  POGW_BITS);
    vx::state::LedgerState ledger;

    // Apply the store's auto-seeded genesis (height 0) so the ledger starts
    // exactly where a fresh node starts.
    {
        const RawBlock* g = store.get_block(0);
        if (g == nullptr) {
            out.error = "genesis block missing";
            return out;
        }
        BlockFrame gf;
        std::memcpy(gf.data(), reinterpret_cast<const uint8_t*>(g), BLOCK_SIZE_BYTES);
        const auto res = ledger.apply_block(BlockView(gf));
        if (!res.ok) {
            out.error = "genesis apply failed: " + res.error;
            return out;
        }
    }
    const uint64_t genesis_ts = store.get_block(0)->header.timestamp;

    // The demo spender: sk = Sponge("VX_DEMO_SPENDER_SK_V1"), address bound
    // to the pinned GENESIS_2 mint receiver payload (public testnet key).
    PqAccount spender;
    spender.sk = [] {
        std::array<uint8_t, 32> sk{};
        VortexSponge256::compute(reinterpret_cast<const uint8_t*>("VX_DEMO_SPENDER_SK_V1"),
                                 21, sk.data());
        return sk;
    }();
    spender.addr = genesis2_mint_receiver_payload();

    // Fixed receive-only sink pool and coinbase receiver pool.
    std::vector<Address> sinks;
    for (size_t i = 0; i < SINK_POOL; ++i) {
        char tag[48];
        std::snprintf(tag, sizeof(tag), "NFA_BIF_SINK_%02zu_00000000000000000000000", i);
        sinks.push_back(addr_of(tag));
    }
    std::vector<Address> miners;
    for (size_t i = 0; i < MINER_POOL; ++i) {
        char tag[48];
        std::snprintf(tag, sizeof(tag), "NFA_BIF_MINER_%02zu_000000000000000000000", i);
        miners.push_back(addr_of(tag));
    }

    // Lazily funded self-certifying PQA accounts (they spend only after
    // their funder pays them; the first witnessed spend binds their key).
    // Tier A is funded by the demo spender, tier B by a tier-A account.
    // A tier-A account funds at most MAX_B_PER_A children and keeps its
    // remaining leaves unused; tier-B accounts spend their 15 tx leaves on
    // user transfers. All leaf budgets respect the 15-leaf tx economy
    // (leaf 15 is the reserved rollover-cert leaf).
    std::vector<PqAccount> tier_a;
    std::vector<PqAccount> tier_b;
    auto tier_a_tag = [](size_t i) {
        char tag[48];
        std::snprintf(tag, sizeof(tag), "VX_BIF_TIERA_SK_V1_%02zu", i);
        return std::string(tag);
    };
    auto tier_b_tag = [](size_t i) {
        char tag[48];
        std::snprintf(tag, sizeof(tag), "VX_BIF_TIERB_SK_V1_%03zu", i);
        return std::string(tag);
    };

    uint64_t rng = 0x1262C0000ull ^ (seed * 0x9E3779B97F4A7C15ull + 0x726A2F9D365E5Cull);

    for (uint64_t h = 1; h <= blocks; ++h) {
        uint8_t tip[32];
        store.tip_hash(tip);
        BlockBuilder b = next_block(store, genesis_ts + h);

        // Coinbase, index 0: MINER_ tag, the guaranteed 50 VX floor claim
        // (valid for any frame hash), bound to (receiver, height, tip).
        {
            Transaction cb{};
            std::memcpy(cb.sender_nfa, "MINER_", 6);
            for (size_t i = 6; i < 42; ++i) cb.sender_nfa[i] = '0';
            const Address& recv = miners[splitmix64(rng) % MINER_POOL];
            std::memcpy(cb.receiver_nfa, recv.data(), 42);
            tx_set_amount(cb, 50ull * ATOMS_PER_VX);
            tx_set_fee(cb, 0);
            tx_set_nonce(cb, 0);
            set_coinbase_binding(cb, h, tip);
            if (!b.add_transaction(cb)) {
                out.error = "coinbase rejected by the builder";
                return out;
            }
        }

        // Height 1: the pinned GENESIS_2 mint -- sender tag "GENESIS_2",
        // exactly GENESIS_2_MINT_ATOMICS, to the pinned receiver payload,
        // once per chain (the ledger recomputes and enforces the shape).
        if (h == 1) {
            Transaction mint = make_tx(addr_of("GENESIS_2"), spender.addr,
                                       GENESIS_2_MINT_ATOMICS, 0);
            sign_transaction(mint); // structural Tier-2 digest for system senders
            if (!b.add_transaction(mint)) {
                out.error = "genesis mint rejected by the builder";
                return out;
            }
        }

        // 0..5 PRNG transfers per block, PQ-signed. Every amount is
        // >= 1.2M atomics = 0.012 VX, comfortably above the TDI dust floor
        // for a 112-byte transaction (0.0112 VX: (amount/112)*10000 >= 1).
        //
        // Nonces are sequential per sender INCLUDING intra-block: the ledger
        // only advances a sender's nonce when the block APPLIES, so the
        // builder must track the expected next nonce for the block itself
        // (seeded from the ledger, advanced per included transaction) --
        // otherwise two spends by one sender in one block nonce-collide.
        std::unordered_map<Address, uint32_t, vx::state::AddressHash> block_nonce;
        auto next_nonce = [&](const Address& a) {
            auto it = block_nonce.find(a);
            if (it != block_nonce.end()) return it->second;
            return ledger.get_next_nonce(a);
        };
        auto bump_nonce = [&](const Address& a) {
            block_nonce[a] = next_nonce(a) + 1;
        };

        const uint32_t n_tx = static_cast<uint32_t>(splitmix64(rng) % 6);
        for (uint32_t k = 0; k < n_tx; ++k) {
            // With probability 1/3, grow the funding tree one account:
            // first fill tier A (the demo spender funds at most MAX_TIER_A
            // children out of its 15 usable leaves), then tier B (each
            // tier-A account funds MAX_B_PER_A children out of its leaves).
            if ((splitmix64(rng) % 3) == 0) {
                if (tier_a.size() < MAX_TIER_A) {
                    if (next_nonce(spender.addr) < MAX_TIER_A &&
                        ledger.balance_of(spender.addr) >=
                            U128(A_FUNDING_ATOMICS + 100)) {
                        PqAccount fresh = make_pq_account(tier_a_tag(tier_a.size()));
                        Transaction fund =
                            make_tx(spender.addr, fresh.addr, A_FUNDING_ATOMICS,
                                    next_nonce(spender.addr));
                        if (!pq_sign(fund, spender)) {
                            out.error = "tier-A funding signature failed";
                            return out;
                        }
                        if (!b.add_transaction(fund)) {
                            out.error = "tier-A funding tx rejected";
                            return out;
                        }
                        bump_nonce(spender.addr);
                        tier_a.push_back(fresh);
                    }
                } else if (tier_b.size() < tier_a.size() * MAX_B_PER_A) {
                    const PqAccount& parent =
                        tier_a[tier_b.size() / MAX_B_PER_A];
                    if (next_nonce(parent.addr) < MAX_B_PER_A &&
                        ledger.balance_of(parent.addr) >=
                            U128(B_FUNDING_ATOMICS + 100)) {
                        PqAccount fresh = make_pq_account(tier_b_tag(tier_b.size()));
                        Transaction fund =
                            make_tx(parent.addr, fresh.addr, B_FUNDING_ATOMICS,
                                    next_nonce(parent.addr));
                        if (!pq_sign(fund, parent)) {
                            out.error = "tier-B funding signature failed";
                            return out;
                        }
                        if (!b.add_transaction(fund)) {
                            out.error = "tier-B funding tx rejected";
                            return out;
                        }
                        bump_nonce(parent.addr);
                        tier_b.push_back(fresh);
                    }
                }
            }

            // A PQ-signed user transfer from a tier-B account. The sender
            // scan starts at a PRNG index and walks forward, skipping
            // accounts that exhausted their 15 tx leaves or their
            // balance -- deterministic either way. With no usable sender
            // the slot is skipped (still deterministic; the digest
            // barely notices).
            if (!tier_b.empty()) {
                const uint64_t amount =
                    TX_MIN_ATOMICS + splitmix64(rng) % TX_SPREAD_ATOMICS;
                const Address& recv = sinks[splitmix64(rng) % SINK_POOL];
                const size_t start =
                    static_cast<size_t>(splitmix64(rng) % tier_b.size());
                for (size_t scan = 0; scan < tier_b.size(); ++scan) {
                    const PqAccount& sender = tier_b[(start + scan) % tier_b.size()];
                    if (next_nonce(sender.addr) >= 15) continue; // leaves spent
                    if (ledger.balance_of(sender.addr) < U128(amount + 100)) {
                        continue; // balance spent
                    }
                    Transaction tx = make_tx(sender.addr, recv, amount,
                                             next_nonce(sender.addr));
                    if (!pq_sign(tx, sender)) {
                        out.error = "transfer signature failed";
                        return out;
                    }
                    if (!b.add_transaction(tx)) {
                        out.error = "transfer rejected by the builder";
                        return out;
                    }
                    bump_nonce(sender.addr);
                    break;
                }
            }
        }

        // Seal (real PoGW work), append, apply, digest. EVERY one of these
        // must succeed for the PRNG's chosen economy; a refusal here is a
        // bug in the test's own economy, not a soft skip.
        const PushResult pushed = push_block(store, ledger, b);
        if (!pushed.ok) {
            out.error = "block " + std::to_string(h) + ": " + pushed.error;
            return out;
        }
        out_digests.push_back(canonical_state_digest(ledger));
    }

    out.ok = true;
    return out;
}

// -- digest-file helpers -----------------------------------------------------

bool read_digest_file(const std::filesystem::path& path,
                      std::vector<std::string>& digests) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return false;
    std::string line;
    while (std::getline(f, line)) {
        if (!line.empty()) digests.push_back(line);
    }
    return true;
}

// Compares two digest lists; on divergence fills `report` with the first
// diverging height and both digests.
bool digest_lists_match(const std::vector<std::string>& a,
                        const std::vector<std::string>& b, std::string& report) {
    if (a.size() != b.size()) {
        report = "digest list lengths differ: parent " +
                 std::to_string(a.size()) + " vs other " + std::to_string(b.size());
        return false;
    }
    for (size_t i = 0; i < a.size(); ++i) {
        if (a[i] != b[i]) {
            // Height h in the digest list = block height i+1 (genesis at 0
            // is applied before the first digest is taken).
            report = "BIFURCATION at height " + std::to_string(i + 1) +
                     ": parent digest " + a[i] + " vs other digest " + b[i];
            return false;
        }
    }
    return true;
}

#ifndef __SANITIZE_ADDRESS__
// -- 3. one fork run for one seed --------------------------------------------
//
// The child builds the seed's chain in ITS OWN temp directory (its own
// BlockStore file, its own genesis.bin, its own LedgerState) and writes the
// per-block digest list to a file, then _exit(0) -- the child NEVER touches
// gtest state or returns into the test body. The parent independently builds
// the SAME chain in its own directory and compares digest lists.
//
// The parent builds WHILE the child runs, so each seed costs roughly one
// chain build of wall time, not two.
bool fork_run_seed(uint64_t seed, uint64_t blocks, std::string& report) {
    const auto base = unique_temp_dir("vx_bif_seed" + std::to_string(seed & 0xFFFF));
    const auto child_dir = base / "child";
    const auto parent_dir = base / "parent";
    std::filesystem::create_directories(child_dir);
    std::filesystem::create_directories(parent_dir);
    const auto child_file = base / "child_digests.txt";

    const pid_t pid = ::fork();
    if (pid < 0) {
        report = "fork() failed: " + std::string(std::strerror(errno));
        std::filesystem::remove_all(base);
        return false;
    }
    if (pid == 0) {
        // -- child: no gtest, no EXPECT, no return into the test body --
        std::string child_err;
        std::vector<std::string> digests;
        try {
            const BuildOutcome o = build_chain(seed, blocks, child_dir, digests);
            if (!o.ok) child_err = o.error;
        } catch (const std::exception& e) {
            child_err = std::string("exception in child build: ") + e.what();
        }
        std::ofstream f(child_file, std::ios::binary | std::ios::trunc);
        if (!f) _exit(2);
        if (!child_err.empty()) {
            f << "BUILD_FAILED " << child_err << "\n";
            f.flush();
            _exit(3);
        }
        for (const auto& d : digests) f << d << "\n";
        f.flush();
        _exit(0);
    }

    // -- parent: the same chain, independently --
    std::vector<std::string> parent_digests;
    const BuildOutcome mine = build_chain(seed, blocks, parent_dir, parent_digests);
    int status = 0;
    ::waitpid(pid, &status, 0);

    bool ok = false;
    do {
        if (!mine.ok) {
            report = "parent build failed: " + mine.error;
            break;
        }
        if (!WIFEXITED(status) || WEXITSTATUS(status) != 0) {
            report = "child exited abnormally (status " +
                     std::to_string(status) + ")";
            break;
        }
        std::vector<std::string> child_digests;
        if (!read_digest_file(child_file, child_digests)) {
            report = "child digest file missing/unreadable";
            break;
        }
        ok = digest_lists_match(parent_digests, child_digests, report);
    } while (false);

    std::error_code ec;
    std::filesystem::remove_all(base, ec);
    return ok;
}
#endif // !__SANITIZE_ADDRESS__

} // namespace

// -- the oracle --------------------------------------------------------------
//
// For each of 5 seeds: fork a child that builds the chain in its own temp
// dir while the parent builds the same chain in its own; the digest list
// taken after every block must match EXACTLY. Any divergence at any height
// is a consensus bifurcation and fails with the height and both digests.
//
// The 5 seeds double as a mini seed-farm: the report below carries per-seed
// pass/fail so a flaky seed-specific divergence is visible immediately.
#ifndef __SANITIZE_ADDRESS__
TEST(VxBifurcationOracle, ForkedProcessesReachIdenticalState) {
    struct SeedResult {
        uint64_t seed;
        uint64_t blocks;
        bool ok;
        std::string note;
    };
    std::vector<SeedResult> results;
    static const uint64_t SEEDS[5] = {
        0xB1474C41E5001ull, 0xB1474C41E5002ull, 0xB1474C41E5003ull,
        0xB1474C41E5004ull, 0xB1474C41E5005ull,
    };

    for (int i = 0; i < 5; ++i) {
        const uint64_t seed = SEEDS[i];
        const uint64_t blocks = BLOCKS_PER_SEED[i];
        std::string report;
        const bool ok = fork_run_seed(seed, blocks, report);
        results.push_back({seed, blocks, ok, report});
        if (!ok) {
            // Print the divergence (height + both digests) loudly before the
            // assertion fires, so it survives gtest failure truncation.
            std::fprintf(stderr, "[seed %llu] %s\n",
                         static_cast<unsigned long long>(seed), report.c_str());
        }
    }

    for (const auto& r : results) {
        EXPECT_TRUE(r.ok) << "seed " << static_cast<unsigned long long>(r.seed)
                          << " (" << static_cast<unsigned long long>(r.blocks)
                          << " blocks): " << r.note;
    }
    // Seed-farm summary on stdout (visible with default gtest output).
    for (const auto& r : results) {
        std::string line = "[BIFURCATION FARM] seed " +
                           std::to_string(r.seed) + " blocks " +
                           std::to_string(r.blocks) + " -> " +
                           (r.ok ? std::string("PASS")
                                 : std::string("FAIL (") + r.note + ")");
        std::fprintf(stdout, "%s\n", line.c_str());
    }
    std::fflush(stdout);
}
#else
// ASan fallback: the fork runs are disabled (a forked child inherits the
// sanitizer shadow and _exit() trips leak checks), so the same oracle runs
// as two INDEPENDENT in-process builds -- fresh temp dirs, fresh BlockStore,
// fresh LedgerState each -- compared digest by digest. Weaker than the fork
// (same address space), but still catches map-order/pointer-dependent
// behavior that changes between two runs of the builder.
TEST(VxBifurcationOracle, IndependentBuildsReachIdenticalState) {
    for (int i = 0; i < 5; ++i) {
        const uint64_t seed = 0xB1474C41E5001ull + static_cast<uint64_t>(i);
        const uint64_t blocks = BLOCKS_PER_SEED[i];
        const auto base = unique_temp_dir("vx_bif_asan_seed" +
                                          std::to_string(seed & 0xFFFF));
        const auto dir_a = base / "a";
        const auto dir_b = base / "b";
        std::filesystem::create_directories(dir_a);
        std::filesystem::create_directories(dir_b);

        std::vector<std::string> a, b;
        const BuildOutcome oa = build_chain(seed, blocks, dir_a, a);
        ASSERT_TRUE(oa.ok) << "seed " << static_cast<unsigned long long>(seed)
                           << ": " << oa.error;
        const BuildOutcome ob = build_chain(seed, blocks, dir_b, b);
        ASSERT_TRUE(ob.ok) << "seed " << static_cast<unsigned long long>(seed)
                           << ": " << ob.error;

        std::string report;
        EXPECT_TRUE(digest_lists_match(a, b, report))
            << "seed " << static_cast<unsigned long long>(seed) << ": " << report;

        std::error_code ec;
        std::filesystem::remove_all(base, ec);
    }
}
#endif
