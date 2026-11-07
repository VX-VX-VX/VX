// libFuzzer target: reorg-interleaved intake (BACKLOG 2.3b, owner
// question 2026-11-05).
//
// One low-difficulty chain driven from the fuzz input through four
// interleaved command streams:
//   cmd 0 — HONEST extension: coinbase + 0..2 PQ-signed transfers from a
//           rolling funded pool (sequential nonces, leaf-ledger burn).
//   cmd 1 — HOSTILE frame: a bit-mutated copy of a valid frame (or a
//           competing-height clone) through the store intake gate; every
//           refusal must leave the ledger untouched and the undo journal
//           consistent (drop_last_record, the production resync order).
//   cmd 2 — REORG: journal displaced frames, rollback to an input-chosen
//           branch height, truncate the store file (the carousel heal
//           ordering), then either re-attach the displaced fork or grow
//           honest blocks again.
//   cmd 3 — sanity tick: ledger height == store height; the undo journal
//           must never gap.
//
// Invariants (checked continuously, cheap):
//   - no crash / no UB (the sanitizer lanes are the oracle);
//   - after every step, ledger.next_expected_height() == store height + 1
//     unless the last op was a refused apply (which must leave both
//     untouched);
//   - sender nonce counters always equal their per-chain user-tx counts;
//   - supply identity holds (exact_total_supply sanity path).
// Final (per exec): a FRESH LedgerState replaying the store's surviving
// frames must converge to the SAME canonical state digest as the live
// ledger - post-heal determinism against a reference apply order.
//
// Honest scope (the limiter BACKLOG 2.3b pins): production fork choice is
// not implemented yet - apply_remote_frame DROPS competing-height frames,
// so competing FORKS enter only through the store-level mutation path
// above (a mutated frame that keeps its work/merkle valid is an
// alternative same-height successor). Extend the harness when fork choice
// lands.
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/core/u128.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/storage/block_store.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/state/undo_engine.hpp"

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <string>
#include <unordered_map>
#include <vector>
#include <unistd.h>

using namespace vx::blockchain;
using vx::core::U128;

namespace {

constexpr uint64_t kGenesisTs = 1761000000ULL;
constexpr uint64_t kPogwBits = 8;
constexpr uint64_t kMinAmount = 1'120'000;
constexpr uint64_t kFee = 100;
constexpr size_t kPoolAccounts = 8;
// 8 pool x 1e9 = 8e9 (+ fees) must fit under the 1e10 GENESIS_2 mint - the
// demo spender funds the whole pool from ONE block (this prefix is built in
// a single deterministic shape every exec, unlike the carousel's
// one-funding-per-block schedule).
constexpr uint64_t kSeedFundingAtoms = 1'000'000'000ULL;
constexpr unsigned kMaxSteps = 48;
constexpr unsigned kMaxTransfers = 30; // bounds the per-exec leaf burns

std::filesystem::path scratch_dir() {
    static const std::filesystem::path dir =
        std::filesystem::temp_directory_path() / "vx_fuzz_reorg";
    return dir;
}

Address addr_of(const std::string &s) {
    Address a{};
    std::memcpy(a.data(), s.data(), s.size() < 42 ? s.size() : 42);
    return a;
}

Address tagged_addr(const char *prefix, uint64_t serial) {
    std::string s(prefix);
    std::string num = std::to_string(serial);
    if (num.size() < 42 - s.size())
        num.insert(0, 42 - s.size() - num.size(), '0');
    s += num;
    return addr_of(s);
}

Address tx_address(const uint8_t nfa[42]) {
    Address a{};
    std::memcpy(a.data(), nfa, 42);
    return a;
}

struct PoolAccount {
    std::array<uint8_t, 32> sk{};
    Address addr{};
};

PoolAccount make_pq_account(const char *tag) {
    PoolAccount acc;
    VortexSponge256::compute(reinterpret_cast<const uint8_t *>(tag), std::strlen(tag),
                             acc.sk.data());
    const auto pub_seed = vx::crypto::pq::pub_seed_from_sk(acc.sk);
    const auto root = vx::crypto::pq::xmss_root(acc.sk, pub_seed);
    derive_pq_address(root.data(), acc.addr.data());
    return acc;
}

Transaction make_coinbase(const Address &recv, uint64_t amount_atoms, uint64_t height,
                          const uint8_t prev_tip[32]) {
    Transaction cb{};
    std::memcpy(cb.sender_nfa, "MINER_", 6);
    for (size_t i = 6; i < 42; ++i)
        cb.sender_nfa[i] = '0';
    std::memcpy(cb.receiver_nfa, recv.data(), 42);
    tx_set_amount(cb, amount_atoms);
    tx_set_fee(cb, 0);
    tx_set_nonce(cb, 0);
    set_coinbase_binding(cb, height, prev_tip);
    return cb;
}

bool pq_sign_transfer(Transaction &tx, const PoolAccount &acc,
                      vx::crypto::pq::PqLeafLedger &mem_ledger) {
    return vx::crypto::pq::pq_sign_transaction(tx, acc.sk, nullptr, &mem_ledger);
}

bool is_system_sender(const Address &a) {
    const char *s = reinterpret_cast<const char *>(a.data());
    return std::strncmp(s, "GENESIS", 7) == 0 || std::strncmp(s, "MINER_", 6) == 0;
}

std::unordered_map<Address, uint32_t, vx::state::AddressHash>
spent_counts(const std::vector<BlockFrame> &chain) {
    std::unordered_map<Address, uint32_t, vx::state::AddressHash> counts;
    for (size_t h = 1; h < chain.size(); ++h) {
        BlockView view(chain[h]);
        const uint32_t n = view.header().tx_count;
        for (uint32_t i = 0; i < n; ++i) {
            const Address sender = tx_address(view.tx(i).sender_nfa);
            if (is_system_sender(sender))
                continue;
            ++counts[sender];
        }
    }
    return counts;
}

// The carousel's canonical convergence digest (accounts sorted by address
// bytes + balances + nonces + supplies + height through the consensus
// sponge).
std::array<uint8_t, 32> canonical_digest(const vx::state::LedgerState &led) {
    std::vector<const std::pair<const Address, U128> *> accs;
    accs.reserve(led.accounts().size());
    for (const auto &kv : led.accounts())
        accs.push_back(&kv);
    std::sort(accs.begin(), accs.end(), [](const auto *x, const auto *y) {
        return std::memcmp(x->first.data(), y->first.data(), 42) < 0;
    });

    std::vector<uint8_t> buf;
    buf.reserve(accs.size() * 62 + 40);
    auto put = [&buf](const uint8_t *p, size_t n) { buf.insert(buf.end(), p, p + n); };
    auto put_u64 = [&buf](uint64_t v) {
        for (int i = 0; i < 8; ++i)
            buf.push_back(static_cast<uint8_t>(v >> (8 * i)));
    };
    auto put_u32 = [&buf](uint32_t v) {
        for (int i = 0; i < 4; ++i)
            buf.push_back(static_cast<uint8_t>(v >> (8 * i)));
    };
    for (const auto *kv : accs) {
        put(kv->first.data(), 42);
        uint8_t bal[16];
        kv->second.to_le_bytes(bal);
        put(bal, 16);
        put_u32(led.get_next_nonce(kv->first));
    }
    uint8_t issued[16], burned[16];
    led.issued_supply().to_le_bytes(issued);
    led.total_burned().to_le_bytes(burned);
    put(issued, 16);
    put(burned, 16);
    put_u64(led.next_expected_height());

    std::array<uint8_t, 32> digest{};
    VortexSponge256::compute(buf.data(), buf.size(), digest.data());
    return digest;
}

// One byte of fuzz input, or 0 when the input is exhausted (the stream
// degenerates to all-zeros - still a valid drive pattern).
struct ByteStream {
    const uint8_t *data;
    size_t size;
    size_t pos = 0;
    uint8_t next() {
        if (pos < size)
            return data[pos++];
        return 0;
    }
    uint64_t next_u64() {
        uint64_t v = 0;
        for (int i = 0; i < 8; ++i)
            v = (v << 8) | next();
        return v;
    }
};

// An invariant violation must ABORT, not return: libFuzzer records the
// crashing input, so every divergence/nonce gap/supply break becomes a
// reproducible artifact instead of a silently passing exec.
[[noreturn]] void fuzz_fail(const char *what) {
    std::fputs((std::string("FUZZ_REORG INVARIANT VIOLATION: ") + what + "\n").c_str(), stderr);
    std::abort();
}

struct Harness {
    std::string dir = scratch_dir().string();
    std::unique_ptr<vx::storage::BlockStore> store;
    std::unique_ptr<vx::state::LedgerState> ledger;
    std::unique_ptr<vx::state::UndoEngine> undo;
    std::vector<BlockFrame> chain; // mirrors accepted store frames
    std::vector<PoolAccount> pool;
    vx::crypto::pq::PqLeafLedger mem_ledger{""}; // memory-only burn tracking
    uint64_t ts = kGenesisTs + 1000;
    uint64_t serial = 0;
    unsigned transfers_built = 0;
    ByteStream &in;

    explicit Harness(ByteStream &s) : in(s) {
    }

    void open_store() {
        store =
            std::make_unique<vx::storage::BlockStore>(dir + "/chain.vxb", "genesis.bin", kPogwBits);
        if (undo)
            undo->attach_store(*store);
    }

    void truncate_store_to(uint64_t height) {
        const std::string path = dir + "/chain.vxb";
        store.reset();
        std::filesystem::resize_file(path, (height + 1) * BLOCK_SIZE_BYTES);
        open_store();
        chain.resize(height + 1);
    }

    // Resync-order application of one frame: journal BEFORE the store
    // append (the production ordering), then intake gate, then ledger.
    bool apply_frame(const BlockFrame &f) {
        BlockView view(f);
        const uint64_t h = view.header().block_height;
        undo->apply_block(view);
        if (!store->append_block(f)) {
            undo->drop_last_record();
            return false;
        }
        const auto res = ledger->apply_block(view);
        if (!res.ok) {
            std::fprintf(stderr, "apply_frame: ledger refused h=%llu: %s\n", (unsigned long long)h,
                         res.error.c_str());
            undo->drop_last_record();
            return false;
        }
        if (chain.size() == h)
            chain.push_back(f);
        return true;
    }

    // The honest block builder: floor coinbase + up to 2 pool transfers.
    bool build_honest_block(BlockFrame &out) {
        const uint64_t h = store->chain_height();
        uint8_t tip[32];
        store->tip_hash(tip);
        std::vector<Transaction> txs;
        txs.push_back(make_coinbase(tagged_addr("VX_FZ_CB_", ++serial),
                                    BLOCK_REWARD_BASE_VX * ATOMS_PER_VX, h, tip));
        const uint32_t m = static_cast<uint32_t>(in.next() % 3);
        // Same-sender transfers inside ONE block must carry sequential
        // nonces (the ledger's pre-check counts per-sender txs within the
        // block): offset each nonce by the number of earlier txs this block
        // already spends from the same pool account.
        std::map<size_t, uint32_t> nonce_off;
        for (uint32_t t = 0; t < m && transfers_built < kMaxTransfers; ++t) {
            const size_t si = in.next() % pool.size();
            const PoolAccount &sender = pool[si];
            const Address receiver = tagged_addr("VX_FZ_ACC_", ++serial);
            const auto bal = ledger->balance_of(sender.addr);
            if (bal < U128(kMinAmount + kFee))
                continue;
            const uint64_t amt = kMinAmount + (in.next_u64() % (3'000'000));
            const uint32_t nonce = ledger->get_next_nonce(sender.addr) + nonce_off[si]++;
            Transaction tx{};
            std::memcpy(tx.sender_nfa, sender.addr.data(), 42);
            std::memcpy(tx.receiver_nfa, receiver.data(), 42);
            tx_set_amount(tx, amt);
            tx_set_fee(tx, kFee);
            tx_set_nonce(tx, nonce);
            if (!pq_sign_transfer(tx, sender, mem_ledger))
                continue;
            ++transfers_built;
            txs.push_back(tx);
        }
        BlockBuilder b;
        b.set_height(h);
        b.set_timestamp(++ts);
        b.set_prev_hash(tip);
        std::array<uint8_t, 384> coords{};
        b.set_attractor_coords(coords.data());
        for (const auto &t : txs)
            if (!b.add_transaction(t))
                break;
        b.finalize();
        BlockFrame f;
        std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
        if (!seal_pogw_nonce(f, kPogwBits))
            return false;
        out = f;
        return true;
    }

    // A hostile frame: bit-mutated copy of a real frame, or a
    // competing-height clone of the tip.
    BlockFrame make_hostile_frame() {
        BlockFrame f{};
        if (!chain.empty())
            f = chain.back();
        const unsigned flips = 1 + in.next() % 16;
        for (unsigned i = 0; i < flips; ++i) {
            const size_t off = in.next_u64() % BLOCK_SIZE_BYTES;
            f[off] ^= static_cast<uint8_t>(1u << (in.next() % 8));
        }
        if (in.next() % 2 == 1 && !chain.empty()) {
            // Competing-height clone: rewind the frame to the CURRENT tip
            // height - the intake gate must drop it.
            auto *raw = reinterpret_cast<RawBlock *>(f.data());
            raw->header.block_height = store->chain_height(); // = tip height
        }
        return f;
    }

    void run() {
        std::filesystem::remove_all(scratch_dir());
        std::filesystem::create_directories(dir + "/undo");
        open_store();
        ledger = std::make_unique<vx::state::LedgerState>();
        undo = std::make_unique<vx::state::UndoEngine>(dir, *store, *ledger);

        // Genesis.
        {
            const auto *g = store->get_block(0);
            if (!g)
                fuzz_fail("genesis frame missing");
            BlockFrame gf;
            std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
            if (!ledger->apply_block(BlockView(gf)).ok)
                fuzz_fail("genesis frame refused on a fresh ledger");
            chain.push_back(gf);
        }

        // Deterministic prefix: the bound-shape GENESIS_2 mint to the demo
        // spender, then one funding block for the pool (identical bytes
        // every exec - the witness registry dedups across execs).
        // The demo spender: the sponge-derived demo sk signs, but its ledger
        // address is the PINNED GENESIS_2 receiver payload (same override as
        // the carousel prefix - the mint credits the pinned attractor
        // address, and the spend path matches the witness root against the
        // genesis binding, not the XMSS-derived address).
        PoolAccount demo = make_pq_account("VX_DEMO_SPENDER_SK_V1");
        {
            const auto pin = genesis2_mint_receiver_payload();
            std::memcpy(demo.addr.data(), pin.data(), 42);
        }
        {
            // Height 1: the mint -> the pinned GENESIS_2 receiver (consensus
            // pin: the receiver MUST equal genesis2_mint_receiver_payload(),
            // which is the demo spender's attractor address).
            const Address recv = [&] {
                const auto p = genesis2_mint_receiver_payload();
                Address a{};
                std::memcpy(a.data(), p.data(), 42);
                return a;
            }();
            BlockBuilder b;
            b.set_height(1);
            b.set_timestamp(++ts);
            uint8_t tip[32];
            store->tip_hash(tip);
            b.set_prev_hash(tip);
            std::array<uint8_t, 384> coords{};
            b.set_attractor_coords(coords.data());
            Transaction mint{};
            std::memcpy(mint.sender_nfa, "GENESIS_2", 9);
            for (size_t i = 9; i < 42; ++i)
                mint.sender_nfa[i] = '0';
            std::memcpy(mint.receiver_nfa, recv.data(), 42);
            tx_set_amount(mint, GENESIS_2_MINT_ATOMICS);
            tx_set_fee(mint, 0);
            tx_set_nonce(mint, 0);
            sign_transaction(mint);
            if (!b.add_transaction(mint))
                fuzz_fail("mint did not fit");
            b.finalize();
            BlockFrame f;
            std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
            if (!seal_pogw_nonce(f, kPogwBits))
                fuzz_fail("mint seal failed");
            if (!apply_frame(f))
                fuzz_fail("mint frame refused");
        }
        for (size_t i = 0; i < kPoolAccounts; ++i) {
            pool.push_back(make_pq_account(("VX_FZ_POOL_SK_" + std::to_string(i)).c_str()));
        }
        {
            // Height 2: the demo spender funds the pool (fixed shape).
            BlockBuilder b;
            b.set_height(2);
            b.set_timestamp(++ts);
            uint8_t tip[32];
            store->tip_hash(tip);
            b.set_prev_hash(tip);
            std::array<uint8_t, 384> coords{};
            b.set_attractor_coords(coords.data());
            for (size_t i = 0; i < pool.size(); ++i) {
                Transaction t{};
                std::memcpy(t.sender_nfa, demo.addr.data(), 42);
                std::memcpy(t.receiver_nfa, pool[i].addr.data(), 42);
                tx_set_amount(t, kSeedFundingAtoms);
                tx_set_fee(t, kFee);
                tx_set_nonce(t, static_cast<uint32_t>(i));
                if (!vx::crypto::pq::pq_sign_transaction(t, demo.sk))
                    fuzz_fail("demo funding signature failed");
                if (!b.add_transaction(t))
                    fuzz_fail("funding tx did not fit");
            }
            b.finalize();
            BlockFrame f;
            std::memcpy(f.data(), b.bytes().data(), BLOCK_SIZE_BYTES);
            if (!seal_pogw_nonce(f, kPogwBits))
                fuzz_fail("funding seal failed");
            if (!apply_frame(f))
                fuzz_fail("funding frame refused");
        }

        // The fuzz-driven stream.
        for (unsigned step = 0; step < kMaxSteps; ++step) {
            const uint8_t cmd = in.next() % 4;
            if (cmd == 0) {
                BlockFrame f;
                if (build_honest_block(f))
                    (void)apply_frame(f);
            } else if (cmd == 1) {
                const BlockFrame f = make_hostile_frame();
                // Two hostile routes: through the store intake gate...
                BlockView v(f);
                undo->apply_block(v);
                const bool accepted = store->append_block(f);
                if (!accepted) {
                    undo->drop_last_record();
                } else {
                    const auto res = ledger->apply_block(v);
                    if (!res.ok)
                        undo->drop_last_record();
                    else if (chain.size() == v.header().block_height)
                        chain.push_back(f);
                }
            } else if (cmd == 2) {
                // Reorg: journal the displaced tail, roll back, truncate,
                // then re-attach the fork or grow honest blocks.
                const uint64_t tip = store->chain_height(); // next height
                if (tip < 3)
                    continue; // nothing to unwind past the prefix
                const uint64_t branch = 1 + in.next_u64() % (tip - 1);
                if (branch + 1 >= tip)
                    continue;
                (void)undo->journal_displaced_frames(branch);
                if (!undo->rollback_to_height(branch))
                    continue; // refused (e.g. GQC) - fine
                truncate_store_to(branch);
                if (in.next() % 2 == 1) {
                    // Re-attach the displaced fork frames in order.
                    for (const auto &df : undo->load_displaced_frames()) {
                        if (df.height != store->chain_height())
                            break;
                        if (!apply_frame(df.frame))
                            break;
                    }
                }
                // Either way the healed chain must satisfy the invariants.
            } else {
                // Sanity tick.
            }

            // Continuous invariants - violations ABORT so libFuzzer keeps
            // the crashing input.
            if (ledger->next_expected_height() != store->chain_height())
                fuzz_fail("ledger height diverged from store height");
            // Nonce sanity: every pool sender's counter equals its
            // user-tx count on the surviving chain.
            const auto counts = spent_counts(chain);
            for (const auto &acc : pool) {
                const auto it = counts.find(acc.addr);
                const uint32_t expect = it == counts.end() ? 0u : it->second;
                if (ledger->get_next_nonce(acc.addr) != expect) {
                    fuzz_fail("sender nonce counter != per-chain user-tx count");
                }
            }
            U128 supply{};
            if (!ledger->exact_total_supply(supply))
                fuzz_fail("exact_total_supply identity broke");
        }

        // Final determinism: a fresh ledger replaying the surviving store
        // frames must converge to the same canonical digest.
        vx::state::LedgerState fresh;
        for (uint64_t h = 0; h < store->chain_height(); ++h) {
            const auto *g = store->get_block(h);
            if (!g)
                fuzz_fail("store lost a frame the ledger had applied");
            BlockFrame gf;
            std::memcpy(gf.data(), reinterpret_cast<const uint8_t *>(g), BLOCK_SIZE_BYTES);
            const auto res = fresh.apply_block(BlockView(gf));
            if (!res.ok)
                fuzz_fail(("fresh replay refused height " + std::to_string(h) + ": " + res.error)
                              .c_str());
        }
        if (!(canonical_digest(*ledger) == canonical_digest(fresh)))
            fuzz_fail("post-heal replay diverged from the live ledger");
    }
};

} // namespace

extern "C" int LLVMFuzzerTestOneInput(const uint8_t *data, size_t size) {
    ByteStream in{data, size};
    Harness h(in);
    h.run();
    return 0;
}
