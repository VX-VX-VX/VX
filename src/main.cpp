#include "vx/core/types.hpp"
#include "vx/core/secure_memory.hpp"
#include "vx/core/u128.hpp"
#include "vx/math/galois_attractor.hpp"
#include "vx/math/tdi_filter.hpp"
#include "vx/wif/wif_matrix.hpp"
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/storage/block_store.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/rpc/http_server.hpp"
#include <cstring>
#include <filesystem>
#include <iostream>
#include <iomanip>
#include <chrono>
#include <ctime>
#include <csignal>
#include <cstdlib>
#include <string>
#include <vector>

namespace {

void print_usage() {
    std::cout << R"(VX node — Vortex Sovereign OS (VX L1), experimental

Usage:
  vx_node [options] [rounds]

Options:
  --serve [PORT]     Run the node and serve the JSON RPC API
                     (optional inline port; default 8088)
  --port PORT        HTTP/RPC port (default 8088)
  --p2p PORT         VX60 P2P wire protocol port (default 19088)
  --peer HOST:PORT   Connect to a peer at startup (repeatable)
  --data-dir DIR     Directory for chain data (default ./data)
  --demo             Run the scripted demo: mine the secondary genesis
                     mint (100 000 VX) and a 25 000 VX transfer between
                     the two demo attractor addresses, then print the
                     ledger audit. Off by default — a node never mines
                     demo blocks on its own.
  -h, --help         Show this help and exit
  -V, --version      Print version information and exit

  rounds             Attractor rounds shown on the engine banner
                     (default 1000)

Without options the node opens (or derives) the chain, replays the
ledger and prints the audit — it does not mine or transfer anything.

Examples:
  vx_node --serve 8088 --port 8088 --data-dir ./data
  vx_node --serve --p2p 19089 --peer 127.0.0.1:19088
  vx_node --demo

RPC endpoints (once serving): /api/status, /api/transfer,
/api/mempool/submit, /api/mempool/seal, /api/crypto/lab,
/api/crypto/pq_sign, /api/crypto/pq_verify, /api/security/audit,
/api/crypto/canonical.
)" << "\n";
}

void print_version() {
    std::cout << "VX node v0.0.1-alpha (Vortex Sovereign OS / VX L1)\n"
              << "C++26, 3-Trunk Vortex Attractor, WOTS+/XMSS post-quantum layer\n";
}

// Scripted demo: secondary genesis mint (100 000 VX) plus a 25 000 VX
// transfer between the two demo attractor addresses. Runs only when the
// operator passes --demo; a node never mines demo blocks on its own.
void run_demo_script(vx::storage::BlockStore& store,
                     vx::state::LedgerState& state,
                     const vx::blockchain::Address& gen1_addr) {
    // ── 1. Derive Coordinates & Addresses for Seed #2 and Seed #3 ────────────
    std::cout << "[DEMO] Computing 1000-round Attractor for Seed #2 and Seed #3...\n";

    // Canonical demo seeds are protocol constants (genesis.hpp): the demo
    // spender address is bound to the public demo PQ key on EVERY node, so
    // the demo exercises the real authorization path.
    std::string seed2 = vx::blockchain::demo_spender_seed_hex();
    std::string seed3 = vx::blockchain::demo_receiver_seed_hex();

    auto res2 = vx::math::VortexAttractor::run(seed2, 1000, true);
    auto res3 = vx::math::VortexAttractor::run(seed3, 1000, true);

    std::cout << "      ✓ Address #2 (Genesis Sender):   " << res2.addressNFA << "\n";
    std::cout << "      ✓ Address #3 (Transfer Target): " << res3.addressNFA << "\n\n";

    // Extract 42-byte raw payload without "NFA_V6_" prefix (skip first 7 chars)
    vx::blockchain::Address addr2_payload{}, addr3_payload{};
    std::memcpy(addr2_payload.data(), res2.addressNFA.data() + 7, 42);
    std::memcpy(addr3_payload.data(), res3.addressNFA.data() + 7, 42);

    // ── 2. Mine New Block: Tx1 (Mint to Addr #2) + Tx2 (Transfer #2 → #3) ────
    uint64_t next_h = store.chain_height();
    std::cout << "[DEMO] Assembling and Mining Block #" << next_h << "...\n";

    vx::blockchain::BlockBuilder builder;
    builder.set_height(next_h);
    builder.set_timestamp(static_cast<uint64_t>(std::time(nullptr)));

    uint8_t tip[32];
    store.tip_hash(tip);
    builder.set_prev_hash(tip);

    // Set attractor coordinates from res2
    auto to_le128 = [](const mpz_class& v, uint8_t out[128]) {
        std::memset(out, 0, 128);
        mpz_class temp = v;
        mpz_class m = 255;
        for (int i = 0; i < 128; ++i) {
            out[i] = static_cast<uint8_t>(mpz_class(temp & m).get_ui());
            temp >>= 8;
        }
    };
    uint8_t coords[384];
    to_le128(res2.finalX, coords);
    to_le128(res2.finalY, coords + 128);
    to_le128(res2.finalZ, coords + 256);
    builder.set_attractor_coords(coords);

    // Determine whether Genesis #2 has been minted already.
    // Check if address has ever appeared in state (even with 0 balance now).
    bool gen2_already_minted = state.tracked_addresses_containing(addr2_payload);

    // Tx 1 (conditional): Secondary Genesis Minting (100,000 VX to Address #2),
    // ONLY if this is the very first time Address #2 appears in the chain.
    if (!gen2_already_minted) {
        vx::blockchain::Transaction tx1{};
        const char* tag = "GENESIS_2";
        std::memcpy(tx1.sender_nfa, tag, 9);
        for (size_t i = 9; i < 42; ++i) tx1.sender_nfa[i] = '0';
        std::memcpy(tx1.receiver_nfa, addr2_payload.data(), 42);

        uint64_t amt1 = 100'000ULL * 100'000'000ULL; // 100k VX
        std::memcpy(tx1.amount, &amt1, 8);
        vx::blockchain::sign_transaction(tx1);
        builder.add_transaction(tx1);
        std::cout << "      ✓ Tx1 included: GENESIS_2 → Address #2 (100,000 VX mint)\n";
    }

    // Tx 2 (always): User Transfer (25,000 VX from Address #2 → Address #3)
    vx::blockchain::Transaction tx2{};
    {
        std::memcpy(tx2.sender_nfa, addr2_payload.data(), 42);
        std::memcpy(tx2.receiver_nfa, addr3_payload.data(), 42);

        uint64_t amt2 = 25'000ULL * 100'000'000ULL; // 25k VX
        std::memcpy(tx2.amount, &amt2, 8);
        // PQ authorization (BACKLOG 0.7): Address #2 is bound to the public
        // demo spender key on every node; the transfer carries a real
        // WOTS+/XMSS witness instead of the keyless digest.
        vx::blockchain::tx_set_fee(tx2, 100);
        vx::blockchain::tx_set_nonce(tx2, state.get_next_nonce(addr2_payload));
        std::array<uint8_t, 32> demo_sk{};
        vx::blockchain::VortexSponge256::compute(
            reinterpret_cast<const uint8_t*>("VX_DEMO_SPENDER_SK_V1"), 21, demo_sk.data());
        vx::crypto::pq::PqSignatureWitness demo_witness{};
        if (!vx::crypto::pq::pq_sign_transaction(tx2, demo_sk, nullptr, nullptr, &demo_witness)) {
            throw std::runtime_error("demo: PQ signing failed (no free leaf)");
        }
        // BACKLOG 2.11: the demo block's header commits its witness set -
        // tx2 is the only user transaction here.
        builder.add_witness_binding(builder.tx_count(), tx2.sender_nfa,
                                    demo_witness.pq_pubkey_root.data());
    }
    builder.add_transaction(tx2);

    builder.finalize();

    auto frame_span = builder.bytes();
    vx::blockchain::BlockFrame frame;
    std::memcpy(frame.data(), frame_span.data(), 65536);

    // BACKLOG 0.9: the intake gate enforces real PoGW work, so the demo seals
    // its frame like every other producer (dev-mode difficulty, ~seconds).
    if (!vx::blockchain::seal_pogw_nonce(frame, store.required_pogw_bits())) {
        throw std::runtime_error("PoGW seal failed: no nonce met the difficulty");
    }

    bool appended = store.append_block(frame);
    std::cout << "      append_block(#" << next_h << ") → " << (appended ? "OK ✓" : "FAILED ✗") << "\n";
    if (!appended) throw std::runtime_error("BlockStore rejected Block #" + std::to_string(next_h));

    // ── 3. Apply the new block to LedgerState ─────────────────────────────────
    std::cout << "\n[DEMO] Applying Block #" << next_h << " to LedgerState...\n";
    auto* new_raw = store.get_block(next_h);
    vx::blockchain::BlockView newv{std::span<const uint8_t, 65536>(
        reinterpret_cast<const uint8_t*>(new_raw), 65536)};
    auto apply_res = state.apply_block(newv);
    if (!apply_res.ok) {
        throw std::runtime_error("Failed to apply Block #" + std::to_string(next_h) + ": " + apply_res.error);
    }
    std::cout << "      ✓ Block #" << next_h << " applied successfully: " << apply_res.transfers << " transfer(s)\n\n";

    // ── 4. Ledger State Audit Summary ──────────────────────────────────────────
    std::cout << "=================== LEDGER STATE AUDIT ===================\n";
    std::cout << "  Genesis #1 Balance:                   "
              << state.balance_of(gen1_addr).to_string() << " atomics\n";

    std::cout << "  Genesis #2 Balance:                   "
              << state.balance_of(addr2_payload).to_string() << " atomics\n";

    std::cout << "  Address #3 Balance:                   "
              << state.balance_of(addr3_payload).to_string() << " atomics\n";

    std::cout << "  -----------------------------------------------------\n";
    std::cout << "  Total Circulating Supply:             "
              << state.total_supply().to_string() << " atomics\n";
    std::cout << "  Live Chain Height:                    "
              << store.chain_height() << " blocks (tip = #" << (store.chain_height() - 1) << ")\n";
    std::cout << "===========================================================\n\n";
}

} // namespace

int main(int argc, char* argv[]) {
    bool serve_mode = false;
    bool demo_mode = false;
    uint16_t port = 8088;       // HTTP/RPC port (never 8080)
    uint16_t p2p_port = 19088;  // VX60 P2P wire port
    std::vector<std::string> peer_endpoints; // --peer host:port
    std::string data_dir = "data";
    uint32_t iterations = 1000;

    for (int i = 1; i < argc; ++i) {
        std::string arg = argv[i];
        if (arg == "-h" || arg == "--help") {
            print_usage();
            return 0;
        } else if (arg == "-V" || arg == "--version") {
            print_version();
            return 0;
        } else if (arg == "--serve") {
            serve_mode = true;
            if (i + 1 < argc && argv[i + 1][0] != '-') {
                port = static_cast<uint16_t>(std::stoul(argv[++i]));
            }
        } else if (arg == "--port") {
            if (i + 1 < argc) port = static_cast<uint16_t>(std::stoul(argv[++i]));
        } else if (arg == "--p2p") {
            if (i + 1 < argc) p2p_port = static_cast<uint16_t>(std::stoul(argv[++i]));
        } else if (arg == "--peer") {
            if (i + 1 < argc) peer_endpoints.emplace_back(argv[++i]);
        } else if (arg == "--data-dir") {
            if (i + 1 < argc) data_dir = argv[++i];
        } else if (arg == "--demo") {
            demo_mode = true;
        } else if (!arg.empty() && arg[0] == '-') {
            std::cerr << "vx_node: unknown option '" << arg << "'\n"
                      << "Run 'vx_node --help' for usage.\n";
            return 1;
        } else {
            try {
                iterations = static_cast<uint32_t>(std::stoul(arg));
            } catch (const std::exception&) {
                std::cerr << "vx_node: invalid argument '" << arg << "'\n"
                          << "Run 'vx_node --help' for usage.\n";
                return 1;
            }
        }
    }

    std::cout << R"(
    ██╗   ██╗██████╗ ██████╗ ████████╗███████╗██╗  ██╗
    ██║   ██║██╔══██╗██╔══██╗╚══██╔══╝██╔════╝╚██╗██╔╝
    ██║   ██║██║  ██║██████╔╝   ██║   █████╗   ╚███╔╝
    ╚██╗ ██╔╝██║  ██║██╔══██╗   ██║   ██╔══╝   ██╔██╗
     ╚████╔╝ ██████╔╝██║  ██║   ██║   ███████╗██╔╝ ██╗
      ╚═══╝  ╚═════╝ ╚═╝  ╚═╝   ╚═╝   ╚══════╝╚═╝  ╚═╝
         VORTEX CRYPTOGRAPHIC CORE ENGINE (C++26)
    )" << "\n";

    std::cout << "Compiler:  GCC " << __GNUC__ << "." << __GNUC_MINOR__ << "." << __GNUC_PATCHLEVEL__
              << " | Standard: C++26 (__cplusplus = " << __cplusplus << ")\n";
    std::cout << "Precision: 1024-bit Galois Fields (3-Trunk Attractor with GMP)\n";
    std::cout << "Iterations to compute: " << iterations << " rounds\n";
    std::cout << "--------------------------------------------------------\n\n";

    // ── 1. BlockStore (auto-derives genesis.bin → ledger.vxb on first run) ────
    std::error_code fs_ec;
    std::filesystem::create_directories(data_dir, fs_ec);
    std::string ledger_path  = (std::filesystem::path(data_dir) / "ledger.vxb").string();
    std::string genesis_path = (std::filesystem::path(data_dir) / "genesis.bin").string();

    std::cout << "[NODE] Opening " << ledger_path << " (auto-init from genesis.bin if empty)...\n";
    vx::storage::BlockStore store(ledger_path, genesis_path);
    // BACKLOG 0.8: durable PQ witness sidecar — every witnessed transaction
    // is fsync'd beside the ledger and replayed on restart.
    vx::crypto::pq::PqWitnessRegistry::instance().attach_durable_log(ledger_path + ".pqw");
    // Rollover certs (v0.0.18): replay the durable cert sidecar too.
    vx::crypto::pq::PqWitnessRegistry::instance().attach_durable_cert_log(ledger_path + ".pqr");
    uint64_t current_height = store.chain_height();
    std::cout << "      ✓ Chain height: " << current_height << " blocks (tip = #" << (current_height - 1) << ")\n\n";

    // ── 2. Replay all existing blocks into LedgerState ────────────────────────
    std::cout << "[NODE] Replaying " << current_height << " block(s) into LedgerState...\n";
    vx::state::LedgerState state;
    for (uint64_t h = 0; h < current_height; ++h) {
        auto* raw = store.get_block(h);
        if (!raw) throw std::runtime_error("BlockStore: missing block #" + std::to_string(h));
        vx::blockchain::BlockView v{std::span<const uint8_t, 65536>(
            reinterpret_cast<const uint8_t*>(raw), 65536)};
        auto r = state.apply_block(v);
        if (!r.ok) throw std::runtime_error("LedgerState apply failed on block #" +
                                             std::to_string(h) + ": " + r.error);
    }

    // Genesis #1 address & balance
    auto* genesis_raw = store.get_block(0);
    vx::blockchain::BlockView gv{std::span<const uint8_t, 65536>(
        reinterpret_cast<const uint8_t*>(genesis_raw), 65536)};
    vx::blockchain::Address gen1_addr = vx::blockchain::tx_address(gv.tx(0).receiver_nfa);

    std::cout << "      ✓ Genesis #1 address: " << vx::state::LedgerState::address_label(gen1_addr) << "\n";
    std::cout << "      ✓ Genesis #1 balance: " << state.balance_of(gen1_addr).to_string() << " atomics (2.54M VX)\n";
    std::cout << "      ✓ Total supply:       " << state.total_supply().to_string() << " atomics\n\n";

    // ── 3. Demo script (optional) — mint + transfer between demo addresses ────
    if (demo_mode) {
        run_demo_script(store, state, gen1_addr);
    } else {
        std::cout << "[NODE] Demo script skipped (pass --demo to run it).\n\n";
    }

    std::cout << "Core execution completed successfully.\n";

    if (serve_mode) {
        // Security review 2026-11-08 (P1): the tree never disposed SIGPIPE
        // (only SIGINT was handled), so any send/write on a peer-reset
        // socket outside the MSG_NOSIGNAL sites - the sendfile block relay,
        // any future flag-less send - had the default action: the whole
        // node process dies, remotely triggerable. Ignore the signal
        // process-wide; every write path already treats EPIPE as an error
        // return, which is the correct per-connection behavior.
        ::std::signal(SIGPIPE, SIG_IGN);
        std::cout << "[NODE] Starting POSIX HTTP/JSON RPC server on port " << port << "...\n";
        std::cout << "[NODE] VX60 P2P wire port: " << p2p_port
                  << " | data-dir: " << data_dir
                  << " | peers: " << peer_endpoints.size() << "\n";
        vx::rpc::HttpServer server(store, state, port, data_dir);
        server.attach_p2p(p2p_port, peer_endpoints);
        std::signal(SIGINT, [](int) { std::exit(0); });
        server.start();
        return 0;
    }

    return 0;
}
