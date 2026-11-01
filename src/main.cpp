#include "vx/core/types.hpp"
#include "vx/core/secure_memory.hpp"
#include "vx/core/u128.hpp"
#include "vx/math/galois_attractor.hpp"
#include "vx/math/tdi_filter.hpp"
#include "vx/wif/wif_matrix.hpp"
#include "vx/blockchain/block.hpp"
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

RPC endpoints (once serving): /api/status, /api/crypto/lab,
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

    std::string seed2 =
        "e76a1d401b5c3b803d9e909a1c7d7b5893f89e991160bfea87d56b9292a9eca5"
        "a3656ecc660111b16d81d181f69f307b864a76d5411051863d74c41f1c9b8d60"
        "dd667f204e057ede165edc4dfdfd3ad5d31330f35667412f0a6ff87b16d55256"
        "0a500902dda48ed0d69b37f28d4f9601a5f10b28ea08510137ccfe6a6b4c96d2"
        "e99756a88b7b8b2d19253166515de608fb5c75fc44e016aa1b93b2d3fae46985"
        "fcbc581bebc4292ec095a0a2d7867a14f0554636a3176bcd2e1aa0cb7cdf5490"
        "7f87113a69b32bfd4e3ab74897dc1af388e09bd6e1dfbd83b1ba63b514fc28b8"
        "2ac7fcf56593a9078dfec7a09b53ca5db9239cdd03ab9aa1b38d2d721ce5f195";

    std::string seed3 =
        "aa0e37b14c1157a6cfeea4036e82f03958b6be4754e88d7c4817c98933cbb5eb"
        "39f34b1493cbad810a7275f9f2a3cc36069c725ad8e20b8e031c00faa6e58984"
        "34cac3a2ab04af9acce52a3e0ee119f78ac2aaf0229955b441296b1bf225e30b"
        "b32bbe6904952ea8e99a38ec07aeda17a5a203aae0a7f0b56e9946fe28f8ccc7"
        "21f6104d749ec1c2f55a8851215942d611d952153fb0e1b2e04e93a89aafc423"
        "2f2971ea1d90abe00e5b86b61561a8adbcb0b6909f4686c033cd7fd73c3eb085"
        "3131f6c100c7d1820ec87bb05ff14b10058ca58df5ed05fb927ce3af5adc23f6"
        "1fae0a4a6065aae3d0e56ec008860385b12423b5938c31d84c5399131b6273aa";

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
        vx::blockchain::sign_transaction(tx2);
    }
    builder.add_transaction(tx2);

    builder.finalize();

    auto frame_span = builder.bytes();
    vx::blockchain::BlockFrame frame;
    std::memcpy(frame.data(), frame_span.data(), 65536);

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
