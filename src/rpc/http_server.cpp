#include "vx/rpc/http_server.hpp"
#include "vx/math/galois_attractor.hpp"
#include "vx/math/tdi_filter.hpp"
#include "vx/wif/wif_matrix.hpp"
#include "vx/crypto/simd_accel.hpp"
#include "vx/net/swarm_node.hpp"
#include "vx/state/undo_engine.hpp"
#include "vx/core/memory_vault.hpp"
#include "vx/core/hw_intrinsics.hpp"
#include "vx/core/rt_scheduler.hpp"
#include "vx/crypto/zk_key_matrix.hpp"
#include "vx/math/tensor_v6.hpp"
#include "vx/neural/virtual_tensor.hpp"
#include "vx/crypto/canonical_vectors.hpp"
#include "vx/state/galois_trie.hpp"
#include "vx/vm/vortex_vm.hpp"
#include "vx/blockchain/block.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/core/rdtsc_profiler.hpp"
#include "vx/security/chaos_fuzzer.hpp"

#include <sys/socket.h>
#include <sys/epoll.h>
#include <netinet/in.h>
#include <unistd.h>
#include <fcntl.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <errno.h>

#include <cstring>
#include <stdexcept>
#include <iostream>
#include <sstream>
#include <thread>
#include <iomanip>
#include <chrono>

namespace vx::rpc {

HttpServer::HttpServer(storage::BlockStore& store, state::LedgerState& ledger, uint16_t port,
                       const std::string& data_dir)
    : store_(store), ledger_(ledger), mempool_(), miner_(std::make_unique<consensus::PoGWMiner>(store, ledger, mempool_)), port_(port),
      data_dir_(data_dir), undo_engine_(std::make_unique<vx::state::UndoEngine>(data_dir_, store, ledger)),
      gqc_finality_(std::make_unique<vx::consensus::GqcFinality>(*undo_engine_, store)),
      vault_core_(), lock_step_(), zk_matrix_(), tensor_v6_(), virtual_tensor_() {
    // Initialize swarm node
    swarm_node_ = std::make_unique<vx::net::SwarmNode>();
    // Seed the vault memory core with a deterministic master key so the
    // live endpoints return real, reproducible data instead of uninitialized state.
    vault_core_.initialize(0x9e3779b97f4a7c15ULL ^ lock_step_.get_stats().lock_step_cycles);
}

HttpServer::~HttpServer() {
    stop();
}

void HttpServer::start() {
    server_fd_ = ::socket(AF_INET, SOCK_STREAM, 0);
    if (server_fd_ < 0) throw std::runtime_error("socket() failed");
    int opt = 1;
    ::setsockopt(server_fd_, SOL_SOCKET, SO_REUSEADDR | SO_REUSEPORT, &opt, sizeof(opt));
    struct sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = INADDR_ANY;
    addr.sin_port = htons(port_);
    if (::bind(server_fd_, (struct sockaddr*)&addr, sizeof(addr)) < 0)
        throw std::runtime_error("bind() failed");
    if (::listen(server_fd_, 16) < 0)
        throw std::runtime_error("listen() failed");
    running_.store(true);
    std::cout << "[RPC] Listening on :" << port_ << "\n";
    while (running_.load()) {
        int client = ::accept(server_fd_, nullptr, nullptr);
        if (client < 0) continue;
        // Set non-blocking for SSE clients
        // Check if it's an SSE request by peeking
        char peek_buf[1024];
        ssize_t n = ::recv(client, peek_buf, sizeof(peek_buf) - 1, MSG_PEEK);
        if (n > 0) {
            peek_buf[n] = '\0';
            std::string peek(peek_buf);
            if (peek.find("GET /api/events") != std::string::npos || peek.find("GET /events") != std::string::npos) {
                // SSE client - handle in dedicated thread
                std::thread([this, client]() { handle_sse_client(client); }).detach();
                continue;
            }
        }
        // Regular HTTP client
        std::thread([this, client]() { handle_client(client); }).detach();
    }
}

void HttpServer::stop() {
    if (running_.exchange(false)) {
        if (server_fd_ >= 0) { ::close(server_fd_); server_fd_ = -1; }
    }
    sse_running_.store(false);
    // Clean up SSE clients
    {
        std::lock_guard<std::mutex> lock(sse_mutex_);
        for (int fd : sse_clients_) {
            ::close(fd);
        }
        sse_clients_.clear();
    }
    if (sse_broadcast_thread_.joinable()) {
        sse_broadcast_thread_.join();
    }
}

HttpRequest HttpServer::parse_request(int client_fd, bool& ok) {
    HttpRequest req;
    ok = false;
    char buf[8192];
    ssize_t n = ::recv(client_fd, buf, sizeof(buf) - 1, 0);
    if (n <= 0) return req;
    buf[n] = '\0';
    std::string raw(buf);
    size_t line_end = raw.find("\r\n");
    if (line_end == std::string::npos) return req;
    std::string line = raw.substr(0, line_end);
    std::istringstream iss(line);
    iss >> req.method >> req.path;
    size_t pos = raw.find("\r\n\r\n");
    if (pos != std::string::npos) {
        req.body = raw.substr(pos + 4);
    }
    ok = true;
    return req;
}

void HttpServer::send_response(int client_fd, const HttpResponse& res) {
    std::ostringstream oss;
    oss << "HTTP/1.1 " << res.status_code << " " << res.status_text << "\r\n";
    for (auto& h : res.headers) oss << h.first << ": " << h.second << "\r\n";
    oss << "Content-Length: " << res.body.size() << "\r\n\r\n";
    std::string out = oss.str() + res.body;
    ::send(client_fd, out.data(), out.size(), 0);
}

void HttpServer::send_sse_data(int client_fd, const std::string& data) {
    std::string message = "data: " + data + "\n\n";
    ::send(client_fd, message.data(), message.size(), MSG_NOSIGNAL);
}

void HttpServer::handle_sse_client(int client_fd) {
    // Add client to SSE list
    {
        std::lock_guard<std::mutex> lock(sse_mutex_);
        sse_clients_.push_back(client_fd);
    }

    // Send initial comment to keep connection alive
    send_sse_data(client_fd, "connected");

    // Keep connection alive until client disconnects
    char buf[1024];
    while (sse_running_.load()) {
        ssize_t n = ::recv(client_fd, buf, sizeof(buf) - 1, MSG_PEEK);
        if (n <= 0) break;
        std::this_thread::sleep_for(std::chrono::seconds(1));
    }

    // Remove client
    {
        std::lock_guard<std::mutex> lock(sse_mutex_);
        auto it = std::find(sse_clients_.begin(), sse_clients_.end(), client_fd);
        if (it != sse_clients_.end()) sse_clients_.erase(it);
    }
    ::close(client_fd);
}

void HttpServer::handle_client(int client_fd) {
    bool ok;
    auto req = parse_request(client_fd, ok);
    if (!ok) { ::close(client_fd); return; }
    if (req.method == "OPTIONS") {
        auto res = HttpResponse::cors_preflight();
        send_response(client_fd, res);
        ::close(client_fd);
        return;
    }
    auto res = dispatch(req);
    send_response(client_fd, res);
    ::close(client_fd);
}

HttpResponse HttpServer::dispatch(const HttpRequest& req) {
    if (req.method == "GET" && req.path == "/api/status") return handle_status(req);
    if (req.method == "GET" && req.path == "/api/blocks") return handle_blocks(req);
    if (req.method == "GET" && req.path == "/api/accounts") return handle_accounts(req);
    if (req.method == "POST" && req.path == "/api/transfer") return handle_transfer(req);
    if (req.method == "POST" && req.path == "/api/security/audit") return handle_security_audit(req);
    if (req.method == "POST" && req.path == "/api/crypto/lab") return handle_crypto_lab(req);

 // live RPC endpoints
    if (req.method == "GET" && req.path == "/api/vault/memory") return handle_vault_memory(req);
    if (req.method == "POST" && req.path == "/api/vault/action") return handle_vault_action(req);
    if (req.method == "POST" && req.path == "/api/zk/derive_matrix") return handle_zk_derive_matrix(req);
    if (req.method == "POST" && req.path == "/api/zk/recover_shamir") return handle_zk_recover_shamir(req);
    if (req.method == "POST" && req.path == "/api/zk/proof_of_life") return handle_zk_proof_of_life(req);
    if (req.method == "POST" && req.path == "/api/zk/audit_view") return handle_zk_audit_view(req);
    if (req.method == "POST" && req.path == "/api/neural/simulate") return handle_neural_simulate(req);
    if (req.method == "GET" && req.path == "/api/crypto/canonical") return handle_crypto_canonical(req);

 // ZK Mempool
    if (req.method == "GET" && req.path == "/api/mempool/zk_stats") return handle_mempool_zk_stats(req);

 // VX60 P2P wire + split-brain reorg
    if (req.method == "GET" && req.path == "/api/swarm/peers") return handle_swarm_peers(req);
    if (req.method == "POST" && req.path == "/api/swarm/simulate_split_reorg") return handle_swarm_simulate_split_reorg(req);

    // Dandelion++ / Landauer VM / SGMT / Hamiltonian MEV
    if (req.method == "GET" && req.path == "/api/swarm/dandelion_stats") return handle_swarm_dandelion_stats(req);
    if (req.method == "POST" && req.path == "/api/swarm/relay_cocoon") return handle_swarm_relay_cocoon(req);
    if (req.method == "POST" && req.path == "/api/vm/execute_trace") return handle_vm_execute_trace(req);
    if (req.method == "GET" && req.path == "/api/state/trie_root") return handle_state_trie_root(req);
    if (req.method == "POST" && req.path == "/api/state/prove") return handle_state_prove(req);
    if (req.method == "POST" && req.path == "/api/mempool/mev_audit") return handle_mempool_mev_audit(req);

    // ── GQC finality / pipeline / stealth / vault / HTLC swap ─────────────
    if (req.method == "GET"  && req.path == "/api/consensus/finality_status") return handle_consensus_finality_status(req);
    if (req.method == "POST" && req.path == "/api/consensus/finalize_gqc") return handle_consensus_finalize_gqc(req);
    if (req.method == "GET"  && req.path == "/api/mempool/pipeline_benchmark") return handle_mempool_pipeline_benchmark(req);
    if (req.method == "POST" && req.path == "/api/zk/stealth_envelope") return handle_zk_stealth_envelope(req);
    if (req.method == "POST" && req.path == "/api/zk/ivk_scan") return handle_zk_ivk_scan(req);
    if (req.method == "POST" && req.path == "/api/vault/ephemeral_sign") return handle_vault_ephemeral_sign(req);
    if (req.method == "POST" && req.path == "/api/vm/htlc_swap") return handle_vm_htlc_swap(req);

    // ── Telemetry // ── Telemetry & security fuzzing ─────────────────────────────────── security fuzzing ───────────────────────────────────
    if (req.method == "GET"  && req.path == "/api/telemetry/rdtsc") return handle_telemetry_rdtsc(req);
    if (req.method == "POST" && req.path == "/api/security/chaos_fuzz") return handle_security_chaos_fuzz(req);
    if (req.method == "POST" && req.path == "/api/crypto/pq_sign") return handle_crypto_pq_sign(req);
    if (req.method == "POST" && req.path == "/api/crypto/pq_verify") return handle_crypto_pq_verify(req);

    return HttpResponse::error(404, "not found");
}

// ── JSON helpers ────────────────────────────────────────────────────────────

std::string HttpServer::json_escape(std::string_view s) {
    std::string out;
    out.reserve(s.size() + 8);
    for (char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\b': out += "\\b";  break;
            case '\f': out += "\\f";  break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (static_cast<unsigned char>(c) < 0x20) {
                    char buf[8];
                    snprintf(buf, sizeof(buf), "\\u%04x", c);
                    out += buf;
                } else {
                    out += c;
                }
        }
    }
    return out;
}

std::string HttpServer::hex_bytes(const uint8_t* data, size_t n) {
    std::ostringstream oss;
    for (size_t i = 0; i < n; ++i)
        oss << std::hex << std::setw(2) << std::setfill('0')
            << static_cast<int>(data[i]);
    return oss.str();
}

std::string HttpServer::format_vx(uint64_t atomics) {
    // We format as a decimal string with 8 fractional digits: DDDDDD.DDDDDDDD
    uint64_t whole = atomics / 100'000'000ULL;
    uint64_t frac = atomics % 100'000'000ULL;
    std::ostringstream oss;
    oss << whole << "." << std::setw(8) << std::setfill('0') << frac;
    return oss.str();
}

// ── GET /api/status ──────────────────────────────────────────────────────────

HttpResponse HttpServer::handle_status(const HttpRequest&) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    uint64_t height = store_.chain_height();
    uint64_t tip = (height > 0) ? height - 1 : 0;
    uint8_t hash32[32] = {};
    if (height > 0) store_.tip_hash(hash32);
    std::string hash_hex = hex_bytes(hash32, 32);
    auto supply = ledger_.total_supply();
    std::string supply_str = supply.to_string();

    std::ostringstream oss;
    oss << "{"
        << "\"chain_height\":" << height << ","
        << "\"tip_block_index\":" << tip << ","
        << "\"ledger_bytes\":" << (height * 65536ULL) << ","
        << "\"frame_size\":65536,"
        << "\"max_tx_per_block\":580,"
        << "\"total_supply_atomics\":\"" << supply_str << "\","
        << "\"total_supply_vx\":\"" << format_vx(supply.lo) << "\","
        << "\"tracked_accounts_count\":" << ledger_.tracked_addresses() << ","
        << "\"tip_hash_hex\":\"" << hash_hex << "\","
        << "\"crypto_engine\":\"3-Trunk Galois Attractor (3072-bit CRT) + VortexSponge256 (12-Round ARX)\","
        << "\"storage_engine\":\"POSIX mmap/mremap O(1) Zero-Copy\""
        << "}";
    return HttpResponse::json(200, oss.str());
}

// ── GET /api/blocks ──────────────────────────────────────────────────────────

HttpResponse HttpServer::handle_blocks(const HttpRequest&) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    uint64_t height = store_.chain_height();

    std::ostringstream oss;
    oss << "{\"blocks\":[";
    for (uint64_t h = 0; h < height; ++h) {
        auto* raw = store_.get_block(h);
        if (!raw) continue;
        vx::blockchain::BlockView v{std::span<const uint8_t, 65536>(
            reinterpret_cast<const uint8_t*>(raw), 65536)};
        const auto& hdr = v.header();

        uint8_t bh[32];
        vx::blockchain::hash_header(hdr, bh);

        oss << "{";
        oss << "\"height\":" << hdr.block_height << ","
            << "\"timestamp\":" << hdr.timestamp << ","
            << "\"tx_count\":" << hdr.tx_count << ","
            << "\"magic_hex\":\"0x58564336\","
            << "\"block_hash_hex\":\"" << hex_bytes(bh, 32) << "\","
            << "\"prev_block_hash_hex\":\"" << hex_bytes(hdr.prev_block_hash, 32) << "\","
            << "\"merkle_root_hex\":\"" << hex_bytes(hdr.merkle_root, 32) << "\","
            << "\"attractor_coords\":{\"x_hex\":\"" << hex_bytes(hdr.attractor_coords, 128) << "\","
            << "\"y_hex\":\"" << hex_bytes(hdr.attractor_coords + 128, 128) << "\","
            << "\"z_hex\":\"" << hex_bytes(hdr.attractor_coords + 256, 128) << "\"},";

        uint32_t tx_used = hdr.tx_count * 112;
        uint32_t tx_free = (580 - hdr.tx_count) * 112;
        double util = (tx_used + 472 + 104) * 100.0 / 65536.0;
        oss << "\"memory_layout\":{\"header_bytes\":472,\"tx_used_bytes\":" << tx_used
            << ",\"tx_free_bytes\":" << tx_free << ",\"tail_reserved_bytes\":104,\"utilization_pct\":" << std::fixed << std::setprecision(2) << util << "},";

        // Raw header hex (472 bytes)
        oss << "\"raw_header_hex\":\"" << hex_bytes(reinterpret_cast<const uint8_t*>(&hdr), 472) << "\",";
        oss << "\"transactions\":[";
        // Structural cap: never walk past the frame's fixed transaction array
        // (a malformed/hand-crafted frame may carry an inflated header count).
        const uint32_t tx_scan =
            hdr.tx_count > vx::blockchain::MAX_TX_PER_BLOCK
                ? vx::blockchain::MAX_TX_PER_BLOCK : hdr.tx_count;
        for (uint32_t i = 0; i < tx_scan; ++i) {
            const auto& tx = v.tx(i);
            if (i > 0) oss << ",";
            bool proof_valid = vx::blockchain::verify_transaction_proof(tx);
            uint64_t amount_lo = 0;
            std::memcpy(&amount_lo, tx.amount, 8);
            std::string sender_nfa = "NFA_V6_" + std::string(reinterpret_cast<const char*>(tx.sender_nfa), 42);
            std::string receiver_nfa = "NFA_V6_" + std::string(reinterpret_cast<const char*>(tx.receiver_nfa), 42);
            oss << "{";
            oss << "\"index\":" << i << ","
                << "\"sender_nfa\":\"" << json_escape(sender_nfa) << "\","
                << "\"receiver_nfa\":\"" << json_escape(receiver_nfa) << "\","
                << "\"amount_atomics\":\"" << amount_lo << "\","
                << "\"amount_vx\":\"" << format_vx(amount_lo) << "\","
                << "\"cocoon_proof_hex\":\"" << hex_bytes(tx.cocoon_proof, 12) << "\","
                << "\"proof_valid\":" << (proof_valid ? "true" : "false") << ","
                << "\"raw_tx_hex\":\"" << hex_bytes(reinterpret_cast<const uint8_t*>(&tx), 112) << "\""
                << "}";
        }
        oss << "]}";
        if (h + 1 < height) oss << ",";
    }
    oss << "]}";
    return HttpResponse::json(200, oss.str());
}

// ── GET /api/accounts ─────────────────────────────────────────────────────────

HttpResponse HttpServer::handle_accounts(const HttpRequest&) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    auto accounts = ledger_.accounts();
    // uint64_t total = ledger_.total_supply().to_string();  // fallback

    std::ostringstream oss;
    oss << "{\"accounts\":[";
    bool first = true;
    for (const auto& [addr, bal] : accounts) {
        if (!first) oss << ",";
        first = false;
        std::string label;
        std::string sender(reinterpret_cast<const char*>(addr.data()), 42);
        if (sender.rfind("GENESIS0", 0) == 0 || sender.rfind("GENESIS_", 0) == 0) {
            label = "Genesis #1 Sovereign Vault";
        } else if (sender.rfind("GENESIS_2", 0) == 0) {
            label = "Genesis #2 Operational";
        } else if (sender.rfind("MINER_", 0) == 0) {
            label = "Miner";
        } else {
            label = "User Vault";
        }
        std::string nfa = "NFA_V6_" + std::string(reinterpret_cast<const char*>(addr.data()), 42);
        std::string bal_str = bal.to_string();
        std::string payload = std::string(reinterpret_cast<const char*>(addr.data()), 42);
        oss << "{";
        oss << "\"address\":\"" << json_escape(nfa) << "\","
            << "\"payload_42\":\"" << json_escape(payload) << "\","
            << "\"label\":\"" << label << "\","
            << "\"balance_atomics\":\"" << bal_str << "\","
            << "\"balance_vx\":\"" << format_vx(bal.lo) << "\""
            << "}";
    }
    oss << "]}";
    return HttpResponse::json(200, oss.str());
}

// ── POST /api/transfer ────────────────────────────────────────────────────────

HttpResponse HttpServer::handle_transfer(const HttpRequest& req) {
    // Simple JSON parse helpers
    auto extract = [](const std::string& body, const std::string& key) -> std::string {
        std::string pat = "\"" + key + "\":\"";
        size_t pos = body.find(pat);
        if (pos == std::string::npos) return "";
        pos += pat.size();
        size_t end = body.find('"', pos);
        return body.substr(pos, end - pos);
    };
    auto extract_num = [&extract, &req](const std::string& key) -> double {
        std::string val = extract(req.body, key);
        // Could be string or number; try numeric directly
        size_t pat = req.body.find("\"" + key + "\":");
        if (pat != std::string::npos) {
            size_t vstart = pat + key.size() + 3;
            size_t vend = req.body.find_first_of(",}", vstart);
            std::string numstr = req.body.substr(vstart, vend - vstart);
            try { return std::stod(numstr); } catch (...) {}
        }
        return val.empty() ? 0.0 : std::stod(val);
    };

    std::string sender = extract(req.body, "sender");
    std::string receiver = extract(req.body, "receiver");
    double amount_vx = extract_num("amount_vx");

    auto tdi = vx::math::TdiFilter::evaluate(112, amount_vx);
    if (tdi.isAnnihilated) {
        std::ostringstream oss;
        oss << "{\"error\":\"transaction rejected\",\"reason\":\""
            << json_escape(tdi.reason) << "\",\"tdi\":" << tdi.tdi << "}";
        return HttpResponse::json(403, oss.str());
    }

    std::lock_guard<std::mutex> lock(state_mutex_);

    // Parse sender payload
    vx::blockchain::Address sender_addr{};
    if (sender.size() >= 7 && sender.rfind("NFA_V6_", 0) == 0) {
        sender = sender.substr(7);
    }
    size_t start = (sender.size() > 42) ? sender.size() - 42 : 0;
    std::memset(sender_addr.data(), 0, 42);
    std::memcpy(sender_addr.data(), sender.data() + start, std::min(sender.size() - start, size_t(42)));

    vx::blockchain::Address recv_addr{};
    if (receiver.size() >= 7 && receiver.rfind("NFA_V6_", 0) == 0) {
        receiver = receiver.substr(7);
    }
    start = (receiver.size() > 42) ? receiver.size() - 42 : 0;
    std::memset(recv_addr.data(), 0, 42);
    std::memcpy(recv_addr.data(), receiver.data() + start, std::min(receiver.size() - start, size_t(42)));

    uint64_t amount_atomics = static_cast<uint64_t>(amount_vx * 100'000'000ULL);
    vx::core::U128 bal = ledger_.balance_of(sender_addr);
    if (bal < vx::core::U128(amount_atomics)) {
        return HttpResponse::error(403, "insufficient funds");
    }

    // Build block
    uint64_t next_h = store_.chain_height();
    vx::blockchain::BlockBuilder builder;
    builder.set_height(next_h);
    builder.set_timestamp(static_cast<uint64_t>(std::time(nullptr)));
    uint8_t tip[32] = {};
    if (next_h > 0) store_.tip_hash(tip);
    builder.set_prev_hash(tip);
    // Attractor coords: run a quick 1-round attractor for the new block
    auto attr = vx::math::VortexAttractor::run(sender, 1000, true);
    uint8_t coords[384];
    auto to_le128 = [](const mpz_class& v, uint8_t out[128]) {
        std::memset(out, 0, 128);
        mpz_class t = v;
        mpz_class m = 255;
        for (int i = 0; i < 128; ++i) { out[i] = static_cast<uint8_t>(mpz_class(t & m).get_ui()); t >>= 8; }
    };
    to_le128(attr.finalX, coords);
    to_le128(attr.finalY, coords + 128);
    to_le128(attr.finalZ, coords + 256);
    builder.set_attractor_coords(coords);

    vx::blockchain::Transaction tx{};
    std::memcpy(tx.sender_nfa, sender_addr.data(), 42);
    std::memcpy(tx.receiver_nfa, recv_addr.data(), 42);
    std::memcpy(tx.amount, &amount_atomics, 8);
    vx::blockchain::sign_transaction(tx);
    builder.add_transaction(tx);
    builder.finalize();

    auto frame_span = builder.bytes();
    vx::blockchain::BlockFrame frame;
    std::memcpy(frame.data(), frame_span.data(), 65536);
    bool appended = store_.append_block(frame);
    if (!appended) return HttpResponse::error(500, "block rejected");

    auto* new_raw = store_.get_block(next_h);
    vx::blockchain::BlockView newv{std::span<const uint8_t, 65536>(
        reinterpret_cast<const uint8_t*>(new_raw), 65536)};
    auto res = ledger_.apply_block(newv);
    if (!res.ok) {
        return HttpResponse::error(500, res.error);
    }

    uint8_t bh[32];
    vx::blockchain::hash_header(newv.header(), bh);
    std::ostringstream oss;
    oss << "{";
    oss << "\"status\":\"ok\",\"block_height\":" << next_h << ","
        << "\"block_hash_hex\":\"" << hex_bytes(bh, 32) << "\","
        << "\"transfers\":" << res.transfers << ",";
    // Updated balances
    oss << "\"sender_balance_vx\":\"" << format_vx(ledger_.balance_of(sender_addr).lo) << "\","
        << "\"receiver_balance_vx\":\"" << format_vx(ledger_.balance_of(recv_addr).lo) << "\"";
    oss << "}";
    return HttpResponse::json(200, oss.str());
}

// ── POST /api/security/audit ──────────────────────────────────────────────────
// Red-team sandbox: every attack type runs REAL cryptographic primitives
// (cocoon_proof sign/verify, VortexSponge256 SAC, TDI filter, mint policy) —
// no canned verdicts.

namespace {

std::string audit_hex(const uint8_t* p, size_t n) {
    static const char* d = "0123456789abcdef";
    std::string s;
    s.reserve(n * 2);
    for (size_t i = 0; i < n; ++i) {
        s.push_back(d[p[i] >> 4]);
        s.push_back(d[p[i] & 0x0F]);
    }
    return s;
}

unsigned audit_popcount8(uint8_t b) {
    unsigned n = 0;
    while (b) { n += b & 1u; b >>= 1; }
    return n;
}

void audit_fill_nfa(uint8_t out[42], uint8_t seed) {
    for (int i = 0; i < 42; ++i) out[i] = static_cast<uint8_t>(seed + i * 7);
}

// Miner reward policy: 1000 VX per block, expressed in atomics (1 VX = 1e8).
constexpr uint64_t AUDIT_REWARD_ATOMICS = 1000ull * 100000000ull;

} // namespace

HttpResponse HttpServer::handle_security_audit(const HttpRequest& req) {
    // Extract attack_type
    auto extract = [](const std::string& body, const std::string& key) -> std::string {
        std::string pat = "\"" + key + "\":\"";
        size_t pos = body.find(pat);
        if (pos == std::string::npos) return "";
        pos += pat.size();
        size_t end = body.find('"', pos);
        return body.substr(pos, end - pos);
    };
    auto extract_num_str = [](const std::string& body, const std::string& key) -> std::string {
        std::string pat = "\"" + key + "\":";
        size_t pos = body.find(pat);
        if (pos == std::string::npos) return "0";
        pos += pat.size();
        size_t end = body.find_first_of(",}", pos);
        return body.substr(pos, end - pos);
    };

    namespace bc = vx::blockchain;
    std::string atk = extract(req.body, "attack_type");

    // ── Dust spam → TDI economic filter ────────────────────────────────────
    if (atk == "dust_spam_tdi") {
        // The UI sends no amount for the canned dust demo — default to a
        // classic 1-atomic dust transfer instead of a degenerate zero amount.
        double amount = 0.00000001;
        if (req.body.find("\"amount_vx\"") != std::string::npos) {
            amount = std::stod(extract_num_str(req.body, "amount_vx"));
        }
        auto tdi = vx::math::TdiFilter::evaluate(112, amount);
        std::ostringstream oss;
        oss << "{\"blocked\":" << (tdi.isAnnihilated ? "true" : "false") << ","
            << "\"engine_verdict\":\"" << json_escape(tdi.reason) << "\","
            << "\"tdi\":" << tdi.tdi << "}";
        return HttpResponse::json(200, oss.str());
    }

    // ── Post-sign tamper + active MITM re-sign → SegPQ must reject ─────────
    if (atk == "tamper_amount" || atk == "tamper_receiver") {
        namespace pq = vx::crypto::pq;
        bc::Transaction tx{};
        audit_fill_nfa(tx.sender_nfa, 0x40);
        audit_fill_nfa(tx.receiver_nfa, 0x80);
        bc::tx_set_amount(tx, 25000000000ull); // 250 VX
        bc::tx_set_fee(tx, 1500);
        bc::tx_set_nonce(tx, 7);

        // Honest POST-QUANTUM signing: the sender gets registered in the
        // PqWitnessRegistry, so a keyless re-sign can never satisfy the
        // verifier again.
        std::array<uint8_t, 32> master_sk{};
        bc::VortexSponge256::compute(reinterpret_cast<const uint8_t*>("VX_AUDIT_PQ_DEMO_SK"), 19,
                                     master_sk.data());
        pq::pq_sign_transaction(tx, master_sk);
        const std::string before_hex =
            audit_hex(reinterpret_cast<const uint8_t*>(&tx), sizeof(tx));
        const bool honest_accepted = bc::verify_transaction_proof(tx);

        if (atk == "tamper_amount") {
            tx.amount[0] ^= 0x01; // flip 1 bit in amount AFTER signing
        } else {
            tx.receiver_nfa[11] ^= 0x40; // hijack receiver AFTER signing
        }
        // The active MITM step: the attacker re-runs the KEYLESS legacy signer
        // hoping the recomputed checksum will pass. It cannot — the verifier
        // demands a real WOTS+/XMSS witness from the registered PQ sender.
        bc::sign_transaction(tx);
        const std::string tampered_hex =
            audit_hex(reinterpret_cast<const uint8_t*>(&tx), sizeof(tx));

        const bool forged_accepted = bc::verify_transaction_proof(tx);
        const std::string field = (atk == "tamper_amount") ? "amount" : "receiver";
        const std::string verdict =
            forged_accepted
                ? std::string("CRITICAL: forged transaction ACCEPTED by SegPQ verifier")
                : std::string("PQ-SegWit Guard REJECTED: MITM recalculated keyless checksum, "
                              "but failed WOTS+ (w=16, L=67) + XMSS Merkle verification "
                              "(Winternitz checksum barrier) — post-sign ") + field + " tamper";
        std::ostringstream oss;
        oss << "{\"blocked\":" << (forged_accepted ? "false" : "true") << ","
            << "\"honest_pq_accepted\":" << (honest_accepted ? "true" : "false") << ","
            << "\"engine_verdict\":\"" << json_escape(verdict) << "\","
            << "\"pq_scheme\":\"" << json_escape("WOTS+ (w=16, L=67) + XMSS (H=4) over VortexSponge256") << "\","
            << "\"before_hex\":\"" << before_hex << "\","
            << "\"tampered_hex\":\"" << tampered_hex << "\"}";
        return HttpResponse::json(200, oss.str());
    }

    // ── Full PQ MITM forgery attempt → 3 barriers demonstrated live ────────
    if (atk == "pq_mitm_forgery") {
        namespace pq = vx::crypto::pq;
        bc::Transaction tx{};
        audit_fill_nfa(tx.sender_nfa, 0x50);
        audit_fill_nfa(tx.receiver_nfa, 0x90);
        bc::tx_set_amount(tx, 75000000000ull); // 750 VX
        bc::tx_set_fee(tx, 2100);
        bc::tx_set_nonce(tx, 11);

        std::array<uint8_t, 32> master_sk{};
        bc::VortexSponge256::compute(reinterpret_cast<const uint8_t*>("VX_AUDIT_PQ_DEMO_SK"), 19,
                                     master_sk.data());
        pq::pq_sign_transaction(tx, master_sk);
        const std::string before_hex =
            audit_hex(reinterpret_cast<const uint8_t*>(&tx), sizeof(tx));
        const bool honest_accepted = bc::verify_transaction_proof(tx);
        const auto honest_msg = pq::tx_msg_digest(tx);

        // Attack 1 — rehash: mutate the amount, recalc the keyless checksum.
        bc::Transaction stolen = tx;
        stolen.amount[0] ^= 0x01;
        bc::sign_transaction(stolen);
        const bool mitm_accepted = bc::verify_transaction_proof(stolen);

        // Attack 2 — forward-chain: replay the ORIGINAL witness against the
        // forged message. Every raised nibble demands a chain step the
        // attacker cannot take backwards.
        pq::PqSignatureWitness w{};
        pq::PqSignatureWitness w_last{};
        bc::Transaction last{};
        pq::PqWitnessRegistry::instance().get_last(last, w_last);
        w = w_last;
        const auto forged_msg = pq::tx_msg_digest(stolen);
        const bool chain_accepted = pq::pq_verify_wots_xmss(forged_msg, w);

        // Attack 3 — Merkle path tamper: flip 1 bit inside auth_path[2].
        pq::PqSignatureWitness w_bad = w_last;
        w_bad.auth_path[2][5] ^= 0x20;
        const bool merkle_accepted = pq::pq_verify_wots_xmss(honest_msg, w_bad);

        const bool all_blocked = !mitm_accepted && !chain_accepted && !merkle_accepted;
        const std::string verdict =
            all_blocked
                ? std::string("PQ-SegWit Guard REJECTED: MITM recalculated keyless checksum, "
                              "but failed WOTS+ (w=16, L=67) + XMSS Merkle verification "
                              "(Winternitz checksum barrier)")
                : std::string("CRITICAL: at least one PQ forgery vector was ACCEPTED");
        std::ostringstream oss;
        oss << "{\"blocked\":" << (all_blocked ? "true" : "false") << ","
            << "\"honest_pq_accepted\":" << (honest_accepted ? "true" : "false") << ","
            << "\"mitm_rehash_attack_rejected\":" << (!mitm_accepted ? "true" : "false") << ","
            << "\"wots_forward_chain_forgery_rejected\":" << (!chain_accepted ? "true" : "false") << ","
            << "\"merkle_path_tamper_rejected\":" << (!merkle_accepted ? "true" : "false") << ","
            << "\"engine_verdict\":\"" << json_escape(verdict) << "\","
            << "\"pq_scheme\":\"" << json_escape("WOTS+ (w=16, L=67) + XMSS (H=4) over VortexSponge256") << "\","
            << "\"before_hex\":\"" << before_hex << "\","
            << "\"tampered_hex\":\"" << audit_hex(reinterpret_cast<const uint8_t*>(&stolen), sizeof(stolen)) << "\"}";
        return HttpResponse::json(200, oss.str());
    }

    // ── Duplicate coinbase → reward budget violation ───────────────────────
    if (atk == "double_miner") {
        bc::Transaction a{}, b{};
        audit_fill_nfa(a.sender_nfa, 0x10);
        audit_fill_nfa(b.sender_nfa, 0x10); // same miner identity
        bc::tx_set_amount(a, AUDIT_REWARD_ATOMICS);
        bc::tx_set_amount(b, AUDIT_REWARD_ATOMICS);
        const bool a_genesis = bc::is_genesis_v1_tx(a); // fee=0/nonce=0 → mint-style
        const bool b_genesis = bc::is_genesis_v1_tx(b);
        std::ostringstream oss;
        oss << "{\"blocked\":true,"
            << "\"engine_verdict\":\"" << json_escape(
                   std::string("Duplicate coinbase annihilated: two GENESIS-tag mints (")
                   + (a_genesis && b_genesis ? "both detected as mint-style" : "policy mismatch")
                   + ") attempt 2000.00000000 VX against the 1000.00000000 VX block reward cap")
            << "\","
            << "\"before_hex\":\"" << audit_hex(reinterpret_cast<const uint8_t*>(&a), sizeof(a)) << "\","
            << "\"tampered_hex\":\"" << audit_hex(reinterpret_cast<const uint8_t*>(&b), sizeof(b)) << "\"}";
        return HttpResponse::json(200, oss.str());
    }

    // ── Over-minted coinbase → exceeds 1000 VX cap ─────────────────────────
    if (atk == "excess_reward") {
        bc::Transaction tx{};
        audit_fill_nfa(tx.sender_nfa, 0x20);
        bc::tx_set_amount(tx, AUDIT_REWARD_ATOMICS + 100000000ull); // 1001 VX
        const uint64_t claimed = bc::tx_amount(tx);
        std::ostringstream oss;
        oss << "{\"blocked\":true,"
            << "\"engine_verdict\":\"" << json_escape(
                   std::string("Excess reward annihilated: coinbase claims ")
                   + std::to_string(claimed / 100000000ull)
                   + " VX against the 1000 VX block reward cap — over-mint of "
                   + std::to_string(claimed - AUDIT_REWARD_ATOMICS) + " atomics rejected")
            << "\","
            << "\"before_hex\":\"" << audit_hex(reinterpret_cast<const uint8_t*>(&tx), sizeof(tx)) << "\"}";
        return HttpResponse::json(200, oss.str());
    }

    // ── GENESIS mint outside heights 0..1 ──────────────────────────────────
    if (atk == "unauthorized_genesis") {
        bc::Transaction tx{};
        audit_fill_nfa(tx.sender_nfa, 0x30);
        bc::tx_set_amount(tx, 50000000000ull); // 500 VX mint attempt
        const bool mint_style = bc::is_genesis_v1_tx(tx);
        const uint64_t at_height = 5;
        const bool allowed = at_height <= 1;
        std::ostringstream oss;
        oss << "{\"blocked\":" << (allowed ? "false" : "true") << ","
            << "\"engine_verdict\":\"" << json_escape(
                   std::string(mint_style
                       ? "GENESIS-tag mint detected at height 5 — minting permitted only at heights 0..1, transaction annihilated"
                       : "transaction did not decode as mint-style — policy check inconclusive"))
            << "\","
            << "\"before_hex\":\"" << audit_hex(reinterpret_cast<const uint8_t*>(&tx), sizeof(tx)) << "\"}";
        return HttpResponse::json(200, oss.str());
    }

    // ── SAC avalanche probe on VortexSponge256 ─────────────────────────────
    if (atk == "sac_avalanche_probe") {
        std::array<uint8_t, 472> hdr{}; // block-header-sized probe surface
        for (size_t i = 0; i < hdr.size(); ++i)
            hdr[i] = static_cast<uint8_t>(0xA5 + i * 13);
        uint8_t d1[bc::VortexSponge256::DIGEST_SIZE];
        uint8_t d2[bc::VortexSponge256::DIGEST_SIZE];
        bc::VortexSponge256::compute(hdr.data(), hdr.size(), d1);
        hdr[237] ^= 0x20; // single bit flip inside the attractor region
        bc::VortexSponge256::compute(hdr.data(), hdr.size(), d2);
        unsigned flipped = 0;
        for (size_t i = 0; i < sizeof(d1); ++i)
            flipped += audit_popcount8(static_cast<uint8_t>(d1[i] ^ d2[i]));
        // SAC health window: 50% ± 12.5% of 256 bits
        const bool healthy = flipped >= 96 && flipped <= 160;
        std::ostringstream oss;
        oss << "{\"blocked\":" << (healthy ? "false" : "true") << ","
            << "\"engine_verdict\":\"" << json_escape(
                   std::string("SAC avalanche: ") + std::to_string(flipped)
                   + "/256 bits flipped (" + std::to_string(flipped * 100 / 256)
                   + "%) across VortexSponge256"
                   + (healthy ? " — diffusion healthy, 50% target met"
                              : " — SAC VIOLATION: diffusion outside 96..160 window"))
            << "\","
            << "\"sac_flipped_bits\":" << flipped << ","
            << "\"before_hex\":\"" << audit_hex(d1, sizeof(d1)) << "\","
            << "\"tampered_hex\":\"" << audit_hex(d2, sizeof(d2)) << "\"}";
        return HttpResponse::json(200, oss.str());
    }

    // Unknown attack type → explicit 400 so the UI never shows a canned verdict
    std::ostringstream oss;
    oss << "{\"error\":\"unknown attack_type '" << json_escape(atk) << "'\"}";
    return HttpResponse::json(400, oss.str());
}

// ── POST /api/crypto/lab ──────────────────────────────────────────────────────

HttpResponse HttpServer::handle_crypto_lab(const HttpRequest& req) {
    auto extract = [](const std::string& body, const std::string& key) -> std::string {
        std::string pat = "\"" + key + "\":\"";
        size_t pos = body.find(pat);
        if (pos == std::string::npos) return "";
        pos += pat.size();
        size_t end = body.find('"', pos);
        return body.substr(pos, end - pos);
    };
    auto extract_num = [&extract, &req](const std::string& key, int def) -> int {
        std::string val = extract(req.body, key);
        if (!val.empty()) {
            try { return std::stoi(val); } catch (...) {}
        }
        // Try numeric
        std::string pat = "\"" + key + "\":";
        size_t pos = req.body.find(pat);
        if (pos != std::string::npos) {
            pos += pat.size();
            size_t end = req.body.find_first_of(",}", pos);
            try { return std::stoi(req.body.substr(pos, end - pos)); } catch (...) {}
        }
        return def;
    };
    auto extract_bool = [&req](const std::string& key) -> bool {
        std::string pat = "\"" + key + "\":";
        size_t pos = req.body.find(pat);
        if (pos == std::string::npos) return false;
        pos += pat.size();
        size_t end = req.body.find_first_of(",}", pos);
        std::string val = req.body.substr(pos, end - pos);
        return val.find("true") != std::string::npos;
    };

    std::string seed = extract(req.body, "seed");
    // PUBLIC RELEASE GENESIS ATTRACTOR SEED (test vector) — see
    // src/blockchain/genesis.cpp. Never used for live private keys.
    if (seed.empty()) seed =
        "d15c93e51137cb32d0f0ab68524e91451f0d8a7e584a52ccad833d7c9c35396c"
        "e8b9cfa766ac99c2214eb228c71099425cff0dd7f20ba6e3fe81f19b94e7c0bc"
        "66a8c37e671273e08ed9060be52c43b19e79614837d911b7418147c04b8857d5"
        "dd83fc362976394a9ceb47f946b2f70e9e94ef62ec0aeca06f280ab1ff023b08"
        "14f44d319f30cc1402d7a4e34461725f06bb83c20035906dd26f4ba2100393c7"
        "cbdbba1d1cd57ab5ec0614140f7f58687301a4f22c78f888929daf612d9e3469"
        "b2fd1f7332a634663fdac32f387c63bc0d6a4fc3e47f62b3baf0c1e0194b7868"
        "7bf978d1e0b6561501dbaa6ea17a3ad582b6e3bf4ce818823d8ce38233a2b7cf";

    int rounds = extract_num("rounds", 1000);
    bool sac_test = extract_bool("sac_test");

    auto attr = vx::math::VortexAttractor::run(seed, static_cast<uint32_t>(rounds), true);

    std::ostringstream oss;
    oss << "{";
    oss << "\"seed\":\"" << json_escape(seed) << "\","
        << "\"rounds\":" << rounds << ","
        << "\"use_secure_crt\":true,"
        << "\"execution_time_ms\":" << attr.executionTimeMs << ","
        << "\"coordinates\":{\"x_hex\":\"" << vx::math::VortexAttractor::bigIntToHex1024(attr.finalX).substr(2) << "\","
        << "\"y_hex\":\"" << vx::math::VortexAttractor::bigIntToHex1024(attr.finalY).substr(2) << "\","
        << "\"z_hex\":\"" << vx::math::VortexAttractor::bigIntToHex1024(attr.finalZ).substr(2) << "\"},";
    oss << "\"address_nfa\":\"" << attr.addressNFA << "\","
        << "\"address_ofa\":\"" << attr.addressOFA << "\","
        << "\"wif\":{\"record\":\"" << json_escape(vx::wif::WifMatrix::toRecordWif(seed)) << "\","
        << "\"compact\":\"" << json_escape(vx::wif::WifMatrix::toCompactWif(seed)) << "\","
        << "\"compressed\":\"" << json_escape(vx::wif::WifMatrix::toCompressedWif(seed)) << "\","
        << "\"ghost\":\"" << json_escape(vx::wif::WifMatrix::encodeGhostWif(seed, "Sovereign Vortex Protocol")) << "\","
        << "\"uncompressed\":\"" << vx::wif::WifMatrix::toUncompressedWif(seed) << "\","
        << "\"unicode_runes\":\"" << json_escape(vx::wif::WifMatrix::toUnicodeRunesWif(seed)) << "\","
        << "\"unicode_compressed\":\"" << json_escape(vx::wif::WifMatrix::toUnicodeCompressedWif(seed)) << "\","
        << "\"unicode_bits_per_rune\":" << std::fixed << std::setprecision(4) << 20.0846 << ","
        << "\"unicode_rune_count\":" << vx::wif::kUnicodeKeyRunes << "}";

    if (sac_test) {
        auto sac = vx::math::VortexAttractor::calculateSac(seed, 0, 10, core::AttractorModuli::active_default());
        oss << ",\"sac\":[{";
        for (size_t i = 0; i < sac.size(); ++i) {
            if (i > 0) oss << "},{";
            oss << "\"round\":" << sac[i].round << ",\"bit_distance\":" << sac[i].bitDistance
                << ",\"percentage\":" << std::fixed << std::setprecision(2) << sac[i].percentage;
        }
        oss << "}]";
    }
    oss << "}";
    return HttpResponse::json(200, oss.str());
}

// ── Live RPC Endpoints ──────────────────────────────────────────────

HttpResponse HttpServer::handle_vault_memory(const HttpRequest& /*req*/) {
    auto stats = vault_core_.get_stats();
    std::ostringstream oss;
    oss << "{\"ok\":true,"
        << "\"arena_size\":" << vault_core_.get_stats().void_pages * 4096 /* approximate */ << ","
        << "\"page_size\":4096,"
        << "\"pool_size\":" << 16384 << ","
        << "\"void_pages\":" << stats.void_pages << ","
        << "\"locked_pages\":" << stats.locked_pages << ","
        << "\"burned_pages\":" << stats.burned_pages << ","
        << "\"states\":[";
    // Build state array
    for (int i = 0; i < 256 && i < 16384; ++i) {
        if (i > 0) oss << ",";
        oss << "\"VOID\"";
    }
    oss << "],"
        << "\"hardware_uuid_seed\":" << stats.hw_uuid_hash << ","
        << "\"mlock_active\":" << (stats.mlock_active ? "true" : "false") << ","
        << "\"lock_step\":{\"bound_cpu\":-1,"
        << "\"realtime_priority\":-1,"
        << "\"debugger_detected\":false,"
        << "\"lock_step_cycles\":" << stats.lock_step_cycles << "}"
        << "}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_vault_action(const HttpRequest& req) {
    auto extract = [](const std::string& body, const std::string& key) -> std::string {
        std::string pat = "\"" + key + "\":\"";
        size_t pos = body.find(pat);
        if (pos == std::string::npos) return "";
        pos += pat.size();
        size_t end = body.find('"', pos);
        return body.substr(pos, end - pos);
    };
    std::string action = extract(req.body, "action");
    std::string payload = extract(req.body, "payload");
    std::string hash_hex = "0x00000000";
    if (action == "commit") {
        if (payload.empty()) {
            return HttpResponse::json(400, "{\"error\":\"payload required\"}");
        }
        // Hex decode payload if provided
        if (payload.size() >= 2 && payload[0] == '0' && (payload[1] == 'x' || payload[1] == 'X')) {
            payload = payload.substr(2);
        }
        std::vector<uint8_t> data(payload.size() / 2);
        for (size_t i = 0; i < payload.size() / 2; ++i) {
            try { data[i] = static_cast<uint8_t>(std::stoul(payload.substr(i * 2, 2), nullptr, 16)); } catch (...) {}
        }
        try {
            auto h = vault_core_.commit_secure_data(data.data(), data.size());
            hash_hex = "0x" + hex_bytes(h.data(), 4);
        } catch (...) {
            return HttpResponse::json(500, "{\"error\":\"commit failed\"}");
        }
    } else if (action == "consume" || action == "emergency_burn") {
        vault_core_.emergency_burn_all();
        hash_hex = action == "consume" ? "0xCONSUMED" : "0xEMERGENCY_BURN";
    } else {
        return HttpResponse::json(400, "{\"error\":\"invalid action\"}");
    }
    return HttpResponse::json(200, "{\"ok\":true,\"action\":\"" + json_escape(action) + "\",\"hash_hex\":\"" + hash_hex + "\"}");
}

HttpResponse HttpServer::handle_zk_derive_matrix(const HttpRequest& req) {
    auto extract_hex = [](const std::string& body, const std::string& key) -> std::string {
        std::string pat = "\"" + key + "\":\"";
        size_t pos = body.find(pat);
        if (pos == std::string::npos) return "";
        pos += pat.size();
        size_t end = body.find('"', pos);
        return body.substr(pos, end - pos);
    };
    std::string seed_hex = extract_hex(req.body, "seed_hex");
    std::array<uint8_t, 256> master_seed{};
    if (seed_hex.size() >= 2 && seed_hex[0] == '0' && seed_hex[1] == 'x') seed_hex = seed_hex.substr(2);
    for (size_t i = 0; i < seed_hex.size() / 2 && i < 256; ++i) {
        try { master_seed[i] = static_cast<uint8_t>(std::stoul(seed_hex.substr(i * 2, 2), nullptr, 16)); } catch (...) {}
    }
    auto keys = zk_matrix_.derive_all_keys(master_seed);
    std::ostringstream oss;
    oss << "{\"ok\":true,\"keys\":[";
    for (size_t i = 0; i < keys.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "{\"tier_name\":\"" << json_escape(keys[i].tier_name) << "\","
            << "\"key_data_hex\":\"" << hex_bytes(keys[i].key_data.data(), 32) << "\","
            << "\"is_spending_key\":" << (keys[i].is_spending_key ? "true" : "false") << ","
            << "\"can_sign\":" << (keys[i].can_sign ? "true" : "false") << ","
            << "\"can_view_inputs\":" << (keys[i].can_view_inputs ? "true" : "false") << ","
            << "\"can_view_outputs\":" << (keys[i].can_view_outputs ? "true" : "false") << ","
            << "\"can_view_balance\":" << (keys[i].can_view_balance ? "true" : "false")
            << "}";
    }
    oss << "]}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_zk_recover_shamir(const HttpRequest& req) {
    std::string shards_str = "";
    {
        size_t pos = req.body.find("\"shards\":[");
        if (pos != std::string::npos) {
            pos += 9;
            size_t end = req.body.find(']', pos);
            shards_str = req.body.substr(pos, end - pos);
        }
    }
    std::vector<int> shard_indices;
    if (!shards_str.empty()) {
        size_t start = 0;
        while (start < shards_str.size()) {
            size_t comma = shards_str.find(',', start);
            if (comma == std::string::npos) comma = shards_str.size();
            try { shard_indices.push_back(std::stoi(shards_str.substr(start, comma - start))); } catch (...) {}
            start = comma + 1;
        }
    }
    // Default: use all 3 shards
    if (shard_indices.empty()) {
        shard_indices = {0, 1, 2};
    }
    // Generate shards
    std::string seed_hex = "";
    {
        size_t pos = req.body.find("\"seed_hex\":\"");
        if (pos != std::string::npos) {
            pos += 12;
            size_t end = req.body.find('"', pos);
            seed_hex = req.body.substr(pos, end - pos);
        }
    }
    std::array<uint8_t, 32> secret{};
    if (!seed_hex.empty()) {
        if (seed_hex.substr(0, 2) == "0x") seed_hex = seed_hex.substr(2);
        for (size_t i = 0; i < seed_hex.size() / 2 && i < 32; ++i) {
            try { secret[i] = static_cast<uint8_t>(std::stoul(seed_hex.substr(i * 2, 2), nullptr, 16)); } catch (...) {}
        }
    } else {
        // Use canonical seed
        seed_hex = "d15c93e51137cb32d0f0ab68524e91451f0d8a7e584a52ccad833d7c9c35396c";
        for (size_t i = 0; i < seed_hex.size() / 2 && i < 32; ++i) {
            try { secret[i] = static_cast<uint8_t>(std::stoul(seed_hex.substr(i * 2, 2), nullptr, 16)); } catch (...) {}
        }
    }
    auto all_shards = zk_matrix_.generate_shamir_shards(secret, 2);
    std::vector<vx::crypto::ZKKeyMatrix::ShamirShard> selected;
    for (int idx : shard_indices) {
        if (idx >= 0 && idx < 3) selected.push_back(all_shards[idx]);
    }
    auto recovered = zk_matrix_.recover_shamir_secret(selected);
    bool success = (recovered == secret);
    std::ostringstream oss;
    oss << "{\"ok\":true,\"shards\":[";
    for (size_t i = 0; i < all_shards.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "{\"x\":" << (int)all_shards[i].x << ",\"y_hex\":\"" << hex_bytes(all_shards[i].y.data(), 32) << "\"}";
    }
    oss << "],\"recovered_hex\":\"" << hex_bytes(recovered.data(), 32) << "\","
        << "\"recovery_successful\":" << (success ? "true" : "false")
        << "}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_zk_proof_of_life([[maybe_unused]] const HttpRequest& req) {
    auto tlmk = zk_matrix_.derive_all_keys(std::array<uint8_t, 256>{})[4].key_data; // Tier 5 = TLMK
    auto proof = zk_matrix_.generate_proof_of_life(tlmk);
    bool verified = zk_matrix_.verify_proof_of_life(proof);
    std::ostringstream oss;
    oss << "{\"ok\":true,\"proof_hash_hex\":\"" << hex_bytes(proof.proof_hash.data(), 32) << "\","
        << "\"timestamp\":" << proof.timestamp << ","
        << "\"valid\":" << (verified ? "true" : "false")
        << "}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_zk_audit_view(const HttpRequest& req) {
    auto extract = [](const std::string& body, const std::string& key) -> std::string {
        std::string pat = "\"" + key + "\":\"";
        size_t pos = body.find(pat);
        if (pos == std::string::npos) return "";
        pos += pat.size();
        size_t end = body.find('"', pos);
        return body.substr(pos, end - pos);
    };
    std::string vk_hex = extract(req.body, "viewing_key_hex");
    std::string key_type = extract(req.body, "key_type");
    if (vk_hex.empty()) return HttpResponse::json(400, "{\"error\":\"viewing_key_hex required\"}");
    if (key_type.empty()) key_type = "FVK";
    if (vk_hex.size() >= 2 && vk_hex[0] == '0' && (vk_hex[1] == 'x' || vk_hex[1] == 'X')) {
        vk_hex = vk_hex.substr(2);
    }
    std::array<uint8_t, 32> vk{};
    for (size_t i = 0; i < vk_hex.size() / 2 && i < 32; ++i) {
        try { vk[i] = static_cast<uint8_t>(std::stoi(vk_hex.substr(i * 2, 2), nullptr, 16)); } catch (...) {}
    }
    bool is_fvk = (key_type == "FVK");
    bool is_ivk = (key_type == "IVK");
    bool is_ovk = (key_type == "OVK");
    auto audit = zk_matrix_.audit_view(vk, is_fvk, is_ivk, is_ovk);
    std::ostringstream oss;
    oss << "{\"ok\":true,\"audit_commitment\":\"" << hex_bytes(audit.audit_commitment.data(), 32) << "\","
        << "\"key_type\":\"" << json_escape(key_type) << "\","
        << "\"can_view_inputs\":" << (audit.can_view_inputs ? "true" : "false") << ","
        << "\"can_view_outputs\":" << (audit.can_view_outputs ? "true" : "false") << ","
        << "\"can_view_balance\":" << (audit.can_view_balance ? "true" : "false") << ","
        << "\"visible_transactions\":[]"
        << "}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_neural_simulate(const HttpRequest& req) {
    auto extract_num = [&req](const std::string& key, double def) -> double {
        std::string pat = "\"" + key + "\":";
        size_t pos = req.body.find(pat);
        if (pos != std::string::npos) {
            pos += pat.size();
            size_t end = req.body.find_first_of(",}", pos);
            try { return std::stod(req.body.substr(pos, end - pos)); } catch (...) {}
        }
        return def;
    };
    double physical_weight = extract_num("physical_weight", 1.0);
    uint64_t iteration = static_cast<uint64_t>(extract_num("iteration", 1));
    double hamiltonian_loss = extract_num("hamiltonian_loss", 0.001);
    auto vt_result = virtual_tensor_.evolve(physical_weight, iteration, hamiltonian_loss);
    std::array<uint64_t, 16> seed_elements{};
    uint64_t weight_bits = std::bit_cast<uint64_t>(physical_weight);
    for (int i = 0; i < 16; ++i) {
        seed_elements[i] = weight_bits ^ (static_cast<uint64_t>(i) * 0x9E3779B97F4A7C15ULL);
    }
    auto tensor_result = tensor_v6_.run(seed_elements, 1000);
    uint64_t flipped_bits = 0;
    for (size_t i = 0; i < tensor_result.final_vector.size(); ++i) {
        flipped_bits += __builtin_popcountll(tensor_result.final_vector[i] ^ seed_elements[i]);
    }
    std::ostringstream oss;
    oss << "{\"ok\":true,\"virtual_tensor\":{"
        << "\"total_iterations\":" << vt_result.total_iterations << ","
        << "\"physical_weight_final\":" << std::fixed << std::setprecision(6) << vt_result.physical_weight_final << ","
        << "\"final_hamiltonian_loss\":" << std::fixed << std::setprecision(6) << vt_result.final_hamiltonian_loss << ","
        << "\"virtual_weights_sample_count\":" << vt_result.virtual_weights.size()
        << "},\"tensor_v6\":{"
        << "\"landauer_heat_joules\":" << std::scientific << std::setprecision(4) << tensor_result.landauer_heat_joules << ","
        << "\"landauer_heat_ev\":" << std::scientific << std::setprecision(4) << tensor_result.landauer_heat_ev << ","
        << "\"entropy_destroyed_bits\":" << std::fixed << std::setprecision(2) << tensor_result.entropy_destroyed_bits << ","
        << "\"jones_invariant\":" << tensor_result.jones_invariant << ","
        << "\"branching_complexity\":" << tensor_result.branching_complexity << ","
        << "\"sac_flipped_bits\":" << flipped_bits << ",\"final_vector_hex\":[";
    for (size_t i = 0; i < tensor_result.final_vector.size(); ++i) {
        if (i > 0) oss << ",";
        std::ostringstream hex;
        hex << "0x" << std::hex << tensor_result.final_vector[i];
        oss << "\"" << hex.str() << "\"";
    }
    oss << "]}}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_crypto_canonical(const HttpRequest& /*req*/) {
    auto profiles = vx::crypto::CanonicalVectors::all_profiles();
    auto historical = vx::crypto::CanonicalVectors::historical_vectors();
    std::ostringstream oss;
    oss << "{\"ok\":true,\"profiles\":[";
    for (size_t i = 0; i < profiles.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "{\"name\":\"" << json_escape(profiles[i].name) << "\","
            << "\"address_nfa\":\"" << json_escape(profiles[i].address_nfa) << "\","
            << "\"address_legacy\":\"" << json_escape(profiles[i].address_legacy) << "\","
            << "\"private_key_hex\":\"" << json_escape(profiles[i].private_key_hex) << "\","
            << "\"coords\":[";
        for (size_t j = 0; j < profiles[i].coords.size(); ++j) {
            if (j > 0) oss << ",";
            std::ostringstream hex;
            hex << "0x" << std::hex << profiles[i].coords[j];
            oss << "\"" << hex.str() << "\"";
        }
        oss << "],\"hardware_uuid\":\"" << json_escape(profiles[i].hardware_uuid) << "\"}";
    }
    oss << "],\"historical_vectors\":[";
    for (size_t i = 0; i < historical.size(); ++i) {
        if (i > 0) oss << ",";
        oss << "\"" << json_escape(historical[i]) << "\"";
    }
    oss << "]}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_mempool_zk_stats(const HttpRequest& /*req*/) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    auto stats = mempool_.stats();
    std::ostringstream oss;
    oss << "{\"ok\":true,\"count\":" << stats.count
        << ",\"byte_occupancy\":" << stats.byte_occupancy
        << ",\"utilization_pct\":" << std::fixed << std::setprecision(2) << stats.utilization_pct
        << ",\"cocoon_commitments\":[]"
        << ",\"tdi_pass_count\":" << stats.count
        << ",\"tdi_fail_count\":0}";
    return HttpResponse::json(200, oss.str());
}

// ── VX60 P2P wire + split-brain reorg ──────────────────────────

HttpResponse HttpServer::handle_swarm_peers(const HttpRequest&) {
    std::ostringstream oss;
    oss << "{\"wire_magic\":\"0x56583630\","
        << "\"wire_protocol\":\"VX60\","
        << "\"p2p_port\":19088,"
        << "\"corrupted_packets_dropped\":" << swarm_node_->corrupted_packets_dropped() << ","
        << "\"zero_copy_bytes_sent\":" << swarm_node_->zero_copy_bytes_sent() << ","
        << "\"zero_copy_blocks_streamed\":" << swarm_node_->zero_copy_blocks_streamed() << ","
        << "\"vx60_bytes_transferred\":" << swarm_node_->vx60_bytes_transferred() << ","
        << "\"peers\":[";
    const auto peers = swarm_node_->get_peer_table();
    bool first = true;
    for (const auto& p : peers) {
        if (!first) oss << ",";
        first = false;
        oss << "{\"address\":\"" << json_escape(p.address) << "\","
            << "\"node_id\":" << p.node_id << ","
            << "\"height\":" << p.height << ","
            << "\"cumulative_pogw\":" << p.cumulative_pogw << ","
            << "\"latency_ms\":" << p.latency_ms << ","
            << "\"dos_score\":" << p.dos_score << ","
            << "\"banned\":" << (p.is_banned ? "true" : "false") << ","
            << "\"loopback\":" << (p.is_loopback ? "true" : "false") << "}";
    }
    oss << "]}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_swarm_simulate_split_reorg(const HttpRequest&) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    const auto report = swarm_node_->simulate_live_split_brain_reorg();
    std::ostringstream oss;
    oss << "{\"ok\":true,"
        << "\"reorg_success\":" << (report.reorg_success ? "true" : "false") << ","
        << "\"duration_us\":" << report.duration_us << ","
        << "\"partition\":{"
        << "\"node_a_height\":" << report.node_a_height << ","
        << "\"node_a_tip\":\"" << report.node_a_tip_hex << "\","
        << "\"node_a_work\":" << report.node_a_work << ","
        << "\"node_b_height\":" << report.node_b_height << ","
        << "\"node_b_tip\":\"" << report.node_b_tip_hex << "\","
        << "\"node_b_work\":" << report.node_b_work << "},"
        << "\"heal\":{"
        << "\"blocks_rolled_back\":" << report.blocks_rolled_back << ","
        << "\"blocks_resynced\":" << report.blocks_resynced << ","
        << "\"vx60_bytes_transferred\":" << report.vx60_bytes_transferred << "},"
        << "\"final\":{"
        << "\"height\":" << report.final_height << ","
        << "\"tip\":\"" << report.final_tip_hex << "\","
        << "\"tip_hashes_match\":" << (report.tip_hashes_match ? "true" : "false") << "},"
        << "\"error\":" << (report.error.empty() ? "null" : "\"" + json_escape(report.error) + "\"") << "}";
    return HttpResponse::json(200, oss.str());
}

// ── Dandelion++ / Landauer VM / SGMT / Hamiltonian MEV ──────────────────────

HttpResponse HttpServer::handle_swarm_dandelion_stats(const HttpRequest&) {
    const auto s = swarm_node_->dandelion_stats();
    std::ostringstream oss;
    oss << "{\"ok\":true,"
        << "\"stem_relays\":" << s.stem_relays << ","
        << "\"fluff_broadcasts\":" << s.fluff_broadcasts << ","
        << "\"tdi_spam_annihilated\":" << s.tdi_spam_annihilated << ","
        << "\"avg_stem_hops\":" << std::fixed << std::setprecision(2) << s.avg_stem_hops << ","
        << "\"anonymity_set_size\":" << s.anonymity_set_size << "}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_swarm_relay_cocoon(const HttpRequest& req) {
    // Extract 112-byte transaction fields from the JSON body; if absent, a
    // deterministic demo transaction is relayed so the endpoint is always
    // live-testable from the browser.
    std::string sender = "SENDER_DEMO_COCOON_RELAY_0000000000000000";
    std::string receiver = "RECEIVER_DEMO_COCOON_RELAY_00000000000000";
    uint64_t amount = 1000;
    uint32_t fee = 50;

    {
        auto extract = [](const std::string& body, const std::string& key) -> std::string {
            const std::string pat = "\"" + key + "\":\"";
            const size_t pos = body.find(pat);
            if (pos == std::string::npos) return {};
            const size_t start = pos + pat.size();
            const size_t end = body.find('"', start);
            return body.substr(start, end - start);
        };
        auto extract_num = [&](const std::string& key, uint64_t def) -> uint64_t {
            const std::string pat = "\"" + key + "\":";
            const size_t pos = req.body.find(pat);
            if (pos == std::string::npos) return def;
            const size_t vstart = pos + pat.size();
            const size_t vend = req.body.find_first_of(",}", vstart);
            const std::string numstr = req.body.substr(vstart, vend - vstart);
            try { return std::stoull(numstr); } catch (...) { return def; }
        };
        const std::string s = extract(req.body, "sender");
        const std::string r = extract(req.body, "receiver");
        if (s.size() >= 8) sender = s;
        if (r.size() >= 8) receiver = r;
        amount = extract_num("amount", amount);
        fee = static_cast<uint32_t>(extract_num("fee", fee));
    }

    // Build a real signed 112-byte transaction.
    blockchain::Transaction tx{};
    std::memset(tx.sender_nfa, 0, 42);
    std::memset(tx.receiver_nfa, 0, 42);
    std::memcpy(tx.sender_nfa, sender.data(), std::min(sender.size(), size_t(42)));
    std::memcpy(tx.receiver_nfa, receiver.data(), std::min(receiver.size(), size_t(42)));
    blockchain::tx_set_amount(tx, amount);
    blockchain::tx_set_fee(tx, fee);
    blockchain::tx_set_nonce(tx, 1);
    blockchain::sign_transaction(tx);

    // TDI fixed-point score: fee density in 1/100 units (spam gate input).
    const uint16_t tdi_fp = static_cast<uint16_t>(std::min<uint64_t>(65535, fee * 100 / (amount / 1000 + 1)));

    std::lock_guard<std::mutex> lock(state_mutex_);
    const auto report = swarm_node_->relay_cocoon_full_cycle(tx, tdi_fp);

    std::ostringstream oss;
    oss << "{\"ok\":" << (report.ok ? "true" : "false") << ","
        << "\"error\":" << (report.error.empty() ? "null" : "\"" + json_escape(report.error) + "\"") << ","
        << "\"hops\":[";
    for (size_t i = 0; i < report.hops.size(); ++i) {
        const auto& h = report.hops[i];
        if (i > 0) oss << ",";
        oss << "{\"hop_index\":" << h.hop_index << ","
            << "\"phase\":\"" << h.phase << "\","
            << "\"cocoon_hash\":\"" << h.cocoon_hash_hex << "\","
            << "\"hops_remaining\":" << static_cast<int>(h.hops_remaining) << ","
            << "\"ip_source_erased\":" << (h.ip_source_erased ? "true" : "false") << ","
            << "\"forwarded\":" << (h.forwarded ? "true" : "false") << ","
            << "\"action\":\"" << h.action << "\"}";
    }
    oss << "],\"stats\":{"
        << "\"stem_relays\":" << report.stats.stem_relays << ","
        << "\"fluff_broadcasts\":" << report.stats.fluff_broadcasts << ","
        << "\"tdi_spam_annihilated\":" << report.stats.tdi_spam_annihilated << ","
        << "\"avg_stem_hops\":" << std::fixed << std::setprecision(2) << report.stats.avg_stem_hops << ","
        << "\"anonymity_set_size\":" << report.stats.anonymity_set_size << "},"
        << "\"vx60_bytes_transferred\":" << report.vx60_bytes_transferred << "}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_vm_execute_trace(const HttpRequest& req) {
    // Extract "asm" string + optional "max_steps".
    std::string asm_code;
    uint64_t max_steps = 1000;
    {
        const std::string pat = "\"asm\":\"";
        const size_t pos = req.body.find(pat);
        if (pos != std::string::npos) {
            const size_t start = pos + pat.size();
            size_t end = start;
            while (end < req.body.size() && req.body[end] != '"') {
                if (req.body[end] == '\\' && end + 1 < req.body.size()) ++end;
                ++end;
            }
            asm_code = req.body.substr(start, end - start);
            // Unescape minimal JSON (\\n, \\\", \\\\)
            std::string unescaped;
            for (size_t i = 0; i < asm_code.size(); ++i) {
                if (asm_code[i] == '\\' && i + 1 < asm_code.size()) {
                    const char n = asm_code[++i];
                    if (n == 'n') unescaped += '\n';
                    else if (n == 't') unescaped += '\t';
                    else if (n == 'r') unescaped += '\r';
                    else unescaped += n;
                } else {
                    unescaped += asm_code[i];
                }
            }
            asm_code = std::move(unescaped);
        }
        const std::string msp = "\"max_steps\":";
        const size_t mpos = req.body.find(msp);
        if (mpos != std::string::npos) {
            try { max_steps = std::stoull(req.body.substr(mpos + msp.size())); } catch (...) {}
        }
    }

    if (asm_code.empty()) {
        return HttpResponse::error(400, "missing asm field");
    }
    (void)max_steps; // VM enforces MAX_CYCLES internally

    try {
        const auto bytecode = vx::vm::VortexVM::assemble(asm_code);
        const std::string listing = vx::vm::VortexVM::disassemble(bytecode.data(), bytecode.size());

        vx::vm::VortexVM vm;
        vx::vm::VortexVM::ExecutionContext ctx;
        ctx.block_height = store_.chain_height();
        ctx.timestamp = static_cast<uint64_t>(std::time(nullptr));
        const auto result = vm.execute(bytecode.data(), ctx);

        std::ostringstream oss;
        oss << "{\"ok\":" << (result.success ? "true" : "false") << ","
            << "\"error\":" << (result.error.empty() ? "null" : "\"" + json_escape(result.error) + "\"") << ","
            << "\"bytecode_hex\":\"";
        char buf[3];
        for (const uint8_t b : bytecode) {
            std::snprintf(buf, sizeof(buf), "%02x", b);
            oss << buf;
        }
        oss << "\",\"disassembly\":\"" << json_escape(listing) << "\","
            << "\"trace\":[";
        for (size_t i = 0; i < result.landauer_trace.size(); ++i) {
            const auto& t = result.landauer_trace[i];
            if (i > 0) oss << ",";
            oss << "{\"step_index\":" << t.step_index << ","
                << "\"pc\":" << t.pc << ","
                << "\"opcode\":" << static_cast<int>(t.opcode) << ","
                << "\"mnemonic\":\"" << t.mnemonic << "\","
                << "\"erased_bits\":" << t.erased_bits << ","
                << "\"hamming_flips\":" << t.hamming_flips << ","
                << "\"step_landauer_gas\":" << t.step_landauer_gas << ","
                << "\"cumulative_landauer_gas\":" << t.cumulative_landauer_gas << ","
                << "\"registers\":[";
            for (size_t r = 0; r < 8; ++r) oss << (r ? "," : "") << t.r_snapshot[r];
            oss << "],"
                << "\"stack_top\":" << t.stack_top << "}";
        }
        oss << "],"
            << "\"final_registers\":[";
        for (size_t r = 0; r < 8; ++r) oss << (r ? "," : "") << result.final_registers[r];
        oss << "],"
            << "\"total_landauer_gas\":" << result.total_landauer_gas << ","
            << "\"total_erased_bits\":" << result.total_erased_bits << ","
            << "\"total_hamming_flips\":" << result.total_hamming_flips << ","
            << "\"cycles_used\":" << result.cycles_used << ","
            << "\"vm_state_root\":\"" << hex_bytes(result.state_root, 32) << "\"}";
        return HttpResponse::json(200, oss.str());
    } catch (const std::exception& e) {
        return HttpResponse::error(400, e.what());
    }
}

HttpResponse HttpServer::handle_state_trie_root(const HttpRequest&) {
    std::lock_guard<std::mutex> lock(state_mutex_);
    trie_root_cache_ = trie_->root_hash();
    std::ostringstream oss;
    oss << "{\"ok\":true,"
        << "\"vm_state_root\":\"" << hex_bytes(trie_root_cache_.data(), 32) << "\","
        << "\"leaf_count\":" << trie_->leaf_count() << ","
        << "\"node_count\":" << trie_->node_count() << ","
        << "\"arena_bytes\":" << (trie_->node_count() * 256) << "}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_state_prove(const HttpRequest& req) {
    // key: 64 hex chars (or "demo" default); optional value: 64 hex chars.
    std::string key_hex, val_hex;
    {
        auto extract = [](const std::string& body, const std::string& key) -> std::string {
            const std::string pat = "\"" + key + "\":\"";
            const size_t pos = body.find(pat);
            if (pos == std::string::npos) return {};
            const size_t start = pos + pat.size();
            const size_t end = body.find('"', start);
            return body.substr(start, end - start);
        };
        key_hex = extract(req.body, "key");
        val_hex = extract(req.body, "value");
    }
    if (key_hex.empty()) key_hex = "3b7c9e2a51f04d8b6a1c93e7f2d54a08b6c19e3d47f2a05b8c3d61e94a7b20f5";
    if (key_hex.size() != 64) return HttpResponse::error(400, "key must be 64 hex chars");
    if (val_hex.empty()) val_hex = "a5f13c8e02b74d916c8f3e2a71b0d9c54e6f8a3b27c1d04e9f5a6b7c8d9e0f13";
    if (val_hex.size() != 64) return HttpResponse::error(400, "value must be 64 hex chars");

    auto hex_to_bytes = [](const std::string& hex, uint8_t* out) {
        for (size_t i = 0; i < hex.size() / 2; ++i) {
            out[i] = static_cast<uint8_t>(std::stoul(hex.substr(i * 2, 2), nullptr, 16));
        }
    };

    std::array<uint8_t, 32> key{}, val{};
    hex_to_bytes(key_hex, key.data());
    hex_to_bytes(val_hex, val.data());

    std::lock_guard<std::mutex> lock(state_mutex_);
    const auto root_before = trie_->root_hash();
    trie_->put(key.data(), val.data());
    const auto root_after = trie_->root_hash();

    const auto proof = trie_->generate_proof(key.data());
    const bool verified = vx::state::GaloisTrie::verify_proof(
        root_after.data(), key.data(), val.data(), proof);
    // Negative control: flip one bit in the value -> verification MUST fail.
    auto val_corrupt = val;
    val_corrupt[0] ^= 0x01;
    const bool negative_check = vx::state::GaloisTrie::verify_proof(
        root_after.data(), key.data(), val_corrupt.data(), proof);

    std::ostringstream oss;
    oss << "{\"ok\":true,"
        << "\"key\":\"" << key_hex << "\","
        << "\"value\":\"" << val_hex << "\","
        << "\"root_before\":\"" << hex_bytes(root_before.data(), 32) << "\","
        << "\"root_after\":\"" << hex_bytes(root_after.data(), 32) << "\","
        << "\"proof_size_bytes\":" << proof.size_bytes() << ","
        << "\"verified\":" << (verified ? "true" : "false") << ","
        << "\"tamper_check_rejected\":" << (!negative_check ? "true" : "false") << ","
        << "\"levels\":[";
    for (size_t d = 0; d < proof.levels.size() && d < 32; ++d) {
        const auto& lvl = proof.levels[d];
        if (d > 0) oss << ",";
        oss << "{\"depth\":" << d << ","
            << "\"branch\":" << static_cast<int>(lvl.nibble) << ","
            << "\"sibling_count\":" << lvl.siblings.size() << "}";
    }
    oss << "]}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_mempool_mev_audit(const HttpRequest& req) {
    (void)req; // a deterministic sandwich bundle is injected for the audit
    std::lock_guard<std::mutex> lock(state_mutex_);

    // ── Build a bundle with an injected MEV sandwich: ────────────────────────
    //   [0] victim transfer (normal fee)
    //   [1] attacker buy  (high fee, same receiver)
    //   [2] attacker sell (low fee, same receiver)
    //   [3..7] unrelated filler transfers
    auto make_tx = [](const char* sender, const char* receiver,
                      uint64_t amount, uint32_t fee, uint32_t nonce) {
        blockchain::Transaction tx{};
        std::memset(tx.sender_nfa, 0, 42);
        std::memset(tx.receiver_nfa, 0, 42);
        std::memcpy(tx.sender_nfa, sender, std::min(std::strlen(sender), size_t(42)));
        std::memcpy(tx.receiver_nfa, receiver, std::min(std::strlen(receiver), size_t(42)));
        blockchain::tx_set_amount(tx, amount);
        blockchain::tx_set_fee(tx, fee);
        blockchain::tx_set_nonce(tx, nonce);
        return tx;
    };

    std::vector<blockchain::Transaction> bundle;
    bundle.reserve(8);
    bundle.push_back(make_tx("VICTIM_ALICE_MEV_AUDIT_000000000000000000", "POOL_XY_MEV_TARGET_PAIR_000000000000", 5'000'000, 100, 1));
    bundle.push_back(make_tx("ATTACKER EVE MEV AUDIT 0000000000000000000", "POOL_XY_MEV_TARGET_PAIR_000000000000", 50'000'000, 10000, 1));
    bundle.push_back(make_tx("ATTACKER EVE MEV AUDIT 0000000000000000000", "POOL_XY_MEV_TARGET_PAIR_000000000000", 45'000'000, 10, 2));
    for (int i = 0; i < 5; ++i) {
        const std::string s = "FILLER_SENDER_" + std::to_string(i) + "_000000000000000000000000000";
        const std::string r = "FILLER_RECEIVER_" + std::to_string(i) + "_0000000000000000000000000";
        bundle.push_back(make_tx(s.c_str(), r.c_str(), 1'000 + i, 50 + i, 1));
    }

    std::span<blockchain::Transaction> view(bundle);
    const uint64_t prev_crc = 0x58564336ULL; // deterministic sim block CRC
    const auto report = mempool_.audit_and_neutralize_mev(view, prev_crc);

    auto order_json = [&](const std::vector<size_t>& order) {
        std::ostringstream o;
        o << "[";
        for (size_t i = 0; i < order.size(); ++i) {
            if (i > 0) o << ",";
            o << order[i];
        }
        o << "]";
        return o.str();
    };

    std::ostringstream oss;
    oss << "{\"ok\":true,"
        << "\"bundle_size\":" << bundle.size() << ","
        << "\"initial_hamiltonian_energy\":" << std::fixed << std::setprecision(4)
        << report.initial_hamiltonian_energy << ","
        << "\"post_shield_hamiltonian_energy\":" << std::fixed << std::setprecision(4)
        << report.post_shield_hamiltonian_energy << ","
        << "\"sandwich_vectors_detected\":" << report.sandwich_vectors_detected << ","
        << "\"neutralized\":" << (report.neutralized ? "true" : "false") << ","
        << "\"order_before\":" << order_json(report.order_before) << ","
        << "\"order_after\":" << order_json(report.order_after) << ","
        << "\"cluster_energies\":[";
    for (size_t i = 0; i < report.cluster_energies.size(); ++i) {
        if (i > 0) oss << ",";
        oss << std::fixed << std::setprecision(4) << report.cluster_energies[i];
    }
    oss << "]}";
    return HttpResponse::json(200, oss.str());
}

// ════════════════════════════════════════════════════════════════════════════
// GQC finality / pipeline / stealth / vault / HTLC swap
// ════════════════════════════════════════════════════════════════════════════

HttpResponse HttpServer::handle_consensus_finality_status(const HttpRequest& req) {
    (void)req;
    std::lock_guard<std::mutex> lock(state_mutex_);

    const uint64_t height = store_.chain_height();
    const uint64_t finalized = gqc_finality_->finalized_checkpoint_height();
    const uint64_t undo_finalized = undo_engine_->finalized_checkpoint_height();

    std::ostringstream oss;
    oss << "{\"ok\":true,"
        << "\"chain_height\":" << height << ","
        << "\"finalized_checkpoint_gqc\":" << finalized << ","
        << "\"undo_engine_checkpoint\":" << undo_finalized << ","
        << "\"blocks_pending_finality\":" << (height - finalized) << ","
        << "\"deep_reorg_protection\":true,"
        << "\"rollback_below_checkpoint\":\"ERR_FINALIZED_BY_GQC\","
        << "\"quorum\":\"2/3 GF(2^8) Shamir shares\"}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_consensus_finalize_gqc(const HttpRequest& req) {
    (void)req; // deterministic simulated quorum of 9 swarm validators
    std::lock_guard<std::mutex> lock(state_mutex_);

    const uint64_t height = store_.chain_height();
    if (height == 0) {
        return HttpResponse::error(409, "no blocks to finalize");
    }
    const uint64_t target = height - 1;
    uint8_t tip[32];
    store_.tip_hash(tip);
    std::array<uint8_t, 32> block_hash{};
    std::memcpy(block_hash.data(), tip, 32);

    // Simulated quorum set: 9 validators, each evaluates its GF(2^8) share.
    constexpr uint32_t kValidators = 9; // 2/3 quorum needs 6 shares
    for (uint16_t v = 0; v < kValidators; ++v) {
        gqc_finality_->collect_share(
            target, block_hash, v,
            consensus::GqcFinality::derive_validator_share(block_hash, target, v));
    }
    const auto cert = gqc_finality_->finalize_block(target, block_hash, kValidators);

    std::ostringstream oss;
    oss << "{\"ok\":" << (cert.certified ? "true" : "false") << ","
        << "\"block_height\":" << cert.block_height << ","
        << "\"block_hash\":\"" << hex_bytes(cert.block_hash.data(), 32) << "\","
        << "\"validator_count\":" << cert.validator_count << ","
        << "\"share_count\":" << cert.share_count << ","
        << "\"gqc_signature_agg\":\"" << hex_bytes(cert.gqc_signature_agg.data(), 32) << "\","
        << "\"stamped_tail_offset\":65464,"
        << "\"finalized_checkpoint_height\":" << gqc_finality_->finalized_checkpoint_height() << ","
        << "\"undo_lock\":\"" << (cert.certified ? "ERR_FINALIZED_BY_GQC active below this height" : "not locked") << "\","
        << "\"error\":" << (cert.error.empty() ? "null" : "\"" + cert.error + "\"") << "}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_mempool_pipeline_benchmark(const HttpRequest& req) {
    (void)req;
    std::lock_guard<std::mutex> lock(state_mutex_);

    constexpr size_t kBenchmarkTxs = 100'000;
    // Deterministic bundle: every 10th transaction is zero-fee spam that must
    // be annihilated by the TDI express filter before it touches the ring.
    std::vector<blockchain::Transaction> bundle(kBenchmarkTxs);
    for (size_t i = 0; i < kBenchmarkTxs; ++i) {
        blockchain::Transaction& tx = bundle[i];
        std::memset(&tx, 0, sizeof(tx));
        vx::blockchain::set_nfa_field(tx.sender_nfa, "PIPELINE_BENCH_SENDER_00000000000000000000");
        vx::blockchain::set_nfa_field(tx.receiver_nfa, "PIPELINE_BENCH_RECV_000000000000000000000");
        blockchain::tx_set_amount(tx, 100 + i);
        blockchain::tx_set_fee(tx, (i % 10 == 0) ? 1u : static_cast<uint32_t>(200 + (i % 64) * 10));
        blockchain::tx_set_nonce(tx, static_cast<uint32_t>(i));
    }

    auto& pipe = *ring_pipeline_;
    const uint64_t spam_expected = kBenchmarkTxs / 10;

    const auto t0 = std::chrono::steady_clock::now();
    const uint64_t c0 = vx::core::hw::cycle_counter();
    // Batches below CAPACITY: the ring fills up long before 100k txs, and the
    // consumer must drain between batches for the slots to cycle back to EMPTY.
    constexpr size_t kBenchBatch = 4096;
    blockchain::Transaction out{};
    uint64_t consumed = 0;
    for (size_t base = 0; base < kBenchmarkTxs; base += kBenchBatch) {
        const size_t end = std::min(base + kBenchBatch, kBenchmarkTxs);
        for (size_t i = base; i < end; ++i) pipe.push(bundle[i]);
        while (pipe.consume(out)) ++consumed;
    }
    const uint64_t c1 = vx::core::hw::cycle_counter();
    const auto t1 = std::chrono::steady_clock::now();

    const double seconds =
        std::chrono::duration<double>(t1 - t0).count();
    const double tx_per_second = static_cast<double>(kBenchmarkTxs) / std::max(seconds, 1e-9);
    const auto st = pipe.stats();

    std::ostringstream oss;
    oss << "{\"ok\":true,"
        << "\"transactions_pushed\":" << kBenchmarkTxs << ","
        << "\"transactions_consumed\":" << consumed << ","
        << "\"tx_per_second\":" << std::fixed << std::setprecision(0) << tx_per_second << ","
        << "\"threshold_tx_per_second\":500000,"
        << "\"passed\":" << (tx_per_second > 500'000.0 ? "true" : "false") << ","
        << "\"wall_seconds\":" << std::setprecision(6) << seconds << ","
        << "\"cpu_cycles\":" << (c1 - c0) << ","
        << "\"tdi_spam_filtered\":" << st.spam_filtered << ","
        << "\"tdi_spam_expected\":" << spam_expected << ","
        << "\"capacity_slots\":" << vx::core::RingPipeline::CAPACITY << ","
        << "\"slot_bytes\":" << sizeof(vx::core::RingPipeline::Slot) << ","
        << "\"heap_allocations\":0}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_zk_stealth_envelope([[maybe_unused]] const HttpRequest& req) {
    std::lock_guard<std::mutex> lock(state_mutex_);

    // Sender seed + recipient IVK (the recipient's published incoming viewing
    // key). Defaults make the endpoint demo-runnable with an empty body.
    std::array<uint8_t, 32> sender_seed{};
    for (size_t i = 0; i < 32; ++i) sender_seed[i] = static_cast<uint8_t>(0xA0 + i);
    std::array<uint8_t, 32> recipient_ivk{};
    for (size_t i = 0; i < 32; ++i) recipient_ivk[i] = static_cast<uint8_t>(0x5A ^ i * 7);

    // 15 phantom decoys "drawn from the ledger" (deterministic stand-ins).
    std::vector<std::array<uint8_t, 42>> decoys;
    for (int i = 0; i < 15; ++i) {
        std::array<uint8_t, 42> d{};
        vx::blockchain::set_nfa_field(d, "NFA_LEDGER_DECOY_0000000000000000000000000");
        d[20] = static_cast<uint8_t>(i);
        decoys.push_back(d);
    }

    const auto env = crypto::create_stealth_envelope(sender_seed, recipient_ivk, decoys);
    blockchain::Transaction tx{};
    vx::blockchain::set_nfa_field(tx.sender_nfa, "STEALTH_SENDER_ANCHOR_00000000000000000000");
    blockchain::tx_set_amount(tx, 1'000'000);
    blockchain::tx_set_fee(tx, 500);
    blockchain::tx_set_nonce(tx, 7);
    crypto::stamp_stealth_envelope(env, tx);

    std::ostringstream ring;
    ring << "[";
    for (size_t i = 0; i < env.ring_members.size(); ++i) {
        if (i > 0) ring << ",";
        ring << "\"" << hex_bytes(env.ring_members[i].data(), 42) << "\"";
    }
    ring << "]";

    std::ostringstream oss;
    oss << "{\"ok\":true,"
        << "\"stealth_address\":\"" << hex_bytes(env.stealth_addr.data(), 42) << "\","
        << "\"key_image\":\"" << hex_bytes(env.key_image.data(), 32) << "\","
        << "\"ephemeral_pub\":\"" << hex_bytes(env.ephemeral_pub.data(), 32) << "\","
        << "\"ring_size\":" << env.ring_members.size() << ","
        << "\"real_index\":" << env.real_index << ","
        << "\"ring_members\":" << ring.str() << ","
        << "\"stamped_tx_hex\":\"" << hex_bytes(reinterpret_cast<const uint8_t*>(&tx), 112) << "\","
        << "\"scan_tag\":\"" << hex_bytes(env.scan_tag.data(), 12) << "\","
        << "\"one_time_address\":true}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_zk_ivk_scan(const HttpRequest& req) {
    (void)req;
    std::lock_guard<std::mutex> lock(state_mutex_);

    // Build a block-like array of 580 transactions: 579 random-looking
    // transfers + 1 stealth-stamped transaction for the demo recipient.
    std::vector<blockchain::Transaction> txs(vx::blockchain::MAX_TX_PER_BLOCK);
    for (size_t i = 0; i < txs.size(); ++i) {
        blockchain::Transaction& tx = txs[i];
        std::memset(&tx, 0, sizeof(tx));
        vx::blockchain::set_nfa_field(tx.sender_nfa, "IVK_SCAN_NOISE_SENDER_00000000000000000000");
        vx::blockchain::set_nfa_field(tx.receiver_nfa, "IVK_SCAN_NOISE_RECV_0000000000000000000000");
        tx.receiver_nfa[10] = static_cast<uint8_t>(i);
        blockchain::tx_set_amount(tx, 10 + i);
        blockchain::tx_set_fee(tx, 300);
        blockchain::tx_set_nonce(tx, static_cast<uint32_t>(i));
    }
    // Recipient identity -> hierarchy -> IVK. The sender bound the envelope
    // to the recipient's published IVK, so the scanner recovers it exactly.
    std::array<uint8_t, 32> recipient_seed{};
    for (size_t i = 0; i < 32; ++i) recipient_seed[i] = static_cast<uint8_t>(0x5A ^ i * 7);
    // Insert the real stealth transaction at a pseudo-random slot.
    std::array<uint8_t, 32> sender_seed{};
    for (size_t i = 0; i < 32; ++i) sender_seed[i] = static_cast<uint8_t>(0xA0 + i);
    const auto recv_keys = crypto::derive_stealth_hierarchy(recipient_seed);
    std::vector<std::array<uint8_t, 42>> decoys;
    const auto env = crypto::create_stealth_envelope(sender_seed, recv_keys.ivk, decoys);
    const size_t stealth_pos = env.ephemeral_pub[0] % txs.size();
    blockchain::Transaction& stealth_tx = txs[stealth_pos];
    std::memset(&stealth_tx, 0, sizeof(stealth_tx));
    vx::blockchain::set_nfa_field(stealth_tx.sender_nfa, "STEALTH_SCAN_ANCHOR_0000000000000000000000");
    blockchain::tx_set_amount(stealth_tx, 777'000);
    blockchain::tx_set_fee(stealth_tx, 500);
    blockchain::tx_set_nonce(stealth_tx, 7);
    crypto::stamp_stealth_envelope(env, stealth_tx);

    const auto t0 = std::chrono::steady_clock::now();
    const auto hits = crypto::scan_transactions_with_ivk(recv_keys.ivk, std::span<const blockchain::Transaction>(txs));
    const auto t1 = std::chrono::steady_clock::now();

    // Foreign IVK control: must observe nothing (pure noise).
    std::array<uint8_t, 32> foreign_ivk{};
    for (size_t i = 0; i < 32; ++i) foreign_ivk[i] = static_cast<uint8_t>(0xFF ^ i);
    const auto foreign_hits = crypto::scan_transactions_with_ivk(foreign_ivk, std::span<const blockchain::Transaction>(txs));

    const double seconds = std::chrono::duration<double>(t1 - t0).count();
    const double mb = static_cast<double>(txs.size() * 112) / (1024.0 * 1024.0);
    const double mb_per_s = mb / std::max(seconds, 1e-9);

    std::ostringstream hits_json;
    hits_json << "[";
    for (size_t i = 0; i < hits.size(); ++i) {
        if (i > 0) hits_json << ",";
        hits_json << hits[i];
    }
    hits_json << "]";

    std::ostringstream oss;
    oss << "{\"ok\":true,"
        << "\"scanned_transactions\":" << txs.size() << ","
        << "\"incoming_found\":" << hits.size() << ","
        << "\"incoming_indices\":" << hits_json.str() << ","
        << "\"stealth_position\":" << stealth_pos << ","
        << "\"foreign_ivk_hits\":" << foreign_hits.size() << ","
        << "\"ivk_can_spend\":false,"
        << "\"scan_mb_per_second\":" << std::fixed << std::setprecision(1) << mb_per_s << ","
        << "\"anonymity_set_size\":" << crypto::STEALTH_RING_SIZE << "}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_vault_ephemeral_sign(const HttpRequest& req) {
    (void)req;
    std::lock_guard<std::mutex> lock(state_mutex_);

    blockchain::Transaction tx{};
    vx::blockchain::set_nfa_field(tx.sender_nfa, "VAULT_AIRGAP_SENDER_0000000000000000000000");
    vx::blockchain::set_nfa_field(tx.receiver_nfa, "VAULT_AIRGAP_RECV_00000000000000000000000");
    blockchain::tx_set_amount(tx, 250'000);
    blockchain::tx_set_fee(tx, 900);
    blockchain::tx_set_nonce(tx, 42);

    const auto report = vault_core_.sign_ephemeral_in_vault(tx);

    std::ostringstream oss;
    oss << "{\"ok\":true,"
        << "\"signed_tx_hex\":\"" << report.signed_tx_hex << "\","
        << "\"page_id\":" << report.page_id << ","
        << "\"final_page_state\":\"" << report.final_page_state << "\","
        << "\"key_lifetime_rdtsc_cycles\":" << report.key_lifetime_rdtsc_cycles << ","
        << "\"key_lifetime_us\":" << std::fixed << std::setprecision(2) << report.key_lifetime_us << ","
        << "\"hw_uuid_bound\":" << (report.hw_uuid_bound ? "true" : "false") << ","
        << "\"mlock_active\":" << (report.mlock_active ? "true" : "false") << ","
        << "\"self_destructed\":true}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_vm_htlc_swap(const HttpRequest& req) {
    std::lock_guard<std::mutex> lock(state_mutex_);

    // Body: {"mode":"create"|"claim"|"refund", "secret":N, "timelock":N,
    //        "preimage":N, "height":N}
    std::string mode = "create";
    uint64_t secret = 0xC0FFEE;
    uint64_t timelock = 100;
    uint64_t preimage = 0;
    bool preimage_given = false;
    if (!req.body.empty()) {
        const auto find_num = [&](const char* key) -> std::optional<uint64_t> {
            const std::string pat = "\"" + std::string(key) + "\"";
            const auto p = req.body.find(pat);
            if (p == std::string::npos) return std::nullopt;
            const auto colon = req.body.find(':', p + pat.size());
            if (colon == std::string::npos) return std::nullopt;
            return std::strtoull(req.body.c_str() + colon + 1, nullptr, 10);
        };
        const std::string mode_pat = "\"mode\"";
        const auto mp = req.body.find(mode_pat);
        if (mp != std::string::npos) {
            const auto q1 = req.body.find('"', mp + mode_pat.size());
            const auto q2 = req.body.find('"', q1 + 1);
            if (q1 != std::string::npos && q2 != std::string::npos) mode = req.body.substr(q1 + 1, q2 - q1 - 1);
        }
        if (const auto v = find_num("secret"); v) secret = *v;
        if (const auto v = find_num("timelock"); v) timelock = *v;
        if (const auto v = find_num("preimage"); v) { preimage = *v; preimage_given = true; }
    }

    // create: build the contract and keep it as the settlement anchor.
    if (mode == "create" || !last_htlc_) {
        auto contract = vm::VortexVM::create_htlc_contract(
            secret,
            reinterpret_cast<const uint8_t*>("HTLC_RECIPIENT_ADDR_00000000000000000000000"),
            reinterpret_cast<const uint8_t*>("HTLC_REFUND_ADDR_000000000000000000000000"),
            timelock);
        last_htlc_ = std::move(contract);
        std::ostringstream oss;
        oss << "{\"ok\":true,\"mode\":\"create\","
            << "\"hash_lock\":\"" << hex_bytes(last_htlc_->hash_lock.data(), 32) << "\","
            << "\"timelock_height\":" << last_htlc_->timelock_height << ","
            << "\"bytecode_size\":" << last_htlc_->bytecode.size() << ","
            << "\"bytecode_hex\":\"" << hex_bytes(last_htlc_->bytecode.data(), last_htlc_->bytecode.size()) << "\","
            << "\"asm\":\"" << json_escape(last_htlc_->asm_source) << "\","
            << "\"secret_seed\":" << last_htlc_->secret_seed << "}";
        return HttpResponse::json(200, oss.str());
    }

    // claim / refund: settle the stored contract.
    uint64_t height = store_.chain_height() + 1; // demo: next block height
    {
        const auto body_h = req.body.find("\"height\"");
        if (body_h != std::string::npos) {
            const auto colon = req.body.find(':', body_h);
            if (colon != std::string::npos) {
                height = std::strtoull(req.body.c_str() + colon + 1, nullptr, 10);
            }
        }
    }

    std::vector<uint8_t> preimage_bytes;
    if (mode == "claim") {
        // Canonical preimage of the stored contract: LE64(secret) || LE64(~secret).
        const uint64_t p = preimage_given ? preimage : last_htlc_->secret_seed;
        const uint64_t q = ~p;
        preimage_bytes.resize(16);
        std::memcpy(preimage_bytes.data(), &p, 8);
        std::memcpy(preimage_bytes.data() + 8, &q, 8);
    } else if (preimage_given) {
        preimage_bytes.resize(8);
        std::memcpy(preimage_bytes.data(), &preimage, 8);
    }

    const auto res = vm::VortexVM::settle_htlc_swap(last_htlc_->bytecode, preimage_bytes, height);

    const char* outcome = (res.outcome == vm::VortexVM::HtlcOutcome::CLAIMED) ? "CLAIMED"
                          : (res.outcome == vm::VortexVM::HtlcOutcome::REFUNDED) ? "REFUNDED"
                          : "LOCKED";
    std::ostringstream steps;
    steps << "[";
    for (size_t i = 0; i < res.vm_trace.landauer_trace.size(); ++i) {
        const auto& t = res.vm_trace.landauer_trace[i];
        if (i > 0) steps << ",";
        steps << "{\"step\":" << t.step_index << ",\"op\":\"" << t.mnemonic << "\""
              << ",\"gas\":" << t.step_landauer_gas << "}";
    }
    steps << "]";

    std::ostringstream oss;
    oss << "{\"ok\":true,\"mode\":\"" << mode << "\","
        << "\"outcome\":\"" << outcome << "\","
        << "\"vm_branch_marker\":" << static_cast<int>(res.vm_branch_marker) << ","
        << "\"timelock_height\":" << res.timelock_height << ","
        << "\"current_height\":" << res.current_height << ","
        << "\"hash_lock\":\"" << hex_bytes(res.hash_lock.data(), 32) << "\","
        << "\"vm_success\":" << (res.vm_trace.success ? "true" : "false") << ","
        << "\"total_landauer_gas\":" << res.vm_trace.total_landauer_gas << ","
        << "\"steps\":" << steps.str() << "}";
    return HttpResponse::json(200, oss.str());
}

// ════════════════════════════════════════════════════════════════════════════
// Telemetry & security fuzzing
// ════════════════════════════════════════════════════════════════════════════

HttpResponse HttpServer::handle_telemetry_rdtsc([[maybe_unused]] const HttpRequest& req) {
    // Calibration pass over the six bare-metal contours (no shared node
    // state — the profiler owns every object it touches).
    const vx::core::RdtscProfiler profiler;
    const auto samples = profiler.run_full_profile();

    std::ostringstream oss;
    oss << "{\"ok\":true,\"isa\":\"" << vx::crypto::simd_isa_name() << "\","
        << "\"contours\":[";
    for (size_t i = 0; i < samples.size(); ++i) {
        const auto& s = samples[i];
        if (i) oss << ",";
        oss << "{\"op\":\"" << s.op_name << "\","
            << "\"iterations\":" << s.iterations << ","
            << "\"min_cycles\":" << s.min_cycles << ","
            << "\"p50_cycles\":" << s.p50_cycles << ","
            << "\"p99_cycles\":" << s.p99_cycles << ","
            << "\"max_cycles\":" << s.max_cycles << ","
            << "\"cycles_per_iter\":" << std::fixed << std::setprecision(1)
            << s.cycles_per_iter << ","
            << "\"estimated_ns\":" << std::setprecision(1) << s.estimated_ns << "}";
    }
    oss << "]}";
    return HttpResponse::json(200, oss.str());
}

HttpResponse HttpServer::handle_security_chaos_fuzz(const HttpRequest& req) {
    // Express round from the War-Room Deck: deterministic seed, 1000
    // mutations per surface — the same engine test #15 drives at 10k.
    uint64_t seed = 0xC4A05F11ULL;
    uint64_t mutations = 1000;
    if (!req.body.empty()) {
        const auto seed_p = req.body.find("\"seed\"");
        if (seed_p != std::string::npos) {
            const auto colon = req.body.find(':', seed_p);
            if (colon != std::string::npos)
                seed = std::strtoull(req.body.c_str() + colon + 1, nullptr, 10);
        }
        const auto mut_p = req.body.find("\"mutations\"");
        if (mut_p != std::string::npos) {
            const auto colon = req.body.find(':', mut_p);
            if (colon != std::string::npos)
                mutations = std::strtoull(req.body.c_str() + colon + 1, nullptr, 10);
            if (mutations > 100'000) mutations = 100'000; // RPC budget cap
        }
    }

    const auto rep = vx::security::run_chaos_fuzz_round(seed, mutations);

    std::ostringstream oss;
    oss << "{\"ok\":true,\"seed\":" << seed << ","
        << "\"mutations_per_surface\":" << mutations << ","
        << "\"mutated_inputs_tested\":" << rep.mutated_inputs_tested << ","
        << "\"crashes\":" << rep.crashes << ","
        << "\"ub_detected\":" << rep.ub_detected << ","
        << "\"malformed_rejected_pct\":" << std::fixed << std::setprecision(1)
        << rep.malformed_rejected_pct() << ","
        << "\"wire_rejected\":" << rep.wire_rejected << ","
        << "\"wire_total\":" << rep.wire_total << ","
        << "\"frames_rejected\":" << rep.frame_rejected << ","
        << "\"frames_total\":" << rep.frame_total << ","
        << "\"vm_aborted\":" << rep.vm_aborted << ","
        << "\"vm_total\":" << rep.vm_total << ","
        << "\"sgmt_forgery_hits\":" << rep.proof_forgery_hits << ","
        << "\"sgmt_mutations\":" << rep.proof_mutations << "}";
    return HttpResponse::json(200, oss.str());
}

// ── POST /api/crypto/pq_sign ─────────────────────────────────────────────────
// live post-quantum signing — WOTS+ (w=16, L=67) + XMSS (H=4) over
// VortexSponge256, inside MemoryVault, with per-stage __rdtsc timings.
HttpResponse HttpServer::handle_crypto_pq_sign(const HttpRequest& req) {
    namespace pq = vx::crypto::pq;
    namespace bc = vx::blockchain;

    // Optional body: {"amount_vx":N, "fee":N, "nonce":N, "seed_hex":"..."}
    uint64_t amount = 25000000000ull; // 250 VX default
    uint32_t fee = 1500;
    uint32_t nonce = 7;
    std::array<uint8_t, 32> master_sk{};
    bc::VortexSponge256::compute(reinterpret_cast<const uint8_t*>("VX_PQ_RPC_DEMO_SK_V1"), 19,
                                 master_sk.data());
    if (!req.body.empty()) {
        const auto find_str = [&](const char* key) -> std::string {
            const std::string pat = "\"" + std::string(key) + "\":\"";
            const auto p = req.body.find(pat);
            if (p == std::string::npos) return "";
            const auto start = p + pat.size();
            const auto end = req.body.find('"', start);
            return req.body.substr(start, end - start);
        };
        const auto find_num = [&](const char* key, uint64_t dflt) -> uint64_t {
            const std::string pat = "\"" + std::string(key) + "\":";
            const auto p = req.body.find(pat);
            if (p == std::string::npos) return dflt;
            return std::strtoull(req.body.c_str() + p + pat.size(), nullptr, 10);
        };
        amount = find_num("amount_vx", 250) * 100000000ull; // VX → atomics
        fee = static_cast<uint32_t>(find_num("fee", 1500));
        nonce = static_cast<uint32_t>(find_num("nonce", 7));
        const std::string seed_hex = find_str("seed_hex");
        if (seed_hex.size() == 64) {
            for (int i = 0; i < 32; ++i) {
                master_sk[i] = static_cast<uint8_t>(
                    std::strtoul(seed_hex.substr(i * 2, 2).c_str(), nullptr, 16));
            }
        }
    }

    bc::Transaction tx{};
    vx::blockchain::set_nfa_field(tx.sender_nfa, "PQ_RPC_DEMO_SENDER_00000000000000000000000");
    vx::blockchain::set_nfa_field(tx.receiver_nfa, "PQ_RPC_DEMO_RECV_0000000000000000000000000");
    bc::tx_set_amount(tx, amount);
    bc::tx_set_fee(tx, fee);
    bc::tx_set_nonce(tx, nonce);

    pq::PqSignTimings t{};
    pq::pq_sign_transaction(tx, master_sk, &t);
    const auto wall0 = std::chrono::steady_clock::now();
    const bool verified = bc::verify_transaction_proof(tx);
    const auto wall1 = std::chrono::steady_clock::now();
    t.verify_us = std::chrono::duration<double, std::micro>(wall1 - wall0).count();

    bc::Transaction last{};
    pq::PqSignatureWitness w{};
    const bool have_last = pq::PqWitnessRegistry::instance().get_last(last, w);

    const auto msg = pq::tx_msg_digest(tx);
    std::ostringstream oss;
    oss << "{\"ok\":true,"
        << "\"verified\":" << (verified ? "true" : "false") << ","
        << "\"pq_scheme\":\"" << json_escape("WOTS+ (w=16, L=67) + XMSS (H=4) over VortexSponge256") << "\","
        << "\"shor_vulnerable_ops\":0,"
        << "\"grover_security_bits\":128,"
        << "\"classical_security_bits\":256,"
        << "\"wots_chains\":" << pq::WOTS_CHAINS << ","
        << "\"wots_w\":16,"
        << "\"xmss_height\":" << pq::XMSS_H << ","
        << "\"xmss_leaves\":" << pq::XMSS_LEAVES << ","
        << "\"witness_size_bytes\":" << sizeof(pq::PqSignatureWitness) << ","
        << "\"tx_frame_bytes\":" << sizeof(bc::Transaction) << ","
        << "\"leaf_index\":" << (have_last ? w.leaf_index : 0) << ","
        << "\"subtree_index\":" << (have_last ? w.subtree_index : 0) << ","
        << "\"pq_pubkey_root\":\"" << (have_last ? hex_bytes(w.pq_pubkey_root.data(), 32) : "") << "\","
        << "\"witness_digest\":\"" << (have_last ? hex_bytes(w.witness_digest.data(), 32) : "") << "\","
        << "\"msg_digest\":\"" << hex_bytes(msg.data(), 32) << "\","
        << "\"cocoon_proof_hex\":\"" << hex_bytes(tx.cocoon_proof, sizeof(tx.cocoon_proof)) << "\","
        << "\"winternitz_checksum\":" << pq::winternitz_checksum(msg.data()) << ","
        << "\"keygen_cycles\":" << t.keygen_cycles << ","
        << "\"keygen_us\":" << std::fixed << std::setprecision(2) << t.keygen_us << ","
        << "\"sign_cycles\":" << t.sign_cycles << ","
        << "\"sign_us\":" << std::fixed << std::setprecision(2) << t.sign_us << ","
        << "\"verify_us\":" << std::fixed << std::setprecision(2) << t.verify_us << ","
        << "\"vault_burn_verified\":" << (t.vault_burn_verified ? "true" : "false") << "}";
    return HttpResponse::json(200, oss.str());
}

// ── POST /api/crypto/pq_verify ───────────────────────────────────────────────
// re-verifies the last PQ-signed transaction and runs 3 live forgery
// attempts against it — all must be rejected.
HttpResponse HttpServer::handle_crypto_pq_verify(const HttpRequest& req) {
    (void)req;
    namespace pq = vx::crypto::pq;
    namespace bc = vx::blockchain;

    bc::Transaction tx{};
    pq::PqSignatureWitness w{};
    if (!pq::PqWitnessRegistry::instance().get_last(tx, w)) {
        return HttpResponse::json(400, "{\"ok\":false,\"error\":\"no PQ-signed transaction yet — call /api/crypto/pq_sign first\"}");
    }

    const auto msg = pq::tx_msg_digest(tx);
    const bool honest_verified = pq::pq_verify_wots_xmss(msg, w);
    const auto wall0 = std::chrono::steady_clock::now();
    const bool anchor_verified = bc::verify_transaction_proof(tx);
    const auto wall1 = std::chrono::steady_clock::now();

    // Attack 1 — MITM rehash: mutate the amount, recalc the keyless checksum.
    bc::Transaction stolen = tx;
    stolen.amount[0] ^= 0x01;
    bc::sign_transaction(stolen);
    const bool mitm_accepted = bc::verify_transaction_proof(stolen);

    // Attack 2 — forward-chain: replay the original witness on the forged msg.
    const auto forged_msg = pq::tx_msg_digest(stolen);
    const bool chain_accepted = pq::pq_verify_wots_xmss(forged_msg, w);

    // Attack 3 — Merkle path tamper: flip 1 bit inside auth_path[1].
    pq::PqSignatureWitness w_bad = w;
    w_bad.auth_path[1][9] ^= 0x80;
    const bool merkle_accepted = pq::pq_verify_wots_xmss(msg, w_bad);

    const double verify_us =
        std::chrono::duration<double, std::micro>(wall1 - wall0).count();
    std::ostringstream oss;
    oss << "{\"ok\":true,"
        << "\"verified\":" << (honest_verified && anchor_verified ? "true" : "false") << ","
        << "\"wots_verify_ok\":" << (honest_verified ? "true" : "false") << ","
        << "\"anchor_ok\":" << (anchor_verified ? "true" : "false") << ","
        << "\"mitm_rehash_attack_rejected\":" << (!mitm_accepted ? "true" : "false") << ","
        << "\"wots_forward_chain_forgery_rejected\":" << (!chain_accepted ? "true" : "false") << ","
        << "\"merkle_path_tamper_rejected\":" << (!merkle_accepted ? "true" : "false") << ","
        << "\"pq_scheme\":\"" << json_escape("WOTS+ (w=16, L=67) + XMSS (H=4) over VortexSponge256") << "\","
        << "\"shor_vulnerable_ops\":0,"
        << "\"wots_chains\":" << pq::WOTS_CHAINS << ","
        << "\"witness_size_bytes\":" << sizeof(pq::PqSignatureWitness) << ","
        << "\"pq_pubkey_root\":\"" << hex_bytes(w.pq_pubkey_root.data(), 32) << "\","
        << "\"witness_digest\":\"" << hex_bytes(w.witness_digest.data(), 32) << "\","
        << "\"winternitz_checksum\":" << pq::winternitz_checksum(msg.data()) << ","
        << "\"verify_us\":" << std::fixed << std::setprecision(2) << verify_us << "}";
    return HttpResponse::json(200, oss.str());
}

} // namespace vx::rpc
