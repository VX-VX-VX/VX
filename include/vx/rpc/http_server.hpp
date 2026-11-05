#pragma once

#include "vx/storage/block_store.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/state/undo_engine.hpp"
#include "vx/state/mempool.hpp"
#include "vx/consensus/pogw_miner.hpp"
#include "vx/consensus/gqc_finality.hpp"
#include "vx/net/swarm_node.hpp"
#include "vx/core/memory_vault.hpp"
#include "vx/core/rt_scheduler.hpp"
#include "vx/core/ring_pipeline.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/vm/vortex_vm.hpp"
#include "vx/crypto/zk_key_matrix.hpp"
#include "vx/math/tensor_v6.hpp"
#include "vx/neural/virtual_tensor.hpp"
#include "vx/crypto/canonical_vectors.hpp"
#include "vx/state/galois_trie.hpp"
#include <array>
#include <atomic>
#include <cstdint>
#include <mutex>
#include <optional>
#include <string>
#include <string_view>
#include <unordered_map>
#include <vector>
#include <thread>
#include <functional>

namespace vx::rpc {

struct HttpRequest {
    std::string method;
    std::string path;
    std::string body;
    std::unordered_map<std::string, std::string> headers;
};

struct HttpResponse {
    int status_code = 200;
    std::string status_text = "OK";
    std::unordered_map<std::string, std::string> headers;
    std::string body;

    static HttpResponse json(int status, std::string_view json_body) {
        HttpResponse r;
        r.status_code = status;
        r.status_text = (status == 200) ? "OK" : "Error";
        r.headers["Content-Type"] = "application/json; charset=utf-8";
        r.headers["Access-Control-Allow-Origin"] = "*";
        r.body = std::string(json_body);
        return r;
    }

    static HttpResponse sse(const std::string& body_str) {
        HttpResponse r;
        r.status_code = 200;
        r.status_text = "OK";
        r.headers["Content-Type"] = "text/event-stream";
        r.headers["Cache-Control"] = "no-cache";
        r.headers["Connection"] = "keep-alive";
        r.headers["Access-Control-Allow-Origin"] = "*";
        r.body = std::string(body_str);
        return r;
    }

    static HttpResponse error(int status, std::string_view message) {
        std::string escaped;
        for (char c : std::string(message)) {
            if (c == '"' || c == '\\' || c < 32) {
                escaped += "\\uXXXX";
            } else {
                escaped += c;
            }
        }
        return json(status, "{\"error\":\"" + escaped + "\"}");
    }

    static HttpResponse cors_preflight() {
        HttpResponse r;
        r.status_code = 204;
        r.status_text = "No Content";
        r.headers["Access-Control-Allow-Origin"] = "*";
        r.headers["Access-Control-Allow-Methods"] = "GET, POST, OPTIONS";
        r.headers["Access-Control-Allow-Headers"] = "Content-Type, Accept";
        r.body = "";
        return r;
    }
};

/**
 * @brief Zero-dependency POSIX HTTP/JSON RPC server.
 *
 * Listens on a TCP port, handles concurrent connections via detached threads,
 * parses HTTP requests, and dispatches 6+ RPC endpoints over the Vortex Core
 * blockchain primitives (BlockStore, LedgerState, VortexAttractor, etc.).
 *
 * SSE push stream: GET /api/events maintains a persistent connection that
 * pushes real-time JSON events (block_sealed, mempool_updated, etc.) to the
 * browser. A 3-second fallback poll is handled client-side.
 */
class HttpServer {
public:
    HttpServer(storage::BlockStore& store, state::LedgerState& ledger, uint16_t port = 8088,
               const std::string& data_dir = "data");
    ~HttpServer();

    HttpServer(const HttpServer&) = delete;
    HttpServer& operator=(const HttpServer&) = delete;

    void start();
    void stop();

    // Full route table behind a defensive catch-all. The HTTP worker
    // threads and the RPC fuzz target both enter through this: a hostile
    // body may produce an error response, never an exception escaping the
    // RPC surface (an uncaught throw in a worker thread would terminate
    // the whole node).
    HttpResponse route(const HttpRequest& req);

    // Parse a raw wire request (method line + headers + body) and route it.
    // Same header parser as the socket path; exists so the tests and the RPC
    // fuzzer can drive the byte-level HTTP parser directly (see scan_headers).
    HttpResponse route_raw(const std::string& raw);

    // The shared header scanner (socket path + route_raw): line-start exact
    // header names, first Content-Length wins, duplicate Authorization fails
    // closed. Public static so the framing rules are directly testable.
    static void scan_headers(const std::string& raw, size_t header_end,
                             size_t& content_length, HttpRequest& req);

    // Bind the VX60 P2P listener, register the block-relay hook and connect
    // to the given static peers (HOST:PORT each). Safe to call with no peers;
    // a failed bind only logs and leaves the node RPC-only.
    void attach_p2p(uint16_t p2p_port, const std::vector<std::string>& peer_endpoints);

    // Apply a block frame that arrived over VX60. Accepts a frame only when
    // it extends the current tip (height == chain_height and prev_block_hash
    // == tip hash); anything else is dropped. On success the frame is
    // re-broadcast to this node's peers so it gossips past its origin.
    bool apply_remote_frame(const void* frame);

private:
    void accept_loop();
    void handle_client(int client_fd);
    void handle_sse_client(int client_fd);

    HttpRequest parse_request(int client_fd, bool& ok);
    void send_response(int client_fd, const HttpResponse& res);
    // Sends one SSE frame with MSG_DONTWAIT|MSG_NOSIGNAL; returns false on
    // EAGAIN/EWOULDBLOCK or a short write — the Drop Slow Consumer signal.
    bool send_sse_data(int client_fd, const std::string& event, const std::string& data);
    HttpResponse dispatch(const HttpRequest& req);
    bool is_sse_client(int client_fd) const;

    // SSE client management
    void register_sse_client(int client_fd);
    void unregister_sse_client(int client_fd);
    void broadcast_sse_event(const std::string& event, const std::string& data);

    // API Endpoint Handlers

    // Shared admission path (BACKLOG 0.14 wiring): validates a signed PQ
    // transfer request and builds the transaction - JSON field extraction,
    // TDI screen, address parsing, balance and nonce checks against the
    // ledger, witness decode, full WOTS+/XMSS + SegPQ-anchor verification
    // and registry registration. Callers must hold state_mutex_. Returns an
    // error response, or std::nullopt when the request carries a fully
    // validated transaction (tx is filled, sender/receiver resolved).
    std::optional<HttpResponse> validate_signed_transfer(const HttpRequest& req,
                                                         blockchain::Transaction& tx,
                                                         blockchain::Address& sender_addr,
                                                         blockchain::Address& recv_addr);

    // Gossip one sealed frame: PQ witnesses first, then the frame (BACKLOG
    // 0.8 ordering - a peer without the witnesses cannot apply the block).
    void broadcast_frame_bytes(const uint8_t* frame65536);

    HttpResponse handle_status(const HttpRequest& req);
    HttpResponse handle_blocks(const HttpRequest& req);
    HttpResponse handle_accounts(const HttpRequest& req);
    HttpResponse handle_transfer(const HttpRequest& req);
    HttpResponse handle_security_audit(const HttpRequest& req);
    HttpResponse handle_crypto_lab(const HttpRequest& req);
    HttpResponse handle_sse_events(const HttpRequest& req);
    HttpResponse handle_crypto_benchmark(const HttpRequest& req);
    HttpResponse handle_mempool(const HttpRequest& req);
    HttpResponse handle_mempool_submit(const HttpRequest& req);
    HttpResponse handle_mempool_seal(const HttpRequest& req);
    HttpResponse handle_mempool_flood(const HttpRequest& req);
    HttpResponse handle_swarm_action(const HttpRequest& req);
    HttpResponse handle_chain_rewind(const HttpRequest& req);
    HttpResponse handle_frames_raw(const HttpRequest& req);

    // Miner RPC Endpoints
    HttpResponse handle_miner_start(const HttpRequest& req);
    HttpResponse handle_miner_stop(const HttpRequest& req);
    HttpResponse handle_miner_mine_one(const HttpRequest& req);
    HttpResponse handle_miner_status(const HttpRequest& req);

    // VM RPC Endpoints
    HttpResponse handle_vm_execute(const HttpRequest& req);
    HttpResponse handle_vm_presets(const HttpRequest& req);

 // RPC Endpoints
    HttpResponse handle_vault_memory(const HttpRequest& req);
    HttpResponse handle_vault_action(const HttpRequest& req);
    HttpResponse handle_zk_derive_matrix(const HttpRequest& req);
    HttpResponse handle_zk_recover_shamir(const HttpRequest& req);
    HttpResponse handle_zk_proof_of_life(const HttpRequest& req);
    HttpResponse handle_zk_audit_view(const HttpRequest& req);
    HttpResponse handle_neural_simulate(const HttpRequest& req);
    HttpResponse handle_crypto_canonical(const HttpRequest& req);

 // RPC Endpoints
    HttpResponse handle_mempool_zk_stats(const HttpRequest& req);

 // VX60 P2P wire + split-brain reorg
    HttpResponse handle_swarm_peers(const HttpRequest& req);
    HttpResponse handle_swarm_simulate_split_reorg(const HttpRequest& req);

    // Dandelion++ / Landauer VM / SGMT / Hamiltonian MEV
    HttpResponse handle_swarm_dandelion_stats(const HttpRequest& req);
    HttpResponse handle_swarm_relay_cocoon(const HttpRequest& req);
    HttpResponse handle_vm_execute_trace(const HttpRequest& req);
    HttpResponse handle_state_trie_root(const HttpRequest& req);
    HttpResponse handle_state_prove(const HttpRequest& req);
    HttpResponse handle_mempool_mev_audit(const HttpRequest& req);

    // ── GQC finality / pipeline / stealth / vault / HTLC swap ─────────────
    HttpResponse handle_consensus_finality_status(const HttpRequest& req);
    HttpResponse handle_consensus_finalize_gqc(const HttpRequest& req);
    HttpResponse handle_mempool_pipeline_benchmark(const HttpRequest& req);
    HttpResponse handle_zk_stealth_envelope(const HttpRequest& req);
    HttpResponse handle_zk_ivk_scan(const HttpRequest& req);
    HttpResponse handle_vault_ephemeral_sign(const HttpRequest& req);
    HttpResponse handle_vm_htlc_swap(const HttpRequest& req);

    // ── Telemetry // ── Telemetry & security fuzzing ─────────────────────────────────── security fuzzing ───────────────────────────────────
    HttpResponse handle_telemetry_rdtsc(const HttpRequest& req);
    HttpResponse handle_security_chaos_fuzz(const HttpRequest& req);

  // ── Post-Quantum WOTS+/XMSS ───────────────────────
    HttpResponse handle_crypto_pq_sign(const HttpRequest& req);
    HttpResponse handle_crypto_pq_verify(const HttpRequest& req);

    // JSON helpers (zero-dependency)
    static std::string json_escape(std::string_view s);
    static std::string hex_bytes(const uint8_t* data, size_t n);
    static std::string format_vx(uint64_t atomics);

    // -- RPC auth (BACKLOG 0.10) --------------------------------------------
    // Mutating endpoints (see is_mutating_endpoint) require the auth token,
    // read ONCE at construction from VX_RPC_TOKEN or VX_RPC_TOKEN_FILE.
    // Resource-heavy endpoints (see is_resource_heavy_endpoint) share the
    // same fail-closed gate. Fail closed: no token configured -> every
    // endpoint in either class answers 401; plain read-only endpoints stay
    // open. The comparison is constant-time.
    static bool is_mutating_endpoint(const HttpRequest& req) noexcept;
    static bool is_resource_heavy_endpoint(const HttpRequest& req) noexcept;
    static bool constant_time_equal(std::string_view a, std::string_view b) noexcept;
    bool token_ok(const HttpRequest& req) const;

    // Path normalization helper
    std::string normalize_path(const std::string& path);

    // Auth token state (never logged, never echoed back).
    std::string auth_token_;
    bool auth_enabled_ = false;

    storage::BlockStore& store_;
    state::LedgerState& ledger_;
    state::Mempool mempool_;
    std::unique_ptr<consensus::PoGWMiner> miner_;
    std::mutex state_mutex_;
    std::mutex sse_mutex_;
    uint16_t port_;
    int server_fd_ = -1;
    std::atomic<bool> running_{false};
    std::vector<int> sse_clients_;
    std::thread sse_broadcast_thread_;
    std::atomic<bool> sse_running_{false};

    // P2P Swarm Mesh
    std::unique_ptr<vx::net::SwarmNode> swarm_node_;

    // Chain rewind / undo
    std::string data_dir_;
    std::unique_ptr<vx::state::UndoEngine> undo_engine_;
    std::unique_ptr<vx::consensus::GqcFinality> gqc_finality_;
    std::unique_ptr<vx::core::RingPipeline> ring_pipeline_ =
        std::make_unique<vx::core::RingPipeline>();
    // Demo anchor for the HTLC endpoint: last created contract + secret.
    std::optional<vx::vm::VortexVM::HtlcContract> last_htlc_;

 // live RPC endpoints for vault / zk / neural / canonical identities
    vx::core::MemoryCore vault_core_;
    vx::core::LockStepScheduler lock_step_;
    vx::crypto::ZKKeyMatrix zk_matrix_;
    vx::math::TensorV6 tensor_v6_;
    vx::neural::VirtualTensor virtual_tensor_;

 // Sparse Galois Merkle Trie (live state-tree backend)
    std::unique_ptr<vx::state::GaloisTrie> trie_ =
        std::make_unique<vx::state::GaloisTrie>();
    std::array<uint8_t, 32> trie_root_cache_{};

 // Durable one-time-leaf registry for PQ signing (data_dir/pq_leaves.reg):
 // a leaf that signed once is never handed out again, across restarts and
 // concurrent signer processes.
    std::unique_ptr<vx::crypto::pq::PqLeafLedger> pq_leaf_ledger_;
};

} // namespace vx::rpc
