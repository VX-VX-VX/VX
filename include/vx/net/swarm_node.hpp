#pragma once

// VX60 Binary P2P Wire Protocol + Zero-Copy sendfile()
// Live Split-Brain Simulation & O(1) Chain Reorg
//
// WireHeader is exactly 24 bytes:
//   magic(4) | msg_type(1) | flags(1) | reserved(2) | payload_len(4) |
//   crc32c(4) | peer_nonce(8)
//
// Every inbound packet is hardware-verified (SSE4.2 CRC32C) before use.
// Corrupted packets are dropped without killing the connection.

#include "vx/blockchain/block.hpp"

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <cstring>
#include <deque>
#include <functional>
#include <iostream>
#include <map>
#include <mutex>
#include <netinet/in.h>
#include <set>
#include <span>
#include <string>
#include <thread>
#include <unordered_map>
#include <vector>

namespace vx::net {

class SwarmNode;

// ── VX60 Wire Protocol ───────────────────────────────────────────

inline constexpr uint32_t VX60_MAGIC = 0x56583630; // "VX60"

enum class WireMsgType : uint8_t {
    HANDSHAKE      = 0x01,
    INV            = 0x02,
    GET_BLOCK      = 0x03,
    RAW_BLOCK_64K  = 0x04,
    TX_COCOON_112B = 0x05,
    PING           = 0x06,
    PONG           = 0x07,
    GQC_VOTE       = 0x08,
};

// Wire flags
inline constexpr uint8_t WIRE_FLAG_ZERO_COPY       = 0x01;
inline constexpr uint8_t WIRE_FLAG_DANDELION_STEM  = 0x02;
inline constexpr uint8_t WIRE_FLAG_COMPRESSED      = 0x04;

struct alignas(8) WireHeader {
    uint32_t magic;        // 0x56583630 ("VX60")
    uint8_t  msg_type;     // WireMsgType
    uint8_t  flags;        // bit 0: zero-copy, bit 1: dandelion_stem, bit 2: compressed
    uint16_t reserved;     // 0x0000
    uint32_t payload_len;  // 0 .. 65536
    uint32_t crc32c;       // Hardware SSE4.2 CRC32C over payload
    uint64_t peer_nonce;   // Anti-replay session nonce
};

static_assert(sizeof(WireHeader) == 24, "WireHeader must be strictly 24 bytes");

/// Hardware SSE4.2 CRC32C over an arbitrary byte buffer.
uint32_t compute_wire_crc32c(const uint8_t* data, size_t len) noexcept;

/// Validate a received wire header: magic + payload_len bounds.
bool wire_header_plausible(const WireHeader& h) noexcept;

// ── Peer table ──────────────────────────────────────────────────────────────

struct PeerInfo {
    std::string address; // IP:port or "loopback"
    uint64_t node_id;    // 32-byte XOR key for Kademlia
    uint64_t height;     // Peer's blockchain height
    uint64_t work;       // Cumulative PoGW work
    uint64_t cumulative_pogw; // Cumulative Galois work (VX60 handshake field)
    int latency_ms;      // Round-trip latency measurement
    int dos_score;       // DoS reputation (0-100), auto-ban at 100
    bool is_banned;      // Immediate ban flag
    bool is_loopback;    // Local loopback peer for testing
    std::chrono::system_clock::time_point last_seen;

    // Kademlia XOR distance to our node ID
    uint64_t xor_distance() const;

    bool operator<(const PeerInfo& other) const;
};

// ── Dandelion++ ZK-Cocoon routing ─────────────────────────────────

// TxCocoon is exactly 128 bytes:
//   encrypted_tx(112) | stem_hops_remaining(1) | phase(1) | tdi_score_fp(2) |
//   cocoon_crc32c(4) | ephemeral_salt(8)
struct alignas(8) TxCocoon {
    uint8_t  encrypted_tx[112];    // Sponge-XOR masked Transaction
    uint8_t  stem_hops_remaining;  // 3..7 from hardware entropy
    uint8_t  phase;                // 0x01 = STEM, 0x02 = FLUFF
    uint16_t tdi_score_fp;         // fixed-point TDI density (spam gate)
    uint32_t cocoon_crc32c;        // SSE4.2 checksum over the cocoon
    uint64_t ephemeral_salt;       // mask layer salt (per hop)
};

static_assert(sizeof(TxCocoon) == 128, "TxCocoon must be strictly 128 bytes");

inline constexpr uint8_t  COCOON_PHASE_STEM  = 0x01;
inline constexpr uint8_t  COCOON_PHASE_FLUFF = 0x02;
inline constexpr uint16_t COCOON_MIN_TDI_THRESHOLD = 100; // fixed-point gate
inline constexpr uint8_t  COCOON_MAX_HOPS = 7;
inline constexpr uint8_t  COCOON_MIN_HOPS = 3;

/// Per-hop Dandelion++ relay trace record (for RPC traceability).
struct CocoonHopTrace {
    uint32_t hop_index = 0;
    std::string phase;             // "STEM" | "FLUFF"
    std::string cocoon_hash_hex;   // sponge hash of the masked cocoon payload
    uint8_t hops_remaining = 0;
    bool ip_source_erased = true;  // inbound socket identity wiped before relay
    bool forwarded = true;
    std::string action;            // "relayed" | "burned" | "broadcast"
};

/// Aggregate Dandelion++ statistics (GET /api/swarm/dandelion_stats).
struct DandelionStats {
    uint64_t stem_relays = 0;
    uint64_t fluff_broadcasts = 0;
    uint64_t tdi_spam_annihilated = 0;
    double avg_stem_hops = 0.0;
    uint64_t anonymity_set_size = 0;
};

/// Result of POST /api/swarm/relay_cocoon.
struct CocoonRelayReport {
    bool ok = false;
    std::string error;
    std::vector<CocoonHopTrace> hops;
    DandelionStats stats;
    uint64_t vx60_bytes_transferred = 0;
};

// ── Split-brain reorg report ─────────────────────────────────────

struct SplitBrainReport {
    bool started = false;
    bool reorg_success = false;
    uint64_t duration_us = 0;

    // Isolation phase
    uint64_t node_a_height = 0;
    uint64_t node_b_height = 0;
    std::string node_a_tip_hex;
    std::string node_b_tip_hex;
    uint64_t node_a_work = 0;
    uint64_t node_b_work = 0;

    // Heal & sync phase
    uint64_t blocks_rolled_back = 0;   // undo.vxl O(1) rollback count
    uint64_t blocks_resynced = 0;      // RAW_BLOCK_64K sendfile transfers
    uint64_t vx60_bytes_transferred = 0;

    // Final invariant
    uint64_t final_height = 0;
    std::string final_tip_hex;
    bool tip_hashes_match = false;
    std::string error;
};

// ── SwarmNode ───────────────────────────────────────────────────────────────

class SwarmNode {
public:
    static constexpr uint8_t MAX_PEERS = 7; // 7 mesh peers + loopback
    static constexpr uint32_t OUR_NODE_ID = 0x58564336; // VX magic number

    SwarmNode();
    ~SwarmNode();

    SwarmNode(const SwarmNode&) = delete;
    SwarmNode& operator=(const SwarmNode&) = delete;

    // Start P2P networking threads
    void start();

    // Emergency stop — halts all P2P worker threads and closes every peer socket
    void emergency_stop();

    // Thread-safe broadcast of a 64KB frame to all peers
    void broadcast_frame(const std::span<const uint8_t, 65536>& frame);

    // Simulate split-brain fork - create alternative history on peer partition
    void simulate_fork();

    // Inject rogue peer for testing
    void inject_rogue_peer();

    // Get current peer table snapshot
    std::vector<PeerInfo> get_peer_table() const;

    // Handle incoming frame from peer
    void handle_incoming_frame(const std::string& from_peer, const std::span<const uint8_t, 65536>& frame);

    // Register a callback invoked for every verified 64 KiB block frame that
    // arrives over the P2P listener. The node layer (RPC server / main) owns
    // the decision to apply, relay or drop the frame; the wire layer only
    // guarantees CRC32C integrity and the BLOCK_MAGIC prefix.
    using FrameHook = std::function<void(const uint8_t* frame, size_t len)>;
    void set_frame_hook(FrameHook hook);

  // ── VX60 wire protocol ────────────────────────────────────────

    // Build a 24-byte WireHeader for a payload (computes hardware CRC32C).
    static WireHeader make_header(WireMsgType type, uint32_t payload_len,
                                  uint64_t nonce, uint8_t flags = 0) noexcept;

    // Blocking send of header + payload on a socket fd. Returns bytes sent.
    uint64_t send_packet(int fd, const WireHeader& hdr, const uint8_t* payload);

    // Receive + validate one VX60 packet. Returns false on corruption/EOF.
    // On success fills hdr and payload (resized to payload_len).
    bool recv_packet(int fd, WireHeader& hdr, std::vector<uint8_t>& payload);

    // Wire statistics
    uint64_t corrupted_packets_dropped() const noexcept { return corrupted_packets_dropped_.load(); }
    uint64_t zero_copy_bytes_sent() const noexcept { return zero_copy_bytes_sent_.load(); }
    uint64_t zero_copy_blocks_streamed() const noexcept { return zero_copy_blocks_streamed_.load(); }
    uint64_t vx60_bytes_transferred() const noexcept { return vx60_bytes_transferred_.load(); }
    uint32_t wire_magic() const noexcept { return VX60_MAGIC; }

    // Zero-copy block streaming: sends a 24B header (RAW_BLOCK_64K) followed by
    // ::sendfile() of the 65536-byte frame at block_height from ledger_fd.
    // Falls back to ::send() when ledger_fd < 0 (in-memory mode) using
    // block_data (may be nullptr only when ledger_fd >= 0).
    bool send_block_zero_copy(int socket_fd, int ledger_fd, uint64_t block_height,
                              const uint8_t* block_data = nullptr);

  // ── Dandelion++ ZK-Cocoon routing ─────────────────────────────

    // Build a cocoon around a transaction: Sponge-XOR mask layer, hardware
    // entropy hop count (3..7), TDI fixed-point gate, CRC32C integrity.
    static TxCocoon seal_cocoon(const blockchain::Transaction& tx,
                                uint16_t tdi_score_fp) noexcept;

    // Unmask the 112-byte transaction using the cocoon's ephemeral salt.
    static blockchain::Transaction open_cocoon(const TxCocoon& cocoon) noexcept;

    // One relay step: TDI gate -> re-mask with a fresh salt layer -> hop
    // countdown. Returns false if the cocoon was burned (spam TDI) or is
    // corrupt. Updates stem_relays_/fluff_broadcasts_/tdi_spam_annihilated_.
    bool relay_cocoon_step(TxCocoon& cocoon, CocoonHopTrace& trace);

    // Full Stem -> Fluff cycle for RPC /api/swarm/relay_cocoon.
    CocoonRelayReport relay_cocoon_full_cycle(const blockchain::Transaction& tx,
                                              uint16_t tdi_score_fp);

    // Aggregate statistics snapshot.
    DandelionStats dandelion_stats() const noexcept;

  // ── live split-brain reorg ────────────────────────────────────

    // Runs the full Partition -> Heal -> O(1) Reorg cycle using two isolated
    // in-process nodes (BlockStore + LedgerState) bridged by real VX60 TCP
    // loopback sockets (HANDSHAKE + RAW_BLOCK_64K via sendfile).
    SplitBrainReport simulate_live_split_brain_reorg();

    // P2P listener port for this node (0 = not bound yet)
    uint16_t listen_port() const noexcept { return listen_port_.load(); }

    // Peer connection tracking (fd per address) for the live TCP path
    bool connect_peer_tcp(const std::string& host, uint16_t port);
    void close_all_peers();

    // Bind a VX60 listener socket (used by the split-brain simulation and by
    // --p2p mode). Returns false if the port is already taken.
    bool bind_p2p_listener(uint16_t port);

private:
    // P2P networking threads
    std::thread listener_thread_;
    std::thread gossip_thread_;
    std::thread health_thread_;

    // Synchronization
    mutable std::mutex peers_mutex_;
    std::condition_variable peers_cv_;
    std::atomic<bool> running_{false};
    std::atomic<bool> emergency_stop_requested_{false};

    // Peer table
    std::set<PeerInfo> peer_table_;

    // Live TCP connections: address -> socket fd
    std::unordered_map<std::string, int> peer_fds_;

    // Listener socket
    int listen_fd_ = -1;
    std::atomic<uint16_t> listen_port_{0};

    // Accepted connection sockets, tracked so emergency_stop() can shut them
    // down and unblock the listener thread's blocking recv.
    std::mutex accepted_mu_;
    std::set<int> accepted_fds_;
    void shutdown_accepted();

    // One handler thread per accepted connection (serving it until EOF), so
    // a persistent peer connection never blocks accept() for the next peer.
    std::mutex handlers_mu_;
    std::vector<std::thread> conn_handlers_;
    void serve_connection(int fd);

    // One reader thread per outgoing peer connection: ingests VX60 packets
    // (PONG keepalives, RAW_BLOCK_64K frames) from sockets we dialed.
    std::mutex readers_mu_;
    std::vector<std::thread> peer_readers_;
    void peer_reader_loop(int fd, std::string label);

    // Callback for verified inbound block frames (set by the node layer)
    FrameHook frame_hook_;

    // VX60 wire statistics (atomic: updated from multiple threads)
    std::atomic<uint64_t> corrupted_packets_dropped_{0};
    std::atomic<uint64_t> zero_copy_bytes_sent_{0};
    std::atomic<uint64_t> zero_copy_blocks_streamed_{0};
    std::atomic<uint64_t> vx60_bytes_transferred_{0};
    std::atomic<uint64_t> session_nonce_{0x5658363000000000ULL};

 // Dandelion++ routing statistics
    std::atomic<uint64_t> stem_relays_{0};
    std::atomic<uint64_t> fluff_broadcasts_{0};
    std::atomic<uint64_t> tdi_spam_annihilated_{0};
    std::atomic<uint64_t> stem_hops_sum_{0};
    std::atomic<uint64_t> stem_cycles_count_{0};
    std::atomic<uint64_t> anonymity_set_size_{8}; // floor: our node + 7 mesh peers

 // standalone split-brain cluster state lives in the .cpp
    // (pimpl-style) to keep BlockStore/LedgerState out of this header.

    // Add loopback peer
    void add_loopback_peer();

    // Listener thread - accepts connections from peers
    void listener_loop();

    // Gossip thread - broadcasts tip to peers
    void gossip_loop();

    // Health monitoring - measures latency, checks DoS scores
    void health_loop();

    // Connect to a peer (virtual mesh connection)
    bool connect_to_peer(const PeerInfo& peer);

    // Disconnect from a peer
    void disconnect_from_peer(const PeerInfo& peer);

    // Send frame to peer using sendfile() zero-copy if available
    bool send_frame_to_peer(int fd, const std::span<const uint8_t, 65536>& frame);

    // Verify frame signature and content
    bool verify_frame(const std::span<const uint8_t, 65536>& frame);

    // Ban peer for DoS
    void ban_peer(const std::string& address, int score_increment);

    // Resolve split-brain fork using heaviest cumulative work
    void resolve_fork(const PeerInfo& challenger);
};

} // namespace vx::net
