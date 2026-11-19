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
#include "vx/crypto/pq_signature.hpp"
#include "vx/net/vx60_sec.hpp"

#include <array>
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
    HANDSHAKE = 0x01,
    INV = 0x02,
    GET_BLOCK = 0x03,
    RAW_BLOCK_64K = 0x04,
    TX_COCOON_112B = 0x05,
    PING = 0x06,
    PONG = 0x07,
    GQC_VOTE = 0x08,
    PQ_WITNESS = 0x09,    // BACKLOG 0.8: consensus-visible PQ signature
    ROLLOVER_CERT = 0x0A, // BACKLOG 1.5: certified one-window key rotation
    // BACKLOG 1.5 P0 GATE: certificate backfill. CERT_INV announces ids of
    // stored certificates (connect-time retention + relay); a peer that
    // misses one answers GET_CERTS with the unknown ids and receives the
    // FULL verified certificate records targeted. Payload for both:
    // count(u32 LE) + count * 32-byte cert ids, count <= 64.
    CERT_INV = 0x0B,
    GET_CERTS = 0x0C,
    // Peer discovery (BACKLOG: DNS seeds / peer exchange). ADDRS is a
    // one-shot push per connection, sent by BOTH sides right after the
    // HANDSHAKE exchange: count(u32 LE) + count * [IPv4(4) | port(u16 BE)],
    // count <= 16. Entries are LISTEN addresses only - never the observed
    // (ephemeral-port) address of a connection - so a dialed node is
    // reachable again by a third node. The old fail-closed rule is
    // preserved one notch further out: 0x0E still fails closed.
    ADDRS = 0x0D,
    // DKSAP wire integration: digest-keyed sidecar records. SGMT_REG =
    // digest(32) + nlen(1) + nickname(n, 1..32) + PublicKeys(1568) for an
    // on-chain SGMTLEAF registration (consensus-visible: the receiving
    // node can only apply the dependent block once this record is in the
    // registry). STEALTH = digest(32) + StealthTx(1540) for an on-chain
    // STEALTH transfer (radar-only, never consensus). Both keyed by
    // tx_msg_digest — a record replayed under a foreign digest cannot
    // pass the leaf gate.
    DKSAP_SGMT_REG = 0x0E,
    DKSAP_STEALTH = 0x0F,
    // VX60-SEC M2 (owner-directed 2026-11-15): the encrypted-transport
    // upgrade. 0x10-0x12 are the handshake frames; 0x13 is RESERVED for the
    // M4 key rotation — receiving it is a protocol violation for now
    // (strike + drop, never silently ignored).
    SEC_CLIENT_HELLO = 0x10,
    SEC_SERVER_HELLO = 0x11,
    SEC_PK_RESPONSE = 0x12,
    SEC_KEM_ROTATE = 0x13,
};

// Wire flags
inline constexpr uint8_t WIRE_FLAG_ZERO_COPY = 0x01;
inline constexpr uint8_t WIRE_FLAG_DANDELION_STEM = 0x02;
inline constexpr uint8_t WIRE_FLAG_COMPRESSED = 0x04;

struct alignas(8) WireHeader {
    uint32_t magic;       // 0x56583630 ("VX60")
    uint8_t msg_type;     // WireMsgType
    uint8_t flags;        // bit 0: zero-copy, bit 1: dandelion_stem, bit 2: compressed
    uint16_t reserved;    // 0x0000
    uint32_t payload_len; // 0 .. 65536
    uint32_t crc32c;      // Hardware SSE4.2 CRC32C over payload
    uint64_t peer_nonce;  // Anti-replay session nonce
};

static_assert(sizeof(WireHeader) == 24, "WireHeader must be strictly 24 bytes");

/// Hardware SSE4.2 CRC32C over an arbitrary byte buffer.
uint32_t compute_wire_crc32c(const uint8_t *data, size_t len) noexcept;

/// Validate a received wire header: magic + payload_len bounds.
bool wire_header_plausible(const WireHeader &h) noexcept;

// ── Peer table ──────────────────────────────────────────────────────────────

struct PeerInfo {
    std::string address;      // IP:port or "loopback"
    uint64_t node_id;         // 32-byte XOR key for Kademlia
    uint64_t height;          // Peer's blockchain height
    uint64_t work;            // Cumulative PoGW work
    uint64_t cumulative_pogw; // Cumulative Galois work (VX60 handshake field)
    int latency_ms;           // Round-trip latency measurement
    int dos_score;            // DoS reputation (0-100), auto-ban at 100
    bool is_banned;           // Immediate ban flag
    bool is_loopback;         // Local loopback peer for testing
    std::chrono::system_clock::time_point last_seen;

    // Peer discovery (ADDRS / handshake v2): the peer's LISTENING endpoint,
    // as it announced itself. Only listen addresses are ever advertised in
    // ADDRS - an observed address carries the outbound ephemeral port and
    // is worthless to a third node. listen_valid is false for old-world
    // peers that never sent the v2 handshake fields (48-byte payload).
    uint32_t listen_ip = 0;   // network byte order
    uint16_t listen_port = 0; // host byte order
    bool listen_valid = false;

    // Kademlia XOR distance to our node ID
    uint64_t xor_distance() const;

    bool operator<(const PeerInfo &other) const;
};

// ── Dandelion++ ZK-Cocoon routing ─────────────────────────────────

// TxCocoon is exactly 128 bytes:
//   encrypted_tx(112) | stem_hops_remaining(1) | phase(1) | tdi_score_fp(2) |
//   cocoon_crc32c(4) | ephemeral_salt(8)
struct alignas(8) TxCocoon {
    uint8_t encrypted_tx[112];   // Sponge-XOR masked Transaction
    uint8_t stem_hops_remaining; // 3..7 from hardware entropy
    uint8_t phase;               // 0x01 = STEM, 0x02 = FLUFF
    uint16_t tdi_score_fp;       // fixed-point TDI density (spam gate)
    uint32_t cocoon_crc32c;      // SSE4.2 checksum over the cocoon
    uint64_t ephemeral_salt;     // mask layer salt (per hop)
};

static_assert(sizeof(TxCocoon) == 128, "TxCocoon must be strictly 128 bytes");

inline constexpr uint8_t COCOON_PHASE_STEM = 0x01;
inline constexpr uint8_t COCOON_PHASE_FLUFF = 0x02;
inline constexpr uint16_t COCOON_MIN_TDI_THRESHOLD = 100; // fixed-point gate
inline constexpr uint8_t COCOON_MAX_HOPS = 7;
inline constexpr uint8_t COCOON_MIN_HOPS = 3;

/// Per-hop Dandelion++ relay trace record (for RPC traceability).
struct CocoonHopTrace {
    uint32_t hop_index = 0;
    std::string phase;           // "STEM" | "FLUFF"
    std::string cocoon_hash_hex; // sponge hash of the masked cocoon payload
    uint8_t hops_remaining = 0;
    bool ip_source_erased = true; // inbound socket identity wiped before relay
    bool forwarded = true;
    std::string action; // "relayed" | "burned" | "broadcast"
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
    uint64_t blocks_rolled_back = 0; // undo.vxl O(1) rollback count
    uint64_t blocks_resynced = 0;    // RAW_BLOCK_64K sendfile transfers
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
    static constexpr uint8_t MAX_PEERS = 7;             // 7 mesh peers + loopback
    static constexpr uint32_t OUR_NODE_ID = 0x58564336; // VX magic number

    SwarmNode();
    ~SwarmNode();

    SwarmNode(const SwarmNode &) = delete;
    SwarmNode &operator=(const SwarmNode &) = delete;

    // Start P2P networking threads
    void start();

    // Emergency stop — halts all P2P worker threads and closes every peer socket
    void emergency_stop();

    // Thread-safe broadcast of a 64KB frame to all peers
    void broadcast_frame(const std::span<const uint8_t, 65536> &frame);

    // BACKLOG 0.8: consensus-visible PQ witnesses. Broadcasts a PQ_WITNESS
    // record for every user transaction of the frame that has a witness in
    // the registry — call this BEFORE broadcast_frame so receiving nodes
    // can verify the block's transactions on arrival. System senders
    // (GENESIS*/MINER_) need no witness.
    void broadcast_witnesses_for(const std::span<const uint8_t, 65536> &frame);

    // BACKLOG 1.5: relay a certified one-window key rotation. The payload
    // layout is sender(42) + from_window(4) + to_window(4) + old_root(32) +
    // new_root(32) + witness(2376) = 2490 bytes; the receiving node
    // verifies the FULL certificate object before storing it (nothing
    // unverified is ever stored). Old nodes that do not know type 0x0A
    // drop the connection - the established fail-closed old/new separation
    // for unknown message types.
    void broadcast_rollover_cert(const vx::crypto::pq::PqRolloverCert &cert);

    // DKSAP wire integration: broadcast the sidecar records the frame's
    // transactions need. For every STEALTH receiver the StealthTx bundle
    // (digest(32) + bundle(1540)) and for every SGMTLEAF receiver the
    // registration record (digest(32) + nlen(1) + nickname + keys(1568))
    // is looked up by the tx digest and relayed — call BEFORE
    // broadcast_frame so receiving nodes can resolve their parked frames
    // on arrival. A missing record is skipped (nothing to relay).
    void broadcast_sidecars_for(const std::span<const uint8_t, 65536> &frame);

    // BACKLOG 1.5 P0 GATE: cert backfill. Announces to ONE peer the ids of
    // this node's most recently stored certificates (connect-time
    // retention; max_ids is capped at 64 by the wire format). The peer
    // pulls what it misses with GET_CERTS and receives full verified
    // records targeted.
    void send_cert_inv_to(const std::string &peer_label, size_t max_ids);

    // Simulate split-brain fork - create alternative history on peer partition
    void simulate_fork();

    // Inject rogue peer for testing
    void inject_rogue_peer();

    // Get current peer table snapshot
    std::vector<PeerInfo> get_peer_table() const;

    // Handle incoming frame from peer. id (when non-null) is the sender's
    // announced durable identity: a failed verification scores BOTH keys
    // (address + identity, PEX 2/2).
    void handle_incoming_frame(const std::string &from_peer,
                               const std::span<const uint8_t, 65536> &frame,
                               const std::array<uint8_t, 32> *id = nullptr);

    // Register a callback invoked for every verified 64 KiB block frame that
    // arrives over the P2P listener. The node layer (RPC server / main) owns
    // the decision to apply, relay or drop the frame; the wire layer only
    // guarantees CRC32C integrity and the BLOCK_MAGIC prefix.
    // The label names the sending peer (IP:port) so the intake layer can
    // attribute witness-commitment violations per peer (BACKLOG 2.11
    // third checkbox).
    using FrameHook =
        std::function<void(const uint8_t *frame, size_t len, const std::string &peer_label)>;
    void set_frame_hook(FrameHook hook);

    // DKSAP wire integration: invoked when a sidecar record arrives over
    // the wire (DKSAP_SGMT_REG / DKSAP_STEALTH). The node layer retries
    // any parked frames whose SGMT registration sidecar just arrived (the
    // analog of the witness retry hook).
    using SidecarHook = std::function<void(const std::array<uint8_t, 32> &digest)>;
    void set_sidecar_callback(SidecarHook hook);

    // BACKLOG 2.11 stage 2: fired on BOTH reader loops after a PQ_WITNESS
    // message is registered in the witness registry, so the intake layer
    // (HttpServer) can retry block frames it parked pending witnesses. The
    // callback runs on the reader thread with NO swarm locks held - the
    // callee owns its own locking (the established state_mutex_ ->
    // seal_mutex_ order; it may re-enter broadcast paths that take
    // peers_mutex_ last, which is consistent with the existing hook).
    using WitnessCallback = std::function<void(const std::array<uint8_t, 32> &digest)>;
    void set_witness_callback(WitnessCallback cb);

    // BACKLOG 2.11 third checkbox (retention): fired once when a peer
    // connection is promoted to a tracked broadcast target - inbound
    // after its first verified packet, outbound right after the dial
    // registers. The node layer uses it to serve the witness-retention
    // window to the freshly connected peer.
    using PeerConnectedCallback = std::function<void(const std::string &peer_label)>;
    void set_peer_connected_callback(PeerConnectedCallback cb);

    // Sends the PQ witnesses this node holds for ONE block frame to a
    // single peer (the retention backfill path; broadcast_witnesses_for
    // remains the one-hop gossip fan-out). Returns false when the label
    // names no connected peer.
    bool send_witnesses_to(const std::string &peer_label,
                           const std::span<const uint8_t, 65536> &frame);

    // BACKLOG 2.11 third checkbox: the intake layer reports a peer whose
    // block header committed a witness set no canonical rule produces
    // (withholding / lying commitment). Reuses the DoS reputation
    // machinery: dos_score += score_increment, auto-ban at 100. The
    // recommended strike weight is 34 (three strikes ban).
    void report_withhold(const std::string &peer_address, int score_increment);

    // True when the peer's DoS reputation crossed the ban threshold.
    bool peer_is_banned(const std::string &peer_address) const;

    // ── VX60 wire protocol ────────────────────────────────────────

    // Build a 24-byte WireHeader for a payload (computes hardware CRC32C).
    static WireHeader make_header(WireMsgType type, uint32_t payload_len, uint64_t nonce,
                                  uint8_t flags = 0) noexcept;

    // Blocking send of header + payload on a socket fd. Returns bytes sent.
    uint64_t send_packet(int fd, const WireHeader &hdr, const uint8_t *payload);

    // Receive + validate one VX60 packet. Returns false on corruption/EOF.
    // On success fills hdr and payload (resized to payload_len).
    bool recv_packet(int fd, WireHeader &hdr, std::vector<uint8_t> &payload);

    // Wire statistics
    uint64_t corrupted_packets_dropped() const noexcept {
        return corrupted_packets_dropped_.load();
    }
    uint64_t zero_copy_bytes_sent() const noexcept {
        return zero_copy_bytes_sent_.load();
    }
    uint64_t zero_copy_blocks_streamed() const noexcept {
        return zero_copy_blocks_streamed_.load();
    }
    uint64_t vx60_bytes_transferred() const noexcept {
        return vx60_bytes_transferred_.load();
    }
    uint32_t wire_magic() const noexcept {
        return VX60_MAGIC;
    }

    // Zero-copy block streaming: sends a 24B header (RAW_BLOCK_64K) followed by
    // ::sendfile() of the 65536-byte frame at block_height from ledger_fd.
    // Falls back to ::send() when ledger_fd < 0 (in-memory mode) using
    // block_data (may be nullptr only when ledger_fd >= 0).
    bool send_block_zero_copy(int socket_fd, int ledger_fd, uint64_t block_height,
                              const uint8_t *block_data = nullptr);

    // ── Dandelion++ ZK-Cocoon routing ─────────────────────────────

    // Build a cocoon around a transaction: Sponge-XOR mask layer, hardware
    // entropy hop count (3..7), TDI fixed-point gate, CRC32C integrity.
    static TxCocoon seal_cocoon(const blockchain::Transaction &tx, uint16_t tdi_score_fp) noexcept;

    // Unmask the 112-byte transaction using the cocoon's ephemeral salt.
    static blockchain::Transaction open_cocoon(const TxCocoon &cocoon) noexcept;

    // One relay step: TDI gate -> re-mask with a fresh salt layer -> hop
    // countdown. Returns false if the cocoon was burned (spam TDI) or is
    // corrupt. Updates stem_relays_/fluff_broadcasts_/tdi_spam_annihilated_.
    bool relay_cocoon_step(TxCocoon &cocoon, CocoonHopTrace &trace);

    // Full Stem -> Fluff cycle for RPC /api/swarm/relay_cocoon.
    CocoonRelayReport relay_cocoon_full_cycle(const blockchain::Transaction &tx,
                                              uint16_t tdi_score_fp);

    // Aggregate statistics snapshot.
    DandelionStats dandelion_stats() const noexcept;

    // ── live split-brain reorg ────────────────────────────────────

    // Runs the full Partition -> Heal -> O(1) Reorg cycle using two isolated
    // in-process nodes (BlockStore + LedgerState) bridged by real VX60 TCP
    // loopback sockets (HANDSHAKE + RAW_BLOCK_64K via sendfile).
    SplitBrainReport simulate_live_split_brain_reorg();

    // P2P listener port for this node (0 = not bound yet)
    uint16_t listen_port() const noexcept {
        return listen_port_.load();
    }

    // Peer connection tracking (fd per address) for the live TCP path
    bool connect_peer_tcp(const std::string &host, uint16_t port);
    void close_all_peers();

    // Bind a VX60 listener socket (used by the split-brain simulation and by
    // --p2p mode). Returns false if the port is already taken.
    bool bind_p2p_listener(uint16_t port);

    // ── Peer discovery (ADDRS / PEX) ──────────────────────────────

    // Durable node identity for the v2 handshake: 32 random bytes created
    // once and persisted at data_dir/node_id (0600, O_EXCL). A peer that
    // announces OUR node_id is ourselves (self-dial through discovery) and
    // is disconnected on sight. Must be called once before start(); with
    // no call the node sends a zero id and self-detection is disabled
    // (48-byte old-world handshake).
    void load_or_create_node_id(const std::string &data_dir);
    void load_vx60_identity(const std::string &data_dir);

    /// The VX60-SEC transport node_id (sponge of the static ML-KEM pk).
    /// Zero until load_or_create_node_id() loads the transport identity.
    const std::array<uint8_t, 32> &vx60_node_id() const noexcept {
        return vx60_id_.node_id;
    }
    bool vx60_ready() const noexcept {
        return vx60_id_loaded_;
    }

    // ── PEX 2/2: node_id-keyed strikes + durable banlist ─────────
    // (security review 2026-11-11 gap, closed 2026-11-15) Strikes land on
    // BOTH keys: the connection label (covers pre-handshake misbehavior,
    // where no identity is known yet) and the announced 32-byte durable
    // identity. Rotating source ports no longer launders a score: fresh
    // ports still announce the SAME identity, and the identity carries the
    // strikes. A banned identity is dropped at handshake on every future
    // connection and survives restarts through <data_dir>/banlist (0600).
    //
    // DORMANT GATE (security review 2026-11-15, HIGH): the v2 handshake
    // id is NOT authenticated — a spoofer can announce a victim's id
    // and self-strike it, turning identity-keyed enforcement into a
    // censorship primitive. Until identities are authenticated
    // (VX60-SEC KEM-PoP), ALL identity-keyed ENFORCEMENT is dormant:
    // report_id_strike is a no-op, id_is_banned is false, nothing is
    // written to the durable banlist, no connection is dropped by id.
    // Address-keyed strikes keep working (pre-handshake surface). The
    // gate flips ON only where the handshake proves key possession.

    // Attach the durable banlist. Must be called once, before start(); an
    // absent file is an empty banlist (first boot). Load is fail-closed
    // per line: a malformed row is skipped with a warning, never fatal and
    // never a silent unban. Rows are DATA while dormant: they load into
    // the in-memory reputation map but enforce nothing until the gate
    // is enabled.
    void attach_banlist_path(const std::string &data_dir);

    // Score a protocol violation against the announced identity, in
    // ADDITION to the address-keyed call the site already makes. A zero id
    // (old-world announce) carries no identity to key on: no-op. Crossing
    // 100 bans the identity durably and drops every live connection that
    // announced it. NO-OP while identity enforcement is dormant
    // (unauthenticated ids must never trigger durable bans).
    void report_id_strike(const std::array<uint8_t, 32> &id, int score_increment);

    // True when the identity is on the durable banlist AND identity
    // enforcement is enabled. Always false while dormant.
    bool id_is_banned(const std::array<uint8_t, 32> &id) const;

    // Dormant-gate control. VX60-SEC (KEM-PoP handshake) enables identity
    // enforcement after proving key possession; tests use the _for_test
    // seam. Default: OFF (dormant).
    void enable_id_enforcement() {
        // The flag is atomic: callers may already hold peers_mutex_ (the
        // SEC channel-creation path) — no lock here, ever.
        id_enforcement_enabled_.store(true, std::memory_order_relaxed);
    }
    bool id_enforcement_enabled() const noexcept {
        return id_enforcement_enabled_.load();
    }
    void set_id_enforcement_for_test(bool enabled) {
        id_enforcement_enabled_.store(enabled);
    }

    const std::array<uint8_t, 32> &node_id() const noexcept {
        return node_id_;
    }

    // Test seam: force a known node id (e.g. two nodes sharing one id for
    // the self-dial test). In-memory only; does not touch any file.
    void set_node_id_for_test(const std::array<uint8_t, 32> &id) {
        node_id_ = id;
    }

    // Feed one listen address into the candidate store (from --seed DNS
    // resolution or the ADDRS wire). Deduped by ip:port, bounded (oldest
    // evicted). Callers never cause a dial directly: the health loop dials
    // at most ONE candidate per 5 s tick and only while connected peers
    // are below the discovery floor.
    // operator_supplied=true marks operator configuration (--seed hosts):
    // the loopback gate is a defense against PEER-supplied targets only.
    bool add_addr_candidate(uint32_t ip_net, uint16_t port, bool operator_supplied = false);

    // Test/diagnostic: current candidate count.
    size_t addr_candidate_count() const;

    // --seed client side: resolve HOST or HOST:PORT (default VX60 19088)
    // with getaddrinfo and feed every A record into the candidate store.
    // Failure to resolve is a warning, never a node failure (a seed host
    // may be down; the mesh does not depend on it once connected).
    // Returns the number of candidates queued.
    size_t add_seed_host(const std::string &host_or_hostport);

    // The endpoint this node advertises in HANDSHAKE v2 / ADDRS. Set by
    // bind_p2p_listener; ip is the best non-loopback IPv4 (loopback as the
    // fallback), 0 when no listener is bound (then listen_valid is false
    // and the node advertises nothing).
    uint32_t self_listen_ip() const noexcept {
        return self_listen_ip_;
    }
    uint16_t self_listen_port() const noexcept {
        return listen_port_.load();
    }

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

    // ── Peer discovery state (guarded by peers_mutex_) ─────────────
    // Listen addresses learned from ADDRS / --seed. Bounded: oldest
    // evicted at 128 entries. The health loop drains candidates OUTSIDE
    // peers_mutex_ (connect_peer_tcp takes it internally) and dials at
    // most one per tick.
    struct PeerCandidate {
        uint32_t ip;      // network byte order
        uint16_t port;    // host byte order
        int attempts = 0; // failed dial count; evicted at 3
    };
    static constexpr size_t kMaxAddrCandidates = 128;
    static constexpr size_t kMinAutoDialPeers = 3;
    static constexpr int kMaxCandidateAttempts = 3;
    std::deque<PeerCandidate> addr_candidates_;

    // Durable node identity (v2 handshake); zero = unknown/old-world.
    std::array<uint8_t, 32> node_id_{};

    // ── VX60-SEC M2: encrypted transport ─────────────────────────────────
    // The transport identity loads beside the legacy node_id (in
    // load_or_create_node_id); a load failure runs the transport
    // identityless (logged) rather than wedging the node.
    vx60::TransportIdentity vx60_id_{};
    bool vx60_id_loaded_ = false;
    // Per-connection encrypted channels keyed by fd (guarded by
    // peers_mutex_). am_initiator selects the nonce direction: the
    // INITIATOR of the SEC upgrade seals with nonce_c, the responder with
    // nonce_s.
    struct SecChannel {
        vx60::SessionKeys keys{};
        uint64_t send_ctr = 0;
        uint64_t recv_ctr = 0;
        bool am_initiator = false;
    };
    std::map<int, SecChannel> sec_channels_;
    // Hygiene 2b (owner-directed 19.11): per-IP accepted-connection cap.
    // Checked on the accept path (serve_connection entry), released by an
    // RAII guard at function exit — no teardown-site bookkeeping.
    static constexpr size_t kMaxConnsPerIp = 8;
    std::map<uint32_t, uint32_t> active_per_ip_; // guarded by peers_mutex_
    // Transport-pk cache: node_id -> static pk of PROVEN SEC peers (fills
    // on every successful handshake; WARM reuses it, first contact = COLD).
    std::map<std::array<uint8_t, 32>, vx::crypto::mlkem::PublicKey> vx60_pk_cache_;
    // Peers that answered the SEC upgrade with a strike/drop (do not speak
    // SEC): skip the upgrade for them this session so legacy peers are not
    // strike-poisoned by the migration probe.
    std::set<std::array<uint8_t, 32>> no_sec_peers_;
    // Node-wide enforcement flip: once any SEC session proves a peer
    // identity, identity-keyed enforcement wakes (the PEX dormant gate).
    bool sec_enforcement_armed_ = false;

    // ── Dandelion++ M3 (owner-directed 19.11; privacy payload classes
    // only — SGMT_REG/STEALTH; blocks/SEC/CERT never stem) ───────────────
    // EPOCH stem channels (the "++" essence): the stem peer set is FIXED
    // per epoch (~5-10 min), not per transaction — a Sybil cannot
    // statistically recover the originator across a transaction series.
    static constexpr size_t kDandelionStemPeers = 2;
    static constexpr uint64_t kDandelionEpochMs = 5 * 60 * 1000;
    static constexpr size_t kDandelionSeenCap = 4096;
    static constexpr uint64_t kDandelionSeenTtlMs = 10 * 60 * 1000;
    static constexpr uint64_t kDandelionEmbargoMs = 45 * 1000;
    std::vector<int> dandelion_stem_fds_; // this epoch's stems
    uint64_t dandelion_epoch_deadline_ms_ = 0;
    // digest → { embargo deadline ms, payload }. The relay decision is a
    // per-hop coin-flip (geometric path length); the deadline passed =
    // self-fluff (embargo timer, the black-hole guard).
    struct DandelionState {
        uint64_t embargo_deadline_ms = 0;
        // Embargo self-fluff needs the payload: a stem chain that dies at a
        // black-hole hop must not lose the transaction (availability over
        // privacy — the same trade as Monero's embargo timer).
        WireMsgType type = WireMsgType::DKSAP_SGMT_REG;
        std::vector<uint8_t> payload;
    };
    std::map<std::array<uint8_t, 32>, DandelionState> dandelion_state_;
    // Seen-digest set: a digest returning to us in stem phase = a LOOP —
    // immediate fluff (never relay a second time). Value = expiry ms.
    std::map<std::array<uint8_t, 32>, uint64_t> dandelion_seen_;
    // FIFO order for the seen cap (4096): evict-oldest at insertion.
    std::deque<std::array<uint8_t, 32>> dandelion_seen_order_;

    /// Seals the outgoing payload in place for a secured fd. Returns false
    /// (payload untouched) when no channel exists — legacy passthrough.
    bool sec_seal_out(int fd, const WireHeader &ad_hdr, std::vector<uint8_t> &payload);
    /// Opens the incoming payload in place. Returns false on any counter/
    /// tag failure (fail-closed: the caller drops the connection); returns
    /// true without touching the payload when the fd has no channel.
    bool sec_open_in(int fd, const WireHeader &ad_hdr, std::vector<uint8_t> &payload);

    // ── PEX 2/2: identity-keyed reputation (guarded by peers_mutex_) ──
    struct IdReputation {
        int dos_score = 0;
        bool banned = false;
    };
    // Bounded: non-banned entries are evictable past the cap (a score that
    // never reached 100 has no durable meaning); BANNED entries are never
    // evicted — they are disk-backed and a memory eviction would let a
    // banned peer re-handshake until the next restart.
    static constexpr size_t kMaxIdReputation = 8192;
    std::map<std::array<uint8_t, 32>, IdReputation> id_rep_;
    // The connection label each handshaked identity announced from (latest
    // wins); feeds the ban-time fd drop. Populated ONLY while identity
    // enforcement is enabled (dormant needs no labels — unauthenticated ids
    // must not consume memory), capped, and erased when the owning
    // connection tears down (security review 2026-11-15, MEDIUM: an
    // ungated/uncapped map let unauthenticated handshakes grow memory).
    std::map<std::array<uint8_t, 32>, std::string> id_conn_labels_;
    static constexpr size_t kMaxIdConnLabels = kMaxIdReputation;
    std::string banlist_path_;
    bool banlist_attached_ = false;
    // DORMANT gate: identity-keyed enforcement OFF until the handshake
    // authenticates ids (VX60-SEC KEM-PoP). Atomic: flips from RPC/init
    // threads while readers poll id_is_banned on their own threads.
    std::atomic<bool> id_enforcement_enabled_{false};
    void trim_id_rep_locked();
    void append_banlist_locked(const std::array<uint8_t, 32> &id);

    // The endpoint advertised to peers. ip stays 0 when unbound.
    uint32_t self_listen_ip_ = 0;
    // PEX residual (2026-11-14): discovery-supplied loopback candidates
    // are refused unless VX_P2P_ALLOW_LOOPBACK=1 (localhost-SSRF gate;
    // the loopback testnet opts in). Operator --peer dials bypass
    // add_addr_candidate entirely.
    bool loopback_candidates_allowed_ = false;

public:
    // Test hook: opt the node into loopback discovery candidates without
    // touching the process environment (the loopback testnet topology).
    void set_loopback_candidates_allowed_for_test(bool allowed) noexcept {
        loopback_candidates_allowed_ = allowed;
    }

    /// Dandelion++ M3 (owner-directed 19.11): epoch maintenance (called from
    /// gossip_loop ticks): regenerate the stem peer set when the epoch
    /// expires; fire embargo self-fluffs for expired stem entries.
    void dandelion_tick();

    /// The stem/fluff decision + relay for a privacy-class payload digest.
    /// Returns true when the caller must SKIP the normal broadcast (the
    /// payload was stemmed to one peer); false = normal broadcast (fluff
    /// or a non-privacy type). The sender fd is excluded from relay picks.
    /// Public: the wire dispatch sites call it; tests exercise the
    /// decision contract directly.
    bool dandelion_on_sidecar(int origin_fd, const std::array<uint8_t, 32> &digest,
                              WireMsgType type, const std::vector<uint8_t> &payload);

private:
    // Handshake/ADDRS helpers shared by both connection loops.
    void send_self_announce(int fd);
    void send_addrs_to(int fd, const std::string &exclude_label);
    // Parses an ADDRS payload (bounds-checked) and ingests candidates,
    // excluding self, the sender's listen endpoint (network-order ip /
    // host-order port; 0-port = unknown), and duplicates. Returns the
    // number of entries ingested; 0 on malformed (caller scores DoS).
    int ingest_addrs(const std::vector<uint8_t> &payload, uint32_t exclude_ip_net,
                     uint16_t exclude_port);

    // Live TCP connections: address -> socket fd
    std::unordered_map<std::string, int> peer_fds_;

    // Listener socket. Atomic: emergency_stop() closes/rewrites it while
    // listener_loop() reads it on its own thread (TSan-reported race, fixed
    // 2026-11-07); the shutdown()-based unblock design is unchanged.
    std::atomic<int> listen_fd_{-1};
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
    WitnessCallback witness_callback_;
    SidecarHook sidecar_callback_;
    PeerConnectedCallback peer_connected_callback_;

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
    bool connect_to_peer(const PeerInfo &peer);

    // Disconnect from a peer
    void disconnect_from_peer(const PeerInfo &peer);

    // Send frame to peer using sendfile() zero-copy if available
    bool send_frame_to_peer(int fd, const std::span<const uint8_t, 65536> &frame);

    // Verify frame signature and content
    bool verify_frame(const std::span<const uint8_t, 65536> &frame);

    // Ban peer for DoS
    void ban_peer(const std::string &address, int score_increment);
    bool send_payloads_to(
        int fd,
        const std::vector<std::array<uint8_t, 32 + 42 + sizeof(vx::crypto::pq::PqSignatureWitness)>>
            &payloads);
    // DKSAP wire integration: variable-length sidecar payloads under one
    // message type (the SGMT record carries the nickname). Same dup-fd and
    // partial-send discipline as send_payloads_to.
    bool send_wire_payloads_to(int fd, WireMsgType type,
                               const std::vector<std::vector<uint8_t>> &payloads);

    // BACKLOG 1.5 P0 GATE: cert backfill plumbing. Handlers parse a
    // bounded id list (count <= 64), answer targeted; senders use the same
    // dup-fd discipline as send_payloads_to. handle_rollover_cert_payload
    // returns true when THIS call stored a NEW certificate (the relay cue).
    bool handle_rollover_cert_payload(const std::vector<uint8_t> &payload);
    void handle_cert_inv(int fd, const std::string &peer_label,
                         const std::vector<uint8_t> &payload);
    void handle_get_certs(int fd, const std::string &peer_label,
                          const std::vector<uint8_t> &payload);
    bool send_cert_payloads_to(
        int fd,
        const std::vector<
            std::array<uint8_t, 42 + 4 + 4 + 32 + 32 + sizeof(vx::crypto::pq::PqSignatureWitness)>>
            &payloads);
    bool send_id_list_to(int fd, WireMsgType type, const std::vector<std::array<uint8_t, 32>> &ids);
    // One-hop CERT_INV fan-out for a freshly stored certificate (the
    // relay cue; full-cert relay remains broadcast_rollover_cert).
    void broadcast_cert_inv_for(const vx::crypto::pq::PqRolloverCert &cert);

    // Resolve split-brain fork using heaviest cumulative work
    void resolve_fork(const PeerInfo &challenger);
};

} // namespace vx::net
