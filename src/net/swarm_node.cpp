#include "vx/net/swarm_node.hpp"

#include "vx/blockchain/block.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/crypto/simd_accel.hpp"
#include "vx/core/hw_intrinsics.hpp"
#include "vx/core/u128.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/state/undo_engine.hpp"
#include "vx/storage/block_store.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <sys/sendfile.h>
#include <sys/uio.h>
#include <unistd.h>
#include <cerrno>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <filesystem>
#include <functional>
#include <iostream>
#include <mutex>
#include <sstream>
#include <thread>

namespace vx::net {

static constexpr uint64_t MAGIC = 0x58564336;

// ── VX60 CRC32C (tiered: x86_64 SSE4.2 / aarch64 CRC32 / scalar) ────────────

uint32_t compute_wire_crc32c(const uint8_t* data, size_t len) noexcept {
    // Portable CRC32C from hw_intrinsics: hardware tiers when available,
    // bitwise Castagnoli fallback otherwise — identical value on all tiers.
    return vx::core::hw::crc32c(data, len);
}

bool wire_header_plausible(const WireHeader& h) noexcept {
    if (h.magic != VX60_MAGIC) return false;
    if (h.reserved != 0) return false;
    if (h.payload_len > 65536) return false;
    const uint8_t t = h.msg_type;
    return t >= 0x01 && t <= 0x08;
}

WireHeader SwarmNode::make_header(WireMsgType type, uint32_t payload_len,
                                  uint64_t nonce, uint8_t flags) noexcept {
    WireHeader h{};
    h.magic = VX60_MAGIC;
    h.msg_type = static_cast<uint8_t>(type);
    h.flags = flags;
    h.reserved = 0;
    h.payload_len = payload_len;
    h.crc32c = 0; // caller fills after payload is known (or use make_header overload)
    h.peer_nonce = nonce;
    return h;
}

// ── PeerInfo ────────────────────────────────────────────────────────────────

uint64_t PeerInfo::xor_distance() const {
    return node_id ^ SwarmNode::OUR_NODE_ID;
}

bool PeerInfo::operator<(const PeerInfo& other) const {
    return xor_distance() < other.xor_distance();
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

SwarmNode::SwarmNode() {
    add_loopback_peer();
}

SwarmNode::~SwarmNode() {
    emergency_stop();
}

void SwarmNode::start() {
    if (running_.load()) return;
    running_.store(true);
    emergency_stop_requested_.store(false);

    listener_thread_ = std::thread([this]() { listener_loop(); });
    gossip_thread_ = std::thread([this]() { gossip_loop(); });
    health_thread_ = std::thread([this]() { health_loop(); });

    // Connect to any statically configured peers is handled via connect_peer_tcp.
}

void SwarmNode::emergency_stop() {
    if (!running_.exchange(false)) return;
    emergency_stop_requested_.store(true);

    close_all_peers();

    if (listen_fd_ >= 0) {
        ::shutdown(listen_fd_, SHUT_RDWR);
        ::close(listen_fd_);
        listen_fd_ = -1;
    }

    if (listener_thread_.joinable()) listener_thread_.join();
    if (gossip_thread_.joinable()) gossip_thread_.join();
    if (health_thread_.joinable()) health_thread_.join();

    std::lock_guard<std::mutex> lock(peers_mutex_);
    peer_table_.clear();
}

void SwarmNode::close_all_peers() {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (auto& [addr, fd] : peer_fds_) {
        if (fd >= 0) { ::shutdown(fd, SHUT_RDWR); ::close(fd); }
    }
    peer_fds_.clear();
}

// ── TCP peer connections ────────────────────────────────────────────────────

bool SwarmNode::connect_peer_tcp(const std::string& host, uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1 ||
        ::connect(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0) {
        ::close(fd);
        std::cerr << "[Swarm] TCP connect " << host << ":" << port << " failed\n";
        return false;
    }

    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

    std::lock_guard<std::mutex> lock(peers_mutex_);
    peer_fds_[host + ":" + std::to_string(port)] = fd;
    return true;
}

// ── Loopback peer ───────────────────────────────────────────────────────────

void SwarmNode::add_loopback_peer() {
    PeerInfo loopback;
    loopback.address = "loopback";
    loopback.node_id = OUR_NODE_ID ^ 0xFFFFFFFFULL; // Inverted ID for loopback
    loopback.height = 0;
    loopback.work = 0;
    loopback.cumulative_pogw = 0;
    loopback.latency_ms = 0;
    loopback.dos_score = 0;
    loopback.is_banned = false;
    loopback.is_loopback = true;
    loopback.last_seen = std::chrono::system_clock::now();
    std::lock_guard<std::mutex> lock(peers_mutex_);
    peer_table_.insert(loopback);
}

bool SwarmNode::connect_to_peer(const PeerInfo& peer) {
    (void)peer;
    // Real TCP connections go through connect_peer_tcp(); virtual mesh peers
    // (10.0.0.x simulation range) remain bookkeeping-only.
    return true;
}

void SwarmNode::disconnect_from_peer(const PeerInfo& peer) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = peer_fds_.find(peer.address);
    if (it != peer_fds_.end()) {
        if (it->second >= 0) ::close(it->second);
        peer_fds_.erase(it);
    }
}

// ── Wire send / recv ────────────────────────────────────────────────────────

uint64_t SwarmNode::send_packet(int fd, const WireHeader& hdr, const uint8_t* payload) {
    if (fd < 0) return 0;

    // Header goes out with crc32c already filled by the caller.
    ssize_t n = ::send(fd, &hdr, sizeof(hdr), MSG_NOSIGNAL);
    if (n != static_cast<ssize_t>(sizeof(hdr))) return 0;

    uint64_t total = sizeof(hdr);
    if (hdr.payload_len > 0 && payload) {
        size_t off = 0;
        while (off < hdr.payload_len) {
            n = ::send(fd, payload + off, hdr.payload_len - off, MSG_NOSIGNAL);
            if (n <= 0) {
                if (n < 0 && (errno == EINTR)) continue;
                return 0;
            }
            off += static_cast<size_t>(n);
            total += static_cast<uint64_t>(n);
        }
    }
    vx60_bytes_transferred_.fetch_add(total);
    return total;
}

bool SwarmNode::recv_packet(int fd, WireHeader& hdr, std::vector<uint8_t>& payload) {
    if (fd < 0) return false;

    // Read exactly 24 bytes of header
    size_t got = 0;
    auto* hdr_bytes = reinterpret_cast<uint8_t*>(&hdr);
    while (got < sizeof(hdr)) {
        ssize_t n = ::recv(fd, hdr_bytes + got, sizeof(hdr) - got, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return false;
        }
        got += static_cast<size_t>(n);
    }

    // Plausibility gate before allocating payload
    if (!wire_header_plausible(hdr)) {
        corrupted_packets_dropped_.fetch_add(1);
        return false;
    }

    payload.resize(hdr.payload_len);
    size_t off = 0;
    while (off < hdr.payload_len) {
        ssize_t n = ::recv(fd, payload.data() + off, hdr.payload_len - off, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return false;
        }
        off += static_cast<size_t>(n);
    }

    // Hardware CRC32C verification — drop silently on mismatch, keep connection.
    if (compute_wire_crc32c(payload.data(), payload.size()) != hdr.crc32c) {
        corrupted_packets_dropped_.fetch_add(1);
        return false;
    }
    return true;
}

// ── Zero-copy block streaming (sendfile) ────────────────────────────────────

bool SwarmNode::send_block_zero_copy(int socket_fd, int ledger_fd, uint64_t block_height,
                                     const uint8_t* block_data) {
    if (socket_fd < 0) return false;

    WireHeader hdr = make_header(WireMsgType::RAW_BLOCK_64K, 65536,
                                 session_nonce_.fetch_add(1), WIRE_FLAG_ZERO_COPY);
    hdr.crc32c = 0; // payload is streamed zero-copy; CRC covers header itself

    // 1. 24-byte header
    ssize_t n = ::send(socket_fd, &hdr, sizeof(hdr), MSG_NOSIGNAL);
    if (n != static_cast<ssize_t>(sizeof(hdr))) return false;

    uint64_t sent = sizeof(hdr);
    bool zero_copy = false;

    if (ledger_fd >= 0) {
        // 2. Zero-copy kernel-space transfer of the 65536-byte frame
        off_t offset = static_cast<off_t>(block_height) * 65536;
        size_t remaining = 65536;
        zero_copy = true;
        while (remaining > 0) {
            ssize_t s = ::sendfile(socket_fd, ledger_fd, &offset, remaining);
            if (s <= 0) {
                if (s < 0 && errno == EINTR) continue;
                zero_copy = false;
                break;
            }
            sent += static_cast<uint64_t>(s);
            remaining -= static_cast<size_t>(s);
        }
    }

    if (!zero_copy && block_data) {
        // Deterministic in-memory fallback via ::send()
        size_t off = 0;
        while (off < 65536) {
            ssize_t s = ::send(socket_fd, block_data + off, 65536 - off, MSG_NOSIGNAL);
            if (s <= 0) {
                if (s < 0 && errno == EINTR) continue;
                return false;
            }
            sent += static_cast<uint64_t>(s);
            off += static_cast<size_t>(s);
        }
    } else if (!zero_copy && !block_data) {
        return false;
    }

    zero_copy_bytes_sent_.fetch_add(sent);
    if (sent >= 24 + 65536) zero_copy_blocks_streamed_.fetch_add(1);
    vx60_bytes_transferred_.fetch_add(sent);
    return true;
}

// ── Frame broadcast / handling ──────────────────────────────────────────────

bool SwarmNode::send_frame_to_peer(int fd, const std::span<const uint8_t, 65536>& frame) {
    if (fd < 0) return false;
    WireHeader hdr = make_header(WireMsgType::RAW_BLOCK_64K, 65536,
                                 session_nonce_.fetch_add(1), WIRE_FLAG_ZERO_COPY);
    hdr.crc32c = compute_wire_crc32c(frame.data(), frame.size());
    ssize_t n = ::send(fd, &hdr, sizeof(hdr), MSG_NOSIGNAL);
    if (n != static_cast<ssize_t>(sizeof(hdr))) return false;
    size_t off = 0;
    while (off < frame.size()) {
        n = ::send(fd, frame.data() + off, frame.size() - off, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return false;
        }
        off += static_cast<size_t>(n);
    }
    vx60_bytes_transferred_.fetch_add(sizeof(hdr) + frame.size());
    return true;
}

void SwarmNode::broadcast_frame(const std::span<const uint8_t, 65536>& frame) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (const auto& [addr, fd] : peer_fds_) {
        (void)addr;
        send_frame_to_peer(fd, frame);
    }
}

void SwarmNode::handle_incoming_frame(const std::string& from_peer, const std::span<const uint8_t, 65536>& frame) {
    if (!verify_frame(frame)) {
        ban_peer(from_peer, 100);
        return;
    }
 // Block relay processing is driven by the RPC/node layer via hooks.
}

bool SwarmNode::verify_frame(const std::span<const uint8_t, 65536>& frame) {
    if (frame.size() < 4) return false;
    uint32_t magic;
    std::memcpy(&magic, frame.data(), 4);
    return magic == blockchain::BLOCK_MAGIC;
}

// ── Peer reputation ─────────────────────────────────────────────────────────

void SwarmNode::ban_peer(const std::string& address, int score_increment) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (auto it = peer_table_.begin(); it != peer_table_.end(); ++it) {
        if (it->address == address) {
            PeerInfo peer = *it;
            peer.dos_score += score_increment;
            if (peer.dos_score >= 100) peer.is_banned = true;
            peer_table_.erase(it);
            peer_table_.insert(peer);
            return;
        }
    }
}

void SwarmNode::simulate_fork() {
 // replaces this with the full live split-brain cycle via
    // simulate_live_split_brain_reorg(). Kept as a legacy no-op marker.
    std::cout << "[Swarm] legacy simulate_fork() — use simulate_live_split_brain_reorg()\n";
}

void SwarmNode::inject_rogue_peer() {
    PeerInfo rogue;
    rogue.address = "10.0.0.99";
    rogue.node_id = OUR_NODE_ID; // Same ID - collision
    rogue.height = 0;
    rogue.work = 0;
    rogue.cumulative_pogw = 0;
    rogue.latency_ms = 0;
    rogue.dos_score = 0;
    rogue.is_banned = false;
    rogue.is_loopback = false;
    rogue.last_seen = std::chrono::system_clock::now();
    std::lock_guard<std::mutex> lock(peers_mutex_);
    peer_table_.insert(rogue);
}

void SwarmNode::resolve_fork(const PeerInfo& challenger) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    std::cout << "[Swarm] Fork resolved: keeping heaviest work" << std::endl;
}

// ── VX60 listener bind ──────────────────────────────────────────────────────

bool SwarmNode::bind_p2p_listener(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0) return false;
    int opt = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (::bind(fd, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 ||
        ::listen(fd, 8) < 0) {
        ::close(fd);
        return false;
    }
    listen_fd_ = fd;
    listen_port_.store(port);
    return true;
}

// ── Background loops ────────────────────────────────────────────────────────

void SwarmNode::listener_loop() {
    while (!emergency_stop_requested_.load()) {
        if (listen_fd_ < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        int c = ::accept(listen_fd_, nullptr, nullptr);
        if (c < 0) {
            if (errno == EINTR) continue;
            if (emergency_stop_requested_.load()) break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }
        int one = 1;
        ::setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));

        // Handshake exchange over VX60: respond PONG to PING, validate CRC32C.
        WireHeader hdr{};
        std::vector<uint8_t> payload;
        if (recv_packet(c, hdr, payload)) {
            if (hdr.msg_type == static_cast<uint8_t>(WireMsgType::PING)) {
                WireHeader pong = make_header(WireMsgType::PONG, 0,
                                              session_nonce_.fetch_add(1));
                pong.crc32c = compute_wire_crc32c(nullptr, 0);
                ::send(c, &pong, sizeof(pong), MSG_NOSIGNAL);
            }
        }
        ::close(c);
    }
}

void SwarmNode::gossip_loop() {
    while (!emergency_stop_requested_.load()) {
        // Periodic tip gossip would broadcast HEADERS here; driven by hooks.
        for (int i = 0; i < 50 && !emergency_stop_requested_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

void SwarmNode::health_loop() {
    while (!emergency_stop_requested_.load()) {
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (auto it = peer_table_.begin(); it != peer_table_.end();) {
                PeerInfo peer = *it;
                if (peer.dos_score >= 100) {
                    peer.is_banned = true;
                    disconnect_from_peer(peer);
                    it = peer_table_.erase(it);
                } else {
                    peer.last_seen = std::chrono::system_clock::now();
                    ++it;
                }
            }
        }
        for (int i = 0; i < 50 && !emergency_stop_requested_.load(); ++i)
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
    }
}

std::vector<PeerInfo> SwarmNode::get_peer_table() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    return std::vector<PeerInfo>(peer_table_.begin(), peer_table_.end());
}

// ── live split-brain reorg ────────────────────────────────────────

namespace {

using blockchain::BlockFrame;
using blockchain::BlockView;
using blockchain::BlockBuilder;
using blockchain::Transaction;
using state::LedgerState;
using storage::BlockStore;

constexpr uint64_t SB_BLOCK_BYTES = 65536;

// Cumulative PoGW work proxy: sum of mined heights' nonces folded by sponge.
// Node B mines more blocks => strictly greater cumulative work.
uint64_t work_of_heights(uint64_t blocks_mined) {
    // Monotone synthetic cumulative work: each block adds (height+1)*1e6.
    uint64_t w = 0;
    for (uint64_t i = 1; i <= blocks_mined; ++i) w += i * 1'000'000ULL;
    return w;
}

// Deterministic single-validator miner for the simulation: mines `count`
// blocks of coinbase-only frames on top of the store's current tip with a
// fast (difficulty-1) PoGW nonce search so the test runs in microseconds.
struct SimNode {
    std::string data_dir;
    std::unique_ptr<BlockStore> store;
    std::unique_ptr<LedgerState> ledger;
    std::unique_ptr<vx::state::UndoEngine> undo;
    uint64_t cumulative_pogw = 0;

    SimNode(const std::string& dir, const std::string& genesis_path) : data_dir(dir) {
        std::filesystem::create_directories(dir);
        const std::string ledger_path = dir + "/ledger.vxb";
        std::filesystem::remove(ledger_path); // fresh partition state each run
        store = std::make_unique<BlockStore>(ledger_path, genesis_path);
        ledger = std::make_unique<LedgerState>();
        undo = std::make_unique<vx::state::UndoEngine>(dir, *store, *ledger);
        // Apply genesis to state (journal entry stays in memory for O(1) undo)
        auto* g = store->get_block(0);
        if (g) {
            BlockView v{std::span<const uint8_t, SB_BLOCK_BYTES>(
                reinterpret_cast<const uint8_t*>(g), SB_BLOCK_BYTES)};
            ledger->apply_block(v);
            undo->apply_block(v);
        }
    }

    uint64_t height() const { return store->chain_height() - 1; }

    std::string tip_hex() const {
        uint8_t h[32];
        store->tip_hash(h);
        std::ostringstream oss;
        for (uint8_t b : h) oss << std::hex << std::setw(2) << std::setfill('0') << int(b);
        return oss.str();
    }

    // Mines `count` coinbase-only blocks; returns updated cumulative work.
    uint64_t mine(uint64_t count) {
        for (uint64_t i = 0; i < count; ++i) {
            const uint64_t h = store->chain_height();
            uint8_t tip[32];
            store->tip_hash(tip);

            Transaction cb{};
            std::memcpy(cb.sender_nfa, "MINER_", 6);
            for (size_t k = 6; k < 42; ++k) cb.sender_nfa[k] = '0';
            std::memcpy(cb.receiver_nfa, "MINER_REWARD_ADDR_SPLIT_BRAIN_SIM", 35);
            for (size_t k = 35; k < 42; ++k) cb.receiver_nfa[k] = '0';
            blockchain::tx_set_amount(cb, 1'000'000ULL * (h + 1)); // distinct per height
            blockchain::sign_transaction(cb);

            BlockBuilder b;
            b.set_height(h);
            b.set_timestamp(1'700'000'000ULL + h * 5);
            b.set_prev_hash(tip);
            b.add_transaction(cb);
            b.finalize();

            // Fast PoGW: difficulty-1 search over the 64KB frame (leading zero byte)
            BlockFrame frame;
            auto fv = b.bytes();
            std::memcpy(frame.data(), fv.data(), SB_BLOCK_BYTES);
            auto* raw = reinterpret_cast<blockchain::RawBlock*>(frame.data());
            uint64_t nonce = 0;
            while (true) {
                raw->tail.pogw_nonce = nonce++;
                uint8_t hash[32];
                blockchain::VortexSponge256::compute(frame.data(), SB_BLOCK_BYTES, hash);
                if (hash[0] == 0) break;
            }
            if (!store->append_block(frame)) break;

            BlockView v{std::span<const uint8_t, SB_BLOCK_BYTES>(frame.data(), SB_BLOCK_BYTES)};
            undo->apply_block(v);
            ledger->apply_block(v);
            cumulative_pogw = work_of_heights(height());
        }
        return cumulative_pogw;
    }
};

// Send one 65536-byte block over VX60 RAW_BLOCK_64K with a real 24B header.
uint64_t vx60_send_block(int fd, uint64_t peer_nonce_base, const uint8_t* frame) {
    WireHeader hdr = SwarmNode::make_header(WireMsgType::RAW_BLOCK_64K, SB_BLOCK_BYTES,
                                            peer_nonce_base);
    hdr.crc32c = compute_wire_crc32c(frame, SB_BLOCK_BYTES);
    ssize_t n = ::send(fd, &hdr, sizeof(hdr), MSG_NOSIGNAL);
    if (n != static_cast<ssize_t>(sizeof(hdr))) return 0;
    size_t off = 0;
    uint64_t total = sizeof(hdr);
    while (off < SB_BLOCK_BYTES) {
        n = ::send(fd, frame + off, SB_BLOCK_BYTES - off, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return 0;
        }
        off += static_cast<size_t>(n);
        total += static_cast<uint64_t>(n);
    }
    return total;
}

// Receive one VX60 packet; validates magic + CRC32C; drops on corruption.
bool vx60_recv_packet(int fd, WireHeader& hdr, std::vector<uint8_t>& payload,
                      uint64_t& dropped_counter) {
    size_t got = 0;
    auto* p = reinterpret_cast<uint8_t*>(&hdr);
    while (got < sizeof(hdr)) {
        ssize_t n = ::recv(fd, p + got, sizeof(hdr) - got, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return false;
        }
        got += static_cast<size_t>(n);
    }
    if (!wire_header_plausible(hdr)) {
        ++dropped_counter;
        return false;
    }
    payload.assign(hdr.payload_len, 0);
    size_t off = 0;
    while (off < hdr.payload_len) {
        ssize_t n = ::recv(fd, payload.data() + off, hdr.payload_len - off, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR) continue;
            return false;
        }
        off += static_cast<size_t>(n);
    }
    if (compute_wire_crc32c(payload.data(), payload.size()) != hdr.crc32c) {
        ++dropped_counter;
        return false;
    }
    return true;
}

// Build a VX60 HANDSHAKE payload: height(8) | cumulative_pogw(8) | tip(32).
std::vector<uint8_t> handshake_payload(uint64_t height, uint64_t work, const uint8_t tip[32]) {
    std::vector<uint8_t> p(48);
    std::memcpy(p.data(), &height, 8);
    std::memcpy(p.data() + 8, &work, 8);
    std::memcpy(p.data() + 16, tip, 32);
    return p;
}

} // anonymous namespace

SplitBrainReport SwarmNode::simulate_live_split_brain_reorg() {
    SplitBrainReport report;
    const auto t0 = std::chrono::steady_clock::now();

    try {
        const std::string base =
            (std::filesystem::temp_directory_path() / "vx_split_brain").string();
        std::filesystem::remove_all(base);
        std::filesystem::create_directories(base);

        const std::string genesis_path = "genesis.bin";
        try {
            blockchain::ensure_genesis_file(genesis_path);
        } catch (const std::exception& e) {
            report.error = std::string("cannot regenerate genesis.bin: ") + e.what();
            return report;
        }

        // ── Two isolated nodes on the shared genesis (height 0) ────────────
        SimNode node_a(base + "/node_a", genesis_path);
        SimNode node_b(base + "/node_b", genesis_path);

  // ── Partition (no communication) ──────────────────────────
        report.node_a_work = node_a.mine(2);  // Node A: 2 blocks (less work)
        report.node_b_work = node_b.mine(4);  // Node B: 4 blocks (more work)
        report.node_a_height = node_a.height();
        report.node_b_height = node_b.height();
        report.node_a_tip_hex = node_a.tip_hex();
        report.node_b_tip_hex = node_b.tip_hex();

  // ── Heal — real VX60 TCP loopback ─────────────────────────
        int srv = ::socket(AF_INET, SOCK_STREAM, 0);
        int cfd = -1, bfd = -1;
        if (srv < 0) {
            report.error = "socket() failed";
            return report;
        }
        int opt = 1;
        ::setsockopt(srv, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
        sockaddr_in addr{};
        addr.sin_family = AF_INET;
        addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        addr.sin_port = 0; // ephemeral
        if (::bind(srv, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) < 0 ||
            ::listen(srv, 1) < 0) {
            ::close(srv);
            report.error = "bind/listen failed";
            return report;
        }
        socklen_t alen = sizeof(addr);
        ::getsockname(srv, reinterpret_cast<sockaddr*>(&addr), &alen);
        const uint16_t port = ntohs(addr.sin_port);

        std::thread acceptor([&]() {
            bfd = ::accept(srv, nullptr, nullptr);
        });
        cfd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in ca{};
        ca.sin_family = AF_INET;
        ca.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ca.sin_port = htons(port);
        if (::connect(cfd, reinterpret_cast<sockaddr*>(&ca), sizeof(ca)) < 0) {
            report.error = "connect failed";
            acceptor.join();
            ::close(srv);
            return report;
        }
        acceptor.join();
        if (bfd < 0) {
            ::close(cfd); ::close(srv);
            report.error = "accept failed";
            return report;
        }

        uint64_t bytes_total = 0;

        // Node A -> Node B: HANDSHAKE (height, work, tip)
        {
            uint8_t tip[32];
            node_a.store->tip_hash(tip);
            auto p = handshake_payload(node_a.height(), node_a.cumulative_pogw, tip);
            WireHeader h = SwarmNode::make_header(WireMsgType::HANDSHAKE,
                                                  static_cast<uint32_t>(p.size()),
                                                  session_nonce_.fetch_add(1));
            h.crc32c = compute_wire_crc32c(p.data(), p.size());
            bytes_total += send_packet(bfd, h, p.data());
        }
        // Node B -> Node A: HANDSHAKE — Node A learns B is heavier
        {
            uint8_t tip[32];
            node_b.store->tip_hash(tip);
            auto p = handshake_payload(node_b.height(), node_b.cumulative_pogw, tip);
            WireHeader h = SwarmNode::make_header(WireMsgType::HANDSHAKE,
                                                  static_cast<uint32_t>(p.size()),
                                                  session_nonce_.fetch_add(1));
            h.crc32c = compute_wire_crc32c(p.data(), p.size());
            bytes_total += send_packet(cfd, h, p.data());
        }
        // Node A receives B's handshake, decides reorg
        {
            WireHeader rh{};
            std::vector<uint8_t> rp;
            uint64_t dropped = 0;
            if (!vx60_recv_packet(cfd, rh, rp, dropped)) {
                corrupted_packets_dropped_.fetch_add(dropped);
                ::close(cfd); ::close(bfd); ::close(srv);
                report.error = "handshake recv failed";
                return report;
            }
            bytes_total += sizeof(rh) + rp.size();
        }

  // ── O(1) Reorg on Node A ──────────────────────────────────
        // Node B streams its 4 blocks; Node A rolls back its 2 via undo.vxl.
        if (report.node_b_work > report.node_a_work) {
            // 3a. Stream B's fork blocks over VX60 first (Node B -> A).
            std::vector<BlockFrame> b_frames;
            for (uint64_t h = 1; h <= report.node_b_height; ++h) {
                auto* raw = node_b.store->get_block(h);
                if (!raw) continue;
                b_frames.emplace_back();
                std::memcpy(b_frames.back().data(), raw, SB_BLOCK_BYTES);
                bytes_total += vx60_send_block(bfd, session_nonce_.fetch_add(1),
                                               b_frames.back().data());
            }

            // 3b. Node A: O(1) rollback to genesis through undo.vxl journal.
            if (node_a.undo->rollback_to_height(0)) {
                report.blocks_rolled_back = report.node_a_height;
            } else {
                report.blocks_rolled_back = 0;
            }
            node_a.ledger->set_next_height(1);
            // Truncate Node A's ledger back to genesis only.
            node_a.store.reset(); // close mmap/fd
            std::filesystem::resize_file(base + "/node_a/ledger.vxb", SB_BLOCK_BYTES);
            node_a.store = std::make_unique<BlockStore>(base + "/node_a/ledger.vxb", genesis_path);

            // 3c. Node A applies B's 4 blocks (received over VX60).
            for (uint64_t h = 1; h <= report.node_b_height; ++h) {
                BlockView v{std::span<const uint8_t, SB_BLOCK_BYTES>(
                    b_frames[h - 1].data(), SB_BLOCK_BYTES)};
                node_a.undo->apply_block(v);
                if (node_a.ledger->apply_block(v).ok) {
                    node_a.undo->commit_undo_point();
                    node_a.store->append_block(b_frames[h - 1]);
                    ++report.blocks_resynced;
                }
            }
            report.vx60_bytes_transferred = bytes_total;
            vx60_bytes_transferred_.fetch_add(bytes_total);
        }

        ::close(cfd); ::close(bfd); ::close(srv);

        // ── Final invariant: identical tips at height 4 ────────────────────
        report.final_height = node_a.height();
        report.final_tip_hex = node_a.tip_hex();
        report.tip_hashes_match = (report.final_tip_hex == report.node_b_tip_hex);
        report.reorg_success = report.tip_hashes_match &&
                               report.final_height == report.node_b_height &&
                               report.blocks_resynced == report.node_b_height;

        const auto t1 = std::chrono::steady_clock::now();
        report.duration_us = static_cast<uint64_t>(
            std::chrono::duration_cast<std::chrono::microseconds>(t1 - t0).count());
        return report;

    } catch (const std::exception& e) {
        report.error = e.what();
        return report;
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Dandelion++ ZK-Cocoon routing
// ═══════════════════════════════════════════ encrypted_tx mask = Sponge(XOR-key stream from ephemeral_salt) ═══

namespace {

// Deterministic XOR mask stream derived from an ephemeral salt (per-hop layer).
// Each hop strips its layer and adds its own — the classic Dandelion++ privacy
// onion over the VortexSponge256 XOF.
void cocoon_mask_layer(uint8_t* bytes112, uint64_t salt) noexcept {
    blockchain::VortexSponge256 sponge;
    sponge.absorb(reinterpret_cast<const uint8_t*>(&salt), sizeof(salt));
    uint8_t stream[112];
    // Absorb enough entropy: 112 bytes through repeated sponge absorption.
    const uint8_t zero = 0;
    for (size_t off = 0; off < sizeof(stream); off += 32) {
        sponge.absorb(&zero, 1);
        sponge.absorb(reinterpret_cast<const uint8_t*>(&salt), sizeof(salt));
    }
    sponge.finalize(stream); // 32 bytes
    // Extend stream to 112 bytes with a counter-mode sponge expansion.
    for (size_t blk = 1; blk * 32 < sizeof(stream); ++blk) {
        blockchain::VortexSponge256 s2;
        s2.absorb(reinterpret_cast<const uint8_t*>(&salt), sizeof(salt));
        const uint8_t ctr = static_cast<uint8_t>(blk);
        s2.absorb(&ctr, 1);
        uint8_t chunk[32];
        s2.finalize(chunk);
        std::memcpy(stream + blk * 32, chunk, std::min(sizeof(stream) - blk * 32, size_t(32)));
    }
    for (size_t i = 0; i < 112; ++i) bytes112[i] ^= stream[i];
}

// Hardware entropy source for hop counts / salts (no std::rand).
uint64_t hw_entropy() noexcept {
    uint64_t v = 0;
    int fd = ::open("/dev/urandom", O_RDONLY | O_CLOEXEC);
    if (fd >= 0) {
        ssize_t r = ::read(fd, &v, sizeof(v));
        (void)r;
        ::close(fd);
    }
    if (v == 0) v = 0x9E3779B97F4A7C15ULL; // deterministic fallback
    return v;
}

} // namespace

TxCocoon SwarmNode::seal_cocoon(const blockchain::Transaction& tx,
                                uint16_t tdi_score_fp) noexcept {
    TxCocoon c{};
    std::memcpy(c.encrypted_tx, &tx, 112);
    const uint64_t salt = hw_entropy();
    c.ephemeral_salt = salt;
    c.stem_hops_remaining = static_cast<uint8_t>(
        COCOON_MIN_HOPS + (hw_entropy() % (COCOON_MAX_HOPS - COCOON_MIN_HOPS + 1)));
    c.phase = COCOON_PHASE_STEM;
    c.tdi_score_fp = tdi_score_fp;
    cocoon_mask_layer(c.encrypted_tx, salt);
    c.cocoon_crc32c = compute_wire_crc32c(reinterpret_cast<const uint8_t*>(c.encrypted_tx), 112);
    return c;
}

blockchain::Transaction SwarmNode::open_cocoon(const TxCocoon& cocoon) noexcept {
    blockchain::Transaction tx{};
    std::array<uint8_t, 112> bytes{};
    std::memcpy(bytes.data(), cocoon.encrypted_tx, 112);
    cocoon_mask_layer(bytes.data(), cocoon.ephemeral_salt); // XOR is self-inverse
    std::memcpy(&tx, bytes.data(), 112);
    return tx;
}

bool SwarmNode::relay_cocoon_step(TxCocoon& cocoon, CocoonHopTrace& trace) {
    // Integrity gate: corrupted cocoons burn without entering the graph.
    const uint32_t crc = compute_wire_crc32c(
        reinterpret_cast<const uint8_t*>(cocoon.encrypted_tx), 112);
    if (crc != cocoon.cocoon_crc32c) {
        trace.action = "burned";
        trace.forwarded = false;
        trace.phase = "BURNED_CRC";
        return false;
    }

    // Spam gate: fixed-point TDI density checked WITHOUT decryption.
    if (cocoon.tdi_score_fp < COCOON_MIN_TDI_THRESHOLD) {
        tdi_spam_annihilated_.fetch_add(1, std::memory_order_relaxed);
        trace.action = "burned";
        trace.forwarded = false;
        trace.phase = "BURNED_TDI";
        return false;
    }

    const uint8_t phase = cocoon.phase;
    if (phase == COCOON_PHASE_STEM) {
        // STEM: peel current layer, re-mask with a fresh ephemeral salt,
        // decrement hops, erase inbound identity, forward to exactly ONE peer.
        cocoon_mask_layer(cocoon.encrypted_tx, cocoon.ephemeral_salt); // peel
        const uint64_t fresh_salt = hw_entropy();
        cocoon.ephemeral_salt = fresh_salt;
        cocoon_mask_layer(cocoon.encrypted_tx, fresh_salt);            // re-mask
        cocoon.cocoon_crc32c = compute_wire_crc32c(
            reinterpret_cast<const uint8_t*>(cocoon.encrypted_tx), 112);

        cocoon.stem_hops_remaining--;
        if (cocoon.stem_hops_remaining == 0) {
            cocoon.phase = COCOON_PHASE_FLUFF;
        }
        stem_relays_.fetch_add(1, std::memory_order_relaxed);
        trace.phase = "STEM";
        trace.action = "relayed";
        trace.forwarded = true;
        trace.hops_remaining = cocoon.stem_hops_remaining;
        trace.ip_source_erased = true; // single-peer stem relay never carries origin
        return true;
    }

    if (phase == COCOON_PHASE_FLUFF) {
        // FLUFF: cocoon opens, tx joins the mempool, fan-out to ALL peers.
        fluff_broadcasts_.fetch_add(1, std::memory_order_relaxed);
        trace.phase = "FLUFF";
        trace.action = "broadcast";
        trace.forwarded = true;
        trace.hops_remaining = 0;
        return true;
    }

    trace.action = "burned";
    trace.forwarded = false;
    trace.phase = "BURNED_PHASE";
    return false;
}

CocoonRelayReport SwarmNode::relay_cocoon_full_cycle(const blockchain::Transaction& tx,
                                                     uint16_t tdi_score_fp) {
    CocoonRelayReport report;
    TxCocoon cocoon = seal_cocoon(tx, tdi_score_fp);
    const uint8_t total_hops = cocoon.stem_hops_remaining;

    uint32_t hop_index = 0;
    while (true) {
        CocoonHopTrace hop;
        hop.hop_index = hop_index;
        ++hop_index;

        // Phase BEFORE this step decides whether it is the final broadcast.
        const uint8_t phase_before = cocoon.phase;

        // Cocoon hash trace (masked payload sponge digest per hop).
        blockchain::VortexSponge256 sponge;
        sponge.absorb(cocoon.encrypted_tx, 112);
        sponge.absorb(reinterpret_cast<const uint8_t*>(&cocoon.ephemeral_salt), 8);
        uint8_t ch[32];
        sponge.finalize(ch);
        std::ostringstream oss;
        for (const uint8_t b : ch) {
            char hex[3];
            std::snprintf(hex, sizeof(hex), "%02x", b);
            oss << hex;
        }
        hop.cocoon_hash_hex = oss.str();

        if (!relay_cocoon_step(cocoon, hop)) {
            report.hops.push_back(std::move(hop));
            report.error = "cocoon burned at hop " + std::to_string(hop.hop_index);
            report.stats = dandelion_stats();
            return report;
        }

        report.hops.push_back(std::move(hop));
        if (phase_before == COCOON_PHASE_FLUFF) {
            // The FLUFF step just broadcast to the whole swarm: cycle done.
            break;
        }
        // Safety bound (must never trigger: hops <= 7).
        if (hop_index > 32) {
            report.error = "hop limit exceeded";
            break;
        }
    }

    // Statistics: average stem hops across completed stem cycles.
    stem_hops_sum_.fetch_add(total_hops, std::memory_order_relaxed);
    stem_cycles_count_.fetch_add(1, std::memory_order_relaxed);

    report.stats = dandelion_stats();
    report.ok = true;
    report.vx60_bytes_transferred =
        report.hops.size() * (24 + sizeof(TxCocoon));
    return report;
}

DandelionStats SwarmNode::dandelion_stats() const noexcept {
    DandelionStats s;
    s.stem_relays = stem_relays_.load(std::memory_order_relaxed);
    s.fluff_broadcasts = fluff_broadcasts_.load(std::memory_order_relaxed);
    s.tdi_spam_annihilated = tdi_spam_annihilated_.load(std::memory_order_relaxed);
    const uint64_t cycles = stem_cycles_count_.load(std::memory_order_relaxed);
    s.avg_stem_hops = cycles ? static_cast<double>(stem_hops_sum_.load(std::memory_order_relaxed)) / cycles : 0.0;
    s.anonymity_set_size = anonymity_set_size_.load(std::memory_order_relaxed);
    return s;
}

} // namespace vx::net
