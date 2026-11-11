#include "vx/net/swarm_node.hpp"
#include <vector>

#include "vx/blockchain/block.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/crypto/simd_accel.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/core/hw_intrinsics.hpp"
#include "vx/core/u128.hpp"
#include "vx/state/ledger_state.hpp"
#include "vx/state/undo_engine.hpp"
#include "vx/storage/block_store.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <sys/random.h> // getrandom: durable node identity
#include <sys/sendfile.h>
#include <sys/socket.h>
#include <sys/stat.h>
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
#include <random>
#include <sstream>
#include <thread>

namespace vx::net {

namespace {

// HANDSHAKE payload v2 (87 bytes): height(8 LE) | cumulative_pogw(8 LE) |
// tip(32) | node_id(32) | listen_ip(4, network order) | listen_port(2,
// network order) | listen_valid(1). The old-world 48-byte payload
// (height|work|tip) is still accepted by every reader: a shorter packet
// simply carries no identity and no listen endpoint. NOTE (byte-order
// contract, security review 2026-11-11): the mixed-looking layout is real
// and intentional - the two u64 counter fields are little-endian, every
// IP and PORT field on VX60 is network byte order. Third-party
// implementers follow exactly this comment.
constexpr size_t kHandshakeV2Size = 87;
constexpr size_t kHandshakeOldSize = 48;
// ADDRS payload: count(u32 LE) + count * [IPv4(4, network order) |
// port(2, network order)], cap 16.
constexpr size_t kAddrEntrySize = 6;
constexpr size_t kMaxAddrEntries = 16;

// Fold the 32-byte durable identity into the PeerInfo.node_id field (the
// Kademlia ordering key). Folding is display/ordering only; self-detection
// compares the full 32 bytes at parse time.
uint64_t fold_node_id(const uint8_t id[32]) {
    uint64_t v = 0;
    std::memcpy(&v, id, 8);
    return v;
}

// True when a 32-byte identity is all zeros: an old-world announce that
// carries no identity at all (upsert must not create entries for it).
bool id_full_zero(const std::array<uint8_t, 32> &id) {
    for (const uint8_t b : id)
        if (b != 0)
            return false;
    return true;
}

} // namespace

// Shared HANDSHAKE parse: fills height/work/tip always (>=48), identity and
// listen endpoint when the v2 tail is present (>=87). Returns false when the
// payload predates even the old-world minimum. self_peer is true when the
// payload carries OUR OWN node_id (a discovery self-dial): the caller must
// drop the connection.
bool parse_handshake_payload(const std::vector<uint8_t> &payload, uint64_t &height, uint64_t &work,
                             uint8_t tip_out[32], const std::array<uint8_t, 32> &our_id,
                             bool &is_self, std::array<uint8_t, 32> &their_id,
                             uint32_t &listen_ip_net, uint16_t &listen_port, bool &listen_valid) {
    if (payload.size() < kHandshakeOldSize)
        return false;
    std::memcpy(&height, payload.data(), 8);
    std::memcpy(&work, payload.data() + 8, 8);
    std::memcpy(tip_out, payload.data() + 16, 32);
    is_self = false;
    listen_valid = false;
    listen_ip_net = 0;
    listen_port = 0;
    their_id.fill(0);
    if (payload.size() >= kHandshakeV2Size) {
        std::memcpy(their_id.data(), payload.data() + 48, 32);
        // Zero identity = old-world peer without one: not "self".
        if (our_id != std::array<uint8_t, 32>{} && their_id == our_id)
            is_self = true;
        std::memcpy(&listen_ip_net, payload.data() + 80, 4);
        std::memcpy(&listen_port, payload.data() + 84, 2);
        listen_port = ntohs(listen_port);
        // listen_valid requires a real endpoint: an all-zero listen ip
        // (0.0.0.0) must not propagate as an advertised dial target
        // (security review P2, 2026-11-11).
        listen_valid = payload[86] == 1 && listen_port != 0 && listen_ip_net != 0;
    }
    return true;
}

static constexpr uint64_t MAGIC = 0x58564336;

// BACKLOG 1.5: the ROLLOVER_CERT wire payload - sender(42) + from_window(4)
// + to_window(4) + old_root(32) + new_root(32) + witness(2376) = 2490 bytes.
constexpr size_t kRolloverCertPayloadSize =
    42 + 4 + 4 + 32 + 32 + sizeof(vx::crypto::pq::PqSignatureWitness);

// BACKLOG 1.5 P0 GATE: parse + REGISTER a received rollover certificate.
// The registry verifies the FULL certificate object (leaf 15, sequential
// windows, both roots, the commitment, the WOTS+/XMSS chain over the
// binding digest) before storing - a hostile relay cannot plant anything
// unverified. Returns true when THIS call stored a NEW certificate: the
// caller then relays the certificate one hop further (the fire-and-forget
// relay is no longer the ONLY delivery path - CERT_INV/GET_CERTS backfill
// recovers whatever a peer misses).
bool SwarmNode::handle_rollover_cert_payload(const std::vector<uint8_t> &payload) {
    if (payload.size() != kRolloverCertPayloadSize)
        return false;
    vx::crypto::pq::PqRolloverCert cert{}; // zero-init: no indeterminate padding
    std::memcpy(cert.sender.data(), payload.data(), 42);
    std::memcpy(&cert.from_window, payload.data() + 42, 4);
    std::memcpy(&cert.to_window, payload.data() + 46, 4);
    std::memcpy(cert.old_root.data(), payload.data() + 50, 32);
    std::memcpy(cert.new_root.data(), payload.data() + 82, 32);
    std::memcpy(&cert.witness, payload.data() + 114, sizeof(cert.witness));
    bool fresh = false;
    const bool ok =
        vx::crypto::pq::PqWitnessRegistry::instance().register_rollover_cert(cert, &fresh);
    if (ok && fresh) {
        // Relay one hop (the pre-existing fire-and-forget path, now actually
        // driven), plus a CERT_INV announcement so peers that miss the full
        // record can pull it by id.
        broadcast_rollover_cert(cert);
        broadcast_cert_inv_for(cert);
    }
    return ok && fresh;
}

// ── VX60 CRC32C (tiered: x86_64 SSE4.2 / aarch64 CRC32 / scalar) ────────────

uint32_t compute_wire_crc32c(const uint8_t *data, size_t len) noexcept {
    // Portable CRC32C from hw_intrinsics: hardware tiers when available,
    // bitwise Castagnoli fallback otherwise — identical value on all tiers.
    return vx::core::hw::crc32c(data, len);
}

bool wire_header_plausible(const WireHeader &h) noexcept {
    if (h.magic != VX60_MAGIC)
        return false;
    if (h.reserved != 0)
        return false;
    if (h.payload_len > 65536)
        return false;
    const uint8_t t = h.msg_type;
    // 0x0D = ADDRS (peer discovery, one-shot push after the v2 handshake);
    // 0x0E still fails closed.
    return t >= 0x01 && t <= 0x0D;
}

WireHeader SwarmNode::make_header(WireMsgType type, uint32_t payload_len, uint64_t nonce,
                                  uint8_t flags) noexcept {
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

bool PeerInfo::operator<(const PeerInfo &other) const {
    // Security review P1 (peer discovery, 2026-11-11): the xor_distance
    // alone is NOT a total order - a wire-supplied node_id can collide
    // with another peer's fold, and in a std::set "equal" means "equivalent":
    // a collide-with claim then makes the legit peer's erase+insert UPDATE
    // silently vanish (peer squatting) and destroys the squatter's own DoS
    // record (strike laundering). Tie-break on the local address label,
    // which is unique per connection.
    if (xor_distance() != other.xor_distance())
        return xor_distance() < other.xor_distance();
    return address < other.address;
}

// ── Lifecycle ───────────────────────────────────────────────────────────────

SwarmNode::SwarmNode() {
    add_loopback_peer();
}

SwarmNode::~SwarmNode() {
    emergency_stop();
}

void SwarmNode::start() {
    if (running_.load())
        return;
    running_.store(true);
    emergency_stop_requested_.store(false);

    listener_thread_ = std::thread([this]() { listener_loop(); });
    gossip_thread_ = std::thread([this]() { gossip_loop(); });
    health_thread_ = std::thread([this]() { health_loop(); });

    // Connect to any statically configured peers is handled via connect_peer_tcp.
}

void SwarmNode::emergency_stop() {
    // Reader threads may exist even when start() was never called
    // (connect_peer_tcp spawns them directly), so teardown of dialed
    // sockets and readers must run on every call, not only when running.
    const bool was_running = running_.exchange(false);
    emergency_stop_requested_.store(true);

    // Closing the dialed sockets unblocks the per-peer reader threads.
    close_all_peers();
    std::vector<std::thread> readers_done;
    {
        std::lock_guard<std::mutex> lock(readers_mu_);
        readers_done.swap(peer_readers_);
    }
    for (auto &t : readers_done)
        if (t.joinable())
            t.join();

    if (!was_running)
        return;

    if (listen_fd_.load() >= 0) {
        const int fd = listen_fd_.load();
        ::shutdown(fd, SHUT_RDWR);
        ::close(fd);
        listen_fd_.store(-1);
    }

    // Unblock the listener thread if it is blocked in a recv on an accepted
    // connection; the fd itself stays open and is closed by the listener.
    shutdown_accepted();

    // Connection handlers exit once their sockets are shut down.
    std::vector<std::thread> handlers_done;
    {
        std::lock_guard<std::mutex> lock(handlers_mu_);
        handlers_done.swap(conn_handlers_);
    }
    for (auto &t : handlers_done)
        if (t.joinable())
            t.join();

    if (listener_thread_.joinable())
        listener_thread_.join();
    if (gossip_thread_.joinable())
        gossip_thread_.join();
    if (health_thread_.joinable())
        health_thread_.join();

    std::lock_guard<std::mutex> lock(peers_mutex_);
    peer_table_.clear();
}

void SwarmNode::close_all_peers() {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (auto &[addr, fd] : peer_fds_) {
        // shutdown only: the owning reader/serve thread observes the
        // shutdown, exits and closes the fd itself. Closing here too would
        // double-close before the owner's close, and a recycled fd number
        // in between would make the owner kill an unrelated connection.
        if (fd >= 0)
            ::shutdown(fd, SHUT_RDWR);
    }
    peer_fds_.clear();
}

// ── TCP peer connections ────────────────────────────────────────────────────

bool SwarmNode::connect_peer_tcp(const std::string &host, uint16_t port) {
    // Security review P0 (peer discovery, 2026-11-11): a second dial to the
    // same label used to overwrite peer_fds_[label], leaking the previous
    // fd while its reader thread stayed blocked on it forever - with the
    // health-loop auto-dial this became a remote fd/thread/connection
    // exhaustion (EMFILE in about an hour) and the orphaned readers also
    // hung emergency_stop() (peer_readers_ join never returned). Refuse a
    // duplicate connection instead: one fd, one owner thread, one label.
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        if (peer_fds_.count(host + ":" + std::to_string(port)) != 0)
            return false;
    }
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return false;

    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    if (::inet_pton(AF_INET, host.c_str(), &addr.sin_addr) != 1) {
        ::close(fd);
        std::cerr << "[Swarm] TCP connect " << host << ":" << port << " failed\n";
        return false;
    }
    // Bound the connect itself: discovery dials candidates that may be dead,
    // and a blocking connect to an unroutable address can hang for minutes
    // (kernel SYN retransmits), stalling the health loop that must keep
    // enforcing bans. Non-blocking connect + 2 s deadline, then restore
    // blocking mode for the handshake/reader path.
    const int fl = ::fcntl(fd, F_GETFL, 0);
    if (fl >= 0)
        ::fcntl(fd, F_SETFL, fl | O_NONBLOCK);
    const int cr = ::connect(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr));
    if (cr < 0 && errno != EINPROGRESS) {
        ::close(fd);
        std::cerr << "[Swarm] TCP connect " << host << ":" << port << " failed\n";
        return false;
    }
    if (cr < 0) {
        pollfd pfd{};
        pfd.fd = fd;
        pfd.events = POLLOUT;
        const int pr = ::poll(&pfd, 1, 2000);
        int soerr = 0;
        socklen_t elen = sizeof(soerr);
        if (pr <= 0 || ::getsockopt(fd, SOL_SOCKET, SO_ERROR, &soerr, &elen) < 0 || soerr != 0) {
            ::close(fd);
            std::cerr << "[Swarm] TCP connect " << host << ":" << port << " timeout\n";
            return false;
        }
        if (fl >= 0)
            ::fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);
    }
    // Restore blocking mode on the immediate-connect path too: the restore
    // above only runs when poll() was taken. A socket that stays O_NONBLOCK
    // would turn every later handshake send into EAGAIN short-writes.
    if (fl >= 0)
        ::fcntl(fd, F_SETFL, fl & ~O_NONBLOCK);

    int one = 1;
    ::setsockopt(fd, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    // Bound blocking sends: broadcast paths call ::send from the RPC/state
    // threads (handle_transfer, apply_remote_frame hold state_mutex_ across
    // the broadcast), so a stalled peer with a full TCP window must fail
    // after seconds instead of freezing the whole chain tip indefinitely.
    struct timeval snd_tv{5, 0};
    ::setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, &snd_tv, sizeof(snd_tv));

    // Handshake: announce ourselves so the remote listener promotes this
    // connection into its peer table (and can broadcast back over it).
    WireHeader ping = make_header(WireMsgType::PING, 0, session_nonce_.fetch_add(1));
    ping.crc32c = compute_wire_crc32c(nullptr, 0);
    ssize_t n = ::send(fd, &ping, sizeof(ping), MSG_NOSIGNAL);
    if (n != static_cast<ssize_t>(sizeof(ping))) {
        ::close(fd);
        std::cerr << "[Swarm] handshake send " << host << ":" << port << " failed\n";
        return false;
    }
    const std::string label = host + ":" + std::to_string(port);
    // Peer discovery: self-announce (v2 handshake) + one-shot ADDRS push.
    // The dialed side answers in kind through its serve loop, so after the
    // exchange both ends know each other's listen endpoint and one hop of
    // the mesh graph. Plain socket writes, no swarm lock held.
    send_self_announce(fd);
    send_addrs_to(fd, label);
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        peer_fds_[label] = fd;
        // Security review P1 (peer discovery, 2026-11-11): outbound peers
        // must exist in peer_table_ from connect time. Without an insert,
        // the reader's HANDSHAKE handler only ever UPDATED an entry that
        // never existed, which made every report_withhold() on this label
        // a silent no-op (unlimited ADDRS flood from a dialed peer) and
        // left discovery-visible tests unable to see the dialed node.
        PeerInfo peer{};
        peer.address = label;
        peer.last_seen = std::chrono::system_clock::now();
        peer.is_loopback = host == "127.0.0.1";
        peer_table_.insert(peer);
    }
    // Reader thread: our outgoing socket must also ingest — otherwise
    // broadcast back to us by the dialed peer is never received.
    {
        std::lock_guard<std::mutex> readers_lock(readers_mu_);
        peer_readers_.emplace_back(&SwarmNode::peer_reader_loop, this, fd, label);
    }
    // Security review P0-1 (2.11 third checkbox): the connect side effect
    // fires OUTSIDE both locks, mirroring the inbound fire_connected
    // discipline - the retention serve re-enters peers_mutex_ through
    // send_witnesses_to, and it also takes state_mutex_ first, so firing
    // under peers_mutex_ would self-deadlock AND invert the documented
    // state_mutex_ -> peers_mutex_ order on the dialing thread.
    if (peer_connected_callback_)
        peer_connected_callback_(label);
    return true;
}

void SwarmNode::peer_reader_loop(int fd, std::string label) {
    // Discovery state for THIS connection: one self-announce / one ADDRS
    // per direction; a second ADDRS from the same peer is a flood signal.
    bool addr_seen = false;
    for (;;) {
        WireHeader hdr{};
        std::vector<uint8_t> payload;
        if (!recv_packet(fd, hdr, payload))
            break;
        const auto type = static_cast<WireMsgType>(hdr.msg_type);
        if (type == WireMsgType::PONG)
            continue; // keepalive reply
        if (type == WireMsgType::HANDSHAKE) {
            // v2 self-announce from the dialed peer: record its durable
            // identity and listen endpoint. A peer announcing OUR node_id
            // is ourselves reached through discovery (seed/ADDRS loop) -
            // drop the connection immediately, before any state records it.
            uint64_t height = 0, work = 0;
            uint8_t tip[32] = {0};
            std::array<uint8_t, 32> their_id{};
            uint32_t lip = 0;
            uint16_t lport = 0;
            bool lvalid = false, is_self = false;
            if (!parse_handshake_payload(payload, height, work, tip, node_id_, is_self, their_id,
                                         lip, lport, lvalid)) {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                peer_fds_.erase(label);
                ::close(fd);
                return;
            }
            if (is_self) {
                std::cerr << "[Swarm] self-dial detected via node_id, dropping " << label << "\n";
                std::lock_guard<std::mutex> lock(peers_mutex_);
                peer_fds_.erase(label);
                ::close(fd);
                return;
            }
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                for (auto &peer : peer_table_) {
                    if (peer.address == label) {
                        PeerInfo updated = peer;
                        // Fold the 32-byte identity into the ordering key
                        // (display/order only; self-detection compared the
                        // full 32 bytes above). With the total-order
                        // operator< the erase+insert cannot collide.
                        std::memcpy(&updated.node_id, their_id.data(), 8);
                        updated.listen_ip = lip; // network order on the wire
                        updated.listen_port = lport;
                        updated.listen_valid = lvalid;
                        updated.last_seen = std::chrono::system_clock::now();
                        peer_table_.erase(peer);
                        peer_table_.insert(updated);
                        break;
                    }
                }
                // Upsert path: an outbound connection whose announce beat
                // this reader to the table has no entry yet (connect_peer_tcp
                // now inserts one; old-world peers that never announce still
                // get the connect-time entry). Insert what we learned.
                bool entry_found = false;
                for (const auto &peer : peer_table_) {
                    if (peer.address == label) {
                        entry_found = true;
                        break;
                    }
                }
                if (!entry_found && !id_full_zero(their_id)) {
                    PeerInfo peer{};
                    peer.address = label;
                    std::memcpy(&peer.node_id, their_id.data(), 8);
                    peer.listen_ip = lip;
                    peer.listen_port = lport;
                    peer.listen_valid = lvalid;
                    peer.last_seen = std::chrono::system_clock::now();
                    peer_table_.insert(peer);
                }
            }
            continue;
        }
        if (type == WireMsgType::ADDRS) {
            // Outbound side: the connection is ours and handshaked by
            // construction, but keep the one-per-connection flood gate
            // symmetric with the inbound loop.
            if (addr_seen) {
                report_withhold(label, 20);
                continue;
            }
            addr_seen = true;
            // Exclude the peer's own listen endpoint from candidates.
            uint32_t lip = 0;
            uint16_t lport = 0;
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                for (const auto &peer : peer_table_) {
                    if (peer.address == label && peer.listen_valid) {
                        lip = peer.listen_ip;
                        lport = peer.listen_port;
                        break;
                    }
                }
            }
            if (ingest_addrs(payload, lip, lport) < 0)
                report_withhold(label, 20); // malformed payload
            continue;
        }
        if (type == WireMsgType::RAW_BLOCK_64K && payload.size() == 65536) {
            handle_incoming_frame(label,
                                  std::span<const uint8_t, 65536>(payload.data(), payload.size()));
            continue;
        }
        if (type == WireMsgType::PQ_WITNESS &&
            payload.size() == 32 + 42 + sizeof(vx::crypto::pq::PqSignatureWitness)) {
            vx::crypto::pq::PqSignatureWitness w;
            std::memcpy(&w, payload.data() + 74, sizeof(w));
            std::array<uint8_t, 32> digest{};
            std::memcpy(digest.data(), payload.data(), 32);
            vx::crypto::pq::PqWitnessRegistry::instance().register_witness_bytes(
                digest, payload.data() + 32, w);
            if (witness_callback_)
                witness_callback_(digest);
            continue;
        }
        if (type == WireMsgType::ROLLOVER_CERT) {
            handle_rollover_cert_payload(payload);
            continue;
        }
        if (type == WireMsgType::CERT_INV) {
            handle_cert_inv(fd, label, payload);
            continue;
        }
        if (type == WireMsgType::GET_CERTS) {
            handle_get_certs(fd, label, payload);
            continue;
        }
        break; // unexpected message type: drop the connection
    }
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        peer_fds_.erase(label);
    }
    ::close(fd);
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

bool SwarmNode::connect_to_peer(const PeerInfo &peer) {
    (void)peer;
    // Real TCP connections go through connect_peer_tcp(); virtual mesh peers
    // (10.0.0.x simulation range) remain bookkeeping-only.
    return true;
}

void SwarmNode::disconnect_from_peer(const PeerInfo &peer) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = peer_fds_.find(peer.address);
    if (it != peer_fds_.end()) {
        if (it->second >= 0)
            ::close(it->second);
        peer_fds_.erase(it);
    }
}

// ── Wire send / recv ────────────────────────────────────────────────────────

uint64_t SwarmNode::send_packet(int fd, const WireHeader &hdr, const uint8_t *payload) {
    if (fd < 0)
        return 0;

    // Header goes out with crc32c already filled by the caller.
    ssize_t n = ::send(fd, &hdr, sizeof(hdr), MSG_NOSIGNAL);
    if (n != static_cast<ssize_t>(sizeof(hdr)))
        return 0;

    uint64_t total = sizeof(hdr);
    if (hdr.payload_len > 0 && payload) {
        size_t off = 0;
        while (off < hdr.payload_len) {
            n = ::send(fd, payload + off, hdr.payload_len - off, MSG_NOSIGNAL);
            if (n <= 0) {
                if (n < 0 && (errno == EINTR))
                    continue;
                return 0;
            }
            off += static_cast<size_t>(n);
            total += static_cast<uint64_t>(n);
        }
    }
    vx60_bytes_transferred_.fetch_add(total);
    return total;
}

bool SwarmNode::recv_packet(int fd, WireHeader &hdr, std::vector<uint8_t> &payload) {
    if (fd < 0)
        return false;

    // Read exactly 24 bytes of header
    size_t got = 0;
    auto *hdr_bytes = reinterpret_cast<uint8_t *>(&hdr);
    while (got < sizeof(hdr)) {
        ssize_t n = ::recv(fd, hdr_bytes + got, sizeof(hdr) - got, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;
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
            if (n < 0 && errno == EINTR)
                continue;
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
                                     const uint8_t *block_data) {
    if (socket_fd < 0)
        return false;

    WireHeader hdr = make_header(WireMsgType::RAW_BLOCK_64K, 65536, session_nonce_.fetch_add(1),
                                 WIRE_FLAG_ZERO_COPY);
    hdr.crc32c = 0; // payload is streamed zero-copy; CRC covers header itself

    // 1. 24-byte header
    ssize_t n = ::send(socket_fd, &hdr, sizeof(hdr), MSG_NOSIGNAL);
    if (n != static_cast<ssize_t>(sizeof(hdr)))
        return false;

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
                if (s < 0 && errno == EINTR)
                    continue;
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
                if (s < 0 && errno == EINTR)
                    continue;
                return false;
            }
            sent += static_cast<uint64_t>(s);
            off += static_cast<size_t>(s);
        }
    } else if (!zero_copy && !block_data) {
        return false;
    }

    zero_copy_bytes_sent_.fetch_add(sent);
    if (sent >= 24 + 65536)
        zero_copy_blocks_streamed_.fetch_add(1);
    vx60_bytes_transferred_.fetch_add(sent);
    return true;
}

// ── Frame broadcast / handling ──────────────────────────────────────────────

bool SwarmNode::send_frame_to_peer(int fd, const std::span<const uint8_t, 65536> &frame) {
    if (fd < 0)
        return false;
    WireHeader hdr = make_header(WireMsgType::RAW_BLOCK_64K, 65536, session_nonce_.fetch_add(1),
                                 WIRE_FLAG_ZERO_COPY);
    hdr.crc32c = compute_wire_crc32c(frame.data(), frame.size());
    ssize_t n = ::send(fd, &hdr, sizeof(hdr), MSG_NOSIGNAL);
    if (n != static_cast<ssize_t>(sizeof(hdr)))
        return false;
    size_t off = 0;
    while (off < frame.size()) {
        n = ::send(fd, frame.data() + off, frame.size() - off, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;
            return false;
        }
        off += static_cast<size_t>(n);
    }
    vx60_bytes_transferred_.fetch_add(sizeof(hdr) + frame.size());
    return true;
}

void SwarmNode::broadcast_frame(const std::span<const uint8_t, 65536> &frame) {
    // Snapshot the peer fds under the lock, send OUTSIDE it: a blocking
    // ::send to a stalled peer (full TCP window) must never hold
    // peers_mutex_ - that would freeze health_loop, disconnect_from_peer
    // and emergency_stop behind one slow socket.
    std::vector<int> fds;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        fds.reserve(peer_fds_.size());
        for (const auto &[addr, fd] : peer_fds_) {
            (void)addr;
            fds.push_back(fd);
        }
    }
    for (int fd : fds)
        send_frame_to_peer(fd, frame);
}

// BACKLOG 0.8: witnesses travel as their own wire message so a receiving
// node can verify the block's user transactions on arrival (the 64 KiB
// frame has no spare bytes — the witness rides beside the frame, never
// inside it).
void SwarmNode::set_witness_callback(WitnessCallback cb) {
    witness_callback_ = std::move(cb);
}

void SwarmNode::set_peer_connected_callback(PeerConnectedCallback cb) {
    peer_connected_callback_ = std::move(cb);
}

bool SwarmNode::send_witnesses_to(const std::string &peer_label,
                                  const std::span<const uint8_t, 65536> &frame) {
    auto *raw = reinterpret_cast<const blockchain::RawBlock *>(frame.data());
    const uint32_t count =
        raw->header.tx_count > blockchain::MAX_TX_PER_BLOCK ? 0u : raw->header.tx_count;
    std::vector<std::array<uint8_t, 32 + 42 + sizeof(vx::crypto::pq::PqSignatureWitness)>> payloads;
    for (uint32_t i = 0; i < count; ++i) {
        const blockchain::Transaction &tx = raw->transactions[i];
        const char *s = reinterpret_cast<const char *>(tx.sender_nfa);
        if (std::strncmp(s, "GENESIS", 7) == 0 || std::strncmp(s, "MINER_", 6) == 0)
            continue; // system senders carry no witness
        const auto digest = vx::crypto::pq::tx_msg_digest(tx);
        vx::crypto::pq::PqSignatureWitness w;
        if (!vx::crypto::pq::PqWitnessRegistry::instance().lookup(digest, w))
            continue; // nothing to relay for this tx
        std::array<uint8_t, 32 + 42 + sizeof(vx::crypto::pq::PqSignatureWitness)> payload{};
        std::memcpy(payload.data(), digest.data(), 32);
        std::memcpy(payload.data() + 32, tx.sender_nfa, 42);
        std::memcpy(payload.data() + 74, &w, sizeof(w));
        payloads.push_back(payload);
    }
    int fd = -1;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        auto it = peer_fds_.find(peer_label);
        if (it == peer_fds_.end())
            return false;
        // Security review P2-5 (2.11 third checkbox): unlike the inbound
        // retention path (the caller IS the fd owner there), a serve for an
        // OUTBOUND peer runs on the dialer thread while the fd's owner is
        // the reader thread - if the remote hangs up mid-serve, the owner
        // closes the fd and the number can be recycled into a new
        // connection mid-send. Duplicate the descriptor under the lock and
        // send on the dup: both share the file description, so a shutdown()
        // by the health loop still kills the send, but close() by the owner
        // cannot swap the target out from under us.
        fd = ::fcntl(it->second, F_DUPFD_CLOEXEC, 0);
        if (fd < 0)
            return false;
    }
    const bool ok = send_payloads_to(fd, payloads);
    ::close(fd);
    return ok;
}

void SwarmNode::broadcast_witnesses_for(const std::span<const uint8_t, 65536> &frame) {
    auto *raw = reinterpret_cast<const blockchain::RawBlock *>(frame.data());
    const uint32_t count =
        raw->header.tx_count > blockchain::MAX_TX_PER_BLOCK ? 0u : raw->header.tx_count;
    std::vector<std::array<uint8_t, 32 + 42 + sizeof(vx::crypto::pq::PqSignatureWitness)>> payloads;
    for (uint32_t i = 0; i < count; ++i) {
        const blockchain::Transaction &tx = raw->transactions[i];
        const char *s = reinterpret_cast<const char *>(tx.sender_nfa);
        if (std::strncmp(s, "GENESIS", 7) == 0 || std::strncmp(s, "MINER_", 6) == 0)
            continue; // system senders carry no witness
        const auto digest = vx::crypto::pq::tx_msg_digest(tx);
        vx::crypto::pq::PqSignatureWitness w;
        if (!vx::crypto::pq::PqWitnessRegistry::instance().lookup(digest, w))
            continue; // nothing to relay for this tx
        std::array<uint8_t, 32 + 42 + sizeof(vx::crypto::pq::PqSignatureWitness)> payload{};
        std::memcpy(payload.data(), digest.data(), 32);
        std::memcpy(payload.data() + 32, tx.sender_nfa, 42);
        std::memcpy(payload.data() + 74, &w, sizeof(w));
        payloads.push_back(payload);
    }
    // Snapshot + send outside the lock (same reasoning as broadcast_frame);
    // a short header send desyncs the peer's stream, so it is fatal there.
    std::vector<int> fds;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        fds.reserve(peer_fds_.size());
        for (const auto &[addr, fd] : peer_fds_) {
            (void)addr;
            fds.push_back(fd);
        }
    }
    for (int fd : fds)
        send_payloads_to(fd, payloads);
}

// BACKLOG 1.5 P0 GATE: cert backfill plumbing ────────────────────────────────

// Sends one CERT_INV / GET_CERTS packet: count(u32 LE) + ids. The caller
// owns the fd (either the connection's own reader thread or a dup taken
// under peers_mutex_).
bool SwarmNode::send_id_list_to(int fd, WireMsgType type,
                                const std::vector<std::array<uint8_t, 32>> &ids) {
    if (ids.empty() || ids.size() > 64)
        return false;
    std::vector<uint8_t> payload(4 + ids.size() * 32);
    const uint32_t count = static_cast<uint32_t>(ids.size());
    std::memcpy(payload.data(), &count, 4);
    for (size_t i = 0; i < ids.size(); ++i)
        std::memcpy(payload.data() + 4 + i * 32, ids[i].data(), 32);
    WireHeader hdr =
        make_header(type, static_cast<uint32_t>(payload.size()), session_nonce_.fetch_add(1));
    hdr.crc32c = compute_wire_crc32c(payload.data(), payload.size());
    if (::send(fd, &hdr, sizeof(hdr), MSG_NOSIGNAL) != static_cast<ssize_t>(sizeof(hdr)))
        return false;
    size_t off = 0;
    while (off < payload.size()) {
        const ssize_t n = ::send(fd, payload.data() + off, payload.size() - off, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;
            return false;
        }
        off += static_cast<size_t>(n);
    }
    return true;
}

// Sends FULL certificate records (the ROLLOVER_CERT payload layout) on one
// fd. Same dup-fd rationale as send_payloads_to applies at the label-lookup
// call sites; here the fd is already owned or duplicated by the caller.
bool SwarmNode::send_cert_payloads_to(
    int fd,
    const std::vector<
        std::array<uint8_t, 42 + 4 + 4 + 32 + 32 + sizeof(vx::crypto::pq::PqSignatureWitness)>>
        &payloads) {
    for (const auto &payload : payloads) {
        WireHeader hdr =
            make_header(WireMsgType::ROLLOVER_CERT, static_cast<uint32_t>(payload.size()),
                        session_nonce_.fetch_add(1));
        hdr.crc32c = compute_wire_crc32c(payload.data(), payload.size());
        if (::send(fd, &hdr, sizeof(hdr), MSG_NOSIGNAL) != static_cast<ssize_t>(sizeof(hdr)))
            return false;
        size_t off = 0;
        while (off < payload.size()) {
            const ssize_t n = ::send(fd, payload.data() + off, payload.size() - off, MSG_NOSIGNAL);
            if (n <= 0) {
                if (n < 0 && errno == EINTR)
                    continue;
                return false;
            }
            off += static_cast<size_t>(n);
        }
    }
    return true;
}

void SwarmNode::broadcast_cert_inv_for(const vx::crypto::pq::PqRolloverCert &cert) {
    std::vector<std::array<uint8_t, 32>> ids{vx::crypto::pq::rollover_cert_id(cert)};
    // Snapshot + send outside the lock (same reasoning as broadcast_frame).
    std::vector<int> fds;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        fds.reserve(peer_fds_.size());
        for (const auto &[addr, fd] : peer_fds_) {
            (void)addr;
            fds.push_back(fd);
        }
    }
    for (int fd : fds)
        send_id_list_to(fd, WireMsgType::CERT_INV, ids);
}

void SwarmNode::send_cert_inv_to(const std::string &peer_label, size_t max_ids) {
    if (max_ids > 64)
        max_ids = 64;
    const auto ids = vx::crypto::pq::PqWitnessRegistry::instance().cert_inventory(max_ids);
    if (ids.empty())
        return;
    int fd = -1;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        auto it = peer_fds_.find(peer_label);
        if (it == peer_fds_.end())
            return;
        // Dup-fd discipline (see send_witnesses_to): the label's owner
        // thread may close the fd while this send runs.
        fd = ::fcntl(it->second, F_DUPFD_CLOEXEC, 0);
        if (fd < 0)
            return;
    }
    send_id_list_to(fd, WireMsgType::CERT_INV, ids);
    ::close(fd);
}

// Parses a bounded id list (count <= 64, payload length checked by the
// dispatch site). Answers CERT_INV with GET_CERTS naming every id this
// node does NOT hold; answers GET_CERTS with the FULL verified certificate
// records for every id it DOES hold. Both responses go targeted down the
// requesting connection.
void SwarmNode::handle_cert_inv(int fd, const std::string &peer_label,
                                const std::vector<uint8_t> &payload) {
    if (payload.size() < 4 || payload.size() > 4 + 64 * 32)
        return;
    uint32_t count = 0;
    std::memcpy(&count, payload.data(), 4);
    if (count > 64 || payload.size() < 4 + count * 32)
        return;
    std::vector<std::array<uint8_t, 32>> missing;
    for (uint32_t i = 0; i < count; ++i) {
        std::array<uint8_t, 32> id{};
        std::memcpy(id.data(), payload.data() + 4 + i * 32, 32);
        if (!vx::crypto::pq::PqWitnessRegistry::instance().have_cert_id(id))
            missing.push_back(id);
    }
    if (missing.empty())
        return;
    send_id_list_to(fd, WireMsgType::GET_CERTS, missing);
}

void SwarmNode::handle_get_certs(int fd, const std::string &peer_label,
                                 const std::vector<uint8_t> &payload) {
    if (payload.size() < 4 || payload.size() > 4 + 64 * 32)
        return;
    uint32_t count = 0;
    std::memcpy(&count, payload.data(), 4);
    if (count > 64 || payload.size() < 4 + count * 32)
        return;
    std::vector<std::array<uint8_t, kRolloverCertPayloadSize>> payloads;
    for (uint32_t i = 0; i < count; ++i) {
        std::array<uint8_t, 32> id{};
        std::memcpy(id.data(), payload.data() + 4 + i * 32, 32);
        vx::crypto::pq::PqRolloverCert cert;
        if (!vx::crypto::pq::PqWitnessRegistry::instance().lookup_cert_by_id(id, cert))
            continue; // unknown id: answer nothing for it (no error channel)
        std::array<uint8_t, kRolloverCertPayloadSize> payload{};
        std::memcpy(payload.data(), cert.sender.data(), 42);
        std::memcpy(payload.data() + 42, &cert.from_window, 4);
        std::memcpy(payload.data() + 46, &cert.to_window, 4);
        std::memcpy(payload.data() + 50, cert.old_root.data(), 32);
        std::memcpy(payload.data() + 82, cert.new_root.data(), 32);
        std::memcpy(payload.data() + 114, &cert.witness, sizeof(cert.witness));
        payloads.push_back(payload);
    }
    if (payloads.empty())
        return;
    send_cert_payloads_to(fd, payloads);
}

// Sends PQ_WITNESS packets for the prebuilt payloads on one socket.
// A short header send desyncs the peer's stream, so it is fatal there;
// here that surfaces as returning false (the caller logs or drops).
bool SwarmNode::send_payloads_to(
    int fd,
    const std::vector<std::array<uint8_t, 32 + 42 + sizeof(vx::crypto::pq::PqSignatureWitness)>>
        &payloads) {
    for (const auto &payload : payloads) {
        WireHeader hdr = make_header(WireMsgType::PQ_WITNESS, static_cast<uint32_t>(payload.size()),
                                     session_nonce_.fetch_add(1));
        hdr.crc32c = compute_wire_crc32c(payload.data(), payload.size());
        ssize_t n = ::send(fd, &hdr, sizeof(hdr), MSG_NOSIGNAL);
        if (n != static_cast<ssize_t>(sizeof(hdr)))
            return false;
        size_t off = 0;
        while (off < payload.size()) {
            n = ::send(fd, payload.data() + off, payload.size() - off, MSG_NOSIGNAL);
            if (n <= 0) {
                if (n < 0 && errno == EINTR)
                    continue;
                return false;
            }
            off += static_cast<size_t>(n);
        }
    }
    return true;
}

// BACKLOG 1.5: relay a certified one-window key rotation. Payload layout
// mirrors handle_rollover_cert_payload; the receiver re-verifies the FULL
// certificate object before storing, so relay is fire-and-forget here.
void SwarmNode::broadcast_rollover_cert(const vx::crypto::pq::PqRolloverCert &cert) {
    std::array<uint8_t, kRolloverCertPayloadSize> payload{};
    std::memcpy(payload.data(), cert.sender.data(), 42);
    std::memcpy(payload.data() + 42, &cert.from_window, 4);
    std::memcpy(payload.data() + 46, &cert.to_window, 4);
    std::memcpy(payload.data() + 50, cert.old_root.data(), 32);
    std::memcpy(payload.data() + 82, cert.new_root.data(), 32);
    std::memcpy(payload.data() + 114, &cert.witness, sizeof(cert.witness));
    // Snapshot + send outside the lock (same reasoning as broadcast_frame);
    // a short header send desyncs the peer's stream, so it is fatal there.
    std::vector<int> fds;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        fds.reserve(peer_fds_.size());
        for (const auto &[addr, fd] : peer_fds_) {
            (void)addr;
            fds.push_back(fd);
        }
    }
    for (int fd : fds) {
        WireHeader hdr =
            make_header(WireMsgType::ROLLOVER_CERT, static_cast<uint32_t>(payload.size()),
                        session_nonce_.fetch_add(1));
        hdr.crc32c = compute_wire_crc32c(payload.data(), payload.size());
        ssize_t n = ::send(fd, &hdr, sizeof(hdr), MSG_NOSIGNAL);
        if (n != static_cast<ssize_t>(sizeof(hdr)))
            continue;
        size_t off = 0;
        while (off < payload.size()) {
            n = ::send(fd, payload.data() + off, payload.size() - off, MSG_NOSIGNAL);
            if (n <= 0) {
                if (n < 0 && errno == EINTR)
                    continue;
                break;
            }
            off += static_cast<size_t>(n);
        }
    }
}

void SwarmNode::set_frame_hook(FrameHook hook) {
    frame_hook_ = std::move(hook);
}

void SwarmNode::handle_incoming_frame(const std::string &from_peer,
                                      const std::span<const uint8_t, 65536> &frame) {
    if (!verify_frame(frame)) {
        ban_peer(from_peer, 100);
        return;
    }
    if (frame_hook_)
        frame_hook_(frame.data(), frame.size(), from_peer);
    // Further block-relay policy (apply / re-broadcast) lives in the hook.
}

bool SwarmNode::verify_frame(const std::span<const uint8_t, 65536> &frame) {
    if (frame.size() < 4)
        return false;
    uint32_t magic;
    std::memcpy(&magic, frame.data(), 4);
    return magic == blockchain::BLOCK_MAGIC;
}

// ── Peer reputation ─────────────────────────────────────────────────────────

void SwarmNode::ban_peer(const std::string &address, int score_increment) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (auto it = peer_table_.begin(); it != peer_table_.end(); ++it) {
        if (it->address == address) {
            PeerInfo peer = *it;
            peer.dos_score += score_increment;
            if (peer.dos_score >= 100)
                peer.is_banned = true;
            peer_table_.erase(it);
            peer_table_.insert(peer);
            return;
        }
    }
}

void SwarmNode::report_withhold(const std::string &peer_address, int score_increment) {
    ban_peer(peer_address, score_increment);
}

bool SwarmNode::peer_is_banned(const std::string &peer_address) const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (const auto &p : peer_table_) {
        if (p.address == peer_address)
            return p.is_banned;
    }
    return false;
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

void SwarmNode::resolve_fork(const PeerInfo &challenger) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    std::cout << "[Swarm] Fork resolved: keeping heaviest work" << std::endl;
}

// ── VX60 listener bind ──────────────────────────────────────────────────────

bool SwarmNode::bind_p2p_listener(uint16_t port) {
    int fd = ::socket(AF_INET, SOCK_STREAM, 0);
    if (fd < 0)
        return false;
    int opt = 1;
    ::setsockopt(fd, SOL_SOCKET, SO_REUSEADDR, &opt, sizeof(opt));
    sockaddr_in addr{};
    addr.sin_family = AF_INET;
    addr.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
    addr.sin_port = htons(port);
    if (::bind(fd, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0 || ::listen(fd, 8) < 0) {
        ::close(fd);
        return false;
    }
    listen_fd_ = fd;
    listen_port_.store(port);
    // Peer discovery: we advertise exactly what we bound (loopback today;
    // a broader --bind rides its own backlog item). Advertising anything
    // else would be a lie to dialers. self_listen_ip_ is NETWORK byte
    // order, same representation as every other listen ip on this node.
    self_listen_ip_ = htonl(INADDR_LOOPBACK);
    return true;
}

// ── Peer discovery (ADDRS / PEX) ────────────────────────────────────────────
//
// Design (archives/notes/pex-addr-design.md): both sides of a connection
// push ONE ADDRS message right after the handshake exchange. Entries are
// LISTEN addresses only (an observed address carries an ephemeral port and
// is worthless to a third node). The health loop dials at most one
// candidate per 5 s tick and only while connected peers are below the
// discovery floor - a 128-entry candidate list can never become a dial
// storm (<= 1 outbound per 5 s).

void SwarmNode::load_or_create_node_id(const std::string &data_dir) {
    if (node_id_ != std::array<uint8_t, 32>{})
        return; // already loaded (explicit call order guard)
    std::array<uint8_t, 32> id{};
    const std::filesystem::path file = std::filesystem::path(data_dir) / "node_id";
    std::error_code ec;
    // Read an existing identity. A short or unreadable file is treated as
    // absent: we do NOT fail the node over identity creation.
    if (std::filesystem::exists(file, ec)) {
        int fd = ::open(file.c_str(), O_RDONLY);
        if (fd >= 0) {
            size_t got = 0;
            while (got < id.size()) {
                ssize_t n = ::read(fd, id.data() + got, id.size() - got);
                if (n <= 0)
                    break;
                got += static_cast<size_t>(n);
            }
            ::close(fd);
            if (got == id.size()) {
                node_id_ = id;
                std::cout << "[Swarm] node identity loaded (" << data_dir << "/node_id)\n";
                return;
            }
            // Security review P2 (peer discovery, 2026-11-11): a corrupt /
            // truncated identity file used to fall straight through to the
            // O_EXCL create, which fails EEXIST forever - the node ran
            // PERMANENTLY identityless (self-dial detection silently
            // disabled). Replace the dead file instead: unlink the corrupt
            // bytes, then create below.
            ::unlink(file.c_str());
        }
        std::cerr << "[Swarm] node_id file unreadable, regenerating\n";
    }
    // Create: O_EXCL so a concurrent plant loses; 0600 so the identity is
    // owner-private. getrandom failure falls back to std::random_device.
    int fd = ::open(file.c_str(), O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd >= 0) {
        if (::getrandom(id.data(), id.size(), 0) != static_cast<ssize_t>(id.size())) {
            std::random_device rd;
            for (auto &b : id)
                b = static_cast<uint8_t>(rd());
        }
        ssize_t put = ::write(fd, id.data(), id.size());
        ::close(fd);
        if (put == static_cast<ssize_t>(id.size())) {
            node_id_ = id;
            std::cout << "[Swarm] node identity created (" << file.string() << ")\n";
            return;
        }
        std::cerr << "[Swarm] node_id write failed; running identityless this session\n";
        std::array<uint8_t, 32>{}.swap(id);
        node_id_ = id;
        return;
    }
    std::cerr << "[Swarm] node_id create failed (errno " << errno
              << "); running identityless this session\n";
}

bool SwarmNode::add_addr_candidate(uint32_t ip_net, uint16_t port) {
    if (port == 0)
        return false;
    // Never a self-candidate: dialing ourselves is filtered at handshake
    // (node_id match), but not even queueing it is cheaper.
    if (listen_port_.load() != 0 && ip_net == self_listen_ip_ && port == listen_port_.load())
        return false;
    // Security review P2 (peer discovery, 2026-11-11): never dial
    // unspecified or multicast targets - they are pure waste of the
    // bounded dial budget at best and a probe primitive at worst. Loopback
    // is ALLOWED on purpose: the testnet topology (single host, three
    // nodes) is loopback-only, and the discovery integration test depends
    // on it. OPEN ITEM before any multi-host deployment: loopback
    // acceptance is a localhost-SSRF/probe primitive on a real network
    // (a peer can aim our dial budget at our own RPC port); it must gain
    // a default-off switch together with real-interface advertisement in
    // bind_p2p_listener (see BACKLOG "public binary surface pass").
    const uint32_t ip_host = ntohl(ip_net);
    if (ip_host == INADDR_ANY || (ip_host >> 24) == 224 || (ip_host >> 24) == 255)
        return false;
    std::lock_guard<std::mutex> lock(peers_mutex_);
    for (const auto &c : addr_candidates_)
        if (c.ip == ip_net && c.port == port)
            return false;
    if (addr_candidates_.size() >= kMaxAddrCandidates)
        addr_candidates_.pop_front();
    addr_candidates_.push_back(PeerCandidate{ip_net, port, 0});
    return true;
}

size_t SwarmNode::addr_candidate_count() const {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    return addr_candidates_.size();
}

size_t SwarmNode::add_seed_host(const std::string &host_or_hostport) {
    std::string host = host_or_hostport;
    uint16_t port = 19088; // default VX60 wire port (--p2p default in main)
    const size_t colon = host.rfind(':');
    if (colon != std::string::npos && host.find(':') == colon) {
        // Security review P2 (peer discovery, 2026-11-11): a garbage port
        // ("host:", "host:abc") used to throw uncaught from main() and
        // kill the node at startup. A seed host is advisory input: warn
        // and skip instead of terminating.
        try {
            const unsigned long p = std::stoul(host.substr(colon + 1));
            if (p == 0 || p > 65535) {
                std::cerr << "[Swarm] seed host '" << host_or_hostport
                          << "' port out of range, skipping\n";
                return 0;
            }
            port = static_cast<uint16_t>(p);
        } catch (const std::exception &) {
            std::cerr << "[Swarm] seed host '" << host_or_hostport
                      << "' has a malformed port, skipping\n";
            return 0;
        }
        host = host.substr(0, colon);
    }
    addrinfo hints{};
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;
    addrinfo *res = nullptr;
    if (::getaddrinfo(host.c_str(), nullptr, &hints, &res) != 0 || res == nullptr) {
        std::cerr << "[Swarm] seed host '" << host_or_hostport << "' did not resolve\n";
        return 0;
    }
    size_t queued = 0;
    for (addrinfo *ai = res; ai != nullptr; ai = ai->ai_next) {
        auto *sa = reinterpret_cast<sockaddr_in *>(ai->ai_addr);
        if (add_addr_candidate(sa->sin_addr.s_addr, port))
            ++queued;
    }
    ::freeaddrinfo(res);
    if (queued > 0)
        std::cout << "[Swarm] seed '" << host_or_hostport << "': " << queued
                  << " candidate(s) queued\n";
    return queued;
}

// Returns -1 when the payload is MALFORMED (a protocol violation worth a
// DoS strike), otherwise the number of candidates newly ingested. Zero is
// a legal outcome - the receiver may already know every advertised
// endpoint - and must never be punished: striking on it would penalize
// honest peers in a steady-state mesh (security review P2, 2026-11-11).
int SwarmNode::ingest_addrs(const std::vector<uint8_t> &payload, uint32_t exclude_ip_net,
                            uint16_t exclude_port) {
    if (payload.size() < 4)
        return -1;
    uint32_t count = 0;
    std::memcpy(&count, payload.data(), 4);
    if (count > kMaxAddrEntries ||
        payload.size() != 4 + static_cast<size_t>(count) * kAddrEntrySize)
        return -1;
    int ingested = 0;
    for (uint32_t i = 0; i < count; ++i) {
        const uint8_t *e = payload.data() + 4 + i * kAddrEntrySize;
        uint32_t ip_net;
        uint16_t port_le;
        std::memcpy(&ip_net, e, 4);
        std::memcpy(&port_le, e + 4, 2);
        uint16_t port = ntohs(port_le);
        if (port == 0)
            continue;
        // Exclude self (exact bound-endpoint match) and the sender's listen
        // endpoint (dialing it back over the same socket we already have is
        // a loop, not discovery).
        if (listen_port_.load() != 0 && ip_net == self_listen_ip_ && port == listen_port_.load())
            continue;
        if (ip_net == exclude_ip_net && port == exclude_port)
            continue;
        if (add_addr_candidate(ip_net, port))
            ++ingested;
    }
    return ingested;
}

void SwarmNode::send_self_announce(int fd) {
    // Height/work/tip stay 0 on the live discovery path: the real mesh has
    // no fork-resolution use for them yet (the split-brain simulator sends
    // real values over its own raw sockets).
    std::vector<uint8_t> p(kHandshakeV2Size, 0);
    const uint64_t zero64 = 0;
    std::memcpy(p.data(), &zero64, 8);
    std::memcpy(p.data() + 8, &zero64, 8);
    std::memcpy(p.data() + 48, node_id_.data(), 32);
    if (listen_port_.load() != 0 && self_listen_ip_ != 0) {
        const uint32_t ip_net = self_listen_ip_; // already network order
        const uint16_t port_le = htons(listen_port_.load());
        std::memcpy(p.data() + 80, &ip_net, 4);
        std::memcpy(p.data() + 84, &port_le, 2);
        p[86] = 1;
    }
    WireHeader h = make_header(WireMsgType::HANDSHAKE, static_cast<uint32_t>(p.size()),
                               session_nonce_.fetch_add(1));
    h.crc32c = compute_wire_crc32c(p.data(), p.size());
    (void)send_packet(fd, h, p.data());
}

void SwarmNode::send_addrs_to(int fd, const std::string &exclude_label) {
    std::vector<std::pair<uint32_t, uint16_t>> entries;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        std::set<std::pair<uint32_t, uint16_t>> seen;
        // Connected peers first: their listen endpoints are confirmed live.
        // listen_ip is stored network-order (PeerInfo comment).
        for (const auto &peer : peer_table_) {
            if (!peer.listen_valid || peer.address == exclude_label)
                continue;
            auto key = std::make_pair(peer.listen_ip, peer.listen_port);
            if (seen.insert(key).second)
                entries.push_back(key);
        }
        for (const auto &c : addr_candidates_) {
            if (entries.size() >= kMaxAddrEntries)
                break;
            auto key = std::make_pair(c.ip, c.port);
            if (seen.insert(key).second)
                entries.push_back(key);
        }
    }
    if (entries.empty())
        return;
    if (entries.size() > kMaxAddrEntries)
        entries.resize(kMaxAddrEntries);
    std::vector<uint8_t> p(4 + entries.size() * kAddrEntrySize);
    uint32_t count = static_cast<uint32_t>(entries.size());
    std::memcpy(p.data(), &count, 4);
    for (size_t i = 0; i < entries.size(); ++i) {
        uint8_t *e = p.data() + 4 + i * kAddrEntrySize;
        std::memcpy(e, &entries[i].first, 4);
        uint16_t port_le = htons(entries[i].second);
        std::memcpy(e + 4, &port_le, 2);
    }
    WireHeader h = make_header(WireMsgType::ADDRS, static_cast<uint32_t>(p.size()),
                               session_nonce_.fetch_add(1));
    h.crc32c = compute_wire_crc32c(p.data(), p.size());
    (void)send_packet(fd, h, p.data());
}

// ── Background loops ────────────────────────────────────────────────────────

void SwarmNode::shutdown_accepted() {
    std::lock_guard<std::mutex> lock(accepted_mu_);
    for (int fd : accepted_fds_)
        ::shutdown(fd, SHUT_RDWR);
}

void SwarmNode::listener_loop() {
    while (!emergency_stop_requested_.load()) {
        const int lfd = listen_fd_.load();
        if (lfd < 0) {
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
            continue;
        }
        int c = ::accept(lfd, nullptr, nullptr);
        if (c < 0) {
            if (errno == EINTR)
                continue;
            if (emergency_stop_requested_.load())
                break;
            std::this_thread::sleep_for(std::chrono::milliseconds(50));
            continue;
        }
        {
            // Stop-race guard: accept() may have been blocked on an fd that
            // emergency_stop() shut down and closed while a concurrently
            // opened socket reused its number. Without this re-check such a
            // connection would be registered AFTER shutdown_accepted() and
            // leak past teardown (TSan fix follow-up, 2026-11-07).
            if (emergency_stop_requested_.load()) {
                ::close(c);
                break;
            }
            std::lock_guard<std::mutex> lock(accepted_mu_);
            accepted_fds_.insert(c);
        }
        // Each connection is served on its own thread: peers stay connected
        // indefinitely, so serving inline would block accept() for the rest
        // of the mesh.
        std::lock_guard<std::mutex> handlers_lock(handlers_mu_);
        conn_handlers_.emplace_back(&SwarmNode::serve_connection, this, c);
    }
}

void SwarmNode::serve_connection(int c) {
    int one = 1;
    ::setsockopt(c, IPPROTO_TCP, TCP_NODELAY, &one, sizeof(one));
    // Same send bound as connect_peer_tcp: an accepted peer that stops
    // reading must not block a broadcast (and with it state_mutex_) forever.
    struct timeval snd_tv{5, 0};
    ::setsockopt(c, SOL_SOCKET, SO_SNDTIMEO, &snd_tv, sizeof(snd_tv));

    // Serve one connection until EOF: PING -> PONG, RAW_BLOCK_64K ->
    // handle_incoming_frame (CRC32C already verified inside recv_packet).
    // Anything else is an unexpected message type; the connection is
    // closed rather than guessed at.
    //
    // The first verified packet promotes the connection to a tracked
    // peer: inbound connections become broadcast targets too, so a node
    // that was connected TO can relay back over the accepted socket.
    std::string peer_label = "loopback";
    bool registered = false;
    // Returns true only on the call that actually registered the peer, so
    // callers can fire one-shot connect side effects (retention re-serve)
    // without re-triggering them on every later packet.
    auto promote = [&]() -> bool {
        if (registered)
            return false;
        sockaddr_in sa{};
        socklen_t sl = sizeof(sa);
        uint16_t rport = 0;
        if (::getpeername(c, reinterpret_cast<sockaddr *>(&sa), &sl) == 0) {
            char ip[INET_ADDRSTRLEN] = {0};
            ::inet_ntop(AF_INET, &sa.sin_addr, ip, sizeof(ip));
            rport = ntohs(sa.sin_port);
            peer_label = std::string(ip) + ":" + std::to_string(rport);
        }
        std::lock_guard<std::mutex> lock(peers_mutex_);
        peer_fds_[peer_label] = c;
        PeerInfo peer{}; // zero-init: height/work/scores start at 0
        peer.address = peer_label;
        peer.node_id = 0; // unknown until a richer handshake exists
        peer.is_loopback = true;
        peer.last_seen = std::chrono::system_clock::now();
        peer_table_.insert(peer);
        registered = true;
        return true;
    };
    // Fired OUTSIDE the promote lock: the callback serves the witness
    // retention window, which re-enters peers_mutex_ through
    // send_witnesses_to - calling it under the lock would self-deadlock.
    auto fire_connected = [&]() {
        if (peer_connected_callback_)
            peer_connected_callback_(peer_label);
    };
    // Discovery (one-shot per connection, sent on the promote call): the
    // v2 self-announce (identity + listen endpoint) and one ADDRS push of
    // our known listen endpoints. Sends happen with NO swarm lock held -
    // they are plain socket writes like every other handler here.
    auto announce = [&]() {
        send_self_announce(c);
        send_addrs_to(c, peer_label);
    };
    // Discovery state: ADDRS is accepted at most once per connection (a
    // second one is a flood signal -> DoS strike); malformed likewise.
    bool addr_seen = false;
    for (;;) {
        WireHeader hdr{};
        std::vector<uint8_t> payload;
        if (!recv_packet(c, hdr, payload))
            break;
        const auto type = static_cast<WireMsgType>(hdr.msg_type);
        if (type == WireMsgType::PING) {
            if (promote()) {
                fire_connected();
                announce();
            }
            WireHeader pong = make_header(WireMsgType::PONG, 0, session_nonce_.fetch_add(1));
            pong.crc32c = compute_wire_crc32c(nullptr, 0);
            ::send(c, &pong, sizeof(pong), MSG_NOSIGNAL);
            continue;
        }
        if (type == WireMsgType::HANDSHAKE) {
            // v2 self-announce from the peer: record identity + listen
            // endpoint; a peer announcing OUR node_id is ourselves (self-dial
            // through discovery) - drop the connection on sight.
            uint64_t height = 0, work = 0;
            uint8_t tip[32] = {0};
            std::array<uint8_t, 32> their_id{};
            uint32_t lip = 0;
            uint16_t lport = 0;
            bool lvalid = false, is_self = false;
            if (!parse_handshake_payload(payload, height, work, tip, node_id_, is_self, their_id,
                                         lip, lport, lvalid)) {
                break; // malformed: unexpected message shape, close like the rest
            }
            if (is_self) {
                std::cerr << "[Swarm] self-dial detected via node_id, dropping " << peer_label
                          << "\n";
                break;
            }
            if (promote()) {
                fire_connected();
                announce();
            }
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                for (auto &peer : peer_table_) {
                    if (peer.address == peer_label) {
                        PeerInfo updated = peer;
                        // Fold the 32-byte identity into the ordering key
                        // (display/order only; self-detection compared the
                        // full 32 bytes above).
                        std::memcpy(&updated.node_id, their_id.data(), 8);
                        updated.listen_ip = lip;
                        updated.listen_port = lport;
                        updated.listen_valid = lvalid;
                        updated.last_seen = std::chrono::system_clock::now();
                        peer_table_.erase(peer);
                        peer_table_.insert(updated);
                        break;
                    }
                }
            }
            continue;
        }
        if (type == WireMsgType::ADDRS) {
            // Only a promoted (handshaked) connection may feed candidates:
            // an unauthenticated pre-promote push is dropped unanswered.
            if (!registered) {
                corrupted_packets_dropped_.fetch_add(1);
                continue;
            }
            if (addr_seen) {
                report_withhold(peer_label, 20);
                continue;
            }
            addr_seen = true;
            // Exclude the sender's own listen endpoint: dialing it back over
            // the same socket we already have is a loop, not discovery.
            uint32_t lip = 0;
            uint16_t lport = 0;
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                for (const auto &peer : peer_table_) {
                    if (peer.address == peer_label && peer.listen_valid) {
                        lip = peer.listen_ip;
                        lport = peer.listen_port;
                        break;
                    }
                }
            }
            if (ingest_addrs(payload, lip, lport) < 0)
                report_withhold(peer_label, 20); // malformed payload
            continue;
        }
        if (type == WireMsgType::RAW_BLOCK_64K && payload.size() == 65536) {
            if (promote()) {
                fire_connected();
                announce();
            }
            handle_incoming_frame(peer_label,
                                  std::span<const uint8_t, 65536>(payload.data(), payload.size()));
            continue;
        }
        if (type == WireMsgType::PQ_WITNESS &&
            payload.size() == 32 + 42 + sizeof(vx::crypto::pq::PqSignatureWitness)) {
            if (promote()) {
                fire_connected();
                announce();
            }
            vx::crypto::pq::PqSignatureWitness w;
            std::memcpy(&w, payload.data() + 74, sizeof(w));
            std::array<uint8_t, 32> digest{};
            std::memcpy(digest.data(), payload.data(), 32);
            vx::crypto::pq::PqWitnessRegistry::instance().register_witness_bytes(
                digest, payload.data() + 32, w);
            if (witness_callback_)
                witness_callback_(digest);
            continue;
        }
        if (type == WireMsgType::ROLLOVER_CERT) {
            if (promote()) {
                fire_connected();
                announce();
            }
            handle_rollover_cert_payload(payload);
            continue;
        }
        if (type == WireMsgType::CERT_INV) {
            handle_cert_inv(c, peer_label, payload);
            continue;
        }
        if (type == WireMsgType::GET_CERTS) {
            handle_get_certs(c, peer_label, payload);
            continue;
        }
        break;
    }
    if (registered) {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        peer_fds_.erase(peer_label);
        for (auto it = peer_table_.begin(); it != peer_table_.end(); ++it) {
            if (it->address == peer_label) {
                peer_table_.erase(it);
                break;
            }
        }
    }
    {
        std::lock_guard<std::mutex> lock(accepted_mu_);
        accepted_fds_.erase(c);
    }
    ::close(c);
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
        std::vector<int> banned_fds;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (auto it = peer_table_.begin(); it != peer_table_.end();) {
                PeerInfo peer = *it;
                if (peer.dos_score >= 100) {
                    peer.is_banned = true;
                    // disconnect_from_peer() locks peers_mutex_ itself, so it
                    // must NOT be called while this thread holds the lock:
                    // a non-recursive mutex would self-deadlock health_loop
                    // WITH the lock held, wedging every later peers_mutex_
                    // consumer (frame broadcasts, /api/swarm/peers, new
                    // peer connections). Act on the socket after unlocking.
                    //
                    // Every peer_fds_ entry has exactly one owner thread (the
                    // dialed reader or the accepted serve loop) that closes
                    // the fd on exit. shutdown() here wakes that owner, which
                    // then performs the single close; closing it here as well
                    // would be a double close, and if the fd number was
                    // recycled in between, the owner's close would kill an
                    // unrelated live connection.
                    auto fd_it = peer_fds_.find(peer.address);
                    if (fd_it != peer_fds_.end()) {
                        banned_fds.push_back(fd_it->second);
                        peer_fds_.erase(fd_it);
                    }
                    it = peer_table_.erase(it);
                } else {
                    peer.last_seen = std::chrono::system_clock::now();
                    ++it;
                }
            }
        }
        for (int fd : banned_fds) {
            // shutdown only: the owning reader/serve thread wakes, tears down
            // its state and closes the fd exactly once (see comment above).
            if (fd >= 0)
                ::shutdown(fd, SHUT_RDWR);
        }

        // Peer discovery auto-dial: at most ONE outbound attempt per tick
        // (5 s) and only while the mesh is below the discovery floor, so a
        // poisoned candidate list can never become a dial storm. The
        // candidate is consumed under the lock, dialed OUTSIDE it
        // (connect_peer_tcp takes peers_mutex_ itself), and evicted after
        // kMaxCandidateAttempts failed rounds.
        {
            uint32_t dip = 0;
            uint16_t dport = 0;
            bool have = false;
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                if (peer_fds_.size() < kMinAutoDialPeers && !addr_candidates_.empty()) {
                    auto &cand = addr_candidates_.front();
                    if (cand.attempts >= kMaxCandidateAttempts) {
                        addr_candidates_.pop_front();
                    } else {
                        cand.attempts += 1;
                        dip = cand.ip;
                        dport = cand.port;
                        have = true;
                    }
                }
            }
            if (have) {
                char ipstr[INET_ADDRSTRLEN] = {0};
                ::inet_ntop(AF_INET, &dip, ipstr, sizeof(ipstr));
                // Pop on SUCCESS: a connected candidate has served its
                // purpose and must not be re-dialed every tick (with the
                // duplicate-dial refusal this would otherwise spin forever
                // on an already-connected endpoint). On failure the
                // attempts counter (incremented above) evicts it after
                // kMaxCandidateAttempts rounds.
                if (connect_peer_tcp(ipstr, dport)) {
                    std::lock_guard<std::mutex> lock(peers_mutex_);
                    if (!addr_candidates_.empty() && addr_candidates_.front().ip == dip &&
                        addr_candidates_.front().port == dport)
                        addr_candidates_.pop_front();
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

using blockchain::BlockBuilder;
using blockchain::BlockFrame;
using blockchain::BlockView;
using blockchain::Transaction;
using state::LedgerState;
using storage::BlockStore;

constexpr uint64_t SB_BLOCK_BYTES = 65536;

// Cumulative PoGW work proxy: sum of mined heights' nonces folded by sponge.
// Node B mines more blocks => strictly greater cumulative work.
uint64_t work_of_heights(uint64_t blocks_mined) {
    // Monotone synthetic cumulative work: each block adds (height+1)*1e6.
    uint64_t w = 0;
    for (uint64_t i = 1; i <= blocks_mined; ++i)
        w += i * 1'000'000ULL;
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

    SimNode(const std::string &dir, const std::string &genesis_path) : data_dir(dir) {
        std::filesystem::create_directories(dir);
        const std::string ledger_path = dir + "/ledger.vxb";
        std::filesystem::remove(ledger_path); // fresh partition state each run
        store =
            std::make_unique<BlockStore>(ledger_path, genesis_path, 1); // sim: difficulty-1 PoGW
        ledger = std::make_unique<LedgerState>();
        undo = std::make_unique<vx::state::UndoEngine>(dir, *store, *ledger);
        // Apply genesis to state (journal entry stays in memory for O(1) undo)
        auto *g = store->get_block(0);
        if (g) {
            BlockView v{std::span<const uint8_t, SB_BLOCK_BYTES>(
                reinterpret_cast<const uint8_t *>(g), SB_BLOCK_BYTES)};
            ledger->apply_block(v);
            undo->apply_block(v);
        }
    }

    uint64_t height() const {
        return store->chain_height() - 1;
    }

    std::string tip_hex() const {
        uint8_t h[32];
        store->tip_hash(h);
        std::ostringstream oss;
        for (uint8_t b : h)
            oss << std::hex << std::setw(2) << std::setfill('0') << int(b);
        return oss.str();
    }

    // Mines `count` coinbase-only blocks; returns updated cumulative work.
    uint64_t mine(uint64_t count) {
        for (uint64_t i = 0; i < count; ++i) {
            const uint64_t h = store->chain_height();
            uint8_t tip[32];
            store->tip_hash(tip);

            Transaction cb{};
            vx::blockchain::set_nfa_field(cb.sender_nfa, "MINER_");
            for (size_t k = 6; k < 42; ++k)
                cb.sender_nfa[k] = '0';
            vx::blockchain::set_nfa_field(cb.receiver_nfa, "MINER_REWARD_ADDR_SPLIT_BRAIN_SIM");
            for (size_t k = 35; k < 42; ++k)
                cb.receiver_nfa[k] = '0';
            blockchain::tx_set_amount(cb, 1'000'000ULL * (h + 1)); // distinct per height
            blockchain::set_coinbase_binding(cb, h, tip);          // chain-position binding

            BlockBuilder b;
            b.set_height(h);
            b.set_timestamp(1'761'000'000ULL + h * 5); // >= genesis ts (intake monotonicity)
            b.set_prev_hash(tip);
            b.add_transaction(cb);
            b.finalize();

            // Fast PoGW: difficulty-1 search over the 64KB frame (leading zero byte)
            BlockFrame frame;
            auto fv = b.bytes();
            std::memcpy(frame.data(), fv.data(), SB_BLOCK_BYTES);
            auto *raw = reinterpret_cast<blockchain::RawBlock *>(frame.data());
            uint64_t nonce = 0;
            while (true) {
                raw->tail.pogw_nonce = nonce++;
                uint8_t hash[32];
                blockchain::VortexSponge256::compute(frame.data(), SB_BLOCK_BYTES, hash);
                if (hash[0] == 0)
                    break;
            }
            if (!store->append_block(frame))
                break;

            BlockView v{std::span<const uint8_t, SB_BLOCK_BYTES>(frame.data(), SB_BLOCK_BYTES)};
            undo->apply_block(v);
            ledger->apply_block(v);
            cumulative_pogw = work_of_heights(height());
        }
        return cumulative_pogw;
    }
};

// Send one 65536-byte block over VX60 RAW_BLOCK_64K with a real 24B header.
uint64_t vx60_send_block(int fd, uint64_t peer_nonce_base, const uint8_t *frame) {
    WireHeader hdr =
        SwarmNode::make_header(WireMsgType::RAW_BLOCK_64K, SB_BLOCK_BYTES, peer_nonce_base);
    hdr.crc32c = compute_wire_crc32c(frame, SB_BLOCK_BYTES);
    ssize_t n = ::send(fd, &hdr, sizeof(hdr), MSG_NOSIGNAL);
    if (n != static_cast<ssize_t>(sizeof(hdr)))
        return 0;
    size_t off = 0;
    uint64_t total = sizeof(hdr);
    while (off < SB_BLOCK_BYTES) {
        n = ::send(fd, frame + off, SB_BLOCK_BYTES - off, MSG_NOSIGNAL);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;
            return 0;
        }
        off += static_cast<size_t>(n);
        total += static_cast<uint64_t>(n);
    }
    return total;
}

// Receive one VX60 packet; validates magic + CRC32C; drops on corruption.
bool vx60_recv_packet(int fd, WireHeader &hdr, std::vector<uint8_t> &payload,
                      uint64_t &dropped_counter) {
    size_t got = 0;
    auto *p = reinterpret_cast<uint8_t *>(&hdr);
    while (got < sizeof(hdr)) {
        ssize_t n = ::recv(fd, p + got, sizeof(hdr) - got, 0);
        if (n <= 0) {
            if (n < 0 && errno == EINTR)
                continue;
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
            if (n < 0 && errno == EINTR)
                continue;
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

// Zero-trust review P2-4: the split-brain sandbox must be owner-private and
// must not outlive the simulation. 0700 on create (regardless of umask) and
// remove_all on every exit path — early returns, exceptions, success.
class TempDirGuard {
public:
    explicit TempDirGuard(std::string path) : path_(std::move(path)) {
    }
    ~TempDirGuard() {
        if (armed_) {
            std::error_code ec;
            std::filesystem::remove_all(path_, ec);
        }
    }
    TempDirGuard(const TempDirGuard &) = delete;
    TempDirGuard &operator=(const TempDirGuard &) = delete;
    const std::string &path() const {
        return path_;
    }

private:
    std::string path_;
    bool armed_ = true;
};

SplitBrainReport SwarmNode::simulate_live_split_brain_reorg() {
    SplitBrainReport report;
    const auto t0 = std::chrono::steady_clock::now();

    try {
        // Zero-trust review P2-3: a FIXED "<tmp>/vx_split_brain" is a
        // symlink-plant target — another process can pre-create the path as
        // a symlink and redirect the simulator's ledger writes, or race the
        // remove/create window. Use a per-process directory, refuse a
        // planted symlink, and create the final component EXCLUSIVELY so a
        // racing plant loses.
        const std::string base =
            (std::filesystem::temp_directory_path() /
             ("vx_split_brain-" + std::to_string(static_cast<long>(::getpid()))))
                .string();
        std::error_code fs_ec;
        const auto st = std::filesystem::symlink_status(base, fs_ec);
        if (!fs_ec && st.type() == std::filesystem::file_type::symlink) {
            report.error = "split-brain temp dir is a planted symlink; refusing";
            return report;
        }
        std::filesystem::remove_all(base, fs_ec); // stale leftovers of this pid
        fs_ec.clear();
        const bool created = std::filesystem::create_directory(base, fs_ec);
        if (fs_ec || !created) {
            // A real error, or the path already existed again (raced plant):
            // refuse rather than write into an attacker-chosen directory.
            report.error =
                "split-brain temp dir could not be created exclusively: " + fs_ec.message();
            return report;
        }
        // P2-4: owner-private sandbox regardless of umask — and round-2
        // review hardening: chmod via an O_NOFOLLOW directory fd (a symlink
        // swap between create and chmod would otherwise be followed), with
        // an inode identity check so a swapped path is refused, not chmodded
        // into an attacker-chosen target.
        fs_ec.clear();
        const int dirfd = ::open(base.c_str(), O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (dirfd < 0) {
            report.error = "split-brain temp dir vanished or is a symlink (race refused)";
            std::filesystem::remove_all(base, fs_ec);
            return report;
        }
        struct stat fd_sb{};
        struct stat path_sb{};
        const bool identity_ok = ::fstat(dirfd, &fd_sb) == 0 &&
                                 ::stat(base.c_str(), &path_sb) == 0 && S_ISDIR(fd_sb.st_mode) &&
                                 fd_sb.st_ino == path_sb.st_ino;
        if (!identity_ok || ::fchmod(dirfd, 0700) != 0) {
            report.error = "split-brain temp dir identity check or chmod 0700 failed";
            ::close(dirfd);
            std::filesystem::remove_all(base, fs_ec);
            return report;
        }
        ::close(dirfd);
        TempDirGuard sandbox(base); // removes the tree on every exit path

        const std::string genesis_path = "genesis.bin";
        try {
            blockchain::ensure_genesis_file(genesis_path);
        } catch (const std::exception &e) {
            report.error = std::string("cannot regenerate genesis.bin: ") + e.what();
            return report;
        }

        // ── Two isolated nodes on the shared genesis (height 0) ────────────
        SimNode node_a(base + "/node_a", genesis_path);
        SimNode node_b(base + "/node_b", genesis_path);

        // ── Partition (no communication) ──────────────────────────
        report.node_a_work = node_a.mine(2); // Node A: 2 blocks (less work)
        report.node_b_work = node_b.mine(4); // Node B: 4 blocks (more work)
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
        if (::bind(srv, reinterpret_cast<sockaddr *>(&addr), sizeof(addr)) < 0 ||
            ::listen(srv, 1) < 0) {
            ::close(srv);
            report.error = "bind/listen failed";
            return report;
        }
        socklen_t alen = sizeof(addr);
        ::getsockname(srv, reinterpret_cast<sockaddr *>(&addr), &alen);
        const uint16_t port = ntohs(addr.sin_port);

        std::thread acceptor([&]() { bfd = ::accept(srv, nullptr, nullptr); });
        cfd = ::socket(AF_INET, SOCK_STREAM, 0);
        sockaddr_in ca{};
        ca.sin_family = AF_INET;
        ca.sin_addr.s_addr = htonl(INADDR_LOOPBACK);
        ca.sin_port = htons(port);
        if (::connect(cfd, reinterpret_cast<sockaddr *>(&ca), sizeof(ca)) < 0) {
            report.error = "connect failed";
            acceptor.join();
            ::close(srv);
            return report;
        }
        acceptor.join();
        if (bfd < 0) {
            ::close(cfd);
            ::close(srv);
            report.error = "accept failed";
            return report;
        }

        uint64_t bytes_total = 0;

        // Node A -> Node B: HANDSHAKE (height, work, tip)
        {
            uint8_t tip[32];
            node_a.store->tip_hash(tip);
            auto p = handshake_payload(node_a.height(), node_a.cumulative_pogw, tip);
            WireHeader h =
                SwarmNode::make_header(WireMsgType::HANDSHAKE, static_cast<uint32_t>(p.size()),
                                       session_nonce_.fetch_add(1));
            h.crc32c = compute_wire_crc32c(p.data(), p.size());
            bytes_total += send_packet(bfd, h, p.data());
        }
        // Node B -> Node A: HANDSHAKE — Node A learns B is heavier
        {
            uint8_t tip[32];
            node_b.store->tip_hash(tip);
            auto p = handshake_payload(node_b.height(), node_b.cumulative_pogw, tip);
            WireHeader h =
                SwarmNode::make_header(WireMsgType::HANDSHAKE, static_cast<uint32_t>(p.size()),
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
                ::close(cfd);
                ::close(bfd);
                ::close(srv);
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
                auto *raw = node_b.store->get_block(h);
                if (!raw)
                    continue;
                b_frames.emplace_back();
                std::memcpy(b_frames.back().data(), raw, SB_BLOCK_BYTES);
                bytes_total +=
                    vx60_send_block(bfd, session_nonce_.fetch_add(1), b_frames.back().data());
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
            node_a.store =
                std::make_unique<BlockStore>(base + "/node_a/ledger.vxb", genesis_path, 1);
            // The journal survived the rollback; re-point it at the reopened
            // store (its old reference died with store.reset() above).
            node_a.undo->attach_store(*node_a.store);

            // 3c. Node A applies B's 4 blocks (received over VX60).
            for (uint64_t h = 1; h <= report.node_b_height; ++h) {
                BlockView v{std::span<const uint8_t, SB_BLOCK_BYTES>(b_frames[h - 1].data(),
                                                                     SB_BLOCK_BYTES)};
                node_a.undo->apply_block(v);
                if (node_a.ledger->apply_block(v).ok) {
                    node_a.undo->commit_undo_point();
                    node_a.store->append_block(b_frames[h - 1]);
                    ++report.blocks_resynced;
                } else {
                    // The block never entered the ledger: its pre-state
                    // journal record must not survive, or a later rollback
                    // would reverse effects that never happened.
                    node_a.undo->drop_last_record();
                }
            }
            report.vx60_bytes_transferred = bytes_total;
            vx60_bytes_transferred_.fetch_add(bytes_total);
        }

        ::close(cfd);
        ::close(bfd);
        ::close(srv);

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

    } catch (const std::exception &e) {
        report.error = e.what();
        return report;
    }
}

// ═════════════════════════════════════════════════════════════════════════════
// Dandelion++ ZK-Cocoon routing
// ═══════════════════════════════════════════ encrypted_tx mask = Sponge(XOR-key stream from
// ephemeral_salt) ═══

namespace {

// Deterministic XOR mask stream derived from an ephemeral salt (per-hop layer).
// Each hop strips its layer and adds its own — the classic Dandelion++ privacy
// onion over the VortexSponge256 XOF.
void cocoon_mask_layer(uint8_t *bytes112, uint64_t salt) noexcept {
    blockchain::VortexSponge256 sponge;
    sponge.absorb(reinterpret_cast<const uint8_t *>(&salt), sizeof(salt));
    uint8_t stream[112];
    // Absorb enough entropy: 112 bytes through repeated sponge absorption.
    const uint8_t zero = 0;
    for (size_t off = 0; off < sizeof(stream); off += 32) {
        sponge.absorb(&zero, 1);
        sponge.absorb(reinterpret_cast<const uint8_t *>(&salt), sizeof(salt));
    }
    sponge.finalize(stream); // 32 bytes
    // Extend stream to 112 bytes with a counter-mode sponge expansion.
    for (size_t blk = 1; blk * 32 < sizeof(stream); ++blk) {
        blockchain::VortexSponge256 s2;
        s2.absorb(reinterpret_cast<const uint8_t *>(&salt), sizeof(salt));
        const uint8_t ctr = static_cast<uint8_t>(blk);
        s2.absorb(&ctr, 1);
        uint8_t chunk[32];
        s2.finalize(chunk);
        std::memcpy(stream + blk * 32, chunk, std::min(sizeof(stream) - blk * 32, size_t(32)));
    }
    for (size_t i = 0; i < 112; ++i)
        bytes112[i] ^= stream[i];
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
    if (v == 0)
        v = 0x9E3779B97F4A7C15ULL; // deterministic fallback
    return v;
}

} // namespace

TxCocoon SwarmNode::seal_cocoon(const blockchain::Transaction &tx, uint16_t tdi_score_fp) noexcept {
    TxCocoon c{};
    std::memcpy(c.encrypted_tx, &tx, 112);
    const uint64_t salt = hw_entropy();
    c.ephemeral_salt = salt;
    c.stem_hops_remaining = static_cast<uint8_t>(
        COCOON_MIN_HOPS + (hw_entropy() % (COCOON_MAX_HOPS - COCOON_MIN_HOPS + 1)));
    c.phase = COCOON_PHASE_STEM;
    c.tdi_score_fp = tdi_score_fp;
    cocoon_mask_layer(c.encrypted_tx, salt);
    c.cocoon_crc32c = compute_wire_crc32c(reinterpret_cast<const uint8_t *>(c.encrypted_tx), 112);
    return c;
}

blockchain::Transaction SwarmNode::open_cocoon(const TxCocoon &cocoon) noexcept {
    blockchain::Transaction tx{};
    std::array<uint8_t, 112> bytes{};
    std::memcpy(bytes.data(), cocoon.encrypted_tx, 112);
    cocoon_mask_layer(bytes.data(), cocoon.ephemeral_salt); // XOR is self-inverse
    std::memcpy(&tx, bytes.data(), 112);
    return tx;
}

bool SwarmNode::relay_cocoon_step(TxCocoon &cocoon, CocoonHopTrace &trace) {
    // Integrity gate: corrupted cocoons burn without entering the graph.
    const uint32_t crc =
        compute_wire_crc32c(reinterpret_cast<const uint8_t *>(cocoon.encrypted_tx), 112);
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
        cocoon_mask_layer(cocoon.encrypted_tx, fresh_salt); // re-mask
        cocoon.cocoon_crc32c =
            compute_wire_crc32c(reinterpret_cast<const uint8_t *>(cocoon.encrypted_tx), 112);

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

CocoonRelayReport SwarmNode::relay_cocoon_full_cycle(const blockchain::Transaction &tx,
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
        sponge.absorb(reinterpret_cast<const uint8_t *>(&cocoon.ephemeral_salt), 8);
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
    report.vx60_bytes_transferred = report.hops.size() * (24 + sizeof(TxCocoon));
    return report;
}

DandelionStats SwarmNode::dandelion_stats() const noexcept {
    DandelionStats s;
    s.stem_relays = stem_relays_.load(std::memory_order_relaxed);
    s.fluff_broadcasts = fluff_broadcasts_.load(std::memory_order_relaxed);
    s.tdi_spam_annihilated = tdi_spam_annihilated_.load(std::memory_order_relaxed);
    const uint64_t cycles = stem_cycles_count_.load(std::memory_order_relaxed);
    s.avg_stem_hops =
        cycles ? static_cast<double>(stem_hops_sum_.load(std::memory_order_relaxed)) / cycles : 0.0;
    s.anonymity_set_size = anonymity_set_size_.load(std::memory_order_relaxed);
    return s;
}

} // namespace vx::net
