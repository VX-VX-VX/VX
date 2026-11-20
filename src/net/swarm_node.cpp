#include "vx/net/swarm_node.hpp"
#include <algorithm>
#include <vector>

#include "vx/blockchain/block.hpp"
#include "vx/blockchain/genesis.hpp"
#include "vx/blockchain/crypto_sponge.hpp"
#include "vx/crypto/simd_accel.hpp"
#include "vx/crypto/pq_signature.hpp"
#include "vx/crypto/dksap_sidecars.hpp"
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
#include <system_error>
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
    // +32: the MAC-only AEAD tag tail of a sealed 64K frame (RAW_BLOCK_64K
    // rides MAC-only over SEC channels — public consensus data, no
    // encryption). 65536+32 is the wire maximum; anything beyond it is a
    // malformed header.
    if (h.payload_len > 65536 + 32)
        return false;
    const uint8_t t = h.msg_type;
    // 0x0D = ADDRS (peer discovery, one-shot push after the v2 handshake);
    // 0x0E still fails closed. 0x10-0x12 = the VX60-SEC handshake frames
    // (M2, owner-directed); 0x13 (KEM_ROTATE) stays outside the gate until
    // M4 wires it — an out-of-range type dies at the plausibility gate.
    return (t >= 0x01 && t <= 0x0D) || (t >= 0x10 && t <= 0x12);
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
    // PEX residual (public binary surface pass, 2026-11-14): discovery
    // candidates pointing at loopback are a localhost-SSRF/probe
    // primitive on a real network (a peer can aim our bounded dial
    // budget at our own RPC port). Default OFF; the three-node loopback
    // testnet opts in via the environment. Operator-supplied --peer
    // endpoints never pass through add_addr_candidate and stay allowed
    // unconditionally.
    loopback_candidates_allowed_ = [] {
        const char *e = ::getenv("VX_P2P_ALLOW_LOOPBACK");
        return e != nullptr && e[0] != '\0' && e[0] != '0';
    }();
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
    // PEX 2/2: identity keying. Filled by the first HANDSHAKE (zero +
    // !known until then — pre-handshake strikes are address-keyed only).
    std::array<uint8_t, 32> handshaked_id{};
    bool id_known = false;
    bool handshake_seen = false;
    // VX60-SEC M2: the dialer is the SEC upgrade INITIATOR (one attempt per
    // connection; the no-SEC mark spares legacy peers from probe strikes).
    bool sec_tried = false, sec_established = false;
    std::optional<vx60::ClientHandshake> sec_client;
    // Erase this connection's id→label entry (only when it still maps to
    // THIS label — a newer connection for the same id owns the slot now).
    auto erase_id_label = [&](const std::string &lbl) {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (auto it = id_conn_labels_.begin(); it != id_conn_labels_.end(); ++it)
            if (it->second == lbl) {
                id_conn_labels_.erase(it);
                break;
            }
    };
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
                erase_id_label(label);
                std::lock_guard<std::mutex> lock(peers_mutex_);
                peer_fds_.erase(label);
                sec_channels_.erase(fd);
                ::close(fd);
                return;
            }
            if (is_self) {
                std::cerr << "[Swarm] self-dial detected via node_id, dropping " << label << "\n";
                erase_id_label(label);
                std::lock_guard<std::mutex> lock(peers_mutex_);
                peer_fds_.erase(label);
                sec_channels_.erase(fd);
                ::close(fd);
                return;
            }
            // A second HANDSHAKE on a live connection is a protocol
            // violation AND an identity-laundering vector: swapping the
            // announced id mid-connection would move later strikes onto a
            // fresh identity. Address-keyed strike only — the NEW id is
            // unverified and never attributed (security review
            // 2026-11-15, MEDIUM).
            if (handshake_seen) {
                report_withhold(label, 20);
                erase_id_label(label);
                std::lock_guard<std::mutex> lock(peers_mutex_);
                peer_fds_.erase(label);
                sec_channels_.erase(fd);
                ::close(fd);
                return;
            }
            handshake_seen = true;
            // PEX 2/2: a banned durable identity never gets promoted — the
            // banlist survived the restart this attacker is counting on.
            if (id_is_banned(their_id)) {
                std::cerr << "[Swarm] banned identity, dropping " << label << "\n";
                erase_id_label(label);
                std::lock_guard<std::mutex> lock(peers_mutex_);
                peer_fds_.erase(label);
                sec_channels_.erase(fd);
                ::close(fd);
                return;
            }
            handshaked_id = their_id;
            id_known = !id_full_zero(their_id);
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                // Label cache: gated on enforcement (dormant ids must not
                // consume memory), capped (arbitrary eviction — best-effort
                // ban-time drop, not consensus state).
                if (id_known && id_enforcement_enabled_.load(std::memory_order_relaxed)) {
                    if (id_conn_labels_.size() >= kMaxIdConnLabels &&
                        !id_conn_labels_.contains(their_id))
                        id_conn_labels_.erase(id_conn_labels_.begin());
                    id_conn_labels_[their_id] = label;
                }
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
            // VX60-SEC M2 upgrade probe: one attempt, right after the
            // legacy handshake. WARM on a cached (proven) pk, COLD on
            // first contact.
            if (!sec_tried && id_known && vx60_id_loaded_ && !id_full_zero(their_id)) {
                bool skip = false;
                {
                    std::lock_guard<std::mutex> lock(peers_mutex_);
                    skip = no_sec_peers_.contains(their_id) || sec_channels_.contains(fd);
                }
                if (!skip) {
                    sec_tried = true;
                    sec_client.emplace();
                    std::string sec_err;
                    std::optional<vx::crypto::mlkem::PublicKey> cached_pk;
                    {
                        std::lock_guard<std::mutex> lock(peers_mutex_);
                        auto pit = vx60_pk_cache_.find(their_id);
                        if (pit != vx60_pk_cache_.end())
                            cached_pk = pit->second;
                    }
                    const bool ok = cached_pk ? sec_client->begin_warm(*cached_pk, sec_err)
                                              : sec_client->begin_cold(sec_err);
                    if (ok) {
                        WireHeader h =
                            make_header(WireMsgType::SEC_CLIENT_HELLO,
                                        static_cast<uint32_t>(sec_client->my_hello.size()),
                                        session_nonce_.fetch_add(1));
                        h.crc32c = compute_wire_crc32c(sec_client->my_hello.data(),
                                                       sec_client->my_hello.size());
                        send_packet(fd, h, sec_client->my_hello.data());
                    } else {
                        std::cerr << "[Swarm] vx60 upgrade begin failed: " << sec_err << "\n";
                        sec_client.reset();
                    }
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
                if (id_known)
                    report_id_strike(handshaked_id, 20);
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
            if (ingest_addrs(payload, lip, lport) < 0) {
                report_withhold(label, 20); // malformed payload
                if (id_known)
                    report_id_strike(handshaked_id, 20);
            }
            continue;
        }
        // ── VX60-SEC M2 dispatch (the dialer is the SEC client) ─────────
        if (type == WireMsgType::SEC_SERVER_HELLO) {
            if (!sec_client.has_value() || sec_established) {
                // Unsolicited server hello: protocol violation.
                report_withhold(label, 20);
                if (id_known)
                    report_id_strike(handshaked_id, 20);
                erase_id_label(label);
                {
                    std::lock_guard<std::mutex> lock(peers_mutex_);
                    peer_fds_.erase(label);
                    sec_channels_.erase(fd);
                }
                ::close(fd);
                return;
            }
            std::string sec_err;
            bool done = false;
            if (sec_client->mode == vx60::kHsFlagWarm) {
                done = sec_client->finish_warm(payload, sec_err);
            } else {
                // COLD: the transport id is TOFU on first contact (zero =
                // skip the sponge pin), but the LEGACY id is known from the
                // handshake — the sealed blob must carry it, or the peer is
                // a relay (MITM), and the session dies.
                const std::array<uint8_t, 32> no_expect{};
                done =
                    sec_client->finish_cold_pk_received(payload, no_expect, handshaked_id, sec_err);
            }
            if (!done) {
                std::cerr << "[Swarm] vx60 handshake failed: " << sec_err << "\n";
                // Crypto faults (AEAD/sponge/legacy-binding failures) are
                // TAMPERING — strike, never a downgrade mark. Only a
                // parse/flag failure (a peer that does not speak SEC) gets
                // the no-SEC mark; otherwise an attacker forces session
                // downgrade at will.
                // Hygiene 2a (owner-directed 19.11): version asymmetry.
                // A peer that claims a NEWER version than ours is not at
                // fault — neutral drop, no strike, no no-sec mark.
                // A peer that claims an OLDER version is pulling the
                // downgrade lever — strike + drop.
                const bool ver_newer = sec_err.find("version newer") != std::string::npos;
                const bool ver_older = sec_err.find("version older") != std::string::npos;
                const bool crypto_fault = sec_err.find("AEAD") != std::string::npos ||
                                          sec_err.find("does not hash") != std::string::npos ||
                                          sec_err.find("legacy_id mismatch") != std::string::npos;
                if (ver_older && id_known)
                    report_id_strike(handshaked_id, 100);
                if (crypto_fault && !ver_older && id_known)
                    report_id_strike(handshaked_id, 100);
                if (!crypto_fault && !ver_newer && !ver_older && id_known) {
                    std::lock_guard<std::mutex> lock(peers_mutex_);
                    no_sec_peers_.insert(handshaked_id);
                }
                erase_id_label(label);
                {
                    std::lock_guard<std::mutex> lock(peers_mutex_);
                    peer_fds_.erase(label);
                    sec_channels_.erase(fd);
                }
                ::close(fd);
                return;
            }
            if (sec_client->mode == vx60::kHsFlagCold) {
                // Send the PK_RESPONSE to complete the server side.
                WireHeader h = make_header(WireMsgType::SEC_PK_RESPONSE,
                                           static_cast<uint32_t>(sec_client->pk_response.size()),
                                           session_nonce_.fetch_add(1));
                h.crc32c = compute_wire_crc32c(sec_client->pk_response.data(),
                                               sec_client->pk_response.size());
                send_packet(fd, h, sec_client->pk_response.data());
            }
            // Channel live: arm the encrypted transport + enforcement.
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                sec_channels_[fd] = {sec_client->keys, 0, 0, /*am_initiator=*/true};
                if (!sec_enforcement_armed_) {
                    sec_enforcement_armed_ = true;
                    id_enforcement_enabled_.store(true, std::memory_order_relaxed);
                }
                if (!id_full_zero(handshaked_id))
                    vx60_pk_cache_[handshaked_id] = sec_client->peer_pk;
            }
            sec_established = true;
            std::cout << "[Swarm] vx60 SEC session established ("
                      << (sec_client->mode == vx60::kHsFlagWarm ? "warm" : "cold/tofu") << ")\n";
            continue;
        }
        if (type == WireMsgType::SEC_PK_RESPONSE || type == WireMsgType::SEC_KEM_ROTATE) {
            // Wrong direction on the dialer (0x12) / reserved for M4 (0x13).
            report_withhold(label, 20);
            if (id_known)
                report_id_strike(handshaked_id, 20);
            erase_id_label(label);
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                peer_fds_.erase(label);
                sec_channels_.erase(fd);
            }
            ::close(fd);
            return;
        }
        if (type == WireMsgType::RAW_BLOCK_64K && payload.size() == 65536) {
            handle_incoming_frame(label,
                                  std::span<const uint8_t, 65536>(payload.data(), payload.size()),
                                  id_known ? &handshaked_id : nullptr);
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
        // ── DKSAP wire integration: sidecar records (dialed side — the same
        // validated shape as the accept loop above) ────────────────────────
        if (type == WireMsgType::DKSAP_SGMT_REG && payload.size() >= 32 + 1 + 384 + 1184) {
            std::array<uint8_t, 32> digest{};
            std::memcpy(digest.data(), payload.data(), 32);
            // Dandelion++ relay gate (accept side): the stem decision + relay
            // send happen inside; the frame hook fans out on its own schedule.
            (void)dandelion_on_sidecar(fd, digest, type, payload);
            const uint8_t nlen = payload[32];
            if (nlen == 0 || nlen > 32 || payload.size() != 32 + 1 + nlen + 384 + 1184) {
                report_withhold(label, 20);
                if (id_known)
                    report_id_strike(handshaked_id, 20);
                continue;
            }
            vx::crypto::dksap::SgmtRecord rec;
            rec.nickname.assign(reinterpret_cast<const char *>(payload.data() + 33), nlen);
            std::memcpy(rec.pub.t_spend.data(), payload.data() + 33 + nlen, 384);
            std::memcpy(rec.pub.kkem.data(), payload.data() + 33 + nlen + 384, 1184);
            vx::crypto::dksap::DksapSidecarRegistry::instance().register_sgmt_candidate(digest,
                                                                                        rec);
            if (sidecar_callback_)
                sidecar_callback_(digest);
            continue;
        }
        if (type == WireMsgType::DKSAP_STEALTH &&
            payload.size() == 32 + sizeof(vx::crypto::dksap::StealthTx)) {
            std::array<uint8_t, 32> digest{};
            std::memcpy(digest.data(), payload.data(), 32);
            // Dandelion++ relay gate (dialed side): stem decision + relay
            // send inside; the frame hook fans out on its own schedule.
            (void)dandelion_on_sidecar(fd, digest, type, payload);
            vx::crypto::dksap::StealthBundle b;
            std::memcpy(&b.tx, payload.data() + 32, sizeof(b.tx));
            vx::crypto::dksap::DksapSidecarRegistry::instance().register_stealth_candidate(digest,
                                                                                           b);
            if (sidecar_callback_)
                sidecar_callback_(digest);
            continue;
        }
        break; // unexpected message type: drop the connection
    }
    // VX60-SEC: an upgrade probe that never established marks the peer
    // no-SEC (it struck/dropped the probe): the migration must not poison
    // legacy peers with repeated strikes on every reconnect.
    if (sec_tried && !sec_established && id_known) {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        no_sec_peers_.insert(handshaked_id);
    }
    erase_id_label(label); // connection teardown: free the id→label slot
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        peer_fds_.erase(label);
        sec_channels_.erase(fd);
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
        // Save the fd BEFORE erase: erasing invalidates the iterator, and
        // reading it->second afterwards is a heap-use-after-free (SAN lane).
        const int fd = it->second;
        if (fd >= 0)
            ::close(fd);
        peer_fds_.erase(it);
        sec_channels_.erase(fd);
    }
}

// ── Wire send / recv ────────────────────────────────────────────────────────

// ── VX60-SEC M2: per-connection payload encryption ──────────────────────────

bool SwarmNode::sec_seal_out(int fd, const WireHeader &ad_hdr, std::vector<uint8_t> &payload) {
    // Empty payloads seal too (a tag-only packet): an unauthenticated empty
    // PING would be an injection hole into a secured channel.
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = sec_channels_.find(fd);
    if (it == sec_channels_.end())
        return false; // no channel: legacy passthrough
    SecChannel &ch = it->second;
    // M3: RAW_BLOCK_64K bodies are PUBLIC consensus data — MAC-only mode
    // (no encryption, CPU-free authentication; the whitebook §4.4 split).
    const bool mac_only = ad_hdr.msg_type == static_cast<uint8_t>(WireMsgType::RAW_BLOCK_64K);
    const auto nonce = ch.keys.packet_nonce(ch.am_initiator, ch.send_ctr);
    std::array<uint8_t, vx60::kAeadTagSize> tag{};
    // AD = the 24-byte WireHeader with the CRC field ZEROED (the CRC is a
    // plaintext-layer check over the sealed bytes; binding it in the AD
    // would desynchronize seal vs open since the CRC is written after the
    // seal). Type/len/nonce ARE bound: a sealed packet cannot be re-cut
    // into another type or re-framed without the AEAD tag failing.
    WireHeader ad = ad_hdr;
    ad.crc32c = 0;
    if (mac_only)
        vx60::aead_mac(ch.keys.key.data(), nonce.data(), reinterpret_cast<const uint8_t *>(&ad),
                       sizeof(ad), payload.data(), payload.size(), tag.data());
    else
        vx60::aead_seal(ch.keys.key.data(), nonce.data(), reinterpret_cast<const uint8_t *>(&ad),
                        sizeof(ad), payload.data(), payload.size(), tag.data());
    // The 32-byte AEAD tag rides AFTER the ciphertext; send_packet accounts
    // for the growth in its local header copy (payload_len += vx60::kAeadTagSize)
    // and recomputes the CRC over the sealed representation.
    payload.insert(payload.end(), tag.begin(), tag.end());
    ++ch.send_ctr;
    // M3 key evolution: the TOTAL packet count (send + recv — symmetric on
    // both ends by construction) crossing the threshold rotates the epoch
    // on both sides at the same packet boundary. No wire frames needed.
    if ((ch.send_ctr + ch.recv_ctr) % vx60::VX60_REKEY_PACKETS == 0)
        ch.keys = vx60::derive_next_epoch(ch.keys);
    return true;
}

bool SwarmNode::sec_open_in(int fd, const WireHeader &ad_hdr, std::vector<uint8_t> &payload) {
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = sec_channels_.find(fd);
    if (it == sec_channels_.end())
        return true; // no channel: legacy passthrough (nothing to verify)
    SecChannel &ch = it->second;
    if (payload.size() < vx60::kAeadTagSize)
        return false;
    const size_t ct_len = payload.size() - vx60::kAeadTagSize;
    const uint8_t *tag = payload.data() + ct_len;
    // The PEER's direction: an initiator receives responder-sealed packets
    // (nonce_s), a responder receives client-sealed ones (nonce_c).
    const auto nonce = ch.keys.packet_nonce(!ch.am_initiator, ch.recv_ctr);
    WireHeader ad = ad_hdr;
    ad.crc32c = 0; // the same zeroed-CRC AD the sealer used
    const bool mac_only = ad_hdr.msg_type == static_cast<uint8_t>(WireMsgType::RAW_BLOCK_64K);
    bool ok;
    if (mac_only) {
        std::array<uint8_t, vx60::kAeadTagSize> expect{};
        vx60::aead_mac(ch.keys.key.data(), nonce.data(), reinterpret_cast<const uint8_t *>(&ad),
                       sizeof(ad), payload.data(), ct_len, expect.data());
        ok = vx::core::ct_equal(expect.data(), tag, vx60::kAeadTagSize);
    } else {
        ok = vx60::aead_open(ch.keys.key.data(), nonce.data(),
                             reinterpret_cast<const uint8_t *>(&ad), sizeof(ad), payload.data(),
                             ct_len, tag);
    }
    if (!ok) {
        // A failed open NEVER advances the counter: TCP is ordered, so a
        // mismatch means tampering — the caller drops the connection.
        return false;
    }
    payload.resize(ct_len);
    ++ch.recv_ctr;
    // M3 key evolution: the same symmetric trigger as the seal side.
    if ((ch.send_ctr + ch.recv_ctr) % vx60::VX60_REKEY_PACKETS == 0)
        ch.keys = vx60::derive_next_epoch(ch.keys);
    return true;
}

uint64_t SwarmNode::send_packet(int fd, const WireHeader &hdr, const uint8_t *payload) {
    if (fd < 0)
        return 0;

    // VX60-SEC: a secured fd seals the payload; the tag rides after the
    // ciphertext, so the LOCAL header copy grows by vx60::kAeadTagSize and the
    // CRC is recomputed over the sealed representation. Legacy fds send
    // the caller's header/payload untouched (the caller's CRC stands).
    WireHeader h2 = hdr;
    std::vector<uint8_t> sealed;
    // A nullptr payload = a zero-length one (PING/PONG): it STILL seals —
    // a tag-only packet authenticates an empty frame, otherwise an
    // attacker could inject unauthenticated empties into a secured channel.
    if (payload || hdr.payload_len == 0) {
        if (payload)
            sealed.assign(payload, payload + hdr.payload_len);
        // The AD header carries the FINAL (sealed) length: the tag adds 32.
        h2.payload_len = static_cast<uint32_t>(sealed.size() + vx60::kAeadTagSize);
        if (sec_seal_out(fd, h2, sealed)) {
            h2.crc32c = compute_wire_crc32c(sealed.data(), sealed.size());
            payload = sealed.data();
        } else {
            h2.payload_len = hdr.payload_len; // legacy passthrough: restore
        }
    }

    ssize_t n = ::send(fd, &h2, sizeof(h2), MSG_NOSIGNAL);
    if (n != static_cast<ssize_t>(sizeof(h2)))
        return 0;

    uint64_t total = sizeof(h2);
    if (h2.payload_len > 0 && payload) {
        size_t off = 0;
        while (off < h2.payload_len) {
            n = ::send(fd, payload + off, h2.payload_len - off, MSG_NOSIGNAL);
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

    // VX60-SEC: a secured fd opens the payload (the CRC above covered the
    // SEALED representation as received). A failed open NEVER advances the
    // receive counter and drops the connection — tampering, not glitch.
    if (!sec_open_in(fd, hdr, payload)) {
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
    // VX60-SEC M3: a raw sendfile send cannot append the AEAD tag, so on a
    // SEC fd this raw path would ship unauthenticated bytes and the peer
    // would drop the connection on its first open attempt. Fail-closed: SEC
    // fds must route through send_packet (MAC-only sealed). No caller today,
    // but the method is public — the guard turns the landmine into an
    // explicit refusal.
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        if (sec_channels_.count(socket_fd) != 0)
            return false;
    }

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
    // Route through send_packet, NOT raw ::send: on a SEC fd the frame goes
    // out MAC-only sealed (tag appended, payload_len 65536+32) — a raw send
    // would ship unauthenticated bytes over a secured channel and the peer
    // would drop the connection on its first open attempt. On a legacy fd
    // send_packet is a byte-identical passthrough.
    return send_packet(fd, hdr, frame.data()) != 0;
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
    // Route through send_packet: on a SEC fd the id list rides sealed —
    // raw ::send would ship unauthenticated bytes and the peer would drop
    // the connection on its first open attempt. Legacy fds: passthrough.
    return send_packet(fd, hdr, payload.data()) != 0;
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
        // send_packet: sealed on SEC fds (see send_id_list_to).
        if (send_packet(fd, hdr, payload.data()) == 0)
            return false;
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
        // send_packet: sealed on SEC fds (see send_id_list_to).
        if (send_packet(fd, hdr, payload.data()) == 0)
            return false;
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
        // send_packet: sealed on SEC fds (see send_id_list_to); fire-and-
        // forget for a broadcast — a failed send just skips this peer.
        (void)send_packet(fd, hdr, payload.data());
    }
}

void SwarmNode::set_frame_hook(FrameHook hook) {
    frame_hook_ = std::move(hook);
}

void SwarmNode::set_sidecar_callback(SidecarHook hook) {
    sidecar_callback_ = std::move(hook);
}

void SwarmNode::broadcast_sidecars_for(const std::span<const uint8_t, 65536> &frame) {
    auto *raw = reinterpret_cast<const blockchain::RawBlock *>(frame.data());
    const uint32_t count =
        raw->header.tx_count > blockchain::MAX_TX_PER_BLOCK ? 0u : raw->header.tx_count;
    // Payloads are variable-length (the SGMT record carries the nickname),
    // so a byte vector is the transport shape for both kinds. Two batches:
    // each kind rides its OWN message type (the receiver shape-checks per
    // type — a stealth bundle under the SGMT type would close connections).
    std::vector<std::vector<uint8_t>> payloads;
    std::vector<std::vector<uint8_t>> stealth_payloads;
    for (uint32_t i = 0; i < count; ++i) {
        const blockchain::Transaction &tx = raw->transactions[i];
        const auto digest = vx::crypto::pq::tx_msg_digest(tx);
        if (vx::crypto::dksap::receiver_is_stealth(tx.receiver_nfa)) {
            // Relay every candidate (bounded per digest); the receiver is
            // not an authority — each peer re-resolves against the frame.
            // STEALTH sidecars ride THEIR OWN message type (adversarial
            // review 2026-11-15 P0): a 1572-byte bundle sent as SGMT_REG
            // fails the receiver's shape check on both branches and closes
            // the connection — the first stealth transfer would disconnect
            // the node from its entire peer set.
            for (const auto &b :
                 vx::crypto::dksap::DksapSidecarRegistry::instance().copy_stealth_candidates(
                     digest)) {
                std::vector<uint8_t> payload;
                payload.reserve(32 + sizeof(vx::crypto::dksap::StealthTx));
                payload.insert(payload.end(), digest.begin(), digest.end());
                const auto *p = reinterpret_cast<const uint8_t *>(&b.tx);
                payload.insert(payload.end(), p, p + sizeof(vx::crypto::dksap::StealthTx));
                stealth_payloads.push_back(std::move(payload));
            }
        } else if (vx::crypto::dksap::receiver_is_sgmtleaf(tx.receiver_nfa)) {
            for (const auto &rec :
                 vx::crypto::dksap::DksapSidecarRegistry::instance().copy_sgmt_candidates(digest)) {
                std::vector<uint8_t> payload;
                payload.reserve(32 + 1 + rec.nickname.size() + 384 + 1184);
                payload.insert(payload.end(), digest.begin(), digest.end());
                payload.push_back(static_cast<uint8_t>(rec.nickname.size()));
                payload.insert(payload.end(), rec.nickname.begin(), rec.nickname.end());
                payload.insert(payload.end(), rec.pub.t_spend.begin(), rec.pub.t_spend.end());
                payload.insert(payload.end(), rec.pub.kkem.begin(), rec.pub.kkem.end());
                payloads.push_back(std::move(payload));
            }
        }
    }
    if (payloads.empty() && stealth_payloads.empty())
        return;
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
    // Dandelion++ originator gate: privacy payloads are partitioned per
    // digest — fresh digests stem to one epoch-fixed stem peer (the caller
    // skips their fan-out), everything else fans out normally. dandelion_on_
    // sidecar() sends the stem frame itself; the fan-out here covers only the
    // non-stemmed remainder.
    {
        std::vector<std::vector<uint8_t>> fanout_sgmt, fanout_stealth;
        for (auto &p : payloads) {
            std::array<uint8_t, 32> d{};
            std::memcpy(d.data(), p.data(), 32);
            if (!dandelion_on_sidecar(-1, d, WireMsgType::DKSAP_SGMT_REG, p))
                fanout_sgmt.push_back(std::move(p));
        }
        for (auto &p : stealth_payloads) {
            std::array<uint8_t, 32> d{};
            std::memcpy(d.data(), p.data(), 32);
            if (!dandelion_on_sidecar(-1, d, WireMsgType::DKSAP_STEALTH, p))
                fanout_stealth.push_back(std::move(p));
        }
        payloads = std::move(fanout_sgmt);
        stealth_payloads = std::move(fanout_stealth);
    }
}

bool SwarmNode::send_wire_payloads_to(int fd, WireMsgType type,
                                      const std::vector<std::vector<uint8_t>> &payloads) {
    for (const auto &payload : payloads) {
        WireHeader hdr =
            make_header(type, static_cast<uint32_t>(payload.size()), session_nonce_.fetch_add(1));
        hdr.crc32c = compute_wire_crc32c(payload.data(), payload.size());
        // Delegates to send_packet: a secured fd seals here (the tag grows
        // the local header copy and the CRC is recomputed over the sealed
        // representation); legacy fds send as-is.
        if (send_packet(fd, hdr, payload.data()) == 0)
            return false;
    }
    return true;
}

void SwarmNode::handle_incoming_frame(const std::string &from_peer,
                                      const std::span<const uint8_t, 65536> &frame,
                                      const std::array<uint8_t, 32> *id) {
    if (!verify_frame(frame)) {
        ban_peer(from_peer, 100);
        if (id != nullptr && !id_full_zero(*id))
            report_id_strike(*id, 100); // PEX 2/2: identity carries the score too
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

void SwarmNode::load_vx60_identity(const std::string &data_dir) {
    if (vx60_id_loaded_)
        return; // already loaded (explicit call order guard)
    // ── VX60-SEC M2: the transport identity loads beside the legacy id. A
    // load failure runs the transport identityless (logged) — the node
    // keeps serving legacy peers; regeneration is an operator decision.
    std::string vx60_err;
    if (vx60::TransportIdentityStore::load_or_create(data_dir, vx60_id_, vx60_err)) {
        vx60_id_loaded_ = true;
        std::string id_hex;
        static const char *hd = "0123456789abcdef";
        for (const uint8_t b : vx60_id_.node_id) {
            id_hex.push_back(hd[b >> 4]);
            id_hex.push_back(hd[b & 0xF]);
        }
        std::cout << "[Swarm] vx60 transport identity loaded (node_id " << id_hex << ")\n";
    } else {
        std::cout << "[Swarm] vx60 transport identity UNAVAILABLE (" << vx60_err
                  << "); running SEC-less this session\n";
    }
}

void SwarmNode::load_or_create_node_id(const std::string &data_dir) {
    if (node_id_ != std::array<uint8_t, 32>{})
        return; // already loaded (explicit call order guard)
    load_vx60_identity(data_dir);
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

// ── PEX 2/2: node_id-keyed strikes + durable banlist ────────────────────────

void SwarmNode::attach_banlist_path(const std::string &data_dir) {
    // Self-sufficient attach: create the directory if missing so a ban can
    // always reach disk. If creation fails, append_banlist_locked warns with
    // its existing fail-open posture (ban stays in-memory only).
    std::error_code fs_ec;
    std::filesystem::create_directories(data_dir, fs_ec);
    const std::string path = (std::filesystem::path(data_dir) / "banlist").string();
    std::lock_guard<std::mutex> lock(peers_mutex_);
    if (banlist_attached_) {
        if (banlist_path_ != path)
            std::abort(); // single ownership, same as the SGMT durable log
        return;
    }
    banlist_path_ = path;
    banlist_attached_ = true;
    // Load: one "<64-hex id> <unix> <reason-code>" row per banned identity.
    // Fail closed PER LINE (skip + warn): a corrupted banlist must never
    // take the node down and never silently unban a peer. An absent file
    // is a first boot: empty list.
    const int fd = ::open(path.c_str(), O_RDONLY);
    if (fd < 0)
        return;
    struct stat st{};
    std::vector<uint8_t> buf;
    if (::fstat(fd, &st) == 0 && st.st_size > 0) {
        buf.resize(static_cast<size_t>(st.st_size));
        size_t got = 0;
        while (got < buf.size()) {
            const ssize_t n =
                ::pread(fd, buf.data() + got, buf.size() - got, static_cast<off_t>(got));
            if (n <= 0)
                break;
            got += static_cast<size_t>(n);
        }
        buf.resize(got);
    }
    ::close(fd);
    auto hexv = [](char c) -> int {
        if (c >= '0' && c <= '9')
            return c - '0';
        if (c >= 'a' && c <= 'f')
            return c - 'a' + 10;
        if (c >= 'A' && c <= 'F')
            return c - 'A' + 10;
        return -1;
    };
    size_t off = 0;
    size_t loaded = 0;
    while (off < buf.size()) {
        size_t end = off;
        while (end < buf.size() && buf[end] != '\n')
            ++end;
        // Parse from the LINE START, before advancing past it: reading the
        // id from the already-advanced cursor both parsed the next line's
        // bytes and walked off the buffer near EOF (security review
        // 2026-11-15, MEDIUM: heap out-of-bounds read).
        const size_t line_start = off;
        const size_t len = end - off;
        off = (end < buf.size()) ? end + 1 : end;
        if (len < 64 || line_start + 64 > buf.size())
            continue;
        std::array<uint8_t, 32> id{};
        bool ok = true;
        for (size_t i = 0; i < 32; ++i) {
            const int hi = hexv(static_cast<char>(buf[line_start + i * 2]));
            const int lo = hexv(static_cast<char>(buf[line_start + i * 2 + 1]));
            if (hi < 0 || lo < 0) {
                ok = false;
                break;
            }
            id[i] = static_cast<uint8_t>((hi << 4) | lo);
        }
        if (!ok) {
            std::cerr << "[Swarm] banlist: malformed row skipped\n";
            continue;
        }
        id_rep_[id] = IdReputation{0, true};
        ++loaded;
    }
    if (loaded > 0)
        std::cout << "[Swarm] banlist: " << loaded << " banned identit(y/ies) loaded\n";
}

void SwarmNode::report_id_strike(const std::array<uint8_t, 32> &id, int score_increment) {
    if (id_full_zero(id))
        return; // old-world announce: nothing durable to key on
    // DORMANT gate (security review 2026-11-15, HIGH): strikes against
    // UNAUTHENTICATED ids must not accumulate toward bans or reach the
    // durable banlist — a spoofer could self-strike a victim's announced
    // id and durably censor it. Address-keyed strikes (pre-handshake
    // surface) keep working via report_withhold. Enforcement enables
    // only where the handshake proves key possession (VX60-SEC KEM-PoP).
    if (!id_enforcement_enabled_.load())
        return;
    std::vector<int> fds_to_drop;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        IdReputation rep;
        auto it = id_rep_.find(id);
        if (it != id_rep_.end())
            rep = it->second;
        if (rep.banned)
            return; // already on the durable list
        rep.dos_score += score_increment;
        if (rep.dos_score < 100) {
            id_rep_[id] = rep;
            trim_id_rep_locked();
            return;
        }
        rep.banned = true;
        id_rep_[id] = rep;
        // Durable append. DELIBERATELY fail-open, unlike the SGMT log:
        // this is DoS response, not consensus state — a full disk must not
        // wedge the node mid-attack; the ban stays in memory and the
        // restart gap is bounded by the attacker re-earning 100 points.
        append_banlist_locked(id);
        // Drop every live connection that announced this identity.
        auto lit = id_conn_labels_.find(id);
        if (lit != id_conn_labels_.end()) {
            auto fit = peer_fds_.find(lit->second);
            if (fit != peer_fds_.end()) {
                // shutdown only: the owning reader/serve thread closes the
                // fd exactly once (same discipline as health_loop).
                // Save the fd BEFORE erase — erase(fit) frees the node and
                // reading fit->second afterwards is a heap-use-after-free
                // (caught by the SAN lane, ASan thread T94).
                const int fd = fit->second;
                fds_to_drop.push_back(fd);
                peer_fds_.erase(fit);
                sec_channels_.erase(fd);
            }
            id_conn_labels_.erase(lit);
        }
    }
    for (int fd : fds_to_drop)
        ::shutdown(fd, SHUT_RDWR);
}

bool SwarmNode::id_is_banned(const std::array<uint8_t, 32> &id) const {
    if (id_full_zero(id))
        return false;
    // DORMANT gate (security review 2026-11-15, HIGH): unauthenticated
    // ids must never trigger identity-keyed enforcement — a spoofer
    // announcing a victim's id would otherwise censor it at handshake.
    // Enforcement enables only where the handshake proves key possession
    // (VX60-SEC KEM-PoP).
    if (!id_enforcement_enabled_.load())
        return false;
    std::lock_guard<std::mutex> lock(peers_mutex_);
    auto it = id_rep_.find(id);
    return it != id_rep_.end() && it->second.banned;
}

void SwarmNode::trim_id_rep_locked() {
    while (id_rep_.size() > kMaxIdReputation) {
        bool evicted = false;
        for (auto it = id_rep_.begin(); it != id_rep_.end(); ++it) {
            if (!it->second.banned) {
                id_rep_.erase(it);
                evicted = true;
                break;
            }
        }
        if (!evicted)
            break; // all entries banned: disk-backed, load restores them
    }
}

void SwarmNode::append_banlist_locked(const std::array<uint8_t, 32> &id) {
    if (!banlist_attached_)
        return;
    const int fd = ::open(banlist_path_.c_str(), O_WRONLY | O_CREAT | O_APPEND, 0600);
    if (fd < 0) {
        std::cerr << "[Swarm] banlist open failed (ban stays in-memory only)\n";
        return;
    }
    char row[64 + 32];
    static const char *hexd = "0123456789abcdef";
    for (size_t i = 0; i < 32; ++i) {
        row[i * 2] = hexd[id[i] >> 4];
        row[i * 2 + 1] = hexd[id[i] & 0xF];
    }
    const int n = std::snprintf(row + 64, sizeof(row) - 64, " %lld %d\n",
                                static_cast<long long>(::time(nullptr)), 100);
    bool ok = n > 0;
    size_t put = 0;
    const size_t total = 64 + static_cast<size_t>(n);
    while (ok && put < total) {
        const ssize_t w = ::write(fd, row + put, total - put);
        if (w <= 0) {
            if (w < 0 && errno == EINTR)
                continue;
            ok = false;
            break;
        }
        put += static_cast<size_t>(w);
    }
    if (ok)
        (void)::fsync(fd); // best-effort durability
    ::close(fd);
    if (!ok)
        std::cerr << "[Swarm] banlist append failed (ban stays in-memory only)\n";
}

bool SwarmNode::add_addr_candidate(uint32_t ip_net, uint16_t port, bool operator_supplied) {
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
    // PEX residual (2026-11-14, review follow-up): peer-supplied
    // candidates must not aim the dial budget at infrastructure — the
    // whole loopback /8 (not just 127.0.0.1) and the link-local
    // 169.254/16 range are refused unless VX_P2P_ALLOW_LOOPBACK=1 (the
    // loopback testnet opts in). Operator --peer endpoints reach
    // connect_peer_tcp directly and operator --seed hosts pass
    // operator_supplied=true — the gate is a defense against PEER-supplied
    // targets only. RFC1918 private ranges ride a future default-off
    // policy switch for public-network deployments (LAN meshes dial them
    // legitimately today).
    const bool is_loopback = (ip_host >> 24) == 127;
    const bool is_link_local = (ip_host & 0xFFFF0000u) == 0xA9FE0000u;
    // The env switch re-opens LOOPBACK ONLY, and only for peer-supplied
    // candidates. Operator-supplied targets (--seed) bypass the gate
    // entirely — the operator chose them. Link-local (169.254/16 — home
    // of the cloud-metadata endpoint) stays refused for peer-supplied
    // candidates unconditionally: no legitimate discovery target lives
    // there, and the switch's name must not widen its meaning.
    if (!operator_supplied && ((is_loopback && !loopback_candidates_allowed_) || is_link_local))
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
        if (add_addr_candidate(sa->sin_addr.s_addr, port, /*operator_supplied=*/true))
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

    // Hygiene 2b (owner-directed 19.11): per-IP connection cap, checked on
    // the accept path BEFORE any packet handling — an IP flooding with
    // connections cannot reach the handshake state machines. Over the cap
    // = instant close, no strike, no withhold. The slot is released by an
    // RAII guard at function exit (all teardown paths covered).
    uint32_t peer_ip = 0;
    bool ip_tracked = false;
    {
        sockaddr_in sa{};
        socklen_t sl = sizeof(sa);
        if (::getpeername(c, reinterpret_cast<sockaddr *>(&sa), &sl) == 0) {
            peer_ip = sa.sin_addr.s_addr;
            ip_tracked = true;
            std::lock_guard<std::mutex> lock(peers_mutex_);
            if (active_per_ip_[peer_ip] >= kMaxConnsPerIp) {
                ::close(c);
                return;
            }
            ++active_per_ip_[peer_ip];
        }
    }
    struct IpSlotGuard {
        SwarmNode *self;
        uint32_t ip;
        bool tracked;
        ~IpSlotGuard() {
            if (!tracked)
                return;
            std::lock_guard<std::mutex> lock(self->peers_mutex_);
            auto it = self->active_per_ip_.find(ip);
            if (it != self->active_per_ip_.end() && it->second > 0) {
                if (--it->second == 0)
                    self->active_per_ip_.erase(it);
            }
        }
    } ip_guard{this, peer_ip, ip_tracked};

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
    // PEX 2/2: identity keying (filled by the first HANDSHAKE; strikes
    // before it are address-keyed only).
    std::array<uint8_t, 32> handshaked_id{};
    bool id_known = false;
    bool handshake_seen = false;
    // VX60-SEC M2: the acceptor is the SEC RESPONDER (frames arrive from
    // the dialer's upgrade probe).
    std::optional<vx60::ServerHandshake> sec_server;
    bool sec_established = false;
    auto erase_id_label = [&](const std::string &lbl) {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        for (auto it = id_conn_labels_.begin(); it != id_conn_labels_.end(); ++it)
            if (it->second == lbl) {
                id_conn_labels_.erase(it);
                break;
            }
    };
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
            // Route through send_packet: a secured fd seals (tag-only for
            // the empty payload); legacy fds send as-is. A raw ::send here
            // would bypass the encryption and leak an unauthenticated
            // packet into a secured channel.
            send_packet(c, pong, nullptr);
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
            // Second HANDSHAKE on a live connection: protocol violation +
            // identity-laundering vector (see the reader-loop twin).
            if (handshake_seen) {
                report_withhold(peer_label, 20);
                break;
            }
            handshake_seen = true;
            // PEX 2/2: a banned durable identity never gets promoted.
            if (id_is_banned(their_id)) {
                std::cerr << "[Swarm] banned identity, dropping " << peer_label << "\n";
                break;
            }
            handshaked_id = their_id;
            id_known = !id_full_zero(their_id);
            if (promote()) {
                fire_connected();
                announce();
            }
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                // Label cache: gated on enforcement + capped (see the
                // reader-loop twin for the rationale).
                if (id_known && id_enforcement_enabled_.load(std::memory_order_relaxed)) {
                    if (id_conn_labels_.size() >= kMaxIdConnLabels &&
                        !id_conn_labels_.contains(their_id))
                        id_conn_labels_.erase(id_conn_labels_.begin());
                    id_conn_labels_[their_id] = peer_label;
                }
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
                if (id_known)
                    report_id_strike(handshaked_id, 20);
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
            if (ingest_addrs(payload, lip, lport) < 0) {
                report_withhold(peer_label, 20); // malformed payload
                if (id_known)
                    report_id_strike(handshaked_id, 20);
            }
            continue;
        }
        // ── VX60-SEC M2 dispatch (the acceptor is the SEC responder) ────
        if (type == WireMsgType::SEC_CLIENT_HELLO) {
            if (!vx60_id_loaded_ || sec_server.has_value() || sec_established) {
                // No identity (legacy node) / re-handshake on a secured
                // connection: both are protocol violations.
                report_withhold(peer_label, 20);
                if (id_known)
                    report_id_strike(handshaked_id, 20);
                break;
            }
            sec_server.emplace();
            sec_server->set_static_keys(vx60_id_.static_ek, vx60_id_.static_dk, node_id_);
            std::string sec_err;
            std::vector<uint8_t> server_hello;
            if (!sec_server->begin_from_client_hello(payload, server_hello, sec_err)) {
                std::cerr << "[Swarm] vx60 server handshake failed: " << sec_err << "\n";
                sec_server.reset();
                // Hygiene 2a: version asymmetry. A client claiming an OLDER
                // version pulls the downgrade lever → strike. A NEWER client
                // is not at fault → neutral drop, no withhold, no strike.
                if (sec_err.find("version older") != std::string::npos) {
                    if (id_known)
                        report_id_strike(handshaked_id, 100);
                    report_withhold(peer_label, 20);
                } else if (sec_err.find("version newer") == std::string::npos) {
                    report_withhold(peer_label, 20);
                }
                break;
            }
            WireHeader h = make_header(WireMsgType::SEC_SERVER_HELLO,
                                       static_cast<uint32_t>(server_hello.size()),
                                       session_nonce_.fetch_add(1));
            h.crc32c = compute_wire_crc32c(server_hello.data(), server_hello.size());
            send_packet(c, h, server_hello.data()); // no channel yet: passthrough
            if (sec_server->mode == vx60::kHsFlagWarm) {
                // WARM: keys ready now.
                std::lock_guard<std::mutex> lock(peers_mutex_);
                sec_channels_[c] = {sec_server->keys, 0, 0, /*am_initiator=*/false};
                if (!sec_enforcement_armed_) {
                    sec_enforcement_armed_ = true;
                    id_enforcement_enabled_.store(true, std::memory_order_relaxed);
                }
                sec_established = true;
                sec_server.reset();
                std::cout << "[Swarm] vx60 SEC session established (warm, inbound)\n";
            }
            continue;
        }
        if (type == WireMsgType::SEC_PK_RESPONSE) {
            if (!sec_server.has_value() || sec_established) {
                report_withhold(peer_label, 20);
                if (id_known)
                    report_id_strike(handshaked_id, 20);
                break;
            }
            std::string sec_err;
            if (!sec_server->finish_cold(payload, sec_err)) {
                std::cerr << "[Swarm] vx60 cold finish failed: " << sec_err << "\n";
                sec_server.reset();
                report_withhold(peer_label, 20);
                break;
            }
            {
                std::lock_guard<std::mutex> lock(peers_mutex_);
                sec_channels_[c] = {sec_server->keys, 0, 0, /*am_initiator=*/false};
                if (!sec_enforcement_armed_) {
                    sec_enforcement_armed_ = true;
                    id_enforcement_enabled_.store(true, std::memory_order_relaxed);
                }
            }
            sec_established = true;
            sec_server.reset();
            std::cout << "[Swarm] vx60 SEC session established (cold, inbound)\n";
            continue;
        }
        if (type == WireMsgType::SEC_SERVER_HELLO || type == WireMsgType::SEC_KEM_ROTATE) {
            // Wrong direction on the acceptor / reserved for M4.
            report_withhold(peer_label, 20);
            if (id_known)
                report_id_strike(handshaked_id, 20);
            break;
        }
        if (type == WireMsgType::RAW_BLOCK_64K && payload.size() == 65536) {
            if (promote()) {
                fire_connected();
                announce();
            }
            handle_incoming_frame(peer_label,
                                  std::span<const uint8_t, 65536>(payload.data(), payload.size()),
                                  id_known ? &handshaked_id : nullptr);
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
        // ── DKSAP wire integration: sidecar records ────────────────────────
        // A record is stored ONLY after full shape validation: the digest
        // keys it to exactly one transaction, the nickname range is checked,
        // and the ring commitment is canonical (the registry re-checks —
        // nothing malformed is ever stored). A store failure does not kill
        // the connection: gossip races with the frame and losers are the
        // normal case, the same shape as witness arrival.
        if (type == WireMsgType::DKSAP_SGMT_REG && payload.size() >= 32 + 1 + 384 + 1184) {
            if (promote()) {
                fire_connected();
                announce();
            }
            std::array<uint8_t, 32> digest{};
            std::memcpy(digest.data(), payload.data(), 32);
            // Dandelion++ relay gate (accept side): same contract as the
            // dialed side — the stem decision + relay send happen inside.
            (void)dandelion_on_sidecar(c, digest, type, payload);
            const uint8_t nlen = payload[32];
            if (nlen == 0 || nlen > 32 || payload.size() != 32 + 1 + nlen + 384 + 1184) {
                report_withhold(peer_label, 20); // malformed: strict shape
                if (id_known)
                    report_id_strike(handshaked_id, 20);
                continue;
            }
            vx::crypto::dksap::SgmtRecord rec;
            rec.nickname.assign(reinterpret_cast<const char *>(payload.data() + 33), nlen);
            std::memcpy(rec.pub.t_spend.data(), payload.data() + 33 + nlen, 384);
            std::memcpy(rec.pub.kkem.data(), payload.data() + 33 + nlen + 384, 1184);
            vx::crypto::dksap::DksapSidecarRegistry::instance().register_sgmt_candidate(digest,
                                                                                        rec);
            if (sidecar_callback_)
                sidecar_callback_(digest);
            continue;
        }
        if (type == WireMsgType::DKSAP_STEALTH &&
            payload.size() == 32 + sizeof(vx::crypto::dksap::StealthTx)) {
            if (promote()) {
                fire_connected();
                announce();
            }
            std::array<uint8_t, 32> digest{};
            std::memcpy(digest.data(), payload.data(), 32);
            // Dandelion++ relay gate (accept side): stem decision + relay
            // send inside; the frame hook fans out on its own schedule.
            (void)dandelion_on_sidecar(c, digest, type, payload);
            vx::crypto::dksap::StealthBundle b;
            static_assert(sizeof(vx::crypto::dksap::StealthTx) == 32 + 4 + 384 + 1088 + 32,
                          "StealthTx must be a fixed contiguous byte layout");
            std::memcpy(&b.tx, payload.data() + 32, sizeof(b.tx));
            vx::crypto::dksap::DksapSidecarRegistry::instance().register_stealth_candidate(digest,
                                                                                           b);
            if (sidecar_callback_)
                sidecar_callback_(digest);
            continue;
        }
        break;
    }
    if (registered) {
        erase_id_label(peer_label); // teardown: free the id→label slot
        std::lock_guard<std::mutex> lock(peers_mutex_);
        peer_fds_.erase(peer_label);
        sec_channels_.erase(c);
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
        // Dandelion++ epoch maintenance: stem-channel rotation + embargo
        // self-fluff sweep, every gossip tick.
        dandelion_tick();
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
                        sec_channels_.erase(fd_it->second);
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
            const auto r = ledger->apply_block(v);
            undo->apply_block(v);
            if (r.ok)
                undo->record_sgmt_undo(v.header().block_height, r.sgmt_undo);
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
            const auto r = ledger->apply_block(v);
            if (r.ok)
                undo->record_sgmt_undo(v.header().block_height, r.sgmt_undo);
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
                const auto r = node_a.ledger->apply_block(v);
                if (r.ok) {
                    // DKSAP wire integration: forward the trie effects the
                    // block committed (the undo journal is keyed by the trie
                    // key — the sidecar is invisible to the undo layer).
                    node_a.undo->record_sgmt_undo(v.header().block_height, r.sgmt_undo);
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

// ── Dandelion++ M3: epoch stem channels, embargo timer, loop guard ──────────
// Reviewed design (owner-directed 19.11): privacy payload classes only
// (SGMT_REG/STEALTH); blocks/SEC/CERT never stem. Phase is inferred from the
// CONNECTION (Monero-style): a stem packet travels only over the stem
// channels of each hop; a non-stem arrival = fluff phase = fan-out. Stem and
// fluff frames are byte-identical for the same tx (same type, same payload,
// same size) — a passive observer cannot separate phases by length, and no
// stem flag ever reaches the wire (phase lives in per-node state only).
//
// seen_ = "this digest already had its relay decision here" (armed on every
// fresh arrival — stem or fluff — and by the originator gate). state =
// "an active stem session exists (embargo timer armed)".
// Contract: true = the caller skips its fan-out for this digest (stemmed
// onward / mid-stem); false = the caller's normal fan-out path (fluff
// transition, duplicate, or non-privacy).

namespace {

// Monotonic ms for the tick/embargo arithmetic (CLOCK_MONOTONIC — wall-clock
// jumps must not fire or skip embargo timers).
uint64_t dandelion_now_ms() noexcept {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return static_cast<uint64_t>(ts.tv_sec) * 1000 + static_cast<uint64_t>(ts.tv_nsec) / 1000000;
}

} // namespace

void SwarmNode::dandelion_tick() {
    const uint64_t now = dandelion_now_ms();
    std::vector<DandelionState> expired;
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        // 1) Epoch rotation: repick the stem channel set when the epoch
        // expires (or on the first tick with no stems). HW-entropy picks —
        // never a predictable PRNG stream.
        if (dandelion_epoch_deadline_ms_ <= now || dandelion_stem_fds_.empty()) {
            std::vector<int> fds;
            fds.reserve(peer_fds_.size());
            for (const auto &kv : peer_fds_)
                if (kv.second > 0)
                    fds.push_back(kv.second);
            if (!fds.empty()) {
                // Rotation REPLACES the set (audit P1-1, 19.11): appending
                // would grow it every epoch, and a closed fd must not
                // survive into the next epoch (P2-1: a recycled fd number
                // would route privacy payloads to an unrelated connection).
                dandelion_stem_fds_.clear();
                for (size_t i = 0; i < kDandelionStemPeers && !fds.empty(); ++i) {
                    const size_t idx = hw_entropy() % fds.size();
                    dandelion_stem_fds_.push_back(fds[idx]);
                    fds.erase(fds.begin() + static_cast<std::ptrdiff_t>(idx));
                }
                dandelion_epoch_deadline_ms_ = now + kDandelionEpochMs;
            }
        } else {
            // Mid-epoch prune: a stem fd that left peer_fds_ (teardown) is
            // dead — drop it so relays never target a recycled fd.
            std::vector<int> live;
            live.reserve(peer_fds_.size());
            for (const auto &kv : peer_fds_)
                if (kv.second > 0)
                    live.push_back(kv.second);
            std::sort(live.begin(), live.end());
            dandelion_stem_fds_.erase(
                std::remove_if(
                    dandelion_stem_fds_.begin(), dandelion_stem_fds_.end(),
                    [&live](int fd) { return !std::binary_search(live.begin(), live.end(), fd); }),
                dandelion_stem_fds_.end());
        }
        // 2) Embargo sweep: state entries past their deadline self-fluff —
        // the black-hole guard (a dead stem peer must not eat the tx).
        for (auto it = dandelion_state_.begin(); it != dandelion_state_.end();) {
            if (it->second.embargo_deadline_ms <= now) {
                expired.push_back(std::move(it->second));
                it = dandelion_state_.erase(it);
            } else {
                ++it;
            }
        }
        // 3) Seen TTL prune + FIFO cap eviction.
        for (auto it = dandelion_seen_.begin(); it != dandelion_seen_.end();) {
            if (it->second <= now)
                it = dandelion_seen_.erase(it);
            else
                ++it;
        }
        while (dandelion_seen_.size() > kDandelionSeenCap && !dandelion_seen_order_.empty()) {
            dandelion_seen_.erase(dandelion_seen_order_.front());
            dandelion_seen_order_.pop_front();
        }
    }
    // Embargo self-fluff OUTSIDE the lock (the broadcast_frame snapshot-then-
    // send pattern: sends block and must never hold peers_mutex_).
    for (const auto &st : expired) {
        std::vector<int> fds;
        {
            std::lock_guard<std::mutex> lock(peers_mutex_);
            for (const auto &kv : peer_fds_)
                if (kv.second > 0)
                    fds.push_back(kv.second);
        }
        for (int fd : fds) {
            std::vector<std::vector<uint8_t>> one{st.payload};
            (void)send_wire_payloads_to(fd, st.type, one);
        }
        fluff_broadcasts_.fetch_add(1, std::memory_order_relaxed);
    }
}

bool SwarmNode::dandelion_on_sidecar(int origin_fd, const std::array<uint8_t, 32> &digest,
                                     WireMsgType type, const std::vector<uint8_t> &payload) {
    // Privacy classes only; everything else fans out normally.
    if (type != WireMsgType::DKSAP_SGMT_REG && type != WireMsgType::DKSAP_STEALTH)
        return false;

    const uint64_t now = dandelion_now_ms();
    int relay_fd = -1; // >= 0 → stem onward; -1 → the caller's fan-out path
    {
        std::lock_guard<std::mutex> lock(peers_mutex_);
        const bool is_origin = origin_fd < 0;
        const bool stem_phase =
            is_origin || std::find(dandelion_stem_fds_.begin(), dandelion_stem_fds_.end(),
                                   origin_fd) != dandelion_stem_fds_.end();
        const bool is_seen = dandelion_seen_.count(digest) != 0;
        const auto st_it = dandelion_state_.find(digest);
        const bool have_state = st_it != dandelion_state_.end();

        if (is_origin) {
            // The originator gate (broadcast_sidecars_for): mid-stem session
            // → keep it and skip the fan-out; otherwise start a fresh stem
            // session and relay to one EPOCH stem peer (the embargo timer
            // arms at every continuing hop).
            if (have_state)
                return true;
            // The originator's leg rides the EPOCH stem channels (the "++"
            // essence, audit P1-2): per-tx random picks from all peers would
            // let a Sybil correlate transactions by varying recipients.
            std::vector<int> fds;
            for (int sfd : dandelion_stem_fds_)
                if (sfd > 0)
                    fds.push_back(sfd);
            if (fds.empty())
                for (const auto &kv : peer_fds_)
                    if (kv.second > 0)
                        fds.push_back(kv.second);
            if (!fds.empty()) {
                DandelionState st;
                st.embargo_deadline_ms = now + kDandelionEmbargoMs;
                st.type = type;
                st.payload = payload;
                dandelion_state_[digest] = std::move(st);
                dandelion_seen_[digest] = now + kDandelionSeenTtlMs;
                dandelion_seen_order_.push_back(digest);
                relay_fd = fds[hw_entropy() % fds.size()];
            }
            // No stems available → no session: the fan-out proceeds (the
            // safe default when the stem channel set is empty).
        } else if (stem_phase) {
            // Wire arrival on a stem connection.
            if (is_seen && have_state) {
                // LOOP GUARD: the chain found a cycle through us. KEEP the
                // session — the packet returned, the chain is stuck in a
                // cycle, and the embargo timer (armed at every continuing
                // hop) is the guaranteed escape: it self-fluffs the payload
                // in ≤45s. Erasing the session here would RE-STEM the digest
                // (the frame hook sees no state → fresh session), which
                // re-enters the same cycle (audit P2-2, 19.11).
            } else if (!is_seen && hw_entropy() % 2 == 0) {
                // Fresh stem arrival, coin-flip continue (geometric path
                // length, mean 2 hops). The relay arms its own embargo
                // timer — the black-hole guard exists at every hop.
                std::vector<int> fds;
                for (int sfd : dandelion_stem_fds_)
                    if (sfd > 0 && sfd != origin_fd)
                        fds.push_back(sfd);
                if (fds.empty())
                    for (const auto &kv : peer_fds_)
                        if (kv.second > 0 && kv.second != origin_fd)
                            fds.push_back(kv.second);
                if (!fds.empty()) {
                    DandelionState st;
                    st.embargo_deadline_ms = now + kDandelionEmbargoMs;
                    st.type = type;
                    st.payload = payload;
                    dandelion_state_[digest] = std::move(st);
                    dandelion_seen_[digest] = now + kDandelionSeenTtlMs;
                    dandelion_seen_order_.push_back(digest);
                    relay_fd = fds[hw_entropy() % fds.size()];
                }
            }
            // seen-without-state (a fluffed duplicate) and coin-flip fluff
            // fall through: the caller's fan-out path handles them.
        }
        // Fluff-phase arrivals (non-stem connection): fall through to the
        // caller's normal fan-out path. seen_ is armed below for fresh
        // digests so the frame-hook gate does not re-stem a fluffed tx.
        if (!is_seen && relay_fd < 0) {
            dandelion_seen_[digest] = now + kDandelionSeenTtlMs;
            dandelion_seen_order_.push_back(digest);
        }
    }
    if (relay_fd >= 0) {
        std::vector<std::vector<uint8_t>> one{payload};
        (void)send_wire_payloads_to(relay_fd, type, one);
        stem_relays_.fetch_add(1, std::memory_order_relaxed);
        return true; // the caller skips its fan-out for this digest
    }
    return false;
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
