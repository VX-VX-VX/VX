# VX Multi-Node Runbook

How to run a real 3-node VX testnet on one machine and watch blocks travel
over the VX60 wire — plus the automated script that does the same thing.
Every output shown here was captured from live runs, not invented.

Other docs: [RPC cookbook](RPC_COOKBOOK.md) · [README](../README.md)

---

## The automated script

```bash
cmake -S . -B build -G Ninja && cmake --build build -j
scripts/multi_node_test.sh build
```

Sample output (this is one real run):

```
[1/5] Minting the demo chain once, then snapshotting it to all nodes
[2/5] Starting star topology (B and C dial A on :19188)
  [PASS] RPC :18088 is up
  [PASS] RPC :18089 is up
  [PASS] RPC :18090 is up
[3/5] Transfer on A must propagate over VX60 to B and C
  [PASS] tip on A matches the transfer block
  [PASS] tip on B matches A
  [PASS] tip on C matches A
  [PASS] sender balance on B is 74993 VX
[4/5] Garbage packets are counted as corrupted; the node stays alive
  [PASS] corruption counter rose (0 -> 10)
  [PASS] node A still serving after garbage
[5/5] In-process split-brain reorg simulation
  [PASS] split-brain reorg converged

=== 10 passed, 0 failed ===
```

Ports used: RPC 18088-18090, VX60 19188-19190. They must be free; edit the
variables at the top of the script to change them.

## The manual walk (3 terminals or nohup)

### 1. Mint the demo chain once, snapshot it

```bash
./build/vx_node --demo --data-dir /tmp/vx_a
cp -r /tmp/vx_a /tmp/vx_b
cp -r /tmp/vx_a /tmp/vx_c
```

**Why a snapshot, not three demo runs?** The demo block embeds
wall-clock time (`set_timestamp(time(nullptr))`). Two nodes that mine the
demo block in different seconds build *different* blocks — and correctly
reject each other's history from that point on. A node joining a network
always starts from a shared snapshot of the chain state; the demo path is
a local convenience, and the snapshot is its multi-node equivalent.

### 2. Start the hub, then the spokes

```bash
# terminal 1 — the hub
./build/vx_node --serve 18088 --p2p 19188 --data-dir /tmp/vx_a

# terminal 2 — a spoke that dials the hub
./build/vx_node --serve 18089 --p2p 19189 --peer 127.0.0.1:19188 --data-dir /tmp/vx_b

# terminal 3 — another spoke
./build/vx_node --serve 18090 --p2p 19190 --peer 127.0.0.1:19188 --data-dir /tmp/vx_c
```

Each `--peer` connection sends a VX60 PING handshake on connect; the hub
answers PONG and promotes the connection into its peer table. A promoted
inbound connection is also a broadcast target, so the hub can push blocks
back down the same socket the spoke dialed.

Check the mesh from the hub:

```bash
curl -s localhost:18088/api/swarm/peers | python3 -m json.tool
```

```json
{
    "wire_magic": "0x56583630",
    "wire_protocol": "VX60",
    "p2p_port": 19188,
    "corrupted_packets_dropped": 0,
    "vx60_bytes_transferred": 65560,
    "peers": [
        {"address": "127.0.0.1:41462", "loopback": true, "banned": false},
        {"address": "loopback", "loopback": true, "banned": false}
    ]
}
```

(`loopback` is the node's own virtual-mesh entry; the `127.0.0.1:<ephemeral>`
entry is a real dialed connection that reached the hub.)

### 3. Transfer on the hub, watch it land on the spokes

```bash
curl -s -X POST localhost:18088/api/transfer -d '{
    "sender":   "NFA_V6_CLIqoXuU6o9M9cAcFUGEWe7dsxsM8WqV0RwVQnukAA",
    "receiver": "NFA_V6_iIgiAC7Bohg_wrdof8Vu1y7z0T3zHB3BMxERENEMAA",
    "amount_vx": 7 }'
```

```json
{"status":"ok","block_height":2,"block_hash_hex":"f88f89cd70615ea6...",
 "sender_balance_vx":"74993.00000000","receiver_balance_vx":"25007.00000000"}
```

About one second later, both spokes show the same world:

```bash
curl -s localhost:18089/api/status   # h=3, tip f88f89cd70615ea6...
curl -s localhost:18090/api/status   # h=3, tip f88f89cd70615ea6...
curl -s localhost:18089/api/accounts # sender 74993.00000000, receiver 25007.00000000
```

All three nodes converged on the same tip hash — the spoke applied the
hub's block frame, then re-broadcast it to its own peers (a frame that
arrives over the wire and extends the tip gossips one hop past its origin).

### 4. Hostile traffic does not hurt

Fire garbage at the VX60 port:

```python
import socket
for _ in range(10):
    s = socket.socket(); s.settimeout(2)
    s.connect(("127.0.0.1", 19188))
    s.sendall(b"\xde\xad\xbe\xef" + b"\x00" * 60)  # wrong magic
    s.close()
```

`/api/swarm/peers` answers `corrupted_packets_dropped: 10`; `/api/status`
keeps serving at the same tip. Every inbound packet carries a 24-byte
VX60 header whose CRC32C is verified in hardware (SSE4.2) before anything
is parsed — a bad CRC is dropped silently, a bad magic is counted.

### 5. Split-brain reorg, live

```bash
curl -s -X POST localhost:18088/api/swarm/simulate_split_reorg | python3 -m json.tool
```

```json
{
    "ok": true,
    "reorg_success": true,
    "duration_us": 131534,
    "partition": {"node_a_height": 2, "node_a_work": 3000000,
                  "node_b_height": 4, "node_b_work": 10000000},
    "heal": {"blocks_rolled_back": 2, "blocks_resynced": 4,
             "vx60_bytes_transferred": 262456}
}
```

This runs two isolated in-process nodes (own BlockStore + LedgerState)
bridged by real VX60 loopback TCP: they mine divergent histories, the
partition heals, the lighter branch is rolled back via the O(1) undo
journal, and both converge on the heavier tip. It is a faithful
demonstration of the reorg machinery — see the honest-limits section
below for what it does not yet cover.

## How the relay actually works

1. **Dial + handshake.** `--peer HOST:PORT` opens TCP, sends a VX60 PING
   (24-byte header, hardware CRC32C), parks the socket with a reader thread.
2. **Promotion.** The hub's listener accepts the connection; the first
   verified packet (PING or a block frame) promotes it: the socket enters
   the broadcast set and the peer table. Connections that only ever speak
   garbage never get promoted.
3. **Broadcast.** A block mined locally (transfer path) is sent to every
   socket in the broadcast set as `RAW_BLOCK_64K`: 24-byte header +
   the full 65536-byte frame.
4. **Ingest.** Each received frame is CRC32C-verified, then passes the
   tip-extension rule (below). Accepted frames are appended, applied to
   the ledger, and re-broadcast to this node's peers.
5. **Reader threads.** Both accepted and dialed sockets are read
   continuously — a node that was dialed INTO still hears what comes back.

**The tip-extension rule.** A frame is applied only when
`frame.height == chain_height` (i.e. exactly the next block) and
`frame.prev_block_hash == tip_hash`. Anything else is dropped silently.
There is no fork choice over the wire yet — see limits.

## Field-tested scenarios

All of the following were run live against real node processes; results
are recorded, not promised:

| Scenario | Result |
|---|---|
| 5 sequential transfers, star topology | all 3 nodes h=7, identical tip, identical balances after every step |
| Multi-hop gossip (node D dials B, not the hub A) | D converged on the next block via B's relay, balances correct |
| Replay of a real historical block with valid CRC32C | dropped by the tip-extension rule, `corrupted_packets_dropped` stays 0 |
| Replay of the current tip frame | dropped (height is not `chain_height`) |
| 10 garbage packets (bad magic) | counter rose to 10, node kept serving |
| 3 concurrent transfers | serialized by the ledger lock: heights n, n+1, n+2, all applied |
| Spoke restart mid-chain | rejoined on connect and received the next block |
| Late joiner from a stale snapshot | honestly stalls at its snapshot height (see limits) |
| Snapshot restart after an abrupt kill | ledger intact on disk; fresh snapshot rejoins at the tip, next block converges |

## Honest limits (read before building on this)

- **No backfill sync.** A node that joins late, or misses a block, has no
  way to request history over the wire yet: it only accepts tip-extending
  frames, so a gap means it stalls until it is restarted from a snapshot
  that includes the missing blocks. INV/GET_BLOCK message types exist in
  the wire protocol but are not served by the listener loop.
- **No live fork choice.** Two nodes that mine competing blocks at the
  same height over the wire will each keep their own tip; neither
  switches. The split-brain simulation above exercises the rollback
  machinery in-process, but wire-level reorg selection is not wired yet.
- **Peer identity is unauthenticated.** A promoted peer has `node_id: 0`;
  there is no identity assertion in the handshake, so a testnet only.
- **Block validity is structural, not economic.** A wire-applied frame is
  checked for tip extension, frame CRC and ledger rules (the same
  `apply_block` path RPC transfers use); it is not re-mined or
  proof-of-work verified. The PoGW check belongs to the mempool/mining
  path.

## Port map

| Port | Protocol | Purpose |
|---|---|---|
| 8088 (default) / 18088+ | HTTP | JSON RPC, SSE events |
| 19088 (default) / 19188+ | VX60 | 24-byte wire header + 64 KiB frames |
