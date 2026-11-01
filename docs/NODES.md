# VX Nodes — how they work

What a VX node actually is, what it loads, what it serves, and what it
listens to. Task-oriented companions: [RPC cookbook](RPC_COOKBOOK.md) for
the JSON API, [multi-node runbook](MULTI_NODE_RUNBOOK.md) for running
several nodes together.

## One binary, three modes

`vx_node` is a single executable; the mode is a flag, not a build.

```
usage:
  vx_node                          Print the chain report and exit
  vx_node --demo                   Mint the scripted demo block, then exit
  vx_node --serve [PORT]           Run the node and serve the JSON RPC
  vx_node --serve --p2p PORT --peer HOST:PORT   ...and join the mesh

  --port PORT        HTTP/RPC port (default 8088)
  --p2p PORT         VX60 P2P wire port (default 19088)
  --peer HOST:PORT   Connect to a peer at startup (repeatable)
  --data-dir DIR     Chain data directory (default ./data)
```

- **Report mode** (no flags) opens the data dir, prints the chain summary
  and exits — useful for a quick audit of a ledger file.
- **`--demo`** mines the secondary genesis (Genesis #2) plus two funded
  demo accounts and exits. It is a local convenience; the block embeds
  wall-clock time, so two nodes that run `--demo` in different seconds
  get *different* blocks — for anything multi-node, run `--demo` once and
  copy the data dir (see the runbook).
- **`--serve`** starts the JSON RPC and (with `--p2p`) the VX60 mesh.
  Serving never mines demo blocks on its own; blocks are produced by the
  transfer path and arrive from peers.

## What lives in the data dir

```
data/
  genesis.bin    65536 B   the genesis frame (block 0)
  ledger.vxb     n*65536 B one 64 KiB frame per block, append-only
  undo/                    undo journal for O(1) reorg rollback (created on demand)
```

`ledger.vxb` is opened `mmap`/`mremap`: appending a block is an O(1)
extend, and reading block *h* is a pointer into the mapping at offset
`h * 65536` — no deserialization step, the RPC serves blocks straight
out of the mapping. The undo journal makes a branch switch a bounded
rollback instead of a re-download.

## The block frame

Every block — genesis, demo, transfer, wire-received — is the same
64 KiB frame:

| Region | Size | Content |
|---|---|---|
| Header | 472 B | height, timestamp, `prev_block_hash`, `merkle_root`, `tx_count`, 384 B attractor coords |
| Transactions | 580 × 112 B | at most `MAX_TX_PER_BLOCK = 580` |
| Padding | 104 B | fixed size, deterministic |

The tip hash is the VortexSponge256 digest of the 472-byte header. The
384 bytes of attractor coordinates (three 128-byte trunks X/Y/Z) are the
3-Trunk Galois attractor state the block commits to. `tx_count` is
structurally bounded — a hostile header claiming more than 580
transactions is rejected before anything is walked.

## Startup path

```
load genesis.bin -> open/mmap ledger.vxb -> apply blocks to LedgerState
             -> (optional) demo mint -> RPC server -> P2P listener + peers
```

Applying a block enforces the ledger rules (balances, signatures) through
the same `apply_block` path used everywhere else; there is no fast path
that trusts a block because it is on disk or on the wire.

## The two ports

| Port | Protocol | Carries |
|---|---|---|
| `--port` (default 8088) | HTTP/JSON | the RPC: 34 endpoints, SSE events |
| `--p2p` (default 19088) | VX60 | 24-byte wire headers + 64 KiB frames |

The RPC is an observation and demo surface — it carries **no consensus
weight**; a node serves the same ledger with the RPC disabled. The VX60
port is the consensus-adjacent one: it is how blocks move.

## The VX60 wire

Every packet starts with a 24-byte header:

```
magic(4) | msg_type(1) | flags(1) | reserved(2) |
payload_len(4) | crc32c(4) | peer_nonce(8)
```

- CRC32C is computed with the hardware SSE4.2 instruction; a mismatched
  packet is dropped without killing the connection, and the count is
  visible at `/api/swarm/peers` as `corrupted_packets_dropped`.
- Message types include `HANDSHAKE`, `INV`, `GET_BLOCK`, `RAW_BLOCK_64K`,
  `TX_COCOON_112B`, `PING`, `PONG`, `GQC_VOTE`. The listener loop
  currently serves `PING`/`PONG` and `RAW_BLOCK_64K`; anything else drops
  the connection rather than being guessed at.
- Blocks travel as a full 65536-byte frame per packet; the block-streaming
  path can also serve them zero-copy via `sendfile()` straight from the
  ledger mapping.

**How a connection becomes a peer.** A node started with `--peer` opens
TCP, sends a PING, and parks the socket with a dedicated reader thread.
On the far side, the listener accepts the connection and — at the first
*verified* packet — promotes it into the peer table and the broadcast
set. A promoted connection works in both directions: the hub pushes
blocks back down the same socket the spoke dialed, and both sides keep
reading continuously, so relays flow either way.

**How a block is accepted.** A received frame is CRC32C-verified, then
must pass the tip-extension rule: its height must be exactly
`chain_height` (the next block) and its `prev_block_hash` must equal the
local tip hash. Accepted frames are appended, applied to the ledger, and
re-broadcast one hop past their origin. Everything else — replays,
duplicates, competing histories — is dropped silently.

## Post-quantum signing on the node

Transaction signatures are WOTS+ (w=16, 67 chains) over XMSS (H=4,
16 one-time leaves), hashed by the same VortexSponge256 — 2 376 bytes
per witness, no elliptic curves, no RSA, nothing for Shor's algorithm.
Signing pages live in the locked MemoryVault: a key page is sealed
VOID → LOCKED → BURNED, so the leaf material exists in RAM only for the
duration of one signature. Verification recomputes the witness digest
from transported fields — nothing is trusted because it arrived (see
whitepaper §9.5).

## Honest limits

Recorded where they were measured — see the
[runbook's limits section](MULTI_NODE_RUNBOOK.md#honest-limits-read-before-building-on-this):
no backfill sync over the wire (a node missing a block stalls until it is
restarted from a snapshot), no wire-level fork choice (each node keeps
its own tip), peer identity not yet authenticated, and wire-applied
frames are checked structurally and by ledger rules rather than
re-mined.
