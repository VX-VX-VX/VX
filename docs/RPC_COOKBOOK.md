# VX RPC Cookbook

Task-oriented recipes for the JSON RPC exposed by `vx_node --serve <port>`.
Every response shown here was captured from a live node — nothing here is
"should look like". The default port is 18088; the examples below use 18099
only to avoid colliding with a node you may already run.

Other docs: [README](../README.md) · [whitepaper](../WHITEPAPER_V6.md) ·
[glossary](GLOSSARY.md) · [The Vortex Challenge](CHALLENGE.md)

---

## Start a node with RPC

```bash
cmake -S . -B build -G Ninja && cmake --build build -j
./build/vx_node --serve 18088 --data-dir /tmp/vx_node1
```

For a chain with a mined demo block (recommended for the transfer recipes
below — it creates the two demo accounts), run the demo first:

```bash
./build/vx_node --demo --data-dir /tmp/vx_node1
./build/vx_node --serve 18088 --data-dir /tmp/vx_node1
```

Both commands work on the same data directory: `--demo` mints and stops,
`--serve` serves the existing ledger. All responses are `application/json`;
endpoints return an `error` field on rejection, and unknown paths return
HTTP 404 `{"error":"not found"}`.

## Read the chain state

### GET /api/status — the tip and supply

```bash
curl -s http://localhost:18099/api/status | python3 -m json.tool
```

```json
{
    "chain_height": 2,
    "tip_block_index": 1,
    "ledger_bytes": 131072,
    "frame_size": 65536,
    "max_tx_per_block": 580,
    "total_supply_atomics": "264000000000000",
    "total_supply_vx": "2640000.00000000",
    "tracked_accounts_count": 3,
    "tip_hash_hex": "1d22ae15...",
    "crypto_engine": "3-Trunk Galois Attractor (3072-bit CRT) + VortexSponge256 (12-Round ARX)",
    "storage_engine": "POSIX mmap/mremap O(1) Zero-Copy"
}
```

What to look at: `tip_hash_hex` is the Sponge256 digest of the 472-byte
header of the tip block. On a **fresh** data directory (no `--demo`) it must
equal the value published in the whitepaper §16 and in
[The Vortex Challenge](CHALLENGE.md):
`ff327c330756241cd7c66a2f207c19202a2d7d38bbe9ffebb23510a72fd75be1`.
After the demo block it differs (the chain grew) — that is expected.

`total_supply_atomics` is a string, not a number: u64 atomics are wider
than some JSON parsers' integers. 1 VX = 10^8 atomics.

### GET /api/blocks — every block frame

```bash
curl -s http://localhost:18099/api/blocks | python3 -m json.tool
```

Each entry carries `height`, `block_hash_hex`, `prev_block_hash_hex`,
`merkle_root_hex`, `tx_count` and the 384-byte `attractor_coords`
(`x_hex`, `y_hex`, `z_hex`) — the 3-Trunk state the block commits to.
Level 1 of the Challenge can be verified with this endpoint: the
`block_hash_hex` of block 0 is the published tip hash.

### GET /api/accounts — balances

```bash
curl -s http://localhost:18099/api/accounts | python3 -m json.tool
```

After a demo run there are three accounts: Genesis #1 (the 2.54M VX
coinbase) and the two demo accounts. `payload_42` is the raw 42-character
address; `address` is the same with the `NFA_V6_` prefix.

## Move value

### POST /api/transfer — send VX

```bash
curl -s -X POST http://localhost:18099/api/transfer \
  -H 'Content-Type: application/json' \
  -d '{
    "sender":   "NFA_V6_CLIqoXuU6o9M9cAcFUGEWe7dsxsM8WqV0RwVQnukAA",
    "receiver": "NFA_V6_iIgiAC7Bohg_wrdof8Vu1y7z0T3zHB3BMxERENEMAA",
    "amount_vx": 10
  }'
```

```json
{
    "status": "ok",
    "block_height": 2,
    "block_hash_hex": "ff575171...",
    "transfers": 1,
    "sender_balance_vx": "74990.00000000",
    "receiver_balance_vx": "25010.00000000"
}
```

Field notes:

- addresses may be passed with or without the `NFA_V6_` prefix — the
  server strips it;
- the transfer is applied to the ledger immediately (this is the demo/CLI
  path, not the mempool path — there is no fee market on this endpoint);
- overspending answers `{"error":"insufficient funds"}` and changes
  nothing.

## Sign post-quantum

### POST /api/crypto/pq_sign — a PQ-signed transaction

```bash
curl -s -X POST http://localhost:18099/api/crypto/pq_sign -d '{}'
```

```json
{
    "ok": true,
    "verified": true,
    "pq_scheme": "WOTS+ (w=16, L=67) + XMSS (H=4) over VortexSponge256",
    "shor_vulnerable_ops": 0,
    "wots_chains": 67,
    "witness_size_bytes": 2376,
    "leaf_index": 7,
    "pq_pubkey_root": "8d5b24d7..."
}
```

This endpoint signs with the full SegPQ stack: the witness is generated
inside a locked MemoryVault page, the key page is burned, and the witness
is registered in the sidecar. `leaf_index` is which of the 16 one-time
leaves this signature consumed — one-time means *consumed forever*.

### POST /api/crypto/pq_verify — check the witness machinery

```bash
curl -s -X POST http://localhost:18099/api/crypto/pq_verify -d '{}'
```

```json
{
    "ok": true,
    "verified": true,
    "wots_verify_ok": true,
    "anchor_ok": true,
    "mitm_rehash_attack_rejected": true,
    "wots_forward_chain_forgery_rejected": true,
    "merkle_path_tamper_rejected": true
}
```

The server runs its built-in adversarial suite against a witness — a
keyless rehash, a forward-chain forgery and a Merkle-path tamper must each
be rejected. Use this endpoint as a self-check after touching any PQ code.

## Verify the cryptography

### GET /api/crypto/canonical — the SAC avalanche trace

```bash
curl -s http://localhost:18099/api/crypto/canonical | python3 -m json.tool
```

Returns the per-round avalanche profile of the canonical seed (whitepaper
§6): flip one seed bit, measure how many of the 3072 state bits diverge
per round. This is level 3 of the Vortex Challenge — cross-check your own
implementation's numbers against this trace.

### POST /api/crypto/lab — run the attractor on your own seed

```bash
curl -s -X POST http://localhost:18099/api/crypto/lab -d '{}' | head -c 400
```

Returns the canonical seed echo plus derived coordinates. A seed parameter
is accepted; without one it uses the published canonical seed.

## Look inside the subsystems

| Endpoint | Method | What it shows |
|---|---|---|
| `/api/vault/memory` | GET | vault arena: page states, mlock status, pool counters |
| `/api/vault/ephemeral_sign` | POST | air-gap signing demo: page VOID→LOCKED→BURNED, rdtsc key lifetime |
| `/api/mempool/zk_stats` | GET | mempool occupancy, cocoon commitments, TDI pass/fail counts |
| `/api/swarm/peers` | GET | VX60 wire stats: bytes sent, corrupted packets dropped |
| `/api/swarm/dandelion_stats` | GET | Dandelion++ stem/fluff relay counters |
| `/api/state/trie_root` | GET | VM state trie root and leaf count |
| `/api/state/prove` | POST | a state inclusion proof for a key |
| `/api/consensus/finality_status` | GET | GQC checkpoint height, pending finality, rollback guard |
| `/api/telemetry/rdtsc` | GET | per-operation cycle contours (Solinas reduction, sponge, ...) |
| `/api/vm/execute_trace` | POST | VM execution with per-step Landauer trace |

### POST /api/vm/execute_trace — run VM bytecode

The field is `asm` (a small assembly string), not `bytecode`:

```bash
curl -s -X POST http://localhost:18099/api/vm/execute_trace \
  -d '{"asm":"PUSH 1"}' | python3 -m json.tool | head -20
```

The response carries the compiled `bytecode_hex`, a `disassembly` and a
per-step `trace` with `erased_bits`, `hamming_flips` and cumulative
Landauer gas — the VM accounts its physical cost per instruction.

## Security tooling

### POST /api/security/audit — replay the guard checks

The endpoint takes an `attack_type` string and runs that scenario against
a live in-memory chain, expecting the guard to hold. The accepted values
are: `dust_spam_tdi`, `tamper_amount`, `tamper_receiver`,
`pq_mitm_forgery`, `double_miner`, `excess_reward`, `unauthorized_genesis`,
`sac_avalanche_probe` — one per guard, in the order the whitepaper
discusses them.

```bash
curl -s -X POST http://localhost:18099/api/security/audit \
  -d '{"attack_type":"tamper_amount"}'
```

An empty or unknown value answers `{"error":"unknown attack_type ''"}` —
the string is case-sensitive.

### POST /api/security/chaos_fuzz — the deterministic chaos suite

Runs the same mutation engine as `VortexChaosFuzzerTest` (wire headers,
frames, VM bytecode) for a bounded round count. Deterministic seeds make
every run replayable bit-for-bit.

## Error handling cheat sheet

| Symptom | Cause | Fix |
|---|---|---|
| `{"error":"insufficient funds"}` | sender balance < amount | check `/api/accounts` |
| `{"error":"unknown attack_type ''"}` | missing or mistyped value | see the list above |
| `{"error":"missing asm field"}` | VM endpoint got `bytecode` instead of `asm` | use `asm` |
| `{"error":"not found"}` (HTTP 404) | unknown path | check the route table |
| serve mode mints a demo block | you ran `--demo` earlier by accident | fresh `--data-dir` |
| nothing tracked in `/api/accounts` | fresh ledger, no demo run | run `--demo` once on this data dir |

## Conventions across all endpoints

- Amounts in responses are strings of atomics or VX with 8 decimals —
  never floats; parse with integer arithmetic.
- Block/tx hashes are lowercase hex without a `0x` prefix; attractor
  coordinates are `0x`-prefixed hex of arbitrary length (up to 256 hex
  chars per trunk).
- The RPC is an observation and demo surface. It is **not** the P2P
  protocol (that is VX60 on port 19088) and carries no consensus weight —
  a node serves the same ledger with the RPC disabled.
