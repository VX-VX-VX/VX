# VX RPC Cookbook

Task-oriented recipes for the JSON RPC exposed by `vx_node --serve <port>`.
Every response shown here was captured from a live node — nothing here is
"should look like". The default port is 18088; the examples below use 18099
only to avoid colliding with a node you may already run.

Other docs: [README](../README.md) · [whitepaper](../WHITEPAPER_V6.md) ·
[nodes guide](NODES.md) · [multi-node runbook](MULTI_NODE_RUNBOOK.md) ·
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
    "chain_height": 1,
    "tip_block_index": 0,
    "ledger_bytes": 65536,
    "frame_size": 65536,
    "max_tx_per_block": 579,
    "total_supply_atomics": "254000000000000",
    "total_supply_vx": "2540000.00000000",
    "max_supply_vx": 7000000000,
    "issued_supply_atomics": "254000000000000",
    "issuance_headroom_vx": "6997460000.00000000",
    "block_reward_base_vx": 50,
    "block_reward_max_vx": 1000,
    "reward_tier_count": 5,
    "tracked_accounts_count": 1,
    "tip_hash_hex": "047f3cf7ac9f259b0eefda8cc3b0a260f86ae326b7574762823be81f5e0d0794",
    "crypto_engine": "3-Trunk Galois Attractor (3072-bit CRT) + VortexSponge256 (12-Round ARX)",
    "storage_engine": "POSIX mmap/mremap O(1) Zero-Copy"
}
```

What to look at: `tip_hash_hex` is the Sponge256 digest of the tip block's
full frame commitment - the 504-byte header AND the 104-byte tail (VM state
root, gas, PoGW nonce, bytecode), so tail metadata cannot change without
changing the block id (external review round 5; earlier captures show the
header-only digest of the same genesis). On a **fresh** data directory
(no `--demo`) it must
equal the value published in the whitepaper §16 and in
[The Vortex Challenge](CHALLENGE.md):
`047f3cf7ac9f259b0eefda8cc3b0a260f86ae326b7574762823be81f5e0d0794` (the VXC7 genesis - the frame gained the 32-byte witness_merkle_root header field on 2026-11-07; the pre-2.11 constant was 485f5afac16d6bec3c96efdce197c76ac9c81d0d669ed8b8f4b597669690b44d).
After the demo block it differs (the chain grew) — that is expected.

`total_supply_atomics` is a string, not a number: u64 atomics are wider
than some JSON parsers' integers. 1 VX = 10^8 atomics.

The emission fields are the hard-coded schedule (user-directed
2026-11-03): at most **7,000,000,000 VX** can ever be issued
(`max_supply_vx`); the block reward is a deterministic function of the
block's own hash — `block_reward_base_vx` (50) is guaranteed for every
valid block, and the hash's leading zero bits step the reward up toward
`block_reward_max_vx` (1,000, the jackpot) across `reward_tier_count` (5)
absolute thresholds (20/24/28/32/40 zero bits pay 75/100/200/400/1,000),
`issued_supply_atomics` is the cumulative issuance actually booked
(coinbase credits minus the fee share re-credited to the producer), and
`issuance_headroom_vx` is what remains under the cap — the final
emission blocks mint exactly this remainder, then the cap closes.

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

### POST /api/transfer — send VX (post-quantum authorized)

Since BACKLOG 0.7 (2026-11-03) a transfer carries a **post-quantum
witness produced by the sender's key** — the server no longer signs on
the user's behalf. The request must carry:

- `sender`, `receiver` (with or without the `NFA_V6_` prefix — the
  server strips it), `amount_vx` as before;
- `witness_b64` — the 2376-byte `PqSignatureWitness`, base64-encoded;
- `fee_atoms` — a positive fee in micro-VX atomic units;
- `nonce` — the sender's next expected nonce (read it from
  `GET /api/accounts` -> `next_nonce_atomics`).

```bash
curl -s -X POST http://localhost:18099/api/transfer \
  -H 'Content-Type: application/json' \
  -d '{
    "sender":     "NFA_V6_CLIqoXuU6o9M9cAcFUGEWe7dsxsM8WqV0RwVQnukAA",
    "receiver":   "NFA_V6_iIgiAC7Bohg_wrdof8Vu1y7z0T3zHB3BMxERENEMAA",
    "amount_vx":  10,
    "fee_atoms":  100,
    "nonce":      0,
    "witness_b64": "<2376-byte PqSignatureWitness, base64>"
  }'
```

The server rebuilds the transaction, re-derives its SegPQ anchor FROM THE
WITNESS (`pq_set_transaction_anchor` — the transported `cocoon_proof` is
never trusted), registers the witness, seals the block with a real PoGW
nonce (BACKLOG 0.9 — the request takes a few seconds at the dev-mode
difficulty) and broadcasts the witnesses BEFORE the block (BACKLOG 0.8),
so peers can authorize it.

Error answers (all 403, nothing changes):

- no `witness_b64`: `PQ witness required: keyless transfers are not
  accepted`;
- `witness_b64` that does not decode to exactly 2376 bytes;
- `fee_atoms` <= 0;
- `nonce` != the ledger's expected next nonce;
- overspending still answers `{"error":"insufficient funds"}`.

**Producing the witness (client side).** The witness signs the canonical
transaction message

```
M = Sponge256("VX_PQ_TX_MSG_V1" || sender[42] || receiver[42] ||
               amount[8] || fee[4] || nonce[4] || chain_id[4])
```

with WOTS+ (w=16, 67 chains) at XMSS leaf `nonce & 0xF` of the key's
H=4 tree; the 2376-byte witness layout is documented in
`include/vx/crypto/pq_signature.hpp`. The signing key's XMSS root must
either derive the sender address (self-certifying `"PQA..."` addresses)
or match the root the address is bound to in ledger state. **The server
deliberately provides no signing endpoint for user keys** — a server
that signs for you holds your key, which is the vulnerability BACKLOG
0.7 removes. The `/api/crypto/pq_sign` demo endpoint signs with the
public documented demo key only (BACKLOG 0.10 tracks compiling the demo
fixtures out).

Address forms: a legacy-shaped address (`NFA_V6_...` that does not start
with `PQA` after prefix stripping) commits no key root, so it can no
longer SEND unless it is one of the genesis-era allocations bound in the
protocol seed table (the canonical genesis receiver and the two demo
addresses); it can always RECEIVE. New spendable addresses are
self-certifying `PQA` addresses derived from the key root.

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
