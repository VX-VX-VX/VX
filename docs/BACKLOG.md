# VX Engineering Backlog

The full build-out list: what exists, what is half-built, what is missing,
and what each piece needs to be called done. This file is the detailed
engineering companion to [ROADMAP](../ROADMAP.md) (which tracks only the
headline items) and [docs/NODES.md](NODES.md).

Priorities: **P0** blocks any public multi-user use, **P1** hardens the
artifact, **P2** is protocol completeness, **P3** is expansion.

---

## Status snapshot — what already exists and how it is verified

| Subsystem | State | Verified by |
|---|---|---|
| 3-Trunk Galois attractor (3072-bit, Solinas primes) | shipped | KATs, SAC avalanche matrix, canonical vectors, Challenge level 3 |
| VortexSponge256 (12-round ARX) | shipped | KATs (test 6), SAC matrix |
| 64 KiB block frame (472 B header, 580 tx cap) | shipped | frame tests, libFuzzer target |
| Storage: mmap/mremap O(1) append-only ledger + undo journal | shipped | reorg test, ASan/UBSan CI lane |
| WOTS+ (w=16, L=67) + XMSS (H=4), 2376 B witness | shipped | 9 424-mutation negative-vector matrix (4 672 + 4 752), MITM/chain-forgery suite, durable leaf ledger |
| MemoryVault (mlock/huge pages, VOID→LOCKED→BURNED pages) | shipped | vault tests, sanitizer lane |
| TDI dust filter (early-stage payload gate) | shipped | mempool tests, `/api/security/audit` |
| 7-tier key matrix (SK/FVK/IVK/OVK/TLMK/MSRK/EK) | demo-grade | derive/scan/proof-of-life/Shamir endpoints |
| JSON RPC (34 endpoints) | shipped | RPC cookbook, live-captured docs |
| VX60 wire (24 B header, CRC32C) | shipped | libFuzzer target, live 3-node testnet |
| P2P: handshake, promotion, reader threads, block relay, one-hop gossip | shipped | 3-node loopback testnet, 9 live scenarios, swarm test suite |
| Split-brain reorg (partition → heal → O(1) rollback) | in-process only | `test_swarm_p2p`, RPC simulate endpoint |
| CI: GCC+Clang matrix, ASan+UBSan, libFuzzer, CodeQL (C++ + web) | shipped | green on every push |
| Web console | shipped | npm build in CI |

---

## P0 — make the P2P layer survivable outside a lab

The live testnet works, but four gaps keep it lab-grade. Each is small
enough to ship in one session; together they turn the loopback demo into
something three machines on a LAN can run.

### 0.1 Backfill sync (INV / GET_BLOCK)

A node that joins late or misses a frame currently stalls forever. The
wire types already exist (`INV`, `GET_BLOCK`) — the listener just does
not serve them.

- [ ] `INV` advertisement: on every accepted (local or remote) block,
  broadcast a small inventory message (height + tip hash) instead of only
  pushing the full frame.
- [ ] `GET_BLOCK` serving: on request, stream the requested range from
  the ledger mapping via the existing zero-copy `send_block_zero_copy`
  path (bounded batch, e.g. 16 frames per request, rate-limited).
- [ ] Requester side: on gap detection (remote tip height > local
  height+1), request and apply backfill frames one tip-extension at a
  time.
- [ ] Test: 4-node net where node D joins 5 blocks late and catches up
  without a snapshot; add to `scripts/multi_node_test.sh`.
- Acceptance: stale joiner converges without snapshot; repeated
  `GET_BLOCK` from one peer cannot starve the listener (per-connection
  budget).

### 0.2 Wire-level fork choice

Competing blocks at the same height are each kept by their own node.

- [ ] Track a candidate header set keyed by (height, hash) with the
  peer's reported cumulative PoGW.
- [ ] On seeing a heavier competing tip, request the branch and replay
  the existing rollback machinery (`UndoEngine` rollback + resync) that
  the in-process split-brain simulation already exercises.
- [ ] Test: two nodes mine divergent tips over real sockets (reuse the
  simulation's deterministic miner), heal over the wire, converge.
- Acceptance: the live split-brain scenario no longer needs the
  in-process shortcut; update the runbook's limits section honestly.

### 0.3 Configurable bind address

`bind_p2p_listener` hardcodes `INADDR_LOOPBACK`.

- [ ] `--bind ADDR` flag (default loopback, `0.0.0.0` opt-in), same for
  the RPC `--port` binding.
- [ ] Document that 0.0.0.0 on the RPC is dangerous without auth (see
  0.4).
- Acceptance: two machines on a LAN sync; loopback behavior unchanged by
  default.

### 0.4 Peer authentication handshake

Promoted peers carry `node_id: 0` and nothing proves who they are.

- [ ] Handshake v1: HELLO message carrying a static node identity (hash
  of the node's long-term PQ public key) + a Sponge-based challenge/
  response bound to the session nonces already in the wire header.
- [ ] Optional allowlist/pin mode for private nets; reputation integration
  with the existing DoS-score path.
- Acceptance: an unauthenticated peer can still connect in open mode, but
  `/api/swarm/peers` shows verified identity where present; a forged
  identity fails the challenge.

### 0.5 Transaction relay over the wire (Dandelion, real)

`TX_COCOON_112B` exists; cocoon relay today runs per-node as a demo.

- [ ] Wire the mempool ingest path to accept sealed cocoons from peers,
  run the TDI gate + hop countdown, and re-seal forward (stem phase) or
  broadcast (fluff phase).
- [ ] Local transfer path seals into a cocoon and pushes to the stem peer
  instead of mining instantly (the RPC demo path stays as is).
- Acceptance: a transfer submitted on node B appears in node A's
  mempool/next block without a direct RPC call; Dandelion counters on
  both nodes move for real traffic.

### 0.6 PoGW verification on wire frames

Largely closed 2026-11-03 together with 0.9: the intake gate verifies the
PoGW nonce (full-frame VortexSponge256, leading zero bits >= the store's
required difficulty) BEFORE `apply_block` on every path, including P2P
wire frames (`apply_remote_frame` → `append_block` → gate). The
`fuzz_block_frame` target now covers the combined verify surface.

- [x] Verify the block's PoGW nonce/attractor commitment against the
  current difficulty before `apply_block` (difficulty-0 attractor
  re-execution beyond the nonce target remains future work).
- [x] Fuzz target for the combined wire→verify→apply path (gate surface
  in `fuzz_block_frame`; 190k+ runs clean).
- Acceptance: met — `NoWorkBlockAccepted` flipped to EXPECT_FALSE, a
  crafted tip-extending frame without valid PoGW is rejected before
  touching the ledger (`PogwGateAcceptsSealedWorkAndBindsTheNonce`).
- Remaining: validator-authenticated PoGW/attractor commitment
  (BACKLOG 0.4/2.4), dynamic retarget in the gate (see 0.9).

### 0.7 Transaction authorization (keyless tier must go)

Pinned reproducibly by `VortexDocumentedGapsTest.KeylessTheftReproducible`
(expect: the theft SUCCEEDS today). `verify_transaction_proof` accepts a
plain sponge digest for any sender not registered as a PQ sender — and a
digest requires no key, so an attacker holding nothing can move funds
from any non-PQ-bound address (external review demonstrated 1 VX out of
the genesis receiver; re-confirmed at current main).

- [ ] Bind addresses to PQ public keys in consensus state (genesis
  allocation + on-chain registration path).
- [ ] Reject any non-PQ-bound sender's transfer on the consensus path
  (remove the keyless Tier 2 fallback from acceptance).
- [ ] The demo RPC must not sign on the user's behalf.
- Acceptance: the pin test flips to EXPECT_FALSE; a forged transfer is
  rejected by ledger rules with a specific error.

### 0.8 PQ witness on the wire (consensus-visible signatures)

`PqSignatureWitness` (2376 B) lives only in the in-process
`PqWitnessRegistry`: another node — or the same node after a restart —
cannot verify a PQ-signed transaction (external review, confirmed).

- [ ] Canonical wire/storage encoding for the witness; block or tx
  carries the witness its verification needs.
- [ ] Sender's XMSS root committed in block data; rules for accepting a
  new sender key.
- Acceptance: node A verifies node B's PQ-signed tx without shared
  process state; restart does not orphan a witnessed chain.

### 0.9 Central block validation (single intake gate)

CLOSED 2026-11-03. One gate (`blockchain::validate_block` + the
`pogw_meets_target` work comparator) now runs on every production intake
path: `BlockStore::append_block` is the single chokepoint — the RPC
transfer/mine path, `apply_remote_frame` (P2P relay) and the background
miner all append through it — and the restart/recovery path re-validates
every stored frame (magic, height, tx_count, merkle) in
`validate_region`. The pin test `NoWorkBlockAccepted` is flipped to
EXPECT_FALSE (an otherwise-valid frame with no PoGW nonce is rejected
with "insufficient PoGW work for the current difficulty"); new tests:
`PogwGateAcceptsSealedWorkAndBindsTheNonce`, `RecoveryRejectsCorruptedLedgerFrame`.
`fuzz_block_frame` drives the gate surface (merkle, timestamp, work
comparator) — 190k+ runs clean.

- [x] One `validate_block()`: magic, height/prev binding, tx count,
  merkle commitment, timestamp monotonicity + future bound, PoGW vs
  difficulty. (State rules stay in `LedgerState::apply_block` by design —
  the store gate rejects invalid frames before any state is touched, and
  the ledger layer remains the defense-in-depth for state validity.)
- [x] Called on ALL intake paths: RPC accept, P2P relay, miner, disk
  write, restart recovery.
- [x] Every block producer seals through `seal_pogw_nonce` — the RPC
  transfer path and the demo now carry real work (~8 s per block at
  dev-mode difficulty 16; ~120 µs per 64 KiB hash).
- Remaining (design-scale, still BACKLOG 0.6): dynamic ASERT retargeting
  wired into the gate (today the gate enforces the store's configured
  difficulty; the miner aims at max(ASERT, gate) so it can never aim
  below the gate), and per-tx proof checks at the block level (each tx
  proof is verified by the ledger on apply).

### 0.10 RPC server hardening

External review (confirmed): `INADDR_ANY` listener, thread-per-connection
(detached), single 8 KiB `recv()` per request, no auth.

- [ ] Bounded thread pool or connection cap; per-connection timeouts.
- [ ] Complete request reads (loop until full header/body or cap).
- [ ] Auth for state-changing endpoints (loopback default; token opt-in).
- [ ] Thread lifecycle: detached HTTP/SSE workers are not tracked or
  joined by `stop()`; a server teardown can race live workers. Replace
  detached threads with tracked workers and join them in `stop()`.
  (The SSE accept/EOF leak itself is fixed — round 5: handshake drained,
  poll-based wait — but the detached-thread model remains.)
- [ ] Demo key material out of the production RPC: `/api/crypto/canonical`
  returns its test-vector private keys, and `/api/crypto/pq_sign` derives
  from a public demo seed. Move fixtures to files, compile demo signers
  out of production builds (external review round 5, finding 18).
- Acceptance: a slow/garbage client cannot stall or exhaust the server;
  state-changing calls fail closed without credentials; `stop()` leaves
  zero live worker threads; no build reachable from the internet serves
  a private key.

### 0.11 Undo journal serialization (no raw pointers on disk)

External review (round 4): `UndoRecord` contains `std::string`,
`std::vector` and `time_point` members, and the journal writes it with a
raw `write(fd, &record, sizeof(record))` — that serializes heap POINTERS,
not payloads. On replay the reconstructed record points at freed/garbage
memory; the journal is corrupt-by-design the moment it holds a
non-trivial member.

- [ ] Versioned, fixed-width record format: length-prefixed payload
  fields written byte-wise (no `sizeof(struct)` writes), a format version
  in the header, and a reader that refuses unknown versions.
- [ ] Reject-or-migrate on open: a journal whose version/magic does not
  match is rebuilt from the ledger, never replayed.
- [ ] Fuzz target: journal bytes -> replay; invariant: no crash, no
  pointer-looking field is ever dereferenced.
- Acceptance: the replay path touches only plain bytes; ASan lane runs a
  rollback-over-poisoned-journal case clean.

### 0.12 Reorg undo correctness (journal the displaced block, restore nonces)

External review (round 4): `rollback_to_height` reads the block at the
rollback height from the store BEFORE the truncation append, so the
displaced block's own frame is what gets re-journaled (or lost) depending
on ordering; and `UndoTransaction` restores balances but not sender
nonces, so a reorg can desynchronize nonce accounting (replayed or
permanently gapped senders).

- [ ] Journal the DISPLACED block frames (read before truncate, write
  before rollback), so a rollback is replayable in both directions.
- [ ] Snapshot/restore `next_nonce` per sender inside `UndoTransaction`
  alongside balances.
- [ ] Test: reorg across a block whose txs advanced nonces, then
  re-apply the same txs; nonces and balances must both converge.
- Acceptance: rollback + re-apply is byte-identical to a fresh apply.

### 0.13 GQC checkpoint persistence (RAM-only finalized_height_)

External review (round 4): `finalized_height_` lives only in RAM. After a
restart the node forgets what was cemented and `rollback_to_height` may
cross a previously finalized checkpoint — the "absolute defence" against
deep reorgs evaporates on reboot.

- [ ] Persist the finalized checkpoint (block tail stamp already exists;
  add a small side-file or scan-back on open: highest height whose tail
  aggregate verifies against the share-derived recomputation).
- [ ] `lock_finalized_height` on open must never report a height lower
  than the persisted one (fail-closed, monotonic).
- Acceptance: restart test — finalize block N, restart, rollback to N-1
  is refused.

### 0.14 Mempool per-sender nonce ordering + publication race

External review (round 4): (a) the global fee sort in `pull_for_sealing`
can order a sender's nonce-1 tx before its nonce-0 tx — the block then
fails apply and (post-fix) the miner drops it with txs retained;
repeatable livelock under load. (b) `count_` is bumped by CAS before the
entry is written into the map; a concurrent reader can observe count
including a not-yet-written entry (reads a default Transaction).

- [ ] Order pulled txs per sender by nonce (topological by sender), not
  only by global fee.
- [ ] Publish entries before bumping `count_` (or use a generation/
  seqlock so readers skip incomplete slots).
- Acceptance: stress test — N senders x M out-of-order submissions, all
  sealed blocks apply on first attempt; concurrent reader never observes
  an unwritten entry.

---

## P1 — harden what ships

### 1.1 RPC input fuzzing (shipped)

- [x] Public `HttpServer::route(const HttpRequest&)` entry with a
  defensive catch-all (a hostile body now answers 500 instead of
  unwinding a detached worker thread).
- [x] `fuzz/fuzz_rpc.cpp`: byte stream → method/path-from-real-routes/body
  → route; invariants: no crash, no hang, GET does not mutate the tip,
  accepted transfers bounded by chain height.
- [x] Body size cap for the fuzzer (4 KiB); fixed seed in CI
  (`-runs=200000`).
- [x] Fixed: unguarded `std::stod` on the transfer amount string form and
  the dust_spam_tdi audit amount (`std::out_of_range` on oversized
  numerals).
- Remaining suspects from the handler review: per-handler `extract`
  lambdas duplicating parsing (consolidation candidate, not a defect).

### 1.2 Constant-time audit of hot paths

The whitepaper-grade concern: data-dependent branches in cryptographic
hot paths (`if (shift == 0)` in rotations, key equality checks, the TDI
gate).

- [ ] Inventory every branch on secret-dependent data in
  `src/crypto/`, `src/math/`, the PQ verify path, and the vault.
- [ ] Replace with branchless forms where the value is secret-derived
  (`rotl` by `shift & 63` arithmetic, constant-time memcmp for digest
  compares).
- [ ] Document what remains and why (e.g. structural checks on public
  data do not need it).
- Acceptance: written audit table in `docs/design/constant-time.md`;
  no secret-dependent branches left outside documented exceptions.

### 1.3 Differential / linear cryptanalysis batteries

Complement the SAC avalanche matrix with classic statistical attacks on
VortexSponge256 and the attractor round function.

- [ ] Differential: fix input differences, count output difference
  distributions over millions of pairs; look for biases above 2^-16.
- [ ] Linear: masked-bit correlation table per round.
- [ ] Automated job producing a report artifact; thresholds documented.
- Acceptance: no exploitable bias found, or one found and fixed — either
  way the report is public.

### 1.5 XMSS tree rollover (gated today)

`pq_sign_transaction` refuses any nonce above 15 (subtree guard, external
review finding): the published root covers exactly the first 16-leaf
tree, and a nonce above 15 would derive the secret WOTS leaf from a
subtree the root does not span — an unverifiable signature that still
burns a ledger leaf. Refusal is fail-closed; TEST 9 pins it
(nonces 0/15 sign+verify; 16/17/255/UINT32_MAX refuse, zero burns).

- [ ] Design tree rollover (XMSS multi-tree: top tree over subtree roots,
  per-subtree roots published with the witness).
- [ ] Re-test witness size and verification cost at the target height.

---

### 1.4 MemoryVault hardening round 2

- [ ] TSan CI lane (the swarm threading grew: listener + per-connection
  handlers + per-peer readers).
- [ ] Guard pages around locked regions; verify mlock failure semantics
  on hosts with low `rlimit_memlock` (document the fallback loudly).
- Acceptance: TSan clean in CI; fallback path tested with a low rlimit.

---

## P2 — protocol completeness

### 2.1 Security reduction write-up (ROADMAP mid-term item 3)

The public answer every cryptographer will ask: what is the hardness
claim, stated precisely.

- [ ] Formalize the attractor as a rational map over GF(p) with XOR/bit
  rotation mixing; state what problem breaking it reduces to (MQ-family
  argument) and, equally important, what is *not* proven.
- [ ] Gröbner-basis section: why the algebraic structure is deliberately
  polluted (XOR + per-round rotation), with estimated polynomial-degree
  blowup numbers instead of hand-waving.
- [ ] Timing-attack section: reference the constant-time audit (1.2).
- [ ] Honest disclaimer: custom sponge = no security reduction to a
  textbook problem; that is exactly why the independent review item
  exists and why the PQ layer (hash-based, standard) carries the
  signature security alone.
- Acceptance: `docs/design/security-model.md`; every claim either
  proven, measured, or explicitly marked as assumption.

### 2.2 Independent cryptographic review (ROADMAP mid-term item 3)

Priority order per ROADMAP: VortexSponge256 → WOTS+/XMSS wiring and key
lifecycle → attractor collision behavior.

- [ ] Package: whitepaper + design docs (from Phase-3 distillation) +
  test vector bundle + negative-vector matrices as a review kit.
- [ ] Identify 2-3 candidate reviewers/labs; budget and timeline.
- Acceptance: review commissioned; findings tracked here.

### 2.3 Formal collision analysis of address derivation (ROADMAP item 5)

- [ ] Model the 18-bit prefix drop in the NFA payload; compute birthday
  bounds for realistic account counts.
- [ ] Prove/disprove the phantom-key argument (ghost collisions) with
  experiments against the derivation function.
- Acceptance: whitepaper §update with numbers, not adjectives.

### 2.4 GQC validator-set formation (ROADMAP item 6)

- [ ] Economics: admission, stake weighting, slash conditions.
- [ ] Wire: GQC_VOTE message type exists — define the vote format and
  finality aggregation over VX60.
- Acceptance: design doc + simulation before any testnet role.

### 2.5 Tokenomics & PoGW economics (testnet prerequisite)

- [ ] Emission schedule already partly encoded (miner reward constants);
  write the full spec: supply curve, fee market, dust thresholds.
- [ ] Simulate: reward pressure vs. TDI-filtered spam economics.
- Acceptance: `docs/design/tokenomics.md`; parameters land in genesis
  config, not scattered constants.

---

## P3 — expansion

### 3.1 GPU engine (CUDA path)

The NFA dual-engine address miner and the PTX ingestion pipeline live
outside this repo by design (build tools are not consensus code).

- [ ] Define the wire-level contract: what a GPU miner submits (PoGW
  nonce + attractor commitment) and how a CPU node verifies it cheaply.
- [ ] Publish the CUDA kernels in a sibling repository with their own
  benchmarks and reproducible test vectors.
- Acceptance: a CPU-only node and a GPU-assisted node interoperate in the
  testnet script.

### 3.2 Wallet stack

- [ ] WIF matrix export/import against the 7-tier key matrix; watch-only
  wallets via IVK; recovery flow via MSRK shards.
- Acceptance: wallet round-trips in the test suite; the cookbook gains a
  wallet chapter.

### 3.3 Community & launch mechanics

- [ ] Promo posts (Tue-Thu, 08:00-11:00 Eastern): the Challenge, the
  negative-vector matrix, the live 3-node testnet.
- [ ] Reproducible-build guide (the manual-compile security stance);
  document compiler pinning.
- [ ] License review: AGPLv3 + explicit no-warranty; consider whether any
  additional clause is enforceable and worth it (honest legal note, not
  bravado).

---

## Explicitly not promised (unchanged)

- Privacy of amounts on the transparent ledger (decoys are structural
  obfuscation, not cryptography; zk-cocoon privacy is a separate research
  track, not a shipped claim).
- Mainnet: gated on the independent review (2.2) and collision analysis
  (2.3), whatever the calendar says.
- Any utility/binary that exists outside this repository.

## Working rules for every item above

- Tests first or with the change; sanitizers stay green; new fuzz targets
  where a parser is touched.
- Docs carry live-captured outputs only — nothing "should look like".
- ASCII-only, no absolute paths, no machine-specific content.
- GPG-signed commits, no attribution trailers, push on explicit command
  only.
