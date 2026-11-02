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

Wire-applied frames are checked structurally and by ledger rules, not
re-mined.

- [ ] Verify the block's PoGW nonce/attractor commitment against the
  current difficulty before `apply_block`.
- [ ] Fuzz target for the combined wire→verify→apply path.
- Acceptance: a crafted tip-extending frame without valid PoGW is
  rejected before touching the ledger; test in the suite.

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
