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
- [x] Coinbase emission binding (closed 2026-11-03): the `MINER_` coinbase
  is bound to its chain position — its `cocoon_proof` must equal
  `trunc12(Sponge("VX_COINBASE_BIND_V1" || receiver || height ||
  prev_tip_hash))`, checked in `apply_block`. The keyless digest no longer
  authorizes emissions, and a coinbase copied from one fork cannot be
  replayed on a competing fork at the same height. Emission is now bounded
  by: one coinbase per block (index 0), the 1000 VX reward cap, real PoGW
  work on the block, and the chain-position binding. Pin flipped:
  `MinerEmissionForgeable` -> `CoinbaseReplayRejected`. What remains is
  permissionless by design: the block producer names the reward address.
- Remaining: validator-authenticated PoGW/attractor commitment
  (BACKLOG 0.4/2.4), dynamic retarget in the gate (see 0.9).

### 0.7 Transaction authorization (keyless tier must go)

CLOSED 2026-11-03. Addresses are now bound to post-quantum keys and the
keyless Tier-2 digest is removed from consensus acceptance. The pin test
is flipped and renamed: `KeylessTheftRejected` (was
`KeylessTheftReproducible`) — the reviewer's theft PoC (1 VX out of the
genesis receiver, zero secrets) no longer moves anything.

Binding model — two sources, no trusted registration table:

1. **Self-certifying addresses** (`blockchain::derive_pq_address`): a
   user address payload is `"PQA"` + 39 base64url characters of
   `Sponge("VXPQADDRV1" || pq_pubkey_root)`. Holding the XMSS key IS
   holding the address; the first witnessed spend binds the address to
   the key in ledger state, and every later spend is checked against
   that binding (`SelfCertifyingAddressAutoBinds`).
2. **Protocol seed table** (`genesis.hpp pq_seed_bindings()`): genesis-era
   allocations are bound at ledger construction — the canonical genesis
   receiver to an OFFLINE root (`"VX_PQ_GENESIS_OFFLINE_ROOT_V1"`; the
   secret is not in the repo, the faucet is locked), and the two demo
   addresses (spender → the public documented demo key
   `"VX_DEMO_SPENDER_SK_V1"`; receiver → an offline root). Genesis frame
   and hash are UNCHANGED — bindings are state-seed constants.

Enforcement (`LedgerState::apply_block`): system senders (`GENESIS*`,
`MINER_`) keep the structural integrity digest guarded by the mint /
coinbase rules; every USER sender must carry a valid `PqSignatureWitness`
(lookup by `tx_msg_digest`, root binding check, full WOTS+/XMSS +
SegPQ-anchor verification). Unbound senders, wrong-key witnesses and
non-self-certifying addresses are refused with specific errors
(`KeylessTheftRejected`, `UnboundSenderRejected`,
`WitnessRootMismatchRejected`).

The demo RPC no longer signs on the user's behalf: `/transfer` requires
`witness_b64` (the 2376-byte witness, base64), `fee_atoms` and `nonce`
from the client; the server rebuilds the tx anchor from the witness
(`pq_set_transaction_anchor`) and stamps nothing into the signed
material.

- [x] Bind addresses to PQ public keys in consensus state (self-
  certifying addresses + protocol seed table; no on-chain registration
  tx needed).
- [x] Reject any non-PQ-bound sender's transfer on the consensus path
  (keyless Tier 2 removed from acceptance; kept as admission pre-filter
  only, and for the guarded system senders).
- [x] The demo RPC must not sign on the user's behalf.
- Acceptance: met — the pin test flipped; forged transfers are rejected
  with specific errors before any balance is touched.
- Remaining (documented, not hidden): root rotation (rebinding an
  address to a new key) is refused for now — a stolen root cannot be
  rotated away yet; the 16-leaf XMSS tree per key means a key is
  exhausted after 16 spends (rollover = new self-certifying address);
  the mempool still admits by the legacy pre-filter (the ledger stays
  the consensus authority; admission divergence is pre-filtered, not
  consensus-visible).

### 0.8 PQ witness on the wire (consensus-visible signatures)

CLOSED 2026-11-03. The 2376-byte `PqSignatureWitness` now travels between
nodes and persists across restarts; the XMSS root is committed by the
witness itself and checked against the sender's binding.

- **Wire**: `WireMsgType::PQ_WITNESS` (0x09), payload = msg_digest(32) +
  sender(42) + witness(2376) = 2450 B. Witnesses are broadcast BEFORE the
  block that carries their transactions (`broadcast_witnesses_for`, called
  ahead of `broadcast_frame` on both the transfer/mine path and P2P
  relay) — a peer that receives a block without its witnesses could not
  authorize the transactions. Receivers register into
  `PqWitnessRegistry::register_witness_bytes`. The 64 KiB frame itself is
  untouched (it has no free bytes — witnesses never travel inside it).
- **Storage**: durable sidecar `<ledger>.pqw` — append-only records
  `"VXPQWT1"` + digest(32) + sender(42) + witness(2376) = 2458 B, written
  and fsync'd on every registration; `attach_durable_log` replays full
  records on startup and stops at the first short/corrupt record
  (fail-closed). `WitnessDurableLogSurvivesRestart` pins the round-trip.
- **Key acceptance rule**: a new sender key is accepted only through a
  self-certifying address — the witness root must DERIVE the sender
  address (`Sponge("VXPQADDRV1" || root)` committed by the address
  itself), after which the binding is enforced in ledger state.
- Acceptance: met — node A verifies node B's PQ-signed tx from the wire
  (digest-keyed registry filled by the PQ_WITNESS messages that precede
  the block); restart does not orphan a witnessed chain.
- Remaining: witness GC (the registry and sidecar grow with every
  registration; pruning policy is future work); no replay-window
  commitment yet — an old witness re-registered for a nonce that was
  already consumed is rejected by the nonce rule, not by the registry.

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

- [x] Complete request reads (loop until full header/body or cap).
  DONE 2026-11-03 (round 8, self-review): `parse_request` now reads until
  the declared Content-Length is satisfied (64 KiB request cap) — a
  ~3.2 KB witness body arriving split across TCP segments is no longer
  truncated; the JSON field scanner tolerates whitespace after `:`, so
  standard serializers no longer get a misleading "witness required"
  error. Still open below: pool/cap, timeouts, auth, tracked threads.
- [ ] Bounded thread pool or connection cap; per-connection timeouts.
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

- [x] Versioned, fixed-width record format: length-prefixed payload
  fields written byte-wise (no `sizeof(struct)` writes), a format version
  in the header, and a reader that refuses unknown versions.
  (2026-11-03) The journal is now magic `VXUNDOJL` + u32 version, then
  fixed-width little-endian records — u64 height, i64 timestamp_ns,
  32 B prev tip hash, 16 B prev supply, u64 accounts, u64 tx_count, then
  per transaction 42+42 B addresses and 16+16 B amount/fee — every field
  byte-wise, partial writes handled, fsync on append and rewrite. The
  replay path touches only plain bytes.
- [x] Reject-or-migrate on open: a journal whose version/magic does not
  match is rebuilt from the ledger, never replayed. (2026-11-03) Wrong
  magic or version (including every pre-0.11 raw-pointer file) -> file
  discarded, journal rebuilds from live block application. Mid-file
  corruption (>= one minimal record of garbage) -> discarded; a short or
  torn tail (fewer bytes than a minimal record) is healed by truncating
  to the last complete record. Two adjacent bugs closed the same day: a
  reloaded journal was re-committed wholesale (duplicating every record,
  so a later rollback reversed each effect twice — fixed with a
  committed-baseline offset), and a block the ledger refused left its
  pre-state journal record behind (new `UndoEngine::drop_last_record()`,
  wired into the swarm resync path).
- [x] Fuzz target: journal bytes -> replay; invariant: no crash, no
  pointer-looking field is ever dereferenced. (2026-11-03)
  `fuzz_undo_journal` (journal bytes -> parse -> rollback -> reload;
  200k execs over a hostile/valid seed corpus, 0 crashes). ASan acceptance:
  `UndoJournalRejectsHostileFiles` rolls back over pointer-shaped poison
  clean.
  Regressions: `UndoJournalByteFormatRoundTrip`,
  `UndoJournalRejectsHostileFiles`.
  Honest remainder for 0.13: the in-memory journal now retains records
  after commit (rollback must keep working post-commit), so journal
  pruning below the GQC checkpoint belongs to 0.13.
- Acceptance: the replay path touches only plain bytes; ASan lane runs a
  rollback-over-poisoned-journal case clean.

### 0.12 Reorg undo correctness (journal the displaced block, restore nonces) — CLOSED 2026-11-03

External review (round 4): `rollback_to_height` reads the block at the
rollback height from the store BEFORE the truncation append, so the
displaced block's own frame is what gets re-journaled (or lost) depending
on ordering; and `UndoTransaction` restores balances but not sender
nonces, so a reorg can desynchronize nonce accounting (replayed or
permanently gapped senders).

- [x] The journal records transactions FROM THE FRAME BEING APPLIED, not
  from the store: the resync path journals before the store append, so
  reading the store at that height captured the DISPLACED block's
  transactions — the rollback then reversed effects that never happened
  on this fork. The pre-state tip now comes from the block's own
  prev_hash, so journaling is ordering-independent.
- [x] Journal the DISPLACED block frames: `rollback_to_height` preserves
  every block above the target in the side journal `undo/displaced.vxd`
  ("VXDISPLC", byte-format records `u64 height | u32 len | frame`, same
  fail-closed policy as the undo journal — foreign magic or a torn record
  yields nothing, 64 MiB cap) BEFORE any state is mutated, so a reorg is
  replayable in both directions (`load_displaced_frames()` reads them
  back, tested byte-exact).
- [x] Snapshot/restore sender nonces: every undo transaction carries the
  sender's pre-block next-nonce (journal format version 2); rollback
  restores it newest-first, so the oldest pre-fork snapshot wins for
  senders that spent in several rolled-back blocks. Coinbase senders are
  not recorded (they never take part in nonce accounting).
- [x] Restore tracked-account state: addresses a rolled-back fork
  CREATED (untracked before the block, tracked after) are journaled in a
  created-address list and erased by the rollback once their reversed
  balance is zero (`LedgerState::forget_empty_address`). Found by the
  regression below: without this, re-applying a height-1 GENESIS_2 mint
  after a rollback is refused forever ("receiver already tracked") — the
  reorg would brick the node.
- [x] Test: `ReorgUndoRestoresNoncesAndFrames` — reorg across a fork
  (a GENESIS_2 mint, then a block with TWO spends from one sender — the
  intra-block sequential-nonce path), journaled in the resync ordering;
  rollback to genesis preserves the displaced frames byte-exact and
  restores balances, nonces AND the tracked-account set; re-applying the
  same frames lands byte-identical to a fresh apply (total supply, issued
  supply, balances, sender nonce, account count); a replayed nonce is
  still refused afterwards.
- Acceptance: rollback + re-apply is byte-identical to a fresh apply.
- Honest remainder: journal pruning below the GQC checkpoint belongs to
  0.13 (with checkpoint persistence); `load_displaced_frames()` exists
  and is tested, the re-attach consumer ships with the deeper net stack.

### 0.13 GQC checkpoint persistence (RAM-only finalized_height_) — CLOSED 2026-11-03

External review (round 4): `finalized_height_` lives only in RAM. After a
restart the node forgets what was cemented and `rollback_to_height` may
cross a previously finalized checkpoint — the "absolute defence" against
deep reorgs evaporates on reboot.

- [x] Persist the finalized checkpoint: the `<ledger>.gqc` sidecar stamp
  already existed (round 5); what was missing is the restore. On open the
  undo engine now scans the sidecar (`BlockStore::highest_gqc_stamp`) and
  re-cements the highest stamped height; `GqcFinality` seeds its reported
  height from the same restored guard, so `/api/consensus/
  finality_status` tells the truth after a restart too.
- [x] `lock_finalized_height` on open never reports a height lower than
  the persisted one: the restore is monotonic (a lower value cannot lower
  the guard) and the sidecar scan is fail-closed — a corrupt record means
  nothing is restored and `finalized_sidecar_trusted()` reports false (no
  fabricated checkpoint); a torn tail (a crash mid-stamp) is healed by
  truncation to the last complete record, like the undo journal.
- [x] Test: `GqcCheckpointSurvivesRestart` — certify block N, "restart"
  (fresh ledger + fresh undo engine over the same store), the guard
  reports N again, `lock_finalized_height(0)` cannot lower it, rollback
  to N-1 is refused with `ERR_FINALIZED_BY_GQC`; a corrupt sidecar is
  reported untrusted and fabricates nothing.
- Acceptance: restart test — finalize block N, restart, rollback to N-1
  refused. Met.
- Honest remainder: a corrupt sidecar is not rebuilt automatically (the
  stamps are re-written by re-certification; until then the guard
  protects only what the running process cemented). Verifying a restored
  stamp against the share-derived recomputation on open belongs to the
  validator-authentication cycle (BACKLOG 0.4 / 2.4), since shares
  currently derive from public data.

### 0.14 Mempool per-sender nonce ordering + publication race (CLOSED 2026-11-03)

External review (round 4): (a) the global fee sort in `pull_for_sealing`
can order a sender's nonce-1 tx before its nonce-0 tx — the block then
fails apply and (post-fix) the miner drops it with txs retained;
repeatable livelock under load. (b) `count_` is bumped by CAS before the
entry is written into the map; a concurrent reader can observe count
including a not-yet-written entry (reads a default Transaction).

- [x] Order pulled txs per sender by nonce: `pull_for_sealing` now
  snapshots the pool under the mutex, groups it into per-sender chains
  (admission keeps each sender's nonces contiguous), sorts each chain
  ascending by nonce, and emits via a deterministic k-way merge — the
  chain whose head tx has the best fee density wins the next slot. The
  comparator uses exact priority comparison (the old epsilon tie-break
  was not a strict weak ordering — the classic std::sort UB pattern)
  with canonical byte tie-breaks.
- [x] Publish entries before bumping `count_`: slot claim, entry write
  and count publication are all under the pool mutex now (`find_slot`'s
  CAS is gone). `stats()`, `pull_for_sealing` and `remove_sealed` hold
  the same mutex; `remove_sealed`'s invalidation + compaction + count
  update is one critical section (a concurrent submit used to be able
  to lose an accepted tx while its pending balance/nonce stayed
  reserved). `count()`/`empty()` stay lock-free approximate hints; the
  dead `version_` counter and unused `validate_pending` wrapper are
  removed.
- Acceptance: stress test — N senders x M out-of-order submissions, all
  sealed blocks apply on first attempt; concurrent reader never observes
  an unwritten entry.
  **Met.** `SealedBatchesApplyOnFirstAttempt` (5 senders x 20 txs, pull
  in partial batches, replay against per-sender nonce gates — every tx
  applies first try) and `ConcurrentSubmitsAndSealsStayConsistent`
  (8 submitter threads racing a sealing reader + concurrent `stats()`;
  every pulled tx matches a submitted tx — no torn/unwritten slot — and
  every batch keeps each sender's chain contiguous from the previously
  sealed prefix). ThreadSanitizer build (GCC, separate build lane): the
  mempool suite is race-free across 6 runs, 0 TSan warnings.
  Remnants: none in scope — the pool-side DoS caps (one sender flooding
  the whole pool) belong to the fee-market spec (BACKLOG 2.5), the
  admission wiring (nothing feeds `submit()` from the network stack yet)
  is part of the swarm-intake work.

### 0.17 Electron renderer stays sandboxed (delivered 2026-11-04) — residual: SSE relay

CodeQL flagged `webSecurity: false` (Medium) and `allowRunningInsecureContent: true`
(High) in `web/electron/main.cjs`. Both removed: the renderer keeps the
same-origin policy; cross-origin RPC to a user-selected node now runs in the
main process over an IPC bridge (`vx:rpc`, GET/POST of JSON bodies only,
redirects refused, 30 s abort). SSE (`/api/events`) is skipped under Electron
when the RPC host is cross-origin — the 10 s polling refresh covers push
reactions. Review follow-ups folded in: the bridge handler registers once at
`app.whenReady` (a second registration from macOS re-activation would throw),
the bridge allowlists method GET|POST and only Accept/Content-Type headers —
undici has no Chromium-style forbidden-header list, so without the allowlist a
compromised renderer could forge Cookie/Host/Content-Length — and 204/205/304
responses reconstruct with a null body (the Response constructor throws
otherwise). Residual: a proper SSE-over-IPC relay in the main process so
push immediacy returns to the desktop client without re-opening the renderer.

### 0.16 GQC sidecar v2 (delivered 2026-11-04) — residual hardening

The v2 record (52 B, CRC32C over height+aggregate) closes the
height-byte-flip inflation hole found by crash torture. Zero-trust review
left three documented residuals, none exploitable under the stated
adversary (single-byte-flip / torn-write; no arbitrary file write):

- [ ] The CRC is unkeyed: it defends against accidental corruption and
  torn writes only. An adversary with arbitrary write access to the
  sidecar can recompute it — the finality guard stays advisory by design
  (consensus never derives from it; the guard is a self-imposed brake).
  If the sidecar ever becomes consensus-load-bearing, upgrade to a
  keyed MAC over the whole record.
- [ ] Mixed RT1/RT2 files fail closed forever (loud stderr, operator
  action required). A friendlier auto-resolution (preserve intact v2
  records, re-stamp the rest) was deliberately NOT built: silent healing
  of a certification store is the unsafe direction.
- [ ] Migration validates every legacy block (tag == VXGQCRT1 and
  height < chain_height) before blessing it with a CRC — the one-time
  bootstrap trusts strictly less than a v1 writer could have produced.

### 0.15 Post-quantum margin: parameterized sponge width (standing principle 2026-11-04)

Owner's standing principle: the margin must be such that even an ideal
quantum computer running Grover's algorithm hits the same wall a
classical computer hits today. Grover's square root halves the exponent:
a 256-bit preimage costs 2^128 quantum operations (the NIST baseline
floor, badly parallelizable), a 512-bit preimage costs 2^256 — the
same wall classical 256-bit work is today. The VX sponge is a custom
construction, so Grover optimality is only a LOWER bound on attacker
power there; width is the insurance against our own assumptions.

- [ ] Parameterize the sponge output width (256/512/1024) behind an
  address version: v1 = 256 (current, frozen wire), v2 = 512 (the
  standing target), 1024 documented as the paranoid maximum (no
  standard requires deeper than a 2^256 preimage class).
- [ ] Extend the wire frame and address derivation for v2 with a soft
  migration (both versions verified in parallel; v1 never invalidated).
- [ ] Fold into the same work: PQ key rollover (a key signs at most 16
  times today — XMSS H=4 leaves 0..15, `pq_sign_transaction` refuses
  nonce >= 16; three independent test waves hit this on 2026-11-04).
  Rollover derives tree #N from the same master seed deterministically
  and publishes a fresh root per binding, so one key never dies after
  16 transfers; the leaf discipline (nonce counter, no double-sign)
  must stay consensus-visible.
- [ ] Retarget parameter lock (found by the 2026-11-04 ASERT review,
  F2): the ASERT anchor and half-life are code constants not covered by
  the genesis frame hash — "same genesis" enforces nothing about the
  curve. Commit a hash of the retarget params into the genesis domain
  and refuse non-default params outside test builds.
- [ ] Time-anchored retarget exponent (ASERT review F3): the current
  height-only curve is monotone forever — a work escalator with a
  finite lifetime (bounded producers deterministically fail above ~26
  bits). Honest eventual fix: exponent from (now - genesis_time) so the
  curve can go down as well as up.

### External review round 5 — ledger/rollback hardening (CLOSED 2026-11-03)

Adversarial review of the post-0.14 tree found two P1s and a set of
durability gaps; all code-side findings are fixed here (the process-level
ones are tracked below).

- [x] **P1 rollback phantom supply:** `rollback_to_height` reversed
  balances tx-by-tx with clamp-at-zero arithmetic — an address whose
  intra-block credit was reversed before its debit went negative mid
  loop, the debit then clamped to zero, and the shortfall was minted
  from nothing. Fixed with two-phase netting per undo record: phase A
  accumulates one reversal delta per address (credit vs debit kept
  separate), phase B applies the net exactly via a new unchecked
  `revert_balance_exact` that reports underflow instead of clamping;
  underflow means state/journal corruption and aborts the rollback with
  `ERR_UNDO_STATE_MISMATCH` (the journal erase now happens after the
  reversal so the records stay diagnosable). Burned supply is restored
  from the record's recomputed `floor(fees/2)` — no wire-format change.
- [x] **P1 unbounded mint:** the height-1 `GENESIS_2` mint was gated only
  by count — whoever mined block 1 could mint any amount to any receiver
  with a keyless digest and capture the remaining supply. The mint is
  now bound to its exact protocol shape: height 1, sender tag
  `GENESIS_2`, exactly 100,000 VX (`GENESIS_2_MINT_ATOMICS`) to the
  pinned demo-spender payload (`genesis2_mint_receiver_payload()`), an
  untracked receiver, one per block. The one-per-block count check runs
  BEFORE the shape check, so a second mint of any shape is caught by the
  count rule.
- [x] **P2 torn sidecar record:** `stamp_gqc` could leave a partial
  48-byte record mid-file after a short write; the reader cannot heal a
  torn middle, so every later restart failed closed and silently reset
  the finality guard. Writes are now a full EINTR-retrying loop plus
  fsync.
- [x] **P2 unfsynced rollback truncate:** `rollback_last_append` shrank
  the store without fsync — a power cut could resurrect the refused
  frame, the replay then throws and the node cannot start. The truncate
  is fsynced.
- [x] **P3 torn multi-tx journal tail:** a torn tail inside a multi-tx
  record was reported as corruption; the loader now probes the record's
  tx count and heals a tail that can no longer hold the remaining
  transactions (bounds-checked), else still fails closed.
- [x] **P2 journal coverage guard:** a rollback against a journal that
  does not cover the full rollback span is refused with
  `ERR_UNDO_JOURNAL_GAP` instead of silently leaving heights applied.
- Acceptance: the documented-gaps suite exercises the double-spend
  rollback netting (no phantom supply, no lost debit), the pinned mint
  shape (wrong amount/receiver/height refused, second mint in one block
  refused, mint-to-tracked-address refused) and the reorg round-trip
  against the pinned mint. 17/17 ctest on the GCC, sanitizer and fuzzer
  lanes.
- Honest remainder (not code bugs, tracked): mempool admission is not
  yet wired to the network stack and the pool has no per-sender eviction
  (swarm-intake work, fee-market spec 2.5); a half-applied block commit
  guard belongs to the atomic-commit work; the redundant finality-guard
  persistence source and the displaced-cap wording are doc cleanups.

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

- [x] Emission schedule hard-coded in consensus (2026-11-03,
  user-directed): `include/vx/blockchain/emission.hpp` — lifetime cap
  7,000,000,000 VX (7e17 atoms; the 7 is the protocol's signature digit).
  The per-block reward is a deterministic function of the block's own PoGW
  hash (the full-frame VortexSponge256 commitment the intake gate already
  checks): 50 VX guaranteed for every valid block, with bonus tiers at
  20/24/28/32/40 leading zero bits paying 75/100/200/400 and — for an
  exceptionally rare hash — the 1,000 VX jackpot. A miner cannot mint the
  bonus, only find a rarer hash, so a bigger reward is strictly more
  proof-of-work; the thresholds are absolute, so any node verifies the
  reward by recounting zeros in the hash it already computes. Cumulative
  issuance (all coinbase credits minus the fee share re-credited to the
  producer) is gated in `LedgerState::apply_block` before any state
  mutation, restored by the reorg undo, and reported by `/api/status`
  (`max_supply_vx`, `issued_supply_atomics`, `issuance_headroom_vx`,
  `block_reward_base_vx`, `block_reward_max_vx`, `reward_tier_count`).
  Genesis allocations count against the cap, so the final emission blocks
  mint exactly the remaining headroom.
  Regressions: `EmissionRewardTiersAndCap`,
  `CoinbaseEntitlementEnforced`, `SupplyCapHardStopsIssuance`,
  `RewardIndependentOfHeight`.
- [ ] Fee market spec: dust thresholds, minimum relay fee, reward
  pressure vs. TDI-filtered spam economics (simulate).
- Acceptance: `docs/design/tokenomics.md`; remaining parameters land in
  genesis config, not scattered constants.

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

### Zero-trust review discipline (standing rule, set 2026-11-03)

- Nothing is trusted on reputation. Doubt is the default posture: a
  component is unsafe until a test proves otherwise, and a review that
  finds nothing is never taken as proof of safety.
- Every diff that touches cryptography, consensus, the wire protocol,
  storage, money math or authorization MUST pass an adversarial
  security-review pass — a dedicated agent instructed to be harsh and
  total, hunting exploitable defects the way a CVE researcher would
  (attack surfaces, state-machine holes, arithmetic and concurrency
  edge cases, fail-open paths) — BEFORE the change is committed.
- Findings are fixed the same day for P0/P1; design-level findings are
  pinned in the BACKLOG with a documented rationale; every reviewer PoC
  becomes an automated regression test.
- No masking hacks: a finding is never silenced by hiding the symptom;
  the root cause is fixed or the limitation is documented honestly.
- The current stage adds: after each major work stage, a full-repo
  adversarial re-hunt runs before the next stage starts, so defects are
  found by us before anyone else finds them.
