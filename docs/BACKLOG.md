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
- Design decision (owner question, 2026-11-05): ASERT makes difficulty a
  pure function of height, so equal-height chains carry the SAME floor
  target and classical cumulative difficulty cannot discriminate. The
  honest weight metric is real proven work: W(chain) = sum over blocks
  of 2^(verified leading zero bits of the block hash) — the tier
  escalation (REWARD_TIER_ZEROS) is enforced against the block's own
  hash, so heavier-tier chains weigh more with no trusted field. Exact
  tie: lexicographically-lowest 32-byte tip hash (objective,
  effectively random, and ungameable — grinding it IS doing more PoGW).
  Attractor-phase tie-breakers (pseudoentropy, F_P/F_Q/F_R trajectory
  distance) are rejected for consensus until proven ungameable:
  attractor_coords is a miner-influenced header field.

### 0.3 Configurable bind address

`bind_p2p_listener` hardcodes `INADDR_LOOPBACK`.

- [ ] `--bind ADDR` flag (default loopback, `0.0.0.0` opt-in), same for
  the RPC `--port` binding.
- [ ] Document that 0.0.0.0 on the RPC is dangerous without auth (see
  0.10).
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

### 0.20 Crypto-math audit (2026-11-05) — delivered hardening + residuals

Full read-audit of the sponge, WOTS+/XMSS, TDI filter, ASERT retarget and
emission/fee law. Clean after hand re-derivation: the ASERT tie formula
(both parities), the saturation early-return (provably value-neutral), the
fee-split law (burned + miner_reward == total_fees identically, odd fees
included), the WOTS+ checksum barrier and XMSS auth-path walk, TDI boundary
arithmetic at 1,120,000 atoms. Delivered in the same wave: finalize
idempotence + absorb-after-finalize abort (sponge), constant-time digest
compares (vx/core/ct_equal.hpp), consensus lookup in Tier-1 witness
verification (admission censoring fix), structurally identical issuance
reversal in the undo engine (genesis-window under-claim no longer
over-reverses supply), sponge streaming-contract tests, domain-tag
prefix-freeness test, odd-half-life and clamp-boundary ASERT tests.
Residuals, each with its trigger condition:

- [ ] **Sponge pad does not encode length** (P2, latent): H(m) == H(m||0…0)
  for trailing zeros inside the final partial chunk. Safe today ONLY because
  every consensus preimage is fixed-length and domain-tagged (now enforced
  by a test). The 0.15 width work MUST ship a v2 sponge with
  length-encoded padding under a new tag — the digest of v1 is frozen by
  the immutable genesis frame.
- [ ] **WOTS+ leaf single-use is signer-side only** (P2): two valid
  witnesses under the same leaf for different messages let the holder walk
  the Winternitz chains and forge for that account at will. Consensus
  cannot see used leaves — the witness lives in a sidecar, not the block.
  Real fix is a wire-format change (consensus-visible leaf binding);
  track it with the 0.15 key-rollover work. Until then the 16-leaf cap,
  the durable PqLeafLedger and fail-closed defaults are the mitigation.
- [ ] **Under-claimed fee share is silently destroyed** (P3, deflationary):
  a coinbase carrying less than the miner's fee share forfeits the
  remainder (neither burned nor credited). Not exploitable; decide and pin
  explicitly (burn-or-credit) before mainnet.
- [ ] Ungoated CPU-burn family + zk shared-state audit: see 0.19.
- [ ] Witness replayability after restart (deterministic subset only) —
  document as a property test once the leaf binding work starts.
- [ ] Undo journal vs apply-integrity guard (P3, re-hunt 2026-11-05):
  UndoEngine::apply_block only RECORDS the undo journal — the caller
  applies to the ledger separately, so a block the new integrity guard
  refuses leaves a phantom undo record (journal written, state never
  moved). Today the only paired undo+ledger callers live in the swarm
  SIMULATOR (src/net/swarm_node.cpp), where refusals do not occur; the
  production seal path does not journal. Before UndoEngine enters the
  production seal/reorg path, callers must gate journaling on the ledger
  apply result (journal AFTER a successful apply), or UndoEngine needs a
  dry-run pre-check. The resync path in the simulator already half-does
  this (commit_undo_point only on success) but the record itself is
  written first and persists via load_latest_undo_journal.

### 0.19 Ungated crypto-lab family (documented scope cut, round-2 review)

Review flagged six POST endpoints that run real crypto on caller input but
stay outside both gate classes: `/api/crypto/lab`, `/api/zk/derive_matrix`,
`/api/zk/recover_shamir`, `/api/zk/proof_of_life`, `/api/zk/audit_view`,
`/api/crypto/pq_verify`. They are NOT gated in this release deliberately:
the web GUI's interactive lab uses them without a token workflow, and
gating them silently breaks the demo surface. Documented risk: an
unauthenticated flooder can burn CPU there (bounded per request, but not
rate-limited). Follow-up (0.20 candidate): a full shared-state audit of
the zk handlers (some mutate `zk_matrix_`/`tensor_v6_` members — locking
discipline needs a pass) TOGETHER with a GUI token workflow, then move the
whole family behind the same fail-closed gate. Do not gate half of it.

### 0.18 GENESIS_2 receiver is a public-key holder (documented decision, testnet-only)

Zero-trust round-2 note (P2-6): the height-1 `GENESIS_2` mint is bound to
`genesis2_mint_receiver_payload()` — the pinned demo-spender payload. That
spender's PQ secret key is the PUBLISHED demo test vector, so whoever holds
the public demo key (everyone) can spend the 100,000 VX mint at height 1.
This is accepted for the testnet/demo phase: the shape binding (P1 fix in
0.14) pins the amount, height and receiver, so the mint itself cannot be
diverted; only its spending is open. MAINNET REQUIREMENT: `mainnet` builds
must pin a receiver payload generated from a key that is never published
(the payload is consensus data — changing it changes the genesis frame
hash, so the decision must land before any mainnet genesis is frozen, not
after). Until then every chain built from this genesis is a test chain by
construction.

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
push immediacy returns to the desktop client without re-opening the
renderer.

DELIVERED 2026-11-05 (v0.0.8): SSE-over-IPC relay in `web/electron/main.cjs`
(`vx:sse-open` streams GET /api/events in the main process — same
hardening as the RPC bridge: absolute http(s), GET, header allowlist,
redirects refused — frames parsed and forwarded as `vx:sse-event`;
per-renderer single stream; aborted on navigation/destroy). Renderer uses
the bridge for cross-origin hosts, EventSource otherwise. Two node-side
bugs found on the way, both fixed: `/api/events` answered with RAW SSE
frames and no HTTP response head (unparseable by any HTTP client), and
`sse_running_` was never set true — the client loop closed every
subscriber ~2 ms after connect. SSE was never functional before v0.0.8;
`broadcast_sse_event` was declared but never implemented, so no named
event ever existed either. Now: conforming response head + named
`block_sealed` events fired from the miner's seal scope and from the
remote-frame intake. E2E-verified (undici stream + real seal).

Shutdown-ordering review (2026-11-05): the new miner callback reaches
into the RPC server's SSE state, and member destruction runs in reverse
order (the miner outlives the SSE members it calls into) — fixed by
quiescing the miner first in `HttpServer::stop()`. Residual (pre-existing,
class-wide, noted here rather than expanded): detached RPC worker threads
can still be mid-request when `HttpServer` is destroyed at process exit;
a deterministic join of the detached-thread pool is the eventual fix.
Also P3, cosmetic: the Electron SSE relay decodes each network chunk as
UTF-8 independently, so a multi-byte character split across chunk
boundaries would garble one frame (all current payloads are ASCII JSON).

Blocking-socket audit (owner package 2026-11-05, item I.4 — DELIVERED
v0.0.14): the feared permanent wedge was already impossible for the
steady state (SSE fds went O_NONBLOCK, sends ran outside sse_mutex_),
but a REAL race remained: the fd was pushed into sse_clients_ BEFORE
O_NONBLOCK was set, so a block sealed in that window made the miner
thread issue send() on a still-BLOCKING socket — a zero-window client
there could wedge the node. Fixed: O_NONBLOCK is set before the fd
becomes visible; all SSE sends now carry MSG_DONTWAIT|MSG_NOSIGNAL
(belt and suspenders — a single send can never block regardless of fd
flags); EAGAIN/short-write drops the subscriber from the push list
(Drop Slow Consumer — its own connection thread keeps fd ownership and
detects the disconnect; no cross-thread close, so no fd-reuse race).
Residual: a zero-window E2E torture test (client that never reads
while >1 MiB of events accumulate) is not practical against 100-byte
seal events at demo rates — the kernel-guaranteed DONTWAIT semantics
and the drop path are verified by construction + live smoke test
(hello frame flows, node serves).

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

- [x] Parameterize the sponge output width (256/512/1024) behind an
  address version: v1 = 256 (current, frozen wire), v2 = 512 (the
  standing target), 1024 documented as the paranoid maximum (no
  standard requires deeper than a 2^256 preimage class). — PRIMITIVE
  DELIVERED v0.0.9 (primitive) and v0.0.16 (1024 width, owner directive
  2026-11-06 "pull everything up to 1024 bits"):
  - `VortexSponge512` (v0.0.9): 16x64-bit state (1024-bit), 64-byte rate
    (capacity 512), 512-bit digest from the capacity words, 12 ChaCha-style
    column+diagonal rounds over the 4x4 word matrix, splitmix64-continued
    Golden Phi init stream, LENGTH-ENCODED padding — the trailing-zeros
    limit frozen into v1 is closed. KATs incl. rate boundaries 63/64/65.
  - `VortexSponge1024` (v3, beside the others in
    `include/vx/blockchain/crypto_sponge.hpp`): 32x64-bit state (2048-bit),
    128-byte rate (capacity 1024), 1024-bit digest from the 16 capacity
    words, same 12-round permutation scaled to the 4x8 word matrix
    (columns + rotating diagonals; every word feeds two QRs per round),
    words 8..31 continue the SAME splitmix64 stream (words 8..15 equal
    v2's rate words by construction), v2 padding/misuse rules verbatim.
    Preimage ~2^1024 classical / ~2^512 Grover. Contract-tested 8/8 (KATs
    incl. rate boundaries 127/128/129, streaming both directions incl.
    double-boundary splits, SAC ~50%, full-diffusion — every digest word
    moves on single-bit flips, idempotent finalize, H(m) != H(m||0)).
  - NEITHER is wired into consensus or the frozen wire: the address-version
    soft migration (both versions verified in parallel) is the remaining
    half of this item; the address-v2 fold is the 2.17 remedy vehicle.
- [ ] Extend the wire frame and address derivation for v2 with a soft
  migration (both versions verified in parallel; v1 never invalidated).
- [ ] Fold into the same work: PQ key rollover (a key signs at most 16
  times today — XMSS H=4 leaves 0..15, `pq_sign_transaction` refuses
  nonce >= 16; three independent test waves hit this on 2026-11-04).
  Rollover derives tree #N from the same master seed deterministically
  and publishes a fresh root per binding, so one key never dies after
  16 transfers; the leaf discipline (nonce counter, no double-sign)
  must stay consensus-visible.
- [x] Retarget parameter lock (found by the 2026-11-04 ASERT review,
  F2): delivered 2026-11-05 as a fingerprint pin instead of a genesis
  domain commitment — the then-current genesis frame hash (485f5afac16d…; superseded 2026-11-07 by the VXC7 frame bump, 2.11: the genesis now commits to 047f3cf7ac9f259b…),
  so folding the params in would change it. `POGW_RETARGET_FINGERPRINT`
  (FNV-1a over anchor_bits||half_life_blocks) is pinned by static_assert
  in retarget.hpp and by `RetargetParameterLock` in test_retarget.cpp:
  any anchor/half-life edit fails the build until both pins are updated
  in the same, announced commit. Residual (wire work): carry the params
  in the version handshake so nodes DISAGREE loudly instead of only
  failing their own build — needs a wire-format version bump.
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

### 0.21 External peer discovery (DNS seeds first, DHT later)

Status (owner question, 2026-11-05): v0.0.6-alpha ships `SwarmNode` with
a TCP listener and STATICALLY configured peers only — no DNS seeds, no
DHT/Kademlia, no peer exchange. External bootstrap today means an
operator-configured address. This entry designs the staged path; nothing
below is implemented yet.

- [ ] Stage 1 — DNS seeds (rendezvous, zero trust): hardcoded seed
  HOSTNAMES (never raw IPs — a domain can be re-pointed without a fork);
  resolved at startup, A-record results treated as untrusted candidate
  peers, capped count, each candidate passes the standard handshake +
  full-node validation like any other peer. Seeds can lie about peers
  but cannot lie about the chain (consensus is validated locally).
- [ ] Stage 2 — peer exchange (ADDR relay): connected nodes share
  known-good addresses; timestamps for staleness; per-peer caps.
- [ ] Stage 3 — DHT (Kademlia-class) as a FALLBACK only, not the primary
  path: heavier, NAT-traversal work, and a sybil-friendly discovery
  channel — which is acceptable only because discovery is never a trust
  input (full-node validation remains the trust root; PoGW + per-peer
  DoS scoring bound the damage of bad peers).
- [ ] Recommendation recorded: DNS seeds as rendezvous (Bitcoin-style),
  NOT DHT-first — DHT-first bootstrap is weaker for a small testnet
  (empty DHT at low peer counts) and adds attack surface before the
  peer-auth handshake (0.4) exists.
- Acceptance: a fresh node with zero config (beyond seeds) joins, syncs
  via 0.1 backfill, and rejects a malicious seed's bad chain under the
  0.2/0.6 rules.

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

### 1.5 XMSS tree rollover (crypto layer DELIVERED v0.0.13; consensus wiring open)

`pq_sign_transaction` refuses any nonce above 15 (window guard, external
review finding): the published root covers exactly the first 16-leaf
tree, and a nonce above 15 would derive the secret WOTS leaf from a
window the root does not span — an unverifiable signature that still
burns a ledger leaf. Refusal stays fail-closed; TEST 9 pins it
(nonces 0/15 sign+verify; 16/17/255/UINT32_MAX refuse, zero burns).

Delivered v0.0.13 (flat-hypertree design, superseding the draft
"top tree over subtree roots" sketch — the 2376-byte witness is frozen,
so a top-tree auth path cannot fit):

- **Flat WOTS+ hypertree**: one master key, one account mask seed,
  32-bit global leaf namespace `global_leaf = (window << 4) | leaf`.
  `pq_sign_message` now builds the witness root and auth path over the
  SAME window its secret chains come from — the pre-rollover code signed
  window-t leaves against a window-0 tree (the incoherence behind the
  guard). Window 0 is byte-identical with the frozen derivation
  (pinned by the full existing PQ suite).
- **`xmss_root_tree(master_sk, pub_seed, t)`** — root over global leaves
  `(t<<4)|0..15`; the PQ public key a rollover publishes for window t.
- **Rollover certificates (XMSS^MT construction)**: leaf 15 of window t
  signs `Sponge("VX_PQ_ROLLOVER_V1" || old_root || u32(from) ||
  u32(to) || new_root)`; `pq_sign_rollover` / `pq_verify_rollover` are
  fail-closed (leaf-15 policy checked independently of the witness
  commitment, commitment recomputed, ct_equal on roots, self-certs and
  out-of-namespace indexes refused). A certificate burns leaf 15 of the
  old window exactly like a transaction leaf (leaf-ledger reserve).
- **Verification cost**: a rollover link verifies in one WOTS+ envelope
  — 0.23 ms measured; witness size unchanged at 2376 B (static_assert).

Remaining (honest gaps, not hidden):

- [x] Consensus wiring (DELIVERED v0.0.18, owner-approved carrier B).
  The implemented acceptance rule differs from the design-note sketch
  below in ONE structural respect - it is STATELESS (no ledger state
  change, no undo integration) and that difference is strictly safer:
  a certificate does not MUTATE the account's bound root; instead
  `LedgerState::apply_block` accepts a witness root that differs from
  the bound anchor ONLY when `PqWitnessRegistry::advance_root_chain`
  walks a sequential chain of FULLY VERIFIED certificates from the
  anchor and its endpoint equals the witness root, with the witness's
  `subtree_index` equal to the walked window. Reorg/rewind needs no
  special handling because nothing was mutated: the walk re-derives
  the same endpoint from the same anchor on any fork (deterministic
  WOTS+ signing makes the valid certificate per (old_root, from, to)
  transition UNIQUE, so the walk is deterministic).

  Delivered pieces:
  - `PqRolloverCert` record (sender, from_window, to_window, old_root,
    new_root, leaf-15 witness) - the owner-decided carrier: wire type
    `ROLLOVER_CERT = 0x0A` (VX60 format addition, old/new node
    separation preserved: old nodes drop unknown types, fail-closed).
  - `register_rollover_cert`: full verification BEFORE storage (leaf
    15 of from_window, to == from + 1, both roots match the witness,
    the commitment matches, `pq_verify_rollover` over the binding
    digest of THIS tuple); dedup; per-sender (32) and per-map (50000)
    caps; certificates alone never touch the `sender_roots_`
    admission cache (pinned by test).
  - `advance_root_chain`: deterministic walk from the anchor (window
    0), capped at `PQ_MAX_CERT_CHAIN_DEPTH = 16`; a gap stops the walk
    at the last unambiguous link; two DISTINCT candidates for one
    transition stop it conservatively (a hash-function break, in
    theory - never observed).
  - `attach_durable_cert_log`: the `VXPQRT1` sidecar
    (sender + windows + roots + witness), appended+fsync'd on every
    accepted registration; replay RE-VERIFIES each record and stops at
    the first failure (fail-closed: unlike the witness log - whose
    entries are re-verified at USE time - a certificate entry is
    consumed by the walk as a pre-verified fact, so a hand-corrupted
    sidecar must not be able to plant a chain the walk would trust).
    A torn TAIL (crash mid-append) is truncated back to the last
    fully-read good record at replay, so honest records appended after
    the tear are not stranded forever (review finding P2; the same fix
    applied to the pre-existing witness sidecar).
  - Leaf-15 exclusivity at USE time: `pq_verify_transaction` refuses
    any witness with `leaf_index >= 15`, covering every path (client
    registration, wire registration, consensus lookup) - the wallet
    discipline (v0.0.15) is now also a consensus invariant.
  - Tests: `VortexPqRolloverWiringTest` (chain walk determinism,
    sequential policy, root substitution both ways, chain gap, depth
    cap, admission-cache neutrality, durable sidecar replay,
    leaf-15 mechanism) and three end-to-end ledger pins in
    `VortexDocumentedGapsTest` (accepted rotation, uncertified
    refusal, certificate-leaf spender refusal).

  Still open under this item:

- [x] **P0 GATE CLOSED (2026-11-08): cert delivery/backfill protocol over
  VX60**. Delivery is no longer fire-and-forget-only:
  - Deterministic cert identity: `rollover_cert_id(cert)` =
    Sponge256("VX_CERT_ID_V1" || sender(42) || from_window u32 LE ||
    to_window u32 LE || old_root(32) || new_root(32)) - a pure function of
    the transition tuple (the WOTS+ witness is deterministic per tuple, so
    it is NOT part of the id; two honest nodes compute the same id for the
    same transition).
  - New wire types `CERT_INV = 0x0B` / `GET_CERTS = 0x0C`, payload
    count(u32 LE) + count x 32-byte ids, count <= 64 (max payload
    2052 B); `wire_header_plausible` accepts 0x01..0x0C, 0x0D still fails
    closed (pinned by the wiring test).
  - Registry id index: `register_rollover_cert(cert, &fresh)` sets
    `fresh` only when THIS call stored a NEW record (the relay cue);
    `have_cert_id` / `lookup_cert_by_id` / `cert_inventory(max<=64)`
    (newest-last, window 1024) index every stored record including the
    sidecar-replay path; certs NEVER touch the sender_roots_ admission
    cache.
  - Relay rule: on a FRESH registration (wire OR sidecar replay) the node
    broadcasts the full ROLLOVER_CERT one hop AND a one-id CERT_INV; on
    CERT_INV a node answers GET_CERTS naming every unknown id; on
    GET_CERTS a node answers with the FULL verified 2490-byte records for
    the ids it holds (unknown id -> silence, no error channel). Pulled
    records go through the SAME full-verification path as relayed ones -
    nothing unverified is ever stored or indexed.
  - Connect-time retention: `serve_witness_retention` (inside the same
    per-IP 60 s rate gate as the witness window) announces the cert
    inventory to every freshly promoted peer, so a node that connected
    mid-stream learns what it missed.
  - Handlers live in BOTH reader loops (peer_reader_loop +
    serve_connection) and re-verify the full object on intake; sends use
    the dup-fd discipline under peers_mutex_.
  - Tests: wiring suite sections 10-13 (cert-id determinism and
    tuple-distinctness, registry id index + fresh flag, payload
    encode/decode round-trip with re-verification), three socket e2e
    tests in VortexSwarmP2PTest (GET_CERTS round-trip returns the exact
    full record; unknown-id CERT_INV triggers the GET_CERTS pull; count=65
    oversized lists fail closed silently and the connection survives),
    and the connect-time CERT_INV pin (first connect announces the id,
    rate-gated second connect announces nothing).
  - Honest residuals: (a) GET_CERTS has no per-peer rate limit beyond the
    payload bounds (64 ids/request) - each request costs at most 64
    lookups + 64 sends; (b) no targeted re-request after an apply
    failure - recovery relies on the connect-time announcement and the
    relay; (c) the inventory window covers the last 1024 stored certs -
    older certs are replayed from the durable sidecar at startup, but a
    node wanting an OLDER cert from a LIVE peer cannot name it until the
    sidecar-scan fallback ships (recorded below); (d) a connection whose
    FIRST packet is CERT_INV/GET_CERTS is served but not promoted into
    the broadcast-target table (promotion hooks PING / RAW_BLOCK_64K /
    PQ_WITNESS / ROLLOVER_CERT) - a pull-only peer relays nothing; wire
    it into the promote set when a peer role concept lands.
- [ ] P3: live-peer sidecar-scan fallback - serve cert ids older than the
  1024-entry inventory window from the durable VXPQRT1 sidecar on demand
  (bounded scan), so deep-history backfill does not depend on restarts.
- [x] Wallet policy — CLOSED (2026-11-11, see 1.5 wallet policy): SSE
  "rollover_advised" at 12/15 burned leaves + auth-gated
  POST /api/wallet/rollover (sign -> burn cert leaf -> register ->
  full-cert broadcast); `broadcast_rollover_cert` now has its RPC/wallet
  trigger. The post-rollover leaf accounting needed NO format change:
  reservations are keyed by the signing window's root (distinct per
  window), so `pq_sign_transaction` signs the walked window
  (nonce = (window << 4) | leaf) against the same 33-byte durable log.
  The leaf-log widening entry below is obsoleted by this keying and is
  NOT shipped.
- [ ] P3 (review 2026-11-07), format-bump candidates - NOT exploitable
  today (the walk's anchor linkage and `derive_pq_address`
  determinism make a transferred certificate inert; store pollution
  only), pinned for the next wire-format revision: (a) the rollover
  binding digest does not commit the SENDER address - a certificate
  object is transferable between senders; commit sender in the digest
  at the next format bump. (b) `from_window`/`to_window` cross the
  wire as native-endian u32 (consistent with the frozen PQ_WITNESS
  whole-struct memcpy; cross-endian peers fail closed on
  `to != from + 1`, so the failure mode is liveness, not safety) -
  pin a byte order before any big-endian host exists. (c) the
  sidecar `fsync` runs under the registry mutex (pre-existing
  witness-sidecar pattern); batching or a writer thread belongs to
  the same future pass.

  HISTORICAL DESIGN NOTE (2026-11-07, pre-implementation) - kept for
  the record. Superseded: the state-mutation model and the undo-vector
  mechanics below (replaced by the stateless walk described above).
  Carried into the implementation: the leaf-15 policy, the sequential
  one-window rule, the commitment-bound certificate, carrier B, and the
  fail-closed refusal posture:

  - Today's posture: `LedgerState::bind_pq_sender` REFUSES a different
    root for an already-bound address, so a bound account is frozen at
    its window-0 root; after 15 leaves the account is dead (today's
    answer: a new self-certifying address). The registry-level
    `sender_roots_` overwrite affects only the admission cache - a
    foreign-root tx can enter the mempool but always fails the
    consensus bound-root check (theft impossible, mempool DoS surface
    only, already mitigated by lookup_verifying).
  - State model: `pq_roots_` keeps holding the CURRENT root (so the
    existing bound-root check needs no signature change); a parallel
    map Address -> u32 current_window defaults to 0 for every bound
    account. A certificate advances both atomically inside block
    application.
  - Certificate rule (sequential-window, fail-closed): a cert is
    accepted only when (a) cert.leaf_index == 15 (the kernel
    invariant), (b) cert.subtree_index == the account's current
    window, (c) the target window == current + 1, (d)
    cert.pq_pubkey_root == the account's current bound root, and (e)
    pq_verify_rollover(bound, from, to, claimed_new_root, cert) passes
    - the signature commits (old_root, from, to, new_root), so the
    claimed new root cannot be substituted. After acceptance the
    account's bound root becomes claimed_new_root and the window
    advances; a REPLAY of the same cert then fails at (b) - windows
    never repeat. Transaction witnesses from any window verify against
    the CURRENT root, so older-window witnesses fail after the cert
    (the account moved).
  - Reorg/undo: the root/window pair joins the existing per-block undo
    vectors (BalanceUndo/NonceUndo pattern) - a rewound block restores
    the pre-cert root and window; replay on the winning fork re-applies
    the cert from the sidecar. Burn discipline stays with the leaf
    ledger (a burned leaf 15 never returns, even across a reorg - the
    account re-certifies on the next leaf... no: leaf 15 is the ONLY
    cert leaf; a reorg-discarded cert re-signs from the same burned
    leaf record, which the ledger already refuses - the wallet must
    keep the discarded cert's witness or re-derive an equivalent one;
    documented as a wallet-policy obligation, not a consensus problem).
  - Carrier (DECIDED by the owner, 2026-11-07: option B):
    A. Zero-amount self-send marker: sender == receiver == the PQA
       address, amount == 0, fee normal. Today "zero transfer" is
       refused for user senders; the wiring carves exactly this shape
       out as a ROLLOVER INTENT whose authorization comes entirely
       from the cert witness (the keyless cocoon digest is irrelevant
       for a valueless self-send). No wire change, no new tx type.
    B. **CHOSEN**: a dedicated wire tag for a certificate record (a
       VX60 format addition per the standing freeze rule - new format
       tag, old/new node separation through the migration protocol,
       DERIVATION_VERSION discipline). Cleaner semantics: certificates
       never mix with value transfers; the tx marker hack is off the
       table.
  - Registry side: a parallel cert store (candidates keyed by sender,
    same fail-closed verification discipline as register_witness) +
    durable sidecar record type; sender_roots_ overwrite semantics
    stay admission-cache-only and are documented as such.
- [ ] Wallet policy: when to roll over (window exhaustion), certificate
  publication/relay, and burning leaf 15 in the ledger at rollover time.
  The leaf-15 burn is NO LONGER caller discipline: kernel invariant
  delivered v0.0.15 (owner directive, 2026-11-05) — leaf 15 is reserved
  EXCLUSIVELY for rollover certificates: `reserve_for_tx` refuses it and
  never assigns it in the lowest-free search; `pq_sign_transaction`
  refuses a leaf-15 nonce with or without a ledger (fail-closed, no
  burn); `pq_sign_rollover` with a ledger reserves+fsyncs leaf 15 under
  the OLD root BEFORE producing the certificate signature (a reserve
  failure signs nothing). Transaction keys offer 15 signatures, not 16
  (TEST 9 and the ledger-lifecycle test updated accordingly).
- [ ] `pq_sign_message` still accepts `subtree_index` values whose
  `window << 4` wraps (t > 0x0FFFFFFF) — the rollover API refuses them,
  but the raw primitive trusts its caller; a fail-closed clamp belongs
  to the same consensus-wiring pass.

### 1.7 WOTS+ w=256 profile (owner pattern II.5, 2026-11-05)

Halve the witness wire cost by lifting the Winternitz parameter into a
signed-scheme profile: w=16 gives L=67 chains (2144 B of signature);
w=256 (1 byte per step instead of a nibble) gives 34 chains
(32 digest bytes + 2 checksum bytes) — 1088 B, exactly half the VX60
traffic and sidecar storage, SAME 256-bit classical / 128-bit Grover
posture, at ~120 µs extra per sign/verify (16x-longer chains).

- [ ] Design: parameterize the scheme (chain length, checksum width,
  domain-separation tags) WITHOUT touching the frozen w=16 derivation;
  a w=256 witness must be a different, self-identifying profile —
  cross-profile witnesses never verify against the wrong profile.
- [ ] This is a wire-format addition → new format tag per the standing
  freeze rule; the w=16 profile stays mandatory-verifiable forever
  (existing chain history).
- [ ] Re-test: leaf-ledger discipline, rollover certificates and the
  SegPQ anchor under the new profile.

---

### 1.4 MemoryVault hardening round 2

- [ ] TSan CI lane (the swarm threading grew: listener + per-connection
  handlers + per-peer readers).
- [ ] Guard pages around locked regions; verify mlock failure semantics
  on hosts with low `rlimit_memlock` (document the fallback loudly).
- Acceptance: TSan clean in CI; fallback path tested with a low rlimit.
- [x] Owner pattern (2026-11-05, II.1) — vault_mutex_ decomposition,
  DELIVERED 2026-11-07: the global vault_mutex_ is gone. Every page
  transition is a CAS on `pages_[i].state` (new CLAIMED state marks the
  claim window); heavy key expansion / signing / zeroize / clflush run
  lock-free on the claimed page and publish the final state with
  memory_order_release; pages are physically disjoint, so page i's work
  never contends with page j. The capability digest became atomic bytes:
  consume compares lock-free on LOCKED pages while an emergency sweep may
  zero a claimed page's digest concurrently (the digest is immutable while
  LOCKED, so a zeroed digest can only produce a skip, never a false token
  match). Emergency wipe latches first (no new claims during the drain;
  the latch stays set - the vault is retired, matching the pre-split
  post-emergency dead pool). Two intermediate designs were caught by the
  project's own gates before they could ship: claim-then-compare hid live
  tokens from concurrent scanners (the stress test failed with 201 lost
  tokens); a plain digest read raced the emergency zeroing (caught by
  reasoning, fixed with atomic bytes before any lane ran). Real BURNED-slot
  reuse now ships with the split (round-5 policy said "reusable after
  consumed or burned" but the scan only ever accepted VOID - the pool was
  silently single-use per initialize). Regression guard green: the v0.0.11
  stress test plus a new `ConcurrentEmergencyBurnTerminatesAndCompletes`
  (4 claimers vs a mid-flight panic wipe; termination + zero LOCKED pages
  + post-wipe "retired" refusal) - 8/8 TSan reruns clean, ASan/UBSan and
  GCC lanes green. Honest notes: stats buckets no longer sum to the pool
  size while pages are CLAIMED in flight (each page still counted exactly
  once); a transient CLAIMED page makes the pool look one slot smaller to
  concurrent committers (the mutex version made them queue instead).
  Adversarial review of the split itself (2026-11-07, before commit) found
  two more defects, both fixed the same day: (1) HIGH - the wipe's drain
  could exit while a commit that had read the latch as false published
  LOCKED behind the sweep (live secret + redeemable token in a retired
  vault); closed by a post-claim latch re-check in commit/ephemeral-sign
  (release the slot, refuse) plus a fixpoint drain that ends only after a
  pass with zero burns, zero CLAIMED observations and a clean final scan;
  (2) MEDIUM - ABA on BURNED-slot reuse in consume: the digest matched
  while LOCKED, then a wipe + re-commit repurposed the page before the
  CAS won, so the old token would have copied out a DIFFERENT committer's
  secret; closed by re-running the constant-time compare under CLAIM and
  restoring LOCKED on mismatch. Exception safety: ephemeral-sign burns its
  claimed page on any throw (a CLAIMED-forever page would hang the drain).

### 1.6 RPC shared-state audit (delivered 2026-11-05, v0.0.11) — residual: TSan

The RPC server serves every handler on detached threads over ONE shared
HttpServer instance, so every mutable member is a potential cross-request
race. Audit of the live endpoints:

- CLEAN (stateless by construction): `ZKKeyMatrix` (no data members —
  every method derives from its arguments), `TensorV6::run` (local
  matrix), `VirtualTensor::evolve` (pure bit-arithmetic). No locks
  needed; recorded so future edits keep them stateless or add locking.
- FIXED: `MemoryCore` (vault_core_) — commit/consume/burn/ephemeral-sign
  all did check-then-claim on `pages_[].state` with no synchronization;
  two concurrent commits could claim the same VOID page and overwrite
  each other's secrets, and consume could read a half-written page.
  Fix: internal `vault_mutex_` serializing all page-state paths
  (sign_ephemeral holds it across the whole claim->SK->anchor->burn
  cycle via `burn_page_internal_`; get_stats snapshots under the lock).
  Regression: `ConcurrentCommitConsumeStress` (8 threads x 200
  commit+consume round-trips, zero cross-contamination, coherent final
  accounting); assert + sanitizer lanes green.
- CLEAN: `last_htlc_` mutated only under state_mutex_ (HTLC endpoint);
  trie_/trie_root_cache_ under state_mutex_ (state endpoints).
- Residual: a TSan lane would catch the NEXT shared member added
  without locking — fold into 1.4's TSan item.

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

### 2.3b Reorg-interleaved fuzz harness (owner question, 2026-11-05)

The current libFuzzer set covers parsers and the sequential frame→state
layer under hostile input; split-brain reorg correctness is covered by
DETERMINISTIC tests only (`test_reorg`, `test_reorg_carousel`,
`test_bifurcation`). No harness interleaves corrupted binary frames
with an active reorg. Honest gap, raised by the owner's review question.

- [ ] `fuzz_reorg`: two interleaved intake streams (honest tip extension
  vs competing-height/corrupted frames) driven from one fuzz input;
  assert no crash/UB and post-heal ledger determinism against a
  reference apply order.
- [ ] Prerequisite/limiter: production fork choice is not implemented
  yet — `apply_remote_frame` DROPS competing-height frames (ROADMAP
  follow-up), so today's harness would exercise the drop path only.
  Build the harness with the drop path first, extend it when fork
  choice lands.
- [ ] Wire-level: fuzz the VX60 handshake/promotion state machine
  (`fuzz_wire` covers message parse, not the session state machine)
  under mid-handshake frame corruption.

### 2.3c Sanitizer coverage for the vault burn path (owner question, 2026-11-05)

- Status: build_san (Clang ASan+UBSan) runs the full ctest set incl.
  `test_vault_memory`; the burn path itself is DSE-safe by construction
  (volatile stores + `asm volatile("" ::: "memory")` barriers +
  `explicit_bzero` in SecureByteBuffer + `_mm_clflush` per cache line +
  `PageState::BURNED` transition).
- [ ] Add a post-burn content check: after `PageState::BURNED`, read
  back the arena bytes of the burned page and assert all-zero (guards
  against a future refactor reintroducing an elidable wipe). Respect
  the vault's read-after-burn policy — do it inside the vault's own
  test seam, not through the public API. Owner-supplied pattern
  (2026-11-05, II.3), guarded by VX_TEST_SEAM:
  `bool MemoryVault::debug_verify_page_zeroed(size_t page_idx) const
  noexcept` — walk `const volatile uint8_t*` over the page accumulating
  `acc |= raw[i]`, then a register barrier `asm volatile("" : "+r"(acc)
  :: "memory")` so the compiler cannot elide the reads; return
  `acc == 0`. The volatile accumulate + register barrier forces a
  physical re-read of all page bytes from RAM after _mm_clflush.
- [ ] MSan lane (Clang MemorySanitizer) is NOT configured — honest gap;
  it requires an MSan-instrumented libc++. Low priority vs the
  ASan/UBSan+fuzz stack, tracked so it is not forgotten.

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

### 2.6 Epoch snapshots & undo-journal pruning (owner question, 2026-11-05)

Today nothing is prunable: the block store is an append-only mmap
archive by design; `undo.vxl` keeps undo records for the WHOLE height
range (the in-memory journal is the write model; `truncate_undo_file`
rewrites the file after a rollback but never shrinks history), and
`displaced.vxd` grows with every reorg event. Honest gap.

- [ ] Phase 1 (provable, cheap): prune undo records and displaced
  frames with height <= GQC finalized_checkpoint_height_ (after each
  new checkpoint and at startup). Safe by construction: rollback below
  the checkpoint is already refused (ERR_FINALIZED_BY_GQC), so those
  records can never be used. Compact via the existing rewrite path.
- [ ] Phase 2 (real epochs): at a GQC-cemented epoch boundary, write a
  state snapshot (LedgerState balances+nonces+supply, GaloisTrie state
  root) into an epoch sidecar, bound to the chain by hashing the state
  root into the certified record. New nodes: snapshot + verify root +
  replay forward. The state-root RPC surface
  (handle_state_trie_root/handle_state_prove) already exists.
- [ ] The block store itself stays append-only this phase — pruning
  blocks would break backfill sync (0.1) and is a separate SPV-mode
  decision.
- [ ] Phase 0 (owner pattern II.4, 2026-11-05) — WAL phase marker to
  close the crash-during-apply window WITHOUT abandoning zero-copy
  mmap: a 64-bit journal_state in the ledger metadata
  (IDLE=0 / APPLYING_HEIGHT_N / ROLLING_BACK_N) with the write order
  (1) undo record + CRC32C + fdatasync, (2) journal_state =
  APPLYING_HEIGHT_N + msync(MS_SYNC), (3) mutate LedgerState + store
  block, (4) journal_state = IDLE + msync(MS_SYNC). On startup,
  journal_state != IDLE proves the previous process died mid-apply →
  auto-roll-back to the last valid undo record (O(1) recovery instead
  of a full replay scan). CRC32C on undo records is the companion
  integrity check.
- [x] Phase 0a (delivered 2026-11-07) — the STORE-append torn-frame
  window, the sibling of the Phase 0 apply window: the append path was
  ftruncate -> pwrite -> fsync, so a crash between the ftruncate and the
  fsync left a torn frame whose file size still lands on the 65536
  boundary (invisible to the size check; the old open then died with
  "corrupted ledger" and needed operator hands). Now a 32-byte
  write-ahead marker in the sidecar `<ledger>.walmark` ("VXWALMK1" =
  state + height + frame-CRC32C + record-CRC32C) makes the append
  crash-consistent: INTENT fsynced BEFORE the ledger is touched,
  COMMITTED fsynced after the ledger fsync (3 fsyncs per append instead
  of 1 - the honest price of "a reported success survived a power cut").
  Recovery on open: INTENT + CRC-matching frame = the crash hit between
  the ledger fsync and the COMMITTED flip, the frame stays; INTENT +
  CRC mismatch = torn frame, healed by truncation; COMMITTED + CRC
  mismatch at the tip = the durable marker and the disk disagree - real
  corruption, fail closed (never silently drop a durable block); a
  marker naming a frame that is not on disk, or a stale record naming
  history, is RESOLVED (cleared) without authorizing healing - the
  surviving chain is always re-judged by validate_region (the first
  draft failed the reorg-heal reopen closed - the crash-torture gate
  caught it: legitimate truncations below a marker exist, the marker
  only speaks about the append frontier); a corrupt or torn
  sidecar record falls back to the pre-marker fail-closed behavior
  (full validate_region, torn frame = refuse to start - no healing from
  untrusted metadata, but no bypass either). rollback_last_append clears
  the marker (a leftover would poison the next open). The directory is
  fsynced once at open so a fresh sidecar's directory entry is durable.
  Regression: VortexWalMarkerTest, 9 sections pinning the whole recovery
  matrix by writing marker bytes exactly the way a crashed writer would
  have left them; SAN lane 9/9 (ASan+UBSan). Adversarial security review
  of the marker (2026-11-07): no findings above threshold - the crafted
  marker path is operator-local tamper only (local file write already
  implies the same capability), no recovery return can elevate a frame
  past validate_region, CRC-only acceptance is unreachable, the byte
  gate precedes recovery. Recorded residual (hardening, below threshold):
  a second BlockStore instance racing the microsecond INTENT window could
  truncate where the pre-marker code would have thrown - an flock on the
  sidecar would close it under the already-broken two-writer premise.

### 2.7 Landauer gas: temperature is abstract (owner question, 2026-11-05)

`LANDAUER_KT_LN2_SCALED = 960` (include/vx/vm/vortex_vm.hpp) is a
dimensionless scaled proxy for k_B*T*ln2, not a physical constant: no
Kelvin value and no joule-to-atom conversion exists in the code, and
none SHOULD exist — gas must be byte-reproducible from bytecode alone,
so any physical constant would be an unverifiable scale factor. The
consensus invariants are determinism and the ratio structure
(erasure : flip : NOP = 960 : 3 : 1; erasure costs more than
overwriting — the physical heart of Landauer's principle). Remaining
work is documentation only: a whitepaper paragraph stating that T is
folded into the scale constant and that any joule mapping is a
doc-level convention, never consensus state.

### 2.9 xorFold truncation window (owner audit item I.1, 2026-11-05)

FACT: xorFold reads only the top 128 bits of each trunk (48 of 384
bytes; 87.5% of the final attractor state never reaches the address
digest). The pinned fold-window test froze this as current behavior;
the owner's audit sharpens WHY it matters: carries propagate from low
to high bits in the modular arithmetic, so a perturbation settling in
the low 896 bits of a trunk late in the orbit may never cascade into
the folded top bits — a potential structural collision class at the
fold boundary.

- [ ] Orbit-segment experiment: measure, over many pseudorandom seeds,
  how many final iterations it takes for a single low-bit flip to
  reach the top 128 bits; if the cascade does not saturate within the
  iteration budget, the collision window is real, not theoretical.
- [ ] Remedy (owner's proposal, adopted as the design direction):
  absorb ALL 384 final trunk bytes through VortexSponge256 BEFORE the
  fold, replacing the linear xorFold — then every one of the 3072
  state bits reaches the digest under the sponge's avalanche criterion
  (SAC). THIS IS A DIGEST-DEFINITION CHANGE: addresses change, so it
  requires a versioned migration (new address tag + dual-verify
  window), never a silent swap — same discipline as the frozen sponge
  digest.
- Related: 2.3 (formal collision analysis) and 0.15 (sponge
  integration).

### 2.10 Degenerate subgroup extension of the seed hunt (owner audit item I.2, 2026-11-05)

v0.0.10/v0.0.12 refused whole classes at the surface (zero seed, 0X
prefix, >512 hex, non-hex). The audit names three deeper degenerate
classes INSIDE the modular arithmetic.

DELIVERED v0.0.15 (canonicalSeedError 2-arg overload; the 1-arg RPC
gate delegates with the classic moduli, so the surface upgrade is
automatic). Checked on BOTH orientations (locked mode reverses the
seed string; both addresses derive from one seed):

- [x] Congruent zero + per-trunk zero: X_0 == 0 / Y_0 == 0 (a seed
  whose second half is all zeros — the old string-level all-zero check
  could not see it) and X_0 % p == 0 / Y_0 % q == 0 (a non-zero word
  that collapses to a zero residue, e.g. the word equal to its
  modulus). NOTE: this SUPERSEDES the v0.0.12 decision to accept
  shorter-than-canonical seeds — every seed of ≤256 hex chars has a
  zero Y trunk and is now refused (documented behavior change; the
  derivation itself stays frozen).
- [x] Zero Z-trunk: a seed whose ACT I derivation produces Z_0 == 0
  (cube_sum == rotl1024(PHI, Y_0 % 64)). CONSTRUCTION CORRECTED
  (2026-11-06, attack-experiment session): the earlier premise "the cube
  map is 3-to-1 (3 | r-1); no inverse of 3 mod r-1" was WRONG - a
  confusion of v2(R-1) = 3 (8 | R-1) with divisibility by 3. In fact
  M-1 = 1 (mod 3) for every frozen modulus, cubing is a BIJECTION
  (docs/CRT_COLLISION_ANALYSIS.md, Theorem 6), the inverse exponent
  d = 3^-1 mod (r-1) exists, and the class is CLOSED-FORM constructible:
  X0 = (rotl1024(PHI, Y0 % 64) - Y0^3)^d mod r gives derive_z0 == 0 for
  any Y0. The checker's refusal of the class stays (fail-closed); the
  regression suite now pins a POSITIVE instance (constructed seed,
  derive_z0 == 0, refused by canonicalSeedError on both moduli sets)
  instead of negative evidence only.
- [x] Fixed-point PREMISE CORRECTED: the audit assumed power maps with
  fixed points 1 and P-1/Q-1/R-1. The actual per-step trunk map is
  AFFINE — (x ^ Phi_lock)*7+13 mod p (and 11+17 / 19+23 for Y/Z) — so
  1 and P-1 are NOT fixed points of the dynamics; the only power map
  is ACT I's cubing. Pinned in the suite: trunk=1 and trunk=p-1 seeds
  are accepted and derive distinct non-degenerate addresses.
- [ ] Trunk diagonal symmetry X_0 == Y_0: pinned ACCEPTED for now —
  the three different moduli break the symmetry after the first round
  (X_0 = W, Y_0 = W give W mod p != W mod q), so the early-round
  correlation is real but non-structural. The deeper orbit-quality
  measurement (cycle lengths, diffusion decay) stays open.
- Acceptance: each class either measured-harmless (pinned in
  test_attractor_degeneracy with the evidence) or fail-closed at the
  surface — met for the zero/congruent classes; diagonal measurement
  open.

### 2.11 VX60 witness delivery: witness_merkle_root + orphan-witness defense (owner audit item I.5, 2026-11-05)

FACT: the block frame is fixed at 65536 B, a transaction is 112 B, a
detached WOTS+/XMSS witness is 2376 B — 30 witnesses (71280 B) exceed
the block itself, so witnesses necessarily travel out-of-band today.

- [x] VERIFIED 2026-11-05 (reject-forever), then SUPERSEDED twice and
  CLOSED 2026-11-07: (1) the liveness stall itself is gone — stage 2
  parks MISSING_WITNESS frames and retries on witness arrival; (2) the
  "new-sender case looks unserveable" claim was STALE: the designed
  first-seen binding path has existed since the rounds 7-9 commit
  (589f38a) — LedgerState's self-certifying branch binds a PQA sender
  on its first witnessed spend (the address commits its own key root;
  derive_pq_address(w.pq_pubkey_root) == sender is enforced, the
  binding is collected as new_bindings_ and committed only after the
  WHOLE block validates). VortexWitnessDeliveryTest.
  RemoteFirstSpendBindsAndContinues pins the full remote lifecycle:
  brand-new PQA account funded by a bound sender, first spend arrives
  in a remote frame, parks on the missing witness, applies on wire
  arrival, the ledger binds the address, and the follow-up remote
  spend goes through the bound-root path. RESIDUAL (recorded, not a
  beta blocker): a sender whose address is NOT self-certifying and
  NOT in the genesis seed table still cannot be remotely onboarded -
  classic-format addresses need a designed registration story if any
  user class beyond PQA is meant to spend; today every user-facing
  address generation is PQA, so the residual is a policy question
  more than a defect.
- [x] STAGE 1 DELIVERED 2026-11-07 (VXC7 frame format): the header grew
  472 -> 504 B (witness_merkle_root[32] at offset 0x1D8),
  BLOCK_MAGIC 0x58564336 -> 0x58564337; VXC6 frames are REFUSED at
  intake by name ("VXC6 frame refused: pre-2.11 format without a
  witness commitment") — a versioned format bump, never a silent swap;
  MAX_TX_PER_BLOCK 580 -> 579 (the 32-byte commitment comes out of the
  tx budget's slack, body_padding 80 B keeps every other tail offset
  unchanged). The producer commits the CANONICAL witness set (one
  WitnessBinding per user transaction: 0-based tx index, sender,
  canonical root) into the header BEFORE PoGW sealing, so the
  commitment is inside the work-sealed frame. Canonical selection
  (consensus_witness_root, arrival-order independent): 1) ledger-bound
  root via the verifier's binding oracle -> direct registry hit ->
  certified rollover-chain walk (advance_root_chain) -> second lookup;
  2) genesis seed table; 3) self-certifying PQA (first verifying
  candidate whose root re-derives the sender address; ~2^-234 collision
  bound). Ledger enforcement: apply_block recomputes the tree from the
  witnesses ITS OWN verification accepted and refuses a lying header
  with ERR_WITNESS_ROOT before any state mutation. Structural intake
  gate, both directions: zero user txs <=> the header must commit the
  fixed domain-separated empty constant Sponge256("VXWMRE1") (nonzero —
  the all-zero commitment is not confusable with "no field"); user txs
  present <=> the header must NOT commit the empty constant (every user
  tx resolves to exactly one canonical witness before a block may
  apply). Leaf = Sponge256("VXWMRL1" || tx_index u32 LE || sender[42]
  || canonical_root[32]); node = Sponge256("VXWMRN1" || left || right);
  odd count duplicates the last leaf. HONEST MIGRATION NOTE: existing
  VXC6 testnet ledgers fail closed at intake — a fresh chain start is
  required; no migration path is offered (the format is pre-beta).
  Tests: VortexWitnessMerkleTest, 8 sections (empty-constant
  determinism, system-only auto-commit + structural refusal, index/
  sender binding, VXC6 named refusal, the inverse structural rule,
  lying-header refused before mutation with byte-identical ledger,
  wrong-key binding refused with a valid witness present, canonical
  selection ignores a foreign pre-registered candidate). All touched
  suites patched and green on the assert lane (38 ctest entries + the
  new suite).
- [x] STAGE 2 DELIVERED 2026-11-07: the delivery protocol around the
  stage-1 commitment. apply_remote_frame PARKS a tip-extending frame
  whose canonical witness set has not arrived (verify_witness_merkle ==
  MISSING_WITNESS) instead of refusing it — witnesses travel out-of-band
  and normally trail the frame by one gossip hop, so parking is the
  steady state, and the old reject-forever behavior was the 2.11
  liveness stall. A frame whose commitment matches NO canonical rule
  (MISMATCH) is refused outright and counted per sending peer
  (witness_withhold_score_) — withholding is attributable; escalation
  to mute/ban rides the SwarmNode reputation surface (still open, see
  the third checkbox). Retry: SwarmNode fires a new witness-arrival
  callback on BOTH reader loops after a PQ_WITNESS registration; the
  HttpServer scans its parked frames for the matching tx digest and
  retries through the SAME apply path (validate -> witness check ->
  append -> apply; no bypass surface), re-parking on still-missing and
  dropping on tip-move (a parked frame only ever extends the tip it
  named). Park bounds: 32 frames, oldest evicted, 60 s TTL with lazy
  purge — DoS-bounded both ways. Design draft:
  archives/notes/witness-delivery-stage2-design.md. Tests:
  VortexWitnessDeliveryTest, 6 sections (park-then-retry, mismatch
  refused and attributed, cap eviction, TTL expiry, tip-move kills a
  parked frame, unrelated witness does not retry). Honest notes, updated
  2026-11-07: (a) CLOSED - the first-seen binding worry was stale: the
  self-certifying binding path (the is_pq_address branch in ledger_state,
  present since 589f38a) binds a brand-new PQA sender on its first
  witnessed spend, verified e2e by RemoteFirstSpendBindsAndContinues (a
  remote first-spend parks, its witness arrives, the frame applies, and
  the binding persists for the follow-up spend); (b) CLOSED by the third
  checkbox below (report_withhold escalation + retention window); (c) a
  dedicated WITNESS_REQUEST pull remains a follow-up only if one-hop
  witness gossip does not converge on deeper topologies.
- [x] CLOSED (2026-11-07): the retention window is live and the withhold
  counter escalates. A newly promoted peer (one-shot per promote(), fired
  outside peers_mutex_) is re-served the witnesses of the last
  kWitnessRetentionBlocks = 16 stored blocks (HttpServer::serve_witness_retention:
  snapshot under state_mutex_, sends outside it) through
  SwarmNode::send_witnesses_to; a MISMATCH frame now feeds
  report_withhold(peer, 34) - three strikes cross the >=100 dos_score ban
  threshold and health_loop disconnects the banned peer. Security review
  of the diff (adversarial, zero-trust) found and fixed BEFORE commit:
  P0-1 the OUTBOUND dial fired peer_connected_callback_ under
  peers_mutex_ - a guaranteed self-deadlock of the whole node on the
  first configured --peer (fixed: fire outside both locks, mirroring the
  inbound fire_connected discipline + regression test
  OutboundDialFiresConnectedCallback); P1-2 retention is a real
  amplifier (one 24-byte PING bought up to ~23 MB of sends and a 1 MiB
  snapshot under state_mutex_) - now rate-limited to one serve per
  source IP per 60 s with a bounded rate map (regression pinned by the
  second-connect branch of RetentionServedOnConnect); P2-3 a parked
  frame's retry MISMATCH was scored against the constant "parked-retry"
  label, voiding the strike - ParkedFrame now carries the origin label;
  P2-4 witness_withhold_score_ is bounded (1024 entries, first-key
  eviction); P2-5 send_witnesses_to now sends on an F_DUPFD_CLOEXEC dup
  of the peer fd so an owner-thread close cannot recycle the fd mid-send
  (the pre-existing same-shape pattern in broadcast_witnesses_for is
  noted as residual). Honest residual: bans remain keyed on the
  connection label (ip:port), so a reconnect on a new ephemeral port
  starts with a clean score - durable identity-based bans wait for a
  richer handshake (node_id is still 0); the state_mutex_-held 1 MiB
  snapshot is rate-bounded, not eliminated.

### 2.8 Seed canonicalization: fail-closed format at the CLI/RPC surface (degeneracy hunt, 2026-11-05 — first findings fixed in v0.0.10)

Hunt suite: `tests/test_attractor_degeneracy.cpp`. Findings, in order of
severity:

- [x] FIXED (v0.0.10): invalid hex parsed SILENTLY to zero.
  `mpz_class::set_str` ignores parse failures, so every non-hex seed
  ("zz...", "12g4", a typo) became 0 and collapsed into the zero-seed
  address — any garbled wallet derivation landed on one known key.
  `hexToBigInt` now validates character-by-character and throws
  (fail-loud), including the partial case (valid first half, garbage
  second half silently zeroed Y_0 before).
- [x] DELIVERED 2026-11-05 (v0.0.12) at the RPC surface:
  `VortexAttractor::canonicalSeedError()` + a 400 gate in the
  crypto-lab endpoint. Refused classes: non-hex, over-length (the
  truncation degeneracy), the uppercase 0X prefix, the all-zero seed.
  E2E-verified against a live node (garbage/zero/overlong -> 400,
  canonical vector -> 200). Shorter-than-canonical seeds were still
  accepted in v0.0.12; SUPERSEDED in v0.0.15 for the zero-trunk
  sub-class (seeds of ≤256 hex chars derive a zero Y trunk — refused;
  see 2.10). Seeds of 257..511 hex chars remain accepted (nonzero
  right-padding degeneracy, pinned in the suite).
- [x] The zero seed has a fixed, findable address
  (NFA_V6_USaRKlmk3c_EfXuVbtfVfwzyd2QEQKZLyL7VbKIIAA with classic
  moduli). The state does not collapse (Z_0 = PHI != 0), but a
  derivation surface should refuse the all-zero seed outright.
- [ ] Seeds longer than 512 hex chars are TRUNCATED; a 2048-bit seed
  and its 1024-bit truncation map to the same address. Seeds shorter
  than 512 chars are RIGHT-padded with '0'; "12" and "1200...0"
  collide. The preimage-space accounting in docs/ADDRESS_SECURITY.md
  (2^2048 seeds) holds only for CANONICAL 512-char seeds.
- [ ] Prefix handling is case-asymmetric: run() strips a lowercase
  "0x" before padding (prefix excluded from the seed budget), an
  uppercase "0X" is not stripped and consumes two chars of budget.
  A fail-closed seed format accepts exactly one canonical spelling.
- [x] Clean results: the zero seed never collapses the state; orbit
  hunt (40 pseudorandom seeds x 1000 iterations, deterministic
  VortexSponge256-generated) — no address collisions, no all-zero
  digest; xorFold index coverage is a bijection onto the 32 digest
  bytes; palindrome seeds produce identical locked/unlocked addresses
  (pinned, expected by construction).
- Where the fix lives: NOT in the attractor (the derivation itself is
  frozen by the canonical vectors) — in the CLI/RPC surfaces that feed
  it, which must validate canonical form and reject everything else.

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

## Items opened from the owner session of 2026-11-05 (late evening)

### 2.12 Orbit-length proof work for the trunk dynamics (fundamental Q1)

- Status: NOT proven. Owner-verified corrections (2026-11-05, late
  evening) are folded in; the system is formally DISSIPATIVE, not
  conservative.
- Conservative-claim corrections:
  - (a) The reference set matters. secure_crt() (the production set,
    proven primes) has v2(P-1) = 2, v2(Q-1) = v2(R-1) = 3 — i.e. P-1 =
    4 x odd for P, 8 x odd for Q and R. The classic() set has v2 = 1
    everywhere. Any cycle-length work computes orders over the ODD part
    of the relevant (M-1)/2^k.
  - (b) The step state is a raw 1024-bit vector; XOR/rotl/add keep it
    there bijectively. The dissipation seam is the mod-M REDUCTION
    inside each step's cube (pow3_mod): values in the tail
    [M, 2^1024) fold back into [0, D-1), D = 2^1024 - M (~2^64 wide),
    colliding with resident values - a weakly-contracting 2-to-1 seam
    with per-step probability ~2^-960. No strict phase-volume
    conservation theorem is possible; Pollard-rho O(sqrt|space|)
    remains the generic bound.
  - (c) SUPERSEDED, honest correction: the release-note spelling
    (x^Phi_lock)*7+13 reads like a power map, but ^ in the code is
    bitwise XOR (one AST, one language). There is NO exponent in the
    step or the lock - only ACT I's Z_0 cubing. XOR with Phi_lock is a
    bijection on Z_2^1024; the gcd(PHI, M-1) numbers are therefore
    irrelevant to the dynamics. The real dissipation is the mod-M
    REDUCTION seam, and the owner's constructive collision on it is
    CONFIRMED (see (e)).
  - (d) The classic() moduli set is COMPOSITE (all three, verified
    with a strong probable-prime test, 2026-11-05). Production
    derivation (run(), genesis, PoGW) uses secure_crt and was never
    affected; the v0.0.16 release moved the seed gate off classic()
    onto active_default() so the validation surface interrogates the
    same moduli as the derivation (surface/derivation mismatch fixed).
  - (e) P0-CANDIDATE (confirmed by verification, not fixed yet):
    CONSTRUCTIVE COLLISION at every mod-M reduction seam. For any
    u in [M, 2^1024) with x1 = u ^ Phi_lock < M and
    x2 = (u - M) ^ Phi_lock < M (both canonical, distinct - holds for
    every Phi_lock variant sampled, 10/10), the lock computes
    (x1 ^ Phi_lock)*7+13 == (x2 ^ Phi_lock)*7+13 (mod M): exactly
    D = 2^1024 - M pairs glue per call. The same seam exists INSIDE
    every step through pow3_mod's mod-M reduction of the full-range
    arx inputs (the step itself never reduces mod M after XOR/rotl;
    states live bijectively in Z_2^1024 until the cube). Practical
    severity is LOW today - steering the attractor to a chosen state
    pair requires inverting 1000 rounds (preimage-hard), and sponge
    preimage resistance keeps mining unexploitable - but the
    "derivation is injective" claim is formally DEAD: the derivation
    is many-to-one at every reduction seam (~2^-960 per step).
    Fix candidate (owner): Conditional Involution Guard -
    candidate = x ^ Phi_lock; mixed = (candidate < M) ? candidate : x;
    next = (mixed*7+13) % M - a cmov bijection, plus the same
    canonicalization inside pow3_mod. Migration discipline applies
    (BACKLOG 2.9): the derivation is frozen, the guard changes outputs
    only on the ~2^-960 tail, genesis vectors must be re-pinned
    byte-identical before any adoption. Decision + tests = next
    session; do not rush the fix.
    RESOLVED AS ANALYSIS (2026-11-06, P0 closed): full formal analysis
    landed as docs/CRT_COLLISION_ANALYSIS.md with deterministic pins in
    tests/test_crt_seam_theorems.cpp (VortexCrtSeamTheoremsTest).
    Key results: fold measure D(M) = 2^1024 - M per full-range
    reduction (pigeonhole minimum; P: 2^64+1747, Q: 2^888+3943,
    R: 2^512+267799); 3005 full-range reductions per 1000-iteration
    derivation (2 z0 + 3000 cubes + 3 lock); Guard proved injective on
    canonical inputs but RELOCATES the fold family - for branch-B states
    (x ^ Phi >= P) the glued pair becomes (x, (x mod P) ^ Phi); the
    original (u, u-P) family is killed, an equally constructible family
    persists (20/20 verified). CORRECTED per-derivation exposure: the
    earlier P-only union bound of 2^-947 applied DELTA(P) to every seam;
    the honest Q-seam-dominated total is < 2^-126 per derivation
    (1001 x 2^-136), still an exposure bound with no known
    seed-exploitation path. DECISION: derivation stays frozen (many-to-one
    KDF by construction); the Guard remains a documented candidate tied to
    the genesis migration protocol, not adopted.
- Work items: (a) compute ord_P(7) and the affine-coefficient orders
  over the odd part of each (M-1). FIRST MEASUREMENT (2026-11-05,
  P_secure): P-1 = 2^2 x 83 x 3769 x 3218807 x C, C = 1004-bit COMPOSITE
  (unfactored; trial division to 10^7). The cofactor needs ECM/PARI or
  a GMP-based hunt next session before the owner's Miller-Rabin
  certificate (7^((P-1)/C) != 1 => ord has a divisor from C) can land;
  without C's factorization no lower bound above 2^64 is claimed yet -
  honestly NOT established; (b) empirical orbit-length probes
  over random starts, hunt for cycles below 2^64; (c) if any short
  cycle is found, the derivation must be re-pinned; (d) document
  Pollard-rho O(sqrt|F|) as the generic bound, not a guarantee; (e2)
  NAMED OPEN PROBLEM (2026-11-06): a solver for XOR/addition condition
  systems joined across a mod-M fold - the ARX toolbox (S-systems,
  ARX Toolkit, hashclash) does not cover the cube-mod-prime layer;
  tracking in docs/CRT_COLLISION_ANALYSIS.md section 8.
- Mining impact: PoGW search enumerates seeds (sponge), not step-map
  iterations; sponge preimage resistance keeps short attractor cycles
  unexploitable for block difficulty. 100/100 distinct top-384
  projections measured (fold probe, this session).

### 2.13 Gas model design note (fundamental Q2) — CORRECTED

- CORRECTION (same night, verified in code after the first answer was
  sent): the first answer claimed VX ships no VM and no gas metering.
  WRONG. VortexVM exists (src/vm/vortex_vm.cpp, VX-ASM, ~28 opcodes)
  with deterministic integer metering:
  gas(step) = base_opcode_cost(op) + erased_bits * 960 + flips * 3.
- Verified answers to the owner's Q2, in code:
  - base_opcode_cost is >= 1 for EVERY opcode, including the fully
    reversible ones (XOR/AND/OR/ROTL = 1, ADD/SUB = 3). A
    "Reversible Infinite Loop" therefore pays >= 1 per step and halts
    out-of-gas like any other loop - the reversible free ride is
    priced away by the floor. No zero-cost opcode exists.
  - The Landauer term is a deterministic PROXY: erased_bits counts
    1->0 transitions between register/stack snapshots, scaled by a
    constant (960 micro-units). It mimics Landauer's form but is
    computed from execution state, not measured joules - consensus
    cannot verify physics, and does not try. The boundary between
    thermodynamics and EVM-style gas passes exactly here: the cost
    MODEL is thermodynamic-inspired; the metering is deterministic
    integer arithmetic, reproducible across validators.
  - Honest framing for docs: "Landauer gas" is a cost model name, not
    a physical claim. README wording should not imply measured heat
    (README sync item below).
- Open: gas is not yet wired into consensus acceptance (no tx-level
  gas accounting end-to-end); pinning that gap is part of the Q2-Q4
  Phase 1 directive.

### 2.14 ZK aggregation path decision (fundamental Q3)

- Verified 2026-11-05 against the production secure_crt() set:
  v2(P-1) = 2, v2(Q-1) = v2(R-1) = 3. No NTT subgroup beyond order 8
  exists in any of the three fields: classic multiplicative-subgroup
  STARK/FRI is algebraically dead on them, naively O(N^2). (The
  classic() set has v2 = 1 everywhere but is composite - see 2.12(d);
  it is not a design target.)
- Decision point for any future witness/state aggregation (ties into
  2.11): prefer (a) Circle-STARK-style construction over these same
  low-2-adicity fields (that regime is exactly what Circle STARKs were
  designed for), or (b) Binius over F_2^k towers. Non-native arithmetic
  emulation in a foreign field is the last resort (million-gate
  multiplications). ZK is not on the roadmap before 0.1.8.

### 2.15 MemoryVault flush-pressure measurement (fundamental Q4)

- Status: honestly NOT profiled. No PMU/uncore counters were ever run
  under combined mining + signing load; the interconnect-saturation
  concern is plausible but unmeasured.
- Constraint: cache-local overwrite alone is NOT sufficient for the
  zeroization promise - lines must reach DRAM or they survive in cache
  after "erasure" (remanence exposure). clflush/clflushopt is the
  mechanism, not an accident.
- Work items: (a) perf-stat profile with uncore/interconnect counters
  under 8-16 mining threads + RPC signing; (b) batch zeroization to
  teardown/free boundaries instead of per-operation where the threat
  model allows; (c) evaluate CPU-affinity isolation of the signing
  arena from mining threads (cgroup/affinity, isolcpus as a deployment
  note); (d) clflushopt vs clflush latency/pressure comparison.

### 1.4 refinement: page-descriptor false sharing (owner, II.1)

- PageState descriptors in a dense array share cache lines under
  parallel access. alignas(64) per descriptor + a static assert on
  sizeof, so concurrent per-page atomics never contend on one L1 line.

### 1.4 refinement: get_stats() without a global lock (owner, II.1)

- Read statistics as a snapshot sweep over the PageState array with
  memory_order_acquire, no global lock. Documented honesty: this yields
  an eventually-consistent snapshot, not a cross-counter atomic read;
  a seqlock is the upgrade if a consistent snapshot is ever required.

### 2.11 refinement: shutdown(fd, SHUT_RDWR) on SSE drop (owner, II.2)

- v0.0.14 removes a slow SSE client from the broadcast list but does
  not wake the connection thread's poll(); the fd lingers until the
  client disconnects. shutdown(fd, SHUT_RDWR) is safe cross-thread
  (touches socket state, not the fd table - zero FD-reuse risk) and
  wakes poll() via POLLHUP so the owning thread closes the socket
  itself. Strictly better than the shipped drop-only behavior.

### 2.3c refinement: acquire barrier in debug_verify_page_zeroed
(owner, II.3)

- The test seam must read the page state with memory_order_acquire and
  verify the BURNED state BEFORE reading raw arena bytes; otherwise the
  seam can observe a page before the final clflush completes.

### 1.5 addition: XMSS per-window leaf cache (owner question)

- Status: IMPLEMENTED (thread_local, two direct-mapped slots, 512 bytes
  per window, memory-only, never persisted). P1 KEY DECLASSIFICATION
  DONE (2026-11-06): master_sk no longer rests in the cache - the slot
  key is an opaque 256-bit generation tag sponge("VX_PQ_CACHE_GEN_V1" ||
  master_sk || pub_seed) recomputed from live key material on every
  lookup. Object-address reuse cannot alias a slot (no pointers in the
  key); pq_sign_rollover invalidates explicitly (pq_leaf_cache_invalidate,
  also exposed publicly); warm/cold byte-identical witness pinned in
  test_pq_rollover section 12 - a stale digest can never be served as
  success. Honest note: auth-path sibling hashes are still recomputed
  per signature, but they are cheap node hashes, not chains.

## 0.1.x beta gate (drafted 2026-11-07, owner ladder: witness root -> leaf cache -> 0.1.8 -> DKSAP)

The witness-root and leaf-cache ladder items closed on 2026-11-07
(2.11 stages 1+2; the per-window leaf cache shipped 2026-11-06). This
section pins what must be TRUE before the version scheme moves from
v0.0.x to beta 0.1.x. Drafted from the open P0/P1 items - the owner
amends the list as needed.

- [x] **2.11 first-seen binding path** — CLOSED (2026-11-07): the
  checkbox was stale. The self-certifying binding path (is_pq_address
  branch in ledger_state, present since 589f38a) already binds a
  brand-new remote PQA sender on its first witnessed spend; the new e2e
  test RemoteFirstSpendBindsAndContinues pins it (park -> witness
  arrives -> frame applies -> binding persists). Residual (policy, not a
  blocker): classic (non-PQA) addresses have no remote onboarding path.
- [x] **1.5 P0 GATE: cert delivery/backfill** — CLOSED (2026-11-08,
  see 1.5): CERT_INV (0x0B) / GET_CERTS (0x0C) over VX60, deterministic
  cert ids, fresh-flag relay, connect-time inventory announcement inside
  the retention rate gate, full-verification-only intake. Residual: no
  per-peer GET_CERTS rate limit beyond payload bounds; live-peer deep
  history (>1024 certs) needs the sidecar-scan fallback (P3, tracked
  above).
- [x] **1.5 wallet policy** — CLOSED (2026-11-11, owner sign-off "fastest
  to ship AND most secure"): (A) soft trigger — one-shot SSE
  "rollover_advised" push at >= 12/15 burned transaction leaves per key
  root, NO automatic rollover anywhere in the node; the owner-triggered
  POST /api/wallet/rollover (auth-gated mutating endpoint) walks the
  certified chain for the account, signs the (from -> from+1)
  certificate with leaf 15 burned fail-closed in the durable leaf ledger
  BEFORE signing, registers it and broadcasts the FULL record
  (ROLLOVER_CERT) so the cert is on the network before the first
  window-1 spend. (B) verifier chain walk — was already wired (LedgerState
  apply + consensus_witness_root); now pinned by tests 15/16 in
  test_pq_rollover_wiring. Sign-side window policy: pq_sign_transaction
  signs ONLY the walked window (nonce = (window << 4) | leaf); a
  certified rotation RETIRES the old window on all three sides (signer,
  ledger verifier, block producer). (C) leaf-log widening — OBSOLETED,
  not shipped: the premise ("the 33-byte record cannot address window-1
  leaves") described anchor-root keying; reservations are keyed by the
  SIGNING window's root, and distinct windows have distinct roots, so
  the headerless 33-byte format already addresses every leaf of every
  window — dropping a store-format migration removes its risk instead of
  adding it. Residual: PQA (self-certifying) addresses commit the
  window-0 root, so a rolled window still needs re-anchoring on a fresh
  address (unchanged, by construction). Retirement convergence is NOT
  self-healing (security review P2-1, 2026-11-11): a window-0 tx signed
  BEFORE the rollover and submitted AFTER the cert exists is refused by
  cert-holding nodes while a cert-less node can seal and apply it at the
  same height — cert-holders then see MISSING_WITNESS forever for that
  frame (a retirement refusal is not parkable witness-lag) and GET_CERTS
  backfill spreads the refusal, it does not heal the already-applied
  block. Not attacker-triggerable (producing the witness needs the
  owner's key, and the owner's own signer refuses retired windows) —
  eclipse-assisted operator error at worst. Follow-up: classify
  retirement-refused frames as attributable refusals rather than parkable
  witness-lag, and track cert coverage in fork choice when reorg/
  fork-choice work lands.
- [ ] P3 (security review 2026-11-11): certificate-slot griefing —
  register_rollover_cert caps 32 certs per sender; junk certificates
  under a victim's sender (attacker's own lineage — inert for consensus)
  durably fill those slots so the VICTIM's own rollover registration
  refuses with 409 forever. Reachable already via the ROLLOVER_CERT wire
  path (no auth); the wallet RPC adds a convenient trigger, not a new
  capability. Fix candidates: prune stored certs whose old_root does not
  chain from the sender's known anchor, or key the per-sender cap by
  (sender, old_root).
- [ ] P3: RingPipelineThroughputNoAllocs floor is TSan-lane flaky — the
  500k ops/s throughput assertion lands ~9% short under ThreadSanitizer
  instrumentation on the dev machine (452-458k observed; reproduced on
  clean HEAD, pre-existing — NOT a regression of the wallet-policy
  diff). Assert and SAN lanes pass the same test. Options: a TSan-
  aware floor (env-multiplied) or a pipeline warm-up, pinned to the
  next test-infra pass.
- [x] **2.11 third checkbox: retention window + withhold ban/score** —
  CLOSED (2026-11-07): every newly promoted peer gets the witnesses of
  the last 16 stored blocks re-served (serve_witness_retention ->
  send_witnesses_to, one-shot per promote()), and the MISMATCH path now
  feeds report_withhold(peer, 34) - three strikes cross the >=100 ban
  threshold and the health loop disconnects the peer. Honest residual:
  bans are keyed on the connection label (ip:port); a reconnect on a
  fresh port starts clean until a richer handshake carries a durable
  node identity.
- [x] **2.6 WAL flock residual** — CLOSED (2026-11-08): the BlockStore
  ctor takes an exclusive non-blocking `flock` on the ledger descriptor
  before any recovery runs - a second instance on the same ledger file
  fails closed at startup ("held by another instance") instead of racing
  the WAL INTENT window (each instance's recovery would heal/truncate
  the other's in-flight append). The lock lives exactly as long as the
  descriptor (released by close on every path, including the ctor error
  paths). Pinned by `VortexWalMarkerTest.SecondInstanceFailsClosedOnFlock`
  (intruder refuses with the named diagnostic, the lawful instance keeps
  appending, sequential reopen succeeds). Caught by the project's own
  gates during development: the full-lane rerun failed
  `VxCrashTortureTest.Level1StoreTailTruncation` - the ctor's
  validate_region throw path ran after `ensure_mapping` WITHOUT munmap,
  and a memory mapping keeps the open file description (and with it the
  flock) alive even after close(), so a refused open left a phantom lock
  the whole process could not reopen through (kernel-verified with a
  minimal repro: open -> flock -> mmap -> close -> flock-by-new-descriptor
  = EAGAIN). Fixed: the post-mapping throw path munmaps before closing;
  the genesis-seed throw paths now close the WAL descriptor too; new pin
  `VortexWalMarkerTest.RefusedOpenReleasesFlock` (refuse at bad-magic ->
  truncate -> reopen succeeds).
- [x] **2.11 refinement: SSE drop shutdown(fd, SHUT_RDWR)** — CLOSED
  (2026-11-08, owner II.2): a dropped SSE client's connection thread used
  to keep polling a subscription nothing was pushed to (the drop relied
  on the client eventually noticing). The drop path now calls
  ::shutdown(fd, SHUT_RDWR) - NOT close: the connection thread owns the
  fd and detects the disconnect in its poll loop - so both ends terminate
  deterministically; membership is re-checked under sse_mutex_
  immediately before each shutdown (see the review P2 below). Exercised
  by `VortexSseDropTest.DroppedClientBranchKeepsPushAlive`: a subscriber
  that dies with a hard RST (SO_LINGER {1,0}) is reclaimed without
  wedging or SIGPIPE, the server survives, and a fresh subscriber still
  receives the hello and a live push event.
  Honest limits (recorded in the test header): (a) the refinement's own
  observable - the FIN the dropped client receives - is not pinned by
  the suite; proving it requires real TCP backpressure, which on loopback
  fights send-buffer autotuning and would make the test
  timing-dependent; (b) branch reach is a race - after the RST the
  server-side connection thread usually observes it in poll first and
  reclaims the fd itself (the correct outcome - broadcast then finds
  nothing to drop); the branch runs only when the broadcast send loses
  that race. Residual (inherent to fd-number identity, bounded): if the
  exiting thread's erase + close + a new SSE accept + its push-back all
  complete inside the drop loop, the new connection holding the same
  number is shut down - it reconnects via EventSource retry; no state
  corruption.
  The new suite also caught a REAL pre-existing defect before commit:
  HttpServer::stop() closed the listening socket while the accept loop
  was blocked in accept() - close() does not wake a blocked accepter on
  Linux, so stop() hung forever on the accept-thread join. stop() now
  ::shutdown()s the listening socket first, then closes.
  Security review of the same diff (adversarial, zero-trust, run BEFORE
  commit) - all fixed in this commit:
  - P1 (pre-existing, remote process kill): send_response used a
    flags=0 ::send and the tree never disposed SIGPIPE - a client that
    sent a complete request and RST before the response send got EPIPE ->
    default-action SIGPIPE -> the whole node died, remotely triggerable
    on any endpoint. Fixed both ends: MSG_NOSIGNAL on send_response and
    process-wide SIG_IGN(SIGPIPE) in main.cpp (covers the flag-less
    paths such as the sendfile block relay; every write path already
    treats EPIPE as an error return).
  - P1 (the diff's own): test_sse_drop was registered in the
    -UNDEBUG foreach before its add_executable - CMake configure would
    fail. Reordered (caught by the review, not by a build).
  - P2: the SSE shutdown could land on an fd number the connection
    thread had already closed and the accept loop recycled (a plain-HTTP
    victim's response would be truncated - and with the flags=0 send
    above, was remotely process-fatal). Membership is now re-checked
    under sse_mutex_ immediately before each shutdown.
  - P3 closed: a non-std exception from write_genesis_file leaked both
    ctor descriptors (catch (...) added); the close(wal_fd_) on the
    wal_fd_ < 0 path dropped.
  - TSan round (found by the TSan lane rerun on the same tree, 40/41
    before the fix): two data races in the stop path - (a) server_fd_
    was a plain int read by the accept loop on every iteration while
    stop() wrote it (now std::atomic<int>); (b) stop() closed SSE fds
    owned by detached threads and returned while detached threads could
    still touch members that die with the object. Fix: stop() only
    ::shutdown()s SSE fds (the owning thread keeps fd ownership), and
    detached connection threads - SSE AND plain HTTP, both touch
    object-lifetime state - are counted by the accept loop BEFORE
    detach() (a thread not yet scheduled is still accounted) and
    drained by stop() with a bounded 2 s wait; handlers decrement on
    every exit path through an RAII guard, spawn failure un-registers.
    The first draft incremented the counter inside the handler, leaving
    a window where stop() could drain a zero count while a detached
    thread had not started yet - caught by self-review, registration
    moved into the accept loop where the joinable accept thread orders
    it before stop(). Final: assert/SAN/TSan all 41/41 on one tree.
- **Public binary surface pass (owner-agreed 2026-11-11)**: before the
  beta flip, walk the entire public surface of the shipped binary as an
  attacker - every RPC endpoint (including the fuzz/chaos/flood handlers,
  which are behind the auth gate but still compiled in) and every CLI
  utility - and remove or hard-gate anything that has no business in a
  public build. Related residuals discovered with peer discovery
  (2026-11-11): loopback acceptance in `add_addr_candidate` is a
  localhost-SSRF/probe primitive on a real network and must gain a
  default-off switch together with real-interface advertisement in
  `bind_p2p_listener` (testnet keeps loopback: the three-node topology
  depends on it); strike/withhold keying is still by connection address,
  not node_id, and no durable banlist exists (designed-but-unwired - see
  the honest gap note in swarm_node.hpp).
- Owner-decision items (NOT beta blockers, tracked in the Q2-Q4
  directive): the 2.12(e) Guard decision, ord_P(7) ECM analysis, the
  CRT-collision formal proof. These gate the NEXT major release, not
  the beta flip.
- Versioning note: the flip itself is a release-engineering act
  (scripts/make_release.sh, version scheme 0.0.x -> 0.1.x); it happens
  only when every box above is checked and all three lanes are green
  on the release tree.

## Owner priority table for the next release (audit of v0.0.16, 2026-11-05 late)

Verdict: positive on the architecture changes; praise for freezing the
derivation instead of rushing the Guard ("the cost of an error in key
material generation logic far exceeds the productivity loss"). Do NOT
rush v0.0.17 - first XMSS state safety and CRT collision analysis.
"31/31 tests is proof of passing 31 test suites, not proof of the
system's cryptographic security."

- P0 CRT-derivation collisions: formal analysis - collision condition,
  minimal counterexample, the Guard's exact domain, proof the Guard
  changes nothing outside its domain, impact on every canonical seed,
  cross-platform determinism. The 2^-960 tail must be confirmed
  MATHEMATICALLY, not statistically. (Ties into 2.12(e).)
- P0 XMSS leaf uniqueness: DONE (2026-11-06, sections 8-11 of
  test_pq_rollover.cpp): (1) crash after reserve+fsync before signing -
  the leaf stays burned after a reopen, the same request lands on the
  next leaf; (2) crash after signing before the tx persists - no leaf
  resurrection, the account continues on the next leaf; (3) 16 threads
  racing one request - 15 distinct leaves (0..14), one refusal, leaf 15
  never assigned under any schedule; (4) two ledger objects on one data
  directory (flock + re-parse) - no double assignment; rollback never
  returns a reserved leaf to the pool (no release API exists; the burned
  set only grows). 32/32 ctest suites green.
- P1 thread-local leaf cache: DONE (2026-11-06). master_sk is out of
  the cache key entirely - the slot key is an opaque 256-bit generation
  tag (sponge over the key material, recomputed per lookup, no secret
  bytes at rest); pub_seed + window stay public plaintext parts of the
  key; pq_sign_rollover invalidates explicitly (pq_leaf_cache_invalidate
  is also public); object-address reuse cannot alias (no pointers in
  the key); warm/cold byte-identical witnesses pinned (test_pq_rollover
  section 12) - the cache can never alter an output, so a stale digest
  cannot surface as success.
- P1 seed validation: DONE (2026-11-06, T8 of VortexCrtSeamTheoremsTest).
  Single-set discipline pinned structurally: active_default() IS
  secure_crt() (field-by-field), the constants live only in
  include/vx/core/types.hpp, src/ references classic() in comments
  only, and tests use it as the declared fixture. Prime certification
  now runs IN-REPO: GMP trial division + 50 Miller-Rabin rounds per
  modulus, documented error probability <= 4^-50 < 2^-100 each - this
  also pins Theorem 6's hypothesis (cube-map bijectivity requires
  prime moduli). The classic fixture set is pinned COMPOSITE
  (definitely-composite verdict for all three), so it can never
  silently become a derivation set.
- P1 genesis migration: DONE (2026-11-06, docs/DERIVATION_MIGRATION.md
  ratified as process): DERIVATION_VERSION = 1 marker; version-1
  reference vectors pinned (4 vectors x full 3072-bit final states +
  both addresses, unlocked and locked orientations); vector-dump and
  label-by-label comparator pinned in test_derivation_migration; rule
  "no silent edit - versioned migration only"; fail-closed foreign-
  version refusal, dual-verification windows are explicit owner
  decisions. First customer: address-format v2 (BACKLOG 2.17).
- P2 XMSS benchmark: DONE (2026-11-07, tests/bench_pq.cpp, target
  bench_pq, manual - not a ctest gate; figures recorded in
  VERIFICATION_EVIDENCE Appendix H). Exact measured figures (Release,
  GCC -O2, two runs): cold window build ~8.4-9.9 ms mean (one-time
  per-window 16-leaf initialization), cold sign ~9.4-10.4 ms, warm sign
  ~0.34 ms, warm verify ~0.28 ms, warm verify/warm sign ratio ~1.2x.
  THE 8.5/0.3 = 28.3x (or 30.6x) ARITHMETIC IS SUPERSEDED: 8.5 ms is
  the cold window build and 0.3 ms the warm verify - the ratio compared
  initialization to verification. Verification's real advantage is
  structural (no secret key, no leaf burn, runs on every node), not a
  ~30x speedup.
- Documentation drift: RESOLVED (2026-11-07 audit): the Landauer gas
  prose is ACCURATE (VortexVM ships deterministic metering
  base_opcode_cost + erased_bits*960 + flips*3 - BACKLOG 2.13 corrected
  account); the Vault model prose is ACCURATE (MemoryVault shipped,
  Nakamoto Vault the opt-in edition); the only real drift was the test
  count (README said 32 targets - now 35 targets / 36 ctest entries,
  fixed). README/BACKLOG stay in sync going forward; every release
  notes update cites tag + commit + zip.
- Note: the owner could not independently confirm the v0.0.16-alpha tag
  contents; future reports must cite tag + commit hash + zip together.

### 2.16 OPSEC_SOVEREIGN_SHIELD — owner directive, 2026-11-06 (CLOSED this session)

Owner directive: absolute forensic, network and regulatory sterility of the
repository — no byte of code, binaries, Git metadata or docs may deanonymize
the author or ground a regulator's claim. Six invariants, all verified in
this session:

- (1) Git metadata sterilization: commits are born UTC — `TZ=UTC` +
  `GIT_AUTHOR_DATE`/`GIT_COMMITTER_DATE` epoch `+0000` via the new
  `scripts/commit_utc.sh`; `git config core.hooksPath scripts/hooks` wires
  the new gates. `scripts/hooks/pre-push` blocks any push whose outgoing
  commits carry a non-`+0000` author/committer offset. Historical commits
  and tags are `+0100` (host CET) and stay: rewriting them would break the
  frozen release hashes — the gate applies from this commit forward.
- (2) Zero-leakage build & release: `CMakeLists.txt` now maps source and
  build dirs to relative paths in `__FILE__`, assert text and debug tables
  (`-ffile-prefix-map` / `-fdebug-prefix-map` / `-fmacro-prefix-map`).
  Release archives switched to deterministic `git archive` (commit-timestamp
  mtimes, uid/gid 0, no host filesystem metadata) with a `.sha256` sidecar:
  `scripts/make_release.sh`. v0.0.15-alpha (c708d91) and v0.0.16-alpha
  (537f37d) zips were regenerated retroactively and re-uploaded together
  with their `.sha256` and a SHA-256 "Archive verification" section in the
  GitHub release notes (checksum = integrity; GPG tag = authenticity).
- (3) Network invariant: `scripts/opsec_scan.sh` gates the whole published
  surface on host-absolute user paths (Linux and macOS homes), private-range
  IPs and Cyrillic — with two documented exceptions (127.0.0.1 loopback
  defaults; the marked 10.0.0.x SIMULATION fixtures in swarm_node). Scan
  result: clean. Default configs carry no personal bootstrap IPs (seed
  lists are loopback/empty by design); no hardcoded author IP in history.
- (4) Regulatory immunity: code audit — no admin keys, no dev fee/treasury
  address, no centralized coordinator, no forced rollback/freeze anywhere
  in src/ (grep-verified; now a standing claim, BACKLOG/README "protocol
  neutrality"). LICENSE rewritten: the "Cypherpunk anti-state clause" was
  REMOVED (as a non-removable additional restriction it violated AGPLv3
  §7 and exposed the author) along with the "sovereign/anonymous"
  rhetoric; added: Mathematical & Academic Specification Only, $0.00 total
  liability cap, Strict Exclusion of Fiduciary Duties, Mandatory User
  Indemnification, auditable Protocol Neutrality, and a historical note
  recording the clause removal.
- (5) Anti-stylometry: `.clang-format` checked in; `scripts/hooks/pre-commit`
  enforces clang-format on staged line ranges (incremental — no big-bang
  reformat of frozen consensus code), plus the Cyrillic/path/IP diff gate.
  Commit messages follow Conventional Commits, dry technical English.
- (6) Tree revision: complete; this BACKLOG entry is the session checklist
  record. Ongoing duty: every future commit goes through the two hooks +
  `commit_utc.sh`; every future release through `make_release.sh`.

### 2.17 P0 FINDING: address digest carries 128 bits, not 256 (palindromic xor-fold)

- FOUND (2026-11-06, during the genesis-migration vector work; flagged
  first as a visual base64 pattern, then confirmed on raw digest bytes,
  pinned 32/32 in test_digest_uniformity / VortexDigestUniformityTest).
- Root cause (src/math/galois_attractor.cpp, xorFold): for k = 0..15
  the fold writes out[2k] = mixed_k and out[2k+1] = nibble_swap(mixed_k)
  - every odd output byte is the nibble swap of the preceding even byte
  and carries zero information. Additionally only the TOP 128 bits of
  each 1024-bit state enter the fold at all (bytes 0..15 of the
  big-endian byte extraction).
- Consequences: address digest space 2^128 (not 2^256); birthday
  collision threshold ~2^64 accounts (not ~2^128); generic fold-preimage
  ~2^128 (not ~2^256); visible payload ~126 bits; and VX addresses are
  VISUALLY FINGERPRINTABLE - the (b, swapnib(b)) structure shows through
  the base64url body, so a VX address is recognizable among arbitrary
  base64 strings (linkability surface). docs/ADDRESS_SECURITY.md
  corrected with a dated section; the pre-correction 256-bit figures
  there are superseded.
- Not a practical break: 2^128 address space and ~2^64 birthday remain
  beyond any realistic account population, and seed preimage still
  requires inverting ~1000 ARX+sponge rounds. The damage is to the
  PUBLISHED CLAIMS (cardinal rule: never present a theoretical figure
  as a cryptographic guarantee) and to address stealth.
- DECISION: derivation, wire and address formats are FROZEN; no silent
  fix. The remedy is ADDRESS FORMAT V2 (fold through the sponge instead
  of the hand-rolled XOR) adopted via the genesis migration protocol
  (docs/DERIVATION_MIGRATION.md, VortexAttractor::DERIVATION_VERSION,
  pinned version-1 vectors, fail-closed old/new node separation) - the
  migration machinery this same session built. Version-1 vectors now
  exist to diff against.
- Status: DOCUMENTED AND PINNED (defect pin, not a fix pin); address v2
  awaits the owner's go, bundled with the migration protocol.
- UPDATE (2026-11-06, later): the VX2 PRIMITIVE IS BUILT AND COMMITTED
  (include/vx/math/address_v2.hpp + tests/test_address_v2.cpp +
  docs/ADDRESS_FORMATS_V2.md) - still ADDITIVE, not wired into consensus
  or the v1 wire; adoption stays gated on the owner + migration
  protocol. VX2 fixes the 2.17 narrow fold by construction (sponge
  digest over all 3072 final-state bits) and the 2.18 side-finding
  (NFA/OFA domain separation) by construction. The VX2 checksum survived
  two of our own adversarial redesigns before commit (order-31 alpha:
  bound void; order-93 alpha: exponent aliasing, 1794 undetected
  weight-2 pairs found empirically); the final design is a 135-bit BCH
  code over GF(2^9) with alpha of order 511 and a valid Vandermonde
  bound - every <= 6-symbol substitution detected, ~2^-135 residual.

### 2.18 DOC-VS-CODE DRIFT: the documented KDF stretch does not exist in the derivation path

- FOUND (2026-11-06, while walking the owner through a live derivation
  with a fresh 2048-bit demo seed): docs/ADDRESS_SECURITY.md sections 3
  and 6 describe the chain as "seed -> KDF stretch (VX_KDF_ITERS sponge
  rounds) -> attractor", and the wall table prices one preimage trial as
  "1000 iterations x 3 cubic maps + KDF". There is NO VX_KDF_ITERS
  anywhere in src/ or include/ and run() consumes the seed directly:
  split -> Z_0 -> 1000 steps. The attractor does not touch the sponge at
  all. (The grep hit "stretch" in emission.hpp is the emission schedule,
  unrelated.)
- Consequence: the per-trial cost claim is PARTLY overstated (the KDF
  term is fiction), but the wall itself is unchanged - one trial is
  measured at ~3 ms (1000 iterations x 3 modular cubings over 1024-bit
  generalized Mersenne moduli), and ~2^128 trials is astronomically
  beyond reach regardless. The drift is a claims-integrity violation of
  the cardinal rule, not a security loss.
- Side finding from the same walk: NFA and OFA share the IDENTICAL
  base64url body (both are formatted from one rawAddr string) - holding
  both address types of one identity is by construction a trivial link.
  Record for the address-v2 design: v2 should domain-separate the two
  formats (different fold tag per address type).
- Fix: correct ADDRESS_SECURITY.md sections 3 and 6 (drop the KDF term
  or specify an actual stretch as a versioned change); revisit whether a
  real KDF stretch SHOULD exist (it would raise bulk-attack cost per
  seed at wallet-open time) - that is a derivation change and goes
  through the migration protocol, not a doc edit.
- Status: OPEN (P2, documentation honesty).
