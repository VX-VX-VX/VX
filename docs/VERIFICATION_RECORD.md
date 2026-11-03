# VX Verification Record

A component-by-component account of what is proven about VX today, how, and
what is still open. This is the engineering companion to the security
validation plan: it follows the plan's own report format (specification,
assumptions, threat model, implementation, tests, limitations, status per
component) and its status vocabulary.

Other docs: [README](../README.md) · [whitepaper](../WHITEPAPER_V6.md) ·
[nodes guide](NODES.md) · [multi-node runbook](MULTI_NODE_RUNBOOK.md) ·
[backlog](BACKLOG.md) · [roadmap](../ROADMAP.md)

---

## Status vocabulary and the honesty rule

| Status | Meaning |
|---|---|
| Designed | The architecture is written down; no or partial code. |
| Implemented | There is real code behind the claim. |
| Tested | Reproducible tests exercise the property (unit, fuzz, live-run). |
| Verified | The property was confirmed by an *independent* party. |
| Audited | An independent audit with a published report exists. |

**Rule: internal testing never counts as Verified.** As of this record,
nothing in VX is Verified or Audited; the best any component can hold is
Tested. That is the honest ceiling until the independent review (BACKLOG
2.2) happens.

## Evidence base for this record

Everything cited below was produced by commands a reader can re-run:

- **Test suite:** 17/17 gtest tests pass (`ctest`, GCC and Clang in CI,
  plus an ASan+UBSan lane and CodeQL on every push).
- **Fuzzing:** three libFuzzer targets in CI (`fuzz_block_frame` 100k,
  `fuzz_pq_witness` 20k, `fuzz_wire` 200k execs, fixed seeds); the JSON RPC
  surface got its own target (`fuzz_rpc`, 200k in CI) in the same pass that
  produced this record.
- **Live multi-node:** `scripts/multi_node_test.sh` — a real 3-node VX60
  testnet, 10 checks (propagation convergence, garbage resistance,
  split-brain reorg), all green; 9 additional hand-run scenarios are
  recorded in [MULTI_NODE_RUNBOOK.md](MULTI_NODE_RUNBOOK.md).
- **Live RPC:** every response in [RPC_COOKBOOK.md](RPC_COOKBOOK.md) was
  captured from a running node; the hostile-input smoke for this pass
  answered clean JSON errors and kept serving.

## Independent replication (external review rounds 1-6)

Every defect listed below was first REPRODUCED INDEPENDENTLY by the
external reviewer — with their own proof-of-concept code, run against the
shipped library or a live node — before we fixed it. The fixes therefore
respond to demonstrated defects, not to theoretical ones, and each fix is
pinned by an automated regression so the replication stays checkable. The
reviewer's PoCs for rounds 3-5 ran standalone against `libvx_core.a`
(their note: the project's own ctest selection was incomplete on their
machine), which makes the reproduction independent of our test harness.

| Round | Independently replicated by the reviewer | Where the fix is pinned |
|---|---|---|
| 1-2 | RPC surface defects, including the two number-parsing crashes | `fuzz_rpc` battery + RPC hardening (§16) |
| 3 | Intra-block double spend minting phantom supply; mempool TOCTOU; phantom fsync acknowledgment | `DoubleSpendInBlockRejected`; single-critical-section mempool; append rollback (§6) |
| 4 | Genesis-v1 nonce replay; `tx_count` poisoning; unverified merkle field; miner draining mempool on a rejected block; RPC-controlled fee/nonce | `NonceZeroReplayRejected`, `OversizedTxCountRejected`, `TamperedMerkleRejected`; miner commit checks; node-stamped fee/nonce (§6) |
| 5 | Vault RPC plaintext exposure; HTLC VM-branch mismatch; GQC tail-stamp overlap; vault page clobber; 32-bit vault token digest; block id ignoring the tail; SSE descriptor leak; demo keys in fixtures; MemoryCore 4×32-bit digest | `HtlcVmFailureForcesLocked`, `VaultTokenDigestFullyChecked`, `VaultPoolFullNotClobber`, `TailMetadataCommitted`, sidecar GQC stamp (§5, §13, §16); WOTS+ leaf reuse was reported stale — already fixed by the durable leaf ledger |
| 6 (2026-11-03) | No-work blocks accepted on every intake path (the round-4 forged-merkle PoC now belongs to the same gate) | `NoWorkBlockAccepted` (flipped to EXPECT_FALSE), `PogwGateAcceptsSealedWorkAndBindsTheNonce`, `RecoveryRejectsCorruptedLedgerFrame` (§4, §6) |

---

## Executive summary

| # | Component | Status | Biggest open gap |
|---|---|---|---|
| 1 | WOTS+/XMSS PQ signatures | Tested | H=4 (16 leaves) is a demo parameter; tree rollover not designed |
| 2 | VortexSponge256 | Tested | No published cryptanalysis battery yet |
| 3 | Key generation & storage | Tested (demo grade) | Entropy-source argument; full per-format WIF roundtrip inventory |
| 4 | PoGW | Implemented | Wire frames are not re-verified (no PoGW check on the relay path) |
| 5 | GQC finality | Implemented | Shares unauthenticated; checkpoint not persisted across restart |
| 6 | State & transactions | Tested | Cross-node state-root equality not yet asserted in the testnet script |
| 7 | Vortex VM / Landauer gas | Implemented | Cross-CPU determinism argument not written |
| 8 | SGMT state trie | Tested | Two-node identical-state test pending |
| 9 | P2P network | Tested (lab) | Backfill sync, wire fork choice, peer auth |
| 10 | Privacy (Dandelion++, cocoons) | Implemented | No threat-model document; no source-tracing experiments |
| 11 | MEV shield | Implemented | No adversary simulation to measure |
| 12 | 64 KiB frame & mmap | Tested | Endian/OS portability argument not written |
| 13 | MemoryVault | Tested | TSan lane pending; mlock-failure semantics under low rlimit |
| 14 | Tokenomics | Designed | Full spec and simulations do not exist yet |
| 15 | Genesis determinism | Tested | Multi-OS/multi-arch regeneration proof |
| 16 | RPC & API security | Tested | No auth or rate limiting by design (demo surface) |
| 17 | Wallet & explorer | Partial | Wallet stack is demo-grade endpoints; no independent explorer |
| 18 | SDK / integrations | Not started | — |

Nothing is Verified; nothing is Audited. The nearest paths to changing that
are BACKLOG 1.3 (cryptanalysis battery), 2.1 (security-model write-up) and
2.2 (independent review kit).

---

## Stage 1 — Cryptographic foundation

### 1. WOTS+ / XMSS post-quantum signatures — **Tested**

- **Specification.** WOTS+ (w=16, L=67) over VortexSponge256, packed into an
  XMSS tree of height H=4; the full witness is 2376 bytes
  (`include/vx/crypto/pq_signature.hpp:36-37`).
- **Implementation.** `src/crypto/pq_signature.cpp`; signing runs inside a
  MemoryVault page, the key page is burned after use, the witness is
  registered in a sidecar.
- **Test suite.** `tests/test_pq_signatures.cpp`, including TEST 7: a
  Wycheproof-style negative-vector matrix — bit-flips, truncated witnesses,
  Merkle-path tampering, forward-chain forgery and a keyless rehash attack
  are each rejected by explicit assertions. The `/api/crypto/pq_verify`
  endpoint replays the same adversarial suite live and reports each
  rejection flag.
- **Security assumptions.** Security rests on the hash function alone
  (hash-based signatures carry no number-theoretic assumption) plus the
  correctness of the Sponge256 instantiation.
- **Threat model.** Forgery without the secret key; replay of mutated
  witnesses; Merkle path tampering.
- **Known limitations (important, stated plainly).**
  1. **Leaf lifecycle (fixed in `c1d6230`).** The leaf used to be derived
     from the tx nonce with no consumed-leaf state — a restored node could
     re-sign on the same one-time leaf, and concurrent signers could take
     the same leaf. Now closed by `PqLeafLedger`: consumed leaves are
     keyed by the key's XMSS root, persisted as fsync'd append-only
     records in `data_dir/pq_leaves.reg`, re-read under an exclusive
     flock on every reservation (threads and sibling processes
     serialize), a busy leaf resolves to the lowest free leaf, the 17th
     signature for a key is refused (RPC 409), and an unparseable log
     fails closed. Evidence and live runs:
     [VERIFICATION_EVIDENCE.md](VERIFICATION_EVIDENCE.md) §7. Remaining:
     per-key durable history lives in the node's data directory only —
     the 16-leaf capacity itself is still item 2 below.
  2. H=4 gives 16 one-time leaves — a deliberate test parameter, not a
     production configuration. The capacity question (how many signatures
     an account may emit per tree, and tree rollover) is designed but not
     implemented or justified numerically.
  3. No 1M-sample randomized positive/negative verification battery yet;
     the negative matrix is structured, not sampled.
- **Reproducibility.** `cd build && ctest`; the live suite is
  `curl -X POST localhost:PORT/api/crypto/pq_verify -d '{}'`.
- **Independent review.** None yet.

### 2. VortexSponge256 — **Tested**

- **Specification.** 12-round ARX sponge; keyed and unkeyed modes with
  domain separation for each protocol role.
- **Implementation.** `src/crypto/simd_accel.cpp` and the core headers;
  hardware CRC32C path is separate (wire only).
- **Test suite.** Known-answer tests (canonical vectors,
  `tests/test_vortex.cpp`, `tests/crypto_deep_tests.cpp`); the SAC
  avalanche matrix (flip one seed bit, count diverging state bits per
  round) is exposed at `/api/crypto/canonical` and asserted in tests;
  `fuzz_pq_witness` and `fuzz_wire` hammer it in CI.
- **Security assumptions.** This is a custom sponge. **No security
  reduction to a textbook problem exists.** The stated design intent is
  that the signature security rests on hash-based PQ primitives; the
  sponge's own strength is an engineering claim, not a theorem.
- **Known limitations.** Differential and linear cryptanalysis batteries
  are planned (BACKLOG 1.3) and have not been run; statistical tests never
  prove cryptographic strength — the independent review exists precisely
  because of this gap. Message-length and domain-separation edge cases are
  fuzz-covered but not formally argued.
- **Reproducibility.** `ctest`; `/api/crypto/canonical` returns the exact
  per-round avalanche trace for cross-implementation comparison.
- **Independent review.** None yet; first in the review priority order
  (BACKLOG 2.2).

### 3. Key generation & storage — **Tested (demo grade)**

- **Implementation.** 7-tier key matrix (`src/crypto/zk_key_matrix.cpp`:
  SK/FVK/IVK/OVK/TLMK/MSRK/EK), Shamir recovery, proof-of-life, IVK scan,
  stealth envelopes — all exercised via RPC endpoints and
  `tests/test_zk_matrix.cpp`. WIF encoding via `src/wif/wif_matrix.cpp`
  (compact runic pair, ghost WIF with cover text, hardware-locked WIF),
  exercised in `tests/crypto_deep_tests.cpp` and `tests/test_vortex.cpp`.
- **Test suite.** Derivation, IVK scan correctness, Shamir combine,
  proof-of-life; WIF encode/decode exercised. The masterplan's
  **per-format roundtrip inventory** (generation -> encode -> decode ->
  identity for every format, 17-format claim) is not yet formalized as a
  test of its own — consolidation candidate.
- **Security assumptions.** The demo path derives from the published
  canonical test vector (fixed seed) — safe to publish, not an entropy
  claim. Production entropy sourcing (OS CSPRNG, seed length, bias) is
  **not yet argued or measured**.
- **Known limitations.** The RPC is a demo surface and will happily derive
  from a caller-supplied seed (`/api/crypto/lab`); no public RPC endpoint
  returns seed material from the node's own state, which is the actual
  requirement. Secret-zeroization on the derivation path is not audited
  (see 13).

---

## Stage 2 — Consensus and chain integrity

### 4. PoGW (Proof-of-Genuine-Work) — **Implemented** (hash-based PoW prototype; NOT the promised mechanism)

- **Implementation.** `src/consensus/pogw_miner.cpp`; miner RPC endpoints
  exist; the demo block embeds an attractor commitment.
- **Honest naming (external review, confirmed in code).** The acceptance
  criterion today is *leading zero bits of a VortexSponge256 hash over
  the frame* — i.e. a hash-lottery proof-of-work prototype that USES the
  attractor in hashing but does not accept "work" on the attractor's
  evaluated cost. The README's "not a hash lottery" line describes the
  intended design, not this code. Difficulty is not yet anchored either:
  `calculate_difficulty()` assumes `prev_difficulty = 16` per call and
  uses `double`/`pow()` — not a real ASERT anchor.
- **What is proven today.** Blocks mine, verify structurally, and apply
  deterministically; the multi-node testnet shows a locally mined block
  propagating and being applied on three independent nodes. Since the
  single intake gate shipped (round 6, BACKLOG 0.9/0.6 closed), every
  intake path — RPC transfer/mine, P2P `apply_remote_frame`, the miner —
  re-verifies the PoGW nonce (full-frame VortexSponge256, leading zero
  bits >= the configured difficulty) BEFORE the frame touches the ledger;
  producers seal through the same comparator the gate judges, so the
  definition of "enough work" cannot drift between miner and verifier.
- **What is NOT proven (the masterplan's own questions, answered
  honestly).**
  - *Cheap verification beyond the nonce target:* the gate verifies the
    hash-lottery nonce; it does not re-execute the attractor commitment
    or bind the coinbase to the mining work (BACKLOG 0.4/0.6 remainder —
    the `MinerEmissionForgeable` pin stays open). Dynamic ASERT
    retargeting is not wired into the gate: today the gate enforces the
    store's configured difficulty (dev mode 16) while the miner aims at
    max(ASERT, gate).
  - *Formal security model:* no model of "genuine work" as a cost function
    exists in writing; no Sybil/replay/timestamp-manipulation simulations.
  - *Hardware asymmetry:* nothing quantifies GPU-vs-CPU advantage; the
    GPU engine deliberately lives outside the repo (BACKLOG P3.1).
- **Reproducibility.** Miner endpoints in the cookbook; multi-node script.

### 5. GQC finality — **Implemented** (share derivation is NOT authenticated — finality NOT cryptographically claimed)

- **Documented gap (external review, pinned by a test).** Validator shares
  are derived from public data only (block hash, height, validator id);
  `collect_share` does not authenticate the submitter. Anyone holding
  zero secrets can produce a full quorum. This is pinned reproducibly by
  the test `GqcQuorumForgeableFromPublicDataOnly` (expect: the forge
  SUCCEEDS today) — flip the test when signature-bearing shares ship
  (BACKLOG 0.4/2.4). Until then VX claims **no** cryptographic finality.
- **Fixed in external-review rounds 4-5.** The share pool was keyed by
  height alone, so votes for DIFFERENT blocks at the same height mixed
  into one quorum; pools are now keyed by (height, block hash) and
  finalization requires shares collected for the exact block being
  certified. The stamp now reports failure (`stamp_gqc` returns `bool`)
  and a failed stamp blocks certification instead of leaving the
  certificate in RAM with nothing durable recorded. Round 5 also moved
  the stamp OUT of the frame: the 104-byte tail has no free bytes
  (vm_state_root, vm_gas_used, pogw_nonce, vm_bytecode), so the old
  tail stamp physically overwrote consensus metadata of the certified
  block; the aggregate now lives as a versioned record in a sidecar
  file (`<ledger>.gqc`), the frame stays byte-identical after
  certification, and the whole tail is inside the block's cryptographic
  commitment (`hash_block` over header AND tail — a mutated PoGW nonce
  now changes the block id; the published genesis constant was
  recomputed accordingly).
- **Still open (round 4).** The finalized checkpoint height lives only
  in RAM: after a restart the rollback guard forgets what was cemented
  (BACKLOG 0.13, fail-closed restore on open).
- **Implementation.** `src/consensus/gqc_finality.cpp`;
  `/api/consensus/finality_status` reports checkpoint height, pending
  finality and the rollback guard; `/api/swarm/simulate_split_reorg`
  exercises partition -> heal -> O(1) rollback through real VX60 loopback
  TCP (13 ms-scale heal, both nodes converging on the heavier tip).
- **What is not proven.** The two-conflicting-finalized-blocks safety
  question has no mathematical specification yet; no BFT-threshold
  analysis (how many Byzantine participants the mechanism tolerates);
  no adversarial simulations with delays and packet loss. The split-brain
  demo is two in-process nodes, not an adversarial network study.
- **Status rationale.** Implemented + demonstrably reorganizing, but the
  masterplan's acceptance criterion ("no two incompatible finalized states
  under the model's assumptions") needs a written model first — BACKLOG
  2.4 (validator-set design) and the security-model write-up.

### 6. Blockchain state & transactions — **Tested** (external-review P0s fixed across rounds 3-4; authorization and emission still NOT claimed)

- **Implementation.** `src/state/ledger_state.cpp` (deterministic
  `apply_block`), undo journal for O(1) rollback, `src/state/mempool.cpp`
  with the TDI dust gate.
- **Fixed this pass (external review, pinned by
  `test_documented_gaps`).**
  - *Intra-block double spend minted phantom supply*: the pre-check
    counted intra-block credits but not the same sender's intra-block
    debits, so two 6 VX spends against a 10 VX balance both passed and
    the commit underflowed U128 to ~2^128. Fixed: per-sender intra-block
    debit accumulator (checked), a hard commit-time underflow guard, and
    a checked `total_supply()` sum. Regression:
    `DoubleSpendInBlockRejected` (block refused with `insufficient
    funds`, zero mutation).
  - *Mempool TOCTOU*: nonce/balance validation and the pending-state
    reservation were two separate critical sections; now one.
  - *Durability*: `append_block` now rolls back the frame and reports
    failure if `fsync` fails, instead of acknowledging a phantom write.
- **Fixed in external-review round 4 (pinned by `test_documented_gaps`).**
  - *Genesis-v1 nonce bypass*: any transaction with fee=0/nonce=0 skipped
    nonce accounting at EVERY height, so the shape could be replayed
    forever. The exemption is now scoped to the genesis replay window
    (`next_height <= 1`). Regression: `NonceZeroReplayRejected` (a
    fee=0/nonce=0 replay at height 3 fails with `nonce mismatch`).
  - *tx_count poisoning + unverified merkle*: `append_block` accepted a
    frame whose header `tx_count` was patched past the structural
    capacity (readers then walk past the frame) and never re-verified the
    merkle root (the commitment field was decorative). Now: tx_count
    bound + merkle recomputation gate at the store. Regressions:
    `OversizedTxCountRejected`, `TamperedMerkleRejected`.
  - *Miner ignoring commit results*: the mining loop called
    append/apply and unconditionally drained the mempool; a rejected
    block destroyed its transactions while the chain stayed behind. The
    miner now checks both results and keeps sealed transactions on
    failure.
  - *RPC transfer auto-fields*: `handle_transfer` left fee/nonce to the
    (attacker-controlled) request body; the node now stamps fee and the
    ledger's next nonce itself.
- **Fixed in external-review round 6 (2026-11-03, BACKLOG 0.9 + 0.6).**
  - *Single intake gate*: `append_block` used to enforce only
    magic/height/prev + tx_count/merkle; a tip-extending frame carrying
    zero mining work was appended and applied by every path. Now one
    `validate_block()` (magic, height/prev binding, tx_count bound,
    merkle commitment, timestamp monotonicity + future bound, PoGW
    full-frame work) runs at the single chokepoint every producer
    appends through; the recovery path re-validates every stored frame
    (tx_count + merkle) on reopen and fails closed. Regressions:
    `NoWorkBlockAccepted` FLIPPED to EXPECT_FALSE,
    `PogwGateAcceptsSealedWorkAndBindsTheNonce`,
    `RecoveryRejectsCorruptedLedgerFrame`. The RPC transfer path and the
    demo now seal their frames (`seal_pogw_nonce`) instead of appending
    unworked ones; `fuzz_block_frame` drives the gate surface.
- **Still open, pinned honestly (expect-success tests).**
  - *Keyless authorization*: `verify_transaction_proof` accepts a plain
    sponge digest for any sender not registered as a PQ sender — a
    digest anyone can compute, so an attacker with NO key moved 1 VX
    from the genesis receiver (`KeylessTheftReproducible` — the theft
    SUCCEEDS today). TX AUTH IS NOT CLAIMED until BACKLOG 0.7/0.8 ship
    (addresses bound to PQ keys in state; witness on the wire).
  - *MINER_ emission*: a coinbase needs only the `MINER_` sender prefix,
    index 0 and an amount at or below the 1000 VX limit — no identity, no
    binding to the block's actual mining work — so anyone still mints the
    maximum reward per block (`MinerEmissionForgeable` — the mint
    SUCCEEDS today). The PoGW work gate (round 6) no longer accepts
    no-work BLOCKS, but the coinbase transaction itself is still not
    bound to the mined nonce or a miner identity. EMISSION INTEGRITY IS
    NOT CLAIMED until that binding ships (BACKLOG 0.6 remainder).
  - *Undo journal serialization*: `UndoRecord` holds `std::string` /
    `std::vector` / `time_point` and is written with a raw
    `write(fd, &record, sizeof(record))` — heap pointers serialized as
    payload (BACKLOG 0.11).
  - *Reorg undo defects*: `rollback_to_height` journals the displaced
    block read from the wrong side of the truncation, and
    `UndoTransaction` restores balances but not sender nonces (BACKLOG
    0.12).
  - *Mempool ordering/race*: the global fee sort can order a sender's
    nonce-1 tx before its nonce-0 tx (guaranteed apply-failure block),
    and `count_` is published before the entry is written, so a
    concurrent reader can observe an unwritten slot (BACKLOG 0.14).
- **Test suite.** Double-spend rejection, overspend rejection (live:
  `{"error":"insufficient funds"}` leaves the tip unchanged), coinbase
  checks (`excess_reward`, `unauthorized_genesis` guard replays at
  `/api/security/audit`), 5-sequential-transfer convergence across 3
  nodes with identical tips and balances after every step, 3 concurrent
  transfers serializing correctly (heights n, n+1, n+2), restart integrity
  after SIGKILL.
- **Known limitations.** All nodes in the testnet are the same binary on
  the same OS — cross-platform determinism is argued by KATs, not measured
  across architectures. Cross-node *state-root* equality (SGMT root)
  is not yet asserted in the multi-node script, only balance/tip
  convergence; cheap to add alongside BACKLOG P0.1. Integer-overflow
  fuzzing of the transfer path arrived with `fuzz_rpc` this pass.

---

## Stage 3 — Execution and data structures

### 7. Vortex VM & Landauer gas — **Implemented**

- **Implementation.** `src/vm/vortex_vm.cpp`; `max_steps` bound enforced
  from the request (`/api/vm/execute_trace`); per-step Landauer trace
  (erased bits, Hamming flips, cumulative gas).
- **What is not proven.** Cross-CPU determinism is claimed by construction
  (fixed-width integer ops, no platform-dependent behavior) but not
  demonstrated on heterogeneous hardware; the Landauer model's mapping
  from physics to cost units is described in the whitepaper, not
  formalized as a spec others could re-implement; HTLC swap contracts
  (`/api/vm/htlc_swap`) are demo-grade.
- **Fuzzing.** VM bytecode is fuzzed by the chaos fuzzer (wire/frames/VM
  mutation rounds) and covered by `tests/test_vm.cpp`,
  `tests/test_landauer_vm_mev.cpp`.

### 8. Galois state trie (SGMT) — **Tested**

- **Implementation.** `src/state/galois_trie.cpp`; `/api/state/trie_root`
  and `/api/state/prove` expose the root and inclusion proofs.
- **Test suite.** `tests/test_galois_trie.cpp` (round-trip lookups,
  absent keys, update correctness).
- **Gap.** The "two independent nodes given the same transactions build
  identical state" test does not exist yet in the multi-node script; it is
  a small addition (compare `/api/state/trie_root` on A, B, C after
  convergence) and belongs with BACKLOG P0.1's convergence checks.

---

## Stage 4 — Network and privacy

### 9. P2P network — **Tested (lab)**

This is the most worked area of this verification pass; the full mechanics
are documented in [NODES.md](NODES.md) and
[MULTI_NODE_RUNBOOK.md](MULTI_NODE_RUNBOOK.md). Evidence:

- 3-node star testnet, real VX60 over TCP: dial + PING handshake,
  promote-on-first-verified-packet, full-frame relay, one-hop gossip;
  convergence on identical tip + balances.
- 9 hand-run scenarios (sequential transfers, multi-hop gossip, replay of
  historical frames with valid CRC rejected by the tip-extension rule,
  concurrent transfer serialization, restart rejoin, snapshot kill
  recovery, garbage-packet resistance).
- In-process split-brain reorg with O(1) undo rollback.
- libFuzzer on the wire ingest gate (200k CI execs); unit tests
  `tests/test_swarm_p2p.cpp` include a full-block round-trip over real
  TCP and listener-hook relay.

**Honest limits (unchanged, tracked in BACKLOG P0):** no backfill sync for
late joiners (scheduled next); no wire-level fork choice (each node keeps
its own tip on a same-height conflict); peer identity unauthenticated
(`node_id: 0`); bind address is loopback-only; no peer discovery (static
`--peer` list); TX_COCOON relay not wired end-to-end. The masterplan's
10/100/1000-node and 30%-malicious scenarios are simulation work, not yet
scheduled beyond the 4-node backfill test.

### 10. Privacy: Dandelion++, stealth, cocoons — **Implemented**

- **Implementation.** Dandelion++ stem/fluff with counters
  (`/api/swarm/dandelion_stats`), sealed 112-byte cocoons, TDI gate,
  stealth envelopes and IVK scan in the key matrix.
- **What is not proven.** No threat-model document exists stating *against
  whom* protection is claimed (outside observer / node operator / global
  passive adversary). No source-IP tracing experiments, no
  sender-transaction linkage analysis, no ring-of-decoys experiments. The
  ledger is transparent: amounts are **not** private — this is stated in
  the whitepaper and repeated here as a standing limitation (zk-cocoon
  privacy is a research track, not a shipped claim).
- **Status rationale.** The machinery is real and counters move on real
  traffic, but the masterplan correctly demands experiments before any
  privacy claim. None exist yet.

### 11. Hamiltonian MEV shield — **Implemented**

- **Implementation.** `/api/mempool/mev_audit` with Hamiltonian
  priority-penalty accounting (`tests/test_landauer_vm_mev.cpp`).
- **Gap.** No exchange/DEX simulator with bots exists, so the masterplan's
  measurable outcomes (share of successful front-runs, user losses,
  inclusion-delay impact) are not measured against anything. Designed +
  Implemented, not Tested against an adversary.

---

## Stage 5 — Performance and node protection

### 12. Fixed 64 KiB frame & mmap — **Tested**

- **Specification.** Frame layout (472 B header + 580 x 112 B transfers +
  104 B padding) is documented in [NODES.md](NODES.md) with per-field
  offsets; block magic `0x58564336`; little-endian packing (`<IBBHIIQ`
  wire header).
- **Test suite.** `tests/test_block.cpp`; `fuzz_block_frame` (100k CI
  execs) asserts malformed lengths/magic are rejected without OOB reads;
  corrupted-frame behavior is live-tested (10 garbage packets counted,
  node keeps serving).
- **Gaps.** The multi-node script runs on one architecture and one OS;
  endianness/alignment portability is argued by explicit LE packing, not
  measured elsewhere. Benchmarks against Bitcoin Core under equal
  conditions do not exist (and are only meaningful after the network
  items land).

### 13. MemoryVault & secrets in RAM — **Tested** (mlock degradation now matches the documented promise)

- **Fixed this pass (external review):** `MemoryCore` used to `throw` on
  `mlock` failure, blocking node launch in containers with a low
  `RLIMIT_MEMLOCK` — while the header itself promised graceful
  degradation for the public build. Now the failure is loud on stderr,
  the node launches with unlocked pages, zeroization guarantees are
  unchanged, and the real protection level stays visible in
  `stats.mlock_active` (`/api/vault/*`). Sovereign Vault editions keep
  mlock as a hard invariant.
- **Fixed in external-review round 5.** The capability token was not
  what its API claimed: `generate_unique_sha32` computed a 4-stream
  CRC32C checksum (not a cryptographic digest), and only the FIRST 4
  BYTES were stored and compared on consume — 224 of the 256 token bits
  were never checked, so a token with a mutated tail still consumed the
  page. Now the full 32-byte VortexSponge256 digest (domain-separated,
  bound to the hardware key and an entropy nonce) is stored and compared
  constant-time. Second round-5 fix: the ring page cursor silently
  ZEROED a still-LOCKED page on pool wrap (commit #4097 destroyed the
  1st live token in a 16 MiB arena); a page is now reusable only after
  consume/burn, and a full pool raises instead of clobbering.
- **Honest limitation (external review round 5, stated).** `MemoryCore`
  (src/core) protects against swap-out (mlock) — NOT against a
  privileged in-process reader: payloads sit in the arena as plaintext,
  and `check_debugger()` exists but is not wired into the hot path.
  mlock is swap/core-dump hygiene, not an anti-analysis boundary; any
  stronger claim would be false. (BACKLOG 1.6 tracks wiring the
  debugger check and/or masking; the separate SDK implementation's
  test results do not transfer to this class.)

- **Implementation.** `src/core/memory_vault.cpp`: mlock'd pages,
  VOID -> LOCKED -> BURNED lifecycle, huge pages, guard values;
  `/api/vault/memory` and `/api/vault/ephemeral_sign` expose the
  lifecycle live (page VOID -> LOCKED -> BURNED with rdtsc-bounded key
  lifetime).
- **Test suite.** `tests/test_vault_memory.cpp`, `tests/test_vault_htlc.cpp`;
  ASan+UBSan lane on every push.
- **Gaps.** No TSan lane yet (the swarm threading grew this week —
  BACKLOG 1.4); mlock-failure semantics on hosts with low
  `rlimit_memlock` are not tested/documented; core-dump exclusion
  (`madvise`/`prctl` paths) not audited; SIGKILL behavior is inherent
  (pages die with the process) but not tested for partial-write
  consistency of the sidecar.

---

## Stage 6 — Economics and protocol rules

### 14. Tokenomics — **Designed**

Miner reward constants and supply accounting exist in code
(`total_supply` is live-computed and reported at `/api/status`, 2.64M VX
post-genesis + demo emission in the recorded runs), but there is **no**
written emission-schedule spec, fee-market description, or simulation of
the masterplan's scenarios (dominant participant, resource collapse,
transaction floods). BACKLOG 2.5. The TDI dust gate is the one economic
mechanism that is both implemented and tested (`dust_spam_tdi` guard
replay, mempool tests).

### 15. Genesis & protocol compatibility — **Tested**

- **Evidence.** The genesis frame is regenerated deterministically
  (`src/blockchain/genesis.cpp` writes a fixed timestamp 1761000000, no
  wall-clock dependency); BlockStore regenerates `genesis.bin` on first
  run rather than trusting a copy ("always regenerate, never copy"); the
  genesis tip hash is published in the whitepaper and in the Challenge and
  asserted by `fuzz_block_frame`-adjacent frame tests and the canonical
  vectors.
- **Gaps.** Regeneration on a different OS/CPU architecture is not
  demonstrated (the KATs imply it; the multi-node script is single-host).
  The demo block, unlike genesis, **does** embed wall-clock time — this is
  documented behavior with a documented workaround (snapshot), not a
  genesis-determinism defect. Protocol versioning and update rules do not
  exist yet.

---

## Stage 7 — Real operation

### 16. RPC & API security — **Tested (this pass)**

- **Transport hardening still open (external review, BACKLOG 0.10):**
  the listener binds `INADDR_ANY`, spawns a detached thread per
  connection, reads a request with a single 8 KiB `recv()`, and has no
  authentication on state-changing endpoints. For any reachable
  deployment: reverse proxy + bind/flag controls first (BACKLOG 0.3),
  then bounded concurrency, complete request reads and auth.
- **What this verification pass added.**
  - A public `route()` catch-all: a hostile body can no longer unwind a
    worker thread (which would terminate the node); it now answers 500.
  - Two unguarded `std::stod` calls fixed (transfer amount string form,
    audit dust amount) — oversized numerals previously threw
    `std::out_of_range` inside a detached thread.
  - `fuzz/fuzz_rpc.cpp`: the entire 34-endpoint surface fuzzed (method
    byte, path from the live route table, 4 KiB body cap), with the
    invariant that **a GET never moves the chain tip**, and bound chain
    growth; 20k clean execs locally during this pass, 200k wired into CI.
  - Live hostile-input smoke: `amount_vx: 1e999` (string and numeric
    forms) answered clean TDI rejections; the node kept serving; valid
    transfers unaffected.
- **Fixed in external-review round 5.** The vault route was a
  remote kill-switch: `POST /api/vault/action` with `consume` OR
  `emergency_burn` both called `emergency_burn_all()` — any RPC client
  could wipe the whole vault (P0). Now `consume` requires the specific
  32-byte capability token and burns exactly one page;
  `emergency_burn` is refused over RPC (403, admin-only in-process
  path). The SSE thread leak is fixed: the SSE handler used to PEEK the
  request forever without consuming it, so a detached thread never
  observed a disconnect — the handshake is now drained and the wait is
  poll()-based.
- **Standing limitations (by design, stated).** No authentication, no
  rate limiting, no request replay protection — the RPC is an observation
  and demo surface with no consensus weight, documented in the cookbook.
  The seed-leakage requirement holds for the NODE's own key material: no
  public endpoint returns it. But external-review round 5 correctly
  flagged demo fixtures over RPC: `/api/crypto/canonical` returns the
  TEST VECTOR private keys of its built-in profiles, and
  `/api/crypto/pq_sign` derives from a public demo seed. These are
  published fixtures, not live keys — but the endpoint must never exist
  in a production build (BACKLOG 0.10).
- **Reproducibility.** `ctest`, the fuzz target, and the cookbook's
  commands.

### 17. Wallet & explorer — **Partial**

Web console ships and builds in CI (npm); address generation, PQ signing
and recovery paths are exercised via the key-matrix endpoints. There is no
standalone wallet application and no independent explorer that verifies
blocks against its own implementation of the rules — both are masterplan
requirements that remain open (BACKLOG P3.2 wallet stack).

### 18. SDK & integrations — **Not started**

No stable-API guarantee, versioning, or multi-language SDK exists. The
cookbook's live-captured request/response pairs are the only integration
surface today.

---

## Priority crosswalk

The masterplan's P0 list, mapped to what exists and to the backlog:

| Masterplan P0 | Today's state | Next concrete step |
|---|---|---|
| WOTS+/XMSS key lifecycle | Tested — durable leaf ledger shipped (`c1d6230`), reuse/restart/exhaustion/tamper covered | H=4 capacity justification and tree rollover design |
| VortexSponge256 cryptanalysis | KATs + SAC only | Differential/linear battery (BACKLOG 1.3) |
| PoGW security model | Implemented, not wire-verified | PoGW check on relay path (BACKLOG 0.6), then model |
| GQC safety & liveness | Split-brain demo only | Written model + adversarial simulation (BACKLOG 2.4) |
| Double-spend validation | Tested (unit + live) | Cross-node trie-root equality test |
| Genesis determinism | Fixed-timestamp regeneration, KATs | Multi-arch regeneration run |

P1: P2P synchronization is this week's backfill work (BACKLOG 0.1-0.2),
fork handling after it, state consistency via the trie-root test, RPC
security just advanced this pass, memory safety via TSan (BACKLOG 1.4).

## Maturity gates

| Gate | VX today |
|---|---|
| Research Alpha (components implemented, tests reproducible) | **Met** — all core subsystems have code and reproducible tests |
| Public Testnet (independent nodes sync, attacks simulated) | **Partially met** — same-binary nodes sync over VX60; independent-party nodes, backfill and adversarial simulations are not there yet |
| Security-Validated | Not met — nothing independently verified |
| Mainnet Candidate | Not met — by design, gated on review and collision analysis |

## What this pass changed

- RPC surface hardened and fuzzed end-to-end (the two `std::stod` crashes
  found by the review were fixed before the first fuzz run executed; the
  200k battery then confirmed the surface stays clean).
- The verification record itself: every claim above is tied to a test,
  an endpoint, or a script a reader can run.
- **The top lifecycle gap closed** (`c1d6230`): the PQ one-time-leaf
  registry is now durable, cross-process-safe and fail-closed, with
  reuse/restart/exhaustion/tamper tests — see
  [VERIFICATION_EVIDENCE.md](VERIFICATION_EVIDENCE.md) for the full
  evidence chain behind every claim in this record.

## Explicitly not promised

- Privacy of amounts on the transparent ledger.
- Independent verification or audit status for any component (none has
  been performed).
- Anything about utilities and binaries that live outside this repository
  by design.
