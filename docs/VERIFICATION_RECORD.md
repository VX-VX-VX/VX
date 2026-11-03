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
- **Fuzzing:** five libFuzzer targets in CI (`fuzz_block_frame` 100k,
  `fuzz_pq_witness` 20k, `fuzz_wire` 200k, `fuzz_rpc` 200k and
  `fuzz_undo_journal` 200k execs, fixed seeds).
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
| 3 | Intra-block double spend minting phantom supply; mempool TOCTOU; phantom fsync acknowledgment; keyless theft of 1 VX from the genesis receiver | `DoubleSpendInBlockRejected`; single-critical-section mempool; append rollback. Keyless theft CLOSED 2026-11-03 (round 7): `KeylessTheftRejected` flipped to EXPECT_FALSE plus `UnboundSenderRejected`, `WitnessRootMismatchRejected`, `SelfCertifyingAddressAutoBinds`, `WitnessDurableLogSurvivesRestart` (§6) |
| 4 | Genesis-v1 nonce replay; `tx_count` poisoning; unverified merkle field; miner draining mempool on a rejected block; RPC-controlled fee/nonce | `NonceZeroReplayRejected`, `OversizedTxCountRejected`, `TamperedMerkleRejected`; miner commit checks; node-stamped fee/nonce. The `MinerEmissionForgeable` pin (emission without mining work or identity) was FLIPPED 2026-11-03 (round 7): `CoinbaseReplayRejected` (§6) |
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
     implemented or justified numerically. Since round 7 this also bounds
     authorization: a key that has consumed all 16 leaves cannot witness
     further spends; rollover means moving to a new self-certifying
     address.
  3. Root rotation is not implemented: an address bound to a PQ root
     cannot be rebound to a new key (a stolen key cannot be rotated away
     yet; see BACKLOG 0.7 remainders).
  4. No 1M-sample randomized positive/negative verification battery yet;
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
- **Still open (round 4) — CLOSED 2026-11-03 (BACKLOG 0.13).** The
  finalized checkpoint used to live only in RAM: after a restart the
  rollback guard forgot what was cemented. The guard is now restored on
  open from the `<ledger>.gqc` sidecar (highest stamped height,
  monotonic, fail-closed: a corrupt sidecar is reported untrusted and
  fabricates nothing; a torn tail is healed). Regression:
  `GqcCheckpointSurvivesRestart` (certify N, restart, rollback to N-1
  refused). Honest remainder: a restored stamp is not yet re-verified
  against the share-derived recomputation on open — that belongs to the
  validator-authentication cycle (BACKLOG 0.4 / 2.4), since shares
  currently derive from public data.
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

### 6. Blockchain state & transactions — **Tested** (external-review P0s fixed across rounds 3-7; transaction authorization and emission bounds CLAIMED since round 7)

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
    (attacker-controlled) request body; the node stamped fee and the
    ledger's next nonce itself. SUPERSEDED in round 7 (BACKLOG 0.7): the
    server no longer signs or stamps anything into the signed material —
    the client supplies `fee_atoms`/`nonce` (both inside the PQ-signed
    preimage, the nonce validated against the ledger's expectation) plus
    the witness; a zero fee + zero nonce can no longer smuggle the
    genesis-v1 shape through, because user senders must carry a PQ
    witness regardless of shape.
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
- **Fixed in round 7 (2026-11-03, BACKLOG 0.7 + 0.8).**
  - *Keyless transaction authorization (the reviewer's round-3 theft
    PoC)*: CLOSED. Addresses are bound to post-quantum keys through two
    sources — self-certifying addresses (`"PQA"` + base64url of
    `Sponge("VXPQADDRV1" || pq_pubkey_root)`: holding the key IS holding
    the address) and a protocol seed table for genesis-era allocations
    (genesis receiver -> an OFFLINE root whose secret is not in the repo;
    demo addresses documented). The ledger refuses every user sender
    without a valid `PqSignatureWitness` (lookup by `tx_msg_digest`,
    root-binding check, full WOTS+/XMSS + anchor verification); the
    keyless Tier-2 digest survives ONLY as an admission pre-filter and
    for the guarded system senders (`GENESIS*`, `MINER_`). The demo RPC
    no longer signs on the user's behalf: `/transfer` requires
    `witness_b64` + `fee_atoms` + `nonce` from the client. Regressions:
    `KeylessTheftRejected` (the flipped pin — the forged transfer is
    refused with "no PQ witness registered" and nothing moves),
    `UnboundSenderRejected` (a valid witness from a key the sender does
    not own spends nothing), `WitnessRootMismatchRejected`
    (protocol-bound address, wrong key), `SelfCertifyingAddressAutoBinds`
    (first witnessed spend binds the address; a foreign key is refused
    afterwards, the owner keeps spending).
  - *PQ witness on the wire + durable storage (BACKLOG 0.8)*: CLOSED.
    `WireMsgType::PQ_WITNESS` (0x09) carries digest(32) + sender(42) +
    witness(2376); witnesses are broadcast BEFORE the block that carries
    their transactions (a peer without the witnesses cannot authorize the
    block). The durable sidecar `<ledger>.pqw` fsyncs a `VXPQWT1` record
    (2458 B) per registration and is replayed fail-closed on attach —
    a restart no longer orphans witnessed transactions. Regression:
    `WitnessDurableLogSurvivesRestart`. The 64 KiB frame itself stays
    byte-identical to the published spec (it has no free bytes).
  - *Coinbase emission binding (BACKLOG 0.6 remainder)*: CLOSED. The
    `MINER_` coinbase no longer authorizes itself with the keyless
    digest: its `cocoon_proof` must equal
    `trunc12(Sponge("VX_COINBASE_BIND_V1" || receiver || height ||
    prev_tip_hash))`, verified against the frame's own header in
    `apply_block`. A coinbase copied from one fork cannot be replayed on
    a competing fork at the same height (its tag commits the OTHER
    fork's tip), and the miner's coinbase builder now emits the binding.
    Emission is bounded by four rules: one coinbase per block (index 0),
    the 1000 VX reward cap, real PoGW work on the block (round 6), and
    the chain-position binding. Pin flipped: `MinerEmissionForgeable` ->
    `CoinbaseReplayRejected`. What remains is permissionless by design:
    whoever produces a valid block names the reward address — no miner
    identity exists to forge.
- **Fixed in round 8 (2026-11-03, adversarial self-review — internal,
    not external replication).** Immediately after round 7 landed, the
    just-written authorization code was audited as an attacker would read
    it. The audit found two P0s, one P1 cluster and two P2s in the round-7
    code itself; all are fixed and covered by the existing suite plus the
    live-node checks below. This round is labeled self-review because the
    defects were found (and fixed) by the project's own adversarial pass,
    not reproduced independently by the external reviewer.
  - *P0 — the wire gate dead-coded the witness channel*: the VX60 header
    plausibility gate still accepted types 0x01..0x08, so every incoming
    `PQ_WITNESS` (0x09) frame was dropped (and the connection closed) —
    the broadcast added in round 7 could never reach a peer. Fixed: the
    gate accepts 0x01..0x09.
  - *P0 — register-before-verify + append-before-apply*: the RPC
    transfer path published an unverified witness into the shared
    registry and, if the ledger refused the block afterwards, left the
    block store one block ahead of the ledger state — every later block
    would then fail the height gate and the node wedges. Fixed on three
    axes: the endpoint verifies the full WOTS+/XMSS + anchor chain BEFORE
    registering; `BlockStore::rollback_last_append()` (ftruncate back to
    the previous tip) is called by the RPC path, the remote-frame path
    and the miner whenever a gate-passed block is refused by the state
    layer; and the miner no longer applies a frame that failed to append.
    A store/ledger tip divergence can no longer persist.
  - *P1 — the witness registry was an authority-shaped cache*: first
    candidate won regardless of validity, duplicates were stored, caps
    were absent (remote flooding filled the map), and the durable log
    could be appended by a second node process without any lock. Fixed:
    nothing enters the registry unverified (`register_witness` runs the
    full tx verification, `register_witness_bytes` verifies the
    commitment and the chain against the claimed digest); byte-exact
    dedup; caps of 8 candidates per digest and 50000 digests; the
    sidecar is opened O_APPEND 0600 under an exclusive `flock` with a
    memory-only fallback; the replay honors the caps and never feeds the
    sender-root table. Consensus lookup switched to
    `lookup_verifying()`: a digest may hold several candidates (an
    attacker can register a cryptographically valid signature for a
    digest they predict), and the lookup returns only a candidate that
    passes full verification against THIS transaction.
  - *P2 — non-transactional self-certifying bindings*: a sender address
    was bound to its PQ root mid-loop, before later transactions of the
    same block could still refuse the block — a rejected block mutated
    consensus state. Fixed: bindings are collected during validation and
    applied only after every transaction in the block validated.
  - *P2 — HTTP parsing fragility (found live)*: the JSON field scanner
    matched only the compact form (`"key":"v"`), so any standard
    serializer emitting `"key": "v"` made the endpoint report a missing
    witness instead of the real validation error; and `parse_request`
    treated one `recv()` as one request, truncating a ~3.2 KB witness
    body that arrived split across TCP segments. Fixed: whitespace-
    tolerant field scan; the request is read until the declared
    Content-Length is satisfied (64 KiB cap bounds a flood).
  - Verified live after the fixes: a full-size garbage witness is refused
    with "witness failed WOTS+/XMSS verification" and does not enter the
    registry; a wrong nonce is refused with the nonce diagnostic; failed
    transfers leave every balance byte-identical; both compact and
    standard JSON produce identical results.
- **Fixed in round 9 (2026-11-03, delegated adversarial audit — internal,
  three hunt-fix-re-hunt cycles).** A full-codebase adversarial pass over
  the round-7/8 code found six more defects, each proven with an
  executable exploit BEFORE the fix (exploit programs run against the
  built library from a scratch directory; the repository carries the
  regression where a gtest can express the invariant).
  - *P0 — health-loop self-deadlock (remotely triggerable)*: the DoS
    score path called `disconnect_from_peer` while holding the peer-table
    mutex, which locks the same non-recursive mutex — one CRC-valid frame
    with a bad magic from any local process deadlocked the whole node
    (broadcasts, peer listing, new connections) at the next health tick.
    Fixed: the ban path collects the affected descriptors under the lock
    and acts on them after unlocking.
  - *P0 — unbounded GENESIS minting inside one height-1 block*: the
    legacy-window mint authorization read COMMITTED balances, so every
    mint in the same block saw its receiver as still untracked and all
    of them applied (N x 100 000 VX of supply created in one block at
    the only window that accepts the mint sender). Fixed: one GENESIS
    mint per block in the legacy window — the second is refused with
    "second GENESIS mint in one block". Regression:
    `SecondGenesisMintInBlockRejected` (the rejected block credits
    nothing and leaves supply byte-identical).
  - *P1 — unbounded blocking sends*: broadcast paths sent from threads
    holding the state or peer mutex; a peer that stopped reading (full
    TCP window) could freeze the chain tip indefinitely. Fixed: a 5 s
    send timeout on every dialed and accepted socket.
  - *P1 — double-close / fd-reuse race on banned peers*: the ban path
    (and teardown) closed a descriptor the peer's own thread also closed;
    a recycled fd number would kill an unrelated live connection. Fixed:
    shutdown-only outside the owning thread, single close by the owner.
    Proven with an LD_PRELOAD close-generation tracker: 41 double-close
    events before, 0 after.
  - *P1 — unbounded remote memory growth via /api/state/prove*: the
    handler inserted the caller-supplied key into the persistent trie
    (about 32 arena nodes per request, never erased, unauthenticated
    listener) — remote OOM at ~3 KB of attacker input per node. Fixed:
    the demo proof runs on a throwaway per-request trie; the persistent
    trie stays read-only (it had no other writer anywhere).
  - *P2 — UB float-to-integer casts on RPC input*: NaN/negative/overflow
    JSON numbers reached `static_cast<uint64_t>` (UB under
    float-cast-overflow) instead of a clean refusal. Fixed: finite/range
    guards before both casts.
  - Report-only (verified, deliberately not fixed, with reasons): the
    background miner's append/apply is unsynchronized but the miner is
    dormant (no caller routes it yet); the mempool races sit behind a
    submit path with zero callers; the undo journal's raw-struct writes
    are BACKLOG 0.11 (a real fix changes the on-disk format); broadcast
    snapshots can send to a concurrently-closed fd (receiver fails
    closed via the plausibility gate + CRC — liveness only); the RPC
    binds 0.0.0.0 (deployment decision, documented).
- **Round 9 tooling and happy-path closure (same wave).**
  - The multi-node harness now drives a REAL PQ-witnessed transfer: the
    demo signer names the transaction (sender/receiver/fee/nonce +
    `demo_key:"spender"`, the public protocol key) and posts the full
    2376-byte witness to `/api/transfer` — the scenario "transfer mined
    on A propagates over VX60 and converges on B and C" passes 10/10
    with post-quantum authorization on every node (previously the script
    still used the removed keyless shape and could not exercise the
    transfer at all).
  - The demo signer endpoint returns `witness_b64` for the transaction
    it just signed (not the registry's first candidate for the digest —
    with several candidates per digest, a lookup can name another key's
    signature) and accepts an optional sender/receiver override. Still
    demo-only key material (BACKLOG 0.10).
  - `pq_sign_transaction` gained an out-parameter returning the witness
    THIS call produced (the registry may hold several valid candidates
    for the same digest; a caller must not go back through it).
  - The `fuzz_pq_witness` harness was deepened: it now signs one real
    message at startup and treats the input as a targeted XOR mutation
    of that structurally valid witness (offset + mask, witness or
    message), so every run walks all 67 WOTS+ chains and the XMSS
    auth-path recomputation instead of bouncing off the first
    commitment check (coverage counters 2 -> 25 in a 100k run; ~280M
    random-input runs and ~245k mutation runs clean).
- **Still open, pinned honestly (expect-success tests).**
  - (None in this section. The remaining consensus gaps are tracked as
    BACKLOG items with design notes — none of them pinned as
    expect-success tests yet; pinning them is part of their fix cycle.)
  - *Undo journal serialization* (CLOSED 2026-11-03, BACKLOG 0.11):
    `UndoRecord` holds `std::string` / `std::vector` / `time_point` and
    was written with a raw `write(fd, &record, sizeof(record))` — heap
    pointers serialized as payload. The journal is now a versioned byte
    format (`VXUNDOJL`, fixed-width little-endian records, reject-or-
    migrate on open, torn-tail healing); see the Evidence changelog and
    regressions `UndoJournalByteFormatRoundTrip` /
    `UndoJournalRejectsHostileFiles`.
  - *Reorg undo defects* (CLOSED 2026-11-03, BACKLOG 0.12): the journal
    read the displaced block's transactions from the store (the resync
    path journals before the store append, so the rollback reversed
    effects that never happened on this fork) — now it records the frame
    being applied, with the pre-state tip from the block's own prev_hash
    (ordering-independent); sender nonces are snapshotted per undo
    transaction and restored by the rollback; addresses the fork CREATED
    are untracked once their reversed balance is zero (a re-applied
    height-1 GENESIS_2 mint used to be refused forever — the reorg
    bricked the node); and the displaced fork frames are preserved in the
    side journal `undo/displaced.vxd` before any mutation, so a reorg is
    replayable in both directions. Regression:
    `ReorgUndoRestoresNoncesAndFrames` (rollback + re-apply byte-
    identical to a fresh apply).
  - *Mempool ordering/race* (CLOSED 2026-11-03, BACKLOG 0.14): sealing
    order is now a deterministic k-way merge over per-sender nonce
    chains — the chain whose head transaction carries the best fee
    density wins the next slot, so a sender's nonce-1 can never enter a
    block ahead of its nonce-0 (the global fee sort could invert them
    and brick every sealed block with a nonce-mismatch apply failure);
    and entry publication is mutex-serialized — an entry is fully
    written before the count reflects it, so a concurrent sealing reader
    can no longer observe an unwritten slot (the pool now guards entry
    storage, pending state and count mutations with one pool mutex;
    count()/empty() remain lock-free approximate hints). Regressions:
    `SealingPreservesPerSenderNonceOrder`,
    `PullBudgetNeverBreaksSenderChain`,
    `SealedBatchesApplyOnFirstAttempt`,
    `ConcurrentSubmitsAndSealsStayConsistent` (8 submitter threads + a
    sealing reader; ThreadSanitizer-clean across 6 runs).
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

### 14. Tokenomics — **Emission schedule implemented (hard-coded); fee market still designed**

The emission schedule is now hard consensus code, not a parameter
(user-directed 2026-11-03; `include/vx/blockchain/emission.hpp`):
- **Hard lifetime cap: 7,000,000,000 VX** (7e17 atoms; the 7 is the
  protocol's signature digit). `static_assert`ed; no height, vote or
  config can issue the 7,000,000,001st VX. The cap — not a height
  window — is the only end of emission: at the 50 VX floor rate it
  closes after roughly 140 million blocks.
- **Hash-dependent block reward**: a deterministic function of the
  block's own PoGW hash (the full-frame VortexSponge256 commitment the
  intake gate already checks). 50 VX is guaranteed for every valid
  block; the hash's leading zero bits unlock the bonus tiers — at
  20/24/28/32/40 zero bits the reward steps to 75/100/200/400 and the
  1,000 VX jackpot (frequencies ~1 in 1M / 17M / 268M / 4.3B / 1.1T
  blocks). A miner cannot mint the bonus, only FIND a rarer hash, so a
  bigger reward is strictly more proof-of-work; the thresholds are
  absolute, so any node verifies the reward by recounting the zeros in
  the hash it already computes — no difficulty estimate enters
  consensus accounting, and as network difficulty grows past a
  threshold the effective reward steps up (emission accelerates only
  when the security behind the chain grows, bounded by the cap).
- The gated quantity is cumulative **issuance**: all coinbase credits
  minus the fee share re-credited to the producer (fees re-entering
  circulation are redistribution, not new emission). Genesis allocations
  (2.54M faucet + the one-time 100k legacy mint) count against the cap,
  so the final emission blocks mint only the remaining headroom and the
  cap closes exactly; afterwards not one atom of new issuance can enter
  state (zero-amount coinbases remain legal so fee redistribution
  survives).
- Enforcement lives in `LedgerState::apply_block` BEFORE any state
  mutation (a refused block leaves the ledger byte-identical) and
  recomputes the frame hash itself; the reorg undo recomputes and
  reverses a block's issuance; the miner claims a tier and searches for
  a hash that justifies the claim (escalating when the found hash is
  rarer than claimed), with the coinbase clamped to the headroom;
  `/api/status` reports `max_supply_vx`, `issued_supply_atomics`,
  `issuance_headroom_vx`, `block_reward_base_vx`,
  `block_reward_max_vx`, `reward_tier_count`.
- Regressions: `EmissionRewardTiersAndCap`,
  `CoinbaseEntitlementEnforced`, `SupplyCapHardStopsIssuance`,
  `RewardIndependentOfHeight`. Genesis frame and hash unchanged.

Still open (BACKLOG 2.5): a written fee-market description, dust
thresholds and simulation of the masterplan's scenarios (dominant
participant, resource collapse, transaction floods). The TDI dust gate is
the one economic mechanism that is both implemented and tested
(`dust_spam_tdi` guard replay, mempool tests).

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
- **Emission schedule hard-coded** (user-directed, 2026-11-03): lifetime
  cap 7,000,000,000 VX, hash-dependent block reward (50 VX guaranteed
  floor; bonus tiers 75/100/200/400/1,000 VX at 20/24/28/32/40 leading
  zero bits of the block's own PoGW hash; the cap, not a height window,
  ends emission), issuance gated in the ledger before any state mutation
  and reversed by the reorg undo — see component 14 and BACKLOG 2.5.
- **Reorg undo correctness** (BACKLOG 0.12, 2026-11-03): the rollback
  now journals the frame being applied (not whatever the store holds at
  that height), restores sender nonces and the tracked-account set, and
  preserves the displaced fork frames in a fail-closed side journal, so
  rollback + re-apply is byte-identical to a fresh apply — see
  [VERIFICATION_EVIDENCE.md](VERIFICATION_EVIDENCE.md) for the full
  evidence chain.
- **Finality checkpoint persisted** (BACKLOG 0.13, 2026-11-03): the
  rollback guard is restored on open from the GQC sidecar — the
  "absolute defence" against deep reorgs no longer evaporates on reboot
  (certify N, restart, rollback to N-1 refused, pinned by
  `GqcCheckpointSurvivesRestart`).
- **Mempool sealing order + publication race** (BACKLOG 0.14,
  2026-11-03): sealing pulls are now a deterministic k-way merge over
  per-sender nonce chains (fee market across senders, inviolable nonce
  order within a sender), and entry storage is mutex-serialized so a
  concurrent reader never sees an unwritten slot; pinned by four
  regressions including a multi-threaded stress test that is
  ThreadSanitizer-clean across 6 runs.
- **Adversarial review round 5, ledger/rollback hardening**
  (2026-11-03): the reorg rollback now nets reversal deltas per address
  and applies them exactly — an underflow aborts with
  `ERR_UNDO_STATE_MISMATCH` instead of minting phantom supply through
  the clamp-at-zero path; the height-1 `GENESIS_2` mint is bound to its
  exact protocol shape (100,000 VX to the pinned demo-spender payload,
  untracked receiver, one per block, count check before shape check);
  the GQC sidecar stamp and the rollback truncate are fsynced
  full-record writes; a torn multi-tx journal tail heals when the
  record's own tx count proves the damage is tail-only; a rollback
  against a journal that does not cover the full span is refused with
  `ERR_UNDO_JOURNAL_GAP`. Unfixed items are process-level and tracked
  in the BACKLOG (mempool admission wiring, half-applied-block commit
  guard).

## Explicitly not promised

- Privacy of amounts on the transparent ledger.
- Independent verification or audit status for any component (none has
  been performed).
- Anything about utilities and binaries that live outside this repository
  by design.
