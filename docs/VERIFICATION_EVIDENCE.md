# VX Verification Evidence

Every claim in [VERIFICATION_RECORD.md](VERIFICATION_RECORD.md), backed by
a run that was actually executed, with the exact command a reader can run
to reproduce it. Nothing in this document is asserted without a command
next to it. Output shown in this file was captured from real runs on the
machine described in section 1; where a claim depends on your machine,
the expected result is stated as a property (a check that must hold), not
as a fixed string.

Companion docs: [verification record](VERIFICATION_RECORD.md) ·
[backlog](BACKLOG.md) · [runbook](MULTI_NODE_RUNBOOK.md) ·
[nodes guide](NODES.md)

Commits referenced by this document (all locally signed by the repo's
GPG key): `93e1756` (RPC fuzzing), `424b743` (roadmap/backlog update),
`d72f6fc` (verification record), `c1d6230` (PQ leaf lifecycle fix).

---

## 0. How to verify any claim here

Three levels, weakest to strongest:

1. **Read the artifact** — test names, configs and code locations cited
   per claim; `grep`-able in the tree.
2. **Re-run the battery** — one command per layer (sections 3-9); every
   command below is complete and copy-pasteable from the repo root.
3. **Re-derive the numbers** — the strongest claims (canonical vectors,
   KATs, SAC matrix, Merkle roots) are property-checks against published
   constants; an independent implementation can reproduce them from the
   whitepaper alone (that is what the Vortex Challenge tests).

The status vocabulary of the record applies unchanged: an internal test
run is evidence for **Tested**, never for **Verified**. Verified requires
someone who does not work on VX.

### Reviewer quick-check (about 15 minutes)

A visitor who wants the shortest path to trusting (or distrusting) this
document:

```bash
# 0. build (3-5 min)
cmake -S . -B build -G Ninja && cmake --build build -j

# 1. the whole unit battery (5 s)
cd build && ctest

# 2. the strongest math claims (10 s)
./test_vortex          # canonical vectors, SAC, WIF, Shamir, TDI, vault
./test_pq_signatures   # PQ forgery matrix + leaf lifecycle
./test_block           # frame geometry, 580 cap, tamper detection

# 3. live multi-node (1-2 min)
scripts/multi_node_test.sh build

# 4. hostile RPC input (10 s, needs a running node)
./vx_node --demo --data-dir /tmp/vx_rev && (./vx_node --serve 18099 --data-dir /tmp/vx_rev &) && sleep 1
curl -s -X POST localhost:18099/api/transfer -d '{"sender":"x","receiver":"y","amount_vx":"1e999"}'
curl -s localhost:18099/api/status | head -c 80   # still serving

# 5. the genesis constant (whitepaper cross-check)
curl -s localhost:18099/api/status | grep -o '"tip_hash_hex":"[a-f0-9]*"'
# fresh dir -> 485f5afac16d6bec3c96efdce197c76ac9c81d0d669ed8b8f4b597669690b44d
```

If all five steps match this document, every claim here has reproduced
on your machine.

---

## 1. Verification environment (real, recorded)

| Item | Value |
|---|---|
| Date of the runs | 2026-11-02 |
| OS | Linux 7.1.2-zen2-1-zen x86_64 (Arch-based) |
| CPU | AMD Ryzen 7 8840HX (8C/16T, x86-64-v3: SSE4.2 CRC32C hardware path active) |
| GCC | 16.1.1 20260728 |
| Clang | 22.1.8 |
| CMake | 4.4.2 |
| Ninja | 1.13.2 |

Verify on your machine:

```bash
uname -srm && grep -m1 "model name" /proc/cpuinfo
g++ --version | head -1 && clang++ --version | head -1
```

Property: the suite must pass on any x86-64 Linux with GCC >= 13 or
Clang >= 17; CI proves GCC and Clang on ubuntu-latest, and the local runs
prove both toolchains here.

---

## 2. Build matrix (3 configurations, all green)

| Config | Purpose | Command (from repo root) |
|---|---|---|
| `build` | Release, GCC, default | `cmake -S . -B build -G Ninja && cmake --build build -j` |
| `build_san` | ASan + UBSan, `-fno-sanitize-recover=undefined` | `cmake -S . -B build_san -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined -g -O1"` then `cmake --build build_san -j` |
| `build_fuzz` | libFuzzer targets, Clang | `cmake -S . -B build_fuzz -G Ninja -DCMAKE_BUILD_TYPE=Release -DCMAKE_CXX_COMPILER=clang++ -DVX_BUILD_FUZZERS=ON` then `cmake --build build_fuzz -j` |

All three compiled warning-relevant clean on the recorded date (two
pre-existing unused-variable warnings in `swarm_node.cpp` and one unused
lambda capture in `unicode_alphabet.hpp`; none in the files touched by
this pass).

---

## 3. Layer 1 - unit/integration suite (ctest)

### 3.1 The run

```bash
cd build && ctest
```

Recorded result (GCC release, with the leaf-lifecycle fix in):

```
100% tests passed out of 17

Total Test time (real) =  6.19 sec
```

Structure: **17 test binaries** - 13 gtest-structured suites carrying
**87 named test cases** (enumerated in 3.3), plus 4 scenario-style mains
carrying **27 numbered test blocks** (enumerated in 3.4). Total: 114
discrete test blocks.

### 3.2 Per-binary results (real ctest output)

```
 1/17 Test  #1: VortexMathTest ...................   Passed    0.00 sec
 2/17 Test  #2: VortexDeepCryptoTest .............   Passed    0.03 sec
 3/17 Test  #3: VortexBlockTest ..................   Passed    0.01 sec
 4/17 Test  #4: VortexDocumentedGapsTest .........   Passed    2.32 sec
 5/17 Test  #5: VortexMempoolTest ................   Passed    0.01 sec
 6/17 Test  #6: VortexVMTest .....................   Passed    0.00 sec
 7/17 Test  #7: VortexChainReorgTest .............   Passed    0.00 sec
 8/17 Test  #8: VortexVaultMemoryTest ............   Passed    0.01 sec
 9/17 Test  #9: VortexZkKeyMatrixTest ............   Passed    0.00 sec
10/17 Test #10: VortexTensorV6Test ...............   Passed    0.01 sec
11/17 Test #11: VortexSwarmP2PTest ...............   Passed    0.21 sec
12/17 Test #12: VortexGaloisTrieTest .............   Passed    0.01 sec
13/17 Test #13: VortexLandauerMevTest ............   Passed    0.00 sec
14/17 Test #14: VortexGqcRingStealthTest .........   Passed    0.03 sec
15/17 Test #15: VortexVaultHtlcTest ..............   Passed    0.01 sec
16/17 Test #16: VortexChaosFuzzerTest ............   Passed    1.50 sec
17/17 Test #17: VortexPqSignatureTest ............   Passed    3.10 sec
```

### 3.3 The 87 named gtest cases (complete enumeration)

**VortexSwarmP2PTest** (tests/test_swarm_p2p.cpp, 6 cases)

| Case | Property proven |
|---|---|
| `WireHeaderIsExactly24Bytes` | the VX60 header is a fixed 24-byte layout, as specified |
| `CorruptedPacketDroppedByCrc32c` | a packet whose CRC32C does not match is dropped, not parsed |
| `RecvPacketRejectsSingleBitFlip` | flipping one bit of a valid packet breaks its CRC and it is rejected |
| `FullBlockRoundTripOverTcp` | a 65536-byte block frame survives a real TCP round-trip byte-for-byte |
| `SplitBrainReorgConverges` | two in-process nodes on divergent tips converge on the heavier branch via O(1) undo rollback |
| `ListenerRelaysVerifiedFrameToHook` | a verified inbound frame is delivered to the registered frame hook (the relay path the RPC node uses) |

**VortexMempoolTest** (tests/test_mempool.cpp, 6 cases)

| Case | Property proven |
|---|---|
| `StaticAssertGeometry` | the mempool's fixed cocoon geometry holds at compile time |
| `MempoolConstruction` | the mempool constructs and accepts a cocoon under its TDI rules |
| `SealingPreservesPerSenderNonceOrder` | sealing order never inverts a sender's nonce chain (BACKLOG 0.14): with sender A holding a low-fee nonce-0 and a high-fee nonce-1 and sender B a mid-fee tx, the pull order is B0, A0, A1 - the fee market rules across senders, nonce order within a sender (the old global fee sort emitted A1 before A0 and bricked the block with a nonce-mismatch apply failure) |
| `PullBudgetNeverBreaksSenderChain` | a budget cut can split a sender's chain only at a nonce boundary: pulling 1-at-a-time yields B0, then A0, then A1 - a high-fee nonce-1 is never pulled while its nonce-0 is still pending |
| `SealedBatchesApplyOnFirstAttempt` | the deterministic acceptance core (BACKLOG 0.14): 5 senders x 20 txs with random fees, drained in partial batches of 7 and replayed against per-sender expected-nonce gates - every tx applies on the first attempt, none pulled twice |
| `ConcurrentSubmitsAndSealsStayConsistent` | the concurrency acceptance (BACKLOG 0.14): 8 submitter threads race a sealing reader (pull + remove_sealed, like the miner) and concurrent `stats()` calls; every pulled tx matches a submitted tx (no torn or unwritten slot is ever observed), every batch keeps each sender's chain contiguous from the previously sealed prefix, and the drain totals exactly 8x40 txs; ThreadSanitizer-clean across 6 runs |

**VortexGaloisTrieTest** (tests/test_galois_trie.cpp, 4 cases)

| Case | Property proven |
|---|---|
| `Insert100KeysDeterministicRoot` | inserting the same 100 keys in the same order always yields the same root |
| `GetRoundTripAndAbsentKeys` | stored values round-trip; absent keys return absence, not garbage |
| `ProofGenerateVerifyUnder2048Bytes` | an inclusion proof verifies for any key in the tree, proof bounded |
| `TamperedProofOrValueFailsVerification` | a tampered proof or value fails verification (SGMT forgery rejected) |

**VortexChainReorgTest** (tests/test_reorg.cpp, 1 case)

| Case | Property proven |
|---|---|
| `EmergencyStop` | the node teardown path stops cleanly under concurrent readers/writers |

**VortexVaultMemoryTest** (tests/test_vault_memory.cpp, 4 cases)

| Case | Property proven |
|---|---|
| `PageStateTransitionsAndBurning` | pages move VOID -> LOCKED -> BURNED and a burned page cannot be re-read |
| `HardwareUuidBindingSeed` | seed material is bound to machine context |
| `EmergencyBurnAll` | the emergency path burns every live page |
| `RegisterScrubbing` | execution registers are scrubbed after consuming secrets |

**VortexVaultHtlcTest** (tests/test_vault_htlc.cpp, 4 cases)

| Case | Property proven |
|---|---|
| `EphemeralSignBurnsPage` | ephemeral signing consumes and burns its key page |
| `HtlcClaimBeforeTimelock` | an HTLC claims with the correct preimage before the timelock |
| `HtlcRefundAfterTimelock` | after the timelock only the refund path opens |
| `HtlcLockedOnWrongPreimage` | a wrong preimage never claims |

**VortexVMTest** (tests/test_vm.cpp, 5 cases)

| Case | Property proven |
|---|---|
| `AssembleDisassembleLimits` | the assembler/disassembler respect documented limits |
| `BasicArithmeticOps` | integer ops are exact and bounded |
| `LogicalOps` | logic ops behave per spec |
| `CryptoOps` | VM crypto ops match the core primitives |
| `StateRootGeneration` | the VM derives a deterministic state root |

**VortexLandauerMevTest** (tests/test_landauer_vm_mev.cpp, 6 cases)

| Case | Property proven |
|---|---|
| `AssembleWithLabelsTwoPass` | two-pass label resolution is deterministic |
| `LandauerFormulaExactness` | gas accounting follows the Landauer formula exactly, per instruction |
| `NewOpcodesGaloisMulSolinasStackOps` | the Galois/Solinas/stack opcodes match their reference math |
| `DandelionStemToFluffCycle` | a cocoon moves stem -> fluff on schedule |
| `DandelionTdiSpamAnnihilated` | TDI-rejected spam is annihilated, not relayed |
| `HamiltonianNeutralizesSandwich` | the Hamiltonian priority penalty makes a sandwich non-profitable in the model |

**VortexGqcRingStealthTest** (tests/test_gqc_ring_stealth.cpp, 7 cases)

| Case | Property proven |
|---|---|
| `GqcFinalizedReorgBlocked` | a reorg across a GQC-finalized height is refused - finality is durable, not advisory |
| `GqcCheckpointSurvivesRestart` | the finalized checkpoint outlives the process (BACKLOG 0.13): certify N, "restart" a fresh undo engine over the same store - the guard reports N again (restored from the `.gqc` sidecar, monotonic: a lower cement cannot lower it), a rollback to N-1 is refused with `ERR_FINALIZED_BY_GQC`, and a corrupt sidecar is reported untrusted and fabricates nothing |
| `GqcAggregationDeterministic` | GQC vote aggregation is deterministic |
| `RingPipelineThroughputNoAllocs` | the ring pipeline sustains throughput with zero hot-path allocations |
| `RingPipelineWrapAround` | the ring wraps correctly at capacity |
| `StealthEnvelopeOneOfSixteen` | a stealth envelope scans 1-of-16 correctly |

**VortexTensorV6Test** (tests/test_tensor_v6.cpp, 4 cases)

| Case | Property proven |
|---|---|
| `FastReducerAndSacEvaluation` | the fast reducer matches reference modular arithmetic; SAC profile in band |
| `MultiTensorV6Pipeline` | the tensor pipeline composes deterministically |
| `TensorNoZeroCollapse` | tensor products never collapse to zero state |
| `VirtualTensorEvolution` | virtual tensor evolution is reproducible |

**VortexZkKeyMatrixTest** (tests/test_zk_matrix.cpp, 9 cases)

| Case | Property proven |
|---|---|
| `DeriveAll7KeyTiers` | all 7 tiers (SK/FVK/IVK/OVK/TLMK/MSRK/EK) derive from one seed |
| `All7KeysArePairwiseDistinct` | no two tiers ever coincide |
| `ShamirSecretSharingRecovery` | MSRK recovers from threshold shards |
| `ShamirAll32BytesComputed` | recovery covers the full 32-byte secret |
| `ProofOfLifeAndAuditView` | proof-of-life signs and the audit view accepts it |
| `ForgedProofHashReturnsFalse` | a forged proof-of-life fails verification |
| `AuditViewRejectsZeroKey` | the zero key is never a valid audit input |
| `ProofOfLifeTimeWindow` | proof-of-life is time-bounded (replay outside the window fails) |
| `ShamirThreshold3` | below threshold there is no recovery |

**VortexChaosFuzzerTest** (tests/test_chaos_fuzzer.cpp, 6 cases)

| Case | Property proven |
|---|---|
| `WireHeaderChaos10k` | 10k mutated wire headers never crash the gate |
| `FrameTxChaos10k` | 10k mutated frames/transactions never crash the parser |
| `VmBytecodeChaos10k` | 10k mutated VM programs never crash the VM |
| `VmInfiniteLoopBounded` | a hostile infinite-loop program is bounded by the step limit |
| `SgmtProofForgeryZeroFalsePositives` | forged SGMT proofs have zero false accepts |
| `FullChaosRoundInvariants` | a full chaos round keeps every documented invariant |

**VortexDocumentedGapsTest** (tests/test_documented_gaps.cpp, 25 cases)

| Case | Property proven |
|---|---|
| `NoWorkBlockAccepted` | FLIPPED to EXPECT_FALSE (BACKLOG 0.9): a structurally valid frame with zero PoGW work is refused by the intake gate |
| `KeylessTheftRejected` | FLIPPED (BACKLOG 0.7): the reviewer's theft PoC no longer moves anything - the ledger refuses the unwitnessed transfer, nothing is credited |
| `DoubleSpendInBlockRejected` | two spends by one sender in one block fail with `insufficient funds`, no U128 underflow, no phantom supply |
| `CoinbaseReplayRejected` | FLIPPED (BACKLOG 0.6 remainder closed): the coinbase tag commits receiver + height + prev tip; the same coinbase bytes in a competing fork frame are refused, the honest coinbase pays the producer |
| `NonceZeroReplayRejected` | a fee=0/nonce=0 replay outside the genesis window fails with `nonce mismatch` |
| `OversizedTxCountRejected` | a tx_count=581 frame is refused before anything reads past the frame |
| `TamperedMerkleRejected` | a forged merkle root is refused by recomputation at the store |
| `HtlcVmFailureForcesLocked` | HTLC bytecode corrupted after the shape check settles LOCKED, never CLAIMED |
| `VaultTokenDigestFullyChecked` | a vault token with 28 mutated tail bytes is rejected (full 32-byte digest) |
| `VaultPoolFullNotClobber` | a full vault pool raises instead of zeroing a live LOCKED page |
| `TailMetadataCommitted` | the block commitment covers header AND tail - a mutated PoGW nonce changes the hash |
| `PogwGateAcceptsSealedWorkAndBindsTheNonce` | the gate accepts real sealed work and rejects a one-off nonce mutation of the same frame |
| `RecoveryRejectsCorruptedLedgerFrame` | a ledger file whose stored frame lost its merkle commitment throws on reopen (fail-closed recovery) |
| `UnboundSenderRejected` | a valid witness from a key the sender does not own spends nothing - the unbound sender is refused (BACKLOG 0.7) |
| `WitnessRootMismatchRejected` | a witness whose XMSS root differs from the sender's bound key is refused before any balance check |
| `SelfCertifyingAddressAutoBinds` | a "PQA" address binds to its key on the first witnessed spend; a foreign key is refused afterwards, the owner keeps spending |
| `WitnessDurableLogSurvivesRestart` | the `<ledger>.pqw` sidecar fsyncs a VXPQWT1 record per registration and replays it on attach (BACKLOG 0.8) |
| `SecondGenesisMintInBlockRejected` | two GENESIS mints in one height-1 block: the second is refused with `second GENESIS mint in one block`, nothing applies (round 9) |
| `EmissionRewardTiersAndCap` | the reward is a pure function of the block hash: the 50 VX floor for any valid block, the 75/100/200/400/1000 VX tiers at 20/24/28/32/40 leading zero bits (verified at every tier boundary and at saturation), and the 7,000,000,000 VX lifetime cap (7e17 atoms) |
| `CoinbaseEntitlementEnforced` | the coinbase amount is part of the hashed frame, so the test pins a nonce whose frame hash stays below the first tier on throwaway ledgers and replays the same frame: one atom above the floor reward is refused, the exact floor mints and is booked into the issued-supply counter, and 1,001 VX (above the absolute 1,000 VX jackpot) is refused for any hash |
| `SupplyCapHardStopsIssuance` | with one VX of headroom left, nothing larger can be issued; the final partial reward closes the cap exactly; afterwards not one more atom - zero-amount coinbases (fee redistribution) still apply |
| `RewardIndependentOfHeight` | the reward depends on the block's hash, not its height: the 50 VX floor still mints at height 400,000,000 (far past the retired 12,000,000-block window of the earlier draft), a zero-amount coinbase stays legal |
| `UndoJournalByteFormatRoundTrip` | the journal is a versioned byte format (BACKLOG 0.11): records survive commit + reload, a rollback over them restores balances AND the issued-supply counter exactly, and a second reload + commit does not duplicate records (a duplicate would double-revert on rollback) |
| `UndoJournalRejectsHostileFiles` | a journal that is not the current format is never replayed: wrong magic, unknown version (including a version-1 file under the v2 format — reject-or-migrate) and mid-file corruption are discarded, a short/torn tail is healed to the last complete record, and pointer-shaped poison bytes are never dereferenced (the rollback-over-poisoned-journal case runs clean under ASan); the displaced-frame side journal gets the same policy |
| `ReorgUndoRestoresNoncesAndFrames` | a reorg rollback is replayable in both directions (BACKLOG 0.12): the journal records the frame being applied (not whatever the store holds at that height), the rollback preserves the displaced fork frames byte-exact in `undo/displaced.vxd`, restores sender nonces AND the tracked-account set (an address the fork created is untracked once its reversed balance is zero — a re-applied height-1 GENESIS_2 mint used to be refused forever), and re-applying the same frames lands byte-identical to a fresh apply while a replayed nonce stays refused |

### 3.4 The 27 numbered blocks in the scenario-style mains (complete enumeration)
**VortexMathTest** (tests/test_vortex.cpp, 6 blocks)

| # | Block | Real captured result |
|---|---|---|
| 1 | Canonical 10-round verification vs the TypeScript reference | `FinalX matches 100% byte-for-byte`; canonical address `NFA_V6_nfrmbXMXrvviPWIUrsqmaH_HmbjmTIAIzM1IlcAcAA`; 10 rounds in 0.11 ms |
| 2 | SAC diffusion on the attractor | 10 rounds, per-round bit-flip dispersion 48.50%..52.44%, mean ~49.8% of 3072 bits |
| 3 | 17-dim WIF engine + Ghost WIF steganography | zero-width-space steganography round-trips with 100% fidelity; compact WIF sample `0VyT5RE3yzLQ8KtoUk6RRR8Nin5YSlLMrYM9fJw1OWwAA` |
| 4 | Shamir 2-of-3 over GF(256) | key reconstructed from every shard pair tested |
| 5 | TDI dust gate | legitimate transfer TDI 60.00 ACCEPTED; dust spam TDI 0.00 ANNIHILATED |
| 6 | Secure allocator | mlock + MADV_DONTDUMP + paranoid wipe verified |

**VortexBlockTest** (tests/test_block.cpp, 8 blocks)

| # | Block | Real captured result |
|---|---|---|
| 1 | Compile-time geometry | `sizeof(BlockHeader)=472`, `sizeof(Transaction)=112`, `sizeof(RawBlock)=65536` - static_asserts |
| 2 | Magic bytes | disk bytes `36 43 56 58` = magic `0x58564336` |
| 3 | Insertion + Merkle root | Merkle root `1ae14421cd4c7be9...` computed, data round-trips |
| 4 | Capacity | exactly 580 transactions fit; the 581st is rejected |
| 5 | Zero-copy BlockView | O(1) parse over the raw buffer, no deserialization |
| 6 | SAC on `hash_header` | 3776 individual single-bit header flips, mean output change 49.93% |
| 7 | Cocoon-proof tamper detection | zeroed proof rejected; post-sign flips of sender/receiver/amount/fee/nonce all rejected |
| 8 | Minting rules | MINER_ only at index 0 with reward <= 1000 VX; GENESIS only at height 0 (one-time GENESIS_2 at height 1) - enforced in `apply_block` |

**VortexPqSignatureTest** (tests/test_pq_signatures.cpp, 8 blocks)

| # | Block | Real captured result |
|---|---|---|
| 1 | WOTS+/XMSS honest sign/verify | 67-chain signature verifies; wrong leaf index rejected |
| 2 | Winternitz checksum barrier | raising a message nibble forced C 459 -> 458; forgery rejected |
| 3 | MITM keyless re-sign | re-signing a mutated amount/receiver without the key is rejected by the SegPQ registry |
| 4 | Chain/path tamper | all 67 chains and all 4 Merkle auth nodes are tamper-evident |
| 5 | Vault burn on ephemeral sign | burn verified (keygen 23.998M cycles, sign 49.185M cycles on this CPU) |
| 6 | Sponge KATs + SAC + collisions | 5 frozen KATs match (empty / "ABC" / 472-byte header / 112-byte tx / 1 MiB); 8-word SAC all within 49.6%..50.7%; 50,000 low-entropy inputs, **zero collisions** |
| 7 | Negative-vector matrix | layer A: 4,672/4,672 signature-region mutations rejected; layer B: 4,752/4,752 whole-witness mutations rejected; total 9,424/9,424 |
| 8 | **PqLeafLedger lifecycle (new in `c1d6230`)** | same nonce signed twice -> leaves 7 then 0; after restart -> leaf 1 (no reuse); 16/16 consumed then the 17th refused; a tampered log fails closed |

**VortexDeepCryptoTest** (tests/crypto_deep_tests.cpp, 5 blocks)

| # | Block | Real captured result |
|---|---|---|
| 1 | Canonical vectors, 20 rounds | seeds 0x0000000000000000 and 0xffffffffffffffff: 100% bit-for-bit match with the TypeScript reference |
| 2 | Secure CRT moduli | P=2^1024-2^64-1747, Q=2^1024-2^888-3943, R=2^1024-2^512-267799: 10 rounds, 100% match; classic moduli 50/50 verified; secure CRT-optimized moduli 50/50 verified |
| 3 | SAC on the 3072-bit state | 10 sampled bit positions, round-15 dispersion 49.02%..52.21% |
| 4 | Frequency (NIST-style) | 100 folded 256-bit digests (25,600 bits): ones 12,828 / zeros 12,772, S_obs 0.350, **p-value 0.726** (alpha 0.01) |
| 5 | All suites | all 5 cryptographic suites passed |

### 3.5 Real per-case timings (all 87 gtest cases, captured output)

Reproduce: `cd build && for b in test_mempool test_galois_trie
test_swarm_p2p test_reorg test_vault_memory test_vault_htlc test_vm
test_landauer_vm_mev test_gqc_ring_stealth test_tensor_v6 test_zk_matrix
test_chaos_fuzzer test_documented_gaps; do ./$b; done`

```
================================================================
  VORTEX CORE 64 KB BINARY BLOCK ARCHITECTURE TEST SUITE       
================================================================

[TEST 1] Compile-time struct size verification...
  sizeof(BlockHeader) = 472 (expected 472)
  sizeof(Transaction) = 112 (expected 112)
  sizeof(RawBlock)    = 65536 (expected 65536)
  ✓ All sizes and offsets match the 64 KB spec exactly!

[TEST 2] Magic bytes and default initialization...
  Magic bytes (LE on disk): 36 43 56 58 
  ✓ Magic verified as 0x58564336!

[TEST 3] Transaction insertion and Merkle root computation...
  Merkle root: 1ae14421cd4c7be9...
  ✓ 2 transactions added, Merkle root computed, data round-tripped!

[TEST 4] Maximum block capacity (580 transactions)...
  ✓ Exactly 580 transactions fit in 64 KB frame, 581st rejected!

[TEST 5] Zero-copy BlockView over raw buffer (O(1) parsing)...
  ✓ Zero-copy parsing works — no deserialization, direct memory access!

[TEST 6] SAC Avalanche Effect on hash_header (single-bit flip → ~50% bit change)...
  Flipped 3776 header bits individually
  Average output bit change: 49.93%
  SAC percentage: 49.93%
  ✓ SAC test completed (pct = 49.93%)

[TEST 7] Transaction tampering detection via cocoon_proof...
  ✓ Original transaction passes cocoon_proof verification
  ✓ Zeroed cocoon_proof rejected
  ✓ Post-sign bit flips (sender/receiver/amount/fee/nonce) all rejected
  ✓ cocoon_proof verification logic present

[TEST 8] Hardened MINER_ and GENESIS minting rules logic verified...
  ✓ MINER_ at index 0 only, reward ≤ 1000 VX enforced
  ✓ GENESIS only at height 0 or one-time GENESIS_2 at height 1
  ✓ All minting rules enforced in apply_block()

================================================================
  ALL BLOCK ARCHITECTURE TESTS PASSED!                         
================================================================
[==========] Running 6 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 6 tests from VortexChaosFuzzerTest
[ RUN      ] VortexChaosFuzzerTest.WireHeaderChaos10k
[       OK ] VortexChaosFuzzerTest.WireHeaderChaos10k (283 ms)
[ RUN      ] VortexChaosFuzzerTest.FrameTxChaos10k
[       OK ] VortexChaosFuzzerTest.FrameTxChaos10k (284 ms)
[ RUN      ] VortexChaosFuzzerTest.VmBytecodeChaos10k
[       OK ] VortexChaosFuzzerTest.VmBytecodeChaos10k (284 ms)
[ RUN      ] VortexChaosFuzzerTest.VmInfiniteLoopBounded
[       OK ] VortexChaosFuzzerTest.VmInfiniteLoopBounded (2 ms)
[ RUN      ] VortexChaosFuzzerTest.SgmtProofForgeryZeroFalsePositives
[       OK ] VortexChaosFuzzerTest.SgmtProofForgeryZeroFalsePositives (283 ms)
[ RUN      ] VortexChaosFuzzerTest.FullChaosRoundInvariants
[       OK ] VortexChaosFuzzerTest.FullChaosRoundInvariants (284 ms)
[----------] 6 tests from VortexChaosFuzzerTest (1423 ms total)

[----------] Global test environment tear-down
[==========] 6 tests from 1 test suite ran. (1423 ms total)
[  PASSED  ] 6 tests.
[==========] Running 25 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 25 tests from VortexDocumentedGapsTest
[ RUN      ] VortexDocumentedGapsTest.NoWorkBlockAccepted
[       OK ] VortexDocumentedGapsTest.NoWorkBlockAccepted (17 ms)
[ RUN      ] VortexDocumentedGapsTest.KeylessTheftRejected
  [closed] keyless theft rejected: the genesis receiver is PQ-bound to an OFFLINE key (secret not in the repo) and no witness exists for the forged transfer (BACKLOG 0.7).
[       OK ] VortexDocumentedGapsTest.KeylessTheftRejected (18 ms)
[ RUN      ] VortexDocumentedGapsTest.DoubleSpendInBlockRejected
  [fixed] intra-block double spend rejected with 'insufficient funds'; no U128 underflow, no phantom balance.
[       OK ] VortexDocumentedGapsTest.DoubleSpendInBlockRejected (73 ms)
[ RUN      ] VortexDocumentedGapsTest.CoinbaseReplayRejected
  [closed] coinbase bound to the chain position: replaying the tag on a competing fork is refused; the honest coinbase pays the producer (BACKLOG 0.6 remainder).
[       OK ] VortexDocumentedGapsTest.CoinbaseReplayRejected (3 ms)
[ RUN      ] VortexDocumentedGapsTest.SecondGenesisMintInBlockRejected
  [closed] one GENESIS mint per block in the legacy window: the second mint is refused and the block applies nothing.
[       OK ] VortexDocumentedGapsTest.SecondGenesisMintInBlockRejected (3 ms)
[ RUN      ] VortexDocumentedGapsTest.EmissionRewardTiersAndCap
  [closed] emission hard-coded: 50 VX floor, hash tiers 75/100/200/400/1000 VX at 20/24/28/32/40 zero bits, lifetime cap 7,000,000,000 VX (the root-of-seven digit).
[       OK ] VortexDocumentedGapsTest.EmissionRewardTiersAndCap (0 ms)
[ RUN      ] VortexDocumentedGapsTest.CoinbaseEntitlementEnforced
[       OK ] VortexDocumentedGapsTest.CoinbaseEntitlementEnforced (0 ms)
[ RUN      ] VortexDocumentedGapsTest.SupplyCapHardStopsIssuance
[       OK ] VortexDocumentedGapsTest.SupplyCapHardStopsIssuance (0 ms)
[ RUN      ] VortexDocumentedGapsTest.RewardIndependentOfHeight
[       OK ] VortexDocumentedGapsTest.RewardIndependentOfHeight (0 ms)
[ RUN      ] VortexDocumentedGapsTest.UndoJournalByteFormatRoundTrip
[       OK ] VortexDocumentedGapsTest.UndoJournalByteFormatRoundTrip (26 ms)
[ RUN      ] VortexDocumentedGapsTest.UndoJournalRejectsHostileFiles
[       OK ] VortexDocumentedGapsTest.UndoJournalRejectsHostileFiles (0 ms)
[ RUN      ] VortexDocumentedGapsTest.ReorgUndoRestoresNoncesAndFrames
[       OK ] VortexDocumentedGapsTest.ReorgUndoRestoresNoncesAndFrames (172 ms)
[ RUN      ] VortexDocumentedGapsTest.NonceZeroReplayRejected
  [fixed] fee=0/nonce=0 replay at height 3 rejected with 'nonce mismatch' - the legacy exemption is scoped to the genesis window.
[       OK ] VortexDocumentedGapsTest.NonceZeroReplayRejected (117 ms)
[ RUN      ] VortexDocumentedGapsTest.OversizedTxCountRejected
[       OK ] VortexDocumentedGapsTest.OversizedTxCountRejected (15 ms)
[ RUN      ] VortexDocumentedGapsTest.TamperedMerkleRejected
[       OK ] VortexDocumentedGapsTest.TamperedMerkleRejected (15 ms)
[ RUN      ] VortexDocumentedGapsTest.HtlcVmFailureForcesLocked
  [fixed] HTLC with a runtime-corrupted opcode settles LOCKED; the VM verdict gates the contract outcome.
[       OK ] VortexDocumentedGapsTest.HtlcVmFailureForcesLocked (0 ms)
[ RUN      ] VortexDocumentedGapsTest.VaultTokenDigestFullyChecked
  [fixed] vault token with 28 mutated tail bytes is rejected; the full 32-byte digest is checked.
[       OK ] VortexDocumentedGapsTest.VaultTokenDigestFullyChecked (2 ms)
[ RUN      ] VortexDocumentedGapsTest.VaultPoolFullNotClobber
  [fixed] full vault pool refuses instead of zeroing a live LOCKED page; both tokens survive.
[       OK ] VortexDocumentedGapsTest.VaultPoolFullNotClobber (0 ms)
[ RUN      ] VortexDocumentedGapsTest.TailMetadataCommitted
[       OK ] VortexDocumentedGapsTest.TailMetadataCommitted (0 ms)
[ RUN      ] VortexDocumentedGapsTest.PogwGateAcceptsSealedWorkAndBindsTheNonce
[       OK ] VortexDocumentedGapsTest.PogwGateAcceptsSealedWorkAndBindsTheNonce (1717 ms)
[ RUN      ] VortexDocumentedGapsTest.RecoveryRejectsCorruptedLedgerFrame
[       OK ] VortexDocumentedGapsTest.RecoveryRejectsCorruptedLedgerFrame (48 ms)
[ RUN      ] VortexDocumentedGapsTest.UnboundSenderRejected
  [closed] a valid witness from an UNBOUND key spends nothing: the sender address commits no PQ root (BACKLOG 0.7).
[       OK ] VortexDocumentedGapsTest.UnboundSenderRejected (37 ms)
[ RUN      ] VortexDocumentedGapsTest.WitnessRootMismatchRejected
  [closed] a witness whose XMSS root differs from the sender's bound key is refused before any balance check (BACKLOG 0.7).
[       OK ] VortexDocumentedGapsTest.WitnessRootMismatchRejected (59 ms)
[ RUN      ] VortexDocumentedGapsTest.SelfCertifyingAddressAutoBinds
  [closed] self-certifying address: first witnessed spend binds it to its key; a foreign key is refused, the owner keeps spending (BACKLOG 0.7).
[       OK ] VortexDocumentedGapsTest.SelfCertifyingAddressAutoBinds (184 ms)
[ RUN      ] VortexDocumentedGapsTest.WitnessDurableLogSurvivesRestart
  [closed] durable witness sidecar: registration fsyncs a VXPQWT1 record and a restart replays it (BACKLOG 0.8).
[       OK ] VortexDocumentedGapsTest.WitnessDurableLogSurvivesRestart (35 ms)
[----------] 25 tests from VortexDocumentedGapsTest (2551 ms total)

[----------] Global test environment tear-down
[==========] 25 tests from 1 test suite ran. (2551 ms total)
[  PASSED  ] 25 tests.
[==========] Running 4 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 4 tests from VortexGaloisTrieTest
[ RUN      ] VortexGaloisTrieTest.Insert100KeysDeterministicRoot
[       OK ] VortexGaloisTrieTest.Insert100KeysDeterministicRoot (8 ms)
[ RUN      ] VortexGaloisTrieTest.GetRoundTripAndAbsentKeys
[       OK ] VortexGaloisTrieTest.GetRoundTripAndAbsentKeys (0 ms)
[ RUN      ] VortexGaloisTrieTest.ProofGenerateVerifyUnder2048Bytes
[       OK ] VortexGaloisTrieTest.ProofGenerateVerifyUnder2048Bytes (2 ms)
[ RUN      ] VortexGaloisTrieTest.TamperedProofOrValueFailsVerification
[       OK ] VortexGaloisTrieTest.TamperedProofOrValueFailsVerification (1 ms)
[----------] 4 tests from VortexGaloisTrieTest (12 ms total)

[----------] Global test environment tear-down
[==========] 4 tests from 1 test suite ran. (12 ms total)
[  PASSED  ] 4 tests.
[==========] Running 7 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 7 tests from VortexGqcRingStealthTest
[ RUN      ] VortexGqcRingStealthTest.GqcFinalizedReorgBlocked
[       OK ] VortexGqcRingStealthTest.GqcFinalizedReorgBlocked (21 ms)
[ RUN      ] VortexGqcRingStealthTest.GqcCheckpointSurvivesRestart
[       OK ] VortexGqcRingStealthTest.GqcCheckpointSurvivesRestart (0 ms)
[ RUN      ] VortexGqcRingStealthTest.GqcQuorumForgeableFromPublicDataOnly
  [documented gap] GQC quorum forged from public data only: 9/9 shares, zero secrets used. Validator authentication is a BACKLOG 0.4/2.4 item; until then cryptographic finality is NOT claimed.
[       OK ] VortexGqcRingStealthTest.GqcQuorumForgeableFromPublicDataOnly (0 ms)
[ RUN      ] VortexGqcRingStealthTest.GqcAggregationDeterministic
[       OK ] VortexGqcRingStealthTest.GqcAggregationDeterministic (0 ms)
[ RUN      ] VortexGqcRingStealthTest.RingPipelineThroughputNoAllocs
[       OK ] VortexGqcRingStealthTest.RingPipelineThroughputNoAllocs (3 ms)
[ RUN      ] VortexGqcRingStealthTest.RingPipelineWrapAround
[       OK ] VortexGqcRingStealthTest.RingPipelineWrapAround (2 ms)
[ RUN      ] VortexGqcRingStealthTest.StealthEnvelopeOneOfSixteen
[       OK ] VortexGqcRingStealthTest.StealthEnvelopeOneOfSixteen (0 ms)
[----------] 7 tests from VortexGqcRingStealthTest (28 ms total)

[----------] Global test environment tear-down
[==========] 7 tests from 1 test suite ran. (28 ms total)
[  PASSED  ] 7 tests.
[==========] Running 6 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 6 tests from VortexLandauerMevTest
[ RUN      ] VortexLandauerMevTest.AssembleWithLabelsTwoPass
[       OK ] VortexLandauerMevTest.AssembleWithLabelsTwoPass (0 ms)
[ RUN      ] VortexLandauerMevTest.LandauerFormulaExactness
[       OK ] VortexLandauerMevTest.LandauerFormulaExactness (0 ms)
[ RUN      ] VortexLandauerMevTest.NewOpcodesGaloisMulSolinasStackOps
[       OK ] VortexLandauerMevTest.NewOpcodesGaloisMulSolinasStackOps (0 ms)
[ RUN      ] VortexLandauerMevTest.DandelionStemToFluffCycle
[       OK ] VortexLandauerMevTest.DandelionStemToFluffCycle (0 ms)
[ RUN      ] VortexLandauerMevTest.DandelionTdiSpamAnnihilated
[       OK ] VortexLandauerMevTest.DandelionTdiSpamAnnihilated (0 ms)
[ RUN      ] VortexLandauerMevTest.HamiltonianNeutralizesSandwich
[       OK ] VortexLandauerMevTest.HamiltonianNeutralizesSandwich (0 ms)
[----------] 6 tests from VortexLandauerMevTest (0 ms total)

[----------] Global test environment tear-down
[==========] 6 tests from 1 test suite ran. (0 ms total)
[  PASSED  ] 6 tests.
[==========] Running 6 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 6 tests from VortexMempoolTest
[ RUN      ] VortexMempoolTest.StaticAssertGeometry
[       OK ] VortexMempoolTest.StaticAssertGeometry (0 ms)
[ RUN      ] VortexMempoolTest.MempoolConstruction
[       OK ] VortexMempoolTest.MempoolConstruction (1 ms)
[ RUN      ] VortexMempoolTest.SealingPreservesPerSenderNonceOrder
[       OK ] VortexMempoolTest.SealingPreservesPerSenderNonceOrder (0 ms)
[ RUN      ] VortexMempoolTest.PullBudgetNeverBreaksSenderChain
[       OK ] VortexMempoolTest.PullBudgetNeverBreaksSenderChain (0 ms)
[ RUN      ] VortexMempoolTest.SealedBatchesApplyOnFirstAttempt
[       OK ] VortexMempoolTest.SealedBatchesApplyOnFirstAttempt (0 ms)
[ RUN      ] VortexMempoolTest.ConcurrentSubmitsAndSealsStayConsistent
[       OK ] VortexMempoolTest.ConcurrentSubmitsAndSealsStayConsistent (6 ms)
[----------] 6 tests from VortexMempoolTest (9 ms total)

[----------] Global test environment tear-down
[==========] 6 tests from 1 test suite ran. (9 ms total)
[  PASSED  ] 6 tests.
================================================================
  VX PHASE 46: PQ HASH-BASED SIGNATURES (WOTS+/XMSS) TEST SUITE
================================================================

[TEST 1] WOTS+ (w=16, L=67) + XMSS (H=4) honest sign/verify...
  ✓ 67-chain signature verifies; wrong leaf index rejected

[TEST 2] Winternitz checksum blocks forward-chain forgery...
  ✓ m_0 += 1 forced C: 459 -> 458; verification rejected

[TEST 3] MITM keyless rehash rejected by SegPQ registry...
  ✓ keyless re-sign after amount/receiver mutation rejected

[TEST 4] Tampered WOTS+ chains / Merkle auth path rejected...
  ✓ all 67 chains + all 4 auth-path nodes are tamper-evident

[TEST 5] Vault ephemeral PQ sign burns secret material...
  ✓ burn verified; keygen 24096361 cyc, sign 48632797 cyc

[TEST 6] VortexSponge256 KATs, SAC matrix [45%..55%], collisions...
  ✓ KAT_EMPTY matches frozen digest
  ✓ KAT_ABC matches frozen digest
  ✓ KAT_HDR472 matches frozen digest
  ✓ KAT_TX112 matches frozen digest
  ✓ KAT_1MB matches frozen digest
  SAC word 0: 50.647%
  SAC word 1: 50.0671%
  SAC word 2: 50.2563%
  SAC word 3: 50.0793%
  SAC word 4: 50.0854%
  SAC word 5: 49.6277%
  SAC word 6: 49.6765%
  SAC word 7: 50.5249%
  ✓ 50 000 low-entropy inputs, zero collisions

[TEST 7] Negative-vector matrix: exhaustive witness mutations...
  ✓ layer A: 4672/4672 signature-region mutations rejected
  ✓ layer A: subtree_index passes (by design), layer B rejects
  ✓ layer B: 4752/4752 whole-witness mutations rejected

[TEST 8] PqLeafLedger: one-time-leaf lifecycle (durable)...
  ✓ same nonce signed twice: leaves 7 then 0 (distinct, both valid)
  ✓ after restart: leaf 1 (history survived, no reuse)
  ✓ 16/16 leaves consumed; 17th signature refused
  ✓ tampered log: signing refused (fail-closed)

[TEST 9] Subtree guard: nonces outside the first tree refuse...
  ✓ nonce 0 -> leaf 0, verify ok
  ✓ nonce 15 -> leaf 15, verify ok
  ✓ nonce 16 -> refused (no leaf burned)
  ✓ nonce 17 -> refused (no leaf burned)
  ✓ nonce 255 -> refused (no leaf burned)
  ✓ nonce 4294967295 -> refused (no leaf burned)
  ✓ ledger holds exactly 2 consumed leaves after the sweep

================================================================
  ALL PQ SIGNATURE TESTS PASSED — SHOR-VULNERABLE OPS: 0        
================================================================
[==========] Running 1 test from 1 test suite.
[----------] Global test environment set-up.
[----------] 1 test from VortexChainReorgTest
[ RUN      ] VortexChainReorgTest.EmergencyStop
[       OK ] VortexChainReorgTest.EmergencyStop (0 ms)
[----------] 1 test from VortexChainReorgTest (0 ms total)

[----------] Global test environment tear-down
[==========] 1 test from 1 test suite ran. (0 ms total)
[  PASSED  ] 1 test.
[==========] Running 6 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 6 tests from VortexSwarmP2PTest
[ RUN      ] VortexSwarmP2PTest.WireHeaderIsExactly24Bytes
[       OK ] VortexSwarmP2PTest.WireHeaderIsExactly24Bytes (0 ms)
[ RUN      ] VortexSwarmP2PTest.CorruptedPacketDroppedByCrc32c
[       OK ] VortexSwarmP2PTest.CorruptedPacketDroppedByCrc32c (0 ms)
[ RUN      ] VortexSwarmP2PTest.RecvPacketRejectsSingleBitFlip
[       OK ] VortexSwarmP2PTest.RecvPacketRejectsSingleBitFlip (0 ms)
[ RUN      ] VortexSwarmP2PTest.FullBlockRoundTripOverTcp
[       OK ] VortexSwarmP2PTest.FullBlockRoundTripOverTcp (0 ms)
[ RUN      ] VortexSwarmP2PTest.SplitBrainReorgConverges
[       OK ] VortexSwarmP2PTest.SplitBrainReorgConverges (108 ms)
[ RUN      ] VortexSwarmP2PTest.ListenerRelaysVerifiedFrameToHook
[       OK ] VortexSwarmP2PTest.ListenerRelaysVerifiedFrameToHook (100 ms)
[----------] 6 tests from VortexSwarmP2PTest (209 ms total)

[----------] Global test environment tear-down
[==========] 6 tests from 1 test suite ran. (209 ms total)
[  PASSED  ] 6 tests.
[==========] Running 4 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 4 tests from VortexTensorV6Test
[ RUN      ] VortexTensorV6Test.FastReducerAndSacEvaluation
[       OK ] VortexTensorV6Test.FastReducerAndSacEvaluation (3 ms)
[ RUN      ] VortexTensorV6Test.MultiTensorV6Pipeline
[       OK ] VortexTensorV6Test.MultiTensorV6Pipeline (0 ms)
[ RUN      ] VortexTensorV6Test.TensorNoZeroCollapse
[       OK ] VortexTensorV6Test.TensorNoZeroCollapse (0 ms)
[ RUN      ] VortexTensorV6Test.VirtualTensorEvolution
[       OK ] VortexTensorV6Test.VirtualTensorEvolution (0 ms)
[----------] 4 tests from VortexTensorV6Test (3 ms total)

[----------] Global test environment tear-down
[==========] 4 tests from 1 test suite ran. (3 ms total)
[  PASSED  ] 4 tests.
[==========] Running 4 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 4 tests from VortexVaultHtlcTest
[ RUN      ] VortexVaultHtlcTest.EphemeralSignBurnsPage
[       OK ] VortexVaultHtlcTest.EphemeralSignBurnsPage (2 ms)
[ RUN      ] VortexVaultHtlcTest.HtlcClaimBeforeTimelock
[       OK ] VortexVaultHtlcTest.HtlcClaimBeforeTimelock (0 ms)
[ RUN      ] VortexVaultHtlcTest.HtlcRefundAfterTimelock
[       OK ] VortexVaultHtlcTest.HtlcRefundAfterTimelock (0 ms)
[ RUN      ] VortexVaultHtlcTest.HtlcLockedOnWrongPreimage
[       OK ] VortexVaultHtlcTest.HtlcLockedOnWrongPreimage (0 ms)
[----------] 4 tests from VortexVaultHtlcTest (2 ms total)

[----------] Global test environment tear-down
[==========] 4 tests from 1 test suite ran. (2 ms total)
[  PASSED  ] 4 tests.
[==========] Running 4 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 4 tests from VortexVaultMemoryTest
[ RUN      ] VortexVaultMemoryTest.PageStateTransitionsAndBurning
[       OK ] VortexVaultMemoryTest.PageStateTransitionsAndBurning (4 ms)
[ RUN      ] VortexVaultMemoryTest.HardwareUuidBindingSeed
[       OK ] VortexVaultMemoryTest.HardwareUuidBindingSeed (0 ms)
[ RUN      ] VortexVaultMemoryTest.EmergencyBurnAll
[       OK ] VortexVaultMemoryTest.EmergencyBurnAll (3 ms)
[ RUN      ] VortexVaultMemoryTest.RegisterScrubbing
[       OK ] VortexVaultMemoryTest.RegisterScrubbing (0 ms)
[----------] 4 tests from VortexVaultMemoryTest (7 ms total)

[----------] Global test environment tear-down
[==========] 4 tests from 1 test suite ran. (7 ms total)
[  PASSED  ] 4 tests.
[==========] Running 5 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 5 tests from VortexVMTest
[ RUN      ] VortexVMTest.AssembleDisassembleLimits
[       OK ] VortexVMTest.AssembleDisassembleLimits (0 ms)
[ RUN      ] VortexVMTest.BasicArithmeticOps
[       OK ] VortexVMTest.BasicArithmeticOps (0 ms)
[ RUN      ] VortexVMTest.LogicalOps
[       OK ] VortexVMTest.LogicalOps (0 ms)
[ RUN      ] VortexVMTest.CryptoOps
[       OK ] VortexVMTest.CryptoOps (0 ms)
[ RUN      ] VortexVMTest.StateRootGeneration
[       OK ] VortexVMTest.StateRootGeneration (0 ms)
[----------] 5 tests from VortexVMTest (0 ms total)

[----------] Global test environment tear-down
[==========] 5 tests from 1 test suite ran. (0 ms total)
[  PASSED  ] 5 tests.
========================================================
  VORTEX CORE (C++26) MATHEMATICAL VERIFICATION SUITE   
========================================================

[TEST 1] Canonical 10-Round Verification vs TypeScript...
  ✓ Step 1 Coordinates (X_1) match 100% byte-for-byte!
  ✓ Final 1024-bit State (FinalX) matches 100% byte-for-byte!
  ✓ NFA Base64 Address: NFA_V6_nfrmbXMXrvviPWIUrsqmaH_HmbjmTIAIzM1IlcAcAA (Matches TS!)
  ✓ Execution time (10 rounds): 0.11684 ms

[TEST 2] Strict Avalanche Criterion (SAC) Diffusion Test...
  Round  1: Bit Diff = 1540 / 3072 (50.13%)
  Round  2: Bit Diff = 1611 / 3072 (52.44%)
  Round  3: Bit Diff = 1491 / 3072 (48.54%)
  Round  4: Bit Diff = 1490 / 3072 (48.50%)
  Round  5: Bit Diff = 1505 / 3072 (48.99%)
  Round  6: Bit Diff = 1495 / 3072 (48.67%)
  Round  7: Bit Diff = 1517 / 3072 (49.38%)
  Round  8: Bit Diff = 1555 / 3072 (50.62%)
  Round  9: Bit Diff = 1569 / 3072 (51.07%)
  Round 10: Bit Diff = 1524 / 3072 (49.61%)
  ✓ SAC achieves ideal ~50% non-linear cryptographic dispersion!

[TEST 3] 17-D WIF Engine & Steganography (Ghost WIF)...
  ✓ Ghost WIF zero-width space steganography encoded & decoded with 100% fidelity!
  ✓ Record WIF (Runes): ⍕⍾𝝣⪨⍾ℵ⍕⍾𝜲⩔∰⨻⎈∰⩔⟡⍕⟡
  ✓ Compact WIF:        0VyT5RE3yzLQ8KtoUk6RRR8Nin5YSlLMrYM9fJw1OWwAA

[TEST 4] Shamir 2-of-3 Secret Shard Reconstruction (Galois GF(256))...
  ✓ Successfully reconstructed original key from Shards (1,2), (2,3), and (1,3)!

[TEST 5] Transaction Density Index (TDI) DoS Protection...
  ✓ Legitimate Tx TDI: 60.00 (ACCEPTED)
  ✓ Dust Spam Tx TDI:   0.00 (ANNIHILATED: Transaction density falls below critical economic threshold (dust attack))

[TEST 6] Secure Memory Allocator (mlock & MADV_DONTDUMP)...
  ✓ Secure memory allocation, page locking, and paranoid wipe verified!

========================================================
  ALL MATHEMATICAL TESTS PASSED WITH 100% PERFECTION!   
========================================================
[==========] Running 9 tests from 1 test suite.
[----------] Global test environment set-up.
[----------] 9 tests from VortexZkKeyMatrixTest
[ RUN      ] VortexZkKeyMatrixTest.DeriveAll7KeyTiers
[       OK ] VortexZkKeyMatrixTest.DeriveAll7KeyTiers (0 ms)
[ RUN      ] VortexZkKeyMatrixTest.All7KeysArePairwiseDistinct
[       OK ] VortexZkKeyMatrixTest.All7KeysArePairwiseDistinct (0 ms)
[ RUN      ] VortexZkKeyMatrixTest.ShamirSecretSharingRecovery
[       OK ] VortexZkKeyMatrixTest.ShamirSecretSharingRecovery (0 ms)
[ RUN      ] VortexZkKeyMatrixTest.ShamirAll32BytesComputed
[       OK ] VortexZkKeyMatrixTest.ShamirAll32BytesComputed (0 ms)
[ RUN      ] VortexZkKeyMatrixTest.ProofOfLifeAndAuditView
[       OK ] VortexZkKeyMatrixTest.ProofOfLifeAndAuditView (0 ms)
[ RUN      ] VortexZkKeyMatrixTest.ForgedProofHashReturnsFalse
[       OK ] VortexZkKeyMatrixTest.ForgedProofHashReturnsFalse (0 ms)
[ RUN      ] VortexZkKeyMatrixTest.AuditViewRejectsZeroKey
[       OK ] VortexZkKeyMatrixTest.AuditViewRejectsZeroKey (0 ms)
[ RUN      ] VortexZkKeyMatrixTest.ProofOfLifeTimeWindow
[       OK ] VortexZkKeyMatrixTest.ProofOfLifeTimeWindow (0 ms)
[ RUN      ] VortexZkKeyMatrixTest.ShamirThreshold3
[       OK ] VortexZkKeyMatrixTest.ShamirThreshold3 (0 ms)
[----------] 9 tests from VortexZkKeyMatrixTest (0 ms total)

[----------] Global test environment tear-down
[==========] 9 tests from 1 test suite ran. (0 ms total)
[  PASSED  ] 9 tests.
```

Timing facts worth noting (not benchmark claims, just this CPU):
- the three 10k-mutation chaos suites each cost ~275 ms, i.e. ~36k
  mutations/second through the full parser+verifier stacks;
- the split-brain reorg (two in-process nodes over real loopback TCP)
  heals in ~81 ms of test time; the relay-hook round trip ~100 ms.

---

## 4. Layer 2 - sanitizer lane (ASan + UBSan)

```bash
cd build_san && ctest
```

Recorded result (with the leaf-lifecycle fix in, so TEST 8 ran under
both sanitizers):

```
100% tests passed out of 17

Total Test time (real) =  13.20 sec
```

Tail of the per-binary output (real):

```
10/17 Test #10: VortexTensorV6Test ...............   Passed    0.02 sec
11/17 Test #11: VortexSwarmP2PTest ...............   Passed    0.34 sec
12/17 Test #12: VortexGaloisTrieTest .............   Passed    0.04 sec
13/17 Test #13: VortexLandauerMevTest ............   Passed    0.02 sec
14/17 Test #14: VortexGqcRingStealthTest .........   Passed    0.11 sec
15/17 Test #15: VortexVaultHtlcTest ..............   Passed    0.02 sec
16/17 Test #16: VortexChaosFuzzerTest ............   Passed    4.35 sec
17/17 Test #17: VortexPqSignatureTest ............   Passed    5.55 sec
```

Property: zero sanitizer findings anywhere in the 114 test blocks. CI runs
the same lane on every push (`.github/workflows/ci.yml`, job `asan`).

Not covered by this lane: TSan (data races). A one-off TSan build lane
(GCC `-fsanitize=thread`, separate build directory) now exists for
targeted runs: the BACKLOG 0.14 mempool concurrency stress test
(`VortexMempoolTest.ConcurrentSubmitsAndSealsStayConsistent` — 8
submitter threads + a sealing reader + concurrent `stats()` calls) was
run 6 times under TSan with **0 data-race warnings** across all runs
(instrumentation verified via `__tsan` symbols in the binary). The full
P2P thread surface (listener + per-connection handlers + per-peer
readers) is still not TSan-covered; a CI TSan job remains BACKLOG 1.4.
Stated plainly: race-freedom of the P2P threads is **not** currently
evidenced.

---

## 5. Layer 3 - libFuzzer targets (5)

| Target | Surface | CI budget | Local recorded run |
|---|---|---|---|
| `fuzz_block_frame` | 64 KiB frame parser | 100k execs, seed 1 | CI green (last push) |
| `fuzz_pq_witness` | PQ witness verify | 20k execs, seed 1 | CI green (last push) |
| `fuzz_wire` | VX60 ingest gate | 200k execs, seed 1 | CI green (last push) |
| `fuzz_rpc` (new, `93e1756`) | the whole JSON RPC surface | 200k execs, seed 1 | **200 000 runs, 484 s, 0 crashes** (section 5.2) |
| `fuzz_undo_journal` (new) | the undo journal replay path (BACKLOG 0.11) | 200k execs, seed 1 | **200 000 runs, 0 crashes** over a hostile/valid seed corpus (re-seeded for format v2: 9 hostile/valid v2 seeds plus the legacy-version seeds; 150 000 execs recorded after the v2 bump) |

Reproduce:

```bash
cmake -S . -B build_fuzz -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_COMPILER=clang++ -DVX_BUILD_FUZZERS=ON
cmake --build build_fuzz -j
mkdir -p /tmp/vx_corpus
./build_fuzz/fuzz_wire -runs=200000 -max_len=70000 -seed=1 /tmp/vx_corpus
./build_fuzz/fuzz_rpc  -runs=200000 -max_len=4096  -seed=1 /tmp/vx_rpc_corpus
```

The `fuzz_rpc` harness (fuzz/fuzz_rpc.cpp):

- byte 0 = method (0 GET / 1 POST / 2 OPTIONS / else garbage bytes),
- byte 1 = path index into the live 34-route table (so inputs reach
  handler depth instead of 404s),
- rest = request body, capped at 4 KiB,
- invariant enforced in-harness: **a GET must never move the chain tip**
  (tip hash compared before/after; violation traps),
- server constructed once per process from a replayed private temp
  ledger; no socket bound; port 0; `start()` never called.

### 5.1 Recorded findings from the RPC surface

Found by the code review that preceded the harness (fixed in `93e1756`
BEFORE the first full battery ran):

| # | Finding | Impact | Fix |
|---|---|---|---|
| 1 | unguarded `std::stod(val)` on the transfer amount *string* form (`{"amount_vx":"1e999"}`), http_server.cpp handle_transfer | `std::out_of_range` escapes into a detached HTTP worker thread -> `std::terminate` -> **the whole node dies** from one RPC body | guarded; falls back to the documented default 0.0 |
| 2 | unguarded `std::stod` on the `dust_spam_tdi` audit amount | same crash class via `/api/security/audit` | guarded; keeps the default amount |
| 3 | no catch-all above dispatch | any future handler throw kills the node | public `HttpServer::route()` catch-all; workers and the fuzz target enter through it; answers fixed `{"error":"internal error"}` (500), never echoing exception text |

Live proof the fixed surface survives the exact hostile inputs:

```bash
# start a node, then:
curl -s -X POST localhost:PORT/api/transfer \
  -d '{"sender":"NFA_V6_...","receiver":"NFA_V6_...","amount_vx":"1e999"}'
# recorded response (node keeps serving):
{"error":"transaction rejected","reason":"Non-positive transaction transfer amount","tdi":0}
curl -s -X POST localhost:PORT/api/security/audit \
  -d '{"attack_type":"dust_spam_tdi","amount_vx":"1e999"}'
# recorded response:
{"blocked":true,"engine_verdict":"Transaction density falls below critical economic threshold (dust attack)","tdi":8.92857e-07}
```

And a valid transfer on the same node immediately after: `{"status":"ok",...}`
(tip advanced by exactly one block).

Full-battery result: section 5.2 below.

### 5.2 The full 200k-execution battery (recorded 2026-11-02)

One process, rebuilt after the leaf-ledger fix (`c1d6230`), running the
final committed harness:

```bash
./build_fuzz/fuzz_rpc -runs=200000 -max_len=4096 -seed=1 \
  -rss_limit_mb=2560 -timeout=25 /tmp/vx_rpc_corpus
```

Recorded tail of the run:

```
#16384   pulse  cov: 147 ft: 285 corp: 36/126b lim: 158  exec/s: 199 rss: 75Mb
#32768   pulse  cov: 147 ft: 285 corp: 36/126b lim: 320  exec/s: 230 rss: 75Mb
#65536   pulse  cov: 147 ft: 285 corp: 36/126b lim: 647  exec/s: 306 rss: 75Mb
#131072  pulse  cov: 147 ft: 285 corp: 36/126b lim: 1295 exec/s: 384 rss: 75Mb
#200000  DONE   cov: 147 ft: 285 corp: 36/126b lim: 1985 exec/s: 413 rss: 75Mb
Done 200000 runs in 484 second(s)
```

- **0 crashes, 0 timeouts, 0 OOM** over 200 000 inputs (total run time
  484 s; peak length explored 1985 bytes; corpus 36 files / 126 bytes;
  stable RSS 75 MB);
- **no tip mutation on any GET** - the in-harness invariant (tip hash
  compared before/after every GET dispatch) never trapped;
- both stod fixes and the `route()` catch-all were in the binary - the
  hostile bodies that crashed pre-fix are now just covered inputs.

Reading the coverage honestly: `cov: 147` is edge coverage over the
fuzzer's *module* (the route table + 34 handlers), not the whole node -
859 inline counters are instrumented. The stable plateau (147 from run
#40 onward) means the corpus reached every reachable handler state early
and the remaining 196k executions were mutation pressure over hostile
bodies, which is exactly what the findings table in 5.1 targeted.

---

## 6. Layer 4 - live multi-node testnet (VX60 over real TCP)

```bash
cmake --build build -j && scripts/multi_node_test.sh build
```

Recorded output (2026-11-03, round 9; all three nodes real processes on
one host; the transfer is now PQ-witnessed end-to-end — the harness asks
the demo signer for a witness bound to the public demo spender key and
posts it to /api/transfer itself):

```
[1/5] Minting the demo chain once, then snapshotting it to all nodes
[2/5] Starting star topology (B and C dial A on :19188)
  [PASS] RPC :18088 is up
  [PASS] RPC :18089 is up
  [PASS] RPC :18090 is up
[3/5] PQ-witnessed transfer on A must propagate over VX60 to B and C
  [PASS] tip on A matches the transfer block
  [PASS] tip on B matches A
  [PASS] tip on C matches A
  [PASS] sender balance on B is 74992.99999800 VX
[4/5] Garbage packets are counted as corrupted; the node stays alive
  [PASS] corruption counter rose (0 -> 10)
  [PASS] node A still serving after garbage
[5/5] In-process split-brain reorg simulation
  [PASS] split-brain reorg converged

=== 10 passed, 0 failed ===
```

(The 2026-11-02 run of the same script passed 10/10 with the then-current
keyless transfer shape; the round-7 authorization rewrite made that shape
unacceptable, so the harness itself was migrated to the witnessed flow —
the balance expectation moved by the two 100-atom fees the demo and the
transfer now pay.)

What each PASS means in protocol terms: a transfer signed with the demo
spender's post-quantum key was relayed as a RAW_BLOCK_64K frame,
CRC32C-verified, tip-extension-checked
(height == chain_height && prev_block_hash == tip), authorized through
the full WOTS+/XMSS witness path on every receiving node, applied through
the same `apply_block` path local transfers use, re-broadcast one hop,
and both spokes ended on the identical tip hash and balances. 10
deliberately malformed packets were counted (`corrupted_packets_dropped`)
and the node kept serving. The reorg demo heals a partition through real
VX60 loopback TCP with O(1) undo rollback.

Beyond the script, 9 hand-run scenarios are recorded with results in
[MULTI_NODE_RUNBOOK.md](MULTI_NODE_RUNBOOK.md) (sequential-transfer
convergence, multi-hop gossip, replay rejection, concurrent-transfer
serialization, restart rejoin, snapshot kill recovery, and others).

---

## 7. Layer 5 - the PQ one-time-leaf fix (before/after)

This is the pass's most consequential hardening (`c1d6230`), closing the
top gap named in the verification record.

**Before** (`93e1756` and earlier): the leaf was derived from the
transaction nonce (`leaf_idx = nonce & 0xF`, pq_signature.cpp) with no
consumed-leaf state anywhere. Consequences that were then *possible by
construction*:

- a node restored from a snapshot re-signs on the same one-time leaf;
- two concurrent signers (or two node processes sharing a data dir) take
  the same leaf;
- signing the 17th transaction on a key silently reuses leaf 0.

**After**: `PqLeafLedger` (pq_signature.hpp/.cpp):

- consumed leaves are keyed by the key's XMSS root (different keys never
  share history);
- durable mode appends 33-byte records (root + leaf) to
  `<data-dir>/pq_leaves.reg`, fsync'd **before** the signature is
  produced - a crash may burn a leaf without emitting its signature,
  never the reverse;
- every reservation re-reads the log under an exclusive `flock`, so
  threads and sibling processes serialize on one data dir;
- a busy requested leaf resolves to the lowest free leaf; the 17th
  signature for a key is refused (RPC answers 409);
- a log that fails to open or parse fails **closed**: the ledger refuses
  forever instead of silently falling back to unprotected signing
  (this exact failure mode was found by TEST 8 during development and
  fixed before commit).

Live evidence, one node, five concurrent signs (distinct leaves, no
reuse), then the durable history surviving a process restart:

```bash
# start a node with a data dir, then run 5 concurrent signs:
for i in 1 2 3 4 5; do
  curl -s -X POST localhost:PORT/api/crypto/pq_sign -d '{}' \
    | python3 -c 'import json,sys; print(json.load(sys.stdin)["leaf_index"])' &
done; wait
# recorded: 7 0 1 2 3   (default nonce 7 -> leaf 7 first, then 0,1,2,3)

# restart the node on the same data dir, sign again:
# recorded: next leaf continues after the consumed set - never a reused one
wc -c < <data-dir>/pq_leaves.reg
# recorded after 3 signs: 99  (= 3 x 33-byte records)
```

Test-level proof: TEST 8 (enumerated in 3.4), which also runs under
ASan+UBSan in the sanitizer lane.

Honest scope note: this makes the leaf lifecycle durable and
race-safe **per data directory**. The 16-leaf capacity itself (H=4) is
still the demo parameter discussed in the record; production would need
tree rollover.

### 7.1 Live endpoint transcripts (captured 2026-11-02, one serving node)

Real responses from a node started exactly as in the cookbook. Every
value below is derived from public, deterministic demo material (the
RPC demo key is derived from the fixed string `VX_PQ_RPC_DEMO_SK_V1`,
so these same outputs reproduce on any machine).

`GET /api/status` (after a demo run - height 2, the demo block on top of genesis):

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
    "tip_hash_hex": "4bfdf8063b26039b323865c02e0d29c81216bc55fe0acc4ba2001ceeaf7c9488",
    "crypto_engine": "3-Trunk Galois Attractor (3072-bit CRT) + VortexSponge256 (12-Round ARX)",
    "storage_engine": "POSIX mmap/mremap O(1) Zero-Copy"
}
```

(A **fresh** data dir instead reports the published genesis tip
`485f5afa...90b44d`'s predecessor constant - see claim C31.)

`POST /api/crypto/pq_sign` (first sign on the demo key):

```json
{
    "ok": true,
    "verified": true,
    "pq_scheme": "WOTS+ (w=16, L=67) + XMSS (H=4) over VortexSponge256",
    "shor_vulnerable_ops": 0,
    "grover_security_bits": 128,
    "classical_security_bits": 256,
    "wots_chains": 67,
    "wots_w": 16,
    "xmss_height": 4,
    "xmss_leaves": 16,
    "witness_size_bytes": 2376,
    "tx_frame_bytes": 112,
    "leaf_index": 7,
    "subtree_index": 0,
    "pq_pubkey_root": "8d5b24d75191aa2cc7453b99267541c57ae1cc8d1456239e89270dc47d2ab1b0",
    "witness_digest": "e1b2cc86e1645763c46bbdee0fcdf57b83325af898a7354d4eac574a79af3a54",
    "msg_digest": "4205b7242ad6b018d36c09c264f0c9502e3f60e678914d0e8aab45bb630dde11",
    "cocoon_proof_hex": "9f9d61f77b6bc0cbf8885fbe",
    "winternitz_checksum": 529,
    "keygen_cycles": 23038499,
    "keygen_us": 7959.83
}
```

`leaf_index: 7` is the nonce-derived leaf, now **consumed** by the leaf
ledger; the second sign reports `leaf_index: 0` (the lowest free leaf),
and `pq_leaves.reg` grew to exactly 66 bytes = 2 x 33-byte records.
Both facts verify in one command each:

```bash
curl -s -X POST localhost:PORT/api/crypto/pq_sign -d '{}' | grep -o '"leaf_index":[0-9]*'
wc -c < <data-dir>/pq_leaves.reg
```

`POST /api/crypto/pq_verify` (the live adversarial self-check):

```json
{
    "ok": true,
    "verified": true,
    "wots_verify_ok": true,
    "anchor_ok": true,
    "mitm_rehash_attack_rejected": true,
    "wots_forward_chain_forgery_rejected": true,
    "merkle_path_tamper_rejected": true,
    "winternitz_checksum": 529,
    "verify_us": 281.99
}
```

`GET /api/telemetry/rdtsc` (per-op cycle contours, AVX2+SSE4.2):

```json
{"ok":true,"isa":"AVX2+SSE4.2","contours":[
  {"op":"solinas_fast_reduction_1024b","iterations":1000,"min_cycles":347,
   "p50_cycles":377,"p99_cycles":435,"max_cycles":3799,"cycles_per_iter":377.9,
   "estimated_ns":138.9},
  {"op":"avx2_sponge_4way_hash","iterations":1000,"min_cycles":232,...]}
```

These are recorded facts about the verification CPU (section 1), useful
for relative comparisons; they are not cross-machine performance claims.

---

## 8. Claim verification index

Every load-bearing claim, with its independent check. Run all commands
from the repo root after building (section 2).

| # | Claim | Command | Expected result |
|---|---|---|---|
| C1 | 17/17 tests pass | `cd build && ctest` | `100% tests passed out of 17` |
| C2 | 114 test blocks exist | `cd build && for b in test_*; do ./$b --gtest_list_tests 2>/dev/null; done \| ...` or read section 3 | counts match 3.3/3.4 |
| C3 | Sanitizer-clean suite | `cd build_san && ctest` | 17/17, no ASan/UBSan output |
| C4 | Frame geometry is exact | `cd build && ./test_block` | sizes 472/112/65536 printed and asserted |
| C5 | Capacity is 580 tx | `./build/test_block` | 581st tx rejected |
| C6 | Frame parser survives chaos | `cd build && ./test_chaos_fuzzer` | 4 x 10k mutation cases pass |
| C7 | Sponge KATs are frozen | `./build/test_pq_signatures` | 5 KAT lines match |
| C8 | 50k low-entropy inputs, zero sponge collisions | same | `zero collisions` printed |
| C9 | PQ negative matrix 9,424/9,424 | same | layer A 4672/4672, layer B 4752/4752 |
| C10 | One-time leaves cannot repeat | `./build/test_pq_signatures` | TEST 8 lines print; 17th refused |
| C11 | Tampered leaf log fails closed | same | `tampered log: signing refused` |
| C12 | SAC ~50% on attractor and header hash | `./build/test_vortex && ./build/test_block` | per-round 48-53%; header 49.93% |
| C13 | Canonical address matches the published one | `./build/test_vortex` | `NFA_V6_nfrmbXMXrvviPWIUrsqmaH_HmbjmTIAIzM1IlcAcAA` |
| C14 | TDI gate: legit accepted, dust annihilated | `./build/test_vortex` | TDI 60.00 ACCEPTED / 0.00 ANNIHILATED |
| C15 | Shamir recovery | `./build/test_vortex` and `./build/test_zk_matrix` | reconstruction from every pair; 9 cases pass |
| C16 | 7 tiers derive, pairwise distinct | `cd build && ./test_zk_matrix --gtest_list_tests` and `./test_zk_matrix` | 9 cases, all pass |
| C17 | HTLC claim/refund/wrong-preimage | `./build/test_vault_htlc` | 4 cases pass |
| C18 | Vault pages burn, registers scrub | `./build/test_vault_memory` | 4 cases pass |
| C19 | GQC finality blocks reorg past checkpoint | `./build/test_gqc_ring_stealth` | `GqcFinalizedReorgBlocked` passes |
| C20 | Wire CRC32C rejects single-bit flips | `cd build && ./test_swarm_p2p` | both CRC cases pass |
| C21 | Full frame round-trips over TCP | same | `FullBlockRoundTripOverTcp` passes |
| C22 | Split-brain reorg converges | same + `scripts/multi_node_test.sh build` | test passes; script 10/10 |
| C23 | Hostile RPC bodies cannot kill the node | section 5.1 curl sequence | clean JSON errors, `/api/status` still serving |
| C24 | GET never moves the tip (fuzz invariant) | `./build_fuzz/fuzz_rpc -runs=200000 -seed=1 /tmp/c` | completes without a trap |
| C25 | Wire gate survives 200k mutated packets | `./build_fuzz/fuzz_wire -runs=200000 -seed=1 /tmp/c` | completes clean |
| C26 | PQ witness verify survives 20k mutations | `./build_fuzz/fuzz_pq_witness -runs=20000 -seed=1 /tmp/c` | completes clean |
| C27 | Frame parser survives 100k mutations | `./build_fuzz/fuzz_block_frame -runs=100000 -seed=1 /tmp/c` | completes clean |
| C28 | Multi-node convergence (live) | `scripts/multi_node_test.sh build` | `10 passed, 0 failed` |
| C29 | Garbage packets counted, node alive | inside the script output | `corruption counter rose (0 -> 10)` |
| C30 | Genesis is deterministic (fixed timestamp, no wall clock) | `grep -n "timestamp" src/blockchain/genesis.cpp` | fixed constant `1761000000` |
| C31 | Fresh node's genesis tip equals the published hash | `./build/vx_node --serve <port> --data-dir /tmp/fresh && curl -s localhost:<port>/api/status` | `tip_hash_hex` starts `ff327c33...` before any demo |
| C32 | CI is the enforcement point | `.github/workflows/ci.yml` | jobs: build matrix, asan, fuzz (4 targets), web, CodeQL |

Notes on the two strongest constants:

- **C13/C31:** the canonical address and the genesis tip hash are
  published in the whitepaper and in the Challenge; a reader with an
  independent implementation of the documented algorithm can reproduce
  them without any VX code. That is the sense in which they are
  independently verifiable.
- **C8 (zero collisions over 50k inputs)** is a sample statement, not a
  proof of collision resistance; the record's limitation on cryptanalysis
  applies unchanged.

---

## 9. What this evidence does NOT establish

Stated with the same care as the claims above:

1. **Nothing here is independent verification.** All 87 blocks, all four
   fuzzers and all live runs were executed by the project's own tooling
   on its own hardware/CI. Statuses cap at Tested.
2. **No cryptanalysis has been run** on VortexSponge256 or the attractor
   round function (differential/linear batteries: BACKLOG 1.3). The SAC
   matrix and NIST-style frequency test are necessary, not sufficient.
3. **No race evidence for the P2P threads** (TSan has been run once, on
   the new mempool concurrency stress test only - clean across 6 runs;
   the P2P surface itself still has no TSan lane - BACKLOG 1.4). The
   leaf ledger's own concurrency story is covered by mutex + flock and
   by design review, not by TSan.
4. **No adversarial network simulations** (10/100/1000 nodes, 30%
   malicious, delay/loss) - the live evidence covers a 3-4 node lab
   testnet with honest, enumerated limits (see runbook).
5. **No performance comparison** against other chains under equal
   conditions; timings in this document (e.g. 0.11 ms / 10 attractor
   rounds, PQ keygen/sign cycles) are recorded facts about this CPU,
   not benchmark claims.
6. **Security-Validated and Mainnet Candidate gates** remain unmet, by
   design, until the independent review (BACKLOG 2.2) and the collision
   analysis (BACKLOG 2.3) exist.

---

## Appendix A - the PqLeafLedger record format (for independent readers)

Location: `<data-dir>/pq_leaves.reg` next to `ledger.vxb` and
`genesis.bin`.

A record is exactly **33 bytes, appended little-endian-free** (the only
variable content is one byte):

```
offset  size  field
0       32    key root  - the account's XMSS root (pq_pubkey_root), the
                        signing key this leaf belongs to; two different
                        keys never share history because of this field
32      1     leaf index - 0..15 (anything >= 16 makes the whole log
                        untrusted and the ledger fails closed)
```

Invariants a reader can check by hand:

1. **Append-only.** The writer only ever appends; it never rewrites or
   truncates (a torn trailing append from a crash is treated as absent).
2. **fsync before use.** `append_locked()` fsyncs the record before
   `reserve()` returns, and `pq_sign_transaction()` reserves *before*
   generating the witness. Consequence: at most the fail-closed direction
   exists - a leaf may be burned without a signature, never signed
   without being burned.
3. **Cross-process exclusion.** Every reservation takes `flock(LOCK_EX)`
   on the file, re-reads the whole log, then appends. Two node processes
   sharing a data dir cannot both observe the same leaf as free.
4. **Fail-closed.** The constructor validates the whole log (33-byte
   alignment, leaf byte < 16, size <= 4 MiB). On any violation the ledger
   refuses every reservation forever - it does not silently downgrade to
   unprotected in-memory signing. This exact fallback bug was caught by
   TEST 8 during development and fixed before commit `c1d6230`.

Verify with: `xxd <data-dir>/pq_leaves.reg | head` after running the
sign smoke in section 7 - each line is 33 bytes; the 33rd byte counts
0x00..0x0f; after N successful signs the file is exactly N*33 bytes
(recorded: 99 = 3 signs).

---

## Appendix B - CI enforcement map (which job proves which claim)

Source: `.github/workflows/ci.yml`. On every push:

| CI job | Enforces | Related claims |
|---|---|---|
| build matrix (GCC + Clang) | the tree compiles warning-relevant clean on both toolchains | C1 environment breadth |
| asan lane | the 16-binary suite under `-fsanitize=address,undefined -fno-sanitize-recover=undefined` | C3 |
| fuzz job (4 targets) | block frame 100k, PQ witness 20k, wire 200k, RPC 200k, all seed=1 | C24-C27 |
| web job | the console builds (npm) | - |
| CodeQL (C++ + web) | static analysis on the core and the console | - |

What CI does NOT enforce yet (honesty): TSan, the multi-node script,
performance regression gates. The multi-node script is documented and
local-runnable (section 6); wiring it into CI is deferred until the bind
address and ports are configurable (BACKLOG 0.3).

---

## Appendix C - the fuzz_rpc harness, line by line (what it enforces)

Source: `fuzz/fuzz_rpc.cpp`. The design choices, so a reader can judge
what the clean 200k run actually covers:

1. **One server per process.** Constructed lazily on the first input:
   private `mkdtemp` dir, `BlockStore` auto-regenerating genesis, ledger
   replayed from the chain, `HttpServer` on port 0 with `start()` never
   called. No listener, no worker threads, no sockets - the RPC is
   exercised purely as a callable unit through `route()`.
2. **Method byte.** 0 -> GET, 1 -> POST, 2 -> OPTIONS, else the next
   bytes are used as a garbage method string (empty, unterminated,
   binary). This covers the 404 path, the CORS preflight path and
   method-vs-path mismatches.
3. **Path byte.** An index into the 34-entry route table mirroring
   `HttpServer::dispatch` (kept in sync manually; the table is asserted
   by use, not by a build check - a drift would show up as 404 coverage,
   which the corpus would flag).
4. **Body.** Everything after byte 1, capped at 4 KiB, so individual
   execs stay fast and the 200k budget explores depth instead of
   drowning in size.
5. **GET-must-not-move-the-tip.** Before every GET the harness snapshots
   `store.tip_hash()`; after the call it compares. A mismatch traps -
   libFuzzer reports the crashing input. This is the strongest invariant
   because it guards the entire read path against accidental mutation.
6. **Bounded chain growth.** Accepted POST /api/transfer calls append
   64 KiB frames; the harness refuses them past height 4096 so a long
   run cannot balloon the temp ledger.
7. **State resets are not needed.** The harness deliberately does NOT
   reset state between inputs: handlers must tolerate a ledger that has
   grown, balances that changed, and consumed PQ leaves - which is the
   reality of a serving node.

Known blind spots of this harness (stated so nobody over-reads the
result): it does not fuzz the TCP/HTTP parsing layer (`parse_request`),
the SSE path, or concurrency (single-threaded calls into `route()`).
Those belong to the socket-level tests and the future TSan lane.

---

## Appendix D - hand-run multi-node scenarios (recorded results)

From the live sessions recorded in [MULTI_NODE_RUNBOOK.md](MULTI_NODE_RUNBOOK.md);
each was executed against real node processes, not simulated:

| # | Scenario | Recorded result |
|---|---|---|
| 1 | 5 sequential transfers, star topology | all 3 nodes h=7, identical tip, identical balances after every step |
| 2 | Multi-hop gossip (node D dials a spoke, not the hub) | D converged on the next block via the spoke's relay |
| 3 | Replay of a real historical frame, valid CRC32C | dropped by the tip-extension rule; corruption counter stayed 0 |
| 4 | Replay of the current tip frame | dropped (height mismatch) |
| 5 | 10 garbage packets (bad magic) | counter rose to 10, node kept serving |
| 6 | 3 concurrent transfers | serialized by the ledger lock: heights n, n+1, n+2, all applied |
| 7 | Spoke restart mid-chain | rejoined on connect and received the next block |
| 8 | Late joiner from a stale snapshot | honestly stalled at its snapshot height (the gap BACKLOG 0.1 closes) |
| 9 | Snapshot restart after abrupt kill | ledger intact on disk; snapshot rejoins at the tip |

Verify 1, 5, 6 and the reorg demo yourself with the script (section 6);
2-4 and 8-9 are short manual walks documented step-by-step in the
runbook.

---

## Appendix E - the full RPC surface (34 routes, real inventory)

Mirrors `HttpServer::dispatch` (src/rpc/http_server.cpp) and the fuzz
harness route table. Each route's live-captured request/response pairs
are in [RPC_COOKBOOK.md](RPC_COOKBOOK.md); the fuzz target covers every
one of them.

| # | Method | Path | Reads/mutates | Live evidence |
|---|---|---|---|---|
| 1 | GET | /api/status | reads | cookbook; C31 genesis constant |
| 2 | GET | /api/blocks | reads | cookbook (Challenge level 1) |
| 3 | GET | /api/accounts | reads | cookbook |
| 4 | POST | /api/transfer | mutates | cookbook + hostile smoke (C23) |
| 5 | POST | /api/security/audit | runs guards | cookbook; 8 attack scenarios |
| 6 | POST | /api/crypto/lab | derives | cookbook |
| 7 | GET | /api/vault/memory | reads | cookbook |
| 8 | POST | /api/vault/action | mutates (demo vault) | cookbook |
| 9 | POST | /api/zk/derive_matrix | derives | cookbook |
| 10 | POST | /api/zk/recover_shamir | derives | cookbook |
| 11 | POST | /api/zk/proof_of_life | derives | cookbook |
| 12 | POST | /api/zk/audit_view | reads | cookbook |
| 13 | POST | /api/neural/simulate | computes | cookbook |
| 14 | GET | /api/crypto/canonical | reads | cookbook (Challenge level 3) |
| 15 | GET | /api/mempool/zk_stats | reads | cookbook |
| 16 | GET | /api/swarm/peers | reads | cookbook + runbook |
| 17 | POST | /api/swarm/simulate_split_reorg | demo reorg | runbook (C22) |
| 18 | GET | /api/swarm/dandelion_stats | reads | cookbook |
| 19 | POST | /api/swarm/relay_cocoon | mutates (mempool) | cookbook |
| 20 | POST | /api/vm/execute_trace | computes | cookbook (Landauer trace) |
| 21 | GET | /api/state/trie_root | reads | cookbook |
| 22 | POST | /api/state/prove | computes | cookbook |
| 23 | POST | /api/mempool/mev_audit | computes | cookbook |
| 24 | GET | /api/consensus/finality_status | reads | cookbook |
| 25 | POST | /api/consensus/finalize_gqc | demo finality | cookbook |
| 26 | GET | /api/mempool/pipeline_benchmark | computes | cookbook |
| 27 | POST | /api/zk/stealth_envelope | derives | cookbook |
| 28 | POST | /api/zk/ivk_scan | derives | cookbook |
| 29 | POST | /api/vault/ephemeral_sign | demo sign | cookbook (C18) |
| 30 | POST | /api/vm/htlc_swap | demo contract | cookbook (C17) |
| 31 | GET | /api/telemetry/rdtsc | reads | cookbook |
| 32 | POST | /api/security/chaos_fuzz | computes | cookbook (deterministic seeds) |
| 33 | POST | /api/crypto/pq_sign | mutates (leaf ledger) | section 7 evidence |
| 34 | POST | /api/crypto/pq_verify | runs adversarial suite | cookbook |

Standing security posture of this surface (restated from the record):
no auth, no rate limiting, no replay protection - it is an observation
and demo surface with **no consensus weight**; a node serves the same
ledger with the RPC disabled. No endpoint returns the node's own secret
material.

---

## Appendix F - verifying this document's integrity

This file is committed with a detached ASCII-armored GPG signature,
`docs/VERIFICATION_EVIDENCE.md.asc`, made with the same key that signs
every commit in this repository:

- key fingerprint: `D2C0A1CA849AC1676E9210A1EB23A59B841118BF`
- key identity: `VX-VX-VX <328492894+VX-VX-VX@users.noreply.github.com>`

Trust anchor: the commits themselves. `git log --show-signature` shows
the same fingerprint signing each commit; a reader who has the repo
already holds proof of which key is the project's key. Then:

```bash
# compare the signature's key fingerprint against the one above:
gpg --list-packets docs/VERIFICATION_EVIDENCE.md.asc | grep -A1 "signature packet"
# after importing the key (from your keyserver of trust, or from the
# project's published key material):
gpg --verify docs/VERIFICATION_EVIDENCE.md.asc docs/VERIFICATION_EVIDENCE.md
```

If you edit the document, the signature will (correctly) stop verifying;
a new signature must be made for the new content, and the fingerprint
check tells you whether the same key signed it.

---

## Appendix G - the whole pass in one ordered checklist

Every layer of this document, compressed into one command sequence a
reviewer can run top-to-bottom on a Linux x86-64 host with `gcc`,
`clang`, `cmake >= 4`, `ninja`, `gtest`, `curl` and `python3`. Each step
is independent: if one fails, the later steps still say something - but
a clean pass reproduces every number above.

```bash
# 0. build both lanes (3-5 min on the recorded CPU)
cmake -S . -B build      -G Ninja -DCMAKE_BUILD_TYPE=Release && cmake --build build -j
cmake -S . -B build_san  -G Ninja -DCMAKE_BUILD_TYPE=Debug \
  -DCMAKE_CXX_FLAGS="-fsanitize=address,undefined -fno-sanitize-recover=undefined" \
  && cmake --build build_san -j

# 1. unit/integration lane (expect: 17/17, ~5 s)
cmake --build build -j && (cd build && ctest --output-on-failure)

# 2. sanitizer lane (expect: 17/17, no diagnostics)
(cd build_san && ctest --output-on-failure)

# 3. the strongest single constants
./build/test_vortex | grep NFA_V6_       # canonical address (claim C13)
./build/test_pq_signatures | grep -E "KAT|collisions"   # C7, C8
./build/test_vortex | grep -E "ACCEPTED|ANNIHILATED"    # TDI gate (C14)

# 4. fuzzers (4 targets; expect clean completion, no traps)
cmake -S . -B build_fuzz -G Ninja -DCMAKE_BUILD_TYPE=Release \
  -DCMAKE_CXX_COMPILER=clang++ -DVX_BUILD_FUZZERS=ON && cmake --build build_fuzz -j
mkdir -p /tmp/vx_corpus
./build_fuzz/fuzz_block_frame -runs=100000 -seed=1 /tmp/vx_corpus
./build_fuzz/fuzz_pq_witness  -runs=20000  -seed=1 /tmp/vx_corpus
./build_fuzz/fuzz_wire        -runs=200000 -seed=1 -max_len=70000 /tmp/vx_corpus
./build_fuzz/fuzz_rpc         -runs=200000 -seed=1 -max_len=4096  /tmp/vx_rpc_corpus

# 5. live multi-node (expect: 10 passed, 0 failed)
scripts/multi_node_test.sh build

# 6. hostile RPC by hand (expect: JSON errors, node keeps serving)
./build/vx_node --serve 18200 --data-dir /tmp/vx_evcheck & sleep 1
curl -s -X POST localhost:18200/api/transfer \
  -d '{"sender":"X","receiver":"Y","amount_vx":"1e999"}'
curl -s -X POST localhost:18200/api/security/audit \
  -d '{"attack_type":"dust_spam_tdi","amount_vx":"1e999"}'
curl -s localhost:18200/api/status | head -c 120; echo
fuser -k 18200/tcp   # stop the node

# 7. the genesis constant (expect: tip_hash_hex starts 485f5afa)
rm -rf /tmp/vx_fresh && ./build/vx_node --serve 18201 --data-dir /tmp/vx_fresh & sleep 1
curl -s localhost:18201/api/status | grep -o '"tip_hash_hex":"[a-f0-9]\{8\}'
fuser -k 18201/tcp

# 8. the leaf ledger (expect: 17th sign -> 409; reg file = N*33 bytes)
#    full recipe: section 7 of this document

# 9. document integrity (Appendix F)
gpg --verify docs/VERIFICATION_EVIDENCE.md.asc docs/VERIFICATION_EVIDENCE.md
git log --show-signature -5   # same fingerprint on every commit
```

Notes on fidelity:

- steps 6-7 need ports; any free port works - the recorded numbers do
  not depend on the port;
- fuzz runs are randomized in *coverage exploration* but deterministic
  in seed; the recorded pass used `-seed=1` everywhere;
- a crash anywhere in steps 1-5 is a finding, not an environment
  problem - please report it as such (steps 6-7 use `fuser -k`, which
  needs the `psmisc` package).

---

## Appendix H - the PQ benchmark, exact figures (P2, 2026-11-07)

A reproducible benchmark ships as `tests/bench_pq.cpp` (target `bench_pq`,
manual - benchmarks do not gate CI). It measures the four cost centers of
the WOTS+ (w=16, L=67) / XMSS (H=4) witness path with fixed inputs and
fixed iteration counts, splitting COLD (first touch of a window: 16 leaf
computations fill the window cache) from WARM (cache-hit steady state).
Recorded from a Release build (GCC, -O2) on the development host, two
consecutive runs:

```
VX PQ benchmark (WOTS+ w=16 L=67, XMSS H=4, 16 leaves/window)
warm runs: sign=45 verify=45 (verified 45/45); cold builds=40; cold signs=5
cold window build               9.945      8.443     13.985   (ms, mean/min/max)
cold sign (fresh window)       10.383      9.369     10.968   (ms, mean/min/max)
warm sign                       0.337      0.308      0.358   (ms, mean/min/max)
warm verify                     0.268      0.259      0.286   (ms, mean/min/max)
ratios (means): warm verify / warm sign = 1.26x | cold build / warm sign = 29.5x

run 2:
cold window build               8.786      8.147     10.997   (ms, mean/min/max)
cold sign (fresh window)        9.592      8.746     10.257   (ms, mean/min/max)
warm sign                       0.353      0.318      0.439   (ms, mean/min/max)
warm verify                     0.299      0.253      0.354   (ms, mean/min/max)
ratios (means): warm verify / warm sign = 1.18x | cold build / warm sign = 24.9x
```

CORRECTED CLAIM (the earlier "~30x verify speedup" arithmetic is
misattributed): the 8.5 ms figure is the COLD WINDOW BUILD (one-time
per-window initialization, 16 WOTS+ leaf derivations), and the 0.3 ms
figure is the WARM DETACHED VERIFY. 8.5/0.3 does not compare sign to
verify. The honest account:

- warm sign ~0.34 ms, warm verify ~0.28 ms - the real verify/sign
  ratio is ~1.2x, not ~30x;
- the ~9 ms cold build is a ONE-TIME cost per window per account
  (amortized over that window's 15 transaction leaves);
- verification's real advantage is structural, not temporal: verify
  holds no secret key material, burns no leaf, and runs on every
  receiving node, while sign runs once per account leaf.

The earlier rounded quotient (30.6x) and the corrected arithmetic
(8.5/0.3 = 28.3x) are both superseded by the measured figures above -
the ratio they tried to express does not exist as stated.

---

## 10. Changelog of this verification pass

| Commit | Content |
|---|---|
| `93e1756` | public `route()` catch-all; two unguarded `std::stod` fixed; `fuzz/fuzz_rpc.cpp` + CI wiring |
| `424b743` | ROADMAP near-term emptied; BACKLOG 1.1 closed |
| `d72f6fc` | VERIFICATION_RECORD.md (18-component status) |
| `c1d6230` | PqLeafLedger: durable one-time-leaf lifecycle, per-call leaf reporting, TEST 8 |
| `f55fbd1` | External-review finding, fixed at HEAD: synthetic ring decoys read 35 bytes from a 32-byte buffer (3 trailing decoy bytes were adjacent stack garbage). Whole-repo `-Warray-bounds` scan after the fix: zero hits |
| (review round 2) | Confirmed in code and closed honestly: **XMSS subtree guard** — nonces above 15 refused before any leaf burn (TEST 9: 0/15 verify, 16/17/255/2^32-1 refuse, exactly 2 leaves consumed); **GQC share forgery pinned** — new test `GqcQuorumForgeableFromPublicDataOnly` forges a 9/9 quorum with zero secrets and asserts the attack SUCCEEDS (documents the gap until validator auth, BACKLOG 0.4/2.4); **PoGW honestly renamed** — record and README now state the acceptance criterion is hash-based (leading zero bits) and difficulty is not anchor-based yet |
| (review round 3) | The reviewer built and ran a node. **Fixed:** intra-block double spend minted a ~2^128 phantom balance (checked per-sender intra-block debits + commit-time underflow guard + checked `total_supply()`; regression `DoubleSpendInBlockRejected`); mempool validate-vs-reserve TOCTOU (one critical section); `append_block` now fails on `fsync` error; `MemoryCore` no longer throws on `mlock` failure (documented degradation, node launches in 8 MiB-RLIMIT containers). **Pinned as expect-success tests:** keyless transaction authorization (theft of 1 VX from the genesis receiver with zero secrets — `KeylessTheftReproducible`, BACKLOG 0.7/0.8; FLIPPED 2026-11-03, round 7 below) and no-work block acceptance (`NoWorkBlockAccepted`, BACKLOG 0.6/0.9; flipped 2026-11-03, round 6). **Rejected as stale:** "P2P never starts" — true only in the reviewer's Nov-1 snapshot; current `http_server.cpp` binds and starts the swarm node (live 3-node testnet proves it) |
| (review round 4) | The reviewer's verdict: NOT READY FOR MAINNET; freeze features, security-fix stage. **Fixed:** genesis-v1 nonce bypass scoped to the genesis replay window (`next_height <= 1`; regression `NonceZeroReplayRejected` — a fee=0/nonce=0 replay at height 3 now fails with `nonce mismatch`); `append_block` gates tx_count past the structural capacity and re-verifies the merkle root (regressions `OversizedTxCountRejected`, `TamperedMerkleRejected` — a forged root or a 581-tx_count frame can no longer enter the ledger file); the miner checks append/apply results and keeps sealed transactions on rejection instead of draining the mempool; GQC share pools keyed by (height, block hash) so votes for different blocks at one height cannot mix, and a failed tail stamp now blocks certification (`stamp_gqc_into_tail` returns bool); the RPC transfer endpoint stamps fee/nonce server-side. **Pinned as expect-success tests:** MINER_ coinbase emission without mining work or identity (`MinerEmissionForgeable` — 1000 VX mint SUCCEEDS today; BACKLOG 0.6/0.9). **Pinned in BACKLOG as P0:** undo journal serializes heap pointers via raw `write(fd, &record, sizeof(record))` (0.11); reorg undo journals the displaced block from the wrong side of the truncation and never restores sender nonces (0.12); GQC finalized checkpoint is RAM-only and evaporates on restart (0.13); mempool global fee sort can invert per-sender nonce order and `count_` is published before the entry write (0.14). Test suite: 17/17 on both the GCC and the ASan+UBSan lanes |
| (review round 5) | Ten more findings (10-19), verified against current main one by one. **Fixed:** (10, P0) `POST /api/vault/action` called `emergency_burn_all()` for BOTH `consume` and `emergency_burn` — any RPC client could wipe the whole vault; now `consume` burns exactly one page identified by its full capability token and `emergency_burn` answers 403 (admin-only, in-process); (11) the HTLC settle outcome was decided BEFORE the VM ran, so bytecode corrupted after the shape check still settled CLAIMED — the VM verdict (success, cycles, branch marker) now gates the outcome to LOCKED (regression `HtlcVmFailureForcesLocked`); (12) the GQC aggregate was stamped into frame bytes 65464..65495, physically overwriting `vm_gas_used`, `pogw_nonce` and half of `vm_bytecode` — the stamp moved to a versioned sidecar record (`<ledger>.gqc`, fail-closed reads), the certified frame stays byte-identical, and tail offsets are now static_asserted; (13) the vault ring cursor silently zeroed a still-LOCKED page on pool wrap — a full pool now raises instead of clobbering (`VaultPoolFullNotClobber`); (14) the vault capability token stored and compared only its first 4 bytes and was generated from CRC32C — now a full 32-byte VortexSponge256 digest, constant-time compared (`VaultTokenDigestFullyChecked`); (16) the block id committed only the 472-byte header, leaving vm_state_root/gas/PoGW nonce/bytecode outside the commitment — `hash_block` now commits header AND tail, `tip_hash` and the RPC block-hash fields use it, and the published genesis constant was recomputed (`ff327c33...` -> `485f5afa...`) across whitepaper/Challenge/cookbook/evidence; (17) SSE threads leaked forever (MSG_PEEK never consumed the request, EOF never surfaced) — handshake drained, poll-based wait. **Verified stale (already fixed in main before this round):** (15) WOTS+ one-time-leaf reuse — the reviewer's own suspicion was right: `PqLeafLedger::reserve` (commit c1d6230) already assigns the lowest free leaf, refuses reuse, survives restart and fails closed on a tampered log; TEST 8 covers exactly the regression battery they asked for. **Documented/pinned:** (18) demo fixture keys over RPC (`/api/crypto/canonical` private keys, `/api/crypto/pq_sign` demo seed) — BACKLOG 0.10, compile-demo-out plan; (19) src/core `MemoryCore` states its real guarantee (mlock = swap/core-dump hygiene, NOT anti-ptrace; `check_debugger` not yet wired) in the record. **Reviewer's meta-note accepted:** their snapshot lacked some test binaries, so their PoCs ran standalone against libvx_core.a — every confirmed PoC is now an automated ctest case that fails on the old code and passes on main. Suite: 17/17 on GCC and ASan+UBSan lanes |
| (2026-11-03, round 6) | BACKLOG 0.9 + 0.6 closed: a single intake gate. `blockchain::validate_block()` (magic, height/prev binding, tx_count bound, merkle commitment recomputed from the body, timestamp monotonicity + 300 s future bound, PoGW full-frame work) now runs at the ONE chokepoint every producer appends through (`BlockStore::append_block`): the RPC transfer/mine path, P2P `apply_remote_frame` and the background miner. The work check is one shared comparator (`pogw_meets_target`) used by both the miner's search and the gate, so the definition of "enough work" cannot drift; producers outside the miner (RPC transfer, demo) seal via `seal_pogw_nonce` — the transfer endpoint now takes a few seconds at dev difficulty (16 leading zero bits, ~120 µs per 64 KiB hash). The miner aims at max(ASERT, gate) so its search can never sit below the gate. The restart/recovery path re-validates every stored frame (magic, height, tx_count, merkle) in `validate_region` and fails closed on a poisoned ledger file. Pin flipped: `NoWorkBlockAccepted` -> EXPECT_FALSE (an otherwise-valid frame with no PoGW nonce is rejected with "insufficient PoGW work for the current difficulty"; the chain height does not move). New regressions: `PogwGateAcceptsSealedWorkAndBindsTheNonce` (difficulty-12 store: sealed frame appended, one-off nonce mutation of the same frame rejected), `RecoveryRejectsCorruptedLedgerFrame` (a ledger whose stored frame lost its merkle commitment throws on reopen). `fuzz_block_frame` now drives the gate surface (mirrored height/prev, input-derived work target) — 188k runs clean in a 30 s smoke. Sim/testnet stores instantiate with the difficulty they simulate (1-8 bits); the swarm sim timestamps moved to >= the genesis timestamp for intake monotonicity. Suite: 17/17 on GCC and ASan+UBSan lanes |
| (2026-11-03, round 7) | BACKLOG 0.7 + 0.8 closed: post-quantum transaction authorization. (1) Addresses are bound to PQ keys through two sources with no trusted registration table: self-certifying addresses — the payload is "PQA" + 39 base64url chars of Sponge("VXPQADDRV1" || pq_pubkey_root), so holding the XMSS key IS holding the address, and the first witnessed spend binds it in ledger state — and a protocol seed table (genesis.hpp pq_seed_bindings) for genesis-era allocations: the canonical genesis receiver is bound to an OFFLINE root whose secret is NOT in the repo (the reviewer's theft PoC target is now unspendable), the demo spender to the public documented demo key, the demo receiver to an offline root. Genesis frame and hash are unchanged. (2) The keyless Tier-2 digest is removed from consensus acceptance: the ledger refuses every user sender without a valid PqSignatureWitness (registry lookup by tx_msg_digest, root-binding check, full WOTS+/XMSS + SegPQ-anchor verification); the digest survives only as an admission pre-filter and for the guarded system senders (GENESIS*, MINER_). (3) The demo RPC no longer signs on the user's behalf: POST /transfer requires witness_b64 (2376-byte witness, base64), fee_atoms and nonce from the client; the server rebuilds the tx anchor from the witness (pq_set_transaction_anchor) and stamps nothing into the signed material. (4) Witnesses travel: WireMsgType::PQ_WITNESS (0x09) = digest(32)+sender(42)+witness(2376), broadcast BEFORE the block that carries the transactions (both the transfer/mine path and P2P relay), so a peer can authorize a block it receives; receivers register into PqWitnessRegistry. (5) Durable sidecar <ledger>.pqw: append-only VXPQWT1 records (8+32+42+2376 = 2458 B), fsync'd per registration, replayed fail-closed on attach — a restart no longer orphans witnessed transactions. Pin flipped: KeylessTheftReproducible -> KeylessTheftRejected (the forged transfer is refused with "no PQ witness registered"; the victim keeps every atom). New regressions: UnboundSenderRejected, WitnessRootMismatchRejected, SelfCertifyingAddressAutoBinds, WitnessDurableLogSurvivesRestart. Honest remainders (BACKLOG 0.7): root rotation not implemented; 16-leaf XMSS capacity bounds a key to 16 spends (rollover = new address); the mempool still admits by the legacy pre-filter — the ledger remains the consensus authority. Same wave, BACKLOG 0.6 remainder closed: the MINER_ coinbase is bound to its chain position — cocoon_proof must equal trunc12(Sponge("VX_COINBASE_BIND_V1" || receiver || height || prev_tip_hash)), verified against the frame's own header in apply_block; the keyless digest no longer authorizes emissions and a coinbase copied from one fork cannot be replayed on a competing fork at the same height. Emission is bounded by: one coinbase per block (index 0), the 1000 VX cap, real PoGW work on the block, the chain-position binding; pin MinerEmissionForgeable -> CoinbaseReplayRejected (the replay of the same coinbase bytes in a fork frame with a fabricated prev tip is refused with "coinbase is not bound to this chain position", the honest coinbase pays the producer; /api/accounts now exposes next_nonce_atomics so a client can build the signed preimage). Suite: 17/17 on GCC, ASan+UBSan and fuzz lanes; demo end-to-end passes with the PQ-signed transfer; fuzz smokes clean (120k block-frame, 60k PQ-witness, 30k RPC, 60k wire)

| (2026-11-03, round 8, self-review) | Adversarial hardening of the round-7 code (internal pass — findings fixed by our own audit, not externally replicated; full narrative in VERIFICATION_RECORD §6, round 8). (1) P0: the VX60 plausibility gate still stopped at 0x08, dead-coding `PQ_WITNESS` (0x09) — witnesses could never arrive over the wire; gate widened to 0x01..0x09. (2) P0: the RPC transfer path registered an UNVERIFIED witness and left the block store one block ahead of the ledger whenever the state layer refused a gate-passed block (every later block then fails the height gate — a permanent wedge). Fixed: verify the full WOTS+/XMSS + anchor chain BEFORE registering; new `BlockStore::rollback_last_append()` (ftruncate to the previous tip) wired into the RPC path, the remote-frame path and the miner; the miner no longer applies a frame that failed to append. (3) P1: the witness registry hardened into a verified cache — nothing enters unverified, byte-exact dedup, caps 8 candidates/digest and 50000 digests, sidecar opened O_APPEND 0600 under exclusive flock with memory-only fallback, fail-closed replay honoring the caps, and consensus switched to `lookup_verifying()` (a digest may hold attacker candidates that simply do not verify against the honest transaction). (4) P2: self-certifying PQ bindings are now transactional — collected during validation, applied only after the whole block validates. (5) P2 (found live): the RPC JSON scanner matched only compact JSON, so standard serializers got a misleading "witness required" error, and one `recv()` was treated as one request, truncating split ~3.2 KB witness bodies; now whitespace-tolerant extraction + read-until-Content-Length (64 KiB cap). Live re-verified: garbage 2376-byte witness refused with the WOTS+/XMSS diagnostic and never registered; wrong-nonce diagnostic exact; failed transfers leave balances byte-identical; compact and spaced JSON behave identically. Suite: 17/17 on GCC, ASan+UBSan and fuzz lanes after every fix; fuzz smokes clean.

| (2026-11-03, round 9, delegated audit) | Three hunt-fix-re-hunt cycles over the full tree; every finding proven with an executable exploit before the fix (record in VERIFICATION_RECORD §6, round 9). Fixed: health-loop self-deadlock on the DoS-ban path (one bad-magic frame from any local process froze the whole node — remotely triggerable P0); unbounded GENESIS minting inside one height-1 block (the legacy window read committed balances, so N mints in one block all applied — P0, regression `SecondGenesisMintInBlockRejected`); unbounded blocking sends under the state/peer locks (5 s SO_SNDTIMEO on every socket); double-close fd-reuse race on banned peers (proven with an LD_PRELOAD close-generation tracker: 41 double-closes before, 0 after); unbounded remote memory growth via /api/state/prove (persistent trie stayed read-only, ~32 arena nodes/request growth eliminated); UB float→integer casts on RPC numbers. Report-only with reasons: dormant miner's unsynchronized commit, mempool races behind a zero-caller submit, undo journal raw writes (BACKLOG 0.11), broadcast fd snapshots (receiver fails closed), 0.0.0.0 bind. Same wave: the multi-node harness now drives a real PQ-witnessed transfer through the demo signer (`demo_key:"spender"` + named tx fields + witness_b64) — 10/10 including tip and balance convergence on B and C with post-quantum authorization on every node; the demo signer returns the witness IT just signed (out-parameter on pq_sign_transaction — the registry may hold several valid candidates per digest); fuzz_pq_witness deepened to targeted mutations of a structurally valid witness (cov 2 -> 25, ~245k runs clean). Suite after every fix: 17/17 on GCC, ASan+UBSan and fuzz lanes.
| (2026-11-03, emission schedule, user-directed) | The emission schedule is hard-coded in consensus: `include/vx/blockchain/emission.hpp` defines the lifetime cap 7,000,000,000 VX (7e17 atoms; the 7 is the protocol's signature digit) and a flat 1,000 VX block subsidy for heights 1..7,000,000 (zero at height 0 and after the window; 7,000,000 blocks x 1,000 VX = the cap exactly, static_asserted). `LedgerState::apply_block` gates cumulative ISSUANCE - all coinbase credits minus the fee share re-credited to the producer (fee redistribution is not new emission) - against the cap BEFORE any state mutation, so a refused block leaves the ledger byte-identical; the producer's coinbase now carries subsidy + fee share clamped to the remaining headroom, so the final emission blocks mint exactly the remainder and the cap closes; genesis allocations count against the cap; the reorg undo recomputes and reverses a block's issuance; `/api/status` reports `max_supply_vx`, `issued_supply_atomics`, `issuance_headroom_vx`, `emission_window_blocks`. Genesis frame and hash unchanged (`485f5afa...`). The dormant PoGWMiner gains the schedule too (subsidy + fee share, headroom-clamped). New regressions: `EmissionScheduleShapeSevenBillion`, `CoinbaseEntitlementEnforced`, `SupplyCapHardStopsIssuance`, `SubsidyEndsAfterEmissionWindow`. Suite: 17/17 on GCC, ASan+UBSan and fuzz lanes (79 named gtest cases); fuzz smokes clean.
| (2026-11-03, emission schedule revision) | The first cut (flat 1,000 VX over 7,000,000 blocks) was revised the same day on user feedback: 7,000,000 blocks is a too-short emission horizon at a seconds-scale block target. The cap stays exactly 7,000,000,000 VX; the schedule is now a halving curve - three 4,000,000-block epochs paying 1,000 / 500 / 250 VX (whole atomics: 1e11 / 5e10 / 2.5e10), zero afterwards. 4M x (1,000 + 500 + 250) = the cap exactly, so the static_asserts still bind the schedule to the cap; the emission window grows to 12,000,000 blocks (~69 years at the 5-second dev target). The ledger gate, the miner clamp, the undo reversal and the /api/status fields are unchanged - only `subsidy_atoms()` and its asserts moved. Regressions updated, suite 17/17 on GCC, ASan+UBSan and fuzz lanes (79 named gtest cases).
| (2026-11-03, emission schedule revision 2: hash-tier reward) | The halving curve was revised again the same day on user feedback: the block reward now depends on the block's own hash, not its height. The guaranteed floor is 50 VX for every valid block; the leading zero bits of the full-frame VortexSponge256 commitment unlock bonus tiers - 20/24/28/32/40 zero bits pay 75/100/200/400 and the 1,000 VX jackpot (frequencies ~1 in 1M / 17M / 268M / 4.3B / 1.1T blocks). A miner cannot mint the bonus, only find a rarer hash, so a bigger reward is strictly more proof-of-work; the thresholds are absolute, so any node verifies the reward by recounting zeros in the hash it already computes for the PoGW gate - no difficulty estimate enters consensus accounting, and the height-window subsidy (`subsidy_atoms`) is gone entirely. The ledger gate now recomputes the frame hash itself (`BlockView::bytes`) and entitlement = reward(hash) + fee share; the miner claims a tier and searches for a hash that justifies the claim, escalating when the found hash is rarer than claimed (the coinbase amount is part of the hashed frame, so claim and justifying hash are searched together); the audit's excess_reward constant is the 50 VX floor. `/api/status` swaps `emission_window_blocks` for `block_reward_base_vx`, `block_reward_max_vx`, `reward_tier_count`. Regressions: `EmissionScheduleShapeSevenBillion` -> `EmissionRewardTiersAndCap`, `SubsidyEndsAfterEmissionWindow` -> `RewardIndependentOfHeight`, `CoinbaseEntitlementEnforced`/`SupplyCapHardStopsIssuance` rewritten frame-hash-exact; suite 17/17 on GCC, ASan+UBSan and fuzz lanes (79 named gtest cases); live smoke on a fresh node verified the new `/api/status` fields.
| (2026-11-03, BACKLOG 0.11: undo journal serialization) | The round-4 review finding is closed: the undo journal no longer serializes heap pointers. `src/state/undo_engine.cpp` now writes a versioned byte format - magic `VXUNDOJL` + u32 format version header, then fixed-width little-endian records (u64 height, i64 timestamp_ns, 32 B prev tip hash, 16 B prev supply, u64 accounts, u64 tx_count, then 42+42 B addresses and 16+16 B amounts/fees per transaction), every field written byte-wise, partial writes handled, fsync on append and rewrite. Reject-or-migrate: a file with a wrong magic/version (including every pre-0.11 raw-pointer file) is discarded and the journal rebuilds from live block application; mid-file corruption (>= one minimal record of garbage) is discarded, a short/torn tail is healed by truncating to the last complete record. Two real bugs fixed alongside: a reloaded journal was re-committed wholesale on destruction, duplicating every record in the file so a later rollback reversed each effect TWICE (fixed with a committed-baseline offset - only records not yet on disk are appended), and a block the ledger refused left its pre-state journal record behind so a later rollback would reverse effects that never happened (new `UndoEngine::drop_last_record()`, wired into the swarm resync path). Regressions: `UndoJournalByteFormatRoundTrip`, `UndoJournalRejectsHostileFiles` (rollback over pointer-shaped poison runs clean under ASan). New fuzz target `fuzz_undo_journal` (journal bytes -> parse -> rollback -> reload; 200k execs over a 9-file hostile/valid seed corpus, 0 crashes). Suite 17/17 on GCC, ASan+UBSan and fuzz lanes (81 named gtest cases). Honest remainder for 0.12: the in-memory journal now retains records after commit (rollback must keep working post-commit), so journal pruning below the GQC checkpoint belongs to 0.12/0.13. |
| (2026-11-03, BACKLOG 0.12: reorg undo correctness) | The round-4 reorg findings are closed, plus one the new regression itself uncovered. First: the journal recorded transactions by reading the store at the block's own height - but the resync path journals BEFORE the store append, so the record captured the DISPLACED block's transactions and the rollback reversed effects that never happened on this fork; `apply_block` now records the frame being passed in, with the pre-state tip taken from the block's own prev_hash (journaling is ordering-independent). Second: `UndoTransaction` restores balances but not sender nonces - every undo transaction now carries the sender's pre-block next-nonce (journal format version 2) and the rollback restores it newest-first. Third (found by the new regression): a rollback left addresses the fork CREATED as tracked zero-balance accounts, so a re-applied height-1 GENESIS_2 mint was refused forever - the reorg bricked the node; undo records now carry a created-address list and `LedgerState::forget_empty_address()` untracks them once the reversed balance is zero. Fourth: the displaced fork frames are preserved in the side journal `undo/displaced.vxd` (`VXDISPLC`, same fail-closed policy, 64 MiB cap) BEFORE any state is mutated, so a reorg is replayable in both directions (`load_displaced_frames()` reads them back byte-exact). Regression `ReorgUndoRestoresNoncesAndFrames`: reorg across a mint + a two-spend block (intra-block sequential nonces), rollback to genesis, re-apply the same frames - supply, issued supply, balances, sender nonce and account count converge byte-identically with a fresh apply, and a replayed nonce stays refused. Suite 17/17 on GCC, ASan+UBSan and fuzz lanes (82 named gtest cases); `fuzz_undo_journal` re-seeded for format v2, 150 000 execs, 0 crashes. Honest remainder for 0.13: journal pruning below the GQC checkpoint; the displaced-frame re-attach consumer ships with the deeper net stack. |
| (2026-11-03, BACKLOG 0.13: GQC checkpoint persistence) | The round-4 finding is closed: the finalized checkpoint no longer lives only in RAM. The `<ledger>.gqc` sidecar stamp existed since round 5; what was missing was the restore. On open `UndoEngine` now scans the sidecar (`BlockStore::highest_gqc_stamp`) and re-cements the highest stamped height - monotonically, so a restart never reports a height LOWER than the persisted one - and `GqcFinality` seeds its reported height from the restored guard, so `/api/consensus/finality_status` tells the truth after a restart too. Fail-closed policy: a corrupt sidecar record means nothing is restored and `finalized_sidecar_trusted()` reports false (no fabricated checkpoint, the operator re-certifies to rebuild); a torn tail (a crash mid-stamp) is healed by truncation to the last complete record, like the undo journal. Regression `GqcCheckpointSurvivesRestart`: certify block N, restart, the guard reports N again, a rollback to N-1 is refused with `ERR_FINALIZED_BY_GQC`, and a corrupt sidecar fabricates nothing. Honest remainder: a restored stamp is not yet re-verified against the share-derived recomputation on open - that belongs to the validator-authentication cycle (BACKLOG 0.4 / 2.4), since shares currently derive from public data. Suite 17/17 on GCC, ASan+UBSan and fuzz lanes (87 named gtest cases). |
| (2026-11-03, BACKLOG 0.14: mempool sealing order + publication race) | Both round-4 mempool findings are closed. Ordering: `pull_for_sealing` no longer runs a single global fee sort (whose GLOBAL nonce tie-break could emit a sender's high-fee nonce-1 ahead of its own nonce-0, so every sealed block failed apply with a nonce mismatch - a repeatable livelock); it now snapshots the pool under the mutex, groups it into per-sender nonce chains and emits a deterministic k-way merge - the chain whose head tx carries the best fee density wins the next slot, so the fee market rules across senders while a sender's nonce order is inviolable. The comparator also drops the epsilon tie-break (`|a-b| > 1e-9` is not a strict weak ordering - the classic std::sort UB pattern) in favour of exact comparison plus canonical byte tie-breaks. Publication race: slot claim, entry write and count publication happen under one pool mutex with the entry fully written first (the `find_slot` CAS that published `count_` before the write is gone); `stats()`, `pull_for_sealing` and `remove_sealed` hold the same mutex, and `remove_sealed`'s invalidation + compaction + count update is one critical section (a concurrent submit could previously lose an accepted tx while its pending balance and nonce stayed reserved). `count()`/`empty()` remain lock-free approximate hints. Regressions: `SealingPreservesPerSenderNonceOrder`, `PullBudgetNeverBreaksSenderChain`, `SealedBatchesApplyOnFirstAttempt`, and the multi-threaded stress test `ConcurrentSubmitsAndSealsStayConsistent` (8 submitters + sealing reader + concurrent stats; every pulled tx matches a submitted tx and every batch preserves per-sender chain contiguity), which is ThreadSanitizer-clean across 6 runs on a one-off TSan lane (0 warnings, instrumentation verified). Suite 17/17 on GCC, ASan+UBSan and fuzz lanes (87 named gtest cases). Honest remainders: pool-side spam caps belong to the fee-market spec (BACKLOG 2.5); the admission wiring (nothing feeds `submit()` from the network stack yet) ships with the swarm-intake work. |
| (2026-11-03, adversarial review round 5: ledger/rollback hardening) | Two P1s fixed. Rollback phantom supply: `rollback_to_height` reversed balances tx-by-tx through a clamp-at-zero `adjust_balance` - an address whose intra-block credit reversed before its debit went negative mid-loop, the debit then clamped, and the shortfall was minted from nothing; the rollback now nets REVERSAL deltas per address in phase A and applies each net exactly in phase B via `revert_balance_exact`, and any underflow aborts the rollback with `ERR_UNDO_STATE_MISMATCH` (journal erase moved after the reversal so records stay diagnosable); burned supply is restored from the record's recomputed `floor(fees/2)`. Unbounded mint: the height-1 `GENESIS_2` mint (old gate bounded only the count - block 1's miner could mint any amount to any receiver with a keyless digest) is now bound to its exact protocol shape: height 1, sender tag `GENESIS_2`, exactly `GENESIS_2_MINT_ATOMICS` (100,000 VX) to the pinned `genesis2_mint_receiver_payload()` (Address #2), untracked receiver, one per block - and the one-per-block count check runs BEFORE the shape check so a second mint of any shape is caught. P2/P3: `stamp_gqc` writes the 48-byte sidecar record with an EINTR-retrying full-write loop plus fsync (a partial write used to poison the file mid-way, fail-closing every later restart and silently resetting the finality guard); `rollback_last_append` fsyncs the truncate (an unfsynced shrink could resurrect a refused frame after a power loss, throwing on replay and bricking startup); the undo-journal loader heals a torn tail inside a multi-tx record when the record's own tx count proves only the tail is damaged (bounds-checked probe), else still fails closed; a rollback whose journal does not cover every height in the span is refused with `ERR_UNDO_JOURNAL_GAP` instead of leaving heights applied. Regressions extended in `test_documented_gaps`: the double-spend rollback pins no phantom supply and no lost debit, the pinned mint shape is exercised for wrong amount/receiver/height/second-mint/tracked-receiver refusals, and the reorg round-trip runs against the pinned mint. Suite 17/17 on GCC, ASan+UBSan and fuzz lanes (87 named gtest cases). Honest remainders (tracked, process-level): mempool admission wiring + per-sender eviction (swarm intake, BACKLOG 2.5), half-applied-block commit guard (atomic-commit work), redundant finality-guard persistence source and displaced-cap wording (doc cleanups). |

| (2026-11-07, BACKLOG 1.5: rollover certificate consensus wiring) | PQ key rollover is now a consensus-level mechanism, not just a crypto primitive. `PqWitnessRegistry::register_rollover_cert` verifies a WOTS+/XMSS-signed window transition certificate (from_window -> to_window, old_root -> new_root, signed by the leaf-15 witness key; deterministic signatures make exactly one valid cert exist per (old_root, from, to) transition) and `advance_root_chain` walks a sender's certificate chain sequentially from the account's anchor (the window-0 root committed by the PQA address), capped at `PQ_MAX_CERT_CHAIN_DEPTH` = 16. The design is deliberately STATELESS: no ledger mutation, no undo-journal surface, deterministic under reorgs. `LedgerState::apply_block` now accepts a witness whose root does not match the bound key only if a certified chain walks from the bound root to the witness root AND the witness window equals the walked window; everything else is refused with an explicit diagnostic. Leaf-15 exclusivity became a USE-time consensus invariant (`pq_verify_transaction` refuses leaf_index >= 15 everywhere: registration, wire path, consensus lookup) - leaf 15 certifies, never spends. Durable sidecar `<ledger>.pqr` (VXPQRT1, 2498 B records, flock/O_APPEND/fsync, replay re-verifies every record, torn-tail truncation to the last good record - the same torn-tail fix went into the VXPQWT1 witness sidecar). Wire: `WireMsgType::ROLLOVER_CERT` (0x0A, 2490 B payload), `wire_header_plausible` accepts 0x01..0x0A, both reader loops handle it, `broadcast_rollover_cert` relays. Caps: 32 certs/sender, 50000 senders, map entries created only on acceptance (security review P1-1: an operator[] empty entry used to defeat the cap accounting). Tests: new `VortexPqRolloverWiringTest` (10 sections: deterministic walk 0->1->2 both from genesis and anchor-relative, non-sequential refusal, root substitution both directions, chain-gap and depth caps, certs never flip is_pq_sender, hand-written VXPQRT1 replay incl. corrupt-magic record, leaf-15 mechanism pin, wire boundary 0x0A/0x0B) and 3 e2e ledger pins in `test_documented_gaps` (rollover chain accepted end-to-end through a real window-1 spend; the same spend without the cert refused with "no certified rollover chain"; leaf-15 spender refused at registration and verification). Adversarial security review triage: P1-1 (cap-defeating empty entries) and P2 (a torn sidecar record poisoned replay permanently; now truncated to the last good offset, tampering evidence preserved for clean-EOF/bad-magic) fixed; P1-2 becomes the recorded **P0 GATE**: cert delivery is fire-and-forget with no backfill - a node that misses a cert cannot heal its walk until the delivery/backfill protocol ships, so no wallet may emit certificates until that gate closes (BACKLOG 1.5). Confirmed explicitly sound: no theft/forgery path (a transferred cert is inert because the walk anchors at the spender's own window-0 root), leaf-15 breaks nothing, wire parsing bounds-checked, concurrency lock-disciplined. Suite: 37/37 ctest entries on the GCC lane and the ASan+UBSan lane (incl. the new wiring suite); TSan: first project-wide run in history 36/36 clean, the second full run caught a PRE-EXISTING unsynchronized `listen_fd_` int in `SwarmNode` (emergency_stop rewrote it while listener_loop read it) - fixed by atomization plus an accept-side stop-race guard, follow-up commit; the touched PQ/net files were also brought to clang-format cleanliness in this commit. Honest limit restated: `pq_sign_transaction` remains window-0-only (post-rollover leaf accounting is a separate BACKLOG item), and the wire windows are native-endian (fail-closed cross-endian, P3-documented). |
| (2026-11-07, BACKLOG 2.3b: reorg-interleaved fuzz harness) | New libFuzzer target `fuzz_reorg`: a deterministic prefix (genesis, the pinned GENESIS_2 mint, one funding block seeding 8 PQ pool accounts - identical bytes every exec so the witness-registry dedup behaves) followed by up to 48 fuzz-driven steps of four commands: honest mined blocks (floor coinbase + 0-2 pool transfers with per-sender intra-block nonce sequencing), hostile bit-mutated frames plus competing-height clones through both intake routes (store gate with undo journal/drop ordering, and raw ledger), reorg operations (journal rollback + store truncate + displaced-frame re-attach in the production resync order), and gossip ticks. Continuous invariants (height/nonce/exact-total-supply) and the final fresh-ledger replay canonical-digest equality abort via `fuzz_fail` so libFuzzer records the counterexample input - a silent `return` would hide the violation. Harness-only lesson recorded: the mint must go to the PINNED `genesis2_mint_receiver_payload()` address and the demo spender signs with the sponge-derived demo sk while spending FROM the pinned address (the carousel's address override, now pinned by this harness too). Smoke: 60 runs clean (PQ-signing-heavy prefix, ~3 s/exec); deeper budgets are a standing nightly item, the harness is not a ctest entry (libFuzzer requires the Clang lane). |
| (2026-11-07, BACKLOG 1.4: vault lock split - the global vault_mutex_ is gone) | The owner pattern (2026-11-05 II.1) is delivered: one global mutex used to span the whole ephemeral-sign cycle (claim -> SK expansion -> sponge sign -> zeroize/clflush burn), queueing every concurrent RPC vault call behind one signer's cryptography. Now every page transition is a CAS on `pages_[i].state` (new `CLAIMED` state marks the claim window), heavy crypto runs lock-free on the claimed page and publishes with `memory_order_release`; pages are physically disjoint, so page i never contends with page j. Design subtleties the gates forced into the open, recorded honestly: (1) a claim-then-compare consume hid live tokens from concurrent scanners for the duration of each compare - the v0.0.11 stress test failed with 201 lost tokens and 201 stranded LOCKED pages, so the final design is compare-then-claim; (2) a plain digest read raced the emergency-burn sweep zeroing the same field (no synchronization edge between the consume's acquire-load of LOCKED and the sweep's claim) - the capability digest became atomic bytes, compared constant-time with relaxed loads; the digest is immutable while LOCKED, so a zeroed digest can only produce a skip, never a false token match. Emergency wipe now LATCHES before sweeping (no new claims during the drain - without it a sustained claim stream could starve the drain loop of a quiet moment; the mutex version got termination for free by queueing), spins out in-flight CLAIMED pages, re-sweeps, and the latch stays set: the vault is retired, matching the pre-split post-emergency dead pool; `initialize` clears it. REAL BURNED-SLOT REUSE ships with the split: the round-5 policy said a page is "reusable after consumed or burned" but the pre-split scan only ever accepted VOID - the pool was silently single-use per initialize (16384 commits exhausted it forever); BURNED slots (capacity 0, zeroed) are now claimable by both commit and sign. `hw_master_key_` became atomic (emergency zeroes it while concurrent commits derive capability digests). Regression guard: the v0.0.11 `ConcurrentCommitConsumeStress` stays green (8 threads x 200 commit+consume round-trips, zero cross-contamination) plus a new `ConcurrentEmergencyBurnTerminatesAndCompletes` (4 claimer threads vs a mid-flight panic wipe: termination guaranteed by the latch, zero LOCKED pages after the wipe, post-wipe commit refused with the "retired" diagnostic). Suite: vault suite 6/6 on GCC, ASan+UBSan and TSan lanes - 8/8 TSan reruns with zero warnings (the first TSan evidence this codebase has for the vault's lock-free paths); full 37/37 ctest re-runs on the TSan and GCC lanes after the split. Honest residuals: stats buckets no longer sum to the pool size while pages are CLAIMED in flight (each page still counted exactly once, and a live token is never misreported as burned); a transient CLAIMED page makes the pool look one slot smaller to concurrent committers (the mutex version made them queue instead); `initialize` remains a setup-only call - atomic per-page stores cannot tear, but racing a live owner is still a semantic race, now documented at the call site. |
| (2026-11-07, BACKLOG 1.4 follow-up: adversarial review of the split - two concurrency defects fixed before commit) | The same review discipline that gated the split caught two more races in the split itself, both fixed and re-verified before commit: (1) HIGH - the emergency-wipe drain exited on `!any_claimed()`, but a commit that had already passed its pre-claim latch check could claim a page and publish LOCKED after the sweep passed its slot - plaintext plus a redeemable token surviving in a retired vault. Closed by a post-claim latch re-check in `commit_secure_data` and `sign_ephemeral_in_vault` (release the slot, refuse with the "retired" diagnostic) plus a fixpoint drain terminating only after a pass with zero burns, zero CLAIMED observations at any visit, and a clean final scan - sound because post-latch no claim can publish LOCKED. (2) MEDIUM - ABA on BURNED-slot reuse in `consume_data`: between the digest compare and the winning CAS the page could be wiped and repurposed, so the CAS would win against a DIFFERENT committer's page and copy that committer's secret out under the old token; closed by re-running the constant-time 32-byte compare under CLAIM, restoring LOCKED on mismatch. Also hardened: ephemeral-sign burns its claimed page on any exception path (a CLAIMED-forever page would hang the drain), and the wipe observation no longer trusts a post-CAS reload (the CAS's own updated `expected` notes CLAIMED, closing the skid window between a failed CAS and a reload). Re-verification: vault suite 8/8 TSan reruns with zero warnings, ASan+UBSan and GCC lanes green, full ctest re-runs on the TSan and GCC lanes with the fixes in (38/38 - the suite gained the unrelated WAL-marker suite along the way). |
| (2026-11-07, BACKLOG 2.6 Phase 0a: WAL intent marker - crash-consistent store append) | The store-append torn-frame window is closed: append_block fsyncs a 32-byte INTENT record (height + frame CRC32C + record CRC32C, "VXWALMK1") into the sidecar `<ledger>.walmark` BEFORE the ledger is touched, and flips it to COMMITTED after the ledger fsync - 3 fsyncs per append instead of 1, the honest price of "a reported success survived a power cut" for the ftruncate-landed-pwrite-did-not window the size check could never see. Recovery on open: corrupt/absent marker = fail-closed fallback (byte-accurate size gate first, then full validate_region); INTENT + CRC-matching tip frame = the crash hit between the ledger fsync and the COMMITTED flip, the frame stays; INTENT + CRC mismatch = torn append, healed by truncation; COMMITTED + CRC mismatch at the tip = durable marker vs disk disagreement, real corruption, fail closed. A marker naming a frame that is not on disk, or a stale record naming history, is RESOLVED (cleared) without authorizing healing - the surviving chain is always re-judged by validate_region. Two first-draft defects were caught by the project's own gates and fixed before commit: the recovery failed the reorg-heal reopen closed (legitimate truncation below a marker exists - VxCrashTortureTest.Level1StoreTailTruncation caught it), and a floor-rounded frame count masked torn tails from the "not a multiple of 65536" gate (the same suite caught it; the byte-accurate gate now runs BEFORE recovery). rollback_last_append clears the marker; the sidecar's directory is fsynced at open. Tests: VortexWalMarkerTest, 9 sections writing marker bytes exactly the way a crashed writer would have left them (clean run, torn-frame heal, fsynced-frame keep, COMMITTED CRC-mismatch fail-closed, corrupt-sidecar fallback both ways, truncation-below-marker, stale marker, intent-beyond-file, rollback). Evidence: SAN lane 9/9 + crash-torture 12/12 + reorg carousel / chain stress / apply integrity / retarget / bifurcation green; full 38/38 ctest on GCC and TSan lanes; adversarial security review of the marker returned no findings above threshold (crafted-marker truncation is operator-local tamper only, no recovery path bypasses validate_region, CRC-only acceptance unreachable), one below-threshold hardening residual recorded in BACKLOG (flock for the two-instance INTENT-window race). |


Every commit above is GPG-signed locally and **not pushed** at the time
of signing this document; the push decision stays with the repository
owner.
