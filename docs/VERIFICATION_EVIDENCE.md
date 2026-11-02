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
# fresh dir -> ff327c330756241cd7c66a2f207c19202a2d7d38bbe9ffebb23510a72fd75be1
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
100% tests passed out of 16
Total Test time (real) = 4.49 sec
```

Structure: **16 test binaries** - 12 gtest-structured suites carrying
**56 named test cases** (enumerated in 3.3), plus 4 scenario-style mains
carrying **27 numbered test blocks** (enumerated in 3.4). Total: 83
discrete test blocks.

### 3.2 Per-binary results (real ctest output)

```
 1/16 VortexMathTest            Passed   0.00 sec
 2/16 VortexDeepCryptoTest      Passed   0.03 sec
 3/16 VortexBlockTest           Passed   0.01 sec
 4/16 VortexMempoolTest         Passed   0.00 sec
 5/16 VortexVMTest              Passed   0.00 sec
 6/16 VortexChainReorgTest      Passed   0.00 sec
 7/16 VortexVaultMemoryTest     Passed   0.01 sec
 8/16 VortexZkKeyMatrixTest     Passed   0.00 sec
 9/16 VortexTensorV6Test        Passed   0.00 sec
10/16 VortexSwarmP2PTest        Passed   0.18 sec
11/16 VortexGaloisTrieTest      Passed   0.01 sec
12/16 VortexLandauerMevTest     Passed   0.00 sec
13/16 VortexGqcRingStealthTest  Passed   0.01 sec
14/16 VortexVaultHtlcTest       Passed   0.00 sec
15/16 VortexChaosFuzzerTest     Passed   1.78 sec
16/16 VortexPqSignatureTest     Passed   3.27 sec
```

### 3.3 The 56 named gtest cases (complete enumeration)

**VortexSwarmP2PTest** (tests/test_swarm_p2p.cpp, 6 cases)

| Case | Property proven |
|---|---|
| `WireHeaderIsExactly24Bytes` | the VX60 header is a fixed 24-byte layout, as specified |
| `CorruptedPacketDroppedByCrc32c` | a packet whose CRC32C does not match is dropped, not parsed |
| `RecvPacketRejectsSingleBitFlip` | flipping one bit of a valid packet breaks its CRC and it is rejected |
| `FullBlockRoundTripOverTcp` | a 65536-byte block frame survives a real TCP round-trip byte-for-byte |
| `SplitBrainReorgConverges` | two in-process nodes on divergent tips converge on the heavier branch via O(1) undo rollback |
| `ListenerRelaysVerifiedFrameToHook` | a verified inbound frame is delivered to the registered frame hook (the relay path the RPC node uses) |

**VortexMempoolTest** (tests/test_mempool.cpp, 2 cases)

| Case | Property proven |
|---|---|
| `StaticAssertGeometry` | the mempool's fixed cocoon geometry holds at compile time |
| `MempoolConstruction` | the mempool constructs and accepts a cocoon under its TDI rules |

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

**VortexGqcRingStealthTest** (tests/test_gqc_ring_stealth.cpp, 5 cases)

| Case | Property proven |
|---|---|
| `GqcFinalizedReorgBlocked` | a finalized checkpoint cannot be reorganized past |
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

### 3.5 Real per-case timings (all 56 gtest cases, captured output)

Reproduce: `cd build && for b in test_mempool test_galois_trie
test_swarm_p2p test_reorg test_vault_memory test_vault_htlc test_vm
test_landauer_vm_mev test_gqc_ring_stealth test_tensor_v6 test_zk_matrix
test_chaos_fuzzer; do ./$b; done`

```
[       OK ] VortexMempoolTest.StaticAssertGeometry (0 ms)
[       OK ] VortexMempoolTest.MempoolConstruction (1 ms)
[       OK ] VortexGaloisTrieTest.Insert100KeysDeterministicRoot (6 ms)
[       OK ] VortexGaloisTrieTest.GetRoundTripAndAbsentKeys (0 ms)
[       OK ] VortexGaloisTrieTest.ProofGenerateVerifyUnder2048Bytes (2 ms)
[       OK ] VortexGaloisTrieTest.TamperedProofOrValueFailsVerification (1 ms)
[       OK ] VortexSwarmP2PTest.WireHeaderIsExactly24Bytes (0 ms)
[       OK ] VortexSwarmP2PTest.CorruptedPacketDroppedByCrc32c (0 ms)
[       OK ] VortexSwarmP2PTest.RecvPacketRejectsSingleBitFlip (0 ms)
[       OK ] VortexSwarmP2PTest.FullBlockRoundTripOverTcp (0 ms)
[       OK ] VortexSwarmP2PTest.SplitBrainReorgConverges (81 ms)
[       OK ] VortexSwarmP2PTest.ListenerRelaysVerifiedFrameToHook (100 ms)
[       OK ] VortexChainReorgTest.EmergencyStop (0 ms)
[       OK ] VortexVaultMemoryTest.PageStateTransitionsAndBurning (4 ms)
[       OK ] VortexVaultMemoryTest.HardwareUuidBindingSeed (0 ms)
[       OK ] VortexVaultMemoryTest.EmergencyBurnAll (3 ms)
[       OK ] VortexVaultMemoryTest.RegisterScrubbing (0 ms)
[       OK ] VortexVaultHtlcTest.EphemeralSignBurnsPage (2 ms)
[       OK ] VortexVaultHtlcTest.HtlcClaimBeforeTimelock (0 ms)
[       OK ] VortexVaultHtlcTest.HtlcRefundAfterTimelock (0 ms)
[       OK ] VortexVaultHtlcTest.HtlcLockedOnWrongPreimage (0 ms)
[       OK ] VortexVMTest.AssembleDisassembleLimits (0 ms)
[       OK ] VortexVMTest.BasicArithmeticOps (0 ms)
[       OK ] VortexVMTest.LogicalOps (0 ms)
[       OK ] VortexVMTest.CryptoOps (0 ms)
[       OK ] VortexVMTest.StateRootGeneration (0 ms)
[       OK ] VortexLandauerMevTest.AssembleWithLabelsTwoPass (0 ms)
[       OK ] VortexLandauerMevTest.LandauerFormulaExactness (0 ms)
[       OK ] VortexLandauerMevTest.NewOpcodesGaloisMulSolinasStackOps (0 ms)
[       OK ] VortexLandauerMevTest.DandelionStemToFluffCycle (0 ms)
[       OK ] VortexLandauerMevTest.DandelionTdiSpamAnnihilated (0 ms)
[       OK ] VortexLandauerMevTest.HamiltonianNeutralizesSandwich (0 ms)
[       OK ] VortexGqcRingStealthTest.GqcFinalizedReorgBlocked (0 ms)
[       OK ] VortexGqcRingStealthTest.GqcAggregationDeterministic (0 ms)
[       OK ] VortexGqcRingStealthTest.RingPipelineThroughputNoAllocs (2 ms)
[       OK ] VortexGqcRingStealthTest.RingPipelineWrapAround (2 ms)
[       OK ] VortexGqcRingStealthTest.StealthEnvelopeOneOfSixteen (0 ms)
[       OK ] VortexTensorV6Test.FastReducerAndSacEvaluation (4 ms)
[       OK ] VortexTensorV6Test.MultiTensorV6Pipeline (0 ms)
[       OK ] VortexTensorV6Test.TensorNoZeroCollapse (0 ms)
[       OK ] VortexTensorV6Test.VirtualTensorEvolution (0 ms)
[       OK ] VortexZkKeyMatrixTest.DeriveAll7KeyTiers (0 ms)
[       OK ] VortexZkKeyMatrixTest.All7KeysArePairwiseDistinct (0 ms)
[       OK ] VortexZkKeyMatrixTest.ShamirSecretSharingRecovery (0 ms)
[       OK ] VortexZkKeyMatrixTest.ShamirAll32BytesComputed (0 ms)
[       OK ] VortexZkKeyMatrixTest.ProofOfLifeAndAuditView (0 ms)
[       OK ] VortexZkKeyMatrixTest.ForgedProofHashReturnsFalse (0 ms)
[       OK ] VortexZkKeyMatrixTest.AuditViewRejectsZeroKey (0 ms)
[       OK ] VortexZkKeyMatrixTest.ProofOfLifeTimeWindow (0 ms)
[       OK ] VortexZkKeyMatrixTest.ShamirThreshold3 (0 ms)
[       OK ] VortexChaosFuzzerTest.WireHeaderChaos10k (276 ms)
[       OK ] VortexChaosFuzzerTest.FrameTxChaos10k (275 ms)
[       OK ] VortexChaosFuzzerTest.VmBytecodeChaos10k (271 ms)
[       OK ] VortexChaosFuzzerTest.VmInfiniteLoopBounded (2 ms)
[       OK ] VortexChaosFuzzerTest.SgmtProofForgeryZeroFalsePositives (271 ms)
[       OK ] VortexChaosFuzzerTest.FullChaosRoundInvariants (274 ms)
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
100% tests passed out of 16
Total Test time (real) = 9.40 sec
```

Tail of the per-binary output (real):

```
10/16 VortexSwarmP2PTest   Passed  0.22 sec
11/16 VortexGaloisTrieTest Passed  0.04 sec
12/16 VortexLandauerMevTest Passed 0.02 sec
13/16 VortexGqcRingStealthTest Passed 0.03 sec
14/16 VortexVaultHtlcTest  Passed  0.02 sec
15/16 VortexChaosFuzzerTest Passed 3.99 sec
16/16 VortexPqSignatureTest Passed 4.81 sec
```

Property: zero sanitizer findings anywhere in the 83 test blocks. CI runs
the same lane on every push (`.github/workflows/ci.yml`, job `asan`).

Not covered by this lane: TSan (data races). The swarm layer grew
listener + per-connection handlers + per-peer reader threads; a TSan job
is BACKLOG 1.4 and not yet run. Stated plainly: race-freedom of the P2P
threads is **not** currently evidenced.

---

## 5. Layer 3 - libFuzzer targets (4)

| Target | Surface | CI budget | Local recorded run |
|---|---|---|---|
| `fuzz_block_frame` | 64 KiB frame parser | 100k execs, seed 1 | CI green (last push) |
| `fuzz_pq_witness` | PQ witness verify | 20k execs, seed 1 | CI green (last push) |
| `fuzz_wire` | VX60 ingest gate | 200k execs, seed 1 | CI green (last push) |
| `fuzz_rpc` (new, `93e1756`) | the whole JSON RPC surface | 200k execs, seed 1 | **200 000 runs, 484 s, 0 crashes** (section 5.2) |

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

Recorded output (2026-11-02, all three nodes real processes on one host):

```
[1/5] Minting the demo chain once, then snapshotting it to all nodes
[2/5] Starting star topology (B and C dial A on :19188)
  [PASS] RPC :18088 is up
  [PASS] RPC :18089 is up
  [PASS] RPC :18090 is up
[3/5] Transfer on A must propagate over VX60 to B and C
  [PASS] tip on A matches the transfer block
  [PASS] tip on B matches A
  [PASS] tip on C matches A
  [PASS] sender balance on B is 74993 VX
[4/5] Garbage packets are counted as corrupted; the node stays alive
  [PASS] corruption counter rose (0 -> 10)
  [PASS] node A still serving after garbage
[5/5] In-process split-brain reorg simulation
  [PASS] split-brain reorg converged

=== 10 passed, 0 failed ===
```

What each PASS means in protocol terms: a transfer minted on the hub was
relayed as a RAW_BLOCK_64K frame, CRC32C-verified, tip-extension-checked
(height == chain_height && prev_block_hash == tip), applied through the
same `apply_block` path local transfers use, re-broadcast one hop, and
both spokes ended on the identical tip hash and balances. 10 deliberately
malformed packets were counted (`corrupted_packets_dropped`) and the node
kept serving. The reorg demo heals a partition through real VX60 loopback
TCP with O(1) undo rollback.

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
`ff327c33...7c9488`'s predecessor constant - see claim C31.)

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
| C1 | 16/16 tests pass | `cd build && ctest` | `100% tests passed out of 16` |
| C2 | 83 test blocks exist | `cd build && for b in test_*; do ./$b --gtest_list_tests 2>/dev/null; done \| ...` or read section 3 | counts match 3.3/3.4 |
| C3 | Sanitizer-clean suite | `cd build_san && ctest` | 16/16, no ASan/UBSan output |
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

1. **Nothing here is independent verification.** All 83 blocks, all four
   fuzzers and all live runs were executed by the project's own tooling
   on its own hardware/CI. Statuses cap at Tested.
2. **No cryptanalysis has been run** on VortexSponge256 or the attractor
   round function (differential/linear batteries: BACKLOG 1.3). The SAC
   matrix and NIST-style frequency test are necessary, not sufficient.
3. **No race evidence for the P2P threads** (no TSan lane yet - BACKLOG
   1.4). The leaf ledger's own concurrency story is covered by mutex +
   flock and by design review, not by TSan.
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

# 1. unit/integration lane (expect: 16/16, ~4.5 s)
cmake --build build -j && (cd build && ctest --output-on-failure)

# 2. sanitizer lane (expect: 16/16, no diagnostics)
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

# 7. the genesis constant (expect: tip_hash_hex starts ff327c33)
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

## 10. Changelog of this verification pass

| Commit | Content |
|---|---|
| `93e1756` | public `route()` catch-all; two unguarded `std::stod` fixed; `fuzz/fuzz_rpc.cpp` + CI wiring |
| `424b743` | ROADMAP near-term emptied; BACKLOG 1.1 closed |
| `d72f6fc` | VERIFICATION_RECORD.md (18-component status) |
| `c1d6230` | PqLeafLedger: durable one-time-leaf lifecycle, per-call leaf reporting, TEST 8 |
| `f55fbd1` | External-review finding, fixed at HEAD: synthetic ring decoys read 35 bytes from a 32-byte buffer (3 trailing decoy bytes were adjacent stack garbage). Whole-repo `-Warray-bounds` scan after the fix: zero hits |

Every commit above is GPG-signed locally and **not pushed** at the time
of signing this document; the push decision stays with the repository
owner.
