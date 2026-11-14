# VX Contracts — VortexVM Program Surface (spec)

Status: NORMATIVE for the parameters it pins; whole sections that are
proposals rather than shipped code are marked OPEN and are tracked for
0.2.x/0.3.x. Sources of truth: `include/vx/vm/vortex_vm.hpp` (opcode
table, gas constants, HTLC types), `src/vm/vortex_vm.cpp` (execution
semantics, assembler), the admission code (src/state/mempool.cpp), and
`src/rpc/http_server.cpp` (the HTLC RPC seam). Where this document and
the code disagree, the code wins and this file is a bug — file it.

Owner-directed (spec-only phase, 2026-11-14): nothing in this document
is implemented beyond what already exists; the 0.1.x beta ships the VM
and the HTLC builtin, not a persistent contract layer.

## 1. What a VX contract is (v1)

A VX contract is a **deterministic validation program in VX-ASM**,
executed by VortexVM. It is stateless by construction: it reads its
inputs from the transaction/preimage and the consensus context
(`ExecutionContext`: block height, block timestamp, block view, TDI
callback, initial register file), executes, and leaves an outcome
(success/failure plus final registers). There is no persistent contract
storage, no contract-owned balance, and no contract-to-contract call in
v1 — see §7 for the explicit non-goals.

The first-class builtin is the HTLC swap (§6); every other contract is
the same shape: bytecode + claim inputs -> verified branch.

## 2. The machine (pinned constants)

| Constant | Value | Notes |
|---|---|---|
| `MAX_CYCLES` | 10 000 | execution aborts past this; a halt-by-budget is a failed contract |
| `STACK_SIZE` | 256 slots | 64-bit words |
| `NUM_REGISTERS` | 8 (R0..R7) | 64-bit each |
| `BYTECODE_MAX_SIZE` | 56 bytes | the block tail reservation is 104 B; the contract slice is 56 B by format |
| `memory_` | 64 words | LOAD/STORE scratch; dies with execution |
| `LANDAUER_KT_LN2_SCALED` | 960 micro-units per erased bit | gas is physical, see §4 |

Opcodes: the 24 canonical slots (0x00..0x17) plus the shipped additions
`DUP/SWAP/GALOIS_MUL/SOLINAS_RED/LOAD/STORE/ASSERT_EQ` (0x19..0x1F).
`mnemonic()` is the canonical name table; the assembler is two-pass with
labels, `;`/`#` comments, hex/decimal literals. Anything not in the
table is invalid bytecode — no extensibility path without a fork.

## 3. Determinism law

- The machine has **no inputs beyond its bytecode and its
  `ExecutionContext`**. Both are consensus data: the same frame on the
  same height yields the same trace on every node, byte for byte.
- Context-fed values (`OP_BLOCK_HEIGHT`, `OP_TIMESTAMP`, the block view
  for `OP_VERIFY_COCOON`, `check_tdi_fn` for `OP_CHECK_TDI`,
  `OP_HTLC_VERIFY`) are the ONLY oracles, and each is pinned by the
  block itself — a contract cannot observe wall-clock time, randomness,
  network state, or anything two honest nodes could disagree on.
- Undefined behavior is impossible by construction: the interpreter
  bounds-checks every stack/register/memory access and treats any
  out-of-range access as a failed execution, not UB.
- Verifier rule: the block producer executes first, but **every node
  re-executes every contract program it validates**. There is no
  "producer says it succeeded" shortcut.

## 4. Gas law (Landauer thermodynamic metering)

Every executed instruction charges:

    step_gas = base_opcode_cost
             + erased_bits * 960        // 1->0 transitions, popcount
             + hamming_flips * 3        // total bit flips

`total_landauer_gas` is carried in the execution result; the
per-instruction trace (`InstructionTrace`) is a first-class artifact —
the same record that makes execution auditable makes gas auditable.

- **NORMATIVE**: gas is *measured and bounded*; a program that would
  exceed `MAX_CYCLES` fails. A contract failure refuses the spend that
  carried it — never the block (admission filters garbage before apply).
- **OPEN (0.3.x, fee-market phase)**: gas is not yet priced in atoms and
  not yet linked to the fee field. Today a contract costs its author
  bandwidth (bytecode in the tx) and the network bounded CPU; the
  fee-per-gas schedule, the per-block gas ceiling, and whether the
  Landauer trace is committed into the block header are OPEN and must
  be resolved before gas enters consensus accounting.

## 5. Spend integration (OPEN — the one big design hole)

This is the section 0.2.x must close; stated as a proposal:

- A transaction's authorization today is exactly one PQ witness
  (WOTS+/XMSS, window policy per the wallet spec). A contract spend
  adds `contract_bytecode` + claim inputs to the authorization: the
  spend is valid iff the witness verifies AND the bytecode executes
  successfully under the consensus context.
- Initial register file (R0..R7) carries the claim inputs (HTLC: the
  preimage in R0/R1); the block's canonical fields fill the context.
- Failure semantics: a failed contract refuses the TRANSACTION at
  admission; a contract that would fail only after apply (context
  divergence) is impossible by §3 — but the apply-integrity rollback
  guard (existing `apply_block` commit journal) is the last-resort
  invariant either way: no partial application, ever.
- Deliberately NOT v1: contract registry addresses, callable contract
  identities, cross-contract state reads. The HTLC builtin shows the
  whole model works without any of them.

## 6. HTLC builtin (NORMATIVE — shipped)

`create_htlc_contract(secret_seed, recipient, refund, timelock)`:
- The 32-byte `hash_lock` is derived through the **4-act Galois
  attractor** over (secret, recipient, refund, timelock) — Act I..IV.
- The claim/refund program compiles to <= 56 B canonical VX-ASM.

`settle_htlc_swap(bytecode, preimage, current_height)`:
- valid preimage + `current_height <= timelock` -> **CLAIMED**
- `current_height > timelock`                  -> **REFUNDED**
- otherwise (no branch executed)               -> **LOCKED**
- `HtlcSettleResult.vm_branch_marker` = R6 left by the executed branch;
  `vm_trace` carries the full Landauer trace (auditable settlement).

Honest gaps, pinned: (a) the demo path anchors the secret to a
`secret_seed` scalar — production swaps must derive `hash_lock` from a
full-entropy preimage, never from a seed small enough to brute force;
(b) the HTLC registry is node-local demo state (`last_htlc_`), not
on-chain state — cross-chain atomicity needs the §5 spend integration
plus a wire settlement flow before mainnet claims.

Natural builtin candidates for the persistent phase (owner concept
source, "VX coin" key-system spec): the **TLMK proof-of-life timer** —
a low-privilege time-locked key whose holder periodically posts a
micro proof-of-life (the endpoint already ships demo-grade) to reset
an on-chain phantom-liquidation countdown; and **MSRK threshold
recovery** — Shamir shards combining on-chain to re-authorize an
account. Both are state-in-trie features: §7 first, then here.

## 7. Non-goals (v1, and why)

- **No persistent contract state.** State means storage-in-trie, gas
  priced per byte, eviction policy, and a reorg story for contract
  storage — none of which has a shipped foundation. The Galois trie
  (SGMT) is the natural home WHEN this lands; 0.2.x decides, 0.3.x
  builds.
- **No reentrancy.** No calls, therefore no reentrancy bugs; any future
  call model ships with reentrancy forbidden structurally (no call
  opcodes) rather than by lint.
- **No contract-paid gas routing.** The payer is the transaction
  sender; a "sponsor pays" model is a mempool-policy question, not a
  VM one.

## 8. Verification surface (test vector expectations)

- `test_vm`: assembler/interpreter round-trips, opcode semantics.
- HTLC KATs: claim/refund/locked classification per §6.
- Determinism: the same bytecode + context yields identical
  `ExecutionResult.state_root` and gas on every lane (assert/SAN/TSan).
- Admission: a transaction whose contract fails never enters the
  mempool; a frame carrying an admitted tx applies exactly once.

Regression rule as everywhere: if a KAT here and the code disagree,
the code wins and the spec is filed as a bug.
