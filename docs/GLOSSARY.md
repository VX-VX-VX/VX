# VX Glossary

Terms used across the codebase, the README and the whitepaper. Section
numbers refer to [WHITEPAPER_V6.md](../WHITEPAPER_V6.md).

## Chain and addresses

- **VX** — the chain and its unit. 1 VX = 10⁸ **atomics**; all ledger
  arithmetic and the `amount` field are atomics (u64 LE).
- **NFA_V6_** — current address format: prefix + 42 URL-safe base64
  characters derived from the 256-bit folded attractor digest (§5).
- **OFA_V2_** — legacy display prefix for the same payload; kept for
  backward compatibility only.
- **Genesis #1** — block #0; the single 2.54M VX coinbase derived
  deterministically from the published canonical seed (§7).
- **GENESIS_2** — demo-mode-only secondary mint tag (§7.3). Never produced
  unless the operator passes `--demo`.

## Attractor

- **3-Trunk Vortex Attractor** — the key-derivation/commitment engine:
  three 1024-bit trunks (X, Y, Z) evolving in three distinct prime fields
  (P, Q, R), executed in four acts (§4).
- **Act I** — seed expansion: 2048-bit seed → three starting trunks (§4.1).
- **Act II** — the round function: ARX cross-mixing + cubic map + round-
  dependent Φ rotation, 1000 rounds (§4.2).
- **Act III** — the one-way lock: final state folded into field residues
  r_p, r_q, r_r (§4.3).
- **Act IV** — CRT synthesis: residues re-expanded to the unique 3072-bit
  commitment (§4.4).
- **Trunk** — one of the three 1024-bit state coordinates.
- **Solinas moduli** — the sparse primes P = 2¹⁰²⁴−2⁶⁴−1747,
  Q = 2¹⁰²⁴−2⁸⁸⁸−3943, R = 2¹⁰²⁴−2⁵¹²−267799; all prime, all ≡ 2 (mod 3),
  which makes the cubic map a bijection (§3.3).
- **Φ (PHI-1024)** — fixed 1024-bit golden-ratio-derived constant used for
  seeding, round-drip and locking (§3.2).
- **SAC** — Strict Avalanche Criterion; the measured per-round Hamming
  distance after flipping one seed bit (§6).

## Frames and hashing

- **Frame** — a fixed-size byte structure: 112-byte transaction frames,
  65 536-byte block frames (§8).
- **VortexSponge256** — the chain's ARX sponge hash: 512-bit state, 32-byte
  absorb blocks, 12 rounds of ChaCha-style quarter-rounds, 256-bit digest
  (§3.5). Custom and unaudited — see §15.
- **xor-fold** — the 384→32-byte structure-mixed digest behind addresses
  (§5).
- **cocoon_proof** — the 12-byte transaction field carrying a truncated
  256-bit anchor that binds the frame to its PQ witness (§8.1, §9.4).
- **VX60** — the binary wire protocol (default port 19088) with tiered
  CRC32C checksums (§14, §8.4).

## Signatures

- **WOTS+** — Winternitz one-time signature over hash chains; w = 16,
  64 message nibbles + 3 checksum nibbles = 67 chains (§9.3).
- **XMSS** — Merkle tree (H = 4, 16 one-time leaves) binding WOTS+ keys to
  one account root; global leaf index never repeats (§9.4).
- **SegPQ** — *Segregated Post-Quantum witness*: the 112-byte tx frame
  stays clean; the 2376-byte witness travels in a sidecar registry keyed
  by the canonical tx digest, bound by the cocoon anchor (§9.4).
- **PQ-backed sender** — an account registered as requiring a valid fresh
  witness; keyless fallback verification is rejected.

## Consensus

- **PoGW** — *Proof of Galois Work*: Sponge256 search over the whole block
  frame for a 64-bit nonce yielding ≥ D leading zero bits (§10.1).
- **ASERT** — the difficulty rule D_h = D_{h−1}·2^((t_target−t_solve)/τ);
  target 5 s, half-life τ = 130 (§10.2).
- **GQC** — *Galois Quorum Certificate*: 2/3-threshold finality stamp over
  GF(2⁸), 32 bytes at frame offset 65464; cemented checkpoints refuse
  rollback (`ERR_FINALIZED_BY_GQC`) (§10.3).
- **Fee split** — 50% of fees to the miner, 50% burned (§10.4).

## State and defense

- **LedgerState** — the deterministic replay fold over blocks (§11).
- **UndoEngine** — the rollback journal; refuses to roll back below a GQC
  checkpoint (§11).
- **VSDPV** — *Vortex Spam Defense Pre-Validation*: batch SIMD filter on
  raw network buffers before mempool admission (§14).
- **TDI** — the priority metric (amount / size) × 10000 used by VSDPV and
  the fee market (§14).
- **VX VM** — the 64-bit register/stack machine with 24 opcodes and a
  10 000-cycle limit.

## Keys and vault

- **Vault memory core** — mlock-protected arenas with the strict page
  lifecycle VOID → LOCKED → BURNED and burn-on-compromise behavior (§12).
- **Emergency burn** — scrub-all-arenas tripwire on detected debugger
  attachment (§12).
- **7-tier key matrix** — SpendingKey → EphemeralKey authority separation;
  lower tiers never imply spending power (§13).
- **MSRK / Shamir 2-of-3** — recovery secret split into three shards, any
  two recover it via Lagrange interpolation (§13.1).
- **Proof-of-Life** — TLMK-generated zero-knowledge statement resetting
  the 10-year phantom-liquidation timer, with no balance access (§13.2).
- **Phantom decoys** — structural decoy receiver candidates accompanying
  transfers; obfuscation, not privacy (§13.3).
