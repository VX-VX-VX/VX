# VX L1 — Vortex Sovereign OS: Technical Whitepaper

**Version:** 6.2 (negative-vector matrix, verification-trust model)
**Date:** 2026-11-01
**License:** AGPLv3 + Cypherpunk Clause (see [LICENSE](LICENSE))
**Implementation:** C++26, GCC 15/16, GMP; this document describes the code
that is actually in this repository — every formula below was checked against
`src/math/galois_attractor.cpp`, `src/crypto/pq_signature.cpp`,
`src/consensus/pogw_miner.cpp`, `src/blockchain/genesis.cpp` and the headers
they include.

---

## 0. How to read this document, and an honesty statement

This paper is written to be *checkable*. Each section states the exact
operations the implementation performs, in the order it performs them, with
the actual constants. Where the design borrows a well-known construction
(WOTS+, XMSS, Shamir sharing, ASERT), we say so and state exactly where it
deviates. Where the design is **custom and unaudited** — the VortexSponge256
hash, the attractor as a key-derivation function, the GQC quorum stamp — we
say that too, in Section 15.

**Status: research alpha.** Not audited. Not battle-tested against a live
adversarial network. Do not trust it with real funds.

Notation used throughout:

| Symbol | Meaning |
|---|---|
| `‖` | byte-string concatenation |
| `⊕` | bitwise XOR |
| `x ≪ s` | left rotation of a 1024-bit integer by `s` bits (cyclic) |
| `mod m` | reduction into `[0, m)` |
| `P, Q, R` | the three 1024-bit field moduli (Section 3.3) |
| `Φ` | the 1024-bit Φ constant (Section 3.2) |
| `Sponge256(x)` | the VortexSponge256 hash (Section 3.5) |
| `uNN` | little-endian unsigned integer of `NN` bits |
| `[a..b)` | half-open range of bits or byte offsets |

---

## 1. Design overview

VX is a layer-1 blockchain built around four design commitments:

1. **Post-quantum signatures from block #0.** There is no ECDSA anywhere in
   the stack. Every transaction is signed with WOTS+ one-time hash chains
   inside an XMSS Merkle tree (Section 9). Hash-based signatures are the
   only digital-signature family with a security reduction to a primitive
   (hash functions) that Shor's algorithm does not touch.

2. **Deterministic genesis.** Block #0 is never shipped as an artifact. The
   full node derives it, bit-for-bit, from a published 2048-bit seed vector
   by running the same attractor every wallet runs (Section 7). "Download
   genesis.bin and trust it" is structurally impossible in VX.

3. **Bytes, not JSON.** The chain is a sequence of fixed 65 536-byte frames:
   a 472-byte header, 580 fixed 112-byte transaction slots, padding, and a
   32-byte finality stamp. Fixed-size frames give zero-copy `std::span`
   views over mmap'd storage and make the wire format equal the storage
   format.

4. **Keys that behave like matter.** Key material lives in `mlock`-protected
   arenas with an explicit page lifecycle (VOID → LOCKED → BURNED) and
   burn-on-compromise behavior (Section 12).

What VX does **not** claim: privacy of amounts (balances are plain), smart
contract expressiveness beyond the 24-opcode VX VM, or resistance to a
51% hash-power attacker beyond the GQC checkpoint mechanism (Section 10.3).

---

## 2. Threat model

| Adversary | Defense |
|---|---|
| Quantum computer (Shor) | No ECDSA/DH anywhere; hash-based signatures only |
| Quantum computer (Grover) | 256-bit digests ⇒ ~128-bit preimage security; 3072-bit attractor state ⇒ ~128-bit collision-class margins at the address level (Section 15 discusses this honestly) |
| Key extraction from memory | `mlock` arenas, `MADV_DONTDUMP`, page burning, anti-debug tripwire |
| Replay of old transactions | Per-sender 32-bit nonce, plus a chain ID in the signed digest |
| Mempool flooding | VSDPV batch filter before any per-transaction allocation |
| Deep reorganization | GQC 2/3 threshold finality stamps cement checkpoints |
| Genesis substitution | Genesis is derived, not distributed; a substituted file fails replay |

Out of scope for this release: side-channel resistance of GMP's modular
exponentiation, host-level compromise (the anti-debug tripwire is a
deterrent, not a boundary), and network-level anonymity.

---

## 3. Mathematical foundations

### 3.1 Bit and byte conventions

- All multi-byte integers in frames are little-endian (`u32`, `u64`).
- All 1024-bit field elements are serialized as 128 bytes, least-significant
  byte first.
- The seed and all hex constants are parsed as big-endian hex strings
  (`mpz_class::set_str(..., 16)`).

### 3.2 The constant Φ (PHI-1024)

The attractor uses a fixed 1024-bit constant Φ, stored as 16 `u64` limbs:

```
Φ = 0x9e3779b97f4a7c15 f39cc0605cedc834 1082276bf3a27251 f86c6a11d0c18e95
    276707e7869666c0   7166e4a2e5576ac6 c5a08e06385cfd4f 54d4f87a0229c15d
    3459c36c6e7804ee   9e54d688cf861f22 e70c5717e4a83ec0 22513f8d3886f443
    e46cf295f7ef0a88   7a0acb2f56747eb1 0013892790757a79 6a40a34a810842e4
```

The first limb is the standard 64-bit golden-ratio constant
⌊2⁶⁴/φ⌋ = 0x9E3779B97F4A7C15 (the same "nothing-up-my-sleeve" constant used
by TEA, ChaCha and many others); the remaining 15 limbs complete a fixed,
published 1024-bit vector. Φ plays three distinct roles: it seeds the third
trunk (Act I), it provides round-dependent mixing (`φ_t`, Section 4.2), and
it seals the final state (Act III).

### 3.3 The three field moduli P, Q, R

The three "trunks" of the attractor live in three different 1024-bit prime
fields. The moduli are **Solinas primes** — sparse integers of the form
2¹⁰²⁴ − 2ᵏ − c:

```
P = 2^1024 − 2^64   − 1747       (shift k = 64,   c = 1747)
Q = 2^1024 − 2^888  − 3943       (shift k = 888,  c = 3943)
R = 2^1024 − 2^512  − 267799     (shift k = 512,  c = 267799)
```

A legacy compatibility set (1397 / 105 / 265049) exists in the code but is
**not** the default; `AttractorModuli::active_default()` returns the set
above, and everything in this paper assumes it.

**Primality.** All three moduli were verified prime with GMP's
`mpz_probab_prime_p` (BPSW + 40 additional Miller–Rabin rounds) — this check
is reproducible from the constants alone and is part of the test vector
section. Primality matters for two reasons: modular inversion in Act IV
requires it, and the cubic map of Section 4.2 has clean algebraic behavior
only over a field.

**The cube-map theorem.** For a prime p, the map f: F_p → F_p, f(x) = x³ is
a bijection if and only if gcd(3, p−1) = 1, i.e. p ≡ 2 (mod 3).

*Proof.* F_p* is cyclic of order p−1. In a cyclic group of order n, the map
g ↦ g³ is a bijection iff 3 is invertible mod n. 3 is invertible mod (p−1)
iff 3 ∤ (p−1) iff p ≢ 1 (mod 3). Since p = 2 is the trivial remaining
residue class for odd primes, p ≡ 2 (mod 3). The inverse map is then
x ↦ x^d where d·3 ≡ 1 (mod p−1), which exists by Bézout. ∎

All three moduli satisfy p ≡ 2 (mod 3) — verified directly:

```
P mod 3 = 2,   Q mod 3 = 2,   R mod 3 = 2
```

so the cubic step is a **permutation** of each field, not merely a map. This
is what makes the attractor's round function invertible per-trunk (relevant
for the CRT "unwrapping" story) and keeps the cube step from degenerating
into a constant-collision attractor.

### 3.4 Solinas fast reduction (division-free pre-reduction)

For a 2048-bit product W = H·2¹⁰²⁴ + L (with 0 ≤ L < 2¹⁰²⁴), reduction mod
each Solinas prime costs two shifts and one small multiply instead of a
division. The identity comes straight from the definition of the modulus:

```
p = 2^1024 − 2^64 − c        ⟹   2^1024 ≡ 2^64 + c   (mod p)
```

Substituting into W:

```
W = H·2^1024 + L
  ≡ H·(2^64 + c) + L
  =  L  +  (H ≪ 64)  +  c·H                    (mod p)
```

Applied to the three moduli:

```
W mod P ≡ L + (H ≪ 64)  + 1747·H
W mod Q ≡ L + (H ≪ 888) + 3943·H
W mod R ≡ L + (H ≪ 512) + 267799·H
```

**Honest scope of this trick:** the value produced is a *congruent
representative*, not necessarily the canonical residue — it can exceed the
modulus, and canonicalizing it needs at least one more pass. In the
production attractor the canonical reductions inside the cubic map are
performed by GMP's `mpz_powm` (internally Montgomery/Barrett, constant-tested
code); the `FastReducer` exists as the division-free pre-reduction path for
batch/streaming use. The paper documents both because both ship.

### 3.5 VortexSponge256

The universal hash primitive of the chain — transaction digests, block
hashes, WOTS+ chains, XMSS node hashing, the PoGW proof-of-work — is a
custom ARX sponge over a 512-bit state. *(Custom and unaudited; see
Section 15.)*

**State.** Eight 64-bit words, initialized from the golden-ratio limb
vector (the first 8 limbs of Φ, same constants as Section 3.2).

**Absorb.** Input is consumed in 32-byte blocks. Block j is zero-padded to
32 bytes and XORed into words 4..7:

```
state[4..7] ^= block_j            (as four u64, little-endian)
permutation(state)                 (12 rounds, below)
```

**Permutation.** One round = four ChaCha-style ARX quarter-rounds:

```
quarter_round(a,b,c,d):
    a += b;  d ^= a;  d ≪= 16
    c += d;  b ^= c;  b ≪= 12
    a += b;  d ^= a;  d ≪= 8
    c += d;  b ^= c;  b ≪= 7
```

The four calls per round are wired so that the state graph is fully
connected:

```
QR(s0, s4, s1, s5)   QR(s2, s6, s3, s7)      — column pairs
QR(s0, s2, s4, s6)   QR(s1, s3, s5, s7)      — cross pairs
```

This is deliberate. The original implementation ran four *independent*
two-word chains, and a flipped input bit reached exactly one digest word —
which let a forged proof prefix verify. The cross-wiring forces every input
bit through carries and rotations into all eight words, restoring ≈50%
avalanche (SAC). The history is documented in the source; we keep it here
as an example of why avalanche is a *property to test*, not to assume.

**Squeeze.** The 256-bit digest is the first four state words, serialized
little-endian. **Padding** is a single 0x80 byte absorbed after the message.
Note the construction has no capacity/rate separation in the Keccak sense —
the whole state participates; the analysis in Section 15 treats it
accordingly.

---

## 4. The 3-Trunk Vortex Attractor

The attractor is the key-derivation and commitment engine of VX: it maps a
2048-bit seed to a 3072-bit state and a 256-bit address digest. It runs in
four acts; the three trunks (X, Y, Z) evolve in three distinct 1024-bit
fields (P, Q, R respectively).

### 4.1 Act I — seed expansion (2048 → 3072 bits)

Input: a hex seed of exactly 512 hex characters (2048 bits). Shorter seeds
are right-padded with '0'; longer ones truncated; if the `unlocked` flag is
false the string is reversed first (a legacy wallet-encryption hook).

```
X₀ = S[0..1024)            // first 256 hex chars, big-endian integer
Y₀ = S[1024..2048)         // second 256 hex chars
Z₀ = (X₀³ + Y₀³) mod R  ⊕  rotl(Φ, Y₀ mod 64)
```

Step by step:

1. The 2048-bit seed is split into two 1024-bit halves — the two starting
   trunks. Nothing is hashed away: the mapping seed → (X₀, Y₀) is exact and
   lossless.
2. The third trunk Z₀ is *derived*, not stored: both halves are cubed and
   reduced mod R, summed, then XOR-masked with Φ rotated by an amount taken
   from the low 6 bits of Y₀ (data-dependent rotation — the same trick
   RC5/RC6 and ChaCha use to make rotation amounts attacker-unpredictable).
3. The cube sum makes Z₀ algebraically tied to both X₀ and Y₀; a seed
   attacking only one trunk cannot control the third.

### 4.2 Act II — the round function (t = 1 .. 1000)

Each round reads the current state (x, y, z) and produces the next. Every
quantity below is a 1024-bit integer unless noted.

```
θx = x mod 64;  θy = y mod 64;  θz = z mod 64        // low 6 bits
φt = rotl(Φ, θy + t)                                 // round-drip constant

arx_X = rotl((x + y) mod 2^1024, θy) ⊕ y
arx_Y = rotl((y + z) mod 2^1024, θz) ⊕ z
arx_Z = rotl((z + x) mod 2^1024, θx) ⊕ x

cube_X = arx_X³ mod P
cube_Y = arx_Y³ mod Q
cube_Z = arx_Z³ mod R

x' = rotl(x, 13) ⊕ cube_Y ⊕ φt      (masked to 1024 bits)
y' = rotl(y, 29) ⊕ cube_Z ⊕ φt
z' = rotl(z, 43) ⊕ cube_X ⊕ φt
```

Why each ingredient is there:

- **Data-dependent rotations (θ).** Rotation amounts come from the state
  itself, so a differential attacker cannot fix them.
- **φt (round-drip).** Φ rotated by `θy + t` differs every round even if
  the state momentarily repeats, breaking cycles that a fixed constant
  would allow. Both the data (`θy`) and the clock (`t`) feed the rotation.
- **ARX cross-neighbor mixing.** Each trunk absorbs its *neighbor* via an
  add (carries — the only cheap non-linear operation on big integers),
  a data-dependent rotate, and an XOR. The three trunks are pairwise
  coupled: X←Y, Y←Z, Z←X.
- **The cubic map (the "Galois" step).** Each mixed value is cubed in its
  own field: x-class values mod P, y-class mod Q, z-class mod R. Cost:
  `mpz_powm` with exponent 3 ≈ two 1024×1024-bit multiplications plus
  reduction per trunk. By the theorem of Section 3.3, cubing is a
  bijection — no entropy is lost inside a trunk.
- **Cross-injection with a cyclic shift.** The cube of trunk Y feeds the
  *next X*, cube of Z feeds next Y, cube of X feeds next Z. This rotation
  of influence is what stops the three trunks from evolving as three
  independent streams — an algebraic event in field P eventually touches
  fields Q and R.
- **Fixed rotations 13 / 29 / 43.** Distinct, prime, and chosen so the
  three trunks' self-feedback terms never align at the same bit offset.
- **Mask to 2¹⁰²⁴.** The XOR of 1024-bit quantities stays in range, but the
  explicit mask makes overflow behavior well-defined rather than
  incidental.

The round function is memoryless: round t+1 depends only on round t, so the
whole 1000-round computation is a fixed point iteration that any
implementation can reproduce bit-for-bit.

### 4.3 Act III — the one-way lock

After the final round t = 1000, the state is folded into field residues:

```
Φlock = rotl(Φ, (y mod 64) + 1000)

r_p = ((x ⊕ Φlock) · 7  + 13) mod P
r_q = ((y ⊕ Φlock) · 11 + 17) mod Q
r_r = ((z ⊕ Φlock) · 19 + 23) mod R
```

Notes:

- Φlock depends on the *final* y, so the lock constant is itself
  data-dependent — two states that differ cannot share a lock value except
  with probability ~2⁻⁶ per attempt.
- The affine maps use small prime multipliers and addends — (7,13), (11,17),
  (19,23) — trivial to compute, cheap to reason about, and sufficient to
  decorrelate the three residues from each other before CRT.
- This is the deliberately **lossy** step of the pipeline: 3072 bits of
  state are compressed into three residues. Act IV then re-expands them
  canonically.

### 4.4 Act IV — CRT synthesis (3 × 1024 → 3072 bits)

Given residues (r_p, r_q, r_r), the Chinese Remainder Theorem reconstructs
the unique X ∈ [0, P·Q·R) satisfying:

```
X ≡ r_p (mod P),   X ≡ r_q (mod Q),   X ≡ r_r (mod R)
```

The implementation computes it in the standard idempotent form. Let
M = P·Q·R (a 3072-bit modulus) and define the partial quotients and their
inverses:

```
Mp = M/P = Q·R,      ep = Mp · (Mp⁻¹ mod P)     // ep ≡ 1 (mod P), ≡ 0 (mod Q,R)
Mq = M/Q = P·R,      eq = Mq · (Mq⁻¹ mod Q)
Mr = M/R = P·Q,      er = Mr · (Mr⁻¹ mod R)

X = (r_p·ep + r_q·eq + r_r·er) mod M
```

*Why this works:* the values e_p, e_q, e_r are the CRT idempotents — each is
1 in its own field and 0 in the other two, so the sum above evaluates to
r_p mod P, r_q mod Q, r_r mod R simultaneously. Uniqueness follows from the
CRT theorem: the map from Z_M to the product field F_P × F_Q × F_R is a
ring isomorphism (P, Q, R pairwise coprime — guaranteed since each is
prime), so the reconstruction is a **bijection**: every residue triple has
exactly one 3072-bit image and vice versa.

The 3072-bit `crtX` is the chain-level commitment used in block headers'
coordinate fields (Section 8) and by higher layers that want a single
compact number summarizing the whole attractor run.

### 4.5 Complexity

One attractor run at 1000 rounds costs 3 000 modular cubings of 1024-bit
numbers (≈ 6 000 big multiplications) plus 3 000 ARX rotations of 1024-bit
values. On a single modern core this is in the tens-of-milliseconds range —
cheap enough that every wallet derives every address locally, expensive
enough to make bulk precomputation of the seed→address space annoying.

---

## 5. Address derivation

The 256-bit account digest and its string form are derived from the final
attractor state (x, y, z):

**Step 1 — serialize.** Each trunk becomes 128 bytes, least-significant
byte first: `xB[0..127]`, `yB[0..127]`, `zB[0..127]`.

**Step 2 — xor-fold to 32 bytes.**

```
for k in 0..15:
    mixed       = xB[k] ⊕ yB[15−k] ⊕ zB[(7k) mod 16]
    digest[2k]  ^= mixed
    digest[2k+1]^= nibble_swap(mixed)      // (mixed >> 4) | (mixed << 4)
```

Reading it apart:

- The X trunk contributes its *low* 16 bytes, the Y trunk its *high* 16
  bytes (reversed order), the Z trunk a strided selection `0,7,14,…,105` —
  three different sampling patterns across the 384 input bytes, so a
  collision must agree in all three simultaneously.
- Each `mixed` byte lands twice: once raw at an even digest position, once
  nibble-swapped at an odd position. Over k = 0..15 the even positions
  0,2,…,30 and odd positions 1,3,…,31 cover all 32 digest bytes exactly
  once each.
- The fold is a keyed-by-structure mixing (no secret), suitable as an
  *address* derivation, not as a general hash — Section 3.5's sponge is
  what proofs and trees use.

**Step 3 — base64url.** The 32-byte digest is encoded in the URL-safe
base64 alphabet (`A–Z a–z 0–9 - _`), 6 bits per character: 42 full
characters (252 bits) plus one character for the trailing 4 bits, then
padded with 'A' to 45 characters total.

**Step 4 — address string.** The first 3 characters are dropped and the
`NFA_V6_` prefix attached:

```
address = "NFA_V6_" ‖ base64url(digest)[3..44]        // 42 characters
```

Precisely: the 42-character payload carries digest bits 18–255 (238 bits)
in its first 40 characters, followed by two zero-valued padding characters.
The legacy `OFA_V2_` form is the same payload with the old prefix, kept for
backward compatibility of display only.

**Step 5 — inside a transaction frame.** The 42-byte `sender_nfa` /
`receiver_nfa` fields hold the 42 ASCII characters of the payload
literally (not re-decoded bits) — the wire form of an address *is* its
display form minus the prefix.

---

## 6. Avalanche: SAC measurement

The design claim "one flipped seed bit changes everything" is a testable
property, and the codebase ships the test. `VortexAttractor::calculateSac`
runs the attractor twice — once with the seed, once with bit i flipped —
and reports, per round t, the Hamming distance between the two states
across all 3072 bits:

```
dist(t) = popcount(x_A(t) ⊕ x_B(t)) + popcount(y_A(t) ⊕ y_B(t)) + popcount(z_A(t) ⊕ z_B(t))
SAC%(t) = dist(t) / 3072 · 100
```

A healthy ARX+modular pipeline reaches ≈50% within a handful of rounds and
stays there; the test suite asserts this behavior over 20 rounds. We treat
SAC as a *smoke test for catastrophic structure* (like the sponge bug found
and fixed, Section 3.5), not as evidence of cryptographic strength.

---

## 7. Deterministic genesis

### 7.1 The principle

No `genesis.bin` is committed, downloaded or signed. Instead:

1. The canonical seed is a **published, fixed 2048-bit test vector** — a
   random value generated once for the public release and committed to
   `src/blockchain/genesis.cpp` as a string literal:

```
d15c93e51137cb32d0f0ab68524e91451f0d8a7e584a52ccad833d7c9c35396c
e8b9cfa766ac99c2214eb228c71099425cff0dd7f20ba6e3fe81f19b94e7c0bc
66a8c37e671273e08ed9060be52c43b19e79614837d911b7418147c04b8857d5
dd83fc362976394a9ceb47f946b2f70e9e94ef62ec0aeca06f280ab1ff023b08
14f44d319f30cc1402d7a4e34461725f06bb83c20035906dd26f4ba2100393c7
cbdbba1d1cd57ab5ec0614140f7f58687301a4f22c78f888929daf612d9e3469
b2fd1f7332a634663fdac32f387c63bc0d6a4fc3e47f62b3baf0c1e0194b7868
7bf978d1e0b6561501dbaa6ea17a3ad582b6e3bf4ce818823d8ce38233a2b7cf
```

2. On first start, a node with an empty ledger runs the full Act I–IV
   pipeline on this seed (1000 rounds), builds the genesis frame exactly
   as specified below, writes it to disk, and verifies its own block hash.
   Every node in the world derives the **same** block #0, bit-for-bit,
   because every operation is deterministic integer arithmetic (GMP
   results do not depend on platform for these operations).

3. A tampered or stale `genesis.bin` fails chain replay — the stored
   prev-hash linkage and header hashes will not match the derived tip —
   so genesis substitution is detected, not trusted away.

### 7.2 The genesis frame, field by field

```
height            = 0
timestamp         = 1761000000                       (fixed unix epoch)
prev_block_hash   = 0x00 × 32                        (root convention)
attractor_coords  = X ‖ Y ‖ Z   (final 1000-round state, 128 B LE each)
coinbase:
    sender_nfa    = "GENESIS0" ‖ "0"×34              (42-byte mint tag)
    receiver_nfa  = NFA_V6 payload of the attractor run on the canonical seed
    amount        = 2 540 000 VX = 254 000 000 000 000 atomics (u64 LE)
    cocoon_proof  = PQ witness anchor of the coinbase (sign_transaction)
merkle_root, header hash: per Sections 8.2–8.3
```

The single coinbase mints the entire initial supply — 2.54 million VX —
to the address derived from the published seed. There are no pre-mine
recipients, no allocation tables, no team addresses: anyone can recompute
the whole thing and see exactly one mint to exactly one derivable address.

### 7.3 Secondary mint (GENESIS_2) — demo only

The node ships a *scripted demo* (`--demo`) that mines one extra block:
a conditional 100 000 VX mint tagged `GENESIS_2` to the attractor address
of a second published demo seed, plus a 25 000 VX transfer to a third. The
mint is idempotent (it checks whether the receiver address has ever
appeared in the ledger state) and **off by default** — a node never mines
demo blocks on its own. It exists to exercise the mint/transfer/finality
paths end-to-end; it is not part of consensus.

---

## 8. Frames: transactions and blocks

### 8.1 Transaction frame — 112 bytes

| Offset | Size | Field | Meaning |
|---|---|---|---|
| 0 | 42 | `sender_nfa` | 42 ASCII chars of the sender address payload |
| 42 | 42 | `receiver_nfa` | 42 ASCII chars of the receiver address payload |
| 84 | 8 | `amount` | u64 LE, atomics (1 VX = 10⁸ atomics) |
| 92 | 4 | `fee` | u32 LE, micro-VX fee units |
| 96 | 4 | `nonce` | u32 LE, per-sender anti-replay counter |
| 100 | 12 | `cocoon_proof` | truncated 256-bit PQ witness anchor (Section 9.4) |

The 112-byte frame is **complete without the signature** — the multi-
kilobyte post-quantum witness travels separately (Segregated PQ witness,
Section 9.4), keyed by the transaction's canonical digest.

### 8.2 Block frame — 65 536 bytes

| Offset | Size | Field |
|---|---|---|
| 0 | 472 | header (below) |
| 472 | 580 × 112 = 64 960 | transaction slots (index 0 = coinbase) |
| 65432 | 32 | padding to the tail |
| 65464 | 32 | `gqc_signature_agg` — finality stamp (Section 10.3) |

Header (472 bytes, packed, no alignment holes):

| Offset | Size | Field |
|---|---|---|
| 0 | 4 | magic `"VXC6"` |
| 4 | 8 | `block_height` (u64 LE) |
| 12 | 32 | `prev_block_hash` |
| 44 | 32 | `merkle_root` over the sealed transactions |
| 76 | 8 | `timestamp` (u64 LE, unix seconds) |
| 84 | 384 | `attractor_coords` = X ‖ Y ‖ Z of the block's attractor run (128 B LE each) |
| 468 | 4 | `tx_count` (u32 LE) |

### 8.3 Hashing

```
block hash (tip hash) = Sponge256(header[0..472))
```

The proof-of-work covers the **entire** 65 536-byte frame (Section 10.1),
so header, transactions and the nonce field are all inside the hashed
surface.

### 8.4 VX60 checksum tiers

Transport-level integrity uses tiered CRC32C: stronger coverage for
money-bearing frames, lighter for metadata. It is a transport guard, not a
consensus primitive — consensus validity never depends on the checksum.

---

## 9. Post-quantum signatures: WOTS+ / XMSS (SegPQ)

### 9.1 Parameters

```
w = 16              Winternitz parameter (4-bit digits)
n = 32 bytes        digest width (Sponge256)
m = 64              message digits (32 bytes = 64 nibbles)
ℓ₁ = 64             message chains
ℓ₂ = 3              checksum chains
L  = ℓ₁ + ℓ₂ = 67   total chains
XMSS height H = 4   → 16 one-time leaves per tree
```

### 9.2 Message digest

The signed message is not the raw frame but a domain-separated digest:

```
M = Sponge256( "VX_PQ_TX_MSG_V1" ‖ sender[42] ‖ receiver[42]
               ‖ amount[8] ‖ fee[4] ‖ nonce[4] ‖ chain_id[4] )
```

Every field that a verifier needs to bind is inside the preimage, and the
chain ID blocks cross-chain replay.

### 9.3 WOTS+ chains

**Base vector.** The 32-byte digest M is split into 64 nibbles
(high nibble first within each byte): `b[0..63]`. The **Winternitz
checksum** is computed and appended as 3 further nibbles:

```
C = Σ_{i=0}^{63} (15 − b_i)            // ∈ [0, 960], fits in 12 bits
b[64] = (C >> 8) & 0xF;  b[65] = (C >> 4) & 0xF;  b[66] = C & 0xF
```

*Why the checksum exists:* without it, an attacker who wants to forge
"M" could instead sign a *smaller* message and walk chains *forward*
(hash chains are easy to advance, impossible to retreat). Adding
(15 − b_i) makes the total (b_i + (15 − b_i)) = 15·64 + 3·(checksum
digits) constant for any valid signature, so forging means walking some
chains forward **and others backward** — the backward direction is
preimage-resistant. This is the core Winternitz argument, unchanged from
the literature.

**Chain step.** Each chain link is a masked sponge call. For chain index
i and step s:

```
mask = Sponge256( "VX_WOTS_MASK" ‖ pub_seed[32] ‖ u16(i) ‖ u8(s) )
out  = Sponge256( "VX_WOTS_STEP" ‖ (x ⊕ mask)[32] ‖ pub_seed[32] ‖ u16(i) ‖ u8(s) )
```

Every (chain, step) position hashes under its **own mask** derived from the
public seed — the multi-target protection of WOTS+ (without it, an
adversary collecting many signatures could attack all positions in
parallel; per-position masks force them apart).

**Key pair.** The secret chain starts `sk_i` (derived from the master
secret key with per-chain domain separation); the public chain end is

```
pk_i = chain_run(sk_i, start = 0, steps = 15, chain = i)
```

**Signature.** For each of the 67 digits b_i, the signature element is the
state of chain i after exactly b_i steps: `sig_i = chain_run(sk_i, 0, b_i, i)`.
A verifier continues each chain from `sig_i` for (15 − b_i) steps and must
land exactly on `pk_i` — computing the base vector of the *claimed*
message. As argued above, moving b_i up is easy but forces some other
chain's checksum digit down, which is preimage-hard.

**Public-key compression.** The 67 chain ends (67 × 32 = 2144 bytes) are
absorbed into a sponge to produce the 32-byte WOTS public-key root.

### 9.4 XMSS tree and the Segregated witness

A WOTS+ key signs **once**; an account needs many signatures. XMSS binds
16 WOTS+ one-time keys into a Merkle tree of height 4:

```
leaf_j     = wots_pk_root(leaf j, master_sk, pub_seed)
node(level ℓ, idx k) = Sponge256( "VX_XMSS_NODE" ‖ pub_seed ‖ u8(ℓ) ‖ u16(k)
                                   ‖ left_child ‖ right_child )
root       = node(4, 0)  — the account's PQ public key
```

The leaf used for a given transaction is determined by a per-tree counter;
the **global leaf index** is `(subtree_index ≪ 4) | leaf_idx`, so when an
account exhausts its 16 leaves it derives the next subtree rather than
reusing a key. **One-time discipline is absolute:** a reused leaf is a
consensus-visible event, and the state machine treats PQ-backed senders as
*required* to carry a valid fresh witness.

**Witness layout (2376 bytes):**

| Part | Size |
|---|---|
| WOTS signature: 67 chains × 32 B | 2144 B |
| XMSS authentication path: H × 32 B | 128 B |
| Witness digest / commitment + leaf bookkeeping | 104 B |

**SegPQ flow.** The witness lives in an in-memory sidecar registry keyed by
the canonical message digest M. The 112-byte transaction frame carries only
a 12-byte truncation of the full 256-bit anchor in `cocoon_proof` — a
keyed ARX+Galois tag binding the frame to its witness. Verification:

1. recompute M from the frame;
2. recompute the WOTS+ chain walks from the witness and check they land on
   the leaf's public chain ends;
3. verify the Merkle path from the leaf to the account's published root;
4. check the anchor: the witness must hash to the value truncated in
   `cocoon_proof`.

A PQ-backed sender without a matching witness is rejected outright — the
chain never falls back to "checksum-only" acceptance.

### 9.5 What verification trusts — and what it recomputes

Verification is layered, and the layers consume different fields. Stating
this explicitly is cheaper than pretending a single check covers everything:

**Layer A — pure WOTS+/XMSS (`pq_verify_wots_xmss`).** Recomputes the base
vector B from M, walks every chain forward, recompresses the leaf, walks
the authentication path and compares against the witness's `pq_pubkey_root`.
This layer consumes: the 67 chains, the auth path, `pub_seed`, and the
**4-bit leaf domain** of `leaf_index` (the walk itself cannot see more than
4 bits, so the verifier normalizes `leaf_index & 15` — an unnormalized
implementation would silently ignore mutations in the high bytes). It does
*not* consume `subtree_index` or the transported `witness_digest` — by
design: they are not needed to decide "is this a valid signature".

**Layer B — the SegPQ anchor (`pq_verify_transaction`).** Recomputes the
256-bit witness commitment **from the witness content** — the same sponge
the signer ran — and refuses any witness whose transported `witness_digest`
field disagrees. Only then is the anchor checked. This is what makes the
whole 2376-byte structure tamper-evident: a digest that merely travelled
next to the witness would be attacker-writable; a recomputed one is not.

**Every transported field is recomputed or checked against a recomputed
value. Nothing is trusted because it arrived.**

**Negative vectors.** The property is tested exhaustively, not sampled:
every single byte of the witness is flipped (two bit-masks per byte) and
every mutation must be rejected — 4672 mutations at layer A, 4752 at
layer B, 16 leaf-domain relabelings, 100% rejection. The numbers and the
two real defects this matrix exposed (and fixed) are in Section 16.

**Where this sits among standardized schemes.** For scale, not as a claim
of superiority:

| Scheme | Basis | Signature | Public key | Status |
|---|---|---|---|---|
| SLH-DSA-SHA2-128s (FIPS-205) | hash-based | 7 856 B | 32 B | NIST standard, analyzed |
| SLH-DSA-SHA2-128f (FIPS-205) | hash-based | 17 088 B | 32 B | NIST standard, analyzed |
| ML-DSA-44 (FIPS-204) | lattice | 2 420 B | 1 312 B | NIST standard, analyzed |
| Falcon-512 (Round 3) | lattice | 666 B | 897 B | submitted, analyzed |
| **VX WOTS+/XMSS (w=16, H=4)** | hash-based | **2 376 B** | 32 B root | custom, **unaudited** |

The compact witness is a consequence of deliberately minimal parameters —
one subtree of 16 leaves, 4-bit chains — traded against a smaller security
margin and the one-time discipline of Section 9.4. It is **not** a better
construction than FIPS-205; it is a smaller one that fits the SegPQ frame
economics. Independent review of this exact wiring is the single most
important open item (Section 15, and ROADMAP item 4).

---

## 10. Consensus

### 10.1 PoGW — Proof of Galois Work

Mining is a Sponge256 search over the **whole** frame:

```
for nonce in 0, 1, 2, …:
    tail.pogw_nonce = nonce                       (u64 in the block tail)
    h = Sponge256(frame[0..65536))
    if leading_zero_bits(h) ≥ D: publish
```

Because the hashed surface includes the header (which includes
`prev_block_hash` and the attractor coordinates), the search cannot be
reused across blocks. Difficulty D is measured in leading zero bits; a
target of D bits expects ~2^D hash attempts per block.

### 10.2 ASERT difficulty adjustment

The difficulty follows a relative exponentially-weighted rule (ASERT —
*Absolutely Scheduled Exponentially Rising Targets*) in a simplified
per-block recursive form:

```
D_h = D_{h−1} · 2^((t_target − t_solve) / τ)
```

with:

- `t_target = 5` seconds (target block interval),
- `t_solve` = actual wall-clock time of the last block,
- `τ = 130` blocks (the half-life: a block arriving τ·1 s early/late moves
  difficulty by a factor √2 per the exponent law — more precisely,
  cumulative drift of τ seconds doubles or halves the target),
- genesis starts at D = 16 bits.

The exponent is computed in fixed point; the rule is symmetric (fast blocks
raise difficulty, slow blocks lower it) and self-correcting without anchor
bookkeeping. *(Simplified variant — the canonical ASERT anchors to a
historical reference block; this implementation recomputes per-block.)*

### 10.3 GQC — Galois Quorum Certificate (finality)

Proof-of-work alone gives probabilistic finality. VX adds a threshold
checkpoint gadget: swarm validators evaluate a per-block Galois share over
GF(2⁸) (polynomial field with the irreducible polynomial 0x11B — the AES
field); once ≥ 2/3 of the quorum set has contributed, shares are aggregated
into a 32-byte `gqc_signature_agg`, stamped into the block tail at offset
65464, and `fsync`ed — a certified checkpoint must survive reboot.

After cementation, any attempt to roll back below the checkpoint is refused
with `ERR_FINALIZED_BY_GQC`. This is the structural answer to deep
reorganizations: a 51% hash-power attacker can fork the POW surface, but
cannot rewrite cemented history without colluding with 2/3 of the quorum
set.

### 10.4 Fees and emission

- Coinbase (index 0) collects **50% of fees**; the other 50% is burned —
  a fee market with a deflationary sink (EIP-1559's lesson, applied harder).
- The base coinbase amount for a `MINER_`-tagged mint is capped at
  1000 VX; anything above the fee-derived reward is rejected by the ledger
  state machine (`excess_reward`).
- The total initial supply is exactly the genesis coinbase: 2 540 000 VX.

---

## 11. Ledger state machine

The ledger is a replay-deterministic fold over the block sequence:

```
state₀ = apply(genesis)
state_h = state_{h−1} ⊕ apply(block_h)
```

Rules enforced per block (each violation is a named rejection the RPC
surface exposes):

- per-sender nonce must be exactly the next expected value (replay
  protection);
- sender must have balance ≥ amount + fee; receiver accounts are created
  on first credit;
- `GENESIS_*`-tagged mints are accepted only from mint tags and only once
  per receiver address (idempotence check: "has this address ever
  appeared in state");
- `MINER_` coinbase amounts are capped;
- fee accounting splits 50/50 miner/burn; burned supply is subtracted from
  circulating supply;
- a full undo journal (`UndoEngine`) supports rollback above GQC-cemented
  checkpoints and nothing below them.

Replay is the trust anchor: a node that disagrees with any step of this
fold has a different chain, and the header-hash linkage makes the
disagreement localizable to an exact height.

---

## 12. Vault memory core

Key material never lives in ordinary heap memory. The vault:

- allocates page-aligned arenas and locks them with `mlock` (with an
  explicit capability probe — if the environment cannot grant
  `RLIMIT_MEMLOCK`, features degrade honestly and the *constructor stays
  strict*; the CI test suite skips locked-arena coverage with a named skip
  rather than pretending coverage);
- marks arenas `MADV_DONTDUMP` so core dumps never contain keys;
- exposes a strict page lifecycle `VOID → LOCKED → BURNED`: a burned page
  is scrubbed and can never re-enter service;
- trips an **emergency burn** of all arenas when a debugger attachment is
  detected (`TracerPid > 0`), scrubbing cache lines (`clflush`) on the way
  out;
- optionally binds key material to the host (`hw_uuid` from
  `/proc/cpuinfo` + `/etc/machine-id`, mixed into the master key), so an
  exfiltrated blob is inert off-host.

**Honest limits:** the anti-debug tripwire is a deterrent, not a security
boundary; host binding is Linux-specific and revocable only by design, not
by magic; and none of this protects a compromised OS kernel.

---

## 13. The 7-tier zero-knowledge key matrix

Accounts separate *abilities* into seven tiers, so that holding a lower
tier never implies spending power:

| Tier | Key | Can sign | Can view incoming | Can view outgoing | Can view balance |
|---|---|---|---|---|---|
| 1 | SpendingKey (SK) | ✓ | ✓ | ✓ | ✓ |
| 2 | FullViewingKey (FVK) | ✗ | ✓ | ✓ | ✓ |
| 3 | IncomingViewingKey (IVK) | ✗ | ✓ | ✗ | ✗ |
| 4 | OutgoingViewingKey (OVK) | ✗ | ✗ | ✓ | ✗ |
| 5 | TimeLockMaintenanceKey (TLMK) | ✗ | ✗ | ✗ | ✗ |
| 6 | MultiSigRecoveryKey (MSRK) | ✗ | ✗ | ✗ | ✗ |
| 7 | EphemeralKey (EK) | ✓ (single use) | ✗ | ✗ | ✗ |

All seven derive deterministically from the 256-byte master seed.

### 13.1 Shamir 2-of-3 recovery (MSRK)

The recovery secret is split with Shamir Secret Sharing over a polynomial
of degree 1 (threshold k = 2, three shards — owner, custodian node, vault
backup):

```
f(x) = s + a₁·x + a₂·x²   (mod field prime)
shard_i = (x_i, f(x_i))    for distinct public x_i
```

Recovery from any two shards is Lagrange interpolation evaluated at 0:

```
s = Σ_i  y_i · Π_{j≠i}  x_j / (x_j − x_i)
```

*Why 2-of-3:* any single shard reveals nothing about s (Shamir's privacy
property: k−1 shares are information-theoretically independent of the
secret), yet the loss of any single shard is survivable. The interpolation
is exact — three or more shards produce the same s as any two.

### 13.2 Proof-of-Life (TLMK)

Inheritance/timeout logic ("phantom liquidation") runs on a 10-year timer.
The TLMK can reset the timer by producing a lightweight zero-knowledge
proof-of-life — demonstrating possession of the tier-5 key **without**
revealing balances or the key itself. Verification is public; the proof
carries no viewing authority (see the table: TLMK has none).

### 13.3 Phantom decoys

Transfer receivers are accompanied by decoy receiver candidates drawn from
the ledger's tracked-address set, so that passive observers cannot
trivially fingerprint the real recipient from frame structure alone.
*(This is structural obfuscation, not cryptographic privacy — amounts and
balances remain public.)*

---

## 14. Networking: VX60 and the VSDPV filter

- **VX60 wire protocol** (default port 19088) carries frames, not JSON;
  checksummed by tiered CRC32C (Section 8.4).
- **VSDPV (Vortex Spam Defense Pre-Validation)** runs a batch SIMD/OpenMP
  filter directly on raw network buffers *before* any per-message
  allocation: cheap arithmetic predicates (including the TDI priority
  metric `(amount / size) × 10000` and dust heuristics) annihilate the
  overwhelming majority of spam without touching the mempool. Only
  survivors reach per-transaction parsing.
- The RPC surface (default port 8088) is deliberately separate from the
  wire port and read-mostly; state-mutating endpoints are the ones the
  security audit endpoint demonstrates attacks against (`dust_spam_tdi`,
  `tamper_amount`, `tamper_receiver`, `pq_mitm_forgery`, `double_miner`,
  `excess_reward`, `unauthorized_genesis`, `sac_avalanche_probe`).

---

## 15. Security analysis — what is strong, what is custom, what is open

**Standard and understood:**

- WOTS+ / XMSS are the NIST-finalist family (SPHINCS+ / LMS/HSS lineage)
  of hash-based signatures; the security argument (Section 9.3) reduces to
  preimage resistance of the underlying hash. Grover halves *effective*
  preimage strength: 256-bit digests → ~128-bit quantum security, which is
  the same margin AES-128 cites and is considered comfortable.
- Shamir sharing and the viewing-key tiering follow the Zcash Sapling
  pattern (cited in the references).
- ASERT is a published difficulty rule; the deviation (per-block recursion
  instead of a historical anchor) is stated above.

**Custom, and therefore the risk surface:**

- **VortexSponge256** is a bespoke ARX sponge. Its design follows
  well-understood principles (ChaCha quarter-rounds, full state-graph
  connectivity, ≈50% SAC — and the code documents one real bug of exactly
  the class such testing catches), but it has **no cryptanalysis track
  record** comparable to SHA-2/SHA-3, and its lack of a capacity/rate split
  means the standard sponge proofs do not transfer verbatim. Replacing it
  with SHA-3 is a deliberate, small, self-contained change if the community
  ever demands it — the sponge is behind one interface.
- **The 3-Trunk attractor** as a key-derivation function: the algebra here
  (permutation cube maps, CRT bijectivity, SAC) is verified, but "verified
  algebra" ≠ "cryptographic PRF". The attractor's role is derivation and
  commitment, not secrecy — but its collision behavior deserves formal
  study before any real-value deployment.
- **GQC** is a threshold stamp over an AES-field; the 2/3 quorum model
  assumes an honest-majority validator set whose formation logic is still
  research-grade.

**Open items (tracked, not hidden):**

1. Independent audit of sponge + WOTS+/XMSS wiring.
2. Formal collision analysis of the xor-fold address mapping (including
   the 18-bit prefix drop of Section 5 — a deliberate display-format
   artifact with a measurable, bounded effect).
3. Side-channel review of the attractor's use of GMP (the paper claims no
   constant-time guarantees for the big-integer path).
4. GQC validator-set formation economics.

---

## 16. Test vectors and reproducibility

Anyone can reproduce every value below from the constants in this paper.

**Canonical genesis seed (2048-bit, published):**

```
d15c93e51137cb32d0f0ab68524e91451f0d8a7e584a52ccad833d7c9c35396c
e8b9cfa766ac99c2214eb228c71099425cff0dd7f20ba6e3fe81f19b94e7c0bc
66a8c37e671273e08ed9060be52c43b19e79614837d911b7418147c04b8857d5
dd83fc362976394a9ceb47f946b2f70e9e94ef62ec0aeca06f280ab1ff023b08
14f44d319f30cc1402d7a4e34461725f06bb83c20035906dd26f4ba2100393c7
cbdbba1d1cd57ab5ec0614140f7f58687301a4f22c78f888929daf612d9e3469
b2fd1f7332a634663fdac32f387c63bc0d6a4fc3e47f62b3baf0c1e0194b7868
7bf978d1e0b6561501dbaa6ea17a3ad582b6e3bf4ce818823d8ce38233a2b7cf
```

**Derived values (1000 rounds, secure moduli set):**

| Quantity | Value |
|---|---|
| Genesis #1 address | `NFA_V6_O4HmXEAExE6zKrurarTRDZVapms3cqqoJkNRNhmgAA` |
| Genesis #1 balance | 254 000 000 000 000 atomics (2.54M VX) |
| Genesis tip hash (Sponge256 of the 472-byte header) | `ff327c330756241cd7c66a2f207c19202a2d7d38bbe9ffebb23510a72fd75be1` |
| Demo address #2 (Genesis Sender) | `NFA_V6_CLIqoXuU6o9M9cAcFUGEWe7dsxsM8WqV0RwVQnukAA` |
| Demo address #3 (Transfer Target) | `NFA_V6_iIgiAC7Bohg_wrdof8Vu1y7z0T3zHB3BMxERENEMAA` |
| Moduli primality | P, Q, R prime (BPSW + 40 MR); P ≡ Q ≡ R ≡ 2 (mod 3) |

Reproduction: clone the repo, build (README), and run
`vx_node --data-dir <fresh dir>` — the node derives genesis and prints the
address and balances above. The tip hash is observed on x86-64
little-endian builds; serialization conventions of Section 3.1 pin it.

**SAC probe.** `/api/crypto/canonical` exposes the single-bit-flip
avalanche trace (Section 6) for the canonical seed.

**Negative vectors (wycheproof-style).** Positive vectors only prove an
implementation agrees with itself. The witness verification is therefore
tested against exhaustive *negative* vectors: every byte of a signed
witness is flipped in turn (bit-masks `0xFF` and `0x01`), plus a full sweep
of the 4-bit leaf domain, and **every** mutation must be rejected:

| Matrix | Mutations | Rejected |
|---|---|---|
| Layer A — signature region (pub_seed, root, 67 chains, auth path) | 4 672 | 4 672 (100%) |
| Layer A — leaf domain (all 16 leaf labels, honest one excluded) | 15 | 15 (100%) |
| Layer B — whole 2376-byte witness incl. index header and digest field | 4 752 | 4 752 (100%) |

Reproduce with `ctest -R VortexPqSignatureTest` — the matrix is TEST 7 of
the suite and prints its own counts.

These vectors are not decorative: building them exposed two real defects,
both fixed. First, the verifier consumed `leaf_index` unnormalized while
the auth-path walk only sees 4 bits, so mutations in the high bytes were
invisible at layer A — the verifier now normalizes `leaf_index & 15`.
Second, the SegPQ anchor trusted the *transported* `witness_digest` field
instead of recomputing it from the witness content, so lying metadata
passed the anchor; the verifier now recomputes the commitment and refuses
a disagreeing witness. Both are exactly the class of bug that positive
vectors cannot catch.

---

## 17. References

1. Bernstein, D. J. et al. — *Hash-based digital signatures*; RFC 8391
   (XMSS), RFC 8554 (LMS/HSS), SPHINCS+ (NIST PQC signature finalist).
2. Zcash Protocol Specification, *Sapling* — viewing-key tiering and
   spend/view authority separation.
3. Bünz, Kiffer, Luu, Zamfir — ASERT difficulty adjustment.
4. Shamir, A. — *How to share a secret*, CACM 1979.
5. Granlund, Möller et al. — GMP: The GNU Multiple Precision library.
6. ISO/IEC 14882:2026 — the C++26 standard.
7. GNU AGPLv3 — https://www.gnu.org/licenses/agpl-3.0.txt
