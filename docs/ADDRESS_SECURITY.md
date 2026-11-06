# Address Security of Vortex: the Key-Search Wall

Status: normative design note for Vortex Core v6.x. Cross-references:
WHITEPAPER_V6.md Section 5 (address derivation) and Section 15 (security
analysis). All numbers below were recomputed independently; the empirical
claims are reproducible from this repository (commands inline).

---

## 1. The problem, restated precisely

Given a published target address `NFA_V6_*`, find a 2048-bit master seed
whose derivation chain ends at that address. Formally:

```
seed ∈ [0, 2^2048)                -- master seed space
     -- KDF stretch (VX_KDF_ITERS rounds of the sponge)
     -- attractor: 1000 iterations of the cubic modular map
        over MOD_P / MOD_Q / MOD_R (generalized Mersenne moduli),
        per-axis rotations keyed off neighbouring axis tails
  → (X, Y, Z) ∈ (Z_modP x Z_modQ x Z_modR), each ~1024-bit
  → address = "NFA_V6_" + base64url(xorFold(X, Y, Z))[3..44]
```

The binding condition a candidate seed must satisfy is the **fold
preimage**: `xorFold(X, Y, Z) == target_digest`. That condition — not a
parity invariant — is the wall this document analyzes.

## CORRECTION (2026-11-06): the digest carries 128 bits, not 256

Found during the genesis-migration vector work and pinned 32/32 in
`test_digest_uniformity` (`VortexDigestUniformityTest`). The xor-fold
implementation (src/math/galois_attractor.cpp) writes

    out[2k]   = mixed_k = x_k ^ y_(15-k) ^ z_((7k) mod 16)
    out[2k+1] = nibble_swap(mixed_k)

so every adjacent byte pair of the digest is (b, swapnib(b)) - the
second byte carries NO new information. Additionally only the TOP 128
bits of each 1024-bit final state enter the fold (bytes 0..15; the
byte-extraction loop writes the most significant byte to index 0).
Corrected arithmetic:

| Quantity | Claimed | ACTUAL |
|---|---|---|
| Address digest space | 2^256 | **2^128** (16 independent bytes) |
| Birthday collision threshold | ~2^128 accounts | **~2^64 accounts** |
| Fold-preimage wall (generic) | ~2^256 | **~2^128** |
| Visible payload entropy | 238 bits | **~126 bits** (16 bytes + truncation) |

Two independent consequences:

1. **Security margin, not break.** 2^128 address space and a ~2^64
   birthday bound remain far beyond any realistic account population;
   seed preimage still requires inverting ~1000 ARX+sponge rounds. But
   the published 256-bit claims above are WRONG and must not be cited.
2. **Fingerprinting.** The (b, swapnib(b)) byte structure is visible in
   the base64url body: every VX address is trivially distinguishable
   from arbitrary base64 strings by this pattern alone - a linkability
   and network-fingerprinting surface that did not have to exist.

DECISION: the derivation, wire formats and address formats are FROZEN.
The fix is an ADDRESS FORMAT V2 (independent hash-based fold - the
sponge, not a hand-rolled XOR) adopted through the genesis migration
protocol (docs/DERIVATION_MIGRATION.md, `DERIVATION_VERSION`), with
old/new node fail-closed separation. Until then this defect stands
documented and pinned. The claims in the numbered sections below are
the PRE-correction analysis; wherever they state 256-bit figures, the
corrected table above governs.

## 2. Space arithmetic

| Quantity | Value | Source |
|---|---|---|
| Master seed space | 2^2048 = 3.2317 × 10^616 | seed wire width |
| Address digest space | 2^256 ≈ 1.1579 × 10^77 | 32-byte xor-fold digest |
| Visible address payload | 238 bits ≈ 2^238 | base64url[3..44] (top 18 bits dropped) |
| Seed-to-address multiplicity | 2^2048 / 2^256 = 2^1792 | Dirichlet-type counting |

Two readings of the multiplicity, both correct and often conflated:

- **Reserve for the legitimate user.** Because ~2^1792 seeds map to each
  reachable digest, a seed *for any address* exists with overwhelming
  probability, and an honest wallet that lost its seed cannot enumerate
  them either — the multiplicity is a statement about the map's shape,
  not a recovery mechanism. The seed remains the sole root of trust.
- **No help to the attacker.** The attacker does not get to *choose*
  among the 2^1792 preimages; finding *any one of them* is a preimage
  search over a random-looking map, and the expected work is governed by
  the digest width (Section 3), not by the ratio 2^1792. A large codomain
  preimage count per target does not lower preimage cost: for a random
  function with 2^256 outputs, expected cost of hitting one specified
  output is ~2^256 evaluations regardless of how large the input space
  is beyond that.

**Structural observation (honest disclosure).** The fold reads only
48 of the 384 serialized state bytes. In the implementation
(`src/math/galois_attractor.cpp`, `VortexAttractor::xorFold`) the
serialization is most-significant byte first (index 0 = most significant
byte), so the digest is computed from the **high 16 bytes (top 128 bits)
of each trunk**: X straight (`xB[k]`), Y reversed (`yB[15-k]`), and Z
permuted by `(7k) mod 16` — since gcd(7, 16) = 1 that permutation visits
all 16 positions (0, 7, 14, 5, 12, 3, 10, 1, 8, 15, 6, 13, 4, 11, 2, 9).
The digest therefore pins 48 state bytes — 128 bits of each trunk — and
the remaining 336 bytes are unconstrained *by the address alone*. This does not by itself lower the wall — the 48-byte
window is not independently choosable; it is the output of 1000 coupled
cubic iterations, and no inversion shortcut from a chosen 48-byte window
to a matching seed is known. But "no shortcut is known" is a claim about
a bespoke map (WHITEPAPER_V6.md Section 15, "custom = risk surface"), and
the window narrowness is the first place formal cryptanalysis should
look. It is recorded here deliberately so reviewers start there.

## 3. The wall: expected preimage cost

For a random 256-bit digest, generic preimage cost is ~2^256 evaluations
of the full chain. In Vortex one "evaluation" is unusually expensive:

- 1 KDF stretch of `VX_KDF_ITERS` sponge rounds (default kept modest;
  the parameter exists to tune wallet-open latency, see Section 6),
- 1000 attractor iterations, each doing three modular cubic maps over
  ~1024-bit generalized Mersenne moduli plus cross-axis rotation taps —
  hundreds of 1024-bit modular multiplications per iteration,
- one xor-fold and base64url encode.

Compare Bitcoin, the reference point the community calibrates against:

| System | Generic preimage of one address | Per-trial cost |
|---|---|---|
| Bitcoin P2PKH | ~2^160 (hash160) | 1 SHA-256 + 1 RIPEMD-160 |
| Bitcoin EC key (Pollard rho) | ~2^128 | 1 scalar add |
| Vortex address | ~2^256 chain evaluations | 1000 iterations × 3 cubic maps (1024-bit) + KDF |

The Vortex wall is stronger in *exponent* (2^256 vs 2^160) and by many
orders of magnitude in *per-trial cost*. Honest symmetry: per-trial cost
cuts both ways — legitimate key generation is also slow. That is a
deliberate tradeoff (wallet creation is a rare, offline, human-attended
event), tunable via `VX_KDF_ITERS`, and it is **not** a VDF claim
(Section 6).

## 4. The parity condition: invariant or filter?

An earlier formulation of this problem listed a third condition,
`X ⊕ Y ⊕ Z = 0` after iteration 1000, as an additional wall. Empirical
result on the canonical seed (the published test vector,
`d15c93e5...2b7cf` in WHITEPAPER_V6.md Section 16): **the bitwise
X ⊕ Y ⊕ Z value of the state changes on essentially every iteration.**
A 60-line probe (linking this repository's `src/math/galois_attractor.cpp`
and calling `VortexAttractor::run(canonicalSeed, 1000, ...)`), built and
run as:

```
g++ -std=c++26 -O2 -Iinclude probe.cpp src/math/galois_attractor.cpp \
    -lgmpxx -lgmp -pthread && ./a.out
```

reports 99 parity changes over 100 recorded steps and a nonzero final
parity.
The address still derives exactly as pinned by the test vector — which
is expected, because the address binds to `xorFold(X, Y, Z)`, not to any
parity of the state.

The dichotomy that resolves this is worth stating once, because it
applies to every proposed "extra condition" on a key search:

- **If a condition holds for all seeds (an invariant),** it adds zero
  attacker work — the attacker satisfies it automatically — and its real
  value is *verification*: a cheap check that a derivation was performed
  honestly. That is useful, but it belongs in the certificate/attestation
  layer, not in the wall.
- **If a condition holds for a fraction 2^-k of seeds (a filter),** it
  multiplies attacker work by up to 2^k — *and* multiplies the honest
  wallet's expected generation attempts by 2^k, since rejection sampling
  is the only way a legitimate user hits it. There is no free lunch:
  filter strength for the attacker is rejection cost for the user.

`X ⊕ Y ⊕ Z = 0` as implemented is neither: the parity is a derived
value that varies freely, so as a wall it is vacuous and as a check it
would reject every honest derivation. **Resolution adopted here:**

1. The security claim of Section 3 rests on the fold preimage alone.
   Parity is dropped from the threat model.
2. A *designed* state invariant is welcome as a v2 option **only** as a
   certified property: if a future wire tag defines a parity-balanced
   derivation variant, it must ship with (a) a proof or a documented
   rejection-sampling cost, (b) a conformance test vector, and (c) its
   own address-prefix or version byte, so the two derivations are never
   silently confused. Until such a tag exists, no document or code may
   assert the parity condition as a security property.

## 5. Hardware binding: salt, not secret

An earlier formulation required the seed to be deterministically XORed
with a 128-bit motherboard UUID ("Hardware DNA") before derivation.
Assessment and resolution:

- **The SMBIOS UUID is public entropy.** It is readable locally
  (`/sys/class/dmi/id/*` on Linux, SMBIOS/WMI tables on Windows) and is
  structurally guessable (vendor-alphabet, weak entropy in some OEM
  ranges). Any security argument that treats it as a *secret* factor is
  false and must not be made.
- **As a public salt it is legitimate and useful:** it domain-separates
  derivations per machine, defeats precomputed-seed-table attacks (the
  attacker cannot amortize a rainbow-style table across machines), and
  costs nothing. The wall of Section 3 is unchanged by a public salt,
  and the document claims nothing more for it.
- **Backup and migration are the real design constraint.** Binding a
  wallet to one motherboard means a dead machine destroys the wallet.
  Therefore, *before* any wire-format freeze adopts machine binding, the
  protocol must ship a **migration transaction**:

  ```
  migrate_binding(old_salt, new_salt, effective_height):
    a signed statement (WOTS+/XMSS under the current key) attesting that
    the same seed is re-bound from old_salt to new_salt from
    effective_height onward; verifiable by any node that knows both
    salts are well-formed; replay-protected by the existing frame
    journal. The seed — never the machine — remains the root of trust;
    the machine binding is an addressing convenience, revocable by the
    key holder.
  ```

  Failing to design this before freeze is how "hardware binding" turns
  into "permanent loss of funds on hardware failure." This ordering is a
  hard requirement, not a recommendation.

## 6. VX_KDF_ITERS: a slow KDF, not a VDF

The derivation chain opens with a parameterized KDF stretch
(`VX_KDF_ITERS` sponge rounds). Claims, kept deliberately modest:

- It raises the per-seed cost of *bulk* brute force (attacker enumerating
  seeds cheaply and testing them in bulk).
- It is **not a verifiable delay function**: there is no uniqueness or
  proof-of-elapsed-time property, no public randomness beacon, and a
  pipeline of independent ASICs evaluates seeds in parallel at full
  speed. "Sequential and uncheatable" is the standard VDF definition;
  this is merely *slow per evaluation*, which is a different and weaker
  property. Do not cite VDF literature for it.
- Default value trades wallet-open latency against bulk-attack cost;
  wallets may lower it (accepting weaker bulk resistance) and archive
  nodes may raise it. The parameter is advisory and not consensus-
  critical — nothing in the wire format depends on it.

## 7. One chain, one identity

The seed derives everything through a single deterministic chain:

```
seed → KDF stretch → (attractor seed point z_0) → 1000 iterations
     → (X, Y, Z) → address  and  → pubseed (verification-key root
       for WOTS+/XMSS, Section 9)
```

There is no independent second derivation that could fork the identity:
given the seed, address and signature key are both forced; given the
address alone, neither is recoverable. This is checked by the address
and key-derivation test vectors (WHITEPAPER_V6.md Section 16).

## 8. Relation to the signature layer (WOTS+/XMSS)

The address-space argument and the signature-security argument are
independent and must not be merged:

- A successful address preimage yields *an address*, not signing
  capability. The attacker who finds a seed mapping to your address has
  produced a different key pair under the same address; on a chain that
  binds spend authority to the verification key in state (not to the
  address string), such a collision does not authorize spending your
  balance. Address preimage is therefore an impersonation/correlation
  threat and a DoS-on-receive nuisance, not a theft primitive —
  *provided* spend authorization continues to key off the published
  verification key, which is the standing rule.
- Conversely, breaking WOTS+/XMSS (second-preimage work ~2^256 against
  the sponge for the used parameter sets, ~2^128 effective under Grover)
  is a signature-layer break and says nothing about the address wall,
  and vice versa. The two walls should be argued and audited separately.

## 9. Summary of claims

| Claim | Status |
|---|---|
| Seed space 2^2048; address digest 2^256; multiplicity 2^1792 | arithmetic, verified |
| Binding condition = fold preimage `xorFold(X,Y,Z) == digest` | implemented (Section 5, Step 2, WHITEPAPER_V6.md) |
| Wall ≈ 2^256 full-chain evaluations, expensive per trial | generic-preimage argument |
| Parity `X ⊕ Y ⊕ Z = 0` is an invariant | **refuted empirically** (Section 4 probe); dropped from claims |
| Parity as v2 certified invariant | design option, gated on proof + vector + version tag |
| Hardware UUID as secret | rejected; public salt only |
| Machine binding without migration transaction | forbidden before wire freeze |
| VX_KDF_ITERS as VDF | rejected; slow-KDF claim only |
| Fold reads 48 of 384 state bytes | recorded as the priority target for formal cryptanalysis |

## 10. What would change this document

- A demonstrated shortcut from a chosen 48-byte fold window back to a
  seed (would lower the wall below 2^256).
- A certified invariant variant with proof and vectors (would amend
  Section 4.2).
- A wire-format decision on machine binding (would make Section 5's
  migration transaction normative rather than preparatory).

The structural claims above are anchored by
`tests/test_fold_window.cpp` (ctest target `VortexFoldWindowTest`):
it pins the 48-byte window (unsampled bits leave the digest unchanged),
the exact two-byte movement of every sampled-byte flip on all three
trunks, and the fold → base64url → `NFA_V6_` round-trip.
