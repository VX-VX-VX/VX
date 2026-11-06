# CRT seam collision analysis — formal status (P0, 2026-11-06)

Scope: the seed -> identity derivation pipeline (`src/math/galois_attractor.cpp`,
`VortexAttractor::run/step/derive_z0`) and the seam collisions identified in
BACKLOG 2.12(e). This document is the P0 deliverable requested in the
2026-11-05 owner audit: formal condition of occurrence, minimal
counterexample, exact scope of the Conditional Involution Guard, proof that
the Guard does not change results outside its scope, impact on canonical
seeds, cross-platform determinism. Every number below is derived from the
code as of commit 9a1a3f1 and the frozen moduli
(`AttractorModuli::secure_crt()` = active_default()).

**Verdict up front.** The derivation is a many-to-one key-derivation
function by construction. Non-injectivity at every mod-M seam is a
theorem (pigeonhole), not a defect that a local guard can remove: any map
from [0, 2^1024) into [0, M) glues at least DELTA = 2^1024 - M pairs, and
both the current code and the owner's Conditional Involution Guard achieve
exactly that minimum. The Guard does not remove the fold family; it
RELOCATES it (proved below, Theorem 4). The derivation stays frozen; the
practical collision-resistance of identities rests on trajectory preimage
hardness (the same class of guarantee as any hash-based KDF), and the
per-derivation probability of ever touching a fold tail is ~2^-126
(Q-seam dominated - see Theorem 5; this corrects the earlier P-only union
bound of 2^-947 quoted in the v0.0.16 session).

## 1. Seam inventory (exact, code-referenced)

The step dynamics proper (XOR, rotl, masked addition, cube-of-residue
recombination) are bijections or full-range fold-free operations on
Z_2^1024. The non-bijective seams are exactly the mod-M reductions of
full-range 1024-bit inputs:

| Seam | Code | Reduction | Count per 1000-iteration derivation |
|---|---|---|---|
| Z0 cubes | `derive_z0` (galois_attractor.cpp:128) | `pow3_mod(X0, r)`, `pow3_mod(Y0, r)` | 2 (R seam) |
| Cube inputs | `step` (:243-245) | `pow3_mod(arxX, p)`, `pow3_mod(arxY, q)`, `pow3_mod(arxZ, r)` | 3 x 1000 = 3000 |
| AKT III lock | `run` (:321-323) | `((x ^ Phi_lock) * 7 + 13) % p` (and q, r) | 3 |
| **Total full-range reductions** | | | **3005** (1001 x P, 1001 x Q, 1003 x R) |

Note: `(cube_sum) % r` inside `derive_z0` reduces a value < 2r, not a
full-range input; it never folds. `(x + y) & mask1024` in the ARX layer is
an addition wrap (many-to-one in the pair (x, y)), inventoried here for
completeness; it is part of the standard ARX structure, not a mod-M seam.

The address of an identity is `xorFold(x, y, z)` of the FINAL full-range
states (:327) - not of the CRT synthesis output. The CRT reconstruction
`computeCrtUnwrapping` (r_p, r_q, r_r -> crtX) is a separate consumer of
the lock residues. The fold families below therefore matter twice: for the
trajectory states (cube seams) and for the lock residues.

## 2. Theorem 1 (fold measure, pigeonhole lower bound)

Let M be one of the active moduli and let red: [0, 2^1024) -> [0, M) be
`x -> x mod M`. For every a in [0, M) the preimage is {a, a+M, a+2M, ...};
the number of glued pairs is exactly

    DELTA(M) = 2^1024 - M.

For the frozen secure set:

    P = 2^1024 - 2^64 - 1747    ->  DELTA(P) = 2^64 + 1747      (< 2^65)
    Q = 2^1024 - 2^888 - 3943   ->  DELTA(Q) = 2^888 + 3943
    R = 2^1024 - 2^512 - 267799 ->  DELTA(R) = 2^512 + 267799

Every full-range mod-M reduction glues exactly DELTA(M) pairs 2-to-1; no
implementation can do better on a full-range domain, and none can be
forced to do worse without changing the reduction itself.

## 3. Theorem 2 (all-rotations canonical family; owner's O(1) construction)

The owner's constructive non-injectivity proof (audit notes, Part I) is
restated with its precondition made a theorem.

Construction on the P seam, for the lock ((x ^ Phi) * 7 + 13) % P:

1. Take any u in [P, 2^1024); there are exactly DELTA(P) = 2^64 + 1747
   such u, and each has its top 960 bits all equal to 1 (because
   u >= P = 2^1024 - DELTA with DELTA < 2^64).
2. u' = u - P in [0, DELTA) has its top 960 bits all 0.
3. Set x1 = u XOR Phi_lock, x2 = u' XOR Phi_lock.
4. The top 960 bits of x1 are the bitwise complement of the top 960 bits of
   Phi_lock, those of x2 are equal to them. FACT (verified exhaustively
   for all 1024 rotations of PHI_1024): every rotation of PHI_1024 contains
   both a 0 and a 1 among its top 960 bits. Hence both complements and
   copies contain a 0 in the top 960 bits, so x1 < 2^1024 - 2^64 < P and
   x2 < P: BOTH partners are canonical field elements and legitimate
   states.
5. (x1 XOR Phi) = u and (x2 XOR Phi) = u' = u - P are congruent mod P, so
   after (*7+13) % P and the following rotl the two states produce
   identical outputs: Step(x1) == Step(x2).

This is not a probabilistic claim: on every step of every trunk seam of
this shape, exactly DELTA(M) canonical pairs glue 2-to-1. Verified
10/10 on independent instances during the 2026-11-05 session.

Corollary (cross-platform determinism): the construction involves only
XOR, subtraction and the frozen constants; it is bit-exact on any platform
that implements the derivation. No floating point, no signed arithmetic,
no endianness dependence.

## 4. The Conditional Involution Guard: exact scope

Owner's proposed fix (audit notes, Part II.1, verbatim):

```cpp
uint1024_t candidate = x ^ Phi_lock;
uint1024_t mixed = (candidate < P) ? candidate : x;
uint1024_t next_x = (mixed * 7 + 13) % P;
```

**Property G (proved): the Guard is injective on canonical inputs.**
Restrict the domain to [0, P). Define A = {x < P : x XOR Phi < P} and
B = {x < P : x XOR Phi >= P}. The Guard maps A by the XOR involution
(closed on A, since XOR is an involution: (x XOR Phi) XOR Phi = x < P) and
fixes B pointwise. The images A and B are disjoint, and their union is
[0, P); so `mixed` is a bijection of [0, P) onto [0, P), and composed with
the affine map (*7+13) mod P (injective when gcd(7, P) = 1, and P is an
odd prime distinct from 7) it is injective. No two canonical elements
glue. On branch A the Guard merely swaps the roles of the pair (x, x XOR
Phi); on branch B it is the identity; OUTSIDE [0, P) it changes nothing
for canonical partners - i.e. for any x whose XOR-mask candidate is
canonical the Guard's decision is the same as the unguarded code. This is
the requested "Guard does not change results outside its scope" statement,
with the scope made precise: **scope = canonical inputs only**.

**Theorem 4 (Guard relocation; the fold family persists).** The actual
state space of the trajectory is the full range [0, 2^1024), not [0, P).
Define the branch-B set B = {x in [0, 2^1024) : x XOR Phi >= P}; since XOR
is a bijection, |B| = 2^1024 - P = DELTA(P) exactly. For every x_B in B
the Guard passes x_B through unchanged (mixed = x_B), so

    g(x_B) = (x_B * 7 + 13) mod P,

while the partner

    x_A = (x_B mod P) XOR Phi

satisfies x_A XOR Phi = x_B mod P < P, hence the Guard takes branch A for
x_A and

    g(x_A) = ((x_B mod P) * 7 + 13) mod P = (x_B * 7 + 13) mod P = g(x_B).

The pair (x_B, x_A) collides. In the frequent sub-case x_B < P the partner
is x_A = x_B XOR Phi - a tail state in [P, 2^1024): the Guard reassigns
each canonical state's glued partner from the old family member to the
tail state itself. Concretely, for u in [P, 2^1024) with u XOR Phi < P
(both canonical by Theorem 2's fact): the UNGUARDED code collides
(u XOR Phi) with ((u - P) XOR Phi); the GUARD collides (u XOR Phi) with u,
and the original pair no longer collides (both its members are canonical
and the Guard is injective there). Verified 20/20 on independent
instances, including the negative check guard(x1) != guard(x2).
What the Guard destroys is the ORIGINAL canonical family (u, u - P) of
Theorem 2; what it creates is the relocated family above. Pigeonhole
forbids anything else. **A guard cannot remove the fold; it can only
choose which pairs carry it.**

## 5. Theorem 5 (per-derivation fold-tail probability; corrected accounting)

Define a "tail hit" as a full-range reduction whose input lands in the
fold zone [M, 2^1024) - the only inputs where the 2-to-1 gluing can be
exercised at all. For a uniformly random trajectory state the probability
per reduction is DELTA(M) / 2^1024:

    P seam: (2^64 + 1747)  / 2^1024 < 2^-959
    Q seam: (2^888 + 3943) / 2^1024 ~ 2^-136
    R seam: (2^512 + 267799)/ 2^1024 ~ 2^-512

Counting all 3005 full-range reductions of one derivation (Theorem 1
inventory) and applying the union bound:

    P trunk: 1001 reductions -> < 2^-950
    Q trunk: 1001 reductions -> ~ 2^-126   (dominates)
    R trunk: 1003 reductions -> ~ 2^-502
    TOTAL:                     < 2^-126

**This corrects the v0.0.16 session figure.** The earlier union bound of
2^-947 applied the P-seam delta to all reductions; the honest total is
Q-seam dominated and equals ~2^-126 per derivation. For calibration this
is the same order as the 2^-128 birthday bound of the 256-bit address
fold itself, and it is an EXPOSURE bound (probability that a derivation
ever visits a state where the local map is non-injective), not a collision
rate: converting a tail visit into an actual two-seed collision requires
realizing the partner trajectory, i.e. inverting ~1000 ARX+sponge rounds
backward to a second valid seed - no method for this is known.

Empirical cross-check (2026-11-05/06 runs): 12 seeds x 1000 iterations,
36036 reductions observed, 0 tail hits - consistent with the bound
(expected tail hits ~2^-123).

## 6. Consequences and decision

1. **The derivation is a many-to-one KDF.** This is not a defect to patch;
   it is the same trust basis as every hash-based identity scheme. The
   fold is intrinsic to reduction (Theorem 1) and the pigeonhole minimum
   is achieved.
2. **No derivation change.** The frozen derivation and the pinned genesis
   stay. This matches the owner's ratified decision to freeze rather than
   rush the Guard.
3. **The Guard is documented as a CANDIDATE, not adopted.** Its real
   property (Theorem G: injective on canonical inputs) would only become
   relevant together with a canonical-state derivation redesign, which
   would change the frozen vectors - it requires the genesis migration
   protocol (BACKLOG 2.15/P1) and byte-identical before/after comparison
   of all 3072 bits and every derived address. Not scheduled.
4. **The honest residual risk statement** for identities: seed-collision
   resistance rests on (a) the 256-bit address fold (birthday ~2^-128 per
   pair), and (b) trajectory preimage hardness; the fold-tail exposure
   adds ~2^-126 per derivation of "non-injectivity exposure" that has no
   known exploitation path from seeds.
5. The classic moduli set (all three composite) is a test fixture only
   (v0.0.16); every bound above is stated for the secure set.

## 7. Theorem 6 (no multiplicative fold; the additive family is the only one)

Attack hypothesis tested 2026-11-06 (owner directive: invent attacks, do
not stop at "no known method"). If 3 divided M-1, the cube map
x -> x^3 mod M would be 3-to-1: there would exist a nontrivial cube root
of unity zeta with v and v*zeta reducing to identical cube inputs - a
collision family INDEPENDENT of the additive DELTA seam, and one that no
amount of canonicalization could remove because it lives inside the
field, not in the tail.

Refuted on the frozen set: every modulus satisfies M = 2 (mod 3), i.e.
3 does not divide M-1 (P-1 = 1 mod 3, Q-1 = 1 mod 3, R-1 = 1 mod 3).
The cube map is therefore a BIJECTION on each of Z_P, Z_Q, Z_R: the
unique cube root is x^(3^-1 mod (M-1)) mod M. Brute-force confirmation:
30,000 random full-range 1024-bit v per modulus, 0 non-additive cube
collisions; additive gluing (v, v+M) confirmed for all three.

This CORRECTS the earlier note (BACKLOG 2.10) claiming "the cube map is
3-to-1 (3 | r-1)" - a confusion of v2(R-1) = 3 (meaning 8 | R-1) with
divisibility by 3. Consequence: the additive DELTA families of
Theorem 1 are the complete collision structure of every reduction seam;
there is no second, field-internal family.

Corollary used below: because cubing is a bijection, the cube-ROOT map
is efficiently computable (exponent 3^-1 mod (M-1)), which is what makes
the constructions of section 8 exact rather than merely existential.

## 8. Constructive fold entry at step 1 (attack experiment; merge is the wall)

The 2^-136 rarity of the Q-seam tail is a probability over RANDOM seeds.
It is NOT a defense against a deliberate constructor. Two exact
inversions, both enabled by Theorem 6, build seeds that LAND in the fold
zone on purpose:

1. **Z0 steering.** For any chosen Y0, the map
   X0 -> derive_z0(X0, Y0) = ((X0^3 mod r + Y0^3 mod r) mod r) XOR
   rotl1024(PHI, Y0 mod 64) is a bijection in the X0 residue. Given any
   desired Z0, X0 = ((Z0 XOR rotl1024(PHI, Y0 mod 64)) - Y0^3)^d mod r
   with d = 3^-1 mod (r-1) reproduces it exactly. (The same inversion
   solves the previously "queued exercise" of BACKLOG 2.10: zero-Z0
   seeds are CLOSED-FORM constructible - X0 = (rotl1024(PHI, Y0 mod 64)
   - Y0^3)^d mod r gives derive_z0 == 0. The surface refusal of that
   class stays; the degeneracy suite now pins a positive instance.)
2. **arxY placement.** With Z0 chosen freely, the step-1 arxY layer
   arxY = rotl1024((Y0 + Z0) mod 2^1024, Z0 mod 64) XOR Z0 inverts
   algebraically: Y0 = rotr1024(arxY XOR Z0, Z0 mod 64) - Z0 mod 2^1024.

Combining both, an attacker constructs TWO distinct seeds A, B whose
step-1 arxY values are an exact additive fold pair, arxY_B = arxY_A + Q
(w < 2^1024 - Q), so cubeY_A == cubeY_B identically - pinned in
`VortexCrtSeamTheoremsTest` (T7). Fold entry is FREE.

What saves the derivation is the MERGE wall. A full state merge at the
step-1 output requires all three of

    rotl(x_A, 13) XOR cubeY_A XOR phi_tA = rotl(x_B, 13) XOR cubeY_B XOR phi_tB
    rotl(y_A, 29) XOR cubeZ_A XOR phi_tA = rotl(y_B, 29) XOR cubeZ_B XOR phi_tB
    rotl(z_A, 43) XOR cubeX_A XOR phi_tA = rotl(z_B, 43) XOR cubeX_B XOR phi_tB

and the lossless rotation paths carry the state difference forward:
the constructed pair diverges in all three coordinates (verified in T7).
One cheap sub-case is CLOSED by the same bijectivity: if the rotations
classes matched (Y0_A mod 64 == Y0_B mod 64) and X0_A == X0_B were
forced, the Z0 equation would give Y0_A^3 == Y0_B^3 mod r, hence
Y0_A == Y0_B - the trivial seed. Literature calibration (2026-11-06 web
survey, owner-requested): the ARX cryptanalysis toolbox DOES contain
solvers for mixed XOR/rotation/addition equation systems - S-systems
solved bit-by-bit from the LSB (Leurent, ASIACRYPT 2012), differential
trails joined meet-in-the-middle (ARX Toolkit; hashclash, the SHA-1
tooling), used against MD5/SHA-1/HAVAL/Tiger/BMW. None of that covers
the cube-mod-prime layer: every known technique propagates LINEAR-ish
XOR/additive differentials through ARX rounds, while the cube map over
a prime field has no differentials except the additive DELTA seam
itself (Theorem 6 - bijective, no zeta family). So the honest statement
is narrower than "no known technique": a full merge must route a state
difference THROUGH the seam fold while simultaneously satisfying all
three output equations - an instance the published ARX tooling does not
handle, but not a class proven impossible. A dedicated solver for
XOR/addition conditions joined across a mod-M fold is the named open
problem, and meet-in-the-middle over the remaining freedom is
~2^1536 per seam. Threat-model summary: entry into the fold zone is
constructible at will; exiting it (merging two trajectories into one
state) remains preimage-hard, and converting a state collision into a
seed collision additionally requires inverting ~1000 ARX+sponge rounds
(section 5).

## 9. Verification status

- Owner's O(1) construction: verified 10/10 (2026-11-05 session).
- All-1024-rotations canonical property (Theorem 2 fact): verified
  exhaustively, 1024/1024 rotations.
- Theorem 4 relocation: verified 20/20 (2026-11-05/06).
- Fold-tail trajectory scan: 12 seeds, 36036 reductions, 0 tail hits.
- Deterministic test pinning of Theorems 1/2/4 and the rotation fact:
  `tests/test_crt_seam_theorems.cpp` (this release).
- Theorem 6 bijectivity (3 does not divide M-1 for P, Q, R; inversion
  round trip; 90,000-sample non-additive collision hunt, 0 hits) and
  Theorem 7 constructive fold pair (exact arxY placement, identical
  step-1 cubeY, divergence at the step output, zero-Z0 positive
  instance): pinned in the same suite and in
  `test_attractor_degeneracy` (2026-11-06).
- Merge-wall claim calibrated against the published ARX-cryptanalysis
  literature (S-systems / Leurent 2012, ARX Toolkit, hashclash): those
  solvers cover XOR/additive differential systems but not a mod-M fold
  nonlinearity; the open problem is now NAMED rather than waved off
  (section 8, 2026-11-06).
