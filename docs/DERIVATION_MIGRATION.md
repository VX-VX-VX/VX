# Derivation migration protocol

Status: RATIFIED as process (2026-11-06). Machinery implemented and
pinned this session; first real customer is the address-format v2
remedy for the palindromic xor-fold defect (BACKLOG 2.17,
docs/ADDRESS_SECURITY.md correction section).

## The rule

The seed-to-address derivation (VortexAttractor: ACT I-IV, the ARX
step map, the AKT III lock, the fold) is FROZEN at
`VortexAttractor::DERIVATION_VERSION = 1`. Any change to it - including
the Conditional Involution Guard candidate or an address-format v2 -
is a VERSIONED MIGRATION, never a silent edit.

## Procedure (all steps mandatory, in order)

1. **Bump the version marker.** `VortexAttractor::DERIVATION_VERSION`
   moves 1 -> 2 in the same commit as the derivation change. A node
   that cannot state its derivation version does not ship.
2. **Pin the OLD vectors.** Version-1 reference vectors are pinned in
   `tests/test_derivation_migration.cpp` (4 vectors: the canonical seed
   unlocked AND locked orientations, plus two 8-hex-char variants -
   full 3072-bit final states and both derived addresses per vector).
   They must not move while version 1 exists.
3. **Regenerate the NEW vectors.** `VX_DUMP_DERIVATION_VECTORS=1
   ./test_derivation_migration` prints the vectors of the running
   build; capture them as the version-2 pin set.
4. **Diff everything.** Label-by-label comparison of ALL 3072 bits
   (final x, y, z) and every derived address (NFA and OFA) between the
   version-1 and version-2 sets. The comparator and its single-bit
   mutation detection are pinned in the same suite. If ANY bit or any
   address is identical between versions where a change was intended,
   or differs where none was intended, STOP and analyze before
   proceeding.
5. **Fail-closed compatibility.** Nodes refuse identity material
   (addresses, signatures bound to addresses, genesis/ledger frames
   carrying version-1 identities) derived under a foreign derivation
   version. No silent interop, no automatic translation. Old nodes keep
   verifying the version-1 chain they were built for; new nodes either
   run a migration window (dual verification, explicit operator
   choice) or start a new chain - both are owner decisions recorded in
   the BACKLOG entry of the change, never defaults.
6. **Documentation moves with the code.** docs/ADDRESS_SECURITY.md,
   docs/CRT_COLLISION_ANALYSIS.md and README claims are updated in the
   same commit; superseded figures stay only as dated corrections.

## Why this exists

- The derivation was nearly changed twice by good arguments (the
  Involution Guard, the classic->secure moduli switch) and both times
  the freeze is what made the analysis - not the change - the outcome.
- A KDF whose outputs are consensus-critical identity roots cannot
  have an "invisible improvement" category: byte-differences are
  fork differences.
