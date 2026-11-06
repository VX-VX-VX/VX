# Address formats: Bitcoin landscape and the VX generation-2 format (VX2)

Status: DESIGN + PRIMITIVE (2026-11-06, owner directive: "make new address
formats, better than Bitcoin's; study Bitcoin's address types first").
The primitive lives in `include/vx/math/address_v2.hpp` with contract tests
in `tests/test_address_v2.cpp`. NOT wired into consensus or the frozen v1
wire - adoption goes through the genesis migration protocol
(docs/DERIVATION_MIGRATION.md), bundled with the address-v2 fold (BACKLOG
2.17 remedy).

## 1. Bitcoin's address types (the landscape)

| Format | Era | Encoding | Payload | Checksum | Length |
|---|---|---|---|---|---|
| P2PKH (`1...`) | 2009 | Base58Check | HASH160, 160 bits | 32-bit double-SHA-256; NO error-detection guarantee, no error location | 26-35 |
| P2SH (`3...`) | 2012 (BIP 16) | Base58Check | HASH160 of redeem script | same 32-bit | 26-35 |
| SegWit v0 (`bc1q...`) | 2017 (BIP 173) | Bech32 | 160/256-bit witness program | 6-symbol BCH over GF(32): guaranteed detection of up to 4 substitutions; insertion/deletion weakness (q-before-p, ~2^-10) | 14-74 |
| Taproot (`bc1p...`) | 2021 (BIP 350) | Bech32m | x-only pubkey, 256 bits | Bech32m: up to 4 substitutions guaranteed; non-substitution patterns ~2^-30 | 62 |
| Silent Payments (`sp1...`) | 2024 (BIP 352) | Bech32m | 66 bytes (scan+spend keys) | Bech32m | >= 117 |
| CashAddr (BCH chain) | 2017 | Base32 | 160-512 bits, size bits in version byte | 40-bit BCH over GF(32): up to 6 errors guaranteed, bursts of 8 | ~50-65 |

Key weaknesses observed across the landscape:

1. **Base58Check**: 32-bit checksum (~2^-32 residual), no guarantee, no
   error location, and a MIXED-CASE alphabet - `S` vs `s` is a live
   lookalike-attack surface.
2. **Bech32**: the q-before-p insertion weakness (BIP 350 fixed it by
   changing one constant, not structurally); only 4-substitution
   guarantee; 90-char limit forces silent payments into 117+ chars.
3. **EIP-55 (Ethereum, for contrast)**: case-derived bits, ~1-in-a-million
   protection, not a checksum at all.
4. **Silent Payments**: 117 characters make raw copy-paste unusable; the
   ecosystem routes around it with NIP-05/BIP-353 name resolution - the
   format itself is the problem.
5. **No format binds display width to wire width**: what you see is all
   there is (160 or 256 bits).

## 2. The VX v1 baseline (for honesty)

- base64url body, CASE-SENSITIVE (mixed-case transcription hazard);
- 31-byte payload = 2^128 effective digest space after the palindromic
  xor-fold defect (BACKLOG 2.17): birthday ~2^64, preimage ~2^128;
- visually fingerprintable - the (b, swapnib(b)) structure shows through
  the body;
- NFA and OFA share the IDENTICAL body (BACKLOG 2.18 side finding) -
  both address types of one identity are trivially linkable;
- hand-rolled XOR fold reads only the top 128 bits of each trunk.

## 3. VX2: the generation-2 format

Design goals, each answering a named weakness above: strictly stronger
checksum than Bitcoin, structurally insertion/deletion-proof,
single-case alphabet, >= taproot address space, domain-separated address
types, no fingerprintable structure, and the full 1024-bit sponge digest
available for wire binding.

### 3.1 Digest

    digest = VortexSponge1024( tag || X || Y || Z )
      tag  = "VX_ADDR_V2_NFA_V1"  (NFA)  /  "VX_ADDR_V2_OFA_V1"  (OFA)
      X, Y, Z = the 1024-bit final trunks, big-endian, 384 bytes total

- Domain separation PER ADDRESS TYPE: NFA and OFA digests are unrelated
  by construction (fixes the 2.18 linkability defect).
- The fold runs over ALL 3072 bits of the final state (fixes the 2.17
  narrow-window defect; the sponge is length-encoded, the tag fixes the
  input framing).
- Digest = 128 bytes (1024 bits). Classical preimage ~2^1024, Grover
  ~2^512; collision floor ~2^512.

### 3.2 Wire vs display: the two-layer payload

- **Core** (32 bytes = 256 bits): digest bytes 0..31. The collision-
  resistant account identifier, displayed.
- **Span** (5 bytes = 40 bits): digest bytes 32..36. Binds the display to
  the full digest: two accounts that collide on the core are separated by
  2^40 of span work, and the on-chain resolver (when the v2 wire lands)
  verifies core+span against the full 1024-bit digest - a truncated-
  display substitution attack must break core AND span.
- **Reserved** (91 bytes = 728 bits): the rest of the digest; never
  displayed, available to the wire.

Displayed entropy: 2^296 (birthday ~2^148) - strictly above taproot's
2^256. DECISION recorded: a full 1024-bit display (205 base32 chars +
checksum) was rejected as unusable - it repeats the silent-payments
mistake; the core+span layering keeps the display at human scale while
nothing on the consensus path depends on the display width.

### 3.3 Encoding

    vx2 <version> <core:52 symbols> <span:8 symbols> <checksum:27 symbols>
    total 91 characters

- **Alphabet**: the VX-OWN single-case charset
  `23456789-abcdefghjkmnpqrstuvwxyz` (value = index): 8 digits (2-9),
  23 letters (a-z minus the lookalikes `i l o`) and `-`. SINGLE CASE
  (transcription-safe); `o`/`O`, `l`/`I`/`1`, `i` typed by a misreading
  human are INVALID characters and are rejected, not misread
  (fail-closed). All-lowercase (canonical) or all-uppercase (QR
  efficiency) accepted; MIXED case rejected (mixed case can encode a
  hidden channel).
- **Version symbol** (5 bits): NFA = 3 (displays `vx25...`), OFA = 4
  (displays `vx26...`); every other value is reserved and fails closed.
- **Length binding is structural**: the total length is fixed at 91 AND
  the fixed length is itself checksummed (the version symbol sits
  inside the checksummed stream). Any insertion or deletion changes the
  length and is rejected deterministically - this kills the entire
  insertion/deletion class that bech32m only patched with a constant
  tweak.
- **Checksum**: the VX-OWN 135-bit BCH code, computed from field theory
  (nothing verbatim from any published spec):
  - field GF(2^9) = GF(2)[x]/(x^9 + x^4 + 1);
  - root alpha = x, ORDER 511 = 2^9 - 1 (primitive); the checksummed
    stream is 92 symbols = 460 bits and 460 < 511, so the bit exponents
    are DISTINCT mod ord(alpha) and the Vandermonde/BCH argument is
    valid - the code is a shortened cyclic code of length 511 over
    GF(2);
  - generator g(x) = product of the minimal polynomials of
    alpha^1,3,5,7,9,11,13,15,17,19,21,23,25,27,29 =
    0x93bc9c6a8f56b4973961ccc8e4411bb683 (degree 135 = exactly 27
    symbols); its roots cover alpha^1..alpha^30 CONSECUTIVELY;
  - convention: polymod over ALL checksummed symbols (prefix, version,
    payload AND the 27 checksum symbols) must equal the init constant
    (the bech32 fixed-target convention), so the undetected-error set
    is exactly {E : g | E};
  - init constant 0x9e3779b97f4a7c15 - the Golden Phi constant (the
    same constant that seeds every sponge state word 0), zero-extended
    to the 135-bit register.

  Provable guarantees: EVERY error of weight <= 30 BITS detected (=
  every substitution of <= 6 whole characters - bech32m guarantees 4,
  cashaddr 6 at ~2^-40 residual); every burst of <= 26 consecutive
  characters detected; ~2^-135 residual for random heavier errors
  (bech32m: ~2^-30). Empirical confirmation of the implementation:
  zero weight-2 holes (2852 single-character error residues, no
  collisions), exhaustive bit weight <= 2 clean over all 460 positions,
  0/30000 sampled bit weight 3..30 undetected.
- **Design history (honesty record)**: two earlier checksum drafts were
  found broken by our own adversarial testing BEFORE commit and were
  redesigned, not patched: (1) an order-31 alpha, where the BCH bound
  is void (the bound needs ord(alpha) above the code length); (2) an
  order-93 alpha, where exponents reach 404 > 93 and alias
  x^(a+93k) == x^a mod g - 1794 undetected weight-2 pairs were found
  empirically. The order-511 design is the first with a VALID bound at
  this code length.
- **Padding pin**: 60 payload symbols = 296 real bits + 4 zero pad bits
  at the END of the stream; the padding is checked on decode
  (fail-closed).

### 3.4 What "better than Bitcoin" concretely means here

| Property | Taproot (best of Bitcoin) | VX2 |
|---|---|---|
| Displayed address space | 2^256 | 2^296 (core 2^256 + span 2^40) |
| Wire-bindable space | 2^256 | 2^1024 (full sponge digest) |
| Checksum guarantee | <= 4 substitutions, ~2^-30 residual | <= 6 substitutions, ~2^-135 residual |
| Burst detection | 8 | 26 |
| Insertion/deletion | patched per-constant (bech32m) | structurally rejected (fixed length, length inside the checksummed stream) |
| Case handling | single case | single case; mixed case rejected; lookalike chars invalid (fail-closed) |
| Alphabet ownership | bech32 charset | VX-OWN charset, field, generator, constants |
| Address-type separation | witness version | domain-separated folds (NFA/OFA digests unrelated) |
| Fingerprintability | none | none (sponge output; v1's palindromic structure is gone) |
| Length | 62 | 91 (the cost of the span + the 6-substitution / 2^-135 checksum) |

Honest limits: 91 > 62 characters (the price of the 40-bit span binding
and the strongest checksum in the landscape); the 6-substitution
guarantee covers whole-symbol substitutions - heavier random damage is
caught with probability 1 - 2^-135, not certainty; Grover on the
256-bit core is 2^128 (same as taproot - the core is NOT
post-quantum-proof, the 1024-bit wire digest is); the v2 wire binding
is not yet defined and adoption waits for the migration protocol.

## 4. Implementation and pins

- `include/vx/math/address_v2.hpp` - `VortexAddressV2`: `derive()`
  (digest via VortexSponge1024, core+span extraction), `encode()`
  (lowercase canonical), `decode()` (fail-closed: length, charset, case
  rule, checksum, reserved-version and padding checks).
- `tests/test_address_v2.cpp` - contract suite: the checksum CODE is
  pinned (the C++ polymod evaluation must equal the independent
  field-theory computation: z, v and the 27 emitted symbols for a fixed
  probe stream), KAT addresses derived from the pinned version-1
  derivation vectors, round-trip, mixed-case rejection,
  reserved-version fail-closed, padding pin, insertion/deletion
  rejection, single substitutions exhaustive and double substitutions
  over every position pair (both pin the implementation to the BCH
  theorem), NFA/OFA domain separation, and a structural no-palindrome
  check (v2 must not reproduce the 2.17 defect).

## 5. Sources

- Unchained, "Bitcoin Address Types Compared" -
  https://www.unchained.com/blog/bitcoin-address-types-compared
- BIP 350 (Bech32m) - https://bitcoin.org/bip/350/
- Bitcoin Optech on Bech32(m) - https://bitcoinops.org/en/topics/bech32/
- BIP 352 (Silent Payments) - https://bitcoin.org/bip/352/
- bitcoin.design guide, Silent Payments UX -
  https://bitcoin.design/guide/how-it-works/silent-payments/
- CashAddr spec (checksum constants, version byte, guarantees) -
  https://documentation.cash/protocol/blockchain/encoding/cashaddr.html
- BIP 173 (Bech32) - https://github.com/bitcoin/bips/blob/master/bip-0173.mediawiki
