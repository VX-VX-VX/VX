# VX Tokenomics — Emission and Fee Law (spec)

Status: NORMATIVE for the parameters it pins; the fee-market section is
partly OPEN (marked per paragraph). Sources of truth:
`include/vx/blockchain/emission.hpp` (constants), the emission gate in
`LedgerState::apply_block` (include/vx/state/ledger_state.hpp), the
mempool admission/ranking code (src/state/mempool.cpp), and the TDI
density filter (include/vx/math/tdi_filter.hpp). Where this document and
the code disagree, the code wins and this file is a bug — file it.

Owner-directed 2026-11-03 (schedule) and 2026-11-11 (this spec).

## 1. Units

- 1 VX = 10^8 atoms (`ATOMS_PER_VX`). One atom = 0.00000001 VX is the
  smallest unit users handle, by design; every ledger amount, fee and
  supply figure below is in atoms unless suffixed `_VX`.
- All supply accounting is 128-bit (`U128`); the exact total-supply sum
  is overflow-checked (`exact_total_supply`), never the u64-saturating
  sentinel.

## 2. Supply law

- **Hard lifetime cap: 7,000,000,000 VX = 7e17 atoms**
  (`MAX_SUPPLY_VX`, `max_supply_atoms()`). The 7 is the protocol's
  signature digit; the cap is a consensus constant, not a parameter: no
  height, no vote, no soft fork of emission.hpp can issue the
  7,000,000,001st VX.
- **ISSUANCE** (the capped quantity) per block = (GENESIS_*/MINER_
  coinbase credits) MINUS the fee share re-credited to the producer.
  Fee re-credits are redistribution of value that already left the
  senders — not new money. Genesis allocations count against the cap,
  so near the end the CAP — not the tier table — determines the last
  partial rewards, and after it nothing new is issued.
- **Enforcement points** (all fail-closed, before any state mutation):
  1. per-block entitlement gate — every coinbase together may mint at
     most `schedule_reward + miner_fee_share` for THIS block; overage
     refuses the block;
  2. cumulative gate — `issued_supply_ + block_issuance <= cap`;
     violation refuses the block. `issued_supply_` is restored by the
     reorg undo vector (a discarded block's issuance never happened).
- **Reporting**: `/api/status` exposes `max_supply_vx`,
  `issued_supply_atomics`, `issuance_headroom_vx`, `block_reward_base_vx`,
  `block_reward_max_vx`, `reward_tier_count`.
- Regressions: `EmissionRewardTiersAndCap`, `CoinbaseEntitlementEnforced`,
  `SupplyCapHardStopsIssuance`, `RewardIndependentOfHeight`.

## 3. Block reward law (PoGW hash tiers)

The per-block subsidy is a pure function of the block's own PoGW hash —
the VortexSponge256 commitment over the full 64 KiB frame, the SAME hash
the intake work gate already computes:

| leading zero bits of the block hash | reward | ~frequency      |
|-------------------------------------|--------|-----------------|
| any valid block (>= network target) |  50 VX | every block     |
| >= 20                               |  75 VX | ~1 in 1e6       |
| >= 24                               | 100 VX | ~1 in 1.67e7    |
| >= 28                               | 200 VX | ~1 in 2.68e8    |
| >= 32                               | 400 VX | ~1 in 4.3e9     |
| >= 40                               | 1000 VX| ~1 in 1.1e12    |

Properties that make this a consensus rule and not a policy:

- **Unforgeable bonus**: a miner cannot mint a bigger reward, only FIND a
  rarer hash — strictly more PoGW work for the block it wanted to seal
  anyway.
- **Absolute thresholds**: verification is recounting leading zeros of a
  hash every node already computes; no difficulty estimate enters
  consensus accounting. (`leading_zero_bits` — big-endian bit order.)
- **Floor coupling to security**: emission accelerates only when network
  difficulty grows past a tier threshold; the cap bounds the total
  regardless. At the 50 VX floor the cap closes after ~140 million
  blocks (~22 years at the 5-second target); every bonus tier only
  stretches that.

## 4. Fee law

- Every non-coinbase transaction pays `fee` (u32 LE field, atoms) on top
  of its amount; the sender's cumulative debit is `amount + fee`.
- **Split**: `burned = total_fees / 2` (floor), `producer_share =
  total_fees - burned` (ceil — odd division rounds TO the producer; the
  single-atom bias is deliberate: fees must not silently multiply the
  burn during heavy spam). This block's split is reported in the apply
  result (`fees_burned`, `fees_miner_reward`).
- **Burned fees leave circulation permanently** (they are subtracted
  from the balance sum and credited to no one); the producer's share is
  a re-credit the producer's coinbase MAY claim — a coinbase minting
  less than the full share simply issues less, the difference is
  forever unclaimed (issuance is computed from what the coinbase
  actually credits, capped by the entitlement).
- **In-block identity** (apply-integrity guard): `post_supply ==
  pre_supply - total_fees + coinbase_mints`. Fees never re-enter the
  balance sum inside the same block. The pre-check loop guarantees each
  sender's cumulative debits fit real balances, so the identity cannot
  underflow — a violation is an integrity signal, not a normal refusal.
- Coinbase transactions pay no fee.

## 5. Fee market — CURRENT state (honest)

- **Mempool ranking**: priority = fee / entropy-cost (fee density over
  the transaction's entropy footprint). Under pressure the pool evicts
  the weakest SUFFIX of the overstayed sender (lowest fee density,
  oldest tie-break) and otherwise evicts the globally weakest entry
  only when the candidate outranks it — the fee market must not churn
  the pool for work it ranks below.
- **TDI density filter** (DoS/dust gate, `TdiFilter::evaluate`): a
  transfer is annihilated when `amount_VX / size_bytes * 10000 <
  1.0` (i.e. < 0.0001 VX per byte), when the payload exceeds the
  100 KB standard-mempool limit, or when the amount is non-positive.
- **NOT yet implemented — OPEN (BACKLOG 2.5)**: (a) a minimum RELAY fee
  (today a zero-fee transfer is admitted if it clears the density
  filter and balances); (b) explicit dust-amount thresholds (density is
  a proxy, not a floor on the amount itself); (c) the reward-pressure
  vs. spam-economics SIMULATION the BACKLOG calls for. Analytic note
  for (c): with a 50/50 split and producer-biased rounding, spam that
  pays fee F transfers F/2 permanently out of the spammers' side
  (burned) at zero benefit to any user, while the producer earns F/2 —
  so sustained spam is a value transfer from spammers to producers plus
  deflation; the attack surface that remains is mempool CAPACITY
  (bounded by eviction) and state growth, not fee leakage. Simulation
  to confirm the eviction dynamics under adversarial churn is still
  owed before beta.

## 6. Parameter placement

- **Consensus-frozen constants** (emission.hpp, change = hard fork):
  `MAX_SUPPLY_VX`, `ATOMS_PER_VX`, `BLOCK_REWARD_BASE_VX`,
  `BLOCK_REWARD_MAX_VX`, `REWARD_TIER_ZEROS[]`, `REWARD_TIER_VX[]`.
- **Genesis config** (remaining parameters land here per BACKLOG 2.5
  acceptance — NOT scattered node constants): genesis allocations and
  their bound receivers; the per-block target for dev/testnet modes.
- **Node policy** (not consensus; may differ between nodes without a
  fork): TDI `MIN_THRESHOLD` and `MAX_SIZE_BYTES`, mempool capacity and
  eviction parameters, the fee-density ranking weights. A node that
  rejects more than consensus requires only fragments its own
  connectivity — it can never fragment consensus.

## 7. Testnet caveat

Genesis #1 credits 2,540,000 VX and GENESIS_2 credits 100,000 VX
(shape-bound, pinned receiver); both count against the cap. GENESIS_2's
demo spender key is PUBLIC (accepted testnet-only; mainnet requires an
unpublished receiver before genesis freeze — BACKLOG 0.14 P1/0.18).
