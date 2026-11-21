#pragma once

// Timelocks — Phase F (0.2.5): TLMK / MSRK / EK-streaming.
//
// Three spend-window mechanisms over CONSENSUS HEIGHT (not wall time —
// the height is the transition condition, the client never owns it):
//
//  TLMK — Timelock Key: unlocks at height H; the spend burns the single
//    leaf (one-shot accounting, same discipline as PqLeafLedger).
//  MSRK — Multi-Step Release Key: a payout schedule of n steps, each
//    with its own height threshold and basis-point fraction; a step
//    applies WHOLE (undo-safe) or not at all — no partial effects
//    (SEC-C4 RUP-analog REVERT discipline).
//  EK  — Streaming channel: partial charges with window boundaries;
//    a boundary breach FAULTs the channel — funds are MUTE, never
//    vanish (settlement frozen until an undo-safe exit).
//
// This is the PURE layer: the state machines and their invariants. The
// ledger wiring (undo records, apply_block integration) is a later
// normative step.

#include <array>
#include <cstdint>
#include <vector>

namespace vx::consensus::timelock {

// ── TLMK ────────────────────────────────────────────────────────────────────

/// A one-shot timelock key: unlocked at target_height, spent once.
struct Tlmk {
    uint64_t target_height = 0;
    std::array<uint8_t, 32> commitment{}; // sponge-commitment of the secret
    bool spent = false;                   // one-shot: the leaf burns
};

/// The unlock gate: height is the transition condition (NORMATIVE).
bool tlmk_unlocked(const Tlmk &k, uint64_t current_height) noexcept;

/// The spend: burns the leaf. Returns false (and changes NOTHING) if the
/// key is still locked or already spent — one-shot is enforced here.
bool tlmk_spend(Tlmk &k, uint64_t current_height) noexcept;

// ── MSRK ────────────────────────────────────────────────────────────────────

inline constexpr uint32_t kFractionDenominator = 10000; // basis points

/// One payout step: unlocks at_height, pays fraction_bps of total.
struct MsrkStep {
    uint64_t at_height = 0;
    uint32_t fraction_bps = 0; // of total, in basis points (≤10000)
};

/// The multi-step release key: a payout schedule. Steps must be sorted
/// by at_height (canonical order) and sum ≤ 10000 bps of total.
struct Msrk {
    uint64_t total = 0;
    std::vector<MsrkStep> steps;
    uint64_t spent_so_far = 0;
};

/// Validates the schedule invariants: non-empty, strictly ascending
/// heights, fractions sum ≤ 10000 bps. Called before any state mutation.
bool msrk_validate(const Msrk &m) noexcept;

/// The amount due at current_height: the sum of fractions of steps whose
/// at_height has passed, minus what has already been spent. Pure
/// computation, no state change.
uint64_t msrk_due(const Msrk &m, uint64_t current_height) noexcept;

/// Claims the amount due: applies WHOLE (spent_so_far jumps by the exact
/// due amount) or not at all. Returns false (changes NOTHING) if the
/// schedule is invalid or nothing is due.
bool msrk_claim(Msrk &m, uint64_t current_height) noexcept;

// ── EK — streaming channel ─────────────────────────────────────────────────

/// The streaming channel: partial charges bounded by a window budget.
/// A breach FAULTs the channel — funds are MUTE (frozen), never vanish.
struct EKChannel {
    uint64_t capacity = 0;      // total funded amount
    uint64_t charged = 0;       // total charged so far
    uint64_t window_budget = 0; // max spend per window
    uint64_t window_used = 0;   // spend inside the current window
    uint64_t window_start = 0;  // first height of the current window
    uint32_t window_len = 0;    // window length in heights
    bool faulted = false;       // FAULT: funds frozen (MUTE)
};

/// Validates the channel config: non-zero capacity, non-zero window,
/// budget ≤ capacity. Rejects degenerate configs (zero frequency, zero
/// boundary) — fail-closed at construction.
bool ek_validate(const EKChannel &c) noexcept;

/// A partial charge: applies whole or not at all. A window rollover
/// (current_height >= window_start + window_len) resets window_used.
/// A charge that would breach the window budget or the capacity FAULTs
/// the channel — the funds are MUTE, nothing is charged.
enum class EkResult {
    kOk,      // charged
    kFault,   // boundary breach: channel FAULTed, funds frozen
    kFaulted, // channel was already FAULTed (MUTE)
};
EkResult ek_charge(EKChannel &c, uint64_t amount, uint64_t current_height) noexcept;

/// The undo-safe exit: after a FAULT the settlement is frozen until an
/// exit is ratified. The exit returns ALL remaining funds
/// (capacity - charged) to the sender — the whole remainder, atomically,
/// never a partial amount.
uint64_t ek_exit_frozen(const EKChannel &c) noexcept;

} // namespace vx::consensus::timelock
