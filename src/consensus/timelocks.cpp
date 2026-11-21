// Timelocks — Phase F (0.2.5): implementation of the pure layer.
//
// Discipline notes:
//  - Every mutation is whole-or-nothing: a refused claim/charge changes
//    NO state (SEC-C4 RUP-analog REVERT discipline — zero partial
//    effects).
//  - The height is the transition condition, checked here — never
//    delegated to the client.
//  - Degenerate configs (zero window, zero frequency, budget > capacity)
//    are rejected at construction, fail-closed.
//  - The FAULT path MUTEs the channel: the funds remain accounted
//    (capacity - charged), never vanish.

#include "vx/consensus/timelocks.hpp"

namespace vx::consensus::timelock {

// ── TLMK ────────────────────────────────────────────────────────────────────

bool tlmk_unlocked(const Tlmk &k, uint64_t current_height) noexcept {
    return current_height >= k.target_height;
}

bool tlmk_spend(Tlmk &k, uint64_t current_height) noexcept {
    if (!tlmk_unlocked(k, current_height))
        return false; // still locked: nothing changes
    if (k.spent)
        return false; // one-shot: the leaf is already burned
    k.spent = true;
    return true;
}

// ── MSRK ────────────────────────────────────────────────────────────────────

bool msrk_validate(const Msrk &m) noexcept {
    if (m.steps.empty())
        return false; // a schedule with no steps is meaningless
    uint64_t sum_bps = 0;
    uint64_t prev_height = 0;
    bool first = true;
    for (const auto &s : m.steps) {
        if (s.fraction_bps > kFractionDenominator)
            return false; // a step over 100% is never valid
        if (!first) {
            if (s.at_height <= prev_height)
                return false; // strictly ascending heights
        }
        prev_height = s.at_height;
        first = false;
        sum_bps += s.fraction_bps;
    }
    return sum_bps <= kFractionDenominator;
}

uint64_t msrk_due(const Msrk &m, uint64_t current_height) noexcept {
    if (!msrk_validate(m))
        return 0;
    uint64_t sum_bps = 0;
    for (const auto &s : m.steps) {
        if (current_height < s.at_height)
            break; // steps are sorted: nothing further is due
        sum_bps += s.fraction_bps;
    }
    // Overflow-safe: total * 10000 must not wrap — a total beyond
    // 2^64/10000 units is beyond any real supply; refuse it (fail-closed).
    if (m.total > UINT64_MAX / kFractionDenominator)
        return 0;
    const uint64_t unlocked = m.total * sum_bps / kFractionDenominator;
    return unlocked > m.spent_so_far ? unlocked - m.spent_so_far : 0;
}

bool msrk_claim(Msrk &m, uint64_t current_height) noexcept {
    if (!msrk_validate(m))
        return false; // invalid schedule: nothing changes
    const uint64_t due = msrk_due(m, current_height);
    if (due == 0)
        return false;      // nothing due: nothing changes
    m.spent_so_far += due; // whole step, or nothing
    return true;
}

// ── EK — streaming channel ─────────────────────────────────────────────────

bool ek_validate(const EKChannel &c) noexcept {
    if (c.capacity == 0)
        return false; // a zero-capacity channel is degenerate
    if (c.window_len == 0)
        return false; // zero frequency: the boundary would never roll
    if (c.window_budget == 0)
        return false; // zero boundary: every charge would FAULT
    if (c.window_budget > c.capacity)
        return false; // the window must never exceed the total
    return true;
}

EkResult ek_charge(EKChannel &c, uint64_t amount, uint64_t current_height) noexcept {
    if (c.faulted)
        return EkResult::kFaulted; // MUTE: frozen, funds accounted
    if (!ek_validate(c))
        return EkResult::kFault; // a degenerate config is a FAULT

    // Window rollover: a new window resets the budget counter.
    if (current_height >= c.window_start + c.window_len) {
        c.window_start =
            c.window_start + ((current_height - c.window_start) / c.window_len) * c.window_len;
        c.window_used = 0;
    }

    // Boundary checks BEFORE any state mutation (fail-closed). A breach
    // FAULTs the channel: the funds are MUTE (frozen, accounted), never
    // vanish — the settlement is frozen until the undo-safe exit.
    if (amount > c.window_budget - c.window_used) {
        c.faulted = true;
        return EkResult::kFault; // window breach
    }
    if (amount > c.capacity - c.charged) {
        c.faulted = true;
        return EkResult::kFault; // capacity breach
    }

    c.window_used += amount;
    c.charged += amount;
    return EkResult::kOk;
}

uint64_t ek_exit_frozen(const EKChannel &c) noexcept {
    if (!c.faulted)
        return 0;                  // the exit exists only on the FAULT path
    return c.capacity - c.charged; // the WHOLE remainder, atomically
}

} // namespace vx::consensus::timelock
