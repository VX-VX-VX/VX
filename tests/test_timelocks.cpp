// VortexTimelocksTest — Phase F (0.2.5): TLMK / MSRK / EK-streaming.
//
// Verifies:
//   1. TLMK: the height gate, one-shot burn, double-spend refusal.
//   2. MSRK: schedule validation, the amount due, whole-step claims
//      (zero partial effects), invalid schedules refused.
//   3. EK: partial charges, window rollover, boundary breaches FAULT,
//      the FAULT path MUTEs (funds never vanish), the frozen exit
//      returns the whole remainder atomically.

#include <gtest/gtest.h>
#include "vx/consensus/timelocks.hpp"

using vx::consensus::timelock::ek_charge;
using vx::consensus::timelock::ek_exit_frozen;
using vx::consensus::timelock::ek_validate;
using vx::consensus::timelock::EKChannel;
using vx::consensus::timelock::EkResult;
using vx::consensus::timelock::Msrk;
using vx::consensus::timelock::msrk_claim;
using vx::consensus::timelock::msrk_due;
using vx::consensus::timelock::msrk_validate;
using vx::consensus::timelock::Tlmk;
using vx::consensus::timelock::tlmk_spend;
using vx::consensus::timelock::tlmk_unlocked;

// ── 1. TLMK ─────────────────────────────────────────────────────────────────

// The height gate: before the target height the key is locked.
TEST(VortexTimelocksTest, TlmkLockedBeforeTarget) {
    Tlmk k;
    k.target_height = 100;
    EXPECT_FALSE(tlmk_unlocked(k, 99));
    EXPECT_FALSE(tlmk_spend(k, 99));
    EXPECT_FALSE(k.spent); // nothing changed
}

// At the target height the key unlocks and the spend burns the leaf.
TEST(VortexTimelocksTest, TlmkUnlocksAtTarget) {
    Tlmk k;
    k.target_height = 100;
    EXPECT_TRUE(tlmk_unlocked(k, 100));
    EXPECT_TRUE(tlmk_spend(k, 100));
    EXPECT_TRUE(k.spent);
}

// Double-spend: the burned leaf refuses a second spend.
TEST(VortexTimelocksTest, TlmkDoubleSpendRefused) {
    Tlmk k;
    k.target_height = 100;
    ASSERT_TRUE(tlmk_spend(k, 100));
    EXPECT_FALSE(tlmk_spend(k, 100));
    EXPECT_FALSE(tlmk_spend(k, 1000));
    EXPECT_TRUE(k.spent); // still exactly one burn
}

// ── 2. MSRK ─────────────────────────────────────────────────────────────────

// A valid schedule: ascending heights, fractions sum ≤ 10000 bps.
TEST(VortexTimelocksTest, MsrkValidSchedule) {
    Msrk sched;
    sched.total = 10000;
    sched.steps = {{100, 5000}, {200, 3000}, {300, 2000}}; // 10000 bps
    EXPECT_TRUE(msrk_validate(sched));
}

// Degenerate schedules: empty, descending heights, over-100% sum.
TEST(VortexTimelocksTest, MsrkDegenerateSchedulesRefused) {
    vx::consensus::timelock::Msrk sched;
    EXPECT_FALSE(msrk_validate(sched)); // empty

    sched.total = 10000;
    sched.steps = {{200, 1000}, {100, 1000}}; // descending
    EXPECT_FALSE(msrk_validate(sched));

    sched.steps = {{100, 6000}, {200, 6000}}; // 12000 bps > 10000
    EXPECT_FALSE(msrk_validate(sched));

    sched.steps = {{100, 10000}}; // equal heights also refused
    sched.steps.push_back({100, 0});
    EXPECT_FALSE(msrk_validate(sched));
}

// The amount due: only steps whose height has passed count.
TEST(VortexTimelocksTest, MsrkDueTracksSteps) {
    vx::consensus::timelock::Msrk sched;
    sched.total = 10000;
    sched.steps = {{100, 5000}, {200, 3000}, {300, 2000}};
    EXPECT_EQ(msrk_due(sched, 50), 0);
    EXPECT_EQ(msrk_due(sched, 100), 5000);
    EXPECT_EQ(msrk_due(sched, 150), 5000);
    EXPECT_EQ(msrk_due(sched, 200), 8000);
    EXPECT_EQ(msrk_due(sched, 300), 10000);
}

// Claims are whole-step: spent_so_far jumps by the exact due amount.
TEST(VortexTimelocksTest, MsrkClaimWholeStep) {
    vx::consensus::timelock::Msrk sched;
    sched.total = 10000;
    sched.steps = {{100, 5000}, {200, 3000}};
    EXPECT_TRUE(msrk_claim(sched, 100));
    EXPECT_EQ(sched.spent_so_far, 5000);
    EXPECT_EQ(msrk_due(sched, 150), 0);   // nothing new due
    EXPECT_FALSE(msrk_claim(sched, 150)); // claim with nothing due: refused
    EXPECT_EQ(sched.spent_so_far, 5000);  // nothing changed
    EXPECT_TRUE(msrk_claim(sched, 200));
    EXPECT_EQ(sched.spent_so_far, 8000);
}

// An invalid schedule never claims — even if a height has passed.
TEST(VortexTimelocksTest, MsrkInvalidScheduleNeverClaims) {
    vx::consensus::timelock::Msrk sched;
    sched.total = 10000;
    sched.steps = {{200, 6000}, {100, 6000}}; // descending, over-100%
    EXPECT_FALSE(msrk_claim(sched, 300));
    EXPECT_EQ(sched.spent_so_far, 0);
}

// ── 3. EK — streaming channel ───────────────────────────────────────────────

// A valid channel config.
TEST(VortexTimelocksTest, EkValidConfig) {
    EKChannel c;
    c.capacity = 10000;
    c.window_budget = 1000;
    c.window_len = 100;
    c.window_start = 0;
    EXPECT_TRUE(ek_validate(c));
}

// Degenerate configs: zero capacity, zero window, zero budget, budget
// over capacity — all refused at construction.
TEST(VortexTimelocksTest, EkDegenerateConfigsRefused) {
    EKChannel c;
    c.capacity = 10000;
    c.window_budget = 1000;
    c.window_len = 100;
    EXPECT_TRUE(ek_validate(c));

    c.capacity = 0;
    EXPECT_FALSE(ek_validate(c));
    c.capacity = 10000;
    c.window_len = 0;
    EXPECT_FALSE(ek_validate(c));
    c.window_len = 100;
    c.window_budget = 0;
    EXPECT_FALSE(ek_validate(c));
    c.window_budget = 20000; // > capacity
    EXPECT_FALSE(ek_validate(c));
}

// Partial charges accumulate within the window budget.
TEST(VortexTimelocksTest, EkPartialCharges) {
    EKChannel c;
    c.capacity = 10000;
    c.window_budget = 1000;
    c.window_len = 100;
    EXPECT_EQ(ek_charge(c, 600, 10), EkResult::kOk);
    EXPECT_EQ(ek_charge(c, 400, 20), EkResult::kOk);
    EXPECT_EQ(c.charged, 1000);
    EXPECT_EQ(c.window_used, 1000);
}

// The window budget is a hard boundary: a breach FAULTs the channel.
TEST(VortexTimelocksTest, EkWindowBreachFaults) {
    EKChannel c;
    c.capacity = 10000;
    c.window_budget = 1000;
    c.window_len = 100;
    EXPECT_EQ(ek_charge(c, 600, 10), EkResult::kOk);
    EXPECT_EQ(ek_charge(c, 500, 20), EkResult::kFault); // 600+500 > 1000
    EXPECT_TRUE(c.faulted);
    EXPECT_EQ(c.charged, 600); // the refused charge applied NOTHING
}

// The window rolls over: a fresh window resets the budget counter.
TEST(VortexTimelocksTest, EkWindowRollover) {
    EKChannel c;
    c.capacity = 10000;
    c.window_budget = 1000;
    c.window_len = 100;
    EXPECT_EQ(ek_charge(c, 1000, 50), EkResult::kOk);
    EXPECT_EQ(ek_charge(c, 1, 100), EkResult::kOk); // window 0 exhausted,
    EXPECT_EQ(c.window_used, 1);                    // window 1 opened at 100
    EXPECT_EQ(c.charged, 1001);
}

// The capacity is a hard boundary: a breach FAULTs even inside budget.
TEST(VortexTimelocksTest, EkCapacityBreachFaults) {
    EKChannel c;
    c.capacity = 10000;
    c.window_budget = 1000;
    c.window_len = 100;
    // 10 windows of 1000 each = 10000 charged over 1000 heights.
    for (int w = 0; w < 10; ++w)
        EXPECT_EQ(ek_charge(c, 1000, 50 + w * 100), EkResult::kOk);
    EXPECT_EQ(c.charged, 10000);
    EXPECT_EQ(ek_charge(c, 1, 950 + 1), EkResult::kFault); // capacity breach
    EXPECT_TRUE(c.faulted);
    EXPECT_EQ(c.charged, 10000);
}

// The FAULT path MUTEs: every further charge is refused, funds frozen.
TEST(VortexTimelocksTest, EkFaultMutes) {
    EKChannel c;
    c.capacity = 10000;
    c.window_budget = 1000;
    c.window_len = 100;
    EXPECT_EQ(ek_charge(c, 600, 10), EkResult::kOk);
    EXPECT_EQ(ek_charge(c, 500, 20), EkResult::kFault);
    EXPECT_EQ(ek_charge(c, 1, 200), EkResult::kFaulted); // MUTE
    EXPECT_EQ(c.charged, 600);                           // funds remain accounted — never vanish
}

// The frozen exit returns the WHOLE remainder, atomically.
TEST(VortexTimelocksTest, EkFrozenExitReturnsRemainder) {
    EKChannel c;
    c.capacity = 10000;
    c.window_budget = 1000;
    c.window_len = 100;
    EXPECT_EQ(ek_charge(c, 600, 10), EkResult::kOk);
    EXPECT_EQ(ek_charge(c, 500, 20), EkResult::kFault);
    EXPECT_EQ(ek_exit_frozen(c), 9400); // 10000 - 600, whole remainder
}

// The exit exists only on the FAULT path: a healthy channel returns 0.
TEST(VortexTimelocksTest, EkExitOnlyOnFault) {
    EKChannel c;
    c.capacity = 10000;
    c.window_budget = 1000;
    c.window_len = 100;
    EXPECT_EQ(ek_charge(c, 600, 10), EkResult::kOk);
    EXPECT_EQ(ek_exit_frozen(c), 0);
}
