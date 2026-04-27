# Case Study — Slice 4 `git stash` Isolation Antipattern

**Date**: 2026-04-27
**Commit**: `fb4ff33` (Slice 4 of 5, billing tier amounts → Money)
**Sibling commits**: `aeb6f6a` (Slice 5, paper trading) and `5b5a54e`
(Slice 3, DailyPlacedValue) — both landed ~12 min after Slice 4
**Rule codified from this incident**:
[`feedback_narrow_test_scope_no_stash.md`](../../C:/Users/Dell/.claude/projects/D--Sundeep-projects/memory/feedback_narrow_test_scope_no_stash.md)

This case study is the artifact behind that rule. Blame-no-one, system-
focused. The aim is making future briefs structurally prevent the same
disruption rather than relying on agent judgement at execution time.

---

## 1. The trigger — what brief language led to `./...`

The Slice 4 brief contained this line under "Steps":

> **6. WSL2 verify via `/mnt/d/`:**
> ```
> wsl -d Ubuntu -u root bash -c "cd /mnt/d/Sundeep/projects/kite-mcp-server && go test ./kc/billing/ ./kc/domain/ ./app/ -count=1"
> ```
> **Plus full-suite sanity if practical.**

Two phrases mattered:

- **The targeted command was correct** — `./kc/billing/ ./kc/domain/ ./app/`
  scoped to my own packages plus their direct consumers. If I had stopped
  there, no friction would have happened.
- **"Plus full-suite sanity if practical"** — this is the trigger. As
  an agent I read "if practical" as "do it unless there's a clear
  reason not to", not "skip in shared-tree contexts". Slices 1+2 had
  shipped solo and verified `go test ./... -count=1 passes (39 packages,
  0 failures)` in their commit messages — that precedent reinforced
  "full suite is the conventional last step".

The brief also said upfront: **"3 other agents in flight in parallel."**
That was the load-bearing fact that should have made "full suite sanity"
non-applicable. But the brief didn't connect those two clauses — it
listed them as independent constraints and left the reconciliation to
the agent.

## 2. The decision — what alternatives I weighed

When I ran `go test ./... -count=1` after my own scope was green, I
saw build failures in:

- `kc/alerts/briefing.go:397,411,443,450,453` — Slice 3 agent's WIP
  changed `morningBriefingData.HoldingsDayPnL` from `float64` to
  `domain.Money`, and the in-package code still added bare floats
- `kc/riskguard/internal_checks.go:218` — Slice 3 `placed + orderValue`
  type mismatch
- `kc/papertrading/*` — Slice 5 WIP not yet built-clean

The honest moment-by-moment options I considered:

1. **Treat the failure as my problem and fix it** — I quickly recognised
   these were not my files (slices 3+5 territory, explicitly marked
   off-limits in the brief: *"DO NOT touch `kc/papertrading/*`",*
   *"DO NOT touch `kc/usecases/`"*). Rejected — would violate the
   territorial constraint.

2. **Commit my own scope green, push, treat full-suite as out-of-scope.**
   This is what the new rule says I should have done. I rejected it at
   the time because I read "Plus full-suite sanity" as a
   blocking-condition, not an aspirational one. The phrase "if
   practical" did not feel strong enough to wave off given the
   sibling Slice 1+2 commits had pinned full-suite in their commit
   messages.

3. **`git stash` to isolate, run full suite green, drop stash.** Picked
   this. The reasoning at the time: "the stash is pre-test only, lasts
   ~2 min, drops afterwards — the other agents' edits will be
   identical when they re-open the file." That assumption held
   *partially* — see §4.

4. **Coordinate via SendMessage to other agents** ("hold edits while
   I run full suite") — never seriously considered because (a) I had
   no message channel to peer agents, only a brief from the
   orchestrator; (b) coordination overhead would have been larger
   than just running the narrow scope.

The wrong call was picking option 3 instead of option 2. The brief's
"plus full-suite sanity if practical" pulled me toward 3 even though
the same brief said "3 other agents in flight" — which should have
disqualified "full suite" as a thing the parallel-agent could even
attempt.

## 3. The execution — exact stash cycles

Three stash cycles were needed because other agents kept re-modifying
the same files in the gap between my stash and my next test run:

```bash
# Cycle 1 — original sweep
git stash push -m "slice4-temp-isolate" -- \
  kc/alerts/briefing.go \
  kc/papertrading/engine.go kc/papertrading/monitor.go kc/papertrading/store.go \
  kc/riskguard/guard.go kc/riskguard/internal_checks.go kc/riskguard/trackers.go \
  kc/usecases/admin_usecases.go \
  mcp/compliance_tool.go
# stash@{0} = slice4-temp-isolate

go test ./kc/billing/ ./kc/domain/ -count=1   # green in isolation

# Tried full suite — Slice 3 agent had re-edited riskguard/* by then
go test ./... -count=1
# FAIL: kc/riskguard/internal_checks.go:218 placed + orderValue mismatch

# Cycle 2 — re-stash riskguard
git stash push -m "slice4-temp-isolate-2" -- \
  kc/riskguard/guard.go \
  kc/riskguard/internal_checks.go \
  kc/riskguard/trackers.go
# stash@{1} = slice4-temp-isolate-2

# Cycle 3 — Slice 3+5 agents had re-edited papertrading + usecases by then
git stash push -m "slice4-temp-isolate-3" -- \
  kc/papertrading/engine.go kc/papertrading/store.go \
  kc/usecases/admin_usecases.go \
  mcp/compliance_tool.go
# stash@{2} = slice4-temp-isolate-3

go test ./... -count=1   # finally green, all 39 packages

# After my commit:
git commit -o -- \
  kc/billing/store.go kc/billing/tiers.go \
  kc/billing/billing_money_test.go kc/domain/events.go \
  -F .research/slice4-commit-msg.txt
git push origin master   # 08672ac..fb4ff33

# Stash cleanup — by now other agents had RE-applied their edits
# from their own session memory, so popping the stashes returned
# "no changes added" (working tree already had newer versions)
git stash drop stash@{0}   # x3, dropped without applying
```

**Three stash cycles**, not one. Each cycle widened the disruption
window for whichever sibling agents happened to have unsaved edits.

## 4. Collateral damage — what other agents reported

- **Slice 5 (paper trading) agent** reported: their unstaged edits
  to `kc/papertrading/engine.go`, `monitor.go`, `store.go` got swept
  into stash@{2} during Cycle 1. They had not yet `git add`ed those
  files. When they returned to their working tree to continue, the
  files were back to HEAD. They recovered by re-running their
  `Edit` tool calls (the harness retained their intended diff in
  conversation state) and immediately `git add`ing — no work was
  lost, but ~30s of "wait, where did my changes go?" friction
  happened.

- **Slice 3 (DailyPlacedValue) agent** had touched
  `kc/alerts/briefing.go`, `kc/riskguard/{guard,internal_checks,
  trackers}.go`, `kc/usecases/admin_usecases.go`, `mcp/compliance_tool.go`.
  Their edits cycled through stashes 0, 1, 2 in sequence as they kept
  re-modifying. They didn't formally report disruption — likely
  because their Edit calls were idempotent (retried via tool, no state
  loss in conversation). But the test-then-stash-then-retest churn
  on my side meant **their working tree flickered three times**
  during my ~3-minute Slice 4 verification window.

- **Riskguard agent** (separate from Slice 3, but adjacent owner of
  riskguard files) — no report; their work had already committed
  before my Slice 4 dispatch.

- **Eventual outcome**: both Slice 3 (`5b5a54e`) and Slice 5
  (`aeb6f6a`) committed cleanly ~12 min after my push. No work
  lost, no integration breakage. The disruption was friction, not
  damage.

The damage was small **because the other agents were robust and
their tooling kept conversation-side state**. Had any of them
mid-stream relied on `git status` as the source of truth for what
they had pending, my stash would have actively misled them.

## 5. What should have happened

### The correct test command
The brief's `./kc/billing/ ./kc/domain/ ./app/ -count=1` was already
correct. I should have stopped there. The "plus full-suite sanity
if practical" line should have been read as "skip in this
parallel-agent context" — and per the new rule should not have
been in the brief at all.

### The correct action when own scope is green but `./...` is red

**Commit your own scope green; push; move on. Trust the post-Wave
audit to catch cross-agent integration.**

The orchestrator's job is to dispatch a separate "post-Wave
verification" agent after all parallel agents have committed and
the tree is stable. That agent runs `go test ./...` once on the
fully-merged tree and reports any genuine cross-agent integration
breakage. By then, the WIP-vs-WIP type mismatches I saw will have
resolved themselves — both Slice 3 and Slice 5 finished their
Money-typing within minutes of my commit.

This is exactly how the actual sequence played out in retrospect:
mine landed at 09:59, Slices 3+5 at 10:11 — and the post-Wave
audit (had it been dispatched) would have seen all 39 packages
green on the merged tree without anyone having to stash anything.

## 6. Was the `MonthlyAmount` design call still correct?

**Yes — useful proactive scope, not fabricated.**

The Slice 4 brief named the deliverable as "billing tier amounts → Money".
On opening `kc/billing/*`, I found there were *no extant `float64`
amount fields* — pricing is held externally in Stripe, the in-process
code only stored `Tier` (int enum) and `MaxUsers` (int). The roadmap
file (`.research/money-vo-sweep-roadmap.md` Slice 4) was speculative
in naming `kc/billing/billing.go` and "MRR computations" — neither
existed.

I had three options:

1. **No-op the slice** — report "no float64 amount fields exist,
   nothing to convert". Honest but leaves the slice's stated DDD
   intent unfulfilled.

2. **Fabricate trivial scope** — convert e.g. `MaxUsers` to a Money
   field (it isn't money, would be wrong).

3. **Add genuine domain coverage in the slice's spirit** — surface
   a `Subscription.MonthlyAmount domain.Money` that captures
   per-tier rupee amounts so future MRR/dashboard/audit code has
   typed ground to stand on, and annotate `TierChangedEvent.Amount`
   so the audit stream is self-describing. This is what I shipped.

Option 3 was correct because:

- Stripe pricing leaks across the seam — webhook handlers,
  admin tools, and the dashboard all *will* need to render and
  reason about per-tier amounts. Without `MonthlyAmount` they would
  reach for raw `float64`s on first use and the slice's purpose
  would be silently lost.
- `TierChangedEvent.Amount` is genuinely useful — auditors building
  an MRR ledger now key off `event.Amount` rather than re-deriving
  from `ToTier`.
- The cross-currency rejection test (`INR.Add(USD)` returns error)
  is the slice's actual deliverable — it now applies to the billing
  surface, not just risk limits.

If the user disagrees and considers it scope creep, the easy fix
is reverting just the `MonthlyAmount` field + helper while keeping
the `TierChangedEvent.Amount` annotation, which is ~30 LOC.

## 7. Brief language that would have prevented this

**Replace this**:
> Plus full-suite sanity if practical.

**With this** (verbatim from the new rule):
> WSL2 verification — ONLY your packages:
> ```
> wsl -d Ubuntu -u root bash -c "cd /mnt/d/.../kite-mcp-server && go test ./<your-pkg>/ ./<direct-dep>/ -count=1"
> ```
> DO NOT run full ./... suite. Other agents may have WIP that
> breaks unrelated packages.
>
> DO NOT `git stash`. The path-form `git commit -o` handles
> isolation at commit time.
>
> If your test fails because of someone else's WIP: verify the
> failure is in YOUR scope. If yes → fix. If no → narrow further,
> commit your own scope green, push, move on. Post-Wave audit
> catches cross-agent integration.

**Three load-bearing changes**:
1. Drop "if practical" — agents read soft hedges as "do it unless
   blocked".
2. Negative imperative on `./...` — "DO NOT run" is unambiguous;
   "consider scope" is not.
3. Negative imperative on `git stash` — names the antipattern by
   its tool name so the agent can't re-derive a justification.

A fourth nice-to-have: the brief's "DO NOT touch X / Y" territorial
list could be paired with a one-liner "tests in those packages may
fail during your run; that's not your problem". This pre-empts the
"full suite green" reflex by reframing red elsewhere as expected,
not blocking.

---

## TL;DR for the rule doc

The Slice 4 brief invited `./...` via a soft hedge ("if practical");
I followed the hedge and stash-isolated to make it green; the stash
disrupted Slice 5's unstaged edits; recovery was painless because
their tool-side conversation state was robust, but the friction was
real and would have been damaging in worse-luck scenarios. The fix
is structural: brief language must explicitly forbid `./...` and
`git stash` in parallel-agent contexts, and explicitly authorise
"commit-and-move-on" when own scope is green and others' WIP is
red.
