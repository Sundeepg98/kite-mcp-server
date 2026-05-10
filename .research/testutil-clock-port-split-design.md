# testutil → Clock-Port Split — Design + Execution Plan

**Phase 1 dispatch** (post Path A.26 closure). Architectural research +
optional execution per user authorization.

State at start: master HEAD `c5b9cf7` = production v252 LIVE
(tools=111). Audit agent's commit `c5b9cf7` (Phase 2.0 port-interface
stub for Postgres adapter) added on top of my survey commit `1f14b3d`.

## Problem statement (from halt-survey at 1f14b3d)

testutil cannot be promoted as a "test helpers external module"
because `kc/fill_watcher.go` line 130 has 1 production reverse-dep:

```go
type FillWatcher struct {
    Clock        testutil.Clock // nil => testutil.RealClock{}
    ...
}
func (w *FillWatcher) pollLoop(placed domain.OrderPlacedEvent,
                                ticker testutil.Ticker) { ... }
```

`testutil.Clock`/`testutil.Ticker`/`testutil.RealClock{}` are used in
**production** struct fields and method signatures. testutil is
effectively `(production clock-port) + (test fakes) + (other test
helpers)` glued into one module — misnamed responsibility.

## Empirical scope (from grep across all .go files)

| Symbol | Sites | Scope |
|---|---|---|
| `testutil.Clock` (interface) | 2 (kc/fill_watcher.go) | **Production** |
| `testutil.Ticker` (interface) | 1 (kc/fill_watcher.go) | **Production** |
| `testutil.RealClock{}` (struct) | 1 (kc/fill_watcher.go) | **Production** |
| `testutil.FakeClock` (struct) | 11 | Test only |
| `testutil.NewFakeClock` (func) | 9 | Test only |

Production users of the port: **only** `kc/fill_watcher.go`. Comment
references in `app/wire.go:588`, `app/ratelimit.go:107`, and
`app/ratelimit_cleanup_test.go` are documentation only.

## Empirical structure of testutil/

| File | LOC | Deps | Scope |
|---|---|---|---|
| `clock.go` | 190 | stdlib only (`sync`, `time`) | **Mixed**: prod port + test fake |
| `clock_test.go` | 188 | testutil + stdlib | Test |
| `kiteserver.go` | 468 | gokiteconnect/v4 | Test fixture |
| `logger.go` | 34 | algo2go/kite-mcp-logger | Test fixture |
| `testutil_test.go` | 318 | self | Test |
| `kcfixture/manager.go` | ? | root, instruments, riskguard | Test fixture |

**Critical observation**: clock.go's port interface is already
production-clean (zero algo2go deps). The "split" is essentially
**file relocation**, not interface redesign.

## Existing precedent: kc/ports

```
kc/ports/                 — non-go.mod package inside root module
  alert.go                — AlertPort interface
  credential.go           — CredentialPort interface (8 methods)
  instrument.go           — InstrumentPort interface
  order.go                — OrderPort interface
  session.go              — SessionPort interface
  assertions.go           — package-level documentation +
                            interface compliance assertions
  credential_leaf_test.go — leaf-stability test (no algo2go deps)
  leaf_stability_test.go  — invariant test
```

Pattern: bounded-context contract interfaces colocated as a
non-module package inside root. Audit agent's Phase 2.0 commit
`c5b9cf7` added `app/providers/store_port.go` to a different
location for Postgres driver-switching, but `kc/ports/` remains the
canonical interface-port location for everything kc/-domain-related.

## Design: 3-phase split

### Phase 1A: Add `kc/ports/clock.go` (new file, no removals yet)

Create `kc/ports/clock.go` containing:
- `Clock` interface (Now + NewTicker)
- `Ticker` interface (C + Stop)
- `RealClock{}` struct (zero-value production default)
- `realTicker` struct (private)

Copy verbatim from `testutil/clock.go` lines 22-71 (port
interfaces + real implementation only). The package becomes
`ports`, not `testutil`. Add `// Package ports` doc, place new file
alongside existing kc/ports/*.go files.

This is **additive only** — no existing file changes. Standalone
build/test will pass. Not yet a useful split; sets up Phase 1B.

### Phase 1B: Migrate kc/fill_watcher.go to ports + delete duplicate

Edits to `kc/fill_watcher.go`:
```go
// BEFORE:
import "github.com/zerodha/kite-mcp-server/testutil"

type FillWatcher struct {
    Clock        testutil.Clock // nil => testutil.RealClock{}
    ...
    clock        testutil.Clock
}
clock = testutil.RealClock{}
func (w *FillWatcher) pollLoop(placed domain.OrderPlacedEvent,
                                ticker testutil.Ticker) { ... }

// AFTER:
import "github.com/zerodha/kite-mcp-server/kc/ports"

type FillWatcher struct {
    Clock        ports.Clock // nil => ports.RealClock{}
    ...
    clock        ports.Clock
}
clock = ports.RealClock{}
func (w *FillWatcher) pollLoop(placed domain.OrderPlacedEvent,
                                ticker ports.Ticker) { ... }
```

5 replacements in one file. Then delete `testutil/clock.go` lines
22-71 (production port + RealClock implementation), keeping only
the FakeClock/fakeTicker/NewFakeClock parts. Add `import
"github.com/zerodha/kite-mcp-server/kc/ports"` to testutil/clock.go
so FakeClock's `NewTicker` method can declare return type
`ports.Ticker`.

`testutil/clock.go` post-edit:
```go
package testutil

import (
    "sync"
    "time"
    "github.com/zerodha/kite-mcp-server/kc/ports"
)

// FakeClock is a test clock whose time only moves when Advance is
// called. ... [unchanged docstring] ...
type FakeClock struct { mu sync.Mutex; now time.Time; tickers []*fakeTicker }

func NewFakeClock(start time.Time) *FakeClock { ... }
func (f *FakeClock) Now() time.Time { ... }
func (f *FakeClock) NewTicker(d time.Duration) ports.Ticker { ... }  // return type changes
func (f *FakeClock) Advance(d time.Duration) int { ... }
func (f *FakeClock) Set(to time.Time) int { ... }

type fakeTicker struct { ... }
func (t *fakeTicker) C() <-chan time.Time { ... }
func (t *fakeTicker) Stop() { ... }
```

**Test files using `testutil.NewFakeClock` continue working
unchanged** — the returned `*FakeClock` satisfies `ports.Clock`
through structural typing. Field type `*testutil.FakeClock`
continues to assign to `ports.Clock`-typed receiver.

`app/ratelimit_cleanup_test.go` adapter type `fakeTickerAdapter`
needs its `t testutil.Ticker` field renamed to `t ports.Ticker`
(1 word change).

### Phase 1C: Update testutil/go.mod

testutil/go.mod gains an internal dep on the root module's
kc/ports package. But since kc/ports is inside root and testutil
already has `replace github.com/zerodha/kite-mcp-server => ../`,
this resolves automatically — no go.mod edits needed.

testutil's clock_test.go also needs minor edit: any test asserting
"FakeClock implements testutil.Clock" needs to become "FakeClock
implements ports.Clock". Let me check that empirically before
finalizing.

### What this enables

- testutil becomes a **test-only** module (genuinely): MockKiteServer
  + Capture/Noop loggers + FakeClock + kcfixture
- testutil's purely-test scope means it's a candidate for promotion
  to `algo2go/kite-mcp-testutil@v0.1.0` (Path A.28) — though this
  is still subject to the kcfixture-imports-root architectural
  blocker, which remains open
- `kc/ports.Clock` becomes the canonical port for time abstraction
  across the codebase

### What this does NOT enable

- testutil promotion to algo2go is **still blocked** by
  testutil/kcfixture/ which imports root (`kc/`) directly. That's a
  separate architectural layer (kcfixture builds *kc.Manager test
  instances; root extraction needs its own design work).
- The clock-port split moves the architectural needle on **only the
  production reverse-dep**. testutil still has the kcfixture
  bidirectional-with-root blocker.

## Cost estimate

| Task | Effort |
|---|---|
| Create kc/ports/clock.go (190 LOC copy) | 15min |
| Edit kc/fill_watcher.go (5 replacements) | 10min |
| Edit testutil/clock.go (delete prod port + add ports import + change return type of FakeClock.NewTicker) | 15min |
| Edit app/ratelimit_cleanup_test.go (1 word change) | 5min |
| Edit clock_test.go (any assertion changes) | 10min |
| WSL2 verify: build + tools=111 + full mcp/ + app/ + kc/fill_watcher tests | 15min |
| Commit + push | 5min |
| **Total** | **~75min** |

Well inside Phase 1's 3-4h budget. Suggests **execute in same
dispatch** if WSL2 stays clean.

## Risk assessment

| Risk | Mitigation |
|---|---|
| testutil.Clock interface is referenced by name in test files (would break) | Empirical check: `grep -rn 'testutil\.Clock'` shows only 2 hits in kc/fill_watcher.go — all other test files use `*testutil.FakeClock` (struct) or `testutil.NewFakeClock` (func). Verified: no broad rename pain. |
| FakeClock no longer satisfies "Clock" because Ticker return type changes | Structural typing: as long as FakeClock has `Now()` + `NewTicker(d) ports.Ticker`, Go accepts it as `ports.Clock`. The interface name change doesn't break implementations. |
| `app/ratelimit.go` line 107 comment "testutil.FakeClock does" becomes stale | Update comment to reference `ports.Clock` instead of `testutil.Clock`. Trivial. |
| Build cascade: app/providers/order_svc.go imports kc/ports (per earlier grep) — does adding new clock.go break it? | Pure addition of new file in existing package. Existing file imports unchanged. No cascade. |
| `Ticker` is a generic name and may conflict with broker's ticker subpackage | broker's `algo2go/kite-mcp-broker/ticker` is a *package* not a type. `ports.Ticker` is a type. No collision in import-path-vs-type-name space. |
| Migration breaks production tools=111 invariant | Standard playbook: WSL2 verify after each phase; halt + revert if invariant breaks. |

## Halt-rules for execution

- Halt if Phase 1A (kc/ports/clock.go addition) breaks any test that
  currently passes
- Halt if Phase 1B's fill_watcher migration causes go vet / go build
  errors that aren't trivially-fixable (1 line)
- Halt if testutil's standalone build breaks after the split
- Halt if any architectural surprise emerges (e.g., a hidden
  reverse-dep on testutil.RealClock by name)

## Decision: execute in same dispatch

The design is clean, the cost is ~75min, the risk surface is
trivially-empirical (5 files, ~10 line edits, structural typing
preserves all test code unchanged). Standard playbook applies:
edit → WSL2 verify → commit → push.

The split is a pure topology change. No new business logic. The
empirical-gate methodology (tools=111 + standalone build/test green)
governs.

If execution succeeds → Phase 1 closed; testutil clock-port split
landed. testutil module is no longer misnamed; the production
abstraction lives at its proper architectural layer. Decision on
Phase 2 (kc/manager_*.go decomp research) happens next.

If execution halts → commit research only, surface findings + halt
reason for orchestrator.

---

## EXECUTION ATTEMPT — HALTED ON ARCHITECTURAL BLOCKER

Phase 1A (additive: create kc/ports/clock.go + kc/ports/clock_test.go)
EXECUTED CLEANLY. Standalone build green; ports package tests passed
in 28ms.

Phase 1B (migrate kc/fill_watcher.go to import kc/ports;
delete production port from testutil/clock.go) FAILED at WSL2 build
verify with **import cycle**:

```
package github.com/zerodha/kite-mcp-server
    imports github.com/zerodha/kite-mcp-server/app from main.go
    imports github.com/zerodha/kite-mcp-server/app/providers from wire.go
    imports github.com/zerodha/kite-mcp-server/kc from alert_svc.go
    imports github.com/zerodha/kite-mcp-server/kc/ports from fill_watcher.go
    imports github.com/zerodha/kite-mcp-server/kc from assertions.go: import cycle not allowed
```

### Root cause

`kc/ports/assertions.go` (existing file, 19 LOC) imports `kc/`
parent for compile-time satisfaction checks:

```go
package ports

import "github.com/zerodha/kite-mcp-server/kc"

// These live in kc/ports (not in kc) so that kc stays free of
// ports-package imports; only ports imports kc, keeping the graph
// acyclic.
var (
    _ SessionPort    = (*kc.Manager)(nil)
    _ CredentialPort = (*kc.Manager)(nil)
    _ AlertPort      = (*kc.Manager)(nil)
    _ OrderPort      = (*kc.Manager)(nil)
    _ InstrumentPort = (*kc.Manager)(nil)
)
```

The existing kc/ports architecture has an explicit invariant
(documented in lines 9-11 of assertions.go): **kc → kc/ports is
forbidden; only kc/ports → kc is allowed**. The whole port package
was designed under that invariant.

Phase 1B violated it: by adding
`kc/fill_watcher.go: import "kc/ports"`, the dep direction inverted.

### What I did wrong

The design doc's Phase 1A/1B steps did not check the existing
kc/ports invariant. I assumed kc/ports was a stand-alone leaf
(matches its naming) when in fact it's already part of a
documented bidirectional contract (kc/ports → kc/) — the inverse
of what's needed for kc/fill_watcher to import a Clock port.

The clue was visible at commit `c5b9cf7` (audit agent's Phase 2.0
port-interface design at app/providers/store_port.go) — they put
the Postgres port at app/providers/, NOT at kc/ports/, possibly
exactly to avoid this cycle. I did not connect that signal at
research time.

### What was reverted

- Deleted: `kc/ports/clock.go`
- Deleted: `kc/ports/clock_test.go`
- Reverted: `kc/fill_watcher.go` (back to original `testutil` import)
- Reverted: `testutil/clock.go` (back to original full port + fakes)
- Reverted: `testutil/clock_test.go` (back to original full port +
  fake test set)
- Reverted: `app/ratelimit_cleanup_test.go` (back to original
  testutil import)

WSL2 verify: build green; tools=111 invariant pass. Working tree
matches HEAD exactly (`git diff HEAD --` empty for all 4 modified
files).

### Recovery options (require new design dispatch)

The clock port cannot live at `kc/ports/` because of the existing
kc/ports → kc/ invariant. Three alternative locations:

**Option A: New non-go.mod package `kc/clockport/`**
- Create `kc/clockport/clock.go` with Clock + Ticker + RealClock
- Has zero imports (stdlib only) — leaf-clean by design
- kc/fill_watcher imports `kc/clockport` — no cycle (clockport ↛ kc)
- testutil's FakeClock imports `kc/clockport` for return type
- Cost: ~75min (same as original Phase 1)
- Trade-off: another tiny package at kc/ root; no architectural cost

**Option B: Promote to algo2go/kite-mcp-clockport (new external
algo2go module = #28)**
- Standard Path A pattern: extract clockport to its own
  github.com/algo2go/kite-mcp-clockport@v0.1.0 module
- Pure stdlib leaf, matches kc/sectors precedent (zero algo2go deps,
  testify-only test deps)
- Cost: ~2-3h (full Path A playbook: gh repo create, filter-repo
  extract, rewrite, bootstrap, push, tag, protect, release, Phase A
  cutover, Phase B canary delete, evidence commit, local clone)
- Benefit: contracts the Path A inauguration arc to 28 modules with
  one more tiny leaf — semantically tidier than 27+1-internal
- Trade-off: testutil still has bidirectional with root via
  kcfixture (separate problem)

**Option C: Define Clock + Ticker interfaces in algo2go/kite-mcp-domain**
- Add Clock + Ticker interfaces to existing kite-mcp-domain module
- Single new external module, but contaminates domain with infra
  concerns (Clock is not a domain concept like Order/Position)
- Risk: pollutes domain's clean type-only surface
- Trade-off: avoid creating a new module, but at the cost of
  domain-purity violation

### Recommended next step

**Option B (Path A.27 — promote clockport as algo2go module)**.

Rationale:
1. Matches the precedent we just closed (Path A.26 = kc/sectors,
   pure stdlib leaf with zero algo2go deps). Clockport is a
   carbon-copy shape: stdlib leaf with testify-only test deps.
2. Architecturally cleanest: the production port lives in its own
   versioned external module, separate from the test fakes. The
   "27 modules + 1 orchestrator" close-out becomes "28 modules +
   1 orchestrator" with the same clean topology.
3. Cost (~2-3h) is well inside Phase 1's 6h total budget across
   Phase 1+2.
4. Eliminates the misnamed-testutil problem fundamentally: testutil
   is then 100% test-only (FakeClock is a fake of an external
   port).

If the orchestrator authorizes Option B, the next dispatch should:
1. `gh repo create algo2go/kite-mcp-clockport`
2. Standard Path A.27 playbook (mirror kc/sectors A.26 — same shape)
3. Phase A canary: kc/fill_watcher imports
   `github.com/algo2go/kite-mcp-clockport`; testutil/clock.go
   imports same module for FakeClock's return type
4. Phase B canary delete
5. Evidence commit + local clone

Phase 2 (kc/manager_*.go decomp research) deferred to next dispatch
after orchestrator routes the recovery decision.
