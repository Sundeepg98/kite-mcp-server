# Path A.27 Pick: kite-mcp-clockport — #28 algo2go module

## Selection rationale

State at start: master HEAD `fa6c70a`, v253 LIVE (tools=111). Phase 1
testutil clock-port split halted at the import-cycle blocker
(`kc/ports → kc/` invariant). Recovery option B authorized: promote
clockport to its own algo2go module instead of placing it in kc/ports.

This is the **28th algo2go module** (Path A inauguration arc closed at
27 with kc/sectors A.26; clockport extends the arc by 1 to address the
testutil-misnaming problem properly).

## Source code location

Unlike kc/* leaf promotions, clockport has NO existing subdirectory.
The production port currently lives **inside testutil/clock.go** at
lines 22-71 (Clock + Ticker interfaces + RealClock + realTicker).
Lines 75-190 are FakeClock + fakeTicker + NewFakeClock (test fakes;
stay in testutil).

This means **no git filter-repo extraction**. Instead:
1. Build new repo content fresh in `/tmp/algo2go-clockport/`
2. Copy port code (clock.go lines 22-71 of testutil/clock.go +
   3 RealClock tests from clock_test.go lines 12-41)
3. Add bootstrap files (LICENSE/CODEOWNERS/.gitignore/README + go.mod)
4. Push as v0.1.0

This is a "from-scratch new repo" pattern, similar to early Path A
modules that didn't have an in-tree subdirectory yet.

## Empirical scope (production reverse-dep)

```
grep testutil.{Clock,Ticker,RealClock,FakeClock,NewFakeClock}
   in production .go files (NOT _test.go)
   => ONLY: kc/fill_watcher.go (5 sites: lines 130, 143, 169, 271)
   => COMMENTS-only: app/wire.go:588, app/ratelimit.go:107
```

Plus 1 production-typed test adapter:
- `app/ratelimit_cleanup_test.go` line 28: `t testutil.Ticker`

Phase A cutover scope (pre-Phase B):
- `kc/fill_watcher.go` imports change: testutil → clockport
- `testutil/clock.go` removes prod port; FakeClock.NewTicker return
  type `Ticker` → `clockport.Ticker`; testutil/clock.go imports
  clockport (one new line)
- `app/ratelimit_cleanup_test.go` adapter type changes:
  `testutil.Ticker` → `clockport.Ticker` (1 word) + new import
- `testutil/clock_test.go` moves 3 RealClock tests to clockport
  repo; updates `var _ Clock = NewFakeClock(...)` assertion to
  `var _ clockport.Clock = NewFakeClock(...)`

## Why this avoids the import cycle

The Phase 1 attempt placed Clock at `kc/ports/` — but that package
has an existing invariant `kc/ports → kc/` (assertions.go imports
*kc.Manager for compile-time port checks). Adding `kc → kc/ports`
inverted the dep, creating the cycle.

algo2go/kite-mcp-clockport is **external** (just like all other
algo2go modules). The dep graph becomes:
- `kc/fill_watcher.go` (root) → `algo2go/kite-mcp-clockport` (external)
- `kc/ports/assertions.go` (root subpackage) → `kc/` (root parent)
- Two independent edges; no cycle.

## Module shape

| Property | Value |
|---|---|
| Module path | `github.com/algo2go/kite-mcp-clockport` |
| Algo2go deps | NONE (pure stdlib leaf — same shape as kc/sectors A.26 + kc/isttz A.6) |
| Stdlib deps | `sync`, `time` |
| Test deps | `github.com/stretchr/testify v1.10.0` |
| Internal monolith deps | NONE |
| Production reverse-deps in master | 1 file (`kc/fill_watcher.go`) |
| Test-only reverse-deps | testutil/clock.go (FakeClock import for return type), app/ratelimit_cleanup_test.go (1-word adapter type), testutil/clock_test.go (FakeClock smoke test) |
| Files in new repo | 2 .go (clock.go + clock_test.go) + bootstrap (LICENSE, CODEOWNERS, .gitignore, README, go.mod, go.sum) |
| Estimated cost | ~2-3h |

## Stop conditions / halt-rules

- Stop ~3h. Halt at ~4h.
- Watchdog: any 600s no-progress → commit + push immediately + surface.
- Hard rules unchanged (no `git stash`; WSL2 for `go test`; agent
  brief stays scoped to own packages; `git add -- <paths>` not `-A`).

## Why no filter-repo

git filter-repo extracts an existing subdirectory's history. Clockport
has no subdirectory — its code lives mixed inside testutil/clock.go.
History extraction would either pull testutil's full history (with
test-fake commits we don't want) or nothing (no isolated subdir
exists). Pattern is "from-scratch new module" — write fresh files,
clean v0.1.0.

The narration in clockport's README will document this: "Initial
release — extracted from testutil/clock.go in
Sundeepg98/kite-mcp-server. Zero algo2go deps; pure stdlib leaf.
The matching test fakes (FakeClock) remain in testutil/."
