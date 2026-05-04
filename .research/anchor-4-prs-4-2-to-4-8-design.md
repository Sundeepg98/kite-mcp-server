# Anchor 4 — PRs 4.2 through 4.8 Design

**Date**: 2026-05-04
**HEAD audited**: `766c133` (Tier 2 leaf 16/24 — kc/instruments extracted; **Tier 2 COMPLETE**)
**Builds on**: `7ac9d34 b-full-pr-shapes.md` (PR-shape decomposition) and `fd603f3 b-full-20-agent-reframe.md` (20-agent denominator)
**Charter**: read-only research. Doc-only. NO code changes.

**State at HEAD `766c133`**:
- 16 modules extracted: broker + kc/{audit, billing, decorators, i18n, instruments, isttz, legaldocs, logger, money, registry, riskguard, scheduler, templates, users, watchlist}
- **PR 4.1 has NOT yet landed** at this HEAD: `kc/domain/go.mod` does not exist; root `go.mod` replace block has 16 entries, no kc/domain
- `kc/domain/`: 17 prod files (.go) + 15 test files; 7,607 prod LOC + 4,229 test LOC; **142 reverse-dep files** distributed across 14 packages (kc/usecases 32, kc/riskguard 23, mcp 15, kc 15, kc/alerts 14, kc/papertrading 11, kc/eventsourcing 10, app 7, kc/billing 4, kc/ops 3, kc/audit 3, kc/telegram 2, kc/cqrs 2, app/providers 2)
- Module-clean external deps: `broker`, `kc/isttz`, `kc/money` only (all already extracted; verified via `grep -hE "^\s+\"github" kc/domain/*.go`)

**Brief assumption**: PRs 4.2-4.8 execute **after** PR 4.1 lands (which adds `kc/domain/go.mod` stub + root replace + go.work entry + Dockerfile manifest pre-stage). This design works backwards from a deployable v203+ post-Anchor-4 state.

**Critical empirical correction to `7ac9d34`**: prior plan listed PRs 4.1-4.8 (8 PRs) but described 4.2 as `chore(go.work): add ./kc/domain to use block` and 4.3 as `chore(Dockerfile): pre-stage kc/domain manifest` — both should land **with 4.1** as a single atomic PR (the kc/instruments precedent at `kc/instruments/go.mod` shows go.mod + go.work + Dockerfile + root go.mod replace ship together). The post-4.1 state has all 4 chore-bumps completed, so PRs 4.2-4.8 are the **incremental migration of consuming modules**, not infrastructure setup.

---

## Per-PR Design

### PR 4.2 — `chore(kc/audit): bump kc/domain require + replace`

- **Files**: `kc/audit/go.mod` (single file edit). Add `github.com/zerodha/kite-mcp-server/kc/domain v0.0.0-00010101000000-000000000000` to `require` block; add `replace github.com/zerodha/kite-mcp-server/kc/domain => ../domain` line. Pattern matches kc/instruments/go.mod precedent.
- **Build verification**: `cd kc/audit && go build ./...` and `cd kc/audit && GOWORK=off go build ./...` and `cd kc/audit && go vet ./...` and `cd kc/audit && go test ./... -count=1` (3 reverse-dep files in kc/audit). Then root `go build ./...` and `go test ./kc/audit/...`.
- **Acceptance**: `kc/audit` standalone build green both with and without GOWORK; tests pass; root tree still green.
- **Time**: ~10 minutes (1 file edit + 4 verification commands).
- **Inter-PR coupling**: must merge after PR 4.1 (kc/domain/go.mod must exist). Independent of 4.3-4.7.

### PR 4.3 — `chore(kc/billing): bump kc/domain require + replace`

- **Files**: `kc/billing/go.mod` single edit, same pattern as 4.2. 4 reverse-dep files in kc/billing.
- **Build verification**: `cd kc/billing && go build ./... && GOWORK=off go build ./... && go vet ./... && go test ./... -count=1` plus root verification.
- **Acceptance**: kc/billing standalone build green both ways; tests pass.
- **Time**: ~10 minutes.
- **Inter-PR coupling**: depends on 4.1 only. **Parallel-safe** with 4.2, 4.4-4.7.

### PR 4.4 — `chore(kc/riskguard): bump kc/domain require + replace`

- **Files**: `kc/riskguard/go.mod` single edit. 23 reverse-dep files (highest among already-extracted modules).
- **Build verification**: same gate. **Note**: kc/riskguard imports kc/domain heavily (`kc/riskguard/check.go`, `guard.go`, `limits.go`, etc. import kc/domain types like `Order`, `Money`); failed build here would catch any kc/domain API drift.
- **Acceptance**: standalone build green; risk-check tests pass.
- **Time**: ~15 minutes (larger reverse-dep surface = more verification time).
- **Inter-PR coupling**: depends on 4.1. **Parallel-safe** with 4.2, 4.3, 4.5-4.7.

### PR 4.5 — `chore(kc/instruments): bump kc/domain require + replace`

- **Files**: `kc/instruments/go.mod` single edit. Empirical: kc/instruments `go.mod` at HEAD does NOT yet require kc/domain because it was extracted before the kc/domain extract; verifying the import surface — `grep -lE "kite-mcp-server/kc/domain" kc/instruments/*.go` — returns the actual edges.
- **Build verification**: standard gate.
- **Acceptance**: build green.
- **Time**: ~10 minutes.
- **Inter-PR coupling**: depends on 4.1 only. **Parallel-safe** with 4.2-4.4, 4.6-4.7.

### PR 4.6 — `chore(kc/{registry,users,scheduler,decorators,watchlist,templates,logger}): bump kc/domain in modules that import it`

- **Files**: 1-7 go.mod files depending on which already-extracted modules import kc/domain. Empirical preflight: `for m in kc/registry kc/users kc/scheduler kc/decorators kc/watchlist kc/templates kc/logger kc/i18n kc/legaldocs kc/isttz kc/money kc/audit kc/billing kc/instruments kc/riskguard broker; do echo "$m:"; grep -lE "kite-mcp-server/kc/domain" $m/*.go 2>/dev/null; done`. Only modules that actually import kc/domain need a go.mod bump.
- **Build verification**: per-module `go build ./...` + `GOWORK=off go build ./...`. The "small batch" PR — keeps each individual module's bump trivially revertable.
- **Acceptance**: all touched modules standalone-buildable.
- **Time**: ~20-30 minutes (depends on 1-7 modules; majority likely don't need kc/domain).
- **Inter-PR coupling**: depends on 4.1 only. **Parallel-safe** with 4.2-4.5, 4.7.

### PR 4.7 — `test(kc/domain): standalone test suite + cycle-detection`

- **Files**: `kc/domain/cycle_detection_test.go` (new ~30 LOC). Test pattern mirrors `redundancy-audit.md` F1+F2 recommendation: use `go list -deps github.com/zerodha/kite-mcp-server/kc/domain` programmatically and assert it does NOT include `github.com/zerodha/kite-mcp-server` (root module). This pins the module-clean property forever.
- **Build verification**: `cd kc/domain && go test -run TestCycleDetection -count=1` plus root `go test ./kc/domain/...`. The 15 existing test files (4,229 LOC) should pass without any modification — they already use the package's `package domain` declaration.
- **Acceptance**: cycle-detection test green; existing 15 test files pass standalone via `cd kc/domain && go test ./...`.
- **Time**: ~30 minutes (write test + verify).
- **Inter-PR coupling**: depends on 4.1; can ship parallel with 4.2-4.6 (test only touches kc/domain). **Parallel-safe.**

### PR 4.8 — `chore: deploy v203 with kc/domain extracted as own module`

- **Files**: zero (deploy-only PR; if changelog discipline requires, single-line `CHANGELOG.md` entry).
- **Build verification**: deploy gate — `flyctl deploy -a kite-mcp-server`; post-deploy curl `https://kite-mcp-server.fly.dev/healthz` reports current build SHA + tools count grep `mcp.NewTool` count = unchanged. **Tool-count-drift CI must be green.**
- **Acceptance**: production deploy completes; tools=111 unchanged (or current count, whichever applies post-Tier-2); healthz green; no error spike in logs over 30-minute observation window.
- **Time**: ~30 minutes (deploy + observation + sign-off).
- **Inter-PR coupling**: depends on 4.2-4.7 all merged + main branch green.

---

## Cross-PR Section

### Topological order

```
              ┌─→ PR 4.2 ─┐
              ├─→ PR 4.3 ─┤
PR 4.1 ───────┼─→ PR 4.4 ─┼──→ PR 4.8 (deploy)
              ├─→ PR 4.5 ─┤
              ├─→ PR 4.6 ─┤
              └─→ PR 4.7 ─┘
```

**Empirical observation**: PRs 4.2 through 4.7 are **all parallel-safe**. Each touches a different `go.mod` file (or, in 4.7's case, only kc/domain itself). At N=20 agent capacity per `fd603f3`, all 6 of 4.2-4.7 can ship simultaneously into a merge queue. **No PR ordering between 4.2-4.7 is required.**

PR 4.8 (deploy) requires all 4.2-4.7 merged and main green. That's the only hard sequential gate within this batch.

### Mid-Anchor checkpoint: when is the codebase deployable?

The codebase is **safely deployable** at any merge-step from 4.1 forward, because:

1. After PR 4.1 lands: `kc/domain` has its own `go.mod` but every consuming module still resolves it via root replace → root tree builds; per-module standalone builds unaffected (consuming modules haven't been told about the new path yet).
2. After PRs 4.2-4.6 land: each touched module has explicitly declared `kc/domain` as a dep. Both root + per-module GOWORK=off builds remain green.
3. After PR 4.7: cycle-detection test pins the property; all functional behavior unchanged.
4. After PR 4.8: production verified.

**Empirical conclusion**: there is no intermediate "broken-state" checkpoint. Each PR is independently deployable. **Production can deploy after any PR if needed for unrelated reasons.**

### Risk floor: smallest committable PR 4.2

If the team wants the absolutely smallest PR to validate the chain works, **PR 4.2 (kc/audit go.mod bump)** is the floor:

- **LOC delta**: ~3 lines added to `kc/audit/go.mod` (1 require line + 1 replace line + blank-line formatting). One file. Fully auto-generable (no design judgment).
- **Review time**: 2-3 minutes to read 3 lines + verify CI green.
- **Revert profile**: 1-line revert if anything breaks. Zero behavior risk.
- **Build verification**: standard 4-command gate (~5 minutes).

**Total time PR 4.2**: ~10 minutes including CI wait.

This is the empirical floor. If PR 4.2 doesn't break anything, the entire 4.3-4.7 batch can ship at the same throughput level.

### Total Anchor 4 calendar at N=20 agent capacity

- PR 4.1: ~30 minutes (architecture agent in flight)
- PRs 4.2-4.7: ~3 hours total elapsed if parallel (single review queue may serialize to ~6 hours)
- PR 4.8: ~30 minutes deploy + observation

**Best case at N=20**: half a day. **Realistic with reviewer queue serialization**: 1-2 working days. **Matches `7ac9d34` estimate of 3 days for the entire Anchor 4** (which budgeted Phase 0/1 design + cleanup).

---

## Verification matrix for "Anchor 4 done"

- [ ] `go.work` lists `./kc/domain` in `use ()` block
- [ ] Root `go.mod` has `replace github.com/zerodha/kite-mcp-server/kc/domain => ./kc/domain`
- [ ] `kc/domain/go.mod` exists with module path `github.com/zerodha/kite-mcp-server/kc/domain`
- [ ] `cd kc/domain && go build ./... && GOWORK=off go build ./...` both green
- [ ] `cd kc/domain && go test ./... -count=1` green
- [ ] Cycle-detection test `kc/domain/cycle_detection_test.go` exists + green
- [ ] All 14 reverse-dep packages still build via root `go build ./...`
- [ ] All consuming modules with their own go.mod (kc/audit, kc/billing, kc/riskguard, kc/instruments, etc.) explicitly require + replace kc/domain
- [ ] Tool count `grep -rE "mcp\.NewTool\(" mcp/*.go | grep -vE "_test" | wc -l` unchanged
- [ ] Production deploy v203+ green; healthz reports new SHA; tool-count-drift CI green
- [ ] Dockerfile pre-stages kc/domain manifest (`COPY kc/domain/go.mod kc/domain/go.sum* kc/domain/`)

---

**End. Doc-only. No code mutated. No tests run.**

Last section completed: **Verification matrix** (final).
