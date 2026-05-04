# Tier 5 + Anchor 6 Pre-Stage

**Date**: 2026-05-04
**HEAD audited**: `d4bb3e6` (PR 4.1 landed; 20/24 modules extracted; Tier 3 COMPLETE — kc/cqrs, kc/ticker, kc/eventsourcing all extracted)
**Builds on**: `7ac9d34 b-full-pr-shapes.md`, `fd603f3 b-full-20-agent-reframe.md`, `dd04545 anchor-4-design.md`, `ffffccc anchor-5-design.md`
**Charter**: read-only research. Doc-only. NO code changes.

**State at HEAD**: 20 modules in `go.work` (broker + kc/{audit, billing, cqrs, decorators, domain, eventsourcing, i18n, instruments, isttz, legaldocs, logger, money, registry, riskguard, scheduler, templates, ticker, users, watchlist}). 20 entries in root replace block.

---

## Q1 — Tier 5 Inventory + Extraction Plan

Empirical candidates verified at HEAD `d4bb3e6`:

| Candidate | Prod files | go.mod? | kc/* deps | Reverse-deps | Module-clean? | Notes |
|---|---:|:-:|---|---:|:-:|---|
| `testutil/` | 3 | No | **none** | 15 | **YES** | Cleanest leaf — zero internal deps, easiest extract |
| `oauth/` | 11 | No | kc/templates, kc/users (both extracted) | 92 | **YES** | Module-clean once those 2 deps are go.mod-extracted (which they are at HEAD) |
| `kc/aop/` | 3 (`aop.go`, `aop_test.go`, `example_audit_riskguard.go`) | No | (build-tag-gated `//go:build research` per ADR-0008) | 0 in production paths | **YES** | Research-only; goes-with-the-research-builds. Smallest & lowest-risk |
| `plugins/{example,rolegate,telegramnotify}` | 3+ | No (none) | kc parent, mcp, oauth | 0 (loaded at runtime via plugin manifest) | **NO** | Imports `kc` parent — blocked on Anchor 6 (kc-root shrink) before extract |

**Tier-5 verdict**: 3 of 4 candidates extractable today. `plugins/` is **blocked on Anchor 6** because plugin packages import the `kc` parent package directly (`grep -hrE "^\s+\"github" plugins/*/*.go` returns `kite-mcp-server/kc`). Move plugins into Tier 6 (post-Anchor-6).

### Per-candidate extraction shape (mirrors prior Tier-1-4 precedent)

**Tier-5 PR T5.1 — `chore(modules): extract testutil as separate module`**
- **Files**: NEW `testutil/go.mod` (~10 LOC), update `go.work` use block, add root `go.mod` replace, add Dockerfile manifest pre-stage.
- **External deps**: stdlib only (zero `kite-mcp-server/*` imports verified via empirical grep).
- **Reverse-deps to verify post-extract**: 15 files across packages — `cd testutil && go build ./... && GOWORK=off go build ./...` and root `go build ./...` for the 15 reverse-dep files.
- **Time**: ~15 min. Smallest of all remaining extracts.
- **Risk**: lowest in repo — zero internal-dep surface.

**Tier-5 PR T5.2 — `chore(modules): extract oauth as separate module`**
- **Files**: NEW `oauth/go.mod` (~15 LOC, with require + replace for kc/templates + kc/users), update `go.work`, add root replace, Dockerfile manifest.
- **External deps**: kc/templates (extracted at `2f04069`), kc/users (extracted at `f32629f`). Both already module-clean.
- **Reverse-deps**: 92 files → wide blast radius for compilation. Mitigation: PR includes per-package smoke test of all 92 reverse-dep files via single `go build ./...`.
- **Time**: ~30 min. Medium complexity.
- **Risk**: medium (92 reverse-deps); pattern proven by broker/ extraction at `5d74acf` (143 reverse-deps successfully).

**Tier-5 PR T5.3 — `chore(modules): extract kc/aop as separate module`**
- **Files**: NEW `kc/aop/go.mod` (~8 LOC), update `go.work`, add root replace, Dockerfile manifest. Build tag `//go:build research` already in place at `kc/aop/aop.go:1`.
- **External deps**: kc/audit, kc/riskguard (per `example_audit_riskguard.go`); both extracted.
- **Reverse-deps**: 0 in production. Build-tag-gated.
- **Time**: ~10 min. Trivial because of build-tag isolation.
- **Risk**: negligible — research-only code path.

**Tier-5 total time at N=20**: ~55 min sequential (or ~30 min parallel if 3 agents pick up in parallel — they touch separate files).

**Plugins extraction deferred to Tier 6** (post-Anchor-6). After Anchor 6 shrinks kc-root to assembly-only, `plugins/` consumers that currently reach `kc.Manager` directly will route through `app/providers/*` ports, breaking the `kc` parent dependency. Then plugins becomes module-clean.

---

## Q2 — Anchor 6 PR-Level Design (15 PRs)

**Empirical baseline at HEAD**:
- `kc/manager_accessors.go`: 121 LOC, **16 named accessors** (CredentialSvc, SessionSvc, PortfolioSvc, OrderSvc, AlertSvc, FamilyService, LoggerPort, SetFamilyService, CommandBus, QueryBus, SessionManager, ManagedSessionSvc, SessionSigner, UpdateSessionSignerExpiry, SetMCPServer, MCPServer)
- `kc.Manager` struct: ~30 fields including 7 Service objects, 5 facade services (StoreRegistry, EventingService, BrokerServices, SchedulingService, SessionLifecycleService), 18 raw stores/clients
- `app/providers/`: 14 existing recipes (alertdb, audit, audit_init, audit_middleware, billing, event_dispatcher, family, lifecycle, logger, manager, mcpserver, riskguard, scheduler, telegram)
- Manager method total: 52

**Strategy**: per `7ac9d34`, extract one Manager method's underlying dep into an `app/providers/X.go` Fx provider, update consumers to take the dep via Fx, then delete the Manager method. Each method = 1 PR pair (1 add + 1 delete). 7 method-pairs + 1 final cleanup = 15 PRs.

### Per-PR Design

#### PR 6.1 — `feat(app/providers): provide CredentialSvc directly via Fx`
- **Files**: NEW `app/providers/credential_svc.go` (~50 LOC). The provider returns `*kc.CredentialService` (concrete) wired from the existing kc/credential_service.go construction path.
- **Build verification**: `go build ./... && GOWORK=off go build ./...` + `go test ./app/providers/... -count=1`.
- **Acceptance**: Fx graph wires CredentialSvc; existing `m.CredentialSvc()` callers untouched yet.
- **Time**: ~25 min.
- **Inter-PR coupling**: depends on Anchor 5 PR 5.8 (ports leaf-stability); independent of other 6.X PRs.

#### PR 6.2 — `refactor(kc): delete Manager.CredentialSvc() accessor`
- **Files**: `kc/manager_accessors.go` (delete 3-LOC method); update consumers (most via ToolHandlerDeps → already abstracted; ~3 files at most need direct edit).
- **Build verification**: same gate. **Critical**: production deploy must verify before next 6.X-pair starts.
- **Acceptance**: `grep -E "m\.CredentialSvc\(\)" --include='*.go' -r .` returns 0 matches; one full deploy cycle (v204+) green for 24 hours.
- **Time**: ~20 min refactor + 24-hour deploy observation gate.
- **Inter-PR coupling**: depends on PR 6.1 + 1 deploy cycle.

#### PR 6.3 — `feat(app/providers): provide SessionSvc directly via Fx`
- **Files**: NEW `app/providers/session_svc.go` (~50 LOC).
- **Build verification**: same gate.
- **Acceptance**: Fx wires SessionSvc.
- **Time**: ~25 min.
- **Inter-PR coupling**: independent of 6.1/6.2; depends on Anchor 5 PR 5.8. **Parallel-safe with 6.1.**

#### PR 6.4 — `refactor(kc): delete Manager.SessionSvc() accessor`
- **Files**: `kc/manager_accessors.go` (delete 3-LOC method); ~5 consumers need direct edit (mcp/setup_tools.go, mcp/alert_tools.go, kc/callback_handler.go, kc/usecases/setup_usecases.go, mcp/admin_server_tools.go per Anchor 5 design).
- **Build verification**: same gate; deploy cycle observation.
- **Acceptance**: `grep -E "m\.SessionSvc\(\)"` returns 0 matches.
- **Time**: ~25 min + 24-hour observation.
- **Inter-PR coupling**: depends on PR 6.3 + 1 deploy cycle.

#### PR 6.5 — `feat(app/providers): provide PortfolioSvc directly via Fx`
- **Files**: NEW `app/providers/portfolio_svc.go` (~50 LOC).
- **Time**: ~25 min.
- **Inter-PR coupling**: depends on Anchor 5 PR 5.8. **Parallel-safe with 6.1, 6.3.**

#### PR 6.6 — `refactor(kc): delete Manager.PortfolioSvc() accessor`
- **Files**: `kc/manager_accessors.go` (delete 3-LOC method); ~3 consumers updated.
- **Time**: ~20 min + 24-hour observation.
- **Inter-PR coupling**: depends on PR 6.5 + 1 deploy cycle.

#### PR 6.7 — `feat(app/providers): provide OrderSvc directly via Fx`
- **Files**: NEW `app/providers/order_svc.go` (~50 LOC).
- **Time**: ~25 min.
- **Inter-PR coupling**: depends on Anchor 5 PR 5.7 (which left `*kc.OrderService` reference in kc/ports/order.go; this PR breaks that final dependency).

#### PR 6.8 — `refactor(kc): delete Manager.OrderSvc() accessor`
- **Files**: `kc/manager_accessors.go` (delete); ~6 consumers updated. **At this PR, kc/ports/order.go can drop its remaining kc-parent import** — opportunistic cleanup.
- **Time**: ~30 min + 24-hour observation.
- **Inter-PR coupling**: depends on PR 6.7 + 1 deploy cycle.

#### PR 6.9 — `feat(app/providers): provide AlertSvc directly via Fx`
- **Files**: NEW `app/providers/alert_svc.go` (~50 LOC).
- **Time**: ~25 min.
- **Inter-PR coupling**: depends on Anchor 5 PR 5.8. **Parallel-safe with 6.1/6.3/6.5/6.7.**

#### PR 6.10 — `refactor(kc): delete Manager.AlertSvc() accessor`
- **Files**: `kc/manager_accessors.go` (delete); ~4 consumers updated.
- **Time**: ~20 min + 24-hour observation.
- **Inter-PR coupling**: depends on PR 6.9 + 1 deploy cycle.

#### PR 6.11 — `feat(app/providers): consolidate CommandBus + QueryBus`
- **Files**: NEW `app/providers/cqrs.go` (~70 LOC; provides both buses).
- **Time**: ~30 min.
- **Inter-PR coupling**: independent. **Parallel-safe with all earlier 6.X.**

#### PR 6.12 — `refactor(kc): delete Manager.{Command,Query}Bus() accessors`
- **Files**: `kc/manager_accessors.go` (delete 6 LOC = 2 methods).
- **Time**: ~20 min + 24-hour observation.
- **Inter-PR coupling**: depends on PR 6.11 + 1 deploy cycle.

#### PR 6.13 — `feat(app/providers): consolidate Session{Manager,Signer} + ManagedSessionSvc`
- **Files**: NEW `app/providers/session_infra.go` (~80 LOC; provides 4 session-infra deps).
- **Time**: ~30 min.
- **Inter-PR coupling**: independent. **Parallel-safe.**

#### PR 6.14 — `refactor(kc): delete 4 session-infra Manager methods`
- **Files**: `kc/manager_accessors.go` (delete `SessionManager`, `ManagedSessionSvc`, `SessionSigner`, `UpdateSessionSignerExpiry` — 12 LOC).
- **Time**: ~30 min + 24-hour observation.
- **Inter-PR coupling**: depends on PR 6.13 + 1 deploy cycle.

#### PR 6.15 — `refactor(kc): collapse manager.go to <100 LOC; delete kc/interfaces.go`
- **Files**: `kc/manager.go` (drop unused fields + methods; collapse from 403 → ~80 LOC), `kc/interfaces.go` (DELETE; all interface declarations relocated by Anchor 5 + Anchor 6 phases). Verify `manager_accessors.go` is now empty or near-empty (target: 1-2 remaining methods like `SetMCPServer` / `MCPServer`).
- **Build verification**: full integration test pass; one full deploy cycle.
- **Acceptance**: `wc -l kc/manager.go` < 100; `kc/interfaces.go` does not exist; tools=111 unchanged.
- **Time**: ~2 hours including verification + observation.
- **Inter-PR coupling**: depends on PRs 6.2/6.4/6.6/6.8/6.10/6.12/6.14 — all 7 deletion PRs must be merged + deployed.

---

## Cross-PR Section

### Topological Order at N=20

```
                          Anchor 5 (PR 5.8) — kc/ports leaf-stability
                                       │
       ┌───────┬───────┬───────┬───────┼───────┬───────┐
      6.1     6.3     6.5     6.7     6.9    6.11    6.13   ← 7 ADD-PROVIDER PRs (all parallel)
       │       │       │       │       │       │       │
      6.2     6.4     6.6     6.8     6.10    6.12    6.14  ← 7 DELETE-METHOD PRs (each waits 1 deploy)
                                       │
                                      6.15  ← FINAL CLEANUP (waits all 7 deletes)
```

**Maximum parallelism**: 7 simultaneous add-provider PRs in Wave C-1. Then each delete waits 1 deploy cycle (24h observation gate per `7ac9d34`).

**Calendar at N=20**:
- Wave C-1 (7 add-providers parallel): ~1 day calendar (parallel review queue + CI capacity)
- 7 deploy-and-delete cycles: 7 × 24h observation = **7 days minimum sequential** (this is the Anchor 6 critical path; cannot parallelize observation gates)
- PR 6.15 final cleanup: ~1-2 days
- **Anchor 6 total: 9-10 days calendar at N=20** (vs `7ac9d34`'s 8-12 weeks at solo scale)

### Mid-Anchor Checkpoints

The codebase is **safely deployable at every PR boundary**:
- After each 6.X (add): Manager retains the old method PLUS new Fx provider exists. Backward-compatible.
- After each 6.X+1 (delete): Manager method removed; consumers route through Fx providers. Forward-compatible.
- 24-hour observation gate between PRs catches any production regression.

**Risk floor (smallest first PR)**: **PR 6.1** (`feat(app/providers): provide CredentialSvc directly via Fx`). 1 new file (~50 LOC), purely additive, zero deletion, zero behavior change. Trivial revert if needed. Validates the Fx-recipe pattern works for the simplest service.

### Coordination with Anchor 2 (app/providers extract)

**Per `fd603f3`**: Anchor 2 should execute *between Anchor 5 and Anchor 6* so that Anchor 6's 7 new providers (6.1, 6.3, 6.5, 6.7, 6.9, 6.11, 6.13) land in the extracted `app/providers/` module from day one rather than growing the in-tree app/providers/ directory.

**Recommendation**: dispatch **Anchor 2 (~6 PRs / 5 hours / 3-5 days calendar per `7ac9d34`)** before any Anchor 6 PR starts. Specifically:
- Anchor 2 PR sequence (per `7ac9d34`): 2.1 add go.mod, 2.2 add to go.work, 2.3 Dockerfile, 2.4 require kc + replace, 2.5 standalone test, 2.6 deploy.
- After Anchor 2 PR 2.6 deploys cleanly, Anchor 6 starts with PR 6.1 modifying the now-extracted app/providers/ module.
- This is a **Wave B-3 ordering constraint** within the broader B-Full plan.

---

## Empirical Calendar Summary

| Phase | Calendar at N=20 | Critical path |
|---|---:|---|
| Tier 5 (T5.1 + T5.2 + T5.3) | ~1 day | Parallel-safe; oauth/ blast radius is the throttle |
| Anchor 2 (6 PRs) | ~3-5 days | Sequential dependency chain |
| Anchor 6 add-providers (7 PRs) | ~1 day | Wave C-1 parallel |
| Anchor 6 delete-methods (7 × 24h) | ~7 days minimum | Observation gates serialize |
| Anchor 6 final cleanup (PR 6.15) | ~1-2 days | After all 7 deletes |
| **Total Tier 5 + A2 + A6** | **~13-16 days calendar** | |

The 24-hour observation gate × 7 cycles = 7 days inherent serialization is the dominant Anchor 6 critical path. **Cannot be compressed by adding more agents.** The only way to reduce: shorten observation from 24h to 4h (risky — production regressions can lag).

---

**End. Doc-only. No code mutated. No tests run.**

Last section completed: **Empirical calendar summary** (final).
