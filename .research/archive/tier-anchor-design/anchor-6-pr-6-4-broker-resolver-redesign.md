# Anchor 6 PR 6.4 Redesign — Narrow `BrokerResolverProvider` for SessionSvc Deletion

**Date**: 2026-05-04
**HEAD audited**: `5514fa3` (Anchor 6 PR 6.2 landed — `Manager.CredentialSvc()` deleted via Fx-direct injection)
**Builds on**: `5fbd4a1 tier-5-and-anchor-6-pre-stage.md` (15-PR Anchor 6 spec); empirical pushback from execution agent on PR 6.4
**Charter**: read-only research. Doc-only. NO code changes.

---

## Empirical correction to brief

The brief cited `kc/manager_interfaces.go:246` as the compile-time satisfaction assertion site (`var _ BrokerResolverProvider = (*Manager)(nil)`). **At HEAD `5514fa3`**: `grep -nE "var _ \w+ = \(\*Manager\)\(nil\)" kc/manager_interfaces.go` returns **zero matches**. The asserts have been removed (likely during prior kc/ports cycle-break work in Anchor 5). 

**Net effect**: deleting `Manager.SessionSvc()` will not break a single explicit assertion — it will break **structural-typing satisfaction at the 7 callsites** that consume `kc.BrokerResolverProvider`. The repair surface is the callsites + the interface definition, not a separate assertion file.

---

## Q1 — Empirical method-usage analysis on `*SessionService`

Verified via `grep -nE "\.SessionSvc\(\)\.\w+" mcp/*.go app/*.go kc/*.go mcp/common/*.go` at HEAD:

| Callsite | Code | Methods used from `*SessionService` |
|---|---|---|
| `mcp/ext_apps.go:992` | `manager.SessionSvc().GetBrokerForEmail(email)` | **`GetBrokerForEmail(string) (broker.Client, error)`** |
| `kc/manager_commands_admin.go:458` | `m.SessionSvc().GetBrokerForEmail(email)` | **`GetBrokerForEmail(string)`** |
| `app/http.go:717` | `app.kcManager.SessionSvc() == nil` | nil-check; needs the accessor itself, not a method |
| `app/http.go:720` | `app.kcManager.SessionSvc().HasBrokerFactory()` | **`HasBrokerFactory() bool`** |
| `app/wire.go:582` | `kc.FillWatcherResolverFromSessionSvc(kcManager.SessionSvc())` | passes whole `*SessionService` to a kc-package helper (`FillWatcherResolverFromSessionSvc(s *SessionService) FillWatcherBrokerResolver` per `kc/fill_watcher.go:102`) |
| `mcp/ext_apps.go:160-162` | `kc.BrokerResolverProvider` (interface embed) | transitive via `:992` ⇒ **`GetBrokerForEmail`** |
| `mcp/common/handler_deps.go:61` | `BrokerResolver kc.BrokerResolverProvider` field | consumed by `BrokerResolver` callers in mcp/ — same as above ⇒ **`GetBrokerForEmail`** |
| `mcp/common/order_deps.go:13` | `BrokerResolver kc.BrokerResolverProvider` field | consumed by order-deps consumers — same ⇒ **`GetBrokerForEmail`** |

**Empirical method set actually used**: only **2 methods from `*SessionService`** (`GetBrokerForEmail`, `HasBrokerFactory`). Plus 1 escape hatch (`FillWatcherResolverFromSessionSvc` in `app/wire.go` which passes the concrete value).

**Recommended narrow interface** (replaces line 100-102 of `kc/manager_interfaces.go`):

```go
// BrokerResolverProvider exposes the narrow contract for resolving a
// broker.Client by email. Two methods cover all 7 production callsites
// (verified empirically pre-PR-6.4).
type BrokerResolverProvider interface {
    GetBrokerForEmail(email string) (broker.Client, error)
    HasBrokerFactory() bool
}
```

The interface drops dependence on `*SessionService` concrete type entirely.

---

## Q2 — Migration plan (PR 6.4 retry)

### Step 1 — Update `BrokerResolverProvider` definition

- File: `kc/manager_interfaces.go:95-102`
- Diff sketch:
  ```diff
  -type BrokerResolverProvider interface {
  -    SessionSvc() *SessionService
  -}
  +type BrokerResolverProvider interface {
  +    GetBrokerForEmail(email string) (broker.Client, error)
  +    HasBrokerFactory() bool
  +}
  ```
- This is **semantically additive at the consumer level** (callsites get methods they already chain to via `.SessionSvc().X()`).

### Step 2 — Make `*Manager` satisfy the new narrow interface

Add 2 passthrough methods on Manager that delegate to the existing `sessionSvc` field (which Manager retains as a private field):

```go
// kc/manager_accessors.go (or new file)
func (m *Manager) GetBrokerForEmail(email string) (broker.Client, error) {
    return m.sessionSvc.GetBrokerForEmail(email)
}
func (m *Manager) HasBrokerFactory() bool {
    return m.sessionSvc != nil && m.sessionSvc.HasBrokerFactory()
}
```

This makes `*Manager` structurally satisfy `BrokerResolverProvider` without exposing `SessionSvc()` publicly.

### Step 3 — Update 7 callsites

| Callsite | Before | After |
|---|---|---|
| `mcp/ext_apps.go:992` | `manager.SessionSvc().GetBrokerForEmail(email)` | `manager.GetBrokerForEmail(email)` |
| `kc/manager_commands_admin.go:458` | `m.SessionSvc().GetBrokerForEmail(email)` | `m.GetBrokerForEmail(email)` |
| `app/http.go:717-720` | `app.kcManager.SessionSvc() == nil` + `.HasBrokerFactory()` | `app.kcManager == nil` (drop the SessionSvc nil-check; the new HasBrokerFactory() handles `sessionSvc==nil` internally) + `app.kcManager.HasBrokerFactory()` |
| `app/wire.go:582` | `kc.FillWatcherResolverFromSessionSvc(kcManager.SessionSvc())` | **Keep `kcManager.SessionSvc()` as private accessor for THIS one callsite.** OR refactor `FillWatcherResolverFromSessionSvc` to take a `BrokerResolverProvider`. **Recommendation: refactor `FillWatcherResolverFromSessionSvc` → `FillWatcherResolverFromBroker`** taking the narrow interface. ~30-line follow-up. |
| `mcp/ext_apps.go:160-162` (interface embed) | unchanged — embedded interface still works | unchanged |
| `mcp/common/handler_deps.go:61` (field type) | unchanged — `BrokerResolver kc.BrokerResolverProvider` | unchanged (interface contract changed, callers consume new methods) |
| `mcp/common/order_deps.go:13` (field type) | unchanged | unchanged |

### Step 4 — Delete `Manager.SessionSvc()` accessor

- File: `kc/manager_accessors.go` (or wherever it's currently declared)
- Action: delete the public accessor method. The private `sessionSvc` field on Manager remains, accessible to internal Manager methods and the new `GetBrokerForEmail`/`HasBrokerFactory` passthroughs.
- **Conditional**: depends on Step 3's Anchor-`wire.go:582` decision. If `FillWatcherResolverFromSessionSvc` is refactored, deletion proceeds cleanly. If kept as-is, an internal package-private accessor is required — acceptable trade-off, the goal is removing the *public* Manager surface.

---

## Q3 — PR 6.4 retry estimate

**Original brief**: 30 min.
**Adjusted realistic**: **~75 min**.

Breakdown:
- Step 1 (interface change): ~5 min — single struct edit.
- Step 2 (Manager passthroughs): ~10 min — write 2 methods, add tests if absent.
- Step 3 (3 distinct callsite patterns × ~10 min each): ~30 min — straightforward find-and-replace. The `app/wire.go:582` callsite needs the helper-function refactor decision; budget +15 min if we do `FillWatcherResolverFromBroker` rename.
- Step 4 (delete `SessionSvc()` accessor + verify all callers compile): ~10 min.
- Build verification + test sweep: ~10 min.
- Buffer for surprises (e.g., a test file that mocks `BrokerResolverProvider` and would need re-mocking with the new method shape): ~10 min.

**Doubles the original estimate** — the interface narrowing is mechanically simple but touches 7 callsites and 1 helper-function refactor.

---

## Q4 — Cascade impact: do the OTHER 5 delete-method PRs have similar blockers?

Empirical inventory of all `*Provider` interfaces declaring **service-type accessors** at HEAD `5514fa3` (`grep -nE "^type \w+Provider interface" kc/manager_interfaces.go` + body inspection):

| Provider Interface | Method signature | Returns concrete service? | Anchor 6 PR affected | Blocker? |
|---|---|:-:|---|:-:|
| `TokenStoreProvider` | `TokenStore() *KiteTokenStore` | YES | (post-Anchor-6 cleanup) | LOW — narrow already by Phase B/D port migration |
| `CredentialStoreProvider` | `CredentialStore() *KiteCredentialStore` | YES | (post) | LOW |
| `TelegramStoreProvider` | similar | YES | (post) | LOW |
| `WatchlistStoreProvider` | similar | YES | (post) | LOW |
| `UserStoreProvider` | similar | YES | (post) | LOW |
| `RegistryStoreProvider` | similar | YES | (post) | LOW |
| `AuditStoreProvider` | similar | YES | (post) | LOW |
| `BillingStoreProvider` | similar | YES | (post) | LOW |
| `TickerServiceProvider` | similar | YES | (post) | LOW |
| `PaperEngineProvider` | similar | YES | (post) | LOW |
| `RiskGuardProvider` | similar | YES | (post) | LOW |
| `EventDispatcherProvider` | similar | YES | (post) | LOW |
| `MCPServerProvider` | similar | YES | (post) | LOW |
| **`BrokerResolverProvider`** | **`SessionSvc() *SessionService`** | **YES — service type** | **PR 6.4** | **HIGH (this dispatch)** |
| `AppConfigProvider` | not service-typed | N/A | N/A | none |
| `CommandBusProvider` | not service-typed | N/A | N/A | none |
| `QueryBusProvider` | not service-typed | N/A | N/A | none |

Now mapping to Anchor 6 deletion PRs from `5fbd4a1`:

| Anchor 6 PR | Method to delete | *Provider interface coupling? | Same blocker pattern? |
|---|---|---|:-:|
| 6.2 (DONE in `5514fa3`) | `Manager.CredentialSvc()` | None — `*CredentialService` not exposed via a Provider interface that callers consume | **No** (already shipped clean) |
| **6.4** | `Manager.SessionSvc()` | **`BrokerResolverProvider` consumes via `SessionSvc()`** | **Yes — THIS dispatch** |
| 6.6 | `Manager.PortfolioSvc()` | Empirical search: `grep -E "PortfolioSvc\b" kc/manager_interfaces.go` returns zero — no `*Provider` interface exposes it | **No likely blocker** |
| 6.8 | `Manager.OrderSvc()` | `grep -E "OrderSvc\b" kc/manager_interfaces.go` returns zero | **No likely blocker** |
| 6.10 | `Manager.AlertSvc()` | `grep -E "AlertSvc\b" kc/manager_interfaces.go` returns zero | **No likely blocker** |
| 6.12 | `Manager.FamilyService()` | `grep -E "FamilyService\b" kc/manager_interfaces.go` returns zero | **No likely blocker** |
| 6.14 | `Manager.LoggerPort()` | `grep -E "LoggerPort\b" kc/manager_interfaces.go` returns zero | **No likely blocker** |

**Net cascade verdict**: PR 6.4's blocker is **unique among the 7 delete-method PRs**. The other 6 (6.2 done; 6.6/6.8/6.10/6.12/6.14 pending) do not have analogous `*Provider`-interface couplings. **PRs 6.6-6.14 should proceed with the original 30-min budget.**

**However**: each of 6.6/6.8/6.10/6.12/6.14 may have *callsite-level* coupling (consumers using the service via the public accessor). Verification recipe per PR: `grep -nE "\.{ServiceName}\(\)\.\w+" mcp/*.go app/*.go kc/*.go mcp/common/*.go | wc -l` before deletion. If count > 0, narrow callsites identically: provide passthrough methods on Manager, update consumers, then delete the accessor.

---

## Net Anchor 6 calendar update

- PR 6.4: was 30 min → now **75 min** (this dispatch).
- PRs 6.6, 6.8, 6.10, 6.12, 6.14: unchanged at 30 min each (no `*Provider`-interface coupling per Q4).
- 24h observation gates unchanged.

**Anchor 6 total at N=20**: still ~9-10 days calendar (the observation gates dominate; PR 6.4's extra 45 min does not cross a calendar-day boundary).

**B-Full total**: still ~21-26 days at N=20 per `04e069a` final tally.

**Green-light recommendation**: dispatch PR 6.4 retry with the narrow-interface plan. Cycle is real but solvable; +45-min mechanical cost.

---

**End. Doc-only. No code mutated. No tests run.**

Last section completed: **Net Anchor 6 calendar update** (final).
