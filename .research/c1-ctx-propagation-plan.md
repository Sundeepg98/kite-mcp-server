# C1 Context Propagation Plan — `app/adapters.go`

**Source-of-truth gap**: C1 (Pass 15 Go-idiom audit) — `app/adapters.go` dispatches commands with `context.Background()`, dropping the request-handler ctx. Cancellation/timeout/X-Request-ID don't propagate to dispatched commands.

**Status**: Catalogued in `.research/final-138-gap-catalogue.md` row C1 (high severity, 40 LOC). Phase placement: Sprint 2.

**Audited HEAD**: `57af60f` (line numbers below).

**Charter**: Read-only research deliverable. No source-file edits in this work product.

---

## Site-by-site enumeration

Line numbers are the **current HEAD `57af60f`** values, not the agent-state.md doc which references pre-commit positions (180, 220, 229, 263, 271, 278, 340, 372). Sites have shifted as Phase 2 commits landed. Map:

| Doc-line | HEAD-line | Method | Caller chain |
|---|---|---|---|
| 180 | 218 | `provisionUser` | `ExchangeRequestToken` / `ExchangeWithCredentials` |
| 220 | 258 | `ExchangeRequestToken` (token cache) | `oauth/handlers_browser.go:58`, `handlers_callback.go:122` |
| 229 | 267 | `ExchangeRequestToken` (registry sync) | same as above |
| 263 | 301 | `ExchangeWithCredentials` (token cache) | `handlers_browser.go:56`, `handlers_callback.go:51,102`, `handlers_oauth.go:396` |
| 271 | 309 | `ExchangeWithCredentials` (credential store) | same as above |
| 278 | 316 | `ExchangeWithCredentials` (registry sync) | same as above |
| 340 | 378 | `SaveClient` | `oauth/stores.go:233,298,343` (`ClientStore.Register/RegisterKiteAPIKey/SaveClientWithSecret`) |
| 372 | 410 | `DeleteClient` | `oauth/stores.go:evictOldest`, callback failure paths |

---

### Site 1 — `provisionUser`, line 218

**Current signature**:
```go
func (a *kiteExchangerAdapter) provisionUser(email, kiteUID, displayName string) error {
    a.ensureBus()
    err := a.commandBus.Dispatch(context.Background(), cqrs.ProvisionUserOnLoginCommand{...})
```

**Caller chain**: `provisionUser` is called from `ExchangeRequestToken` (line 249) and `ExchangeWithCredentials` (line 291). Both already lack ctx. So Site 1's ctx availability depends on Sites 2-6 (the public methods on `KiteExchanger` interface) being fixed first.

**Proposed signature**:
```go
func (a *kiteExchangerAdapter) provisionUser(ctx context.Context, email, kiteUID, displayName string) error {
    a.ensureBus()
    err := a.commandBus.Dispatch(ctx, cqrs.ProvisionUserOnLoginCommand{...})
```

**Test impact**: `provisionUser` is unexported. Callers are within `app/adapters.go` only. Tests that build `kiteExchangerAdapter` literals + call `ExchangeRequestToken/WithCredentials` get the change transitively — no separate test signature update needed.

**LOC delta**: ~3 (signature + 2 callsites in same file).

---

### Sites 2-3 — `ExchangeRequestToken` token-cache + registry-sync, lines 258, 267

**Current signature** (line 236):
```go
func (a *kiteExchangerAdapter) ExchangeRequestToken(requestToken string) (string, error) {
```

**Method satisfies interface** `oauth.KiteExchanger` (`oauth/handlers.go:22-27`):
```go
type KiteExchanger interface {
    ExchangeRequestToken(requestToken string) (email string, err error)
    ExchangeWithCredentials(requestToken, apiKey, apiSecret string) (email string, err error)
    GetCredentials(email string) (apiKey, apiSecret string, ok bool)
    GetSecretByAPIKey(apiKey string) (apiSecret string, ok bool)
}
```

**Caller chain** (HTTP handlers — all have `r.Context()` available):
- `oauth/handlers_browser.go:58 email, err = h.exchanger.ExchangeRequestToken(requestToken)` — handler signature `func (h *Handler) handleBrowserLogin(w http.ResponseWriter, r *http.Request)`. `r.Context()` ready to thread.
- `oauth/handlers_callback.go:122 email, err := h.exchanger.ExchangeRequestToken(requestToken)` — same handler pattern.

**Proposed interface change** (in `oauth/handlers.go:22-27`):
```go
type KiteExchanger interface {
    ExchangeRequestToken(ctx context.Context, requestToken string) (email string, err error)
    ExchangeWithCredentials(ctx context.Context, requestToken, apiKey, apiSecret string) (email string, err error)
    GetCredentials(email string) (apiKey, apiSecret string, ok bool)
    GetSecretByAPIKey(apiKey string) (apiSecret string, ok bool)
}
```

`GetCredentials` / `GetSecretByAPIKey` stay ctx-less — they're cheap synchronous lookups against in-memory stores; ctx adds zero value there.

**Implementation update** (`app/adapters.go:236-277`):
```go
func (a *kiteExchangerAdapter) ExchangeRequestToken(ctx context.Context, requestToken string) (string, error) {
    // ...
    if err := a.provisionUser(ctx, email, result.UserID, result.UserName); err != nil {
        return "", err
    }
    // ...
    if dispErr := a.commandBus.Dispatch(ctx, cqrs.CacheKiteAccessTokenCommand{...}); dispErr != nil {
    // ...
    if dispErr := a.commandBus.Dispatch(ctx, cqrs.SyncRegistryAfterLoginCommand{...}); dispErr != nil {
```

**Caller updates** (both HTTP handlers):
```go
// oauth/handlers_browser.go:58
email, err = h.exchanger.ExchangeRequestToken(r.Context(), requestToken)
// oauth/handlers_callback.go:122
email, err := h.exchanger.ExchangeRequestToken(r.Context(), requestToken)
```

**Test impact**: 16 test files mention these methods. Compile-time breaks until updated. Mock implementations of `KiteExchanger` (e.g., `mockExchanger` types in `auth_edge_test.go`, `app_edge_test.go`, `server_oauth_test.go`) need their method signatures updated. Test bodies that call `adapter.ExchangeRequestToken("token")` need `ctx` arg — `context.Background()` in test scope is acceptable (test ctx is the unit-of-work).

**LOC delta**: ~8 (interface +1, adapter signature +1, 2 dispatch calls +2 chars each, 2 caller updates +2, mock-impl signature updates ×N test files +N). Estimate **15-20 LOC across files**.

---

### Sites 4-6 — `ExchangeWithCredentials` token-cache + cred-store + registry-sync, lines 301, 309, 316

**Same pattern as Sites 2-3** — method already in `KiteExchanger` interface; caller chain identical (HTTP handlers with `r.Context()`).

**Caller sites** (4 production):
- `oauth/handlers_browser.go:56`
- `oauth/handlers_callback.go:51`
- `oauth/handlers_callback.go:102`
- `oauth/handlers_oauth.go:396`

All handlers take `(w http.ResponseWriter, r *http.Request)` — `r.Context()` available.

**Implementation update** (`app/adapters.go:279-327`):
```go
func (a *kiteExchangerAdapter) ExchangeWithCredentials(ctx context.Context, requestToken, apiKey, apiSecret string) (string, error) {
    // ...
    if err := a.provisionUser(ctx, email, result.UserID, result.UserName); err != nil {
    // 3 Dispatch calls all use ctx
```

**LOC delta**: ~8 (signature +1, 3 dispatch calls +3 chars, 4 caller-side updates +4). Bundled with Sites 2-3 in the interface change PR.

---

### Site 7 — `SaveClient`, line 378

**Current signature** (line 376):
```go
func (a *clientPersisterAdapter) SaveClient(clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error {
```

**Method satisfies interface** `oauth.ClientPersister` (`oauth/stores.go:111`):
```go
type ClientPersister interface {
    SaveClient(clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error
    LoadClients() ([]*ClientLoadEntry, error)
    DeleteClient(clientID string) error
}
```

**Caller chain** (3 production sites in `oauth/stores.go`):
- Line 233: `s.persister.SaveClient(...)` inside `ClientStore.Register` (called by dynamic-client-registration HTTP handler in `oauth/handlers_dynamic_registration.go` — needs verification)
- Line 298: inside `ClientStore.RegisterKiteAPIKey` (admin-side seeding)
- Line 343: inside `ClientStore.SaveClientWithSecret` (mcp-remote `--static-oauth-client-info` path)

The `ClientStore` methods themselves don't currently take ctx. **This is the deeper plumbing problem — propagating ctx requires:**
1. Update `ClientPersister` interface in `oauth/stores.go:111-114` to take ctx.
2. Update `ClientStore.Register/RegisterKiteAPIKey/SaveClientWithSecret/evictOldest` to take ctx and pass through.
3. Update HTTP handlers calling those `ClientStore` methods to pass `r.Context()`.
4. Update `localOAuthClientStore.SaveClient/DeleteClient` (`app/adapters_local_bus.go:266,269`) for test wiring.

**Proposed interface change** (`oauth/stores.go:111-114`):
```go
type ClientPersister interface {
    SaveClient(ctx context.Context, clientID, clientSecret, redirectURIsJSON, clientName string, createdAt time.Time, isKiteKey bool) error
    LoadClients() ([]*ClientLoadEntry, error)
    DeleteClient(ctx context.Context, clientID string) error
}
```

**LOC delta**: ~25 across `oauth/stores.go` (interface + 3-4 methods + 3 caller sites), `oauth/handlers_*.go` (HTTP wiring), `app/adapters.go:376-386`, `app/adapters_local_bus.go:266`. **Site 7 + Site 8 are jointly larger than Sites 1-6 combined.**

---

### Site 8 — `DeleteClient`, line 410

**Current signature** (line 408):
```go
func (a *clientPersisterAdapter) DeleteClient(clientID string) error {
```

**Caller chain** — `ClientStore.evictOldest` (line ~194 of `stores.go` per Pass 22 grep), plus failure-path cleanup. evictOldest is called from `Register` when at capacity. So Site 8's ctx availability is downstream of Site 7's interface change.

**LOC delta**: ~8 (bundled with Site 7's interface change).

---

## Summary table

| Site | Line (HEAD `57af60f`) | Method | Interface | Test files touched | LOC delta |
|---|---|---|---|---|---|
| 1 | 218 | `provisionUser` | (private) | 0 | 3 |
| 2 | 258 | `ExchangeRequestToken` (token cache) | `KiteExchanger` | ~6 | bundled |
| 3 | 267 | `ExchangeRequestToken` (registry sync) | `KiteExchanger` | ~6 | bundled |
| 4 | 301 | `ExchangeWithCredentials` (token cache) | `KiteExchanger` | ~6 | bundled |
| 5 | 309 | `ExchangeWithCredentials` (cred store) | `KiteExchanger` | ~6 | bundled |
| 6 | 316 | `ExchangeWithCredentials` (registry sync) | `KiteExchanger` | ~6 | bundled |
| 7 | 378 | `SaveClient` | `ClientPersister` | ~3 | 25 |
| 8 | 410 | `DeleteClient` | `ClientPersister` | ~3 | bundled |

**Subtotals**:
- Sites 1-6 (`KiteExchanger` interface + adapter + 6 oauth/ caller sites + ~6 test files): **~20 LOC + ~30 test LOC = 50 LOC**
- Sites 7-8 (`ClientPersister` interface + adapter + `oauth/stores.go` plumbing + `adapters_local_bus.go` + ~3 test files): **~30 LOC + ~20 test LOC = 50 LOC**

**Total LOC delta: ~100 LOC** (vs. catalogue's "C1 = 40 LOC" estimate which underestimated the interface-cascade cost).

---

## Recommended commit batching

**Option A — Single PR `refactor(adapters): thread ctx through OAuth bridge & client persister (C1)`**
- All 8 sites in one cohesive change
- Pros: atomic — every interface and impl moves together; reviewer sees full ctx-propagation story
- Cons: ~100 LOC across ~10 files including 2 interfaces; CI risk if any test file misses an update

**Option B — Split into 2 PRs**
- **PR 1**: `KiteExchanger` interface + Sites 1-6 (50 LOC). Lower cascade — only oauth handlers + ~6 test files.
- **PR 2**: `ClientPersister` interface + Sites 7-8 (50 LOC). Independent of PR 1; touches `oauth/stores.go` + dynamic-registration handler.
- Pros: smaller blast radius per PR; PR 1 is mechanical; PR 2 is the harder one (deeper `ClientStore` plumbing)
- Cons: 2 review cycles instead of 1

**Recommendation**: **Option B (2 PRs)**. Rationale: the `ClientPersister` cascade (Site 7-8) genuinely is deeper plumbing than `KiteExchanger` (Sites 1-6) and may surface unexpected issues in `evictOldest` / capacity-eviction paths that don't currently reason about ctx-driven cancellation. Splitting lets PR 1 land fast (high confidence, mechanical) and PR 2 get the focused review the deeper change deserves.

If Agent A prefers atomic landings: Option A is safe — none of the interface changes are subtle. `c1` is well-contained Go-idiom plumbing. Either approach works; risk is uniformly LOW.

---

## Risk profile

- **All 8 sites are LOW risk** under either option. No semantic change — just plumbing.
- **No production cancellation behavior changes** until callers actually cancel ctx. Production HTTP handlers don't currently cancel mid-OAuth, but a future timeout middleware could — this PR makes that future work possible.
- **Test fixtures** (`mockExchanger`, `mockClientPersister` types in test files) need signature updates. Compile-time breaks force exhaustive coverage — no silent skips possible.
- **`InMemoryBus.Dispatch`** (`kc/cqrs/bus.go:67-90`) already accepts ctx and threads through middleware — the wiring at the bus end is correct. C1 only fixes the caller-side "we're throwing ctx away" pattern.

## Catalogue cross-references

- C1 entry in `.research/final-138-gap-catalogue.md`: high severity, 40 LOC (revised: ~100 LOC).
- Bundle in PR-text with E1 (sentinel %w wrap) and E4 (PII email-hash in errors) — those are sibling Go-idiom fixes from Pass 15. Commit `5b3d0da` already landed E1+E4; C1 is the deferred third.
- Sprint 2 placement (per catalogue + Sprint plan in §4 of catalogue).

## Out-of-scope deferrals

- `kc/manager_commands_oauth.go:320,324 oauthClientStoreAdapter.SaveClient/DeleteClient` — these are inside-the-bus adapters bridging to `alerts.DB`. They're not in `app/adapters.go` scope; they call `a.db.SaveClient(...)` directly with no command dispatch. Out of C1 scope; would belong to a separate "thread ctx through alerts.DB" effort.
- `kc/alerts/db_commands.go:198,220 DB.SaveClient/DeleteClient` — same. SQL-level methods. Threading ctx into SQL queries (`db.ExecContext` etc.) is its own work item; C1 stops at the Dispatch call boundary.
- 41 other `context.Background()` sites in production code (Pass 15 verified 48 total, 8 in adapters.go) — separate audit. C1 scope is `app/adapters.go` only.

---

*Generated 2026-04-25 against HEAD `57af60f`. Read-only research deliverable; no source files modified.*
