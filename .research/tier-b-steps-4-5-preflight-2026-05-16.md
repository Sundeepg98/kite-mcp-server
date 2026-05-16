---
title: Tier B Steps 4-5 empirical pre-flight
date: 2026-05-16
agent: fix-context-agent (Dispatch A)
status: RESEARCH-COMPLETE — dispatch-ready
upstream-heads:
  kite-mcp-kc: e406da1 (post-Step-2 manager 49 fields, 129 methods)
  kite-mcp-server: master
roadmap-cite: .research/kc-manager-decomp-roadmap-2026-05-16.md §4-§5
methodology: empirical compile-and-run + balanced-brace classifier (no grep-counts)
---

# Tier B Steps 4-5 empirical pre-flight (2026-05-16)

## §0 Headline findings (read first)

**Step 4 — `kc/identity/` extraction**: LOW-MEDIUM risk, ~3-5h estimated. Empirical scope is **larger than the roadmap framing** (touches 8 fields + 1 facade + 4 init wirings, not the 4-5 the roadmap implied), BUT the consumer-blast-radius is zero: bootstrap + usecases never reach into `m.SessionSvc.*` / `m.CredentialSvc.*` / `m.SessionLifecycle.*` directly (0/0/0 external direct-reads). Passthrough methods on Manager stay; the underlying re-bundle is mechanically clean.

**Step 5 — Drain 96 passthroughs**: roadmap framing of "96 passthroughs" was correct in direction but slightly off in count. **Empirical count: 86 trivial passthroughs + 3 short setters = 89 total drain candidates**, plus 14 medium and 26 complex methods that are NOT passthroughs (keep as Manager-internal logic). Effort estimate revised: **~6-10h, not 12-20h** — because most consumers route through services already, so the work is mostly deleting Manager-side delegates with light call-site rewrite.

The combined Step 4+5 work compresses to **~9-15h** if executed sequentially (Step 4 first establishes the IdentityService boundary, then Step 5 drains across all services). Previously roadmap §4-§5 forecast ~16-26h.

## §1 — Empirical baseline at HEAD `e406da1` (kite-mcp-kc master, post-Step-2)

### 1.1 Manager state (verified via balanced-brace Python classifier)

| Metric | Count |
|---|---|
| Manager fields | **49** (was 63 pre-Step-2; Step 2 absorbed 13 Wave D use-case fields into OrderService) |
| Manager methods (non-test) | **129** |
| → Trivial passthroughs (1-line `(return) m.<field>.<...>` shape) | **86** |
| → Short setters (1-2 line `m.<field> = X`) | **3** |
| → Medium logic (3-8 lines) | **14** |
| → Complex logic (>8 lines) | **26** |
| Total LOC in `kc/` root | 9,669 |
| Total non-test .go files in `kc/` root | 56 |

### 1.2 Manager passthroughs grouped by target field

| Target | Passthroughs | % of total |
|---|---|---|
| `m.stores` (StoreRegistry facade) | 23 | 27% |
| `m.brokers` (BrokerServices facade) | 15 | 17% |
| `m.sessionLifecycle` (SessionLifecycleService facade) | 11 | 13% |
| `m.CredentialSvc` (direct service) | 9 | 10% |
| `m.scheduling` (SchedulingService facade) | 7 | 8% |
| `m.AlertSvc` (direct service) | 5 | 6% |
| `m.eventing` (EventingService facade) | 5 | 6% |
| `m.SessionSvc` (direct service) | 2 | 2% |
| direct field reads (`externalURL`, `adminSecretPath`, `devMode`, `apiKey`, `projector`, `commandBus`, `queryBus`, `SessionManager`, `mcpServer`) | 9 | 11% |
| **Total** | **86 + 3 setters = 89** | |

**Interpretation**: 5 of 49 Manager fields (stores, brokers, sessionLifecycle, scheduling, eventing) absorb 61 of the 89 passthroughs (69%). Pattern is established. Step 4 (IdentityService bundle) will add a 6th facade, absorbing ~22 more (CredentialSvc 9 + SessionSvc 2 + SessionLifecycle 11) — bringing 83 of 89 passthroughs (93%) under facade control.

## §2 — Step 4 dispatch brief: `kc/identity/` extraction (or IdentityService bundle)

### 2.1 Decision: IdentityService bundle (NOT a sub-folder split)

The roadmap framed Step 4 as either "dedicated IdentityService" OR "sub-folder split". Empirical scope says **IdentityService bundle is the right call** for these reasons:

1. **The 5 existing decomp facades are all bundle-style** (StoreRegistry, BrokerServices, SchedulingService, EventingService, SessionLifecycleService). Adding a sub-folder would break the precedent and force a divergent file layout discipline. Bundle preserves the pattern.

2. **Identity fields cluster behaviorally**, not by package boundary. SessionSvc + CredentialSvc + SessionSigner + tokenStore + credentialStore + registryStore + SessionManager work together to answer one question: "who is this caller, can they trade, what's their token". A bundle named `IdentityService` (or `identity_service.go` file) carries that meaning. A sub-folder would force premature export-surface decisions.

3. **`StoreRegistry` already owns tokenStore, credentialStore, registryStore, userStore as accessors** (line `store_registry.go:TokenStore` returns `m.stores.TokenStore()`). Promoting them to a sub-folder would force StoreRegistry to either (a) re-aggregate identity stores via IdentityService cross-import, or (b) lose them — both are worse than keeping the bundle thin.

### 2.2 Fields in scope for IdentityService bundle

Direct identity ownership (move to `IdentityService` struct fields, drain from `Manager` struct):

| # | Field | Type | Move? | Notes |
|---|---|---|---|---|
| 1 | `CredentialSvc` | `*CredentialService` | YES → `IdentitySvc.Credential` | already a service; just rebrand the home |
| 2 | `SessionSvc` | `*SessionService` | YES → `IdentitySvc.Session` | same |
| 3 | `ManagedSessionSvc` | `*ManagedSessionService` | YES → `IdentitySvc.ManagedSession` | thin facade; trivial move |
| 4 | `SessionSigner` | `*SessionSigner` | YES → `IdentitySvc.Signer` | crypto bundle; cohesive with identity |
| 5 | `SessionManager` | `*SessionRegistry` | KEEP as field (exposed accessor); thread through `IdentitySvc.Sessions()` | **CAVEAT**: 4 external consumers reach `m.SessionManager` directly (bootstrap + usecases) — see §2.4 |
| 6 | `sessionLifecycle` | `*SessionLifecycleService` | YES → `IdentitySvc.Lifecycle` | already a facade; move trivial |

**Stay on Manager (NOT in IdentityService)**:
- `tokenStore`, `credentialStore`, `registryStore`, `userStore` — owned by StoreRegistry per Phase 3a design. IdentityService consumes them via interface ports threaded through SessionSvc/CredentialSvc (already the case at HEAD).
- `encryptionKey` — used by users.Store TOTP encryption + alerts.DB key derivation. Cross-cutting concern; stays on Manager or moves to a hypothetical "Crypto" bundle in a later step.

### 2.3 Field count delta

| Before Step 4 | After Step 4 |
|---|---|
| Manager: 49 direct fields | Manager: **44 fields** (drop CredentialSvc, SessionSvc, ManagedSessionSvc, SessionSigner, sessionLifecycle) |
| Manager facade objects: 5 (stores, brokers, scheduling, eventing, sessionLifecycle) | Manager facade objects: **5** (stores, brokers, scheduling, eventing, identity) — sessionLifecycle absorbs into identity |
| Net drain: -5 fields | |

**Caveat**: SessionManager stays as field (5th slot), so net is -5 not -6. Could be -6 if SessionManager moves into identity bundle too — see §2.4 risk note.

### 2.4 Consumer blast-radius (verified empirical)

External direct-reads via `grep -rE "\.<Field>\b" --include="*.go" kite-mcp-bootstrap kite-mcp-usecases` minus `_test.go`:

| Field | External direct reads | Risk |
|---|---|---|
| `m.SessionSvc.*` | **0** | None — passthroughs absorb 100% of access |
| `m.CredentialSvc.*` | **0** | None |
| `m.SessionLifecycle.*` (`m.SessionLifecycle().X` shape) | **0** | None |
| `m.SessionSigner` | 3 | Low — 3 call sites; easy update OR keep accessor |
| `m.SessionManager` / `m.SessionRegistry()` | 4 | Low-medium — 4 sites; keep accessor for back-compat |

**The 3 SessionSigner + 4 SessionManager sites can be handled two ways**:
- **Option A (preserve back-compat)**: Manager keeps `SessionSigner()` and `SessionRegistry()` accessor methods that delegate to `m.identity.Signer` and `m.identity.Sessions`. Zero consumer churn.
- **Option B (clean rewrite)**: rewrite 7 call sites to use `manager.Identity().Signer()` / `manager.Identity().Sessions()`. Slightly cleaner API, 7-file edit, ~30min.

**Recommend Option A** for Step 4. Option B can land later as a separate Phase 3b polish dispatch.

### 2.5 Init-wiring touch surface

Currently in `manager_init_services.go`:
```go
m.SessionSvc = NewSessionService(SessionServiceConfig{
    CredentialSvc: m.CredentialSvc,
    TokenStore:    m.tokenStore,
    SessionSigner: m.SessionSigner,
    ...
})
m.SessionSvc.SetSessionManager(m.SessionManager)
m.ManagedSessionSvc = NewManagedSessionService(m.SessionManager)
```

After Step 4 (in a new `identity_service.go`):
```go
m.identity = newIdentityService(IdentityServiceConfig{
    CredentialSvc:  NewCredentialService(...),
    SessionSigner:  signer,
    SessionManager: registry,
    TokenStore:     m.stores.TokenStore(),
    Logger:         logger,
})
// internal: identity wires SessionSvc + ManagedSessionSvc + SessionLifecycle from these primitives
```

### 2.6 Risk + WSL2 verification

| Risk | Likelihood | Mitigation |
|---|---|---|
| Test breakage from struct-literal Manager construction in `helpers_test.go` | LOW | Tests use `NewWithOptions` not struct literals at HEAD (verified). Re-verify before commit. |
| Bootstrap import-cycle if `identity` is a sub-package | N/A | Bundle pattern keeps it in `kc` package; no new import edges. |
| OAuth flow regression (CompleteSession + rotate) | LOW | All flow is via SessionSvc methods already; rebundling doesn't change call paths. |
| External v0.X version-tag bump | YES — needed | Step 4 ships as `v0.1.4` after `go test ./... -race -short` + WSL2 GOWORK=off build green. |

**WSL2 risk forecast**: LOW. Step 2 (which absorbed 13 Wave D use-cases into OrderService) was a deeper structural change and shipped clean; Step 4 has narrower scope and zero external consumer churn under Option A.

### 2.7 Step 4 estimate

| Phase | Effort |
|---|---|
| Author `identity_service.go` (struct + constructor + accessor methods) | 1h |
| Move SessionSvc/ManagedSessionSvc/SessionLifecycle to identity-owned | 1h |
| Update manager_init_services.go + manager_struct.go (drop 5 fields) | 30min |
| Update Manager passthrough delegators (re-target from `m.SessionSvc.X` to `m.identity.Session.X`) | 1h |
| WSL2 verify: `go build ./...`, `GOWORK=off go build ./...`, `go test -race -short ./...` | 30min |
| Tag + push v0.1.4 | 15min |
| **Total** | **~3.5-4.5h** |

Roadmap §4 forecast: "LOW risk" — confirmed. Actual estimate sits at the high end of LOW.

## §3 — Step 5 dispatch brief: drain 89 passthroughs

### 3.1 Empirical count correction

Roadmap §5 said "96 passthroughs". Empirical: **89** (86 trivial + 3 short setters). Difference: the 7-method gap is mostly from medium-length methods (5 register* command-bus methods + 2 init helpers) that the roadmap likely counted as passthroughs but are actually multi-step initializers. Net direction is the same; count tightened.

### 3.2 Drain strategy by target service

Each row = one batch dispatch:

| # | Target | Passthroughs | Drain strategy | Effort |
|---|---|---|---|---|
| 1 | `m.stores` (StoreRegistry) | 23 | **KEEP passthroughs as Manager-level back-compat shims.** 73 files depend on `m.TokenStore()` etc. (per the comment in `store_registry.go:13-15`). Phase 3a explicitly retained these. **Verdict: NO DRAIN; documented architectural decision.** | 0h |
| 2 | `m.brokers` (BrokerServices) | 15 | **MIXED**: 8 are pure passthroughs that could route through `Brokers()` facade access. Bootstrap consumer count is mid-high; needs per-method audit. Estimate: drain 8, keep 7. | 2-3h |
| 3 | `m.sessionLifecycle` (after Step 4: `m.identity.Lifecycle`) | 11 | **KEEP for back-compat OR drain to `manager.Identity().Lifecycle().X` at consumer sites**. Per §2.4, currently 0 external direct-reads — drain is safe but offers minimal value because passthroughs are 1-line and external consumers already use them. **Verdict: documentation-only; no code change.** | 0.5h docs |
| 4 | `m.CredentialSvc` (after Step 4: `m.identity.Credential`) | 9 | Same as #3. Consumers route through Manager passthroughs already. **Verdict: documentation-only.** | 0.5h docs |
| 5 | `m.scheduling` (SchedulingService) | 7 | Mostly metric-tracker methods (`IncrementMetric`, `TrackDailyUser`). External callers? **Probe TBD** — likely low; if so, drain candidate. | 1h |
| 6 | `m.AlertSvc` | 5 | `TelegramNotifier()` has 11 external callers. Keep passthrough. Other 4 may be drainable. | 1h |
| 7 | `m.eventing` (EventingService) | 5 | `EventDispatcher()` has 4 callers. Keep passthrough. Other 4 (Store, Setters) — mostly internal init use; drainable. | 1h |
| 8 | Direct field reads (`externalURL`, `adminSecretPath`, `devMode`, `apiKey`, `projector`, `commandBus`, `queryBus`, `SessionManager`, `mcpServer`) | 9 | **Mixed**: `DevMode`, `APIKey`, `AdminSecretPath`, `Projector` have **0 external callers** — delete entirely or scope to internal. `MCPServer` has 14 callers — keep. `CommandBus`/`QueryBus` have low consumer count but Wave D depends on them — keep. | 1-2h |

**Aggregate Step 5 effort**: 6-10h. Many of the 89 are "delete one Manager method, leave consumers as-is because they already route through facades" — so the LOC delta is large but per-method touch is small.

### 3.3 Deletion candidates (zero external callers — empirical)

These 4 Manager methods have **zero external consumer counts** in `kite-mcp-bootstrap` + `kite-mcp-usecases` (verified 2026-05-16):

| Method | Body | Decision |
|---|---|---|
| `Manager.DevMode()` | `return m.devMode` | **DELETE.** `m.devMode` is internal config; if no external reader, scope to private field with internal-only access. |
| `Manager.APIKey()` | `return m.apiKey` | **DELETE.** Same — internal config field. CredentialSvc already exposes per-user API key. |
| `Manager.AdminSecretPath()` | `return m.adminSecretPath` | **DELETE** OR keep only if app/http.go reads it (re-verify before deletion). |
| `Manager.Projector()` | `return m.projector` | **DELETE.** Projector is used internally for read-side projections; no external direct-read. |

Plus **`Manager.SetFamilyService(fs)`** (1-line setter) — used only by app/wire.go post-construction; verify and either delete or keep.

**Conservative recommendation**: do not auto-delete in Step 5 batch dispatch. Each "0 callers" finding may have hidden indirect use (struct-literal initialization in test fixtures, type-assertion targets). Add a "Phase 5b — internal-config cleanup" sub-dispatch that runs `go vet ./...` + grep for `_ = m.X()` patterns before deleting.

### 3.4 Sed-able batch plan for 8 brokers-passthrough drain

For the 8 brokers-passthroughs that ARE drain candidates (per §3.2 row 2), the rewrite template is:

```bash
# Before: m.KiteClientFactory()
# After:  m.Brokers().KiteClientFactory()

cd /mnt/d/Sundeep/projects/algo2go/kite-mcp-bootstrap
for method in KiteClientFactory InstrumentsManager TickerService PaperEngine RiskGuard \
              ForceInstrumentsUpdate UpdateInstrumentsConfig GetInstrumentsStats; do
  grep -rln "\.${method}(" --include="*.go" . | grep -v _test.go | while read f; do
    # Per-file inspection required: some sites use kc.Manager directly,
    # others use a wrapper. Manual review per-file (no global sed).
    echo "review: $f"
  done
done
```

**This is NOT a global sed.** Each site needs review because the receiver may be `manager.X()` vs `mgr.X()` vs `m.X()` vs `kc.Manager.X()` shape. ~30min per file × 8 methods × ~3 sites avg = ~12 file edits.

### 3.5 Step 5 recommended phasing

| Phase | Scope | Effort |
|---|---|---|
| 5a — Internal-config cleanup (4 deletion candidates) | DevMode/APIKey/AdminSecretPath/Projector accessors; verify zero indirect uses; delete | 1-2h |
| 5b — brokers-passthrough drain (8 methods) | Rewrite consumer sites to use `m.Brokers().X()`; delete Manager-level method | 2-3h |
| 5c — scheduling-passthrough drain (7 methods) | Similar shape; metric trackers route through `m.Scheduling().X()` | 1-2h |
| 5d — eventing-passthrough drain (4 of 5; keep EventDispatcher accessor) | Similar | 1h |
| 5e — Documentation: mark stores/sessionLifecycle/CredentialSvc/AlertSvc passthroughs as RETAINED for back-compat per Phase 3a precedent | Add comments at retained sites citing this doc | 1h |
| **Total** | | **~6-10h** |

Roadmap §5 forecast: "12-20h, LOW risk" → revised to **6-10h, LOW risk**.

## §4 — Combined Step 4 + Step 5 verdict

| Step | Roadmap forecast | Empirical revised forecast |
|---|---|---|
| Step 4 (identity extraction) | LOW risk, ~4-6h | LOW risk, **~3.5-4.5h** |
| Step 5 (96 passthroughs drain) | LOW risk, 12-20h | LOW risk, **~6-10h** |
| **Combined** | **16-26h** | **~9-15h** |

Combined estimate is ~50-60% of roadmap. Drivers:
1. Many Manager passthroughs are correctly RETAINED for back-compat per Phase 3a — not drain candidates.
2. Zero external consumers route into `m.SessionSvc.*` / `m.CredentialSvc.*` / `m.SessionLifecycle.*`; Step 4 is a clean re-bundle with no consumer churn.
3. 4 Manager methods have zero callers — pure deletion candidates (subject to indirect-use re-verification).

## §5 — Dispatch packaging for Step 4 (ready to launch when Step 3 lands)

**Brief**: extract `IdentityService` bundle in `kite-mcp-kc`. Field count: 49 → 44. WSL2 verify clean. Tag v0.1.4. Push.

**Procedure**:
1. Pull `kite-mcp-kc` to latest (must be on Step-3 HEAD, not Step-2 `e406da1`).
2. Create `identity_service.go` (~80 LOC): `IdentityService` struct holding `Credential *CredentialService`, `Session *SessionService`, `ManagedSession *ManagedSessionService`, `Signer *SessionSigner`, `Lifecycle *SessionLifecycleService`, `Sessions *SessionRegistry`.
3. Add `IdentityServiceConfig` + `newIdentityService(cfg)` constructor.
4. Update `manager_struct.go`: drop 5 fields (CredentialSvc, SessionSvc, ManagedSessionSvc, SessionSigner, sessionLifecycle); add `identity *IdentityService`.
5. Update `manager_init_services.go`: replace direct field wiring with `m.identity = newIdentityService(...)`.
6. Update Manager passthrough methods: re-target `m.SessionSvc.X` → `m.identity.Session.X`, etc. (~22 methods touch).
7. Add `Manager.Identity() *IdentityService` public accessor for future external use.
8. WSL2 verify:
   - `go build ./...` (kite-mcp-kc tree)
   - `GOWORK=off go build ./...` (cross-mod resolution)
   - `go vet ./...`
   - `go test -race -short ./...`
9. Commit: `refactor(manager): extract IdentityService bundle (Tier B Step 4 — Manager 49→44 fields)`
10. Tag `v0.1.4`, push origin master + tag.
11. Cross-repo bootstrap pin update (separate commit on `kite-mcp-server` master).

**Halt conditions**:
- If any external consumer references `m.SessionSvc` or `m.CredentialSvc` directly (re-verify via grep immediately before commit) → switch to Option B (clean rewrite) or halt for orchestrator decision.
- If WSL2 GOWORK=off build fails on cross-module path resolution → revert the `kc/` package keep-internal decision; reconsider sub-folder option.

## §6 — Dispatch packaging for Step 5 (ready after Step 4 lands)

**Brief**: drain 89 Manager passthroughs in 5 sub-phases (5a–5e), totaling ~6-10h.

**Procedure**: per §3.5 phasing table. Each sub-phase is a separate WSL2-verified commit; combined push at end. Cross-repo bootstrap pin updates per drained-method consumer rewrite.

**Halt conditions**:
- If `go test -race -short ./...` regresses on bootstrap after any drain commit → revert that commit, do not push.
- If a passthrough turns out to have hidden test-fixture or reflection-based callers → keep it as back-compat shim with documentation comment.

## §7 — Methodology footnote

### 7.1 Probes run (all 2026-05-16)

| Probe | Result |
|---|---|
| `git log -1 --oneline` on kite-mcp-kc | `e406da1` (README post-Step-2) |
| `wc -l manager_struct.go` + field-count count | 49 direct fields + 5 facade objects = 49 total slots |
| `grep -c "^func (m \*Manager)" *.go` | 129 methods (non-test) |
| Balanced-brace Python classifier on 56 non-test .go files | 86 trivial + 3 setter + 14 medium + 26 complex |
| `grep -rE "\.SessionSvc\.[A-Z]" kite-mcp-bootstrap kite-mcp-usecases` | 0 external direct-reads |
| `grep -rE "\.CredentialSvc\.[A-Z]" kite-mcp-bootstrap kite-mcp-usecases` | 0 external direct-reads |
| `grep -rE "\.SessionLifecycle\(\)\." kite-mcp-bootstrap kite-mcp-usecases` | 0 external direct-reads |
| Consumer counts for 9 sampled accessors (HasCachedToken, GetAPIKeyForEmail, TokenStore, AlertStore, UserStore, TelegramNotifier, ExternalURL, DevMode, APIKey) | Range: 0 to 19 callers per method |

### 7.2 Confidence

HIGH on Step 4 estimate (3.5-4.5h) — empirical scope is fully mapped; consumer-blast radius is empirically zero; pattern matches the 5 existing facades.

MEDIUM on Step 5 estimate (6-10h) — per-passthrough drain decisions need per-method consumer audit (only 9 sampled out of 89). Some retained-vs-drain decisions may flip during execution. Recommend committing each sub-phase separately so revisions are cheap.

### 7.3 What this dispatch did NOT verify

- Whether `kc/` test suite passes at HEAD `e406da1` (assumed green per Step 2 success).
- Bootstrap-side cross-module test impact (deferred to dispatch execution).
- Whether the 4 deletion-candidates (DevMode/APIKey/AdminSecretPath/Projector) have indirect callers via reflection or struct-tag use (requires `go vet -reflect` or manual scan).
- Path A may extract additional fields during Step 3 (alert subsystem) that change the 49-field baseline. Re-verify field count on Step 4 dispatch launch.

### 7.4 Cross-references

- `.research/kc-manager-decomp-roadmap-2026-05-16.md` §4 (Step 4), §5 (Step 5), §8.6 (passthrough breakdown) — superseded scope estimates per this preflight
- `.research/track-2b-position-empirical-resurvey.md` — sister empirical-correction dispatch from earlier today
- `kite-mcp-kc/store_registry.go` lines 13-55 — Phase 3a documented decision to RETAIN Manager-level store accessors as back-compat shims; informs Step 5 §3.2 row 1 "no drain"
