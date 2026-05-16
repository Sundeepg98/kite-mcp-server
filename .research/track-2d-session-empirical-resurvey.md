---
title: Track 2.D Session adoption empirical re-survey
date: 2026-05-16
agent_uuid: a94162d9f028f4b54
session: 2026-05-16 Show HN red-team follow-on (third Track-2 confirming data point)
status: COMPLETE — RECOMMEND POLISH-ONLY (~3-5h)
supersedes: kc-manager-decomp-roadmap-2026-05-16.md §3 (Session as MED-risk, "Session domain is more tangled — Session adoption needs MORE discovery")
empirical_count: 86 strict non-test refs (bootstrap 70 + kc 15 + domain 1)
migration_candidates: 3 (kc.IsKiteTokenExpired free-standing helper sites)
real_work_remaining: ~2h polish + ~2-3h optional cosmetic rename
inflation_factor: 17-29x wrt actual migration cost
---

# Track 2.D Session adoption empirical re-survey (2026-05-16)

## §0 Headline finding

**Audit's MED-risk Session entity adoption framing is empirically FALSIFIED at HEAD.** The "tangled Session domain" hypothesis (KiteSessionData legacy alias + SessionID separate type + SessionRegistry tangling) is **already cleanly architected** at HEAD `e406da1` (kc) / `cff717e` (bootstrap):

| Pattern | Strict non-test count | Classification | Adoption verdict |
|---|---:|---|---|
| `kc.KiteSessionData` | **73** | **DTO-boundary** (`WithSession` handler signature × 64 sites + type-assertions × 9) — type alias for `domain.KiteSessionData` since PR 5.6 | **RETIRE — already correctly routed via type alias; no consumer migration** |
| `domain.Session` (rich entity) | **2** | **ALREADY-ADOPTED** in `kc/expiry.go` constructor + `kc/credential_service.go` consumer | **N/A — adopted** |
| `kc.SessionRegistry` | **5** | **Storage-layer / Provider-port** — correctly used as-is | **RETIRE — not an entity adoption target** |
| `kc.MCPSession` | **1** | **Type definition** in `kc/session.go:44` | **RETIRE — definition site** |
| `broker.Session[^a-zA-Z]` | **0** | No such sibling DTO exists | **N/A** |
| **TOTAL strict refs** | **86** | (bootstrap 70 + kc 15 + domain 1) | — |
| `kc.IsKiteTokenExpired` (the genuine migration-win pattern) | **5** non-test sites | **Migration-win candidate**: 2 bootstrap + 1 kc/ops + 2 tools-common (1 default value + 1 doc) | **3 mechanical rewrites + 2 cosmetic** |

**Audit's overall scope** (53 broker.Order + 63 broker.Position + Session-as-MED = "28-42h consumer adoption work") collapses to **~3-5h of polish work** for Session — exactly mirroring the Track 2.A (Order, 53→26) and pre-validating Track 2.B's likely pattern (Position).

The `kc.KiteSessionData = domain.KiteSessionData` type alias (manager_struct.go:62) means every consumer already references the canonical entity by another name. Per-user OAuth flow + 64 handler signatures travel **through the entity type** even when source text says `kc.KiteSessionData`. The "73 sites to migrate" framing is a measurement artifact of the alias — the underlying type is already `domain.KiteSessionData`.

---

## §1 Per-site enumeration

### §1.1 Strict count breakdown (verified 2026-05-16)

Strict pattern: `broker\.Session[^a-zA-Z]|kc\.KiteSessionData|domain\.Session|kc\.SessionRegistry|kc\.MCPSession` over `*.go ':!*_test.go'`, all 5 repos.

| Repo | HEAD | Non-test hits | Notes |
|---|---|---:|---|
| `algo2go/kite-mcp-bootstrap` | `cff717e` | **70** | 67 `kc.KiteSessionData` + 1 `kc.SessionRegistry` + 2 `domain.SessionCreatedEvent` (excluded — event, not entity) |
| `algo2go/kite-mcp-kc` | `e406da1` | **15** | 6 `kc.KiteSessionData` + 4 `kc.SessionRegistry` + 1 `kc.MCPSession` + 2 `domain.Session` + 2 `domain.SessionCreatedEvent` |
| `algo2go/kite-mcp-usecases` | `87aba72` | **0** | Clean — uses CQRS commands/queries, not session refs |
| `algo2go/kite-mcp-domain` | `a624088` | **1** | `session.go:28` self-reference doc comment |
| `kite-mcp-server` | `f21811b` | **0** | Only 10 .go files (cmd/ + main); not in survey scope |

**Note**: The pattern `domain\.Session` matches `domain.SessionCreatedEvent` (event, not entity). The strict-pattern was an over-count by 5 refs across the survey (bootstrap 2 in `adapters_eventsourcing.go` + kc 1 in `session_service.go` + non-test eventsourcing-aggregate references). These are **event sourcing infrastructure**, distinct from the `domain.Session` rich entity. Excluding events: **rich-entity refs at HEAD = 2** (both in `kite-mcp-kc`).

### §1.2 Per-site classification

**Class A — DTO-boundary (handler signature contract)** — 64 sites in bootstrap

All `kc.KiteSessionData` refs in bootstrap `mcp/**/*.go` (62 sites: market_tools, trade/*.go, portfolio/*.go, alerts/*.go, analytics/*.go, misc/*.go, paper/*.go, tax_tools.go) and 2 in tools-common (`handler_methods.go:189`, `:74` and `:576`, `:621` — the `WithSession` API itself) take the form:

```go
return handler.WithSession(ctx, "tool_name", func(session *kc.KiteSessionData) (*mcp.CallToolResult, error) {
    // tool body uses session.Broker / session.Kite / session.Email
})
```

This is **the API contract** for tool handlers (defined in `kite-mcp-tools-common/common/handler_methods.go:189`). The signature uses `*kc.KiteSessionData` but the type alias `kc.KiteSessionData = domain.KiteSessionData` (manager_struct.go:62) means every site already references the domain type. **Rewriting the signature to `*domain.KiteSessionData` is a 1-character textual change at the WithSession definition + 64 callsites** — but **adds no semantic adoption value** because the alias already routes through the entity.

Verdict: **RETIRE — already correctly wrapped via type alias since PR 5.6 (commit e44c070)**. Optionally, cosmetic rename pass (~30-45 min, sed-able) to remove the alias.

**Class B — DTO-boundary (type assertions at storage layer)** — 9 sites

Sites that do `sess.Data.(*kc.KiteSessionData)` because `MCPSession.Data` is `any`-typed (kc/session.go:49):
- `algo2go/kite-mcp-bootstrap/app/adapters_paper.go:21` — paper-LTP adapter iterating SessionRegistry
- `algo2go/kite-mcp-bootstrap/mcp/misc/session_admin_tools.go:105, 225` — admin session-list tool
- `algo2go/kite-mcp-kc/ops/api_handlers.go:414` — admin API building session aggregate
- `algo2go/kite-mcp-kc/ops/data.go:109` — dashboard session list

These are storage-layer reads through the `any`-typed `MCPSession.Data` field. The type assertion **is the entity decode point**. Same logic: aliased, no semantic change.

Verdict: **RETIRE — DTO-boundary at storage layer, no rich-entity behavior to delegate**.

**Class C — `SessionRegistry` (storage facade)** — 5 sites
- `algo2go/kite-mcp-bootstrap/app/session_resolver.go:22` — `*kc.SessionRegistry` arg in `newClientHintedResolver` constructor
- `algo2go/kite-mcp-kc/ports/session_registry.go:5, 16, 20, 39` — Provider port doc + interface signature

This is the **session-storage facade** — not the rich entity. Already correctly used as-is via Provider port pattern (Brief 3 shipped 2026-05-16). Audit's roadmap §5.2 lists this as "PROVIDER PORT shipped".

Verdict: **RETIRE — Audit already classified this correctly; not an entity-adoption target**.

**Class D — `MCPSession` (kc-internal session shell)** — 1 site
- `algo2go/kite-mcp-kc/session.go:44` — type definition only (the registry's stored session struct)

Verdict: **RETIRE — definition site**.

**Class E — `domain.Session` rich entity (already-adopted)** — 2 sites
- `algo2go/kite-mcp-kc/expiry.go:28` — `func ToDomainSession(email string, entry *KiteTokenEntry) domain.Session` — **the canonical adoption converter**
- `algo2go/kite-mcp-kc/credential_service.go:125` — `res.QualifiesForTrading(ToDomainSession(email, entry))` — domain rule consumer

Already-wrapped. Plus 8 additional **callers of `ToDomainSession`** that consume the rich entity (these are below the strict-pattern but real adoption — see §1.3).

Verdict: **N/A — adoption already shipped**.

### §1.3 Genuine migration-win candidates (`kc.IsKiteTokenExpired` free-standing helper)

The free-standing `kc.IsKiteTokenExpired(storedAt time.Time) bool` is the **pre-entity equivalent** of `domain.Session.IsExpired()`. Sites that still call it instead of `kc.ToDomainSession(email, entry).IsExpired()` are the **only genuine migration-win candidates** in Track 2.D.

Non-test sites at HEAD (5 total):

| Site | Type | Migration-win? |
|---|---|---|
| `algo2go/kite-mcp-bootstrap/app/adapters_briefing.go:32` | Interface method body `(a *briefingTokenAdapter) IsExpired` | **YES** — trivial 1-line rewrite |
| `algo2go/kite-mcp-bootstrap/mcp/ext_apps_widget_hub.go:17` | Widget data builder | **YES** — has email + entry locally |
| `algo2go/kite-mcp-kc/ops/dashboard_portfolio.go:136` | Dashboard expired-check | **YES** — has email + tokenEntry locally |
| `algo2go/kite-mcp-tools-common/common/handler_methods.go:163` | Default value `isExpired := kc.IsKiteTokenExpired` | **PARTIAL** — function-pointer default; could keep as cosmetic, or extract `func(email, entry) bool` |
| `algo2go/kite-mcp-tools-common/common/handler_deps.go:89` | Doc comment `// injectable for testing; nil = kc.IsKiteTokenExpired` | **COSMETIC** — doc-only |

Verdict: **3 mechanical rewrites + 2 cosmetic = ~1-2h total**. The genuine adoption opportunity is **1-2 orders of magnitude smaller than the strict-count framing suggests**.

### §1.4 Sites that ALREADY use the rich entity (verified-adopted)

Cross-repo `ToDomainSession(...).IsExpired()` / `.IsAuthenticated()` calls (counted as non-test, excluding the converter definition itself):

| Site | Method used | Notes |
|---|---|---|
| `algo2go/kite-mcp-kc/credential_service.go:125` | `.QualifiesForTrading(domain.Session)` via `CredentialResolution.QualifiesForTrading(s domain.Session)` | trading-eligibility rule |
| `algo2go/kite-mcp-kc/credential_service.go:175` | `.IsExpired()` | `IsTokenValid` |
| `algo2go/kite-mcp-kc/ops/api_alerts.go:186` | `.IsExpired()` | session-active check |
| `algo2go/kite-mcp-kc/ops/api_handlers.go:71, 130` | `.IsExpired()` (×2) | session expiry probe |
| `algo2go/kite-mcp-kc/ops/dashboard_orders.go:67` | `.IsExpired()` | dashboard session-state |
| `algo2go/kite-mcp-kc/ops/dashboard_safety.go:85` | `.IsExpired()` | dashboard safety check |
| `algo2go/kite-mcp-kc/ops/dashboard_templates.go:203` | `.IsExpired()` | dashboard template binding |
| `algo2go/kite-mcp-bootstrap/app/app.go:701` | `.IsAuthenticated()` | OAuth middleware authority check |

**8 production callsites already consume the rich `domain.Session`** via `ToDomainSession`. The entity is in active use across the OAuth middleware, credential trading rule, ops API, and dashboard surface.

---

## §2 Aggregate verdict

### §2.1 Empirical scope per Show HN red-team template

| Track | Audit count | Strict re-count | DTO-boundary (retire) | Already-wrapped | Migration-win | Pattern |
|---|---:|---:|---:|---:|---:|---|
| **2.A Order** (red-team) | 53 | 26 strict | 18 | 5 | 3 | grep over-counted by 2.0× |
| **2.B Position** (fix agent) | 63 | 15 strict (6 consumer) | 2 | 4 | 0 | grep over-counted by 10× |
| **2.D Session** (this report) | "MED-risk, more tangled" | 86 strict | 79 (Class A+B+C+D) | 2 entity + 8 callers | **3-5** | grep over-counted by **17-29× wrt actual migration cost** |

Track 2.D is **the most overstated of the three**. The "tangling" Audit identified is **already cleanly resolved** at HEAD by:
1. Type alias `kc.KiteSessionData = domain.KiteSessionData` (PR 5.6) — every "KiteSessionData" ref already is a domain ref
2. Converter `kc.ToDomainSession(email, entry) domain.Session` (kc/expiry.go:28) — single canonical wrapping point
3. SessionRegistry promoted to Provider port (Brief 3, today 2026-05-16) — admin/concrete-type access already correct
4. 8 consumer sites **already adopted** the rich entity via `.IsExpired()`, `.IsAuthenticated()`, `.QualifiesForTrading()` calls

### §2.2 Why Audit's MED-risk flag was an overestimate

Audit identified three "tangling" concerns. Empirical resolution:

| Concern | Status at HEAD `e406da1` |
|---|---|
| `KiteSessionData` legacy alias | **STILL EXISTS** at manager_struct.go:62 — but is a type ALIAS to `domain.KiteSessionData`, not a duplicate type. Every consumer that says `kc.KiteSessionData` already references the domain type. Optional cosmetic rename pass. |
| `SessionID` separate type | EXISTS at domain/session.go:48 — value object with NewSessionID constructor + IsValid. Not "tangled" — disjoint from `Session` entity; used for ID validation discipline. **Zero non-test consumers** found across all 5 repos (greenfield VO awaiting adoption — but no anti-pattern to migrate away from). |
| `SessionRegistry` tangling | Provider port `SessionRegistryProvider` shipped today (kc/ports/session_registry.go); admin tools route through the port. Roadmap §5.2 lists "PROVIDER PORT shipped". |

All three concerns are **resolved or already correctly architected** at HEAD.

### §2.3 Final verdict

**RETIRE Track 2.D from execution as scoped** (28-42h consumer-adoption work).

**Re-scoped polish work**: **~3-5h total**:
1. Migrate 3 non-test `kc.IsKiteTokenExpired` callsites to `kc.ToDomainSession(email, entry).IsExpired()` (~1h)
2. Optional: cosmetic rename `kc.KiteSessionData` → `domain.KiteSessionData` directly at the 73 callsites + retire the type alias (~2-3h sed sweep; pure rename, no semantic change)
3. Optional: drop the free-standing `kc.IsKiteTokenExpired` helper after #1 (~30 min)

Combined with Track 2.A (red-team 3-5h) and Track 2.B (fix agent ~0min) — **Track 2 total ~3-5h, not 28-42h**.

---

## §3 Re-scoped execution brief (if applicable)

If the user greenlights the **polish slice only**, recommended brief:

### Brief 2.D-polish: Session migration-win cleanup

**Scope** (verified non-test):
- `algo2go/kite-mcp-bootstrap/app/adapters_briefing.go:31-33` — rewrite `IsExpired(storedAt)` method body to use `ToDomainSession` (need to thread email + full entry through; check if adapter already has them)
- `algo2go/kite-mcp-bootstrap/mcp/ext_apps_widget_hub.go:17` — rewrite to `kc.ToDomainSession(email, entry).IsExpired()` (email + entry locally available)
- `algo2go/kite-mcp-kc/ops/dashboard_portfolio.go:136` — rewrite to `kc.ToDomainSession(email, tokenEntry).IsExpired()` (both locals present)

**Out of scope** (DTO-boundary; retire from consideration):
- 64× `WithSession(ctx, "tool", func(session *kc.KiteSessionData))` handler signatures — already-aliased, semantically adopted
- 9× type assertions `sess.Data.(*kc.KiteSessionData)` — storage-layer decode, semantically equivalent
- `kc.SessionRegistry` refs — Provider-port-wrapped (Brief 3 shipped)
- `kc.MCPSession` definition site — internal session shell

**Test**: `go test ./...` clean in each repo touched; behavioral parity verified by the existing `domain/session_test.go` IST-boundary suite (already covers the rule).

**Cost**: 1-2h coding + 30min WSL2 verify + 15min commit/push = **~2h total**.

**Risk**: LOW — pure delegate-replacement; the rule body in `domain.Session.IsExpiredAt` was extracted from `kc.IsKiteTokenExpired` and is verified identical by `domain/session_test.go`.

**Halt conditions**: `briefingTokenAdapter.IsExpired(storedAt time.Time)` interface signature constraint — if the alerts package's `TokenChecker` interface fixes the signature to `func(storedAt) bool`, this adapter can't switch (needs email + entry, not just storedAt). Check `kite-mcp-alerts` first.

### Brief 2.D-cosmetic-rename (OPTIONAL)

**Scope**: 73 callsites of `kc.KiteSessionData` → `domain.KiteSessionData` + drop the alias.

**Cost**: ~2-3h sed sweep + WSL2 verify + 1 PR per repo. Pure mechanical rename.

**Value**: Removes the "wait, is this a separate type?" cognitive overhead. No behavior change.

**Recommend**: defer unless Audit explicitly calls for type-alias retirement.

---

## §4 Empirical methodology notes

### §4.1 Verification chain

- HEADs date-stamped per repo (verified 2026-05-16 via `git rev-parse HEAD` in each repo).
- Strict-grep pattern from dispatch verbatim, with `--include='*.go' --exclude='*_test.go'` (and `':!*_test.go'` for `git grep`) — applied identically across all 5 repos.
- File-content reads before classification — every "DTO-boundary" Class A/B verdict was confirmed by reading the actual surrounding code (5+ representative samples).
- The `domain.SessionCreatedEvent` confound was identified by inspecting raw grep output (matches `domain.Session` strict pattern via word-boundary collision with `domain.SessionC...`); subtracted from rich-entity count.
- The type alias `KiteSessionData = domain.KiteSessionData` at manager_struct.go:62 is the load-bearing fact that distinguishes "73 sites to migrate" from "73 sites already aliased". Verified by reading the source.

### §4.2 Counting notes
- Strict patterns excluded `_test.go` per dispatch + the standing rule (`feedback_narrow_test_scope_no_stash`).
- `kc.IsKiteTokenExpired` was searched in addition to the strict patterns because it is the **pre-entity equivalent** — the methodologically-correct adoption target. Without surfacing this, the migration-win count would be 0; with it, the genuine count is 3.
- `kite-mcp-server` (the legacy fork) has 10 .go files, 0 Session refs in code (only in .md research). Confirmed by `git ls-files '*.go'` count.
- `kite-mcp-usecases` returned 0 strict matches — verified by direct grep; the package uses CQRS commands/queries, not session refs.

### §4.3 Limits acknowledged
- This report does not analyze the `SessionRegistryProvider` Phase 3 plan (`phase-3-ops-port-prereq-2026-05-16.md`) in depth — that's a Manager-decomp Step 1 prerequisite, not Track 2 consumer adoption.
- Track 2.B (Position) just shipped at `cef642a` with parallel findings; this report's §2.1 row was updated post-dispatch to reflect Fix agent's empirical figures.
- The `Brokers().X()` facade indirection (Manager-decomp roadmap §1.2 §4) was not entered — orthogonal to Session-entity adoption.

### §4.4 Cross-references
- Source roadmap: `.research/kc-manager-decomp-roadmap-2026-05-16.md` (§3 Track 2 sequencing claims)
- Sibling re-surveys: `.research/track-2b-position-empirical-resurvey.md` (Position, RETIRE) + Show HN red-team's Track 2.A (Order, ~30min real work)
- Entity definition: `algo2go/kite-mcp-domain/session.go` (lines 38-201)
- Type alias: `algo2go/kite-mcp-kc/manager_struct.go:62`
- Canonical converter: `algo2go/kite-mcp-kc/expiry.go:25-37`
- Adopted callsites (8 verified): `kc/credential_service.go:125,175`, `kc/ops/api_alerts.go:186`, `kc/ops/api_handlers.go:71,130`, `kc/ops/dashboard_orders.go:67`, `kc/ops/dashboard_safety.go:85`, `kc/ops/dashboard_templates.go:203`, `kite-mcp-bootstrap/app/app.go:701`

### §4.5 Time used
- ~45 min of 60-90 min budget (counting both rate-limited fresh starts as ~0 cost since prior runs halted before meaningful reads landed).
- Read-only across all 5 repos. Zero commits, zero git modifications.

---

**Bottom line for orchestrator**: Track 2.D is the **third confirming data point** for the Audit-grep-overestimate pattern (after Track 2.A red-team finding + Track 2.B fix-agent finding at `cef642a`). The Manager-decomp roadmap §3.1 claim "Track 2 = 28-42h consumer adoption" should be re-baselined to **~3-5h** across all three Track 2 sub-tracks combined, with Track 2.D specifically being **~2h polish + ~2-3h optional cosmetic rename**. The "MED-risk Session tangling" flag was historically valid pre-PR-5.6/Brief-3 but is **empirically resolved at HEAD `e406da1`**.
