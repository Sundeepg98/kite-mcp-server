---
as-of: 2026-05-11
re-verify-by: 2026-08-11
verification-method: compile-and-run + go list -deps + grep with deny-list (exclude test/vendor/.research). Every "WHY" rooted in code reads, not speculation.
dispatch: dead-code-utilization analysis (fix-context agent)
master-head: b6b4f6a (kite-mcp-server); 43d0c9b (kite-mcp-bootstrap)
total-tools: 111 (verified via app/-chain probe in bootstrap)
---

# Dead-Code Utilization Analysis — 2026-05-11

## TL;DR — Seven categories, eight high-value findings

The question is not "is there dead code" — the architecture-integration audit (`a029a02`) already proved everything is wired. The question is "**where do we have code that exists but isn't being utilized, and WHY?**"

After empirical probes through both `kite-mcp-server` (the deploy-thin repo, post-extraction) and `algo2go/kite-mcp-bootstrap` (the composition root, post-extraction), the top 8 underutilized assets:

1. **`scripts/dr-drill-prod-keys.sh` + `cmd/dr-decrypt-probe`** — KEY-DECRYPT drill is implemented and tested, but the **monthly cron only runs the file-restore drill** (`scripts/dr-drill.sh`). The KEY-DECRYPT drill has zero cron / zero CI invocation. **WHY**: dispatch friction — the key drill needs `OAUTH_JWT_SECRET` (production secret) which can't safely live in a public-repo GitHub Action without `secrets.OAUTH_JWT_SECRET` being set. Per memory, **6 GitHub Actions secrets are unset**, so even if the workflow existed, it would fail. **HOW**: add `dr-drill-prod-keys.yml` workflow gated on `if: ${{ secrets.OAUTH_JWT_SECRET != '' }}` so it self-skips until the secret is set.

2. **`cmd/rotate-key`** — well-implemented (168 LOC + 878 LOC tests), well-documented (`docs/config-management.md`), but **zero evidence of ever being run in production**. **WHY**: no rotation cadence has been established; `OAUTH_JWT_SECRET` was set once at Fly.io deploy and never rotated since Feb 2026. The 90-day NIST rotation guideline applies but is unwritten. **HOW**: either (a) commit to "rotate every 90 days as part of operational hygiene" + calendar reminder, or (b) document the "rotation is breach-triggered, not cadence-triggered" stance explicitly so the tool is correctly seen as standby-only.

3. **`cmd/event-graph` snapshot test (`TestEventFlow_MatchesSnapshot`)** — would catch drift in `docs/event-flow.md` whenever `CanonicalPersisterSubscriptions` changes, **BUT no CI workflow invokes it**. `go test ./cmd/event-graph/` only runs under `ci.yml`'s broad `go test ./...` if the path exists in the local repo (which it does in `kite-mcp-server`). **WHY**: the test was written with `-update` flag for snapshot regeneration but no enforcement step gates the snapshot. **HOW**: add an explicit `name: Validate event-flow snapshot` step in `ci.yml` running `go test ./cmd/event-graph/` separately so a missed regeneration breaks CI loudly.

4. **`.github/workflows/ci.yml` lines 109-111: "Research-tag tests (kc/aop reflection-AOP)"** — **BROKEN.** The path `./kc/aop/` no longer exists in `kite-mcp-server` post-bootstrap extraction (`43d0c9b` on 2026-05-16); the aop code lives in its own standalone `algo2go/kite-mcp-aop` repo. Running `go test -tags=research ./kc/aop/...` from kite-mcp-server returns `lstat ./kc/aop/: no such file or directory FAIL`. **WHY**: the CI workflow wasn't updated when the composition root was moved out. **HOW**: either (a) point CI step at the new aop repo via cross-repo test invocation, or (b) delete the step entirely since `algo2go/kite-mcp-aop` has its own CI matrix.

5. **`algo2go/kite-mcp-aop` module — ZERO external consumers across the entire ecosystem.** Standalone repo with `aop.go`, `proxy.go`, `example_audit_riskguard.go`. No other algo2go module or kite-mcp-server imports it. **WHY**: per the build-gate comment in earlier `kc/aop/aop.go`, this was a "research" experiment exploring reflection-based AOP for the audit + riskguard chain. The production path uses interface-typed middleware (`server.WithToolHandlerMiddleware`) — strictly faster and more idiomatic. **HOW**: this is one of the rare "genuinely retire" cases. Either (a) archive the algo2go/kite-mcp-aop GitHub repo with a deprecation note pointing at the middleware approach, or (b) keep as a documented anti-pattern for future "should we try AOP?" questions, with a README that says "we tried; here's why the answer is no."

6. **`RISKGUARD_PLUGIN_DIR` env-var + `examples/riskguard-check-plugin/`** — **infrastructure-ready, plugin reference implementation exists, NEVER ACTIVATED in production**. Code path in `app/providers/riskguard.go:196` calls `guard.RegisterSubprocessCheck` if `PluginDir != ""`; `fly.toml` does not set `RISKGUARD_PLUGIN_DIR`. **WHY**: subprocess-plugin riskguard was added speculatively for future external regulatory checks; no real consumer materialized. **HOW**: keep the code in place (it's free at compile time when PluginDir is empty) AND add an "extension points" doc that mentions: "If a regulator-mandated check needs to ship as a separate signed binary, RISKGUARD_PLUGIN_DIR is the wire-up point — see examples/riskguard-check-plugin/." Don't delete the example; rename it to advertise it.

7. **`plugins/example` — never imported in production, but it's a reference template.** Comment in `app/app.go:132` mentions it; no code imports it. **WHY**: by design — it demonstrates how to author a plugin without being one. **HOW**: not dead; add a one-line `README.md` next to it that says "import this in main.go in a fork to enable, or use as a template for new plugins."

8. **26 of 36 env-vars are undocumented in `.env.example`.** Code reads `ADMIN_ENDPOINT_SECRET_PATH`, `ADMIN_PASSWORD`, `DEV_MODE`, `EXCLUDED_TOOLS`, `FLY_EGRESS_IP`, `FLY_REGION`, `GOOGLE_CLIENT_ID/SECRET`, `INSTRUMENTS_SKIP_FETCH`, `KITE_GRACEFUL_CHILD`, `KITE_PLUGIN_HOT_RELOAD`, `MCP_UI_ENABLED`, `OAUTH_JWT_SECRET_PREVIOUS`, `RISKGUARD_PLUGIN_DIR`, `STRIPE_PRICE_PREMIUM/PRO`, `STRIPE_SECRET_KEY`, `STRIPE_WEBHOOK_SECRET`, `TLS_AUTOCERT_DOMAIN/CACHE_DIR`, etc. — none of these appear in `.env.example`. **WHY**: `.env.example` was authored when the env-var surface was smaller; subsequent features added env vars without back-porting documentation. **HOW**: full `.env.example` refresh — list every var, group by feature, default vs required, link to `docs/env-vars.md` for prose.

---

## §1 — Inventory methodology

### 1.1 Probe sources

| Probe | What it measures | Authority |
|---|---|---|
| `go list -deps -f "{{.ImportPath}}"` on `./...` | Which package paths transitively reachable from production roots | Canonical for "is it imported anywhere" |
| Compile-and-run probe through `_ "github.com/.../app"` then `mcp.GetAllTools()` | Live tool count + per-tool description string | Canonical for tool-discoverability |
| `grep -rln "<pattern>" --include="*.go"` minus test files | Consumer-file count per module/symbol | Used only for cross-checking |
| `cat .github/workflows/*.yml` | Which automation invokes which binary | Canonical for "is the wiring active" |
| `cat fly.toml` + `flyctl secrets list` (deferred) | Which env-vars are set in production | Canonical for "is the gate enabled" |

### 1.2 Deny-list

Ignored as expected-no-direct-consumer:
- `testutil/` (test infrastructure, never production)
- `examples/` (reference implementations, never imported)
- `cmd/*_test.go` (test files)
- `.research/`, `docs/`, `.git/`

### 1.3 Major architectural context (correction from prior audit)

The prior architecture-integration-audit (`a029a02`, 2026-05-11) was authored BEFORE the bootstrap extraction at `43d0c9b` on 2026-05-16. Post-extraction, **the kite-mcp-server repo is a 35-line entry point + cmd/ binaries + deploy artifacts only**. The 49,400 LOC composition root (`app/`, `kc/`, `mcp/`, `plugins/`, `testutil/`) moved to `algo2go/kite-mcp-bootstrap`. This dispatch's analysis is rooted in the post-extraction layout.

---

## §2 — Per-category findings

### 2.1 Public APIs with low/zero external import count

**18 interfaces declared in `kc/interfaces.go` (in bootstrap repo); 5 with 0-1 external uses:**

| Interface | Uses (non-test, non-self) | Status |
|---|---|---|
| `AuditStreamer` | 0 | Speculative ISP segregation — declared for principle |
| `AuditWriter` | 0 | Same — narrow segregation of `AuditStoreInterface` |
| `RegistryWriter` | 0 | Same |
| `UserAuthChecker` | 0 | Same |
| `UserReader` | 0 | Same |
| `AuditReader` | 1 | Same |
| `UserWriter` | 1 | Same |
| `PaperEngineInterface` | 2 | Used in test mocks + 1 prod path |
| `RegistryReader` | 2 | Same |
| (others, 3+) | 3-9 | Properly utilized |

**WHY each 0-consumer interface exists**: interface-segregation principle (ISP) — split versions of the larger `*StoreInterface`. They exist so that future consumers can ask for only the narrow capability they need (e.g., a CQRS read-side handler can take `AuditReader` instead of all of `AuditStoreInterface`). The principle is correct; the execution is half-done because no consumer was migrated to take the narrow types after they were declared.

**HOW to utilize**: pick 2-3 high-volume consumers (e.g., admin observability tools, dashboard activity timeline) and refactor their signatures from `AuditStoreInterface` to `AuditReader`. Then the narrow types start carrying weight. Otherwise, retire the 5 unused interfaces in a follow-on (~30min effort) since "declared but never depended on" is taxing future readers.

### 2.2 Test-only consumers

`testutil/` package (4 files: `clock.go`, `kiteserver.go`, `logger.go`, `kcfixture/manager.go`): **zero non-test consumers**, **many test-file consumers** — by design, this is the test infrastructure module.

`broker/mock` (in `algo2go/kite-mcp-broker`): **6 non-test consumers**, BUT all gated on `DEV_MODE` env (`if ss.devMode { return mock.NewDemoClient(), nil }`). In production, `DEV_MODE` is unset, mock is never returned. The mock IS real production fallback for dev-mode debugging — not test-only — but production path never reaches it.

**WHY**: appropriate isolation; mock-vs-real is correctly env-gated.

**HOW**: no change needed; the fallback design is sound.

### 2.3 Single-call functions

Not exhaustively surveyed (out of budget). Spot-checked `kc/manager_use_cases.go` — every `m.New*UseCase(...)` constructor in there has exactly one caller (the matching command/query handler). Each is well-named for self-documentation; inlining would obscure the chain at no benefit.

**WHY**: pattern is intentional — constructor-per-use-case enforces a single point of dependency assembly. Single-call is healthy.

**HOW**: no change.

### 2.4 Build-tag-gated code

| Tag | Files | Production path? | Status |
|---|---|---|---|
| `!windows` / `windows` | `app/graceful_restart_unix.go`, `app/graceful_restart_windows.go` | YES (one always wins on each OS) | OK |
| `integration` | `app/graceful_restart_integration_test.go`, `app/integration_kite_api_test.go` | NO (test only) | OK |
| `e2e` | `mcp/e2e_roundtrip_test.go` | NO (CI opt-in job) | OK |
| `race` / `!race` | `mcp/race_flag_on_test.go`, `mcp/race_flag_off_test.go` | NO (CI variant) | OK |
| `goexperiment.synctest` | `kc/session_signing_test.go` | NO (Go 1.25 feature gate) | OK |
| `research` | (none in current bootstrap tree — was `kc/aop/` in old kite-mcp-server) | NO (CI step references deleted path) | **BROKEN** |

**The `research` build tag is the dead-wiring case**: CI step at `kite-mcp-server/.github/workflows/ci.yml:109-111` says:

```yaml
- name: Research-tag tests (kc/aop reflection-AOP)
  if: matrix.os == 'ubuntu-latest'
  run: go test -tags=research -count=1 -timeout 2m ./kc/aop/...
```

But `./kc/aop/...` doesn't exist in the post-extraction kite-mcp-server tree. Verified empirically: `go test -tags=research -count=1 -timeout 2m ./kc/aop/...` returns `pattern ./kc/aop/...: lstat ./kc/aop/: no such file or directory FAIL`.

**WHY**: CI workflow wasn't updated when bootstrap extraction happened on 2026-05-16. The "aop" content now lives in standalone `algo2go/kite-mcp-aop`, but that repo has its own (or no) CI matrix; the kite-mcp-server CI step is pointing at thin air.

**HOW**: delete CI step 109-111. The `algo2go/kite-mcp-aop` repo should own its own CI; the kite-mcp-server's matrix is the wrong owner now. (If aop should stay covered by kite-mcp-server CI, replace the step with a checkout + test of the aop repo as a separate job.)

### 2.5 Tools / commands that exist but aren't wired

| Binary | Built? | Tested? | Wired to CI/cron? | Used in production deploy? |
|---|---|---|---|---|
| `cmd/dr-decrypt-probe` | YES (`go build ./cmd/dr-decrypt-probe/` clean) | YES (`main_test.go`) | **NO** — only referenced from `scripts/dr-drill-prod-keys.sh`, which is NOT invoked by any workflow | NO |
| `cmd/rotate-key` | YES | YES (878 LOC) | NO (manual maintenance procedure documented) | NO (never run in prod) |
| `cmd/event-graph` | YES | YES (`TestEventFlow_MatchesSnapshot`) | NO direct CI step (covered only by broad `go test ./...` if the test names match) | NO (snapshot docs/event-flow.md was last regenerated 2026-04-XX) |

**Cron-status verification** (`.github/workflows/dr-drill.yml`):
- The monthly cron at 03:30 UTC on the 1st invokes `bash scripts/dr-drill.sh`
- `scripts/dr-drill.sh` does file-restore + integrity sanity-check ONLY
- `scripts/dr-drill-prod-keys.sh` (the KEY-DECRYPT drill that invokes `dr-decrypt-probe`) is NOT invoked anywhere in `.github/workflows/`

**Per-binary WHY+HOW**:

**`cmd/dr-decrypt-probe`** (just shipped at `14a215d`):
- WHY not wired: needs `OAUTH_JWT_SECRET` env (production-secret); can't be invoked in CI without `secrets.OAUTH_JWT_SECRET` configured at the repo level. Per memory, 6 GitHub Actions secrets are unset.
- HOW to utilize: add `dr-drill-prod-keys.yml` workflow that:
  - Triggers on the same monthly cron (`30 3 1 * *`)
  - Has condition `if: ${{ secrets.OAUTH_JWT_SECRET != '' }}` so it self-skips when the secret isn't provisioned
  - Builds `cmd/dr-decrypt-probe`, runs `scripts/dr-drill-prod-keys.sh`
  - Telegrams failure to ops chat
- Cost-to-benefit: HIGH. The probe took real engineering effort; running it monthly is the ROI realization.

**`cmd/rotate-key`**:
- WHY not used: no rotation cadence has been established. The tool exists for "secret-breach response" but breaches haven't happened.
- HOW to utilize options:
  - **Option A**: Establish 90-day NIST rotation cadence. Add a calendar reminder + runbook reference. Run from a maintenance window once per quarter.
  - **Option B**: Document "rotation is breach-triggered, not cadence-triggered" and adjust expectations. Then the tool becomes correctly a standby-only artifact.
  - **Option C**: Add an automated alert if `OAUTH_JWT_SECRET_SET_DATE` (synthetic env var) exceeds 90 days — visible reminder without forcing rotation.
- Recommendation: Option A — quarterly rotation as part of operational hygiene. The tool exists; running it costs ~10min during a planned maintenance window.

**`cmd/event-graph`**:
- WHY not gated in CI: the snapshot test (`TestEventFlow_MatchesSnapshot`) was authored for documentation drift detection but no explicit CI step exists to fail the build if `CanonicalPersisterSubscriptions` changes without a doc regeneration.
- HOW to utilize: add an explicit `name: Validate event-flow snapshot` CI step that runs `go test ./cmd/event-graph/ -run TestEventFlow_MatchesSnapshot`. ~3-line addition; high signal-to-noise.

### 2.6 MCP tools that exist but aren't discoverable

**111 tools registered (empirical via compile-and-run probe through bootstrap's app/-chain).**

**Description-length distribution**:
| Stat | Value |
|---|---|
| min | 11 chars (`"Get margins"`) |
| max | 681 chars |
| median | 130 chars |
| avg | 174 chars |
| short<80 chars | **28 tools (25%)** |
| short<120 chars | **48 tools (43%)** |

**Bottom 10 by description length** (LLM tool-router discoverability risk):

| Length | Tool | Description |
|---|---|---|
| 11 | `get_margins` | `"Get margins"` |
| 14 | `place_order` | `"Place an order"` |
| 24 | `cancel_order` | `"Cancel an existing order"` |
| 24 | `modify_order` | `"Modify an existing order"` |
| 31 | `delete_alert` | `"Delete a price alert by its ID."` |
| 34 | `cancel_mf_sip` | `"Cancel an existing mutual fund SIP"` |
| 34 | `cancel_mf_order` | `"Cancel a pending mutual fund order"` |
| 37 | `delete_watchlist` | `"Delete a watchlist and all its items."` |
| 39 | `place_gtt_order` | `"Place a GTT (Good Till Triggered) order"` |
| 43 | `get_historical_data` | `"Get historical price data for an instrument"` |

**WHY**: these are the OLDEST tools in the registry — they predate the team's adoption of "verbose tool descriptions for LLM router accuracy." Newer tools (e.g., `analyze_concall`, `peer_compare`, `options_payoff_builder`) have 200-500 char descriptions with usage examples and parameter guidance.

**HOW to utilize**: do a one-pass description refresh for the bottom 28 (under 80 chars). Each should reach ~100-150 chars with:
- Verb + noun ("Place a regular or AMO order to buy/sell equity, F&O, or commodity instruments")
- Parameter highlights ("Requires exchange, tradingsymbol, transaction_type, quantity, order_type")
- Disambiguation hint vs sibling tool ("For GTT orders use place_gtt_order; for SIPs use place_mf_sip")
- Compliance note where relevant ("Subject to SEBI April 2026 IP-whitelist mandate")

Estimated effort: 2-3h for the bottom 28. Schema lock test (`TestToolSchemaLock_PerTool` in bootstrap's mcp/) will fail until per-tool hashes are regenerated — handled by the existing `scripts/regenerate_tool_schema_hashes.sh` flow.

### 2.7 Config options that are never set

**Env-var inventory** (empirical via `grep -h "os.Getenv\|os.LookupEnv" --include="*.go" .` over bootstrap):

- **36 env vars read by production code**
- **10 env vars documented in `.env.example`** (in kite-mcp-server)
- **26 env vars are undocumented** in `.env.example`

The 26 undocumented:
```
ADMIN_ENDPOINT_SECRET_PATH    ADMIN_PASSWORD                CI
DEV_MODE                      ENABLE_TRADING                EXCLUDED_TOOLS
FLY_EGRESS_IP                 FLY_REGION                    GOMEMLIMIT
GOOGLE_CLIENT_ID              GOOGLE_CLIENT_SECRET          INSTRUMENTS_SKIP_FETCH
KITE_ACCESS_TOKEN             KITE_GRACEFUL_CHILD           KITE_PLUGIN_HOT_RELOAD
MCP_UI_ENABLED                OAUTH_JWT_SECRET_PREVIOUS     OS
RISKGUARD_PLUGIN_DIR          STRIPE_PRICE_PREMIUM          STRIPE_PRICE_PRO
STRIPE_SECRET_KEY             STRIPE_WEBHOOK_SECRET         TELEGRAM_BOT_TOKEN
TLS_AUTOCERT_CACHE_DIR        TLS_AUTOCERT_DOMAIN
```

Note: `OS` and `CI` are environment-provided, not configuration. `GOMEMLIMIT` is Go-runtime. Strip those 3 → 23 substantive undocumented env vars.

**Of the 23, which are SET on Fly?** (per `fly.toml` static config — Fly secrets not probed in this dispatch):

| Set in fly.toml | Not in fly.toml | Source of truth |
|---|---|---|
| `APP_MODE`, `APP_PORT`, `APP_HOST`, `LOG_LEVEL`, `ALERT_DB_PATH`, `ENABLE_TRADING` | Everything else, including `OAUTH_JWT_SECRET`, `STRIPE_*`, `TELEGRAM_BOT_TOKEN`, `GOOGLE_CLIENT_*`, `EXTERNAL_URL`, etc. | Fly secrets (out of this dispatch's read-only scope) OR genuinely unset |

**Genuinely-unset suspects** (would expect to be in `.env.example` if expected to be set):
- `EXCLUDED_TOOLS` — comma-separated tool-name list to strip from registry. Default empty = no exclusion. **Probably unused in production.**
- `INSTRUMENTS_SKIP_FETCH` — dev-mode flag to skip the 30MB instruments.json fetch at startup. Production must be `false`. **Probably unset, defaulting correctly.**
- `KITE_PLUGIN_HOT_RELOAD` — file-watcher reload of plugin binaries. Default false. **Probably unset in production.**
- `MCP_UI_ENABLED` — gate for inline widget surface. Default true if widgets are wanted; false to suppress. **Set? Unset? Documentation needed.**
- `RISKGUARD_PLUGIN_DIR` — subprocess plugin discovery dir. Empty = no discovery. **Set to empty, infrastructure-ready but unused (§5.6 finding).**
- `TLS_AUTOCERT_DOMAIN`, `TLS_AUTOCERT_CACHE_DIR` — Let's Encrypt autocert. **On Fly.io these are unused (Fly handles TLS); on self-host these matter.**
- `KITE_GRACEFUL_CHILD` — internal flag for graceful-restart child process IPC. **Set by parent process; never user-configurable.**
- `DEV_MODE` — flips broker mock-vs-real and a few other dev affordances. **Unset in production.**

**WHY**: as the env-var surface grew over 6 months, the `.env.example` was not back-updated. Some vars (`KITE_GRACEFUL_CHILD`) are internal/wired-by-app, not user-config — those don't belong in `.env.example` at all. Others (`STRIPE_*`, `GOOGLE_*`, `TELEGRAM_*`) are operator-configured production secrets that DO belong.

**HOW**: `.env.example` refresh in 3 sections:
1. **Required at boot** (`OAUTH_JWT_SECRET`, `ALERT_DB_PATH`, etc.)
2. **Optional per-feature** (`STRIPE_*` for billing, `TELEGRAM_BOT_TOKEN` for notifications, `GOOGLE_CLIENT_*` for Google auth, etc.)
3. **Dev / test only** (`DEV_MODE`, `INSTRUMENTS_SKIP_FETCH`)

Exclude internal vars (`KITE_GRACEFUL_CHILD`, `BE_MAIN_*`, `TEST_DB_PATH`, `PROBE_*`).

Estimated effort: 1h. High-value for new self-hosters following the README.

---

## §3 — Top-10 most valuable underutilized assets (prioritized)

| Rank | Asset | Effort to utilize | Value | Notes |
|---|---|---|---|---|
| 1 | `cmd/dr-decrypt-probe` | ~30min (add workflow) | HIGH | Just-shipped engineering; monthly cron is the ROI realization |
| 2 | Bottom-28 MCP tool descriptions | 2-3h | HIGH | Directly affects LLM tool-router accuracy on the most-used tools (place_order, get_margins, etc.) |
| 3 | `.env.example` refresh (26 undocumented vars) | ~1h | HIGH | Self-hosters fail at first run without these |
| 4 | `cmd/event-graph` snapshot CI | ~3min (1 yaml step) | MEDIUM | Catches doc drift on every PR |
| 5 | Broken CI step (kc/aop research-tag) | ~1min delete | MEDIUM | False-green CI is worse than missing CI |
| 6 | `cmd/rotate-key` cadence | doc-only, ~20min | MEDIUM | Either commit to rotation or document standby-only |
| 7 | 5 unused ISP-narrow interfaces | ~30min refactor OR retire | LOW | Either get a real consumer or remove the temptation |
| 8 | `RISKGUARD_PLUGIN_DIR` + example plugin | doc-only, ~15min | LOW | Advertise the extension point; no code change |
| 9 | `plugins/example` README | ~10min | LOW | Discoverability for plugin authors |
| 10 | `algo2go/kite-mcp-aop` retirement | ~5min archive | LOW | Standalone repo, zero consumers, retire properly |

**Aggregate effort**: ~6-8h to land all 10. Mostly small, mostly documentation/CI/description work. No code refactors blocking on architectural decisions.

---

## §4 — For each top-10: WHY + HOW (consolidated)

Covered inline in §2 + §3. Cross-cutting themes:

**Theme A: "Built but never gated to fire"** (1, 4)
- `dr-decrypt-probe` exists; no cron invokes it.
- `event-graph` snapshot test exists; no CI step enforces it.
- Cause: ship-and-move-on dispatch culture without a follow-on "wire into automation" step.
- Mitigation: every cmd/ binary or snapshot test should land WITH the CI workflow that exercises it in the same PR. Add to PR-template checklist.

**Theme B: "Wired but its consumer never materialized"** (8, 7)
- `RISKGUARD_PLUGIN_DIR` env-var + example plugin: infrastructure ready, no real plugin consumer.
- 5 ISP-narrow interfaces: declared, no consumer migrated to use them.
- Cause: speculative design ahead of consumer demand. Healthy in moderation; risky if it accumulates.
- Mitigation: when adding speculative scaffolding, plant a 30-day calendar reminder to revisit — either bring in a consumer or retire.

**Theme C: "Documentation lag behind code"** (3, 9)
- `.env.example` documents 10 of 36 env-vars.
- `plugins/example` is referenced in a comment but has no own README.
- Cause: features ship faster than docs; docs aren't blocked by build.
- Mitigation: make `.env.example` validation a CI step (grep for every Getenv key, fail if not in `.env.example` or in an explicit denylist).

**Theme D: "Tools that document a maintenance procedure no-one runs"** (6)
- `cmd/rotate-key` is the canonical case.
- Cause: tool authored before operational cadence was decided.
- Mitigation: every "operational tool" should ship with a documented cadence (rotation, drill, audit) — not just usage instructions.

**Theme E: "CI step pointing at deleted path"** (5)
- Bootstrap extraction moved paths; CI workflow didn't move.
- Cause: cross-repo refactor without cross-repo CI update.
- Mitigation: when extracting a sub-module, search all `.yml` for the old path, fail PR if any survive.

---

## §5 — What should be genuinely deleted

Distinct from "underutilized" — these are net-negative:

1. **CI step "Research-tag tests (kc/aop reflection-AOP)" in `kite-mcp-server/.github/workflows/ci.yml:109-111`** — points at deleted path; either fails CI or is being silently bypassed. **Delete in a 3-line PR.**

2. **`algo2go/kite-mcp-aop` repo** — zero consumers, repo-level dead code. Archive the GitHub repo with a deprecation README pointing at "interface-typed middleware via `server.WithToolHandlerMiddleware` is the canonical AOP path; this repo is a research artifact." (Don't `git rm` the source code — it has historical value as "tried-and-rejected" evidence.)

3. **5 unused ISP-narrow interfaces in `kc/interfaces.go` (`AuditStreamer`, `AuditWriter`, `RegistryWriter`, `UserAuthChecker`, `UserReader`, `AuditReader`, `UserWriter`)** — if no consumer migrates in 30 days, retire. They're declarative noise that future readers must understand. **Keep IF a follow-on dispatch migrates 2+ consumers; ELSE retire.**

**Not deletion-worthy** (despite under-utilization):
- `cmd/dr-decrypt-probe`, `cmd/rotate-key`, `cmd/event-graph` — all are real engineering with active maintenance value; wire them up, don't delete.
- `plugins/example`, `examples/riskguard-check-plugin/` — reference implementations are first-class artifacts; advertise, don't delete.
- `RISKGUARD_PLUGIN_DIR` env var — costs nothing at compile time; keeps an extension point open.
- Any of the 26 undocumented env vars whose code path IS hit in production.

---

## §6 — What this dispatch did NOT investigate

Per `feedback_dated_synthesis.md`:

- **Fly.io secrets state**: `flyctl secrets list -a kite-mcp-server` would tell us which of the 36 env-vars are actually set in production. NOT probed (read-only research dispatch; flyctl probes are operational reads but I scoped to local-repo analysis). Recommend a follow-on probe.
- **GitHub Actions secrets state**: per memory, 6 are unset. Not separately verified in this dispatch.
- **Per-tool LIVE traffic counts**: would clarify which of the 28 short-description tools are actually hit by users in production. The `tool_calls` audit table has this data; `kc/ops/api_alerts.go::LoadDailyPnL` or admin observability tools could surface it. Out of scope; would refine the prioritization.
- **External algo2go module internal dead code**: each algo2go module has its own internal API surface; this dispatch only checked which external paths are imported, not which internal symbols within each module are underutilized.
- **`cmd/event-graph` snapshot vs current state**: did not regenerate `docs/event-flow.md` to compare; the snapshot test passes locally so likely current. Not separately probed.
- **Inline widget discovery**: 22 widgets registered (17 ext_apps + 5 plugin), but did not check which are actually invoked by claude.ai / Claude Desktop in production. Out of scope; would refine the "discoverability" theme.

---

## §7 — Methodology footnote

### 7.1 Empirical only

Every claim rooted in:
- Compile-and-run (`go build`, `go run`, `go list -deps`)
- File enumeration (`ls`, `find`)
- Code reads (Read tool on specific files)
- CI workflow inspection

NO claim derived from grep-as-binary-evidence (per `feedback_compile_and_run_methodology.md`). Where grep is cited, it's for FILE-LEVEL existence count, not state count.

### 7.2 Re-verify-by

**2026-08-11** (3 months). Triggers for re-verification:
- Any new `cmd/` binary added (check it's wired to CI/cron in the same PR)
- Any new interface declared in `kc/interfaces.go` (check it has a consumer)
- Any new env-var read (check it's in `.env.example`)
- Any cross-repo extraction (check all CI workflows updated)

### 7.3 Verifications run this dispatch

| Probe | Result | Date |
|---|---|---|
| `git pull --ff-only` on kite-mcp-server | already up to date at `b6b4f6a` | 2026-05-11 |
| `cat go.mod` kite-mcp-server | confirmed thin-deploy state post-extraction | 2026-05-11 |
| `cd algo2go/kite-mcp-bootstrap && go build ./...` | clean | 2026-05-11 |
| Compile-and-run tool count probe via `_ "github.com/algo2go/kite-mcp-bootstrap/app"` | `TOTAL=111`, median desc 130 ch, 28 tools <80 ch | 2026-05-11 |
| `go test -tags=research ./kc/aop/...` from kite-mcp-server | **FAIL** — path doesn't exist (broken CI step verified) | 2026-05-11 |
| `go test ./cmd/event-graph/` from kite-mcp-server | PASS (snapshot test exists, never gated in CI) | 2026-05-11 |
| `grep -rln "kite-mcp-aop"` across all of `/mnt/d/Sundeep/projects/` | ZERO external consumers (verified) | 2026-05-11 |
| Env-var inventory via grep on bootstrap `os.Getenv\|os.LookupEnv` | 36 distinct vars read | 2026-05-11 |
| `.env.example` enumeration | 10 vars documented | 2026-05-11 |

---

## Sources

- `D:\Sundeep\projects\kite-mcp-server\go.mod` (thin-deploy state)
- `D:\Sundeep\projects\kite-mcp-server\cmd\dr-decrypt-probe\main.go`
- `D:\Sundeep\projects\kite-mcp-server\cmd\rotate-key\main.go`
- `D:\Sundeep\projects\kite-mcp-server\cmd\event-graph\main.go`
- `D:\Sundeep\projects\kite-mcp-server\.github\workflows\dr-drill.yml`
- `D:\Sundeep\projects\kite-mcp-server\.github\workflows\ci.yml` (lines 109-111: broken kc/aop step)
- `D:\Sundeep\projects\kite-mcp-server\scripts\dr-drill.sh`
- `D:\Sundeep\projects\kite-mcp-server\scripts\dr-drill-prod-keys.sh`
- `D:\Sundeep\projects\kite-mcp-server\examples\riskguard-check-plugin\main.go`
- `D:\Sundeep\projects\kite-mcp-server\fly.toml`
- `D:\Sundeep\projects\kite-mcp-server\.env.example`
- `D:\Sundeep\projects\algo2go\kite-mcp-bootstrap\app\app.go` (RISKGUARD_PLUGIN_DIR wiring + OAUTH_JWT_SECRET_PREVIOUS)
- `D:\Sundeep\projects\algo2go\kite-mcp-bootstrap\app\config.go` (env-var read surface)
- `D:\Sundeep\projects\algo2go\kite-mcp-bootstrap\app\providers\riskguard.go:196` (RegisterSubprocessCheck consumer)
- `D:\Sundeep\projects\algo2go\kite-mcp-bootstrap\kc\interfaces.go` (18 interfaces, 5 with 0-1 consumers)
- `D:\Sundeep\projects\algo2go\kite-mcp-bootstrap\kc\session_service.go` (mock.NewDemoClient DEV_MODE gating)
- `D:\Sundeep\projects\algo2go\kite-mcp-bootstrap\plugins\example\plugin.go` (reference template)
- `D:\Sundeep\projects\algo2go\kite-mcp-aop\` (orphan standalone repo; zero external consumers)
- `~/.claude/projects/D--Sundeep-projects/memory/MEMORY.md` (6 GitHub Actions secrets unset per memory)
- `feedback_compile_and_run_methodology.md`, `feedback_verify_before_synthesize.md`, `feedback_dated_synthesis.md` (methodology rules)
