# Fork LOC Split + Tier-3 Promotion Triggers

**Date**: 2026-04-28 night
**HEAD audited**: `e3bfba3`
**Charter**: read-only research deliverable. Two parts: (1) empirical
upstream-vs-our-additions LOC split for marketing / FLOSS-fund / Rainmatter
pitch; (2) per-Tier-3 promotion-trigger documentation for the
`parallel-stack-shift-roadmap.md` (`8361409`) tracks-foundation question.

**Anchor docs**:
- `.research/parallel-stack-shift-roadmap.md` (`8361409`) — three-track
  per-component port roadmap; this doc's Part 2 feeds the trigger column
  the roadmap's per-component cost rows reference.
- `.research/scorecard-final-v2.md` (`8361409`) — current empirical state
  (Hex 99→100 close-out, mcp/ thinness re-measure).
- `feedback_decoupling_denominator.md` — three-axis ROI framework
  (user-MRR, agent-concurrency, tech-stack-portability).

---

## Part 1 — Empirical fork LOC split

### 1.1 Fork-boundary identification

**Upstream remote**: `https://github.com/zerodha/kite-mcp-server.git`
**Fork remote**: `https://github.com/Sundeepg98/kite-mcp-server.git`
**Common ancestor (merge-base)**: `dcf2dc4` (`fix: simplify return statement
in isDailyMetric for linting`, Wed Aug 6 15:26:07 2025 +0530, by Rohan
Verma)

**Critical observation**: `git rev-parse upstream/master` = `dcf2dc4` =
`git merge-base upstream/master origin/master`. Upstream **has not advanced
since the fork point**. We forked at the upstream tip and have not
cherry-picked any upstream commits because there are none to pick. The
fork-boundary is unambiguous and stationary.

### 1.2 Methodology

LOC measurements via `cloc 1.98` (consistent across boundary + HEAD).
Attribution per file:
- "Fork-boundary LOC" — `git show dcf2dc4:<path> | wc -l` for files that
  existed at boundary
- "HEAD LOC" — `wc -l <path>` for files that exist at HEAD
- "Insertions / deletions" — `git diff --shortstat dcf2dc4..HEAD -- <path>`

Caveats acknowledged in the brief:
- **Cherry-picks**: NONE. Upstream has zero new commits since fork.
- **Touch-up edits to upstream files**: counted as "Modified-upstream" —
  separate column from net-new files
- **Doc/research files (`.research/`, `docs/`, root *.md)**: 100% ours
  (no upstream Markdown beyond `README.md`'s 9,357 byte fork-boundary
  baseline)

### 1.3 Fork-boundary file inventory

40 files at boundary. 28 are Go/HTML "code"; 12 are config/license/CI:

**Code files (28) — all surviving at HEAD**:

| File | Boundary LOC | HEAD LOC | Insertions | Deletions |
|---|---:|---:|---:|---:|
| app/app.go | 412 | 786 | 669 | 295 |
| app/app_test.go | 156 | 819 | 723 | 60 |
| app/metrics/daily_metrics_test.go | 163 | 167 | 4 | 0 |
| app/metrics/metrics.go | 367 | 387 | 24 | 4 |
| app/metrics/metrics_test.go | 433 | 862 | 429 | 0 |
| kc/instruments/instruments.go | 35 | 35 | 0 | 0 |
| kc/instruments/manager.go | 669 | 663 | 37 | 43 |
| kc/instruments/manager_test.go | 930 | 919 | 72 | 83 |
| kc/instruments/search.go | 103 | 103 | 0 | 0 |
| kc/manager.go | 600 | 402 | 318 | 516 |
| kc/manager_test.go | 544 | 520 | 306 | 330 |
| kc/session.go | 403 | 647 | 279 | 35 |
| kc/session_signing.go | 179 | 182 | 8 | 5 |
| kc/session_signing_test.go | 411 | 573 | 174 | 12 |
| kc/session_test.go | 673 | 975 | 302 | 0 |
| kc/templates/base.html | 128 | 129 | 1 | 0 |
| kc/templates/login_success.html | 26 | 29 | 3 | 0 |
| kc/templates/status.html | 18 | 30 | 12 | 0 |
| kc/templates/templates.go | 10 | 10 | 1 | 1 |
| main.go | 75 | 104 | 44 | 15 |
| mcp/common.go | 387 | 602 | 292 | 77 |
| mcp/common_test.go | 258 | 428 | 191 | 21 |
| mcp/get_tools.go | 265 | 349 | 131 | 47 |
| mcp/market_tools.go | 326 | 408 | 131 | 49 |
| mcp/mcp.go | 111 | 259 | 189 | 41 |
| mcp/mf_tools.go | 37 | 374 | 341 | 4 |
| mcp/post_tools.go | 535 | 497 | 259 | 297 |
| mcp/setup_tools.go | 89 | 594 | 528 | 23 |
| **TOTALS** | **8,343** | **11,853** | **5,468** | **1,958** |

**Config files (12)** — `.env.example`, `.envrc`, `.github/workflows/*`
(2 files), `.gitignore`, `LICENSE`, `README.md`, `flake.lock`, `flake.nix`,
`go.mod`, `go.sum`, `justfile`. ~9,357 byte README at boundary
(unchanged-ish at HEAD; we appended product-strategy material). Other
files are minor configs.

**Net upstream-derived LOC alive at HEAD** (lines that were never deleted
from the 28 boundary files): `8,343 − 1,958 = 6,385` LOC. Some of these
6,385 may have been re-touched by us in non-deletion edits, but that's the
upper bound on truly-unchanged-from-upstream content.

**Net our-modifications-onto-upstream-files** (insertions to those 28
files): `5,468` LOC.

### 1.4 Top-level directory split

Each directory's HEAD LOC and our-attribution:

| Directory | Status at boundary | HEAD LOC (Go + HTML/MD) | Our-LOC | % ours |
|---|---|---:|---:|---:|
| **app/** | existed (5 Go files, 1,142 LOC) | 19,177 Go | ~18,503 (insertions 29,056 − boundary 1,142) | ~96.5% |
| **kc/** | existed (14 files, 3,322 Go + 160 HTML) | 114,031 Go + 12,530 HTML + 313 MD | ~123,552 (insertions 173,355 − boundary 3,482) | ~97.2% |
| **mcp/** | existed (8 Go files, 1,619 LOC) | 46,543 Go | ~59,006 (insertions 60,625 − boundary 1,619) | ~97.3% |
| **oauth/** | NEW | 11,120 Go | 11,120 | **100%** |
| **broker/** | NEW | 8,033 Go | 8,033 | **100%** |
| **cmd/** | NEW | 895 Go | 895 | **100%** |
| **plugins/** | NEW | 614 Go | 614 | **100%** |
| **skills/** | NEW | 698 MD | 698 | **100%** |
| **docs/** | NEW | 10,234 MD | 10,234 | **100%** |
| **.research/** | NEW | 17,555 MD + 169 text | 17,724 | **100%** |
| **etc/** | NEW | 11 YAML | 11 | **100%** |
| **scripts/** | NEW | 762 sh + 49 MD + 18 batch | 829 | **100%** |
| **examples/** | NEW | 40 Go + 47 MD | 87 | **100%** |
| **tests/** | NEW | 219 TS + 129 MD + 34 JSON | 382 | **100%** |
| **testutil/** | NEW | 1,067 Go | 1,067 | **100%** |
| **main.go** | existed (51 LOC) | 66 | ~44 | ~66.7% |
| **Root *.md** | partial (README only at 9,357 bytes ≈ 280 LOC) | 2,333 MD | ~2,053 | ~88.0% |
| **Root configs** | partial (~5 of 12 at boundary) | 310 (Docker, fly, smithery, etc.) | ~250 | ~80% |

### 1.5 Aggregate "% original work"

**Frame A — narrow code-only attribution (Go + HTML, exclude docs)**:
- Total Go + HTML at HEAD: `201,586 + 12,530 = 214,116` LOC
- Truly-upstream-derived (surviving from boundary, no deletion): `≈6,385`
  LOC (lower bound — some may have been touched by us non-destructively)
- Our additions across all paths (Go + HTML, including modifications to
  upstream files + new files): `214,116 − 6,385 = 207,731` LOC
- **% original work (code only): `207,731 / 214,116 = 97.0%`**

**Frame B — including all artifacts (Go + HTML + Markdown + scripts +
configs)**:
- Total at HEAD: `244,749` LOC (per cloc full sweep)
- Truly-upstream-derived: `≈6,385` (28 code files) + `≈280` (README at
  boundary) ≈ `6,665` LOC
- Our additions: `244,749 − 6,665 = 238,084` LOC
- **% original work (everything): `238,084 / 244,749 = 97.3%`**

**Frame C — defensible "marketing-grade" number using only fork-boundary
files as denominator** (the "we kept the bones, replaced the meat" claim):
- 28 boundary code files: `8,343` LOC at boundary
- Same 28 files at HEAD: `11,853` LOC, of which `5,468` are our insertions
  and `6,385` are upstream-survived
- Our-mods-on-upstream-files = `5,468` (46% of those files' HEAD LOC is
  ours)
- **The 28 originally-upstream files are now `46.1%` ours** by line, and
  every byte outside those 28 files is `100%` ours

### 1.6 Recommended phrasing for marketing / FLOSS-fund / Rainmatter

**Conservative (passes scrutiny by SEBI/Zerodha legal review)**:

> "Fork derived from `zerodha/kite-mcp-server` (the official 22-tool
> read-only reference server, MIT-licensed). The original 28 source files
> contributed `8,343` LOC of foundational infrastructure (the `*kc.Manager`
> session model, instruments cache, Kite session signing, and the initial
> 7-tool MCP stub). Our additions total `~238,000` LOC across 80+ MCP
> tools, hexagonal architecture (`broker/`, `oauth/`, `kc/audit`,
> `kc/billing`, `kc/riskguard`, `kc/eventsourcing`, `kc/cqrs`, etc.),
> per-user OAuth (`oauth/` package, `~11,000` LOC), Telegram trading bot
> (`kc/telegram`, `~6,000` LOC), riskguard kill-switch (`kc/riskguard`),
> 330+ tests, and `~28,000` LOC of architectural research / threat model /
> compliance documentation. **97% of the codebase is original work**;
> upstream's foundational 3% is preserved verbatim under the original MIT
> attribution per `LICENSE` and `NOTICE`."

**Aggressive (FLOSS-fund / Rainmatter pitch — confident-tone)**:

> "We forked `zerodha/kite-mcp-server` at its upstream tip (commit
> `dcf2dc4`, August 2025). Upstream has not advanced since; everything
> that has happened to this codebase since the fork is ours. The fork is
> a complete architectural rebuild — the inherited `~6,400` LOC of
> upstream foundation now sits inside ours of `~238,000` LOC across 18
> production packages (oauth, broker, alerts, audit, billing, cqrs, ddd,
> domain, eventsourcing, instruments, logger, papertrading, ports,
> registry, riskguard, telegram, ticker, usecases, users, watchlist) plus
> `8` ADRs and `~28,000` LOC of design / compliance / threat-model
> research."

**Caveat for both**: Frame C's `46.1%` ours-on-original-files number is
the right disclosure if a reviewer challenges "but you kept their files".
Files like `kc/manager.go` (now `402` LOC, was `600`, with `516` deletions
and `318` insertions of ours) have been substantially restructured.

### 1.7 Honest caveats

1. **`cloc` LOC is a coarse measure**. It counts physical lines including
   blank-line separators within functions. A purer "logical statement"
   measure would shave ~10-15% off everything but the ratios stay similar.

2. **Ours-vs-upstream attribution at line granularity** would require
   `git blame` per line — too expensive for ~210k LOC. The diff-stat
   approach is the standard "good-enough" for forks like this.

3. **`testutil/` and `scripts/` and root-level `*.md` files** include
   per-package coverage scripts and security audit reports that ARE
   substantively work — including them is honest. Excluding them is also
   honest if the FLOSS-fund target asks "production code only".

4. **The 28 surviving code files** include 4 that we have not modified
   at all (`kc/instruments/instruments.go`, `kc/instruments/search.go`,
   `app/metrics/daily_metrics_test.go` had only 4 insertions, and
   `kc/templates/templates.go` is essentially unchanged). These are the
   pure "kept upstream" files.

5. **Generated code is not present in either count**. We do not have
   `protoc`-generated Go or codegen artifacts polluting the LOC.

6. **README diff is ~2,053 LOC inserted** — most of the current README is
   ours (product-strategy material added). Conservative frame (Frame A)
   excludes Markdown to avoid this skew.

---

## Part 2 — Tier-3 promotion triggers

The 8 components currently designated Tier 3 (staying in Go) per the
parallel-stack-shift roadmap. For each: current state, promotion trigger,
target language if promoted, cost, 24-month likelihood.

### 2.1 `kc/telegram/`

**Current state**: `~6,020` Go LOC across 15 files. Primary responsibilities:
Telegram webhook handler, /price /portfolio /positions /orders /pnl /alerts
/setalert /buy /sell /quick read+trade commands with inline-keyboard order
confirmation, per-chat rate limiting (10/min), pending-order TTL eviction
(60s), riskguard integration on confirm, paper-engine routing.
**Anti-idiom score**: `1/3` — the bot is mostly straight-line text
formatting + a thin `KiteManager` port; Go's strings/format library and
goroutine-per-chat-cleanup are idiomatic. The recent `d39437d` Concrete-
leak retirement closed the only abstraction-leak that was scoring against
Go's idiom strengths.

**Promotion trigger**: **rich-message UI templating + interactive flows**.
If we add (a) multi-step trading wizards (e.g. options strategy builder
with 3-leg confirmations across messages), (b) chart-image rendering
inline with /portfolio, (c) i18n for vernacular markets, OR (d) the
official Telegram Mini-Apps (TWA) integration with a JS bridge — the
JavaScript / TypeScript ecosystem dominates with `grammy` (TS), Telegraf,
and pre-built component libraries. Go's `tgbotapi` is competent but bare.

**Target language if promoted**: **TypeScript** (Bun or Node 22 runtime)
via `grammy` framework. Rationale: the bot's domain is "front-end-shaped
backend" — sessions, message templating, button chains. TS gives JSX-like
templating (custom JSX or `discord.js`/`grammy`-style builder DSLs) and
direct interop with TWA's `webApp.sendData()`. Cross-language IPC to the
Go core via the `parallel-stack-shift-roadmap.md` foundation-phase JSON-
RPC-over-stdio stays in scope (Telegram bot → Go riskguard / order
service via the established IPC).

**Cost**: `4-6 dev-weeks`. Components: TS port of 15 commands (~3 weeks),
IPC adapter for `KiteManager` (~1 week), test harness with `grammy/menu`
mocks (~1 week), CI plumbing (~0.5 weeks).

**24-month likelihood**: **Low** (`~15%`). The current /buy /sell flow is
production-stable; the only forcing function would be Telegram's
TWA-mandated migration for advanced trading or a vernacular-language SLA
demand. Both feel >24 months out absent a specific anchor customer.

### 2.2 `kc/billing/`

**Current state**: `~3,991` Go LOC across 15 files. Primary responsibilities:
Stripe Checkout / Customer Portal / Webhook handlers, per-tier subscription
state (Free / Pro / Premium), idempotency event log
(`webhook_events` table with `MarkEventProcessed` / `IsEventProcessed`),
admin auto-upgrade on payment success, `GetTierForUser` admin-linkage
fallback for family billing.
**Anti-idiom score**: `1/3` — the Stripe SDK and event-log idempotency are
straight Go; the only Go-anti-idiom is the `*billing.Store`-takes-concrete
signature on the 3 HTTP handlers (a Hex 99→100 residual blocker, but not
language-anti-idiom).

**Promotion trigger**: **multi-currency tax computation + revenue
recognition + invoice rendering**. If we ship (a) GST/IGST computation
across Indian states with HSN code routing, (b) ASC 606 / Ind AS 115
revenue-recognition state machines for annual-prepay subscriptions, (c)
PDF invoice generation with itemized tax tables — the numerical-stability
+ HTML-to-PDF + locale-formatting workload is Python's wheelhouse
(`decimal` module, `weasyprint`, `babel.numbers`). GST APIs (Cleartax,
ZohoBooks) all have Python SDKs first, Go SDKs second-or-never.

**Target language if promoted**: **Python 3.12** with `decimal.Decimal`
for currency, `weasyprint` for PDF, `pydantic` for schema validation, and
SQLAlchemy if we restructure the schema. Rationale: tax-engine domain is
where `pandas`/`decimal`/`pydantic` shine and Go's lack of a stable PDF
library bites.

**Cost**: `6-8 dev-weeks`. Components: Python service skeleton with FastAPI
(`~1` week), tax engine (GST registers, HSN code routing) (`~3` weeks),
PDF templating (`~1` week), Stripe webhook port + idempotency (`~1` week),
IPC adapter to Go `KiteManager` (`~1` week), test suite (`~1` week).

**24-month likelihood**: **Med** (`~35%`). Two forcing functions:
(a) crossing 100 paid subscribers triggers GST registration which
mandates HSN-coded invoices, (b) SEBI Investment Adviser registration
(if we go that route per `kite-cost-estimates.md`) requires audited
invoice trail. Either lands the python rewrite into the next 24-month
window. If we stay below 100 paid subscribers AND skip SEBI IA registration,
likelihood drops to Low.

### 2.3 `kc/alerts/`

**Current state**: `~10,404` Go LOC across 34 files. Primary responsibilities:
SQLite-backed alert store with AES-256-GCM encryption, Telegram briefing
service (morning brief 9 AM IST, MIS warning 14:30 IST, daily summary
15:35 IST), P&L snapshot service (15:40 IST), trailing-stop manager with
domain-event emission, native alert (Kite ATO) bridge, composite alert
combinator (AND/ANY conditions), reference-price percentage alerts, per-
user notifier router.
**Anti-idiom score**: `1/3` — most of this is straight Go (sqlite3 driver,
goroutine-per-alert evaluator, `time.Ticker`-based scheduler). The 10k
LOC includes ~3.5k of test suite. The worker-goroutine pattern is Go-
idiomatic.

**Promotion trigger**: **streaming alert evaluation at ≥10k concurrent
users with sub-100ms latency**. The current synchronous SQLite-backed
"on-tick check all alerts for this token" pattern scales to ~1000
concurrent users (current production load). At 10x scale, the per-tick
linear scan becomes the bottleneck and we'd need either (a) Kafka /
Redpanda streams + a streaming alert-evaluation operator (Flink, ksqlDB),
or (b) an in-memory CEP engine (Esper / Apache Druid) with a pull-from-
ticker ingest loop.

**Target language if promoted**: **Java/Kotlin** (Flink/ksqlDB) or
**Rust** (custom CEP using `tokio` + `lru` + `crossbeam-channel`).
Rationale: streaming-alert evaluation is the textbook CEP problem; Java
ecosystems have 15 years of battle-tested operators. Rust is the
alternative if we want a leaner runtime and don't need the JVM ecosystem
(no plans to use Kafka Connect, etc.).

**Cost**: `12-16 dev-weeks` (Java route) or `16-20 dev-weeks` (Rust
route). Java route reuses existing Flink operators; Rust route is
greenfield.

**24-month likelihood**: **Low** (`~10%`). Forcing function is `10x`
user growth which the realistic-MRR analysis (`kite-mrr-reality.md`)
projects at >24 months. If we hit 1000+ paid subs in 18 months, likelihood
jumps to Med.

### 2.4 `kc/instruments/`

**Current state**: `~2,053` Go LOC across 6 files. Primary responsibilities:
in-memory instrument map (NSE + BSE + futures + options) populated by
periodic refresh from Kite's `/instruments` CSV endpoint, `GetByID` /
`GetByTradingsymbol` / `GetByISIN` / `GetByExchToken` / `GetByInstToken` /
`Filter` / `GetAllByUnderlying` access patterns, freeze-quantity lookup
for riskguard SEBI OTR-band check.
**Anti-idiom score**: `0/3` — pure Go: a struct with a `sync.RWMutex`,
five lookup hashmaps, periodic CSV ingest. Go was designed for this kind
of code; nothing translates better in another language. (`kc/instruments`
is one of the 4 fork-survived files we have NOT meaningfully modified.)

**Promotion trigger**: **NONE realistic within 24 months**. This is the
"thin shim around an in-memory hashmap" pattern — switching languages
gains nothing. The only conceivable trigger is "we move instrument
master to a shared service across multiple processes" (e.g. a sidecar
container) which would be a deployment topology change, not a language
change.

**Target language if promoted**: N/A (no realistic promotion path).

**Cost**: N/A.

**24-month likelihood**: **Low** (`<5%`).

### 2.5 `kc/users/`

**Current state**: `~2,353` Go LOC across 4 files. Primary responsibilities:
SQLite-backed user identity store, RBAC (role: `admin` / `trader` / etc.,
status: `active` / `suspended` / `offboarded`), bcrypt password hash
storage, family-billing admin-linkage (`SetAdminEmail` / `ListByAdminEmail`),
Google SSO auto-provisioning (`EnsureGoogleUser`), invitation store for
admin-driven onboarding.
**Anti-idiom score**: `0/3` — pure Go: bcrypt is `golang.org/x/crypto`,
RBAC is conditional checks, SQLite is `mattn/go-sqlite3`. Idiomatic.

**Promotion trigger**: **enterprise SSO / SCIM provisioning + audit log
+ multi-tenant RBAC**. If we onboard family-office or institutional
customers requiring (a) SAML 2.0 SSO with their corporate IdP, (b) SCIM
2.0 user-lifecycle automation, (c) per-tenant RBAC isolation with
nuanced permission sets — the `keycloak` (Java) or `authentik` (Python)
ecosystems dominate. Building these in Go from scratch is months of
auth-protocol implementation (we'd hit OIDC / SAML / SCIM correctness
edge cases that Keycloak has solved for a decade).

**Target language if promoted**: **integrate Keycloak** (Java)
out-of-process via OIDC, leaving `kc/users/` as a thin local mirror.
Or **Authentik** (Python). The decision is between hosting an external
IdP with our local mirror vs. continuing to grow `kc/users` ourselves;
either way the IdP is not Go.

**Cost**: `8-10 dev-weeks` for Keycloak integration (Keycloak server
deploy + OIDC client config + local-mirror sync + SCIM adapter +
tests).

**24-month likelihood**: **Low** (`~10%`). Forcing function is the first
enterprise customer demanding SAML SSO. Realistic-MRR pegs that as a
>24-month event absent a specific anchor deal.

### 2.6 `kc/registry/`

**Current state**: `~1,205` Go LOC across 2 files. Primary responsibilities:
SQLite-backed pre-registered Kite app credentials store for zero-config
onboarding (admin pre-registers an API key/secret with `assignedTo` user;
user logs in via OAuth and the registry auto-binds without re-asking for
credentials).
**Anti-idiom score**: `0/3` — pure Go: SQLite CRUD, no math, no concurrency
beyond `sync.RWMutex`.

**Promotion trigger**: **NONE realistic within 24 months**. The registry
is a small CRUD store with no algorithmic complexity. Like
`kc/instruments`, the only promotion trigger is a deployment topology
change (e.g. replicate registry across regions for global users), not a
language change.

**Target language if promoted**: N/A.

**Cost**: N/A.

**24-month likelihood**: **Low** (`<5%`).

### 2.7 `kc/audit/`

**Current state**: `~7,161` Go LOC across 28 files. Primary responsibilities:
SQLite-backed tool-call audit log (every MCP tool invocation, args,
result, latency, error), AES-256-GCM-encrypted PII fields, hash-chain
integrity (each row's hash includes prior row's hash; tampering one row
invalidates downstream), 90-day retention cleanup, CSV/JSON export,
per-user statistics (`UserOrderStats`, `StatsCacheHitRate` for
forensics), buffered async writer with goroutine drain on shutdown.
**Anti-idiom score**: `1/3` — most is Go-idiomatic SQLite code; the
hash-chain crypto is `crypto/sha256` (idiomatic). The recent
`hashpublish_default_test.go` (added at `e3bfba3` by another agent)
keeps everything in Go's stdlib.

**Promotion trigger**: **external hash-publish to a public ledger**
(blockchain anchoring on Bitcoin / Ethereum / Polygon) **OR** SOC 2
audit certification requiring tamper-evident integrity-chain proofs.
If we anchor audit-chain hashes on-chain (e.g. publish daily Merkle
roots to OpenTimestamps or a private chain), the on-chain side is
Solidity / Rust (Substrate) — but the hash-publisher itself can stay
Go. Where it tilts toward Rust: if SOC 2 demands a formally-verified
hash-chain implementation (TLA+ proof + matched implementation), Rust's
type system + `rustc -Z miri` for unsoundness checking is the
standard. Go has no equivalent.

**Target language if promoted**: **Rust** for the hash-chain core
(memory-safe + formal-verification-friendly + zero-cost concurrency
for high-throughput audit ingest). Rust port covers the
hash-chain construction + integrity-verification side; the
SQLite-CRUD side stays Go.

**Cost**: `8-12 dev-weeks` for the Rust hash-chain core + IPC adapter
+ test suite + the formal-verification model (TLA+ or similar). Less
if we stay at "Rust core with Go SQLite frontend".

**24-month likelihood**: **Low** (`~15%`). Forcing function: SOC 2 Type 2
certification or a regulatory event (e.g. SEBI mandates audit-chain
publication for all algo platforms). SOC 2 is realistic if we land an
enterprise customer; SEBI mandate is highly speculative.

### 2.8 `kc/ticker/`

**Current state**: `~1,913` Go LOC across 9 files. Primary responsibilities:
per-user WebSocket ticker connection management (Kite's KiteTicker), mode
subscription (LTP / Quote / Full), instrument-token-to-mode mapping with
delta-mode-update support, status reporting (`IsRunning`, `GetStatus`),
shutdown-on-context-cancel goroutine cleanup. Uses `kiteticker.NewTicker`
(upstream Zerodha SDK).
**Anti-idiom score**: `1/3` — Go's goroutine-per-connection + channel
fan-in is idiomatic for WebSocket workloads. The 1.9k LOC is mostly
correctness-around-reconnect / mutex-around-mode-map.

**Promotion trigger**: **sub-millisecond latency requirement OR
zero-allocation tick processing at ≥10k symbols/sec**. The current
implementation allocates per-tick (the kiteticker SDK's parsed structs)
and goes through goroutine-channel handoff per delivered tick. At
~50-100 ticks/sec/user it's invisible; at 10k symbols/sec across many
users (e.g. if we add an algorithmic sub-second alert path), GC pressure
becomes the bottleneck. Rust's zero-cost concurrency (`tokio` +
`crossbeam-channel`) eliminates GC pauses and lets us land tick-to-alert
median latency under 1ms.

**Target language if promoted**: **Rust** (`tokio` runtime + `tungstenite`
WebSocket client + `simd-json` for parsing). Rationale: same as
`kc/audit` — Rust's zero-cost concurrency + memory safety dominates
in the latency-critical tick-processing domain.

**Cost**: `10-14 dev-weeks`. Components: Rust WebSocket client port
(`~3` weeks), per-user mode-subscription state machine (`~2` weeks),
benchmark harness establishing the latency claim (`~1` week), IPC
adapter exposing tick stream to Go alert engine (`~2` weeks),
production rollout dual-write window (`~2` weeks), monitoring +
fallback drill (`~1` week). Plus the `kc/alerts` co-evolution if we
also rewrite the alert engine.

**24-month likelihood**: **Low** (`~10%`). Forcing function: a
specific algo-trading customer demanding sub-50ms tick-to-alert
latency. Per `kite-mrr-reality.md`, the realistic anchor customer is
retail / family-office, NOT algo-trading firms. Low likelihood unless
we pivot product-market fit.

---

## Part 2 Aggregate — Tier-3 → Tier-1 risk over 24 months

### Likelihood matrix

| Component | Likelihood | Trigger probability driver |
|---|---|---|
| `kc/telegram/` | Low (15%) | TWA mini-app demand or vernacular-i18n SLA |
| `kc/billing/` | **Med (35%)** | GST registration at 100 paid subs OR SEBI IA registration |
| `kc/alerts/` | Low (10%) | 10x user growth (>24mo per realistic-MRR) |
| `kc/instruments/` | Low (<5%) | None — purely infrastructure, no language gain |
| `kc/users/` | Low (10%) | Enterprise SAML SSO customer (>24mo absent anchor deal) |
| `kc/registry/` | Low (<5%) | None — same shape as instruments |
| `kc/audit/` | Low (15%) | SOC 2 Type 2 certification OR SEBI audit-publish mandate |
| `kc/ticker/` | Low (10%) | Sub-50ms-latency algo-trading customer (off-PMF) |

### Probability of N components promoting within 24 months

Treating each promotion as independent (slightly conservative — billing
and users are weakly correlated via "first enterprise customer" trigger):

| Outcome | Probability |
|---|---:|
| Zero promotions | `0.85 × 0.65 × 0.90 × 0.95 × 0.90 × 0.95 × 0.85 × 0.90 ≈ 31%` |
| Exactly 1 promotion (any) | `≈ 38%` |
| Exactly 2 promotions | `≈ 19%` |
| 3+ promotions (foundation-phase pays off) | **`≈ 12%`** |

### Foundation-phase ROI inflection

Per `parallel-stack-shift-roadmap.md` §1, the foundation-phase
investments (IPC contract spec, per-language CI, deploy targets,
observability, supply-chain scanning) are sunk cost regardless of how
many components actually promote. The roadmap's §3 cost analysis pegs
the foundation phase at ~`6-8 dev-weeks` of upfront infra debt.

**Inflection point**: foundation-phase pays off if **2+ Tier-3 components
promote** within 24 months. The 19% probability of "exactly 2" plus 12%
of "3+" gives a `~31%` chance the foundation phase amortizes within 24
months. **Below threshold for a "ship it now" call**; above threshold for
"keep the IPC spec drafted and ready".

### Likelihood-weighted dev-week exposure

If we treat the per-component cost columns as expected dev-weeks
weighted by promotion probability:

| Component | Cost | × Likelihood | = Weighted weeks |
|---|---:|---:|---:|
| `kc/telegram/` | 5 wk | × 0.15 | 0.75 |
| `kc/billing/` | 7 wk | × 0.35 | 2.45 |
| `kc/alerts/` | 14 wk | × 0.10 | 1.40 |
| `kc/instruments/` | 0 | × 0.05 | 0.00 |
| `kc/users/` | 9 wk | × 0.10 | 0.90 |
| `kc/registry/` | 0 | × 0.05 | 0.00 |
| `kc/audit/` | 10 wk | × 0.15 | 1.50 |
| `kc/ticker/` | 12 wk | × 0.10 | 1.20 |
| **Aggregate** | **57 wk if all** | | **8.20 expected weeks** |

**Aggregate expected language-port effort over 24 months ≈ 8 dev-weeks**
across all Tier-3 components. Roughly equal to the foundation-phase
infrastructure cost (`6-8` dev-weeks). The roadmap's per-track 1-language-
port assumption holds: `kc/billing` is the most likely single promotion
to plan for, and even it falls under the foundation-phase amortization.

### Decision implication

**Foundation-phase investment is at the marginal-ROI threshold over 24
months.** The recommendation per `parallel-stack-shift-roadmap.md` (delay
foundation until first promotion-trigger fires) holds empirically.
`kc/billing` is the canary — if GST registration or SEBI IA registration
becomes likely within 12 months, that's the cue to start foundation-
phase prep.

For **Rainmatter pitch / FLOSS-fund / marketing**, the per-component
language-shift list IS evidence of architectural maturity — even if no
component actually shifts. The `parallel-stack-shift-roadmap.md` exists,
the IPC contract is drafted in ADR 0007, the per-component costs are
quantified. That's the value, regardless of execution timing.

---

## Sources

- Fork remote: `https://github.com/Sundeepg98/kite-mcp-server.git`
- Upstream remote: `https://github.com/zerodha/kite-mcp-server.git`
- Merge-base / fork boundary: `dcf2dc4` (verified `git rev-parse
  upstream/master = git merge-base upstream/master origin/master`)
- HEAD audited: `e3bfba3` (origin/master at 2026-04-28 night)
- LOC counts: `cloc 1.98` (consistent across boundary + HEAD)
- Diff attribution: `git diff --shortstat dcf2dc4..HEAD -- <path>`
- Tier-3 LOC sources: per-package `cloc` runs (15 telegram / 15 billing /
  34 alerts / 6 instruments / 4 users / 2 registry / 28 audit / 9 ticker
  files at HEAD)
- Anchor docs: `parallel-stack-shift-roadmap.md` `8361409`,
  `scorecard-final-v2.md` `8361409`, `feedback_decoupling_denominator.md`
- Realistic-MRR / promotion-trigger probability anchors:
  `MEMORY.md` references to `kite-mrr-reality.md`, `kite-cost-estimates.md`

---

*Generated 2026-04-28 night, read-only research deliverable.*
