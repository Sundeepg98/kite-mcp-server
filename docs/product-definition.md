# Kite MCP Server — Product Definition

**Status:** Canonical. This is what the product *is*, written to be lifted verbatim into a launch deck or README hero. If a fact in this file disagrees with another file in the repo, this file is authoritative for product positioning.

**Last updated:** 2026-05-02
**Source files cross-checked:** `README.md`, `kc/templates/landing.html`, `.claude-plugin/plugin.json`, `funding.json`, `FUNDING.json`, `server.json`, `docs/drafts/zerodha-compliance-email.md`, `mcp/` package (128 `mcp.NewTool` registration sites across 53 files).

---

## Section 1 — What kite-mcp-server IS

### One-sentence value prop

A self-hosted MCP server that turns Claude or ChatGPT into a power-user trading copilot for your Zerodha Kite account — with order placement, riskguard safety rails, paper trading, options Greeks, backtesting, and Telegram alerts that the official Zerodha MCP doesn't cover.

### Who it's for

Active Indian retail traders on Zerodha Kite who:

- Already pay (or are willing to pay) Zerodha's ₹500/month for a Kite Connect developer app
- Want their AI assistant (Claude Desktop, Claude Code, claude.ai web, ChatGPT, Cursor, VS Code Copilot, Windsurf) to *do things* on their account, not just describe them
- Care about safety rails: order caps, kill switch, audit trail, encrypted credentials at rest
- Are comfortable bringing their own developer credentials (the BYO model is the entire point — credentials never leak across users)

Explicitly *not* for: passive investors, advisor-led clients, anyone who wants someone else's algo running on their account, or anyone outside the SEBI retail self-trading framework's "self/spouse/dependent" scope.

### What it DOES (capabilities)

1. **Trading and orders** — place / modify / cancel / GTT / convert positions / close-all, options multi-leg builder (8 strategies), trailing stops, native Kite alerts. Order placement is gated to local self-host only on the Fly.io deployment per NSE/INVG/69255.
2. **Portfolio and analytics** — holdings, positions, margins, P&L, sector exposure (150+ NSE stocks mapped to 20+ sectors), tax-loss harvest, dividend calendar, portfolio rebalancing, peer comparison (PEG / Piotroski / Altman-Z), FII/DII flow, earnings concall summarizer.
3. **Market data and indicators** — quotes, LTP, OHLC, historical candles, instrument search, RSI, SMA, EMA, MACD, Bollinger Bands. Black-Scholes Greeks (delta, gamma, theta, vega, IV) computed server-side.
4. **Backtesting and simulation** — 4 built-in strategies (SMA crossover, RSI reversal, breakout, mean reversion) with Sharpe ratio and max drawdown. Paper trading mode with virtual ₹1 crore portfolio and background LIMIT fill monitor.
5. **Alerts and notifications** — price above/below, percentage drop/rise, composite conditions, volume spike. Delivered to Telegram with inline `/buy /sell /quick /setalert` keyboard. Morning briefing 9 AM IST + daily P&L 3:35 PM IST. Native Kite GTT alerts also supported.
6. **Safety and audit** — RiskGuard runs 9 checks before every order (kill switch, per-order ₹50k cap, daily 20-order count, 10/min rate limit, 30s duplicate window, daily ₹2L cumulative cap, idempotency, anomaly detection vs μ+3σ baseline, off-hours block, auto-freeze circuit breaker). Per-tool-call audit trail in SQLite with 90-day retention, CSV/JSON export.
7. **Inline UI** — MCP Apps widgets render portfolio / orders / alerts / activity inside chat on claude.ai web, Claude Desktop, and ChatGPT (with `openai/outputTemplate` shim). Dashboard at `/dashboard`, `/dashboard/activity`, `/dashboard/orders`, `/dashboard/safety`, `/dashboard/paper`, `/admin/ops`.

**Tool count:** ~80 user-facing MCP tools across 53 source files in `mcp/` (128 `mcp.NewTool` call sites; ~48 of those are admin / test / variant registrations). README and landing page round to "~80".

### How users install / connect

Three install paths, ordered by friction:

**A. Hosted, read-only (zero install).** Point any MCP client at `https://kite-mcp-server.fly.dev/mcp`. OAuth handshake brings up a browser Kite login. Order placement is gated off (`ENABLE_TRADING=false`) per NSE Path 2; analytics, market data, backtesting, paper trading all work. Static egress IP `209.71.68.157` (Mumbai region) — whitelist in your Kite developer console per the SEBI April 2026 mandate.

**B. Self-hosted local (full functionality).** `git clone && docker compose up -d` against `Dockerfile.selfhost`. Set `OAUTH_JWT_SECRET` (only required env), `ENABLE_TRADING=true`, point your client at `http://localhost:8080/mcp`. This is the personal-use safe-harbor path — you remain the Zerodha Client of record.

**C. Client config snippet.** Add to `~/.claude.json`, `claude_desktop_config.json`, `.vscode/mcp.json`, etc.:

```json
{
  "mcpServers": {
    "kite": {
      "command": "npx",
      "args": ["mcp-remote", "https://kite-mcp-server.fly.dev/mcp"]
    }
  }
}
```

Then say: "Log me in to Kite" — complete the OAuth flow — and ask anything from "show my portfolio" to "backtest SMA crossover on INFY".

### Pricing / tier

- **Software:** Free, MIT licensed, source on GitHub (`Sundeepg98/kite-mcp-server`). Self-host costs nothing.
- **Hosted endpoint:** Free during preview. Read-only by design.
- **Required upstream cost:** Zerodha's Kite Connect developer app at ₹500/month (paid by user directly to Zerodha; not collected by us).
- **Future:** Optional paid tier for hosted full-trading post-empanelment (50+ paid users gates the NSE empanelment process). Infrastructure recovery only — no advisory or brokerage fees ever.

### Differentiation vs official Zerodha Kite MCP

Zerodha ships its own MCP at `mcp.kite.trade/mcp`. It's free and zero-setup. Our differentiation is concrete and verifiable:

| Feature | This server | [Official Kite MCP](https://mcp.kite.trade) | Streak |
|---------|:-----------:|:-------------------------------------------:|:------:|
| Tool count | ~80 | 22 | N/A |
| Order placement | Yes (local build) | GTT only | Yes |
| Paper trading | Yes | No | No |
| Safety checks | 9 (RiskGuard) | 0 | 0 |
| Backtesting | 4 strategies | No | Yes |
| Options Greeks | Yes (Black-Scholes) | No | No |
| Telegram alerts | Yes (`/buy /sell /quick`) | No | No |
| Self-hostable | Yes | No | N/A |
| Inline widgets | Yes (4 widgets) | No | No |
| Audit trail | 90-day, CSV export | No | No |

The official server is the right choice for read-only, zero-setup use — and we recommend it for that case. This server is for traders who want *order placement with safety rails, paper trading, alerts that go to Telegram, and analytics that the official server doesn't cover.*

---

## Section 2 — What's IN the repo but NOT the product (the journal)

The repo contains far more than the product. Empirical inventory below.

### Inventory totals

| Bucket | Count | On-disk location | Git status |
|---|---|---|---|
| `.research/` files (internal architecture journal) | **202 files** (152 tracked + ~50 untracked) | `.research/*` | tracked |
| Build artifacts at repo root (`.out`, `.exe`, `.cov`, `.html`) | **228 files** | repo root | **NOT git-tracked** (covered by `.gitignore`) |
| Stray temp markdown files at repo root (`a.md`, `ch.md`, `mod.md`, `req.md`, `gen_ref.md`, `api.md`, `admin.md`, `COVERAGE.md`) | 8 files | repo root | mixed (`COVERAGE.md` tracked; others likely untracked) |
| `docs/` files | **93** (45 in root + subdirs blog/drafts/launch/superpowers/evidence/adr) | `docs/*` | mostly tracked |
| Public ADRs | 10 | `docs/adr/*.md` | tracked |
| `mcp/` package source files | ~120 .go files | `mcp/*` | tracked, **product code** |

The good news: the `.gitignore` already covers `*.out *.exe *.test *.prof coverage.out coverage.html`. The 228 build artifacts are *on disk only*, not in the GitHub repo. The single biggest pre-launch issue is `.research/` — 152 tracked files of internal architecture exploration that genuinely should not be in the public repo.

### Categorization and recommended actions

#### A. Product code — KEEP IN REPO PUBLIC (no change)

`mcp/`, `kc/`, `app/`, `oauth/`, `broker/`, `cmd/`, `plugins/`, `skills/`, `etc/`, `tests/`, `testutil/`, `scripts/`, `rotate-key/`, `main.go`, `main_test.go`, `go.mod`, `go.sum`, `Dockerfile`, `Dockerfile.selfhost`, `docker-compose.yml`, `fly.toml`, `flake.nix`, `flake.lock`, `justfile`, `smithery.yaml`, `server.json`, `funding.json`, `FUNDING.json`, `.claude-plugin/`, `examples/`.

This is the product. Do not touch.

#### B. Public-facing docs — KEEP IN REPO PUBLIC

Root: `README.md`, `LICENSE`, `NOTICE`, `SECURITY.md`, `PRIVACY.md`, `TERMS.md`, `CONTRIBUTING.md`, `CHANGELOG.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`.

`docs/` (user/contributor-facing): `self-host.md`, `tls-self-host.md`, `config-management.md`, `env-vars.md`, `byo-api-key.md`, `adding-a-new-tool.md`, `client-examples.md`, `cookbook.md`, `faq.md`, `claude-desktop-config.md`, `tool-catalog.md`, `tool-renames.md`, `release-checklist.md`, `releasing.md`, `release-notes-v1.1.0.md`, `architecture-diagram.md`, `event-flow.md`, `audit-export.md`, `kite-token-refresh.md`, `chatgpt-apps-validation.md`, `mcp-registry-prepublish-checklist.md`, `floss-fund-proposal.md`, `sebi-paths-comparison.md`, `kite-version-hedge.md`, `multi-broker-plan.md`, `sbom.md`, `incident-response.md`, `incident-response-runbook.md`, `operator-playbook.md`, `wsl2-setup-runbook.md`, `evidence/` (skeleton for compliance posture), `blog/oauth-13-levels.md`.

#### C. Public ADRs — KEEP IN REPO PUBLIC, optionally banner as "internal/architectural"

`docs/adr/0001` through `0010` are decision records. Useful for contributors to understand *why* the codebase made specific choices (broker port interface, sqldb port, per-user OAuth, SQLite+Litestream, middleware order, fx, plugin IPC, decorator approach, JSON-RPC IPC, stack-shift deferral). Keep — these are exactly what a serious open-source project should expose. Optionally add a one-line banner: *"ADRs document architectural decisions for contributors. End users do not need to read these to use the product."*

#### D. Internal-architecture rubric churn — MOVE TO PRIVATE REPO `kite-mcp-internal`

These are the *internal architectural exploration* journal. They belong in a private companion repo, not in the public release. Specific files (verified tracked in git):

- All `scorecard-final*.md` (3 files): `FINAL-SCORECARD.md`, `FINAL-VERIFIED-SCORECARD.md`, `scorecard-final.md`, `scorecard-final-v2.md`, `scorecard-final-v3.md`
- All `path-to-100*` files (5+ files): `path-to-100.md`, `path-to-100-final.md`, `path-to-100-business-case.md`, `path-to-100-per-class-deep-dive.md`, `path-to-98-min-loc.md`, `final-100-report.md`
- `state-and-100pct-reconciliation.md`, `why-not-literal-100.md`, `why-not-100-msg.txt`
- `agent-concurrency-decoupling-plan.md`, `parallel-stack-shift-roadmap.md`, `decorator-stack-shift-evaluation.md`, `decorator-code-gen-evaluation.md`, `component-language-swap-plan.md`, `go-irreducible-evaluation.md`, `fork-loc-split-and-tier3-promotion.md`, `non-wire-decoupling-followup.md`
- All `wave-d-*` (4 files): `wave-d-phase-2-recompute.md`, `wave-d-phase-2-wire-fx-plan.md`, `wave-d-phase-3-package-6-mcp-scoping.md`, `wave-d-resolver-refactor-plan.md`, `post-wave-d-skipped-items-reeval.md`
- All `phase*` and `slice*` working notes (40+ files)
- All `*-progress.md` reports (30+ files): `cov-200-progress.md`, `cqrs-100-progress.md`, `ddd-spec-progress.md`, `mcp-redesign-progress.md`, etc.
- All commit-message scratch (`*-msg.txt`, ~25 files)
- Architecture re-audit chains: `arch-gaps-fixed.md`, `architecture-100-gap-current.md`, `architecture-re-audit.md`, `arch-reaudit.md`, `final-138-gap-catalogue.md`, `final-arch-verification.md`, `non-external-100-final-blockers.md`, `blockers-to-100.md`, `all-blockers-enumeration.md`, `blocker-fix-patterns.md`, `blocker-resolutions.md`
- Hexagonal/CQRS/DDD/ES exploration: `hex-100-progress.md`, `hex-ddd-100-progress.md`, `hexagonal-fix-plan.md`, `hexagonal-surface-survey.md`, `cqrs-bypass-fix.md`, `cqrs-fix-plan.md`, `cqrs-100-progress.md`, `cqrs-200-progress.md`, `ddd-es-fix-plan.md`, `ddd-spec-wiring-progress.md`, `ddd-vo-progress.md`
- Test-arch chains: `test-arch-audit.md`, `test-arch-final.md`, `test-arch-oauth.md`, `test-arch-ops.md`, `test-arch-reality-check.txt`, `test-arch-remaining.md`, `test-100-final-report.md`

**Recommended action: `git mv .research/ ../kite-mcp-internal/` then `git rm -r .research/` after pushing the internal repo.** Public repo gets clean.

#### E. Hook/team-agent meta-research — MOVE TO `kite-mcp-internal` (NOT EVEN KITE-RELATED)

These are about the *Claude Code agent infrastructure* used to develop the project, not about the project itself. They have zero value for a public reader:

- `team-hooks-analysis.md`, `team-hooks-analysis-v2.md`, `team-hooks-analysis-v3.md`
- `team-hooks-r9-asyncrewake-design.md`
- `cclsp-vs-marketplace-lsp-divergence.md`, `gopls-marketplace-manifest-patch.md`, `windows-side-gopls-resolver-options.md`, `path-b-lsp-manager-deep-dive.md`
- `hook-verify-best-option.md`, `disable-marketplace-plugin-decision.md`, `anti-rec-plugin-deep-research.md`
- `next-session-team-plan.md`, `session-end-state.md`

Especially the `team-hooks-*` and `gopls/cclsp` files — these reference the developer's local Claude Code hook setup, which is irrelevant to anyone using the kite product.

#### F. `.cov` orphans inside `.research/` — DELETE (build artifacts)

`.research/` contains 8 binary coverage files: `alerts.cov`, `audit.cov`, `oauth.cov`, `papertrading.cov`, `rotatekey.cov`, `usecases.cov`, `usecases2.cov`, `usecases3.cov`, `users.cov`. These are stray Go coverage outputs in the wrong directory. Delete unconditionally.

#### G. `mfa-wsl-test.sh` and similar — DELETE

`.research/mfa-wsl-test.sh` is a one-off WSL test script. Not part of the product. Delete.

#### H. Repo-root junk markdown — DELETE

`a.md`, `ch.md`, `mod.md`, `req.md`, `gen_ref.md`, `api.md`, `admin.md` at repo root are workspace scratch. Verify if tracked, then remove.

#### I. Repo-root junk binaries — already gitignored, but DELETE FROM DISK

228 `.out` / `.exe` / `.cov` / `.html` files at repo root. None are tracked (verified). They clutter local `ls` and `git status` only. Run a one-shot cleanup: `git clean -fX` would delete all gitignored files (use `-n` first to preview).

#### J. Auxiliary `docs/` clutter — DECIDE PER-FILE

Files in `docs/` that are session-specific and could move to `kite-mcp-internal`:

- `consistency-audit-2026-04-18.md`, `session-2026-04-18-handoff.md`
- `delete-candidates-verification.md`, `placeholder-substitution-map.md`
- `pre-push-audit.md`, `triage-execution-guide.md`, `triage-script-analysis.md`, `untracked-files-triage.md`, `worktree-cleanup-plan.md`, `worktree-merge-sequence.md`, `worktree-merge-sequence-v2.md`
- `remember-md-anomaly.md`, `renusharma-email-cleanup-report.md`
- `recovery-plan.md`, `deferred-items.md`, `deploy-impact-analysis.md`, `engagement-mr-karan.md`, `gitignore-policy-analysis.md`
- `dpdp-reply-templates.md`, `cohort-1-landing.md`, `cohort-1-surveys-emails.md`, `kite-forum-replies.md`, `reddit-buildlog-posts.md`, `show-hn-post.md`, `substack-week-1-options-greeks.md`, `twitter-launch-kit.md`, `rainmatter-onepager.md`, `launch-materials.md`, `launch/` subdir, `drafts/` subdir
- Risk/governance internals (keep some, move others): `risk-register.md`, `path-6a-risk-audit.md`, `option-c-implementation-plan.md`, `billing-activation-plan.md`

Reader-facing docs to **keep** publicly: anything a contributor or operator genuinely needs (security, threat model, NIST mapping, monitoring, vendor management, vulnerability management, change management, data classification, RETENTION, access control, asset inventory, incident response).

Marketing/launch drafts can stay in `docs/launch/` and `docs/drafts/` if you want them tracked publicly — they're aspirational and not embarrassing — but moving them to `kite-mcp-internal` makes the public repo focus tighter on "this is the product" and "here's how to use it."

### Summary of recommended cleanup actions

1. **Create private repo `kite-mcp-internal`** at `github.com/Sundeepg98/kite-mcp-internal` (private).
2. **Move `.research/` (152 tracked + ~50 untracked = 202 files)** into the private repo.
3. **Delete 8 orphan `.cov` files** from `.research/` (coverage artifacts, not source).
4. **Delete repo-root junk md** (`a.md`, `ch.md`, `mod.md`, `req.md`, `gen_ref.md`, `api.md`, `admin.md` if untracked).
5. **Delete 228 gitignored build artifacts from disk** via `git clean -fX` (preview with `-n` first).
6. **Audit `docs/`** — move ~20-30 internal/session-specific files to private repo; keep ~60 reader-facing.
7. **Add a one-line "internal/architectural" banner** to `docs/adr/` README if you don't already have one.

After this, the public repo presents as: clean root, README.md is the front door, `docs/` is reference material organized by audience (user, contributor, operator, compliance), `.claude-plugin` and `skills/` are integrations, `mcp/ kc/ app/ oauth/ broker/ cmd/` are the product code. That's the launch-ready state.

---

## Section 3 — Launch positioning narrative

### Draft A — Hacker News post

**Title:** Show HN: Kite MCP Server — give Claude/ChatGPT direct access to your Zerodha trading account

**Body:**

I built kite-mcp-server because the official Zerodha MCP is read-only — 22 tools, GTT-only orders, no alerts, no paper trading, no Greeks. Mine has ~80 tools, places orders with 9 pre-trade safety checks, runs 4 backtest strategies, computes Black-Scholes Greeks, and pings a Telegram bot at 9 AM IST with a morning briefing.

It's a Go server speaking Model Context Protocol. Each user brings their own Kite Connect developer app (₹500/month, paid to Zerodha directly) — the server holds zero master credentials, uses per-user OAuth 2.1 + PKCE, and AES-256-GCM-encrypts everything at rest. Works in Claude Desktop, Claude Code, claude.ai web, ChatGPT, Cursor, VS Code Copilot, Windsurf — anything MCP-compliant.

Hosted at `kite-mcp-server.fly.dev/mcp` (read-only, free), or self-host with `docker compose up` for full order placement under SEBI's retail self-trading framework. RiskGuard runs 9 checks before any order: kill switch, ₹50k per-order cap, 20-orders-per-day count, 10/min rate, 30s duplicate, ₹2L daily cumulative, idempotency, anomaly detection (μ+3σ), off-hours block.

7,000+ tests, 27-pass security audit (181 findings, all resolved), MIT licensed. Repo: github.com/Sundeepg98/kite-mcp-server.

Built for active Zerodha retail traders who want their AI to actually *do things* on their account, not just describe their portfolio.

(150 words. Concrete, no architecture journey, leads with the Zerodha-MCP-vs-this-server differentiation.)

### Draft B — README hero replacement

> # Kite MCP Server
>
> Give Claude or ChatGPT direct access to your Zerodha Kite trading account — with order placement, paper trading, options Greeks, backtesting, Telegram alerts, and 9 pre-trade safety checks. ~80 tools. Open source, MIT.
>
> [Try the hosted demo](https://kite-mcp-server.fly.dev/mcp) (read-only) · [Self-host in 60 seconds](#quick-start) (full trading) · [Compare vs official Zerodha MCP](#comparison)
>
> ```bash
> claude mcp add --transport http kite https://kite-mcp-server.fly.dev/mcp
> ```
>
> Then say: *"Log me in to Kite. Show my portfolio. Backtest SMA crossover on INFY. Set an alert for RELIANCE 2% drop."*

(About 70 words. Three concrete CTAs above the fold; one copy-paste install line; no compliance preamble; no rubric mentions; assumes the reader is here for the trading copilot, not an architecture museum.)
