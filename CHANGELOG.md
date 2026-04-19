# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Added
- Per-calendar-second order cap in riskguard (9/sec defensive — broker enforces at 10/sec per SEBI April 2026 retail-algo framework); keyed by `(email, calendar-second)` with lazy GC; evaluated before the per-minute check
- DPDP hash-chained consent log with OAuth-callback recorder — append-only SQLite table records OAuth consent events with a tamper-evident SHA-256 chain
- `composite_alert` persistence via shared alerts table + CQRS command — composite alert definitions now survive restarts alongside simple alerts
- `SessionRegistry.ClientHint` population from HTTP `User-Agent` — lets downstream code identify client type (claude.ai / Claude Desktop / ChatGPT / mcp-remote) per session
- `kc/legaldocs` Go package embedding `PRIVACY.md` and `TERMS.md` via `//go:embed`, consumed by `app/legal.go` for `/privacy` and `/terms` rendering
- `?format=md` query param on `/privacy` and `/terms` for raw-markdown fetch
- ChatGPT Apps SDK live-validation script (`scripts/`) — end-to-end probe of OAuth dynamic client registration + MCP bearer flow against the Fly.io deployment; used as a pre-publish smoke test
- DPDP + CERT-In data breach playbook (`docs/incident-response.md`) — CERT-In 6-hour notification template, DPDP Act §8(5) 72-hour DPB notification, first-60-minute decision tree, user-breach email template, Kite API credential-compromise sub-playbook
- README Trademark block clarifying kite-mcp-server is unaffiliated with Zerodha Broking Ltd., Personal-use scope note citing SEBI §I(c) family carve-out and the <10 OPS threshold, and a Compliance section summarising enforced controls + DPDP posture
- MCP Registry prepublish config: `server.json` v1.1.0 with registry-friendly title, neutral description, `orderPlacement: false` on hosted + `orderPlacementSelfHostedOnly: true`, and `riskGuardChecks: 9`
- goldmark v1.8.2 as a direct module dependency for markdown rendering of legal pages
- ChatGPT Apps SDK widget support: `openai/outputTemplate` metadata shim alongside `ui/resourceUri` in `mcp/ext_apps.go` — ChatGPT clients now render the same widget resources Claude renders, with no new hosting
- `smithery.yaml` at repo root enabling Smithery one-click install
- `.env.example` at repo root as the canonical env-var reference for self-hosters

### Changed
- `/privacy` and `/terms` now render embedded markdown via goldmark instead of hardcoded HTML constants; DPDP-aligned content (Bengaluru arbitration seat, Privacy Notice heading, Erase/Data Fiduciary terminology)
- `Cache-Control` for `/privacy` and `/terms` tightened from 86400s (24h) to 3600s (1h) to accelerate legal-content propagation
- `composite_alert` tool response shape: was `{status: "pending_persistence"}`, now `{status: "created", alert_id: ...}` reflecting durable storage
- Riskguard check count bumped from 8 to 9 across README and `server.json` (per-calendar-second cap added)
- `server.json` registry title reframed from "Kite Trading MCP Server" to "MCP Server for Zerodha Kite Connect API" (trademark-safe); `algo-trading` keyword dropped, `kite-connect` added

### Fixed
- Product metadata (`plugin.json`, issue-template contact links, `funding.json`) no longer references a personal-foundation email address; replaced with a placeholder pending product-contact setup
- Compliance documents (Zerodha compliance email draft, FLOSS/fund proposal, compliance timeline owner, `compliance-emails-sent.md`) scrubbed of the same personal-foundation address; two remaining references in incident-response scenarios replaced with `<grievance officer email>` placeholder
- Production bug: `Confirmed` field now threaded through `PlaceOrderCommand`/`ModifyOrderCommand` to the use-case layer so middleware-approved orders are not re-blocked by the second-layer riskguard re-check (the default-on `RequireConfirmAllOrders` gate short-circuited before value/duplicate/count checks)
- CORS preflight `OPTIONS /mcp` now returns 204 with permissive CORS headers; previously returned 401, blocking browser-based MCP clients at the preflight stage
- `.gitignore` root-anchored patterns for build artifacts (`/*.out`, `/*.exe`, `/*.cov`, `/app_*.html`, `/coverage.*`) — belt-and-suspenders against committing build noise
- 13 previously-failing tests brought back to green after `RequireConfirmAllOrders` tightening left their assertions stale (mcp middleware chain, use-case riskguard path, app env-validation)

### Security
- OAuth-callback path now records a DPDP consent event (`purpose`, `scope`, `proof-hash`) into the hash-chained consent log on every successful authorisation — produces auditable evidence for DPDP §6 consent-manager requirements
- Sub-second order throttle (9/sec) closes a theoretical bypass where 10 orders in a single second could pass the prior 10/min window while breaching the SEBI sub-second retail-algo threshold

## [1.1.0] — 2026-04-18

### Added
- Research copilot tools (LLM-framed, no market data dependency): `analyze_concall` for earnings call transcript analysis, `get_fii_dii_flow` for FII/DII daily flow context, `peer_compare` for PEG + Piotroski + Altman Z-Score comparison across 2–6 stocks
- Claude Skills wrapper package (8 skills + README) for use with the Claude Skills system
- OAuth 13-Levels blog post (`docs/blog/oauth-13-levels.md`) distilled from the 237KB callback deep-dive archive
- Incident response runbook — actionable crisis playbook for production incidents
- FLOSS/fund proposal + `funding.json` manifest (Zerodha open-source grant application)
- BYO Anthropic API key guide — walks users through bypassing Claude.ai tool-call quotas by bringing their own key
- Setup checklist widget (`ui://kite-mcp/setup`) and `test_ip_whitelist` tool for in-Claude IP/credential verification- MCP Registry manifest (`server.json`) for listing on modelcontextprotocol.io- Per-user rate limiting (email-based), complementing existing per-IP limits- CHANGELOG.md
- Evidence package skeleton — pre-built SEBI/regulatory response templates for incident-response handoff
- Claude plugin marketplace scaffold (`.claude-plugin` + `.mcp.json`) for discoverable plugin distribution
- Pre-deploy 5-minute operator checklist — last-mile verification runbook before `flyctl deploy`
- `server_version` MCP tool — git SHA + build time + region reported inline for debugging and audit
- Opt-in pre-commit git hooks (gofmt / vet / build) with an install script
- Anomaly-detection `BaselineProvider` wired to `audit.Store` at startup so per-user rolling baselines persist across restarts
- Kite daily token-refresh runbook (6 AM IST expiry) — user-visible re-auth guidance
- Monitoring and observability guide — Prometheus labels, log grep recipes, Fly.io metrics panels
- `test-race` CI workflow running `go test -race` across concurrency-heavy packages
- MCP Resources (`resources/list`, `resources/read`) exposing user holdings, positions, and orders as typed MCP resources for client-side caching
- Self-hosted `ENABLE_TRADING` configuration guide for users running the fork locally with order placement enabled
- Claude Desktop `claude_desktop_config.json` snippets for one-paste MCP server wiring (Mac/Windows/Linux)
- MCP tool catalog documentation — exhaustive list of ~80 tools with parameters, examples, and tier gating
- Architecture diagrams (Mermaid + ASCII) covering OAuth flow, middleware chain, persistence layers, and deployment topology
- `/healthz` endpoint now reports anomaly-detection baseline cache hit rate alongside existing liveness signals
- FAQ page covering daily token refresh, IP whitelist, Path 1 vs Path 2 distinction, and per-user OAuth

### Changed
- README rewritten with trust signals, compliance framing, and self-hosted fork positioning
- Riskguard defaults tightened — lower order value cap, stricter daily limits, and order confirmation elicitation now defaults on (mitigates prompt-injection risk in agentic flows)
- MCP Apps widgets are now gated on client capability — hosts that don't render widgets no longer receive widget-URL noise in responses
- Telegram outbound messages prefixed with SEBI disclaimer, plus `/disclaimer` command (protects against SEBI advisory classification drift)
- Landing page redesigned with client-specific setup tabs (claude.ai web / Claude Desktop / Claude Code / ChatGPT / VS Code), IP whitelist prerequisite notice, daily refresh note, and algorithmic-developer framing- CQRS duplicate handler registration now returns an error instead of panicking at startup- OAuth `/oauth/authorize` short-circuits when a dashboard session cookie is present, eliminating a second Kite login for dashboard users- MCP responses wrap array data in `{items: [...]}` so strict-validating clients accept them; fixes `get_holdings`, `get_positions`, `get_orders`, `get_gtts`, `get_mf_holdings`- Hardcoded local paths updated after project relocation- Tool rename follow-up (SEBI Path 1 compliance framing): `pre_trade_check` -> `order_risk_report`, `tax_harvest_analysis` -> `tax_loss_analysis`. Descriptions rewritten in factual voice with "Not investment advice." disclaimer appended. Behavior unchanged.
- Lint cleanup sweeps — idiom modernization, `strings.Builder.Fprintf`, drop unnecessary `fmt.Sprintf` in Telegram package
- README gained a Documentation section cross-linking the new session docs, runbooks, and blog post
- Modernization sweep: `interface{}` → `any` across tests, plus `range N` int-range idiom
- 15-minute TTL cache on `UserOrderStats` in the audit path — reduces SQLite pressure on every order placement

### Fixed
- Audit buffer drop log spam; now logs `Warn` only every 100 drops under sustained overflow- XSS edge case in widget data injection: U+2028/U+2029 JS line separators are now escaped- Audit log newline injection: user-controlled strings in `InputSummary` now sanitize `\n`/`\r`/`\t`- Rate limiter IP-only bypass via VPN/botnet (closed by per-user rate limiting)
### Security
- Idempotency keys on `place_order` / `modify_order` — `client_order_id` deduplication prevents replay and duplicate submissions across retries
- Tool-description integrity manifest — detects line-jumping prompt-injection attacks against the MCP tool registry
- `X-Request-ID` header propagation across HTTP → MCP → audit layers for end-to-end correlation and forensic replay
- Anomaly detection in riskguard — rolling baseline of user behavior + off-hours block for atypical order patterns
- SBOM (Software Bill of Materials) generation on master push and release tags via CI
- Kite Connect v4 vendor hedge — vendored dependencies + CI watchdog workflow to detect upstream breakage
- Path 2 compliance gate: `ENABLE_TRADING` env flag for order-placement tools (read-only by default when unset)
- Legal `TERMS` and `PRIVACY` marked as DRAFT under review to mitigate DPDP exposure
- Complete MIT attribution — Dockerfile `LICENSE` copy, `NOTICE` file, and landing-page footer attribution
- Per-user rate limiting (`X-RateLimit-Scope: user`) blocks credential-stuffing and multi-IP abuse- Audit log injection via malicious watchlist/symbol names is now prevented- OAuth consent ordering verified + SSRF blocklist added on the audit-publish endpoint
- `testing.F` fuzz harnesses added for `ArgParser`, widget data injection, and the Telegram command parser
- Weekly `gosec` + `govulncheck` CI scans with SARIF output wired into GitHub Code Scanning

## [1.0.0] — 2026-04-02

First stable release of the self-hosted fork. Forty MCP tools for AI-assisted trading via Zerodha Kite Connect, multi-user OAuth 2.1, and full SQLite persistence.

### Added
- **Trading**: `place_order`, `modify_order`, `cancel_order`, GTT CRUD, `convert_position`, `close_all_positions`, `close_position`, SEBI-compliant `market_protection` parameter
- **Portfolio analytics**: `portfolio_summary`, `portfolio_rebalance`, `sector_exposure`, `tax_harvest_analysis`, `dividend_calendar`, `position_analysis`, concentration/HHI metrics
- **Market data & indicators**: `get_quotes`, `get_ltp`, `get_ohlc`, `get_historical_data`, 174K+ instrument search, `technical_indicators` (RSI, SMA, EMA, MACD, Bollinger Bands), `options_greeks`, `options_strategy` (8 multi-leg presets), options chain view
- **Mutual funds**: MF read and write tools (5 total)
- **Advanced alerts**: price above/below, percentage drop/rise with reference price, Kite native alerts API (server-side ATO)
- **Composite tools**: `pre_trade_check` (5 checks in 1 call), `trading_context` (unified state snapshot), `backtest_strategy` (4 strategies, Sharpe, max drawdown)
- **Paper trading**: virtual portfolio mode via middleware interception, background LIMIT fill monitor, `paper_trading_toggle`/`status`/`reset`
- **Riskguard (3 phases)**: kill switch, order value cap, quantity limit, daily count, rate limit, duplicate detection, daily value cap, auto-freeze circuit breaker
- **Elicitation**: order confirmation prompts on 8 tools (fail-open for older clients)
- **MCP prompts**: `morning_brief`, `trade_check`, `eod_review`
- **MCP Apps widgets**: portfolio, activity, orders, alerts, safety, paper trading, order form, options chain, technical analysis, hub, metrics (~15 widgets)
- **Telegram**: webhook commands (`/price`, `/portfolio`, `/positions`, `/orders`, `/pnl`, `/alerts`, `/watchlist`, `/status`, `/help`), trading commands (`/buy`, `/sell`, `/quick`, `/setalert`) with inline confirmation, morning 9 AM IST briefing, daily 3:35 PM P&L summary
- **Ticker**: WebSocket market data streaming, live P&L dashboard
- **AI activity audit trail**: every MCP tool call logged to SQLite, timeline page at `/dashboard/activity`, buffered async writer, PII redaction, 90-day (now 5-year for SEBI) retention, CSV/JSON export
- **Dashboards**: user dashboard at `/dashboard`, admin at `/admin/ops`, safety page, metrics, family management, account/billing
- **Per-user OAuth 2.1 with PKCE**: dynamic client registration (RFC 7591), per-user Kite credentials, OAuth-protected ops dashboard, dashboard SSO cookie set during MCP callback
- **Users & families**: users table with RBAC, family invite flow, admin force-reauth, family-admin Telegram DM plugin (`telegramnotify`), viewer-role gate plugin (`rolegate`)
- **Billing**: tier-based tool gating, Stripe webhook with idempotency, account/billing page, Stripe Customer Portal, Solo Pro tier, billing history
- **Infrastructure**: Litestream SQLite backup to Cloudflare R2, static egress IP for SEBI whitelisting, self-service landing page, Terms of Service, Privacy Policy, security headers, htmx + SSE for admin/user dashboards
- **Plugin system**: registry with hooks, sample plugin, CSS design tokens

### Changed
- **Architecture**: hexagonal / SOLID refactor with composable middleware, extracted store and broker interfaces, split `manager.go` into focused services, Zerodha adapter wraps `gokiteconnect` through `broker.Client` interface (21+ tools migrated)
- **DDD**: value objects (`Money`, `Quantity`, `InstrumentKey`), domain events, `Order`/`Alert` aggregates
- **CQRS**: command/query types, use case layer, ~16 tools wired through `QueryBus`/`CommandBus`; full path-to-100 sweep (CQRS ~100%, ISP 90%)
- **Event sourcing**: append-only event store, `Order` and `Position` aggregate reconstitution, `get_order_history_reconstituted` tool, 11 persisted domain events
- **OAuth**: replaced Google SSO (for traders) with Kite as identity provider; admin login keeps password + Google SSO
- **Dashboard auth separation**: 7-day dashboard JWT, 24h MCP bearer JWT
- **Audit retention**: bumped 90 days to 5 years for SEBI compliance
- **Security hardening**: HMAC-SHA256 hashed session IDs in DB, token invalidation on credential change, email HMAC in audit trail, hash chaining, random HKDF salt with auto-migration
- **Tool annotations**: all 60 tools annotated with title, `readOnlyHint`, `destructiveHint`, `idempotentHint`, `openWorldHint`
- **structuredContent**: all tool responses include typed data alongside text
- **Go 1.25.8**: bumped to patch 3 stdlib CVEs (GO-2026-4603 XSS in `html/template`)
- README rewritten as product landing page for the self-hosted fork
- MCP Apps AppBridge rewrite for inline widget rendering across claude.ai / ChatGPT / VS Code / Claude Desktop
- Comprehensive coverage push: 5000+ tests, 92%+ coverage, 11+ modules at 100%, all `coverage_*` files renamed

### Fixed
- Null guard for triggered alerts on expired token
- Dashboard bugs surfaced via Playwright E2E
- Telegram cleanup goroutine leak
- `gosec` G104/G115/G703/G705/G115 findings resolved (15+ items)
- `distance_pct` omitempty bug, top-tool in metrics, dynamic tool count in server card
- Stripe metadata mismatch, billing PK rename, dynamic pricing
- 10 trading simulation findings (auto-ticker, market status, trailing notifications, enriched briefings)
- 30+ dashboard/widget bug batches across 5 audits
- Alerts race condition via `sync.Mutex` on `newBotFunc`
- CI: Go 1.25 upgrade, Node.js 24, duplicate test names, cross-platform path test
- Credential store fallback when `client_secret` missing
- Credential store check for returning users with expired tokens (auto re-auth — eliminates double login)
- SQLite write permissions on `/data` for appuser
- Historical NSE holiday schedule corrected

### Security
- Full 4-layer AES-256-GCM encryption at rest: tokens, credentials, OAuth client secrets, alerts
- STRIDE threat model, `SECURITY.md`, `security.txt`, GitHub Actions CI, automated pentest (gosec + manual)
- Dual-port admin separation (later reverted for password auth on main port)
- OAuth and auth hardening (MED severity) — Stream B spec alignment, B6/B9 additions
- Critical security fixes (HIGH severity), 79 MED/LOW/INFO audit findings resolved
- Security audit: 27-pass manual analysis, 181 findings (6 HIGH, ~40 MED) — 153 fixed, 28 accepted risk
- Per-IP rate limiting on auth (2/sec), token (5/sec), MCP (20/sec)
- Admin tool filter: admin-only tools hidden from non-admin users
- CSS injection, XSS false-positive, gosec G115 integer overflow addressed
- Security headers middleware (X-Frame-Options, HSTS, CSP)

### Removed
- Dead ticker listener code
- P&L dashboard page (replaced by widget + `/auth/browser-login`)
- Dead JS references to htmx-replaced elements
- 3 aggregates deleted in DDD sweep (later reverted — restored in `bda9b51`)

## [0.4.0-dev3] — 2025-12-17

### Added
- OAuth 2.1 JWT authorization server and migration to the official MCP SDK (`bba7aac`)
- RFC 7591 Dynamic Client Registration (`0cb3130`)
- Enhanced instrument search tool with modes, verbosity, and metrics (`b9e8510`)

### Changed
- Comprehensive dead code cleanup and API modernization (`4302d13`)

## [0.4.0-dev1] — 2025-09-15

### Added
- Comprehensive Kite alerts management tool (`a09d6d3`)
- Custom app name support for Kite Connect clients (`8f56275`)
- `type` parameter on `HoldingsTool` (`2ad6c03`)
- `market_protection` field on `PlaceOrderTool` (`da296f0`)

## [0.4.0-dev0] — 2025-09-01

### Added
- OAuth 2.1 authorization server for MCP compliance (`40a2278`)

### Changed
- Metrics migrated to Prometheus client and labels (`f84ca63`)

### Fixed
- Linting issues for GitHub Actions CI (`72de17a`)

## [0.3.1] — 2025-08-06

### Added
- Compliance logging for successful user logins (`de94bb2`)
- Session type labels on metrics tracking (`8bf8057`)

### Fixed
- Metrics tracking for POST tools (`72a5e75`)
- Simplified return statement in `isDailyMetric` for linter (`dcf2dc4`)

## [0.3.0] — 2025-08-05

### Added
- Daily tool usage metrics and AI risk warning (`cb81e01`)

### Changed
- Merged `develop` branch into `main` (`4113eba`)

## [0.2.0-dev4] — 2025-06-10

### Added
- Metrics support (`a611014`)

### Fixed
- External session IDs in SSE (`b0991b8`)
- Timeouts set to 0 (no timeout) (`96d5157`)
- Linting issues (`534df1a`)

## [0.2.0-dev0] — 2025-06-10

### Added
- GitHub CI test and release workflow (`a1aab77`, `67cb4ac`)

### Changed
- Major architecture overhaul with hybrid HTTP + SSE transport (`c1882d4`)

## [0.1.0-dev1] — 2025-06-04

### Changed
- Bumped `mcp-go` dependency to v0.30.0 (`6ec1f47`)

## [0.1.0-dev0] — 2025-05-27

### Added
- `get_order_trades` tool (`1e60729`)
- `GetLTP` and `GetOHLC` tools (`1fba373`)
- Order history tool (`2a78747`)
- Keep-alive pings sent to clients (`844d122`)
- Lock over session map (`854210a`)
- Nix dev setup info (`9e0a4e9`)

### Changed
- Bumped `mcp-go` dependency to v0.30.0 (`c2b7674`)
- Style changes for index template (`3b85c87`)
- Bumped `mcp` library (`9f88d50`)

### Fixed
- Hosted version URL in Claude config now uses HTTPS (`f3a7390`)

## [0.0.1] — 2025-04-29

Initial Go rewrite of the Kite MCP server with the majority of tools implemented.

### Added
- Working Go rewrite covering the majority of tools (`995d075`)
- GTT tools (`8ca1bbc`)
- Historical data tool (`c031570`)
- Instrument search by underlying (`ff7ba94`)
- `get_mf_holdings` mutual fund holdings tool (`0fc5a11`)
- Holdings pagination (`c5a6bf5`)
- Configurable host and port (`0f2c453`)
- HTML template rendering for login success page (`e00f883`)
- Consolidated callback and SSE under a single mux (`8146243`)
- Session handling validation, error handling, and instrument search filters (`5ebabab`)
- Caddy deployment docs (`9b33762`)
- LICENSE file (`0f4f638`)

### Fixed
- `kite orange` theming issue (`ab15c7e`)
- Query parameter handling in `HandleKiteCallback` (`4f8577e`)

## [Initial] — 2025-02-24

Initial commit of the upstream Kite MCP server (`9c56b1f`).

[Unreleased]: https://github.com/Sundeepg98/kite-mcp-server/compare/v1.1.0...HEAD
[1.1.0]: https://github.com/Sundeepg98/kite-mcp-server/compare/v1.0.0...v1.1.0
[1.0.0]: https://github.com/Sundeepg98/kite-mcp-server/compare/v0.4.0-dev3...v1.0.0
[0.4.0-dev3]: https://github.com/Sundeepg98/kite-mcp-server/compare/v0.4.0-dev1...v0.4.0-dev3
[0.4.0-dev1]: https://github.com/Sundeepg98/kite-mcp-server/compare/v0.4.0-dev0...v0.4.0-dev1
[0.4.0-dev0]: https://github.com/Sundeepg98/kite-mcp-server/compare/v0.3.1...v0.4.0-dev0
[0.3.1]: https://github.com/Sundeepg98/kite-mcp-server/compare/v0.3.0...v0.3.1
[0.3.0]: https://github.com/Sundeepg98/kite-mcp-server/compare/v0.2.0-dev4...v0.3.0
[0.2.0-dev4]: https://github.com/Sundeepg98/kite-mcp-server/compare/v0.2.0-dev0...v0.2.0-dev4
[0.2.0-dev0]: https://github.com/Sundeepg98/kite-mcp-server/compare/v0.1.0-dev1...v0.2.0-dev0
[0.1.0-dev1]: https://github.com/Sundeepg98/kite-mcp-server/compare/v0.1.0-dev0...v0.1.0-dev1
[0.1.0-dev0]: https://github.com/Sundeepg98/kite-mcp-server/compare/v0.0.1...v0.1.0-dev0
[0.0.1]: https://github.com/Sundeepg98/kite-mcp-server/releases/tag/v0.0.1
[Initial]: https://github.com/Sundeepg98/kite-mcp-server/commit/9c56b1f
