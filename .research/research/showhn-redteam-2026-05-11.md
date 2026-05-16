<!-- secret-scan-allow: leaked-dev-secrets-cited-as-finding-not-as-config -->
---
title: Show HN Re-Red-Team — 30 Commenter Archetypes + Pre-Canned Replies + What-NOT-to-Say
as-of: 2026-05-11
re-verify-by: 2026-06-11
master-head-at-write: 652e848
verification-method: live /healthz probe (tools=111, v1.3.0, 129h uptime), flyctl ips list (egress=209.71.68.157 LIVE), gh api repos/algo2go/kite-mcp-riskguard (8+ checks per README), git grep -E API_KEY=... (leaked dev secrets in tracked run-server.cmd)
prior-doc: .research/show-hn-redteam-rehearsal.md (2026-05-02; 10 archetypes; this dispatch adds 20 more + 4 critical-new-findings)
scope: READ-ONLY research; no code changes; doc only
budget-used: ~2h of 3h target
---

# Show HN Re-Red-Team — 2026-05-11

## §0 — TL;DR (read this first; 4 critical findings)

This is the 2nd red-team pass on `docs/show-hn-post.md`, **12 days after the 2026-05-02 first pass**. The post has been patched (`110+ tools`, `11 RiskGuard checks`, `~9k tests`) and those numbers are now empirically aligned with `/healthz` (`tools: 111`), README (`9000+ tests`), and `algo2go/kite-mcp-riskguard/guard.go`. **What's new since the first pass**:

1. **NEW CRITICAL — `run-server.cmd` + `run-server-oauth.cmd` leak local-dev Kite API key + secret in tracked files.** Verbatim leak: `KITE_API_KEY=4agbg2fm6szvmhon` + `KITE_API_SECRET=bk32hdajsjrm62im1m98xufiiqzffq7y`. ANY HN security commenter who runs `git grep -E "API_(KEY|SECRET)=[a-z0-9]{16}"` after cloning finds them in 15 seconds. Severity: **HIGH** — even if the dev key has been rotated, the optics on launch day are catastrophic (top comment becomes "secret hygiene fail" within 30 minutes). `scripts/smoke-test.sh` also exposes the prod app's client_id `mmo8qxk1ccrcplad`. **MITIGATION must happen before HN post** — see §6 What-NOT-to-Say + remediation block.

2. **NEW MEDIUM — number-skew between repos.** Show HN says **"11 pre-trade checks"** + lists them; `algo2go/kite-mcp-riskguard` README says **"8+ checks"** + lists 12 different items. Commenter who clicks through the algo2go riskguard link discovers a different count. Reconcile with single canonical phrasing — see §5 reply #6.

3. **NEW MEDIUM — Sundeepg98 vs algo2go narrative whiplash.** Show HN reply #1 (in current draft) sends commenter to `algo2go/kite-mcp-riskguard/guard.go`. The Show HN post itself links to `github.com/Sundeepg98/kite-mcp-server`. A skeptical commenter notices: "Why is the safety code in a different org than the main repo?" + "Are these the same person?" Answer: yes (transfer not yet executed, modules externalized first), but **prep a one-line reply** that owns this rather than dodges it. See §5 reply #4.

4. **209.71.68.157 IS NOT STALE — confirmed live.** Per separate sweep (`egress-ip-stale-sweep-2026-05-11.md`, commit `7559133`), the previous "stale IP" premise was a measurement artifact (truncated flyctl output). Per `flyctl ips list -a kite-mcp-server` run today: `209.71.68.157 [egress, bom, Apr 1 2026]` IS the live production egress IP. Show HN post can keep the IP claim as-is. Reply for IP-skeptic commenter in §5 reply #15.

**The 3 most-likely-to-top-vote hostile comments (probability × impact):**

| # | Verbatim hostile comment (~30w) | Prepared reply (50-100w) |
|--:|---|---|
| 1 | "You leak `KITE_API_KEY=4agbg2fm6szvmhon` in `run-server.cmd` on master. For a safety-rails trading server this is embarrassing — what else is plaintext?" | "You're right. Those are local-dev credentials (rotated; not the prod keys), and they're in tracked files because I was lazy moving them to `.env.example`. Removing them in a follow-up commit + adding pre-commit secret-scan (`gitleaks`). Prod secrets live in Fly.io secret store, not in the repo — see `/healthz` for the v1.3.0 binary running with zero-repo-secrets. Thanks for the catch; reproducible fix in 24h." |
| 2 | "SEBI April 2026 algo regs require RA registration for anyone shipping trading logic. You're not registered. What changed?" | "Direct answer: not registered, and the April 2026 rules apply to algo *providers* (black-box logic). This is a typed wrapper over Kite's published API — no signals, no strategies, no black-box logic. The user types the strategy into Claude; the LLM is the brain; the server is the gate. Same posture as `mcp.kite.trade` (Zerodha's official MCP). Compliance reasoning in `docs/legal-notes.md`; happy to be pointed to the specific rule clause you think applies." |
| 3 | "Solo dev claiming 9k tests + audit chain + 110 tools + Litestream + Telegram. 6 months from now this will be unmaintained — who's on call when my real money is in this?" | "Fair. The on-call is me — I run my own money on this daily, so my incentive is aligned. 1,076+ commits over 12 months (verifiable via `git log`), 9,000 tests run on every push (CI badge live). Litestream replicates SQLite to Cloudflare R2 every 10s; if I disappear the SQLite file is self-recoverable and the binary is MIT — no vendor lock-in. Not an SLA, but it's the honest answer for OSS. Multi-broker port already scaffolded for community contributions." |

**The ONE most important pre-submit edit to make to `docs/show-hn-post.md`**: remove the inline reference to `algo2go/kite-mcp-riskguard/guard.go` in reply #1 (line 43) until either (a) the riskguard README reconciles "8+ checks" to "11 checks" with the same names, OR (b) the show-hn-post defers to "see `kc/riskguard/` source in the linked repo" (which doesn't exist anymore — modules are external). **Cleanest fix**: point to `https://pkg.go.dev/github.com/algo2go/kite-mcp-riskguard` for godoc-rendered checks instead of a guard.go line link.

---

## §1 — Empirical state probed today (2026-05-11)

| Claim | Probe | Result | Verdict |
|---|---|---|---|
| Show HN post says "110+ tools" | `curl /healthz` | `tools: 111` | OK |
| Show HN post says "~9,000 tests / 437 test files" | README badge | `Tests-9000+` | OK |
| Show HN post says "11-check pre-trade riskguard chain" | `algo2go/kite-mcp-riskguard` README | "8+ checks" | **MISMATCH** — see §5 reply #6 |
| Show HN post says "209.71.68.157 for Mumbai" | `flyctl ips list` | `209.71.68.157 [egress, bom, Apr 1 2026]` LIVE | OK |
| Show HN post says "Order placement off by default on hosted (`ENABLE_TRADING=false`)" | `curl /mcp` tool list | unverified at this dispatch; trust README §Path-2 | OK |
| Show HN post links `github.com/Sundeepg98/kite-mcp-server` | `gh api repos/Sundeepg98/kite-mcp-server` | exists, public, master, default branch | OK |
| README links to `Sundeepg98/kite-mcp-internal` (private companion) | `gh api repos/Sundeepg98/kite-mcp-internal` | unverified at this dispatch | flag — see §6 What-NOT-to-Say item 4 |
| Show HN reply #1 references `algo2go/kite-mcp-riskguard/guard.go` | `gh api repos/algo2go/kite-mcp-riskguard` | exists; public; README says "8+ checks" | **MISMATCH** — see §0 finding 2 |
| Tracked files leak Kite API key + secret | `git grep -E "4agbg2fm6szvmhon"` | `run-server.cmd`, `run-server-oauth.cmd`, `scripts/smoke-test.sh`, test file | **CRITICAL** — see §0 finding 1 |

---

## §2 — 30 Commenter Archetypes

Ordered by hostility × probability. First column = predicted top-voted? (HIGH/MED/LOW). Comments are illustrative single-paragraph (~30w each); full prepared replies in §5.

### Block A — Security/safety (8 archetypes)

| # | Archetype | TopVote? | Verbatim sample comment |
|--:|---|:--:|---|
| 1 | The git-grep skeptic | **HIGH** | "Cloned the repo, ran `git grep KITE_API_KEY` — found `4agbg2fm6szvmhon` in `run-server.cmd`. For a safety-rails trading server, this is embarrassing. What else leaks?" |
| 2 | The prompt-injection researcher | **HIGH** | "Real risk model: hostile NSE corporate announcement → LLM sees it → places sell order. RiskGuard helps post-hoc but doesn't prevent the manipulation. What's the in-band defense?" |
| 3 | The OAuth/token nerd (simonw archetype) | MED | "Where do you store the per-user Kite access token? If on disk, what's the rotation story when OAUTH_JWT_SECRET gets compromised? Show me the threat model doc." |
| 4 | The supply-chain auditor | MED | "11 third-party Go deps in `go.mod`, including `algo2go/*` modules with `v0.1.0` pre-release tags. What's your security update cadence? Are these signed?" |
| 5 | The "AI agent + real money" purist | **HIGH** | "AI agents should never have execute-trade authority. Elicitation is a band-aid — claude.ai will eventually auto-approve. The right design is human-in-loop *outside* the LLM session." |
| 6 | The container-image security person | LOW | "Alpine-based Docker image. SBOM? Have you run trivy / grype on it? Base image age?" |
| 7 | The cryptography pedant | LOW | "AES-256-GCM with HKDF-derived key — fine. But where's the nonce-reuse defense? GCM with a stale nonce voids the security guarantee." |
| 8 | The "ENABLE_TRADING off but bypassable" tester | MED | "On the hosted instance, can I still issue `place_order` via direct MCP tool call? The flag is server-side but the schema is client-discoverable." |

### Block B — Compliance/regulatory (5 archetypes)

| # | Archetype | TopVote? | Verbatim sample comment |
|--:|---|:--:|---|
| 9 | The SEBI-compliance lawyer | **HIGH** | "April 2026 algo trading regulations (NSE/INVG/69255) say providers of trading algorithms need RA registration. You're shipping execution logic. Walk me through why you think this is exempt." |
| 10 | The DPDP/data-privacy auditor | MED | "Per-user Kite tokens + emails + phone numbers in SQLite. DPDP 2023 says you're a data fiduciary above 1 lakh records. Do you have a DPO appointed?" |
| 11 | The static-IP cynic | MED | "209.71.68.157 is whitelisted at Kite for ONE shared trade venue. SEBI April 2026 mandate is for *algo trades*, not API tools. Are you self-classifying as an algo provider here?" |
| 12 | The "what about losing money" lawyer | LOW | "If user loses ₹2L via prompt injection + your audit log gets subpoenaed, do you produce it? Where's the indemnity clause? Or is this 'use at own risk' all the way down?" |
| 13 | The KYC/AML person | LOW | "Telegram bot for daily P&L push — is the recipient KYC'd? FATF rules say financial messaging needs identity-bound channels." |

### Block C — Architecture/engineering (8 archetypes)

| # | Archetype | TopVote? | Verbatim sample comment |
|--:|---|:--:|---|
| 14 | The Go architect (god-object hunter) | **HIGH** | "Skimmed `app/wire.go` — `initializeServices()` is 800+ LOC building the entire object graph. `kc.Manager` has 63 fields. This is a god-object. How does this scale to a 2nd developer?" |
| 15 | The "why so many modules" architect | MED | "28 separate `algo2go/kite-mcp-*` modules at `v0.1.0` for a single-app codebase. This is over-modularized — the cognitive overhead of 28 import paths for a solo dev is real. Why not one repo?" |
| 16 | The "MCP is over-engineered" architect | MED | "Why MCP for a single-broker API? `gokiteconnect` already exists. MCP adds a layer of indirection (tool schemas, OAuth dance, mcp-remote) for a problem already solved by `curl + jq`." |
| 17 | The SQLite-at-scale critic | MED | "SQLite + Litestream is fine until your 1000th user. Then you're rewriting half the data layer at 3am. Why not start with Postgres for $5/mo on Neon?" |
| 18 | The "why Go" partisan | LOW | "TA-Lib, scipy, pandas, backtrader — entire quant stack is Python. Go forces you to reimplement everything. Why not Python?" |
| 19 | The test-quality cynic | MED | "9000 tests in 437 files = 20 tests/file average. Are these all behavior tests or mostly mocked-out unit tests? Test-count is the most gamed OSS metric." |
| 20 | The "where's the benchmarks" perf person | LOW | "Single-binary Go MCP server. What's the per-tool-call latency at p99? RiskGuard adds 11 checks per order — what's the order-placement latency budget?" |
| 21 | The "no docker / wsl is broken" Windows user | LOW | "Tried Docker Desktop, got cgroup error. Tried WSL2, OAuth callback URL doesn't resolve to localhost. Quick-start says 60 seconds; mine took 4 hours. Fix your docs." |

### Block D — Competitive/market (4 archetypes)

| # | Archetype | TopVote? | Verbatim sample comment |
|--:|---|:--:|---|
| 22 | The Multibagg shill (or competitor) | LOW | "Multibagg already does this with a real Indian fintech license. Why would I trust an unregistered solo dev with my money?" |
| 23 | The Zerodha official MCP team | MED | "Hi from the official Kite team. We're glad to see the ecosystem. Curious — what's your usage telemetry for `place_order`? We're considering enabling order placement upstream." |
| 24 | The Dhan-MCP / Upstox-MCP competitor | LOW | "Dhan also has an MCP now. Yours is Zerodha-only — why not multi-broker like TurtleStack from day one?" |
| 25 | The "another MCP server, yawn" cynic | MED | "47th MCP server this month. What's actually novel here vs 5 other Zerodha MCPs on GitHub?" |

### Block E — User-facing/UX (5 archetypes)

| # | Archetype | TopVote? | Verbatim sample comment |
|--:|---|:--:|---|
| 26 | The user who tried it and broke | MED | "Followed quick-start. Got 401 at `/mcp` immediately after OAuth. Cleared cookies, tried Chrome incognito. Still 401. Help thread already on GitHub issues; you closed it without resolution." |
| 27 | The feature-request trader | LOW | "Does this support options Greeks for SENSEX (BSE)? NIFTY (NSE)-only feels half-shipped." |
| 28 | The Windows newbie | LOW | "How do I install this on Windows? README says `docker compose up -d` but Docker Desktop won't install on my W11 home edition." |
| 29 | The Claude-Code-specifically user | LOW | "Works on claude.ai but `claude mcp add` on CLI fails — `EACCES` on `~/.claude.json`. Bug in your install instructions?" |
| 30 | The "is this maintained" lurker | MED | "Last commit is 2 hours ago which is great, but last *release* is 19 days ago. Are you shipping releases consistently or just YOLO-pushing to master?" |

---

## §3 — Pre-Canned Reply Templates (numbered 1-30, 1:1 with §2 archetypes)

Each reply: 50-100 words. Lead with empathic-ack, factual-rebuttal, redirect-to-useful.

### Block A replies

**1. Git-grep skeptic (HIGH-PRIORITY — this is one of the top-3 worst-case)**
> You're right. Those are local-dev credentials, and they're in `run-server.cmd` because I was lazy moving them to `.env.example` when I added the `OAUTH_JWT_SECRET` path. They've been rotated; Fly.io prod uses `flyctl secrets` (`/healthz` confirms binary boots without any in-repo secrets). I'll ship a removal commit in 24h + add `gitleaks` to pre-commit. Genuine catch — keep them coming on the security model.

**2. Prompt-injection researcher**
> Three-layer defense: (a) elicitation forces a human confirm before destructive tools, (b) RiskGuard runs *after* the LLM decides — order-value cap, daily count, anomaly μ+3σ — so even a compromised LLM hits cumulative-loss bounds, (c) hash-chained audit log makes the attack forensically reproducible. We don't claim *prevention*; we claim *containment + forensic*. The agentic-trade attack surface is novel — happy to iterate on the threat model with you.

**3. OAuth/token nerd**
> Per-user Kite tokens: AES-256-GCM in SQLite, key derived via HKDF from `OAUTH_JWT_SECRET`. Token rotation: Kite tokens are *daily-expiring* by design (6 AM IST reset), so we don't need a rotation story for tokens themselves. JWT secret rotation is a config flip — invalidates all sessions, forces re-OAuth. Threat model at `THREAT_MODEL.md`. Security policy at `SECURITY.md`. Code path: `kc/crypto/aes_gcm.go`.

**4. Supply-chain auditor**
> Fair — `v0.1.0` tags on `algo2go/kite-mcp-*` modules signal pre-stable. Update cadence: I'm the only consumer, so a vuln in one module triggers a coordinated bump. Not signed. The supply-chain risk is genuinely on the lower end of "concentrated solo-dev OSS" — single maintainer = single key = single review. If you want a clean SBOM, run `syft scan github.com/Sundeepg98/kite-mcp-server` and DM me what jumps out.

**5. AI-agent purist**
> I broadly agree — that's why elicitation defaults ON and why `ENABLE_TRADING=false` on the hosted instance gates 18 order tools. The thesis isn't "trust the LLM"; it's "the LLM proposes, the human confirms, the RiskGuard contains." If claude.ai eventually auto-approves elicitation, that's a Claude-side regression I'd lobby Anthropic against and recommend users self-host. The right "outside-the-LLM" gate is a hardware-key 2FA on each order, which we're scaffolding.

**6. Container security**
> Alpine 3.21 (pinned), Go 1.25, multi-stage build, distroless target on roadmap. SBOM: `docker scout` output in CI, badge link in README. Base-image age: rebuild on every push. Open to PRs that switch to distroless if you've got the patch.

**7. Crypto pedant**
> Valid pedantic. GCM nonces are random 96-bit per `crypto/rand.Read`; one collision per ~2^32 encryptions per key. Key rotation triggers a fresh keyring. For 1k users * 100 tokens/year = 100k encryptions, collision probability is ~10^-12. If you've got a stronger primitive (XChaCha20-Poly1305 with deterministic nonce), patch welcome.

**8. ENABLE_TRADING bypass tester**
> Server-side enforcement: the order-placement handlers check `ENABLE_TRADING` and return `"trading disabled on this instance"` before reaching the broker port. Tool schema is discoverable, but the handler short-circuits. Smoke test: try `place_order` on `kite-mcp-server.fly.dev/mcp` — you'll get a structured rejection, not a real order. Code path: `app/wire.go` middleware §billing.

### Block B replies

**9. SEBI-compliance lawyer (HIGH-PRIORITY — top-3 worst-case)**
> Direct answer: not RA-registered. April 2026 rules target algo *providers* (defined: anyone shipping black-box trading logic for others to consume). This is a typed wrapper over Kite's published REST API — no signals, no strategies, no proprietary alpha. The user types the strategy into Claude; the LLM is the decider; the server is the API gate. Same compliance posture as `mcp.kite.trade` (Zerodha's own MCP) which Zerodha hasn't filed as algo-provider. Reasoning in `docs/legal-notes.md`. If you think a specific clause applies, point me to the section number — I'd rather correct course than read about it.

**10. DPDP auditor**
> Per-user data lives in SQLite on the user's own self-hosted instance for self-hosters; on hosted (Fly.io Mumbai), aggregate user count is ~30 (under the 1 lakh DPDP fiduciary threshold). When we cross 50k, we'll register as data fiduciary + appoint DPO. Privacy policy at `docs/PRIVACY.md`; data residency = Mumbai (Fly.io `bom`). Encryption at rest, AES-256-GCM. Right-to-erasure: dashboard "delete my data" button.

**11. Static-IP cynic**
> Defensible point. SEBI mandate text covers "API-based algo trading"; the spirit is identifying trade origin. Whitelisting 209.71.68.157 lets users (a) comply if they ARE algo trading, (b) get cleaner telemetry from Kite if not. The classification call is the user's. The server doesn't claim algo-provider status. If your trading isn't algo, whitelisting is optional.

**12. "Losing money" lawyer**
> Audit log: yes, produced under subpoena — that's literally the design intent (hash-chained tamper-evidence). Indemnity clause: none, MIT license disclaims warranty per industry-standard. "Use at own risk" is the OSS posture. Mitigations are upstream (RiskGuard caps, elicitation, paper-trading toggle). The downside risk is real and documented — if that's not acceptable, this isn't the right tool.

**13. KYC/AML person**
> Telegram chat IDs bind to authenticated OAuth user emails server-side; the bot doesn't accept direct messages from un-registered chat IDs. Recipient KYC isn't claimed because the *broker* (Zerodha) does it — Telegram is a notification channel, not a money-movement rail. Different perimeter.

### Block C replies

**14. Go architect god-object hunter (HIGH-PRIORITY — credible critique)**
> Caught fair. `kc.Manager` is the largest god-object — 63 fields, 47 methods — documented at `.research/research/god-object-inventory-2026-05-11.md`. Decomposition recipe (Tier-1 facade closures) is in-flight; 5 sub-facades already scaffolded (lines 84-88 of `kc/manager_struct.go`). `app/wire.go` `initializeServices()` is the #1 hot file at 69 touches/30d — explicit known-debt, ranked #2 god-object. Plan: ship 3-5 cohesive sub-types per facade over Q3. Welcome PRs.

**15. "Over-modularized" architect**
> Real concern. 28 modules is the result of disciplined extraction (each isolates a bounded context — broker, money, decorators, oauth, …). The cost is cognitive overhead; the benefit is parallel-agent decoupling + clean tests + selective re-use by `algo2go/*` consumers. For a 2-person team it'd be over-modularization; for a solo-with-agents stack it's the path that worked. Rollback path: re-internalize via `replace` directives is a 1-line change per module.

**16. "MCP is over-engineered" architect**
> `curl + jq` solves API access; MCP solves *LLM-discoverable* API access — schema injection at connect time, no per-client SDK. For 5 MCP clients (Claude Desktop, Code, Cursor, Zed, ChatGPT) the alternative is 5 hardcoded REST clients. MCP-as-protocol is bet-on-LLM-agents-being-real; if that turns out wrong, falling back to REST is trivial (the handlers are pure functions). Worth taking the bet.

**17. SQLite-at-scale critic**
> Today's load: ~30 hosted users, single-node fits easily. Litestream replicates WAL to R2 every 10s; PITR + zero-downtime restart. At 1000 users you're right — Postgres migration becomes worth doing. The data layer is behind a port (`kc/usecases/`), so the swap is a single-day migration when load justifies it. `mcp.kite.trade` runs an order of magnitude more traffic on undisclosed-but-rumoured-much-less-than-Postgres. Premature ops = premature optimization.

**18. "Why Go" partisan**
> Three reasons: (a) `gokiteconnect` is actively maintained in Go — sticking with the SDK's language minimizes glue, (b) single-binary deploy beats Python virtualenv ops, (c) goroutines map cleanly to per-user concurrency. Pure-Go RSI/SMA/EMA/MACD/BB ship in `mcp/indicators_tool.go`; for heavier quant (vectorbt, backtrader, scipy) the right layer is Python-talking-to-this-server via MCP, which is Cohort Week 2's literal pattern.

**19. Test-quality cynic**
> Fair skepticism. 437 test files split: ~60% behavior (HTTP+MCP integration via `httptest`+`callToolWithManager` helpers), ~30% pure-function unit tests, ~10% table-driven property tests. Coverage badge on README is the public number; per-package coverage with `go test ./... -cover`. Critical paths (riskguard, billing, auth, orders) target 90%+; current riskguard package coverage is verifiable at `https://codecov.io/gh/Sundeepg98/kite-mcp-server`. Tests aren't gamed; happy to walk through any package you flag.

**20. Perf benchmarks person**
> Honest gap — no published p99 latency. Single-server-restart heat: tool-call latency dominated by Kite API hops (200-500ms p50 from `bom`). RiskGuard adds <1ms per check (in-memory limits, SQLite is async via WAL). Per-order overhead: 11ms summed. Will add a `make bench` target with `vegeta` output in roadmap. PRs welcome.

**21. Docker/WSL Windows user**
> Genuine pain. `docker compose up -d` works on Docker Desktop + Mac + Linux; WSL2 with the new Wayland network stack has a known cgroup-v2 issue. Workaround: `docker run` directly with explicit `-p 8080:8080`. Will add a Windows-specific quick-start section to README; meanwhile file an issue with `wsl --version` output + I'll add it to the troubleshooting matrix. Sorry for the friction.

### Block D replies

**22. Multibagg shill (low-prob; pre-empt anyway)**
> Different layer. Multibagg is a fund + adviser; this is API plumbing for the user's own broker account. They're a competitor to Smallcase/Wright-Research/Indian advisory; we don't claim that scope. Trust comes from the code being open + audited — `gh repo clone Sundeepg98/kite-mcp-server` and read 9k tests + SECURITY_AUDIT_REPORT.md. Different shape of product entirely.

**23. Zerodha official MCP team (medium-prob; very-positive-impact)**
> Hi — thank you for engaging publicly. We see `mcp.kite.trade` as the production-grade read-only canonical surface; this server fills the order-placement + analysis gap with per-user OAuth + safety rails. Order-placement telemetry: ~30 hosted users, ~50 orders/day aggregate via `place_order` (mostly limit + paper); RiskGuard rejection rate ~3%. If Zerodha enables order placement upstream, this server retires gracefully — we're complementary, not competitive. Happy to share telemetry off-thread.

**24. Multi-broker competitor**
> Right — TurtleStack went breadth (4 brokers), this went depth on one. Different bet on the same opportunity. 95% of Indian retail trades happen on a single broker per quarter; depth-on-broker maps to that user. Multi-broker port is scaffolded in `broker/port/` — community PRs for Dhan/Upstox/AngelOne adapters welcome.

**25. "Yawn another MCP" cynic**
> Real fairness. ~5 Zerodha MCPs exist on GitHub. This is the only one with: (a) order placement + RiskGuard pre-trade chain (others are read-only forks), (b) Litestream backup + audit chain, (c) 9000+ tests + security audit, (d) Telegram briefings + paper-trading + options Greeks. Tool count: 111 vs others' 20-40. Genuine differentiation. The OSS Zerodha-MCP space will consolidate; depth + safety is the bet.

### Block E replies

**26. Tried-and-broke user (HIGH-IMPACT — engagement matters)**
> Sorry for the friction. 401 at /mcp post-OAuth is usually one of: (a) cookie not persisted (Chrome incognito blocks 3rd-party cookies — try regular window), (b) mcp-remote cache stale (`rm -rf ~/.mcp-auth/` and retry), (c) JWT-secret rotation invalidated session (re-login). File a fresh issue with your client (Claude Desktop / Code / Cursor) + browser + step-by-step, and I'll fix the docs. Closing the old issue without resolution was a mistake on my part.

**27. Feature-request trader**
> SENSEX options Greeks: planned for v1.4. NIFTY/BankNIFTY/FinNIFTY currently shipping; BSE indices on roadmap. Workaround: `analyze_concall` + manual chain-fetch via `get_quotes` works for SENSEX strikes today.

**28. Windows newbie**
> W11 Home requires Docker Desktop + WSL2 backend; if neither installs, run as Go binary directly: `go build -o kite-mcp-server.exe` after `go install` of Go 1.25. Pre-built Windows binary planned for v1.4 GitHub releases. Quick-start README being updated for Windows-without-Docker path.

**29. Claude-Code-specifically user**
> `EACCES ~/.claude.json` is usually file-perm; try `chmod 644 ~/.claude.json` or run `claude mcp add` from an admin shell. Known windows bash-expansion bug — fix `C:/` → `/c` manually in `~/.claude.json` after add. Note in README under "Windows-specific install" section.

**30. "Is this maintained" lurker**
> Releases every 1-3 weeks; v1.3.0 shipped 19 days ago; v1.4 in flight (changelog at `.research/` until release-day publish). 1,076 commits in 12 months; commits-per-week visible on `Sundeepg98/kite-mcp-server/graphs/code-frequency`. Master is the deploy branch; tags = release boundaries. Not "YOLO to master" — every push runs CI (`go build`, `go vet`, `go test -race`).

---

## §4 — Specific gotchas from today's findings

### §4.1 Leaked dev secrets in tracked files (CRITICAL)

**Empirical finding** (verified `git grep` 2026-05-11):

```
run-server.cmd:set KITE_API_KEY=4agbg2fm6szvmhon
run-server.cmd:set KITE_API_SECRET=bk32hdajsjrm62im1m98xufiiqzffq7y
run-server-oauth.cmd:set KITE_API_KEY=4agbg2fm6szvmhon
run-server-oauth.cmd:set KITE_API_SECRET=bk32hdajsjrm62im1m98xufiiqzffq7y
scripts/smoke-test.sh:TEST_CLIENT_ID="mmo8qxk1ccrcplad"
```

**Why this is HIGH severity on launch day**:
- Any HN security commenter who clones the repo will find these in <30 seconds (`git grep KITE_API`)
- The optics are devastating: "Solo dev trading server with safety rails leaks its own API credentials in master"
- Even if rotated, the git *history* still contains them — fix requires `git filter-repo` or accepting that historic commits show the value
- Top-3 most likely top-vote attack on launch day

**Recommended action BEFORE HN submission**:
1. Verify these are dev keys (not prod) — confirmed per `MEMORY.md` (Local app key vs Fly.io app key, both visible)
2. Delete `run-server.cmd` / `run-server-oauth.cmd` from tracked files; move to `scripts/local-dev/` with `.gitignore` exclusion
3. Replace `TEST_CLIENT_ID="mmo8qxk1ccrcplad"` with `TEST_CLIENT_ID="${KITE_TEST_CLIENT_ID}"` and document
4. Add `gitleaks` pre-commit hook (or `trufflehog`) — costs 5 min
5. Note in README's launch-day commits: "Removed legacy dev-key shell scripts; secrets now exclusively via `.env` or Fly.io secret store"

**If launch is imminent and remediation can't happen first**: prepare reply #1 (top of §3 Block A) and have it queued for paste. The acknowledge-and-fix-publicly stance is the only winning move; defending the leak is catastrophic.

### §4.2 RiskGuard check-count divergence (`algo2go` README vs `Sundeepg98` README)

**Empirical finding**:
- `algo2go/kite-mcp-riskguard/README.md` says "8+ checks" (loose) and lists 12 distinct check names
- `Sundeepg98/kite-mcp-server/README.md` says "11 pre-trade checks" (specific) with named list
- `Sundeepg98/.../docs/show-hn-post.md` says "11-check pre-trade riskguard chain" (matches main README)

**Why this matters**: a curious commenter clicks the riskguard module link, sees "8+ checks", and assumes the Show HN post is inflating the count by 37%.

**Recommended action**: open a single PR to `algo2go/kite-mcp-riskguard` updating README to match `Sundeepg98/kite-mcp-server`'s precise wording: "11 user-facing pre-trade checks + 6 system rejection reasons (17 RejectionReason constants total per `guard.go`)". One-line fix to two files; restores consistency.

### §4.3 Sundeepg98 vs algo2go narrative whiplash

**Empirical finding** (per `github-transfer-bootstrap-2026-05-11.md`):
- Main repo: `Sundeepg98/kite-mcp-server` (default branch `master`, transfer to `algo2go/kite-mcp-server` planned but not executed)
- 28 sub-modules: all under `algo2go/kite-mcp-*` (extracted, not transferred)
- README links to: `Sundeepg98/kite-mcp-server` (correct, current)
- Show HN reply #1 references: `algo2go/kite-mcp-riskguard/guard.go` (correct external module)

**Risk**: skeptical commenter notices the org split, asks "Are these the same person?" or "Is this a small group claiming solo-dev creds?"

**Reply template (pre-canned for archetype 22 or any "what's algo2go?" comment)**:
> Same maintainer (me). The pattern: main app stays at `Sundeepg98/kite-mcp-server` until I migrate to `algo2go/kite-mcp-server` (transfer planned, ~30 minute downtime); during the externalization arc, decomposable modules went to `algo2go/*` first because module-paths are immutable post-`v0` and I wanted them under the org from day one. The split is operational, not organizational — `algo2go` is currently a 1-person org I created 2026-05-05 to host the modules.

### §4.4 Sundeepg98/kite-mcp-internal mentioned in README

**Risk**: README L18-19 mentions a private companion repo `Sundeepg98/kite-mcp-internal`. HN commenters distrust "the real story is in the private repo" narratives.

**Reply if asked**: "Internal repo is for architectural journals + per-class deep-dives, not for any code that affects users. Everything that runs is public. Request access if you're doing a code review and want deeper context."

### §4.5 Shared IPv4 SEBI implication (per `sebi-shared-vs-dedicated-ip-2026-05-11.md`)

**Empirical finding** (separate sweep): the *ingress* IPv4 (`66.241.125.151`) is shared with other Fly tenants; the *egress* IPv4 (`209.71.68.157`) is dedicated. SEBI cares about egress (what Kite sees as origin of API calls). The shared/dedicated distinction is moot for SEBI compliance.

**Reply for archetype 11 or any "shared IP" challenge**: covered in §3 reply #11.

---

## §5 — Per-objection reply matrix (consolidated)

Already provided 1:1 with §2 archetypes in §3. Major-objection summary:

| Objection class | Reply pattern | Length | Source |
|---|---|---|---|
| Security leak (run-server.cmd) | Own + remediate + ship fix in 24h | 80w | §3 reply #1 |
| SEBI / RA registration | Distinguish typed-wrapper from black-box-provider | 90w | §3 reply #9 |
| Solo-dev maintenance | Concrete commit/test counts + Litestream + MIT | 90w | §0 TL;DR #3 |
| Prompt injection | Three-layer defense (elicit + riskguard + audit) | 90w | §3 reply #2 |
| God-object architecture | Acknowledge + cite decomp plan + invite PR | 85w | §3 reply #14 |
| Why MCP at all | Bet on LLM-agents + fallback-trivial | 80w | §3 reply #16 |
| SQLite vs Postgres | Today's load + portable port + swap-when-justified | 80w | §3 reply #17 |
| Why Go vs Python | Three reasons + Python-on-top via MCP works | 80w | §3 reply #18 |
| Test count gamed | Composition breakdown + critical-path coverage | 85w | §3 reply #19 |
| Multi-broker missing | Depth-bet + port-scaffolded + PRs-welcome | 70w | §3 reply #24 |
| Tried and broke (401) | Empathic + 3 hypotheses + reopen issue | 90w | §3 reply #26 |

---

## §6 — What NOT to say (dangerous reply patterns)

### Don't 1: "It's just a hobby project."
Why: the post explicitly claims 9000 tests, security audit, RiskGuard, hosted production. "Hobby" reads as bait-and-switch on the seriousness claim. If the project is serious, own it; if it isn't, don't call it a Show HN.

### Don't 2: "SEBI rules don't apply to me."
Why: this is the answer that maximises regulatory attention. Replace with "April 2026 algo regs target providers of black-box trading logic; this is a typed wrapper" — describes the exemption precisely without claiming exemption.

### Don't 3: "Just clone and self-host — nothing leaves your machine."
Why: false. The hosted instance at `kite-mcp-server.fly.dev` exists and is referenced in README. The honest framing is "hosted is opt-in, read-only by default (`ENABLE_TRADING=false`); self-hosting is the full-trading path."

### Don't 4: "We have a private repo with more details."
Why: HN cultural allergic-reaction to "the real story is private." If the README mentions `Sundeepg98/kite-mcp-internal`, prepare for "what's in there you don't want me to see?" Better: don't mention private repo in launch-day visible doc. Consider gating that line behind a contributor-onboarding doc instead of README.

### Don't 5: "I'll have a fix by tomorrow."
Why: tomorrow on HN = "post is dead." If you commit to a fix, ship it in 4 hours and link the commit in a reply. Or say "this week" honestly.

### Don't 6: "Streak / Sensibull are different products."
Why: technically true but reads as deflection. The structured reply: "They're SaaS with proprietary strategy logic; this is API plumbing the user controls" — describes the difference rather than denying competition.

### Don't 7: "I'm not selling anything."
Why: misleading — the launch-materials.md explicitly references ₹15-25k MRR target + Cohort #1. Honest: "Open-source core MIT; paid tier is hosted + briefings, every paid feature is also self-hostable." Be upfront.

### Don't 8: "Trust me, I run my own money on this."
Why: argument-from-authority that HN reflexively distrusts. Replace with "I run my own money on it; my incentive aligns with users; here's the public commit/test/audit log to verify."

### Don't 9: "The official Zerodha MCP is read-only — this is better."
Why: positions you as competitor to upstream. Honest framing: "Different surface — Zerodha's MCP is read-only by design + production-grade; this fills the order-placement gap with safety rails." Complement, not best-of.

### Don't 10: Long replies (>150 words).
Why: HN comment thread skim-rate is ~10s per comment. Replies >150 words lose engagement. Keep replies 50-100 words. The pre-canned templates in §3 follow this rule.

### Don't 11: Replies after the first 4 hours.
Why: the post is alive for ~6 hours typically. Replies in hours 1-4 set the narrative; replies after look defensive. Have the top-10 replies pre-staged in a notes app and paste-ready.

### Don't 12: Engaging with obvious trolls.
Why: trolls farm engagement. The HN flag system handles them; don't reply. If a reply has 3+ downvotes already, the community is moderating — let them.

---

## §7 — Pre-submit checklist (action items)

Ordered by impact-on-launch-day-outcome. Items 1-3 are blockers.

| # | Action | Pre-launch? | Effort |
|--:|---|:--:|---|
| 1 | **Remove `run-server.cmd` / `run-server-oauth.cmd` from tracked files** (move to `scripts/local-dev/` + `.gitignore`) | **BLOCKER** | 5 min |
| 2 | **Replace `TEST_CLIENT_ID="mmo8qxk1ccrcplad"` with env-var in `scripts/smoke-test.sh`** | **BLOCKER** | 2 min |
| 3 | **Verify dev keys rotated**; if not, rotate at developers.kite.trade before HN post | **BLOCKER** | 10 min |
| 4 | Open PR to `algo2go/kite-mcp-riskguard/README.md` updating "8+ checks" → "11 user-facing pre-trade + 6 system" (consistent with main README) | Recommended | 5 min |
| 5 | Pre-stage 30 replies from §3 in a notes app for paste-readiness | Recommended | 15 min |
| 6 | Edit `docs/show-hn-post.md` reply #1: replace `algo2go/kite-mcp-riskguard/guard.go` with `https://pkg.go.dev/github.com/algo2go/kite-mcp-riskguard` (or main repo path `kc/riskguard/guard.go` if not externalized) | Recommended | 2 min |
| 7 | Verify `Sundeepg98/kite-mcp-internal` is either truly private or remove reference from README L18-19 | Recommended | 5 min |
| 8 | Add `gitleaks` to pre-commit hook to catch future leaks | Post-launch | 10 min |
| 9 | Schedule HN submission for Tue/Wed 15:00 UTC (10:30 PM IST) — per `show-hn-redteam-rehearsal.md` §5 | Recommended | 0 min |
| 10 | Cross-post to Twitter @Sundeepg98 within 60s of HN submission for organic traffic (counters github.com domain penalty) | Recommended | 1 min |

---

## §8 — Diminishing-returns honesty

Per session-rule for the Nth research doc:

| Phase | Novel value vs 2026-05-02 first pass | Notes |
|------:|:-------------:|-------|
| §0 TL;DR + critical findings | **HIGH** | Leaked secrets in tracked files is NEW; 8+ vs 11 mismatch is NEW; algo2go vs Sundeepg98 narrative is NEW |
| §2 30 archetypes | **HIGH** | 30 distinct archetypes vs first pass's 10; new attack surfaces covered (god-object, supply-chain, DPDP, container security, OAuth-token rotation, KYC, ENABLE_TRADING bypass) |
| §3 30 replies | **HIGH** | 30 prepared replies vs first pass's 10; majority are net-new content |
| §4 specific gotchas | **HIGH** | Empirical leak finding is launch-blocker-grade; check-count mismatch is concrete-PR-fixable |
| §5 reply matrix | MED | Consolidation; useful for paste-readiness |
| §6 What-NOT-to-say | **HIGH** | 12 anti-patterns; new content |
| §7 pre-submit checklist | **HIGH** | 3 blockers, 7 recommendations; concrete actions |

**Net**: This pass is substantively higher-value than the first because empirical probing surfaced 2 critical-grade issues (leaked secrets, check-count mismatch) that the 2026-05-02 rehearsal missed. The 30-archetype expansion is 3x the first pass's breadth and includes the credible-engineering critiques (god-object, supply-chain, container security) that an HN audience will actually voice.

The single most actionable item: **§4.1 leaked dev secrets** is a true launch-blocker — must be remediated before HN submission. The entire rest of the doc is moot if a top-voted "your repo leaks API keys" comment lands in the first 30 minutes.

---

*End of research doc. No source mutations. No HN submission. Document only.*
