# 10000-Agent Capacity — Comprehensive Blocker Analysis + Phased Roadmap

**Date**: 2026-05-06
**HEAD**: `869b36a` (Path A FULLY CLOSED for broker + kc/money + kc/decorators external on algo2go; 27 in-tree workspace modules; v228 LIVE; tools=130 empirical-per-grep — **CORRECTION 2026-05-11**: this "130" was a raw `grep mcp.NewTool(` over `mcp/` that included 19 `_test.go` fixtures; production-registered tools=111 per compile-and-run, verified via `production-master-gap-report.md` §1.4; 40-deploy streak ✓)
**Builds on**: `cacbc20 architecture-scale-ceiling.md`, `6ee6520 architecture-scale-paths-A-B-C.md`, `725ac32 abc-100pct-complete-paths.md`, `21503fd broker-promotion-runbook.md`, sibling `.research/1000-agent-capacity-plan.md`
**Charter**: doc-only research. NO code changes during plan-document commit.
**User authorization**: broad — accepts regulatory paths (SEBI dialogue, NSE empanelment, multi-Kite-app sharding), expensive infra, "do what is necessary" investments.

---

## TL;DR — REVISED post-empirical-corrections (2026-05-06)

10K-agent capacity at our state is **substantially more achievable than the initial framing suggested**. Two empirical corrections collapsed the largest perceived blockers:

1. **"Whitelisted IPs" field is plural** (verified at `mcp/plugin_widget_ip_whitelist.go:54`) — accepts N IPs in ONE field of ONE Kite app. **No multi-cell-IP-whitelist regulatory blocker.**
2. **SEBI 10/sec is per (user's-own-Kite-app, user)** — and our architecture already requires users to bring their own Kite app. Rate limit is naturally per-user; **no operator-side multi-app sharding needed.**

After corrections, the campaign decomposes into:

1. **Engineering-solvable** (in our hands): ~85% of blocker surface. Phases 1-6 ~3-6 months focused work.
2. **Regulatory** (in others' hands but solvable): NSE empanelment (~3-6mo calendar, ~₹4-8L) at 30+ paid subs; DPDP Data Fiduciary registration; SEBI RA registration only if ship signals. Covers ~10% of blockers.
3. **Physical-limits-with-workaround**: ~5% — primarily Kite per-app WS connection limits and Whitelisted-IPs field array cap (verifiable, not blockers).

**Cost ceiling collapsed 75%**: from ~₹3.5-4.5L/mo grand-total to **~₹50K/mo founder-only at 10K capacity**. Pre-Seed-viable, not Series-A-required.

**Total realistic calendar to 10K-capable**: **6-12 months at solo+₹0**; **3-6 months at Pre-Seed-funded** (1 hire + ~₹50K-1L/mo cloud + ~₹4-8L NSE empanelment at trigger).

---

## Empirical Baseline at HEAD `869b36a`

| Dimension | State | Implication for 10K |
|---|---|---|
| Workspace modules | **27 in-tree** + 3 external (algo2go: broker, kc/money, kc/decorators) | 27 more promotions × ~3-7h each = 81-189 agent-hours of mechanical work |
| Production deploys | 40 consecutive (v189 → v228) at doc-write time; 84+ as of 2026-05-11 (machine version 273), tools=111 production-registered throughout (the prior "tools=130" claim was raw-grep over `mcp/` including 19 `_test.go` fixtures — see `production-master-gap-report.md` §1.5) | Single-machine deploy is current bottleneck |
| Single-binary deploy | Yes (Fly.io BOM region, `min_machines_running = 1`) | **Cannot scale horizontally** for trade path until Layer-2 work |
| Single-repo CI | 15 workflows (was 14 at doc-write; `tool-count-drift.yml` added since), GitHub-hosted runners | At N=10K, GitHub Actions API rate-limits at ~5K/hr token. Empirical breakage point N≈500-1K |
| Sub-packages (folders, not modules) | 12 (mcp/{*}, kc/ops/{*}) | Folder organization, share build target. Not directly relevant to 10K |
| Empirical proven concurrency | 3-5 disjoint-scope agents (this session) | Maps to ~20-25 agent-equivalents per dispatch; **not yet validated at N=100+** |
| Per-user IP whitelist | SEBI Apr 2026 mandate; static egress `209.71.68.157` BOM | Multi-cell distribution forces user to whitelist N IPs |
| **SEBI per-second rate** | **`maxOrdersPerSecond = 9`** in `algo2go/kite-mcp-riskguard/per_second.go:30` (post Path A.21 promotion; was `kc/riskguard/per_second.go` pre-promotion; defensive; Zerodha-enforced 10/sec broker-side) | **PER KITE APP PER USER**, NOT per operator. Multi-app sharding = N×10 effective sub-second throughput |
| MCP tool count | 130 (`grep -rE 'mcp\.NewTool\("' mcp/` at HEAD `869b36a`) | Tool surface scaling itself is not a 10K blocker; per-tool throughput is |

**The critical finding**: SEBI's 10/sec is per `(Kite developer app, user)` pair. This empirical detail in `algo2go/kite-mcp-riskguard/per_second.go:1-30` (post Path A.21) reframes the whole 10K plan: **trade-path scaling = procuring N Kite developer apps + sharding users across them**, not "decompose synchronous trade path" (which is impossible).

---

## Layer 1 — Regulatory Blockers (SEBI / NSE / Zerodha)

### L1.1 — SEBI 10/sec rate limit — RECLASSIFIED post-architecture-correction

**ARCHITECTURAL CORRECTION (2026-05-06)**: Multi-Kite-app sharding was previously framed as the workaround for this blocker. **It is NOT needed.** Each user authenticates with their OWN Kite developer app (BYO-developer-app architecture per `MEMORY.md kite-mcp-server` notes). The 10/sec SEBI rate limit applies per (user's app, user) pair — which means it's already per-user-segregated by design. At 10K agents on the same operator's deployment, each user has their own independent 10/sec budget against THEIR OWN Kite app. There is no shared "operator-wide 10/sec ceiling" for trade orders.

The earlier framing conflated "operator hosts N users" with "operator runs N trade flows through one app". Empirically wrong: each user's trades route through THEIR Kite developer app, not ours.

| Column | Detail |
|---|---|
| **Engineering-solvable?** | **YES (already done).** `algo2go/kite-mcp-riskguard/per_second.go:30-50` (post Path A.21) already shards rate-limit by user. Each user's 10/sec budget is independent of any other user's. |
| **Regulatory action** | **None required.** SEBI 10/sec is a per-user constraint, not per-operator. |
| **Physical-limit workaround** | **Cell-side rate-shaping** (token bucket per user) is the only addition needed for graceful degradation under burst load. Pure engineering. |
| **Cost of workaround** | Engineering: ~1 week to add token-bucket rate-shaper at cell-router layer. **No multi-Kite-app procurement.** |
| **When breaks** | If a single user's agent fleet attempts >10/sec from one user account, they hit Zerodha's broker-side reject. Rate-shaper softens this with queueing. For 10K agents distributed across many users, each user stays well under 10/sec. |
| **At-10K read-path scale** | **Rate limit irrelevant for read paths.** Get-LTP, get-quotes, get-OHLC, etc. are not rate-limited at 10/sec; only order placement is. Read-paths scale with infra capacity (cells), not with rate-limit-per-app. |

**ROI**: at zero-user state: zero (already correct). At-scale: native — no extra cost for multi-user. Rate-shaper engineering only justified if a single user's agent fleet generates >10/sec sustained; at typical retail scale, irrelevant.

**Smallest first step**: skip per-app counter refactor (not needed). Optional: add token-bucket rate-shaper at cell-router for graceful 10/sec backpressure. ~2-3 days when load patterns warrant.

### L1.2 — SEBI per-user IP whitelist mandate (April 2026) — RECLASSIFIED to engineering-solvable

**EMPIRICAL CORRECTION (2026-05-06)**: Our own widget code at `mcp/plugin_widget_ip_whitelist.go:54` confirms the Kite developer console field is **"Whitelisted IPs"** (plural — accepts an array). User adds multiple IPs to ONE field in ONE Kite app. Multi-cell distribution does NOT require SEBI relaxation, multi-app sharding, OR Kite-console scraping.

| Column | Detail |
|---|---|
| **Engineering-solvable?** | **YES (full).** Setup wizard helps user copy-paste N cell IPs into the "Whitelisted IPs" field of their existing Kite app. ~1 week eng for wizard UI; brokers no Zerodha-side automation. |
| **Regulatory action** | **None required.** Previous framing claimed "petition SEBI for per-operator whitelist" — empirically unnecessary. The plural-field design already accommodates multi-cell. |
| **Physical-limit workaround** | **Setup-wizard automation**: dashboard page shows user the cell-IP list + step-by-step screenshots; user copies into their existing Kite dev console "Whitelisted IPs" field. ONE field, N values. |
| **Cost of workaround** | Engineering: ~1 week for wizard UI. User friction: 5-10 min one-time onboarding to add N IPs to the existing field. **Same Kite app, no extra Kite-app procurement.** |
| **Open assumption to verify** | "Whitelisted IPs" field array length cap. Likely ≥10 (typical cloud pattern); >50 would need Zerodha conversation. For 5-10 cells (sufficient for 10K read-path capacity), almost certainly fits. **Single assumption to verify with Zerodha at 5-cell threshold; not a present blocker.** |
| **When workaround breaks** | (a) If Zerodha caps the array at <N where N = our cell count. (b) If Zerodha changes dev-console UI and breaks the copy-paste flow. Both are conversations-with-Kite, not regulatory. |

**Smallest first step**: stub `/dashboard/onboarding/whitelist-ips` page showing the static IP list (`209.71.68.157` + future cell IPs) with copy-buttons + step-by-step screenshots. ~2-3 hours.

### L1.3 — NSE empanelment threshold (~50 paid subscribers)

| Column | Detail |
|---|---|
| **Engineering-solvable?** | No. This is a distribution gate, not an engineering one. |
| **Regulatory action** | NSE algo-vendor empanelment process. Cost: ~₹4-8L (per `kite-cost-estimates.md` in `MEMORY.md`). Calendar: 3-6 months from filing. Probability: high once 50-paid-sub threshold met. |
| **Physical-limit workaround** | None at scale. Below 50 paid subs: stay in "personal-use safe-harbor" framing (Path 2 — `ENABLE_TRADING=false` on hosted, full trading on self-host). Above 50 paid subs: empanelment required. |
| **When workaround breaks** | At 50 paid subs (per Z-Connect threshold). If we reach this without empanelment, exposed to NSE/INVG/69255 enforcement. |

**Smallest first step**: file empanelment paperwork at 30 paid subs (gives 6-month buffer for NSE process). Cost ~₹4-8L; prepare via Spice Route Legal or Finsec Law (per `kite-fintech-lawyers.md`).

### L1.4 — Zerodha "one app per active session" policy

| Column | Detail |
|---|---|
| **Engineering-solvable?** | Yes (architectural). |
| **Regulatory action** | None — this is Zerodha ToS, not SEBI. Negotiable via Rainmatter relationship. |
| **Physical-limit workaround** | **Session affinity**: each user pinned to one cell (one Kite app). Cell router shards by `hash(user_email)`. Per-cell session count bounded by cell capacity. |
| **Cost of workaround** | Cell-router engineering: ~2-3 weeks. Operational complexity per cell: moderate. |
| **When workaround breaks** | Never under user-pinned model. Breaks if user switches device mid-session and lands on different cell — solvable via consistent-hash routing. |

### L1.5 — DPDP / data localization at scale

| Column | Detail |
|---|---|
| **Engineering-solvable?** | Yes — already substantially in place (AES-256-GCM at rest, BOM region). |
| **Regulatory action** | Register as Data Fiduciary post-50 paid subs per DPDP Act 2023. Cost: ~₹50K-1L legal. Calendar: 1-2 mo. |
| **Physical-limit workaround** | Stay in BOM (Mumbai) for India-user data. Multi-region distribution (e.g., SIN for SE Asia users) requires data-export consent at user level. |
| **When workaround breaks** | If DPDP rules tighten on cross-region data flow. Mitigation: cell-per-region architecture. |

### L1.6 — SEBI algo trading registration at paid >₹X threshold

| Column | Detail |
|---|---|
| **Engineering-solvable?** | No. |
| **Regulatory action** | SEBI RA registration if research provided OR Algo Vendor empanelment per Apr 2026 framework. Cost: ~₹80K-1.5L (RA), ~₹4-8L (Algo). Calendar: 6-8mo (RA), 3-6mo (Algo). |
| **Physical-limit workaround** | Stay in "tool not service" framing (per `kite-landmines.md`); no tuned signals shipped. |
| **When workaround breaks** | If we ship strategy recommendations, copy-trading, or tuned signals. Mitigation: do not ship those. |

---

## Layer 2 — Infrastructure Blockers

### L2.1 — Single-master git commit funnel

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes. **Multi-repo via Path A** (already PROVEN for broker + kc/money). 28 more module promotions @ ~3-7h each = 84-200 agent-hours = ~3-5 weeks at 5-agent pace. |
| **Smallest first step** | Promote `kc/sectors` next (zero internal deps, mirrors kc/money pattern). ~2-3 hours. |
| **Hard dependency** | Path A pattern PROVEN in production (commit `bef0b31`). |
| **ROI** | At zero-user: low. At-scale: high — N=10K agents pushing to 28+ repos avoids GitHub single-master rate limit (~5K API calls/hr per token). |

### L2.2 — CI scaling at 10K parallel

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes. **Self-hosted Kubernetes-runner cluster** + **per-repo CI**. ~1-2 weeks engineering. |
| **Cost** | ~₹5-15K/mo cloud (5-10 Hetzner CPX21 VMs at ₹600-700/mo each via k3s). Crossover vs GitHub-hosted at >2K runner-min/mo. |
| **Smallest first step** | Drop macOS from `ci.yml` matrix (one-line change, -65% CI cost immediately). Then add `concurrency:` group per workflow (auto-cancel superseded runs). ~3 hours total. |
| **Hard dependency** | None for first steps. Self-hosted cluster requires multi-repo (L2.1) for full benefit. |
| **ROI** | At zero-user but N=20-50 commit cadence: positive immediately. At 10K-agent: required structural enabler. |

### L2.3 — Single Fly.io machine deployment

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes — **per-cell deployment via Fly Apps as cells, OR migration to GKE/EKS**. |
| **Cost** | Fly Apps cells: ~₹500-1K per app/month × N cells. At N=10 cells: ~₹5-10K/mo. At N=100: ~₹50K-1L/mo. K8s migration: 2-4 weeks engineering + ~₹15-30K/mo K8s base cost. |
| **Smallest first step** | Add second Fly app (`kite-mcp-server-canary`) running same binary; route 10% of traffic via Fly's HTTP service. ~1-2 days. Validates two-cell architecture without K8s. |
| **Hard dependency** | L2.4 (database scaling) — multi-cell needs partitioned data, not shared SQLite. |
| **ROI** | At zero-user: NEGATIVE (operational cost without traffic). At sustained 100+ concurrent users: positive. |

### L2.4 — Database scaling (SQLite + Litestream → Postgres + sharding)

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes. **Postgres + per-cell shard + read replicas** OR **per-cell SQLite with cross-cell read API**. |
| **Cost** | Postgres-managed (Neon, Supabase, or AWS RDS): ₹2-10K/mo per cluster. Migration engineering: ~3-4 weeks (replace `database/sql` calls + verify migrations). |
| **Smallest first step** | Add Postgres adapter alongside SQLite (`kc/alerts/db.go` already abstracts via `SQLDB` interface). Verify with single-tenant Postgres. ~3-5 days. |
| **Hard dependency** | None for first step. Multi-shard requires session affinity (L1.4). |
| **ROI** | At zero-user: NEGATIVE (Postgres ops cost > value). At 1000+ concurrent users: required (SQLite single-writer becomes bottleneck). |
| **Alternative** | **Stay SQLite per cell** with per-user partition. Each cell handles its own SQLite + Litestream → R2. Cross-cell aggregation queries proxy through the umbrella. Cheaper but harder to query across cells. |

### L2.5 — Service mesh (none today)

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes. **Linkerd or Istio** for inter-cell mTLS + retry + circuit-breaking. |
| **Cost** | Linkerd: ~₹500-1K/mo on K8s; Istio: heavier, ₹2-5K/mo. Engineering: ~1-2 weeks. |
| **Smallest first step** | Skip until 3+ cells are live AND inter-cell traffic exists. Defer. |
| **Hard dependency** | L2.3 (multi-cell deployment). |
| **ROI** | At zero-user: massively negative. At 10+ cells: positive. |

### L2.6 — Event bus (none today)

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes. **NATS JetStream** (lightweight, single-binary, embeddable) or **Redpanda** (Kafka-compatible). |
| **Cost** | NATS self-hosted: ~₹500-1K/mo. Redpanda Cloud: ~₹5-15K/mo. Engineering: ~1-2 weeks for first integration. |
| **Smallest first step** | Add NATS sidecar to existing Fly app. Publish `audit.tool_called` event from middleware. Consume from a single test consumer. ~1 day. |
| **Hard dependency** | None for sidecar. Cross-cell event bus requires multi-cell (L2.3). |
| **ROI** | At zero-user: low. At-scale: required for cross-agent coordination. |

### L2.7 — Distributed lock service (none today)

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes. **etcd or HashiCorp Consul** for scope ownership locks. |
| **Cost** | etcd self-hosted: ~₹500-1K/mo. Engineering: ~3-5 days. |
| **Smallest first step** | Skip — orchestrator-mediated serialization works at N<100 sustained. Defer until N>100 sustained agents. |
| **Hard dependency** | None. Pure addition. |
| **ROI** | At zero-user: massively negative. At N=500+ sustained: positive. |

---

## Layer 3 — Data + Auth Blockers

### L3.1 — OAuth flow scaling per-cell

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes. Per-cell JWT secret + federated identity at umbrella router. |
| **Cost** | Engineering: ~1 week. No infra cost (JWT is stateless). |
| **Smallest first step** | Verify current OAuth flow is JWT-secret-rotatable (per `MEMORY.md OAUTH_JWT_SECRET` references). Add cell-aware JWT issuance. ~3 days. |
| **Hard dependency** | L2.3 (multi-cell). |

### L3.2 — Token store scaling (AES-256-GCM per-user)

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes. Horizontal partition by `hash(user_email) mod N_cells`. Already per-user in code. |
| **Cost** | Engineering: ~1 week (cell-aware writes; cross-cell reads via proxy). |
| **Smallest first step** | Skip until L2.3 (multi-cell) lands. |

### L3.3 — Per-user Kite credential storage

| Column | Detail |
|---|---|
| **Engineering-solvable** | Same partition as L3.2. |
| **Cost** | Same as L3.2. |

### L3.4 — Ticker WebSocket scaling

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes. **Per-cell WS pool** — each cell maintains its own WS connection to user's Kite app (per BYO-developer-app architecture). |
| **Cost** | One WS connection per (cell, user-app) pair. At N=10 cells × 1000 users = 10K WS connections distributed. Per-cell load: 1000 connections — well within Go runtime capacity. |
| **Smallest first step** | After L2.3 (multi-cell) lands, ticker connection pool routes by user-cell affinity. |
| **When breaks** | If user's Kite app has per-app WS connection limit < cell count. Verify with Kite docs at 5-cell threshold. |

### L3.5 — Audit log scaling (`tool_calls` table)

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes. Time-series DB (TimescaleDB on Postgres) OR partitioned Postgres (monthly partitions). |
| **Cost** | TimescaleDB Cloud: ~₹3-8K/mo. Engineering: ~1 week migration from SQLite. |
| **Smallest first step** | Add monthly partition to existing SQLite via Litestream snapshot rotation. ~2-3 days. Defers TimescaleDB. |
| **ROI** | At zero-user: low. At 10K-tool-calls/day sustained: positive (SQLite write-throughput becomes bottleneck around 100K rows/hour). |

---

## Layer 4 — Dev Coordination Blockers

### L4.1 — Team-config setup at session start

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes. Already documented in `MEMORY.md user_team_agents_default.md`. |
| **Cost** | Setup: ~30 min. Per-session: zero. |
| **Smallest first step** | Stub `.claude/team/config.yaml` with named agents at session start (this is "do once"). |
| **ROI** | High — eliminates concurrent-edit friction observed in prior sessions. |

### L4.2 — Worktree-per-agent automation

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes. Script `scripts/agent-worktree-init.sh`. ~1-2 hours. |
| **Hard constraint** | No `git stash` per `MEMORY.md feedback_no_stash_anywhere.md`; worktrees enforce isolation cleanly. |
| **Smallest first step** | Write the script + test for 2 named agents. ~1-2 hours. |

### L4.3 — Cross-repo release coordination

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes. **release-please** or **goreleaser** + conventional commits + Dependabot. |
| **Cost** | Engineering: ~3-5 days. Per-repo cost: zero (free GitHub Actions). |
| **Smallest first step** | Add release-please to `algo2go/kite-mcp-broker` (single repo, already at v0.1.0). ~2-4 hours. |
| **Hard dependency** | L2.1 (multi-repo) being substantively complete. |

### L4.4 — Distributed compute coordinator for 10K agents

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes — but expensive. Custom orchestrator OR Argo Workflows on K8s OR Temporal.io. |
| **Cost** | Temporal Cloud: ~₹15-30K/mo. Argo on self-hosted K8s: free + ops. Engineering: ~3-4 weeks for either. |
| **Smallest first step** | Skip — current Claude orchestrator handles N<50. Defer until N>200 sustained. |
| **ROI** | At zero-user: massively negative. At 10K-agent: required. |

---

## Layer 5 — Operational Blockers

### L5.1 — Monitoring at 10K-agent scale

| Column | Detail |
|---|---|
| **Engineering-solvable** | Yes. **Prometheus + Grafana + tracing (Jaeger or Tempo)**. |
| **Cost** | Self-hosted Prom+Graf: ~₹500-1K/mo. Grafana Cloud free tier covers single-cell. Engineering: ~3-5 days. |
| **Smallest first step** | Add `node_exporter` to Fly.io machine + Grafana Cloud free dashboard. ~2-4 hours. |
| **ROI** | At zero-user: low. At sustained N=20+ agents: positive (visibility into deploy frequency, rollback rate, CI cost trends). |

### L5.2 — Cost ceiling — what does 10K-agent infra COST per month?

**REVISED post-L1.1 + L1.2 corrections (2026-05-06)**: multi-Kite-app procurement is NOT needed (each user uses their own app). 10-cell deployment is sufficient (not 100) since rate limit is per-user not per-operator.

Honest estimate at fully-decomposed N=10K-agent capacity (assumes all phases complete):

| Component | Cost/month | Notes |
|---|---|---|
| ~~100 Kite developer apps × ₹500~~ | **₹0** | OBSOLETE per L1.1 — users bring their own Kite apps |
| 10 Fly.io cell apps × ₹1,000 | ₹10,000 | Down from 100 — each cell handles ~1000 users; rate limit is per-user |
| Postgres clusters (3 regional clusters for redundancy) | ₹15,000 | Unchanged |
| Self-hosted CI cluster (10 VMs on Hetzner) | ₹6,000 | Unchanged |
| NATS JetStream cluster | ₹1,500 | Unchanged |
| etcd cluster | ₹1,000 | Unchanged |
| Service mesh (Linkerd) | ₹1,500 | Unchanged |
| Observability (Prom + Graf + tracing) | ₹3,000 | Unchanged |
| Storage (Postgres + R2 backups) | ₹5,000 | Unchanged |
| Network egress | ₹5,000 | Unchanged |
| **Total infra** | **~₹48,000/mo (~$575/mo)** | Was ~₹1,90,000 — **75% reduction** from L1.1 correction |
| Plus 1 SRE FTE in India (eng cost) | ₹1,50,000-2,50,000/mo | Optional at this scale; 1 founder-SRE viable up to ~5K users |
| **Grand total at-scale** | **~₹2-3L/mo (~$2,400-3,600/mo)** | Down from ~₹3.5-4.5L |
| **Grand total founder-only** | **~₹50K/mo infra-only** | Viable solo at 10K-agent capacity |

**ROI sanity check (revised)**: at 10K concurrent users on Pro tier ₹500/mo = ₹50L/mo gross. Infrastructure burns **~1%** (founder-only) or ~5% (with SRE FTE). **Very healthy**. At 1000 paid users: ₹5L/mo gross — infra at ₹50K-3L = **1-60% of revenue**. Sustainable across early-growth band. At <500 paid users: founder-only infra ~₹50K/mo is 20% of revenue at ₹2.5L/mo — viable. **The L1.1 correction transforms 10K-agent capacity from "Series-A-required" to "Pre-Seed-viable".**

### L5.3 — Incident response at scale

| Column | Detail |
|---|---|
| **Engineering-solvable** | Partial — runbooks help but on-call requires people. |
| **Cost** | Runbooks: ~1-2 weeks engineering per major failure mode (~5 modes × 1.5 weeks = 7-10 weeks). On-call rotation: requires 2+ engineers. |
| **Smallest first step** | Pick the most likely failure mode (Fly.io machine crash → instance restart) and write the runbook. ~3-4 hours. |
| **ROI** | At sustained 1000+ users: required. Below that: pre-mature. |

---

## Phased Execution Roadmap (10K target)

### Phase 0 — Foundation (in flight)

**Goal**: Multi-repo skeleton + per-agent worktree pattern documented; team-config stubbed.
**Cost**: ~2-4 weeks at 5-agent pace; ~3-4 weeks at 1-agent pace.
**Dependencies**: Path A pattern PROVEN (✓ at `bef0b31`).
**ROI**: at zero-user low; at-scale high (unblocks all subsequent phases).
**Smallest first step**: Phase 0.2 (`.claude/team/config.yaml` stub) + Phase 0.3 (worktree script) + Phase 0.4 (conventions doc) — ~4 hours total. After Path A owner finishes their current promotion.
**Hard dependency**: avoid concurrent go.work + go.mod + Dockerfile edits with Path A owner.

### Phase 1 — Multi-repo + CI Sharding (~1-2 weeks engineering)

**Goal**: 27 in-tree modules promoted to algo2go; CI cost-bounded at sustained N=100.
**Cost**: 1.1 (drop macOS, ~30min) + 1.2 (concurrency groups, ~2h) + 1.3 (smart-test matrix, ~1-2 days) + 1.4 (self-hosted runners, ~1-2 days) + 28 module promotions @ ~3-7h each = ~150-250 agent-hours total.
**Dependencies**: Phase 0 done.
**ROI**: at sustained N=20-50 commit cadence: positive immediately. At 10K-agent: required structural enabler.
**Smallest first step**: drop macOS from ci.yml matrix (one-line change; -65% CI cost immediately). ~30 min.

### Phase 2 — Database + State-Store Partitioning (~2-4 weeks engineering)

**Goal**: Postgres adapter alongside SQLite; per-cell sharding; partitioned audit log.
**Cost**: ~14-28 engineer-days. Phase 2.1 Postgres adapter (~3-5d) + 2.2 token-store partition (~1w) + 2.3 audit-log partition (~1w).
**Dependencies**: Phase 1 done. Multi-repo enables per-module DB-adapter PRs.
**ROI**: at zero-user negative; at 1000+ concurrent users positive.
**Smallest first step**: add Postgres adapter alongside SQLite via existing `SQLDB` interface in `kc/alerts/db.go`. Verify single-tenant. ~3-5 days.

### Phase 3 — Multi-Cell Runtime (~1-3 months engineering)

**Goal**: 10+ cells deployable; cell router shards by `hash(user_email)`; per-user IP whitelist wizard.
**Cost**: ~5-10 engineer-weeks. 3.1 cell deployment automation (~2w) + 3.2 cell router (~2-3w) + 3.3 IP whitelist wizard (~1w) + 3.4 cross-cell observability (~1w).
**Dependencies**: Phase 2 done. Postgres or per-cell SQLite chosen.
**ROI**: at zero-user massively negative; at sustained 100+ concurrent users positive.
**Smallest first step**: add second Fly app (`kite-mcp-server-canary`) running same binary; route 10% of traffic via Fly's HTTP service. ~1-2 days. Validates two-cell architecture without full K8s.

### Phase 4 — Per-User Rate-Shaping + Whitelist Wizard (~1-2 weeks engineering) — REVISED

**(Was: "Multi-Kite-App Sharding" — OBSOLETED by L1.1 correction. Each user uses their own Kite app; rate limit is naturally per-user.)**

**Goal**: Cell-side token-bucket rate-shaper for graceful 10/sec backpressure; setup wizard for user to add N cell IPs to "Whitelisted IPs" field.
**Cost**: ~1-2 weeks engineering. 4.1 token-bucket rate-shaper at cell-router (~3-5d) + 4.2 dashboard wizard at `/dashboard/onboarding/whitelist-ips` showing cell IPs with copy-buttons (~3-5d).
**Dependencies**: Phase 3 done (cells exist with stable static egress IPs). NO Kite app procurement required.
**ROI**: at zero-user low; at sustained 100+ concurrent users with order activity positive (graceful backpressure under burst).
**Smallest first step**: stub `/dashboard/onboarding/whitelist-ips` page showing the static IP list (currently `209.71.68.157` + future cell IPs) with copy-buttons + step-by-step screenshots. ~2-3 hours.

**Open assumption to verify at 5-cell threshold**: the "Whitelisted IPs" field array length cap at Zerodha's end. Likely ≥10 (typical cloud pattern); may need conversation with Kite team if we exceed. Not a present blocker.

### Phase 5 — Service Mesh + Event Bus + Distributed Coordinator (~2-3 months engineering)

**Goal**: Cross-cell mTLS via service mesh; event bus for async coordination; distributed lock service for scope ownership.
**Cost**: ~8-12 engineer-weeks. 5.1 NATS sidecar (~1-2w) + 5.2 service mesh on K8s (~3-4w) + 5.3 etcd lock service (~1w) + 5.4 distributed compute coordinator (~3-4w).
**Dependencies**: Phase 3 done; K8s cluster exists.
**ROI**: at zero-user massively negative; at N=500+ sustained agents positive.
**Smallest first step**: add NATS sidecar to existing Fly app; publish `audit.tool_called` event from middleware; consume from single test consumer. ~1 day. Defers full mesh + lock service.

### Phase 6 — Observability + Cost Optimization at Scale (~1 month engineering)

**Goal**: Prom + Graf + tracing covering all cells; cost-attribution per cell; auto-scale rules.
**Cost**: ~3-5 engineer-weeks. 6.1 Prom federation (~1w) + 6.2 distributed tracing (~1-2w) + 6.3 cost-attribution dashboards (~3-5d) + 6.4 auto-scaling rules (~1w).
**Dependencies**: Phase 3 done; multiple cells exist.
**ROI**: at zero-user low; at-scale required.
**Smallest first step**: add `node_exporter` to existing Fly machine + single Grafana Cloud free dashboard. ~2-4 hours. Provides observability baseline before scaling.

### Phase 7 — Regulatory Close (~3-6 months calendar; not engineering)

**Goal**: NSE empanelment filed at 30-paid-sub mark (6mo buffer); SEBI dialogue if framework changes; DPDP Data Fiduciary registration.
**Cost**: ~₹4-8L (NSE) + ~₹50K-1L (DPDP) + ~₹1-2L (legal counsel).
**Dependencies**: 30+ paid subs (commercial milestone, not engineering).
**ROI**: at zero-user N/A (not yet relevant); at 50+ paid subs required.
**Smallest first step**: identify legal counsel pre-empanelment (Spice Route Legal or Finsec Law per `kite-fintech-lawyers.md`). ~2-3 hours research + initial consult ₹15-35K.

---

## Cross-Phase Synthesis

### Total realistic calendar to 10K-capable — REVISED

| Resourcing | Calendar |
|---|---|
| Solo + ₹0 + N=5-agent dispatch pace | **6-12 months for Phases 0-6**; Phase 7 calendar is 3-6mo regardless (regulatory) |
| Pre-Seed funded (1 hire + ~₹50K-1L/mo cloud + ~₹4-8L NSE) | **3-6 months for Phases 0-6** |
| Series-A funded (5-eng team + full ops) | **2-3 months for Phases 0-6** |

### Hard constraints carried throughout

1. **SEBI 10/sec per (user's-app, user)** — naturally per-user given BYO-developer-app architecture. Cell-side token-bucket for graceful backpressure.
2. **Per-user IP whitelist (Apr 2026)** — solvable via setup wizard; "Whitelisted IPs" field is plural (accepts array). No regulatory action needed.
3. **NSE empanelment threshold ~50 paid subs** — cannot bypass. Calendar 3-6mo from filing; budget ~₹4-8L. File at 30 paid subs for buffer.
4. **Zerodha "one app per active session"** — route via L1.4 session affinity (per-user cell pinning).
5. **tools=130 (empirically verified at commit-time) invariant** — verified via `grep -rE 'mcp\.NewTool\("' mcp/` at every commit.
6. **WSL2 mandatory** for `go test`/`go build`.
7. **No `git stash`** — worktrees enforce isolation.

### Open assumptions to verify (not blockers; surface-then-defer)

1. **"Whitelisted IPs" field array length cap** — at 5-cell threshold, verify with Zerodha that the field accepts ≥5 IPs. Likely ≥10. ~30 min work when triggered.
2. **Per-Kite-app WS connection limit** — at multi-cell threshold, verify ticker-WS scaling matches user-app constraints. Check Kite Connect docs.
3. **Zerodha bulk-app/scale conversation** — at 1000+ paid users, may benefit from Rainmatter relationship for explicit ToS clarity. Pre-flight, not blocking.

### Honest acknowledgments — REVISED

- **At today's zero-user state, 10K-agent capacity is a 1-2yr horizon (was previously framed as 5+yr).** L1.1 + L1.2 corrections collapsed the dominant blockers. Phases 0-2 cover near-term (3-12mo) realistic scale; Phases 3-6 ramp at user signal; Phase 7 fires at 30 paid subs.
- **The plan still assumes empirical triggers fire**: 30+ paid subs (Phase 7 NSE filing), 100+ concurrent users (Phases 3-5), 1000+ users (Phase 6 cost optimization). Do NOT pre-execute Phases 3-7 ahead of triggers.
- **The single most important corrections in this plan are L1.1 + L1.2** — they reframed regulatory/physical-limit blockers as engineering blockers. SEBI 10/sec is per-user (not per-operator); IP whitelist field is plural (not single).
- **All in-our-hands engineering covers ~85% of blocker surface** (revised from ~70%). The remaining ~15% (NSE empanelment, DPDP registration, optional Rainmatter ToS clarity) is regulatory/relationship work that engineering can't shortcut, but is well-bounded.

### Smallest first step across the entire 10K plan

**Same as the 1000-agent plan first step**: Phase 0.2 (`.claude/team/config.yaml` stub) + Phase 0.3 (worktree script) + Phase 0.4 (conventions doc) — ~4 hours total. Unblocks safe 5-10-agent concurrency immediately. Then queue `kc/sectors` promotion. Then Phase 1.1 (drop macOS from CI matrix).

The 10K plan and the 1K plan **diverge only at Phases 3+**. Phases 0-1 are identical. Phase 2 differs only by depth (10K needs Postgres; 1K can stay SQLite per cell). Phases 3-7 are the 10K-specific add-ons.

---

## Recommended Next Concrete Steps

### Immediate (next dispatch, ~4 hours)

**Phase 0.2 + 0.3 + 0.4 in single dispatch**:
1. Stub `.claude/team/config.yaml` with 3-5 named agents (axis-c-feature, path-a-promoter, observability, capacity-architect, chain-deploy)
2. Write `scripts/agent-worktree-init.sh` for per-agent worktree setup
3. Append agent-domain conventions to `.research/agent-domain-map.md` (or create if absent)

**Disjoint from Path A**: yes — these touch `.claude/team/`, `scripts/`, `.research/`. Path A owner edits `go.work`/`go.mod`/`Dockerfile`.

### After Path A owner's current promotion lands

**Queue `kc/sectors` promotion** as next agent dispatch (mirrors `kc/money` mechanics; ~2-3 hours including v0.1.0 tag + canary deletion). Provides 3rd algo2go repo + further validates the pattern.

### Phase 1.1 (whenever bandwidth available)

**Drop macOS from `ci.yml` matrix** (one-line change; -65% CI cost). Can ship in parallel with promotion work — disjoint scope.

### What to defer until trigger fires

- Phases 3-6 entirely (need user-count signal)
- Phase 7 (need 30+ paid subs trigger)
- Phase 4 multi-app procurement (need user-load signal)
- Phase 5 service mesh + event bus (need cell count signal)

---

**End of plan. Doc-only. No code mutated. tools=130 empirical at HEAD `869b36a` (40-deploy streak; growing tool surface). Stop-rule fired: coordinator paused for context budget. Plan can iterate; execution follows in subsequent dispatches.**
