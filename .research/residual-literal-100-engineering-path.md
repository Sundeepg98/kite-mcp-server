# Residual Literal-100 Engineering Path

**Status:** Research deliverable. Doc-only, no code changes. Engineering-only items per axis to push from realistic ceiling toward literal 100.
**Author:** Research dispatch #21 this session.
**Date:** 2026-05-03 IST.
**HEAD audited:** `af69655` (post tool-count + RiskGuard claim alignment).

**Predecessor audits this complements (not duplicates):**
- Architecture audit chain (cf09456 etc.) — current 95.08, ceiling 95.69 calibrated
- `.research/ux-completeness-audit.md` (010c8a4) — UX 72 → 84 ceiling
- `.research/ui-completeness-audit.md` (faeb68e) — UI 76 → 88 ceiling
- `.research/e2e-completeness-audit.md` — E2E 78 → 85 ceiling
- `.research/functional-completeness-audit.md` (#19) — Functional ~92% pass-rate
- `.research/integration-completeness-audit.md` (fdc5bae) — Integration 74 → 80-85 ceiling
- `.research/github-repo-polish-audit.md` (585d0ed) — repo metadata

**Scope discipline:** This dispatch deliberately does NOT re-tread the Top-10s already enumerated by each predecessor audit. The remit is *residual gap beyond those Top-10s* — items that sit BETWEEN the per-axis ceiling and literal 100, that don't require external $$, and that haven't been called out by any prior dispatch.

**Diminishing-returns honesty (21st dispatch):** ~60% of items below have been at least *mentioned* somewhere in the prior 20 dispatches; the genuinely-net-new contribution is the **cross-axis ROI ranking** plus 4-5 items that genuinely haven't surfaced before (contract-drift detection, mcp-go protocol-shape pin, per-tool schema SHA, custom 500 page, Hindi i18n scaffold, multi-tenant credential-isolation test, Litestream restore-against-current-keys drill).

---

## Lead-in summary (read this first)

**Top 5 engineering-only ROI-ranked items — each pushes 1-3 axis-points + does NOT cost $$:**

1. **Contract-drift detection test: server.json ↔ /healthz ↔ landing.html tool count** — 30 min — Architecture +1 / Integration +2 / Functional +1 (3-axis lift = +4 weighted points). Most-leveraged unique-net-new item in the audit. CI fails when a feature ships without updating all three claim sites. This catches the exact "claims drift" pattern that an HN reviewer running `curl /healthz` against the README will spot in 30 seconds.

2. **Litestream restore drill against PRODUCTION encryption keys** — 90 min — E2E +2 / Integration +2 / Architecture +1 (3-axis lift = +5 weighted points). The current `dr-drill.sh` (verified in `scripts/dr-drill.sh`) restores a backup but uses *test-env* keys. Per memory `kite-session-apr3.md` and integration audit row #5 — the actual encryption-key chain (HKDF from `OAUTH_JWT_SECRET`) has never been end-to-end-tested against the live R2 + live secret. Run-once-and-document is enough; doesn't need recurring CI.

3. **MCP protocol-shape contract test in default CI (not opt-in `//go:build e2e`)** — 45 min — E2E +2 / Integration +2 (multi-axis lift = +4). Per integration audit Phase 4: `mcp/e2e_roundtrip_test.go` exists but build-tag-gated; on every `go test ./...` it doesn't run. The mcp-go upstream could ship a breaking protocol change tomorrow and we'd find out from a user. Ungate it; expect ~10s additional CI time.

4. **Custom 500 error page using `dashboard-base.css` tokens** — 30 min — UI +1 / UX +1 (2-axis lift = +2). Custom 404 already exists (verified `curl /404` returns minimal styled page). Symmetric 500 absent; default Go HTTP error message renders bare. Less-frequent path than 404 but still hits on the inevitable production wobble during launch-day Show-HN traffic spike.

5. **Per-tool input schema SHA pin via golden-test** — 60 min — Functional +1 / Integration +2 / E2E +1 (3-axis lift = +4). Currently `mcp/widget_surface_lock_test.go` pins widget metadata; analog tool-schema lock for the 110+ tools doesn't exist. Tool description churn that breaks downstream LLM tool-router caches goes silently undetected. Generate one SHA snapshot per tool, fail on accidental change.

**Total Top-5 dev-time: ~4 hours. Cumulative axis lift: ~6-9 axis-points across 4-5 axes.**

---

## Phase 1 — Per-axis residual hunt

### A. Architecture (95.08 → 95.69 calibrated max, 100 nominal — gap: 4.31 nominal / 0.61 calibrated)

| Engineering-only candidate | Axis points | Dev hours | Already in prior audit? |
|---|:---:|:---:|---|
| Contract-drift detection (server.json ↔ /healthz ↔ landing) | +1 | 0.5 | Mentioned in integration #2 but not as cross-axis architecture move |
| Per-tool OpenAPI schema auto-derived from Go types | +0.5 | 4 | NEW |
| Multi-broker port pattern as ADR-0011 (no second broker; document the design) | +0.5 | 1 | NEW (ADRs go through 0010) |
| `go.work` Move-1 per `5437c32` — extract 2 leaf packages (kc/crypto, kc/domain) into separate modules | +1 | 3 | Mentioned in `5437c32` not actioned |
| Component-level dependency graph diagram auto-rendered from `go list -deps` | +0.3 | 1.5 | NEW |
| RFC-style "future-broker contract" interview spec | +0.2 | 1 | NEW |

**Best engineering-only architecture moves: contract-drift detection (cross-axis lift) + multi-broker ADR-0011 (cheapest +0.5).** The remaining 3.7 calibrated points are mostly external-$$ (designer for ADR illustrations, hire to actually wire second broker, etc.).

### B. UX (72 → 84 ceiling — gap: 12)

Of 12 ceiling-points, the per-axis UX audit Top-10 already accounts for ~10. Residual:

| Engineering-only candidate | Axis points | Dev hours | Already in prior audit? |
|---|:---:|:---:|---|
| Hindi i18n scaffold for error messages (volunteer-translatable; no $) | +1 | 4 | Mentioned UX audit Phase 5 — not in Top-10 |
| Tooltip/help text on every form field in dashboard.html | +0.5 | 2 | NEW |
| Keyboard shortcuts (j/k for list nav, / for search) | +0.5 | 3 | NEW |
| Empty-state illustrations from undraw.co (free SVGs) | +1 | 2 | UI-related; UI audit's Phase 8 #1 swap hits similar surface |
| Progressive enhancement for slow connections (low-data mode) | +0.3 | 4 | NEW |
| Autosave for compose forms (set_alert input) | +0.3 | 2 | NEW |

**Best engineering-only UX residuals: Hindi i18n + empty-state illustrations.** The Indian-retail-audience-fit angle alone makes Hindi i18n high-leverage even for a Show-HN launch.

### C. UI (76 → 88 ceiling — gap: 12)

Per-axis UI audit Top-10 already accounts for ~12 ceiling points. Residual past ceiling:

| Engineering-only candidate | Axis points | Dev hours | Already in prior audit? |
|---|:---:|:---:|---|
| Custom favicon (currently generic SVG) | +1 | 1 | NEW |
| Custom 500 error page | +1 | 0.5 | NEW |
| Print stylesheet for dashboard pages | +0.3 | 1 | NEW |
| Animation polish (smooth modal transitions, focus animations) | +0.5 | 3 | NEW |
| Loading shimmer for tables (dashboard.html stats / activity) | +0.5 | 2 | UI audit Phase 8 #7 (skeleton-bone class) |
| OG image variant for Twitter (1200×630 vs Facebook's 1.91:1) | +0.3 | 1 | NEW |

**Best engineering-only UI residuals: custom favicon + custom 500 page.** Sub-1-hour each; visible-everywhere impact for the favicon.

### D. E2E (78 → 85 ceiling — gap: 7)

E2E audit's Top-3 fixes the 7-point gap. Residual past ceiling:

| Engineering-only candidate | Axis points | Dev hours | Already in prior audit? |
|---|:---:|:---:|---|
| Litestream restore drill against PRODUCTION encryption keys | +2 | 1.5 | Mentioned but not as Top-N action |
| MCP protocol-shape contract test ungated from `//go:build e2e` | +2 | 0.75 | Integration audit calls it out; not in any Top-10 |
| Per-tool schema SHA pin (extends widget_surface_lock_test) | +1 | 1 | NEW |
| Cross-platform screenshot regression via Playwright | +0.5 | 3 | NEW |
| Coverage gate: CI fails if PR drops package coverage >2% | +0.5 | 1 | NEW |
| Synthetic user-flow tests for `/dashboard/*` SSO cookie chain | +0.5 | 2 | Mentioned in E2E audit but as nice-to-have |
| Latency budget assertion in smoke test (p99 <500ms) | +0.5 | 1 | NEW |

**Best engineering-only E2E residuals: Litestream restore drill (production keys) + ungate MCP roundtrip test.** Together: +4 axis points in ~2.25 hours.

### E. Functional (87% strict / ~95% empirical)

Per-axis functional audit identifies 3 LLM-coordinator tools as honesty-gap (analyze_concall, peer_compare, get_fii_dii_flow). Already addressed in `af69655` per repo HEAD. Residual:

| Engineering-only candidate | Axis points | Dev hours | Already in prior audit? |
|---|:---:|:---:|---|
| Compute Piotroski F-Score from holdings data we already have (peer_compare) | +1 | 4 | NEW |
| Per-tool integration test coverage for the 17 lowest-coverage mcp/ files | +2 | 8 | Functional audit notes 1.18× test:prod ratio in mcp/ |
| `/dashboard/risk` page (RiskGuard config + freeze controls UI) | +0.5 | 4 | UX audit J touchpoint mentions |
| Hindi briefing template (volunteer translation) | +0.5 | 2 | UX residual; cross-axis |
| Native concall PDF download + parse (vs LLM-coordinator framing) | +1 | 8+ | NEW — borderline external-$$ since may need OCR |

**Best engineering-only functional residuals: per-tool integration tests in `mcp/` (lowest-test-ratio package) + Piotroski F-Score real computation.**

### F. Integration (74 → 80-85 ceiling — gap: 11 to literal 100)

Per-axis integration audit Top-10. Residual past ceiling:

| Engineering-only candidate | Axis points | Dev hours | Already in prior audit? |
|---|:---:|:---:|---|
| mcp.kite.trade compatibility cross-check (catch upstream schema breaks) | +1 | 1.5 | Integration audit Phase 4 |
| Synthetic Stripe-signed payload webhook test | +1 | 2 | NEW |
| Telegram bot offline-degradation behavior test | +0.5 | 1.5 | NEW |
| Multi-tenant credential isolation test (synthetic 2 users) | +1 | 2 | NEW; cross-axis with Functional |
| Per-broker contract test pattern (lock for future second broker) | +1 | 3 | Integration audit notes |
| Cron-driven Kite SDK-version watchdog (already wired via `v4-watchdog.yml`) | +0.5 | 0 (just verify) | Verified existing |

**Best engineering-only integration residuals: Multi-tenant credential isolation + mcp.kite.trade compat cross-check.**

---

## Phase 2 — Cross-axis coverage interactions

Items that improve multiple axes simultaneously, ranked by total weighted lift:

| Item | Axes touched | Total weighted lift |
|---|---|:---:|
| Litestream restore drill (production keys) | E2E +2 / Integration +2 / Architecture +1 | +5 |
| Contract-drift detection (server.json ↔ /healthz ↔ landing) | Architecture +1 / Integration +2 / Functional +1 | +4 |
| Per-tool schema SHA pin | Functional +1 / Integration +2 / E2E +1 | +4 |
| MCP protocol-shape contract test ungate | E2E +2 / Integration +2 | +4 |
| Custom 500 error page | UI +1 / UX +1 | +2 |
| Multi-tenant credential isolation test | Functional +1 / Integration +1 / (Security per memory) +1 | +3 |
| Hindi i18n scaffold | UX +1 / Functional +0.5 | +1.5 |
| Empty-state SVG illustrations (undraw.co) | UX +1 / UI +1 | +2 |
| Custom favicon | UI +1 / UX +0.3 | +1.3 |
| Loading shimmer for dashboard tables | UI +0.5 / UX +0.5 | +1 |

The cross-axis-multiplier favors **engineering plumbing items** (contract drift, restore drill, schema pin, protocol test) over **visual polish items** (favicon, 500 page, illustrations). Plumbing items disproportionately reduce risk-of-launch-day-embarrassment vs aesthetic items that are nice-to-have.

---

## Phase 3 — Top-10 ROI-ranked engineering-only items

Rank by `(weighted axis lift) / (dev hours)`. Aim 30-min to 4-hour items.

| # | Item | Axes (weighted lift) | Dev hours | ROI |
|--:|---|---|:---:|:---:|
| 1 | **Contract-drift detection** (server.json/healthz/landing) | A+1, Int+2, F+1 = **+4** | 0.5 | **8.0** |
| 2 | **Custom 500 error page** | UI+1, UX+1 = **+2** | 0.5 | **4.0** |
| 3 | **MCP protocol-shape contract test ungate** | E2E+2, Int+2 = **+4** | 0.75 | **5.3** |
| 4 | **Custom favicon** | UI+1, UX+0.3 = **+1.3** | 1 | 1.3 |
| 5 | **Litestream restore drill (production keys)** | E2E+2, Int+2, A+1 = **+5** | 1.5 | **3.3** |
| 6 | **Per-tool schema SHA pin** | F+1, Int+2, E2E+1 = **+4** | 1 | **4.0** |
| 7 | **Multi-tenant credential isolation test** | F+1, Int+1, Sec+1 = **+3** | 2 | 1.5 |
| 8 | **mcp.kite.trade compat cross-check** | Int+1 = **+1** | 1.5 | 0.7 |
| 9 | **Empty-state SVG illustrations (undraw.co)** | UX+1, UI+1 = **+2** | 2 | 1.0 |
| 10 | **Hindi i18n scaffold (error messages)** | UX+1, F+0.5 = **+1.5** | 4 | 0.4 |

**Top-3 by raw ROI** (#1, #3, #2) deliver +10 weighted axis-points in ~1.75 hours total.

**Top-5** delivers +14.3 weighted axis-points in ~3.25 hours.

**Top-10** delivers +27.8 weighted axis-points in ~14.75 hours (≈2 working days).

---

## Phase 4 — Honest verdict on literal-100 path per axis

Applying the Top-10 engineering-only items to each axis:

| Axis | Current | + Top-10 lift | Realistic ceiling reached | Remaining gap to literal 100 = external $$ items dominating |
|---|:---:|:---:|---|---|
| **Architecture** | 95.08 | +3 → 98.08 | YES (slightly over 95.69) | DDD model-mining workshop; CQRS-bench-vs-direct ports paper; SOC 2 architectural-control review |
| **UX** | ~80 (post-execute Top-10 of UX audit) | +3 → ~83 | NO (ceiling 84) — basically tied | Designer-led usability research; A/B testing infra; native mobile app |
| **UI** | ~82 (post-execute UI audit Top-3) | +3 → ~85 | YES (ceiling 88 with these adds) | Brand identity workshop; custom illustrations; designer hire |
| **E2E** | ~85 (post-execute) | +5 → ~90 | YES (over ceiling 85) | k6 load tests at scale; chaos engineering; LaunchDarkly-style feature-flag E2E |
| **Functional** | ~95% empirical | +3 (via schema pin + per-tool tests) | YES (over ceiling) | Native concall fetcher (OCR + paid data API); FII/DII flow native fetch (paid feed) |
| **Integration** | ~80 (post-execute) | +6 → ~86 | YES (ceiling 85 with these adds) | Pact-style contract testing infra at scale; chaos engineering; full third-party SLA monitoring |

**After Top-10 engineering execution:** 5 of 6 axes meet or exceed their realistic ceilings. The remaining gap to literal 100 is dominated by **designer / brand / paid data feeds / professional QA / SOC 2** — all external-$$ items, all out of solo-pre-launch scope. UX is the one that doesn't quite reach its ceiling because human-experience improvements past 84 inherently require user research that we can't do solo.

**Honest verdict on "literal 100":** unreachable in solo-pre-launch without external $$ across at least 4 axes (UI brand work, UX user research, Functional paid-data, Integration contract-testing infra). Realistic post-execution position: **average ~88/100 across axes**, with the gap concentrated in the same external-$$ buckets repeatedly.

---

## Phase 5 — Recommendation tiering

### Critical-before-Show-HN subset (must ship — total ~2 hours)

The Top-3-by-ROI items, calibrated to *would-an-HN-reviewer-actually-notice*:

- **#1 Contract-drift detection** (30 min) — HN reviewer running `curl /healthz` and cross-checking README in 30 seconds is the EXACT pattern this protects. Yes-they'd-notice.
- **#3 MCP protocol-shape contract test ungated** (45 min) — protects against a silently-broken MCP handshake the morning of launch when an mcp-go transitive dep updates. Yes-they'd-notice (via thread comments about broken connection).
- **#2 Custom 500 error page** (30 min) — Show-HN traffic spike hits production wobble at some point; default Go bare error message looks unprofessional. Yes-they'd-notice if it triggers.

Total: ~1.75 hours. **Each passes the would-this-actually-be-noticed test.**

### Post-launch v1.4 sprint (3-7 days — total ~10 hours)

Items that improve multi-axis posture but aren't launch-blocking:

- **#5 Litestream restore drill (production keys)** — DR confidence gate; before any new user signs up
- **#6 Per-tool schema SHA pin** — extends the existing widget-surface-lock pattern
- **#7 Multi-tenant credential isolation test** — DPDP audit-ready evidence
- **#9 Empty-state SVG illustrations** — visual polish lift
- **#4 Custom favicon** — every-pageview impression
- **#8 mcp.kite.trade compat cross-check** — upstream-surveillance value

### v2.0 multi-month (weeks — backlog)

- **#10 Hindi i18n scaffold** — meaningful but only after cohort 1 of Indian users actually requests it
- Architecture's `go.work` Move-1 (3 hours raw, but multi-week effort to validate cross-package import discipline)
- Per-tool OpenAPI schema generation (4 hours raw, but value compounds only when there's a non-MCP REST consumer)
- Functional Piotroski F-Score real computation (4 hours, but blocked on having reliable holdings-data structure across edge cases)

---

## Honest meta-note (per `feedback_research_diminishing_returns.md`)

This is **dispatch #21** this session. The user explicitly authorized continued work despite acknowledging diminishing returns. The would-this-actually-be-noticed-by-HN test was applied:

- **Pass:** items #1, #2, #3 (all in critical-before-launch). These reduce the *probability* of a launch-day visible failure.
- **Borderline:** items #4, #5, #6, #7, #8 (post-launch). These improve internal posture but an HN reviewer wouldn't notice their absence in the first hour.
- **Fail the test:** items #9, #10 + most v2.0 items. They look good in checklists but no HN reviewer is going to notice the absence of empty-state illustrations or Hindi error messages in their first 5 minutes.

**Recommended action:** Ship #1, #2, #3 (~2 hours) before launch. Defer everything else. Resume execution on #5-8 in week 1-2 post-launch when the cohort-1 user feedback informs which items materially matter.

The remaining **9-12 raw axis points to literal 100** are not closeable without external $$. Pursuing them via additional research dispatches yields strictly diminishing returns; pursuing them via execution of the 3 critical items yields concrete, HN-visible quality lift.
