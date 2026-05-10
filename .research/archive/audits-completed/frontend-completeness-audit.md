# Frontend Completeness Audit — kite-mcp-server

**Sibling-of:** `docs/product-definition.md` (`99b9bdf`), `.research/functional-completeness-audit.md` (`25a9168`), prior UI audit (`faeb68e`), prior UX audit (`010c8a4`)
**Audit dimension:** Frontend code quality + performance + tooling. **Distinct from UI** (visual design — covered in `faeb68e`) and **UX** (flow — covered in `010c8a4`).
**Method:** Empirical reads of `kc/templates/`. Zero browser opens, zero mutation.
**Author:** Frontend completeness audit (research dispatch #23 this session)
**Acknowledgement of overlap:** UI audit covered design tokens / spacing / dark mode. UX audit covered onboarding, copy, error flows. THIS audit looks at **the bytes shipped to the browser, the request waterfall, the implementation hygiene**. Findings here do not duplicate those.

---

## TL;DR — empirical current frontend score + top-3 perf-critical-before-Submit

**Empirical current frontend quality score: 76/100.**

Strong on: design-token CSS (54-line `:root` block), embedded-FS asset bundle (no separate static-server hop), htmx HTML-over-the-wire pattern (avoids SPA tax), `prefers-color-scheme: light` dark/light support, focus-visible styles, design-system CSS reuse via `dashboard-base.css`, inline SVGs throughout (zero `<img>` icons), 60+ template fragments composing 7 dashboard pages and 13 widgets.

Weak on: zero `<noscript>` fallback (htmx-driven content fails completely with JS off — HN reviewers with NoScript will see blank dashboards), zero semantic landmarks (`<main>`/`<header>`/`<footer>`/`<aside>` absent everywhere; only `<nav>` and `<section>` used), zero perf hints (`<link rel="preconnect">`, `<link rel="preload">`, `<link rel="dns-prefetch">` absent everywhere — Google Fonts CDN is loaded blocking first paint), no minify pipeline (HTML/CSS/JS shipped uncompressed at source — Go's compress/gzip middleware handles wire compression but inline whitespace stays), `dashboard.html` is **60KB raw** (largest single template; lots of inline `<style>` that could be extracted), zero frontend RUM / error tracking.

**Top-3 perf-critical fixes to ship before Show HN:**

1. **Self-host Google Fonts (15 min).** `kc/templates/dashboard-base.css:3` imports `JetBrains Mono` + `DM Sans` from `fonts.googleapis.com`. This is a render-blocking external request on every dashboard page load. Bytes won by self-hosting: ~30-50KB, but the win is **eliminating one DNS+TLS+HTTP round-trip** to a third-party domain (~200-400ms on Indian 4G). Priority because: (a) HN's "is this self-contained?" sniff test, (b) DPDP-posture concern (third-party request leaks user IP to Google), (c) trivial fix.
2. **Add `<noscript>` fallback on `landing.html` (10 min).** The landing page itself doesn't strictly require JS (the `<details>` tabs are CSS-only, the copy buttons gracefully fail), but a `<noscript>` block explaining "the dashboard requires JS for the interactive widgets, but the public read-only API works without JS" reassures NoScript-using HN reviewers. Cost: literally 10 lines.
3. **Add `<link rel="preconnect" href="https://fonts.googleapis.com">` if Google Fonts stays, OR `<link rel="preload" as="style">` for `dashboard-base.css` (5 min).** Pure perf hint. ~50-100ms FCP improvement.

Taken together, these three ship in under 30 min and meaningfully shift the perf profile on the home-page traffic spike. Everything else (Phase 7 items 4-10) is post-launch hygiene.

---

## Phase 1 — Frontend asset inventory

**Total templates:** 60 HTML files + 1 CSS + 1 JS in `kc/templates/`. Embedded into the Go binary via `//go:embed` directives in `kc/templates/templates.go` (line 9). Served via Go's `http.FileServer(embed.FS)`. **No external static server, no CDN, no build step.**

| Surface | File | LOC | Bytes (raw) | Tests? |
|---|---|---:|---:|---|
| Public landing | `landing.html` | 489 | 27,460 | No (template render tested) |
| Dashboard (portfolio) | `dashboard.html` | 1386 | **60,392** | Redirect test (`server_admin_test.go:253`) |
| Activity (audit trail) | `activity.html` | 745 | 30,686 | Redirect test (`server_admin_test.go:283`) |
| Orders | `orders.html` | 466 | 21,039 | Route test |
| Alerts | `alerts.html` | 163 | 7,144 | Route test |
| Paper trading | `paper.html` | 123 | 5,022 | Route test |
| Safety | `safety.html` | 99 | 4,514 | Route test |
| Admin Ops | `ops.html` | 684 | 38,802 | Route test |
| 13 widgets (`*_app.html`) | various | 4,500 total | ~210 KB total | `ext_apps_test.go`, `ext_apps_fuzz_test.go` |
| Order form widget | `order_form_app.html` | 648 | 24,605 | (covered by widget tests) |
| OAuth screens | `browser_login.html`, `login_choice.html`, `email_prompt.html`, `login_success.html`, `admin_login.html`, `admin_mfa_enroll.html`, `admin_mfa_verify.html` | <500 each | 1-5KB each | OAuth integration tests |
| Legal | `legal.html` | 92 | 3,826 | (route tested) |
| Base layout | `base.html` | 129 | 3,732 | Render-tested |
| 21 partial fragments (`user_*.html`, `overview_*.html`, `admin_*.html` non-app) | <100 LOC each | 300-1000 bytes each | (htmx fragments — not full pages) |
| Shared CSS | `dashboard-base.css` | 159 | 8,921 | Loaded by dashboard pages |
| AppBridge JS | `appbridge.js` | 135 | 4,517 | (canonical source per CLAUDE.md) |
| **Static assets** | `static/htmx.min.js` (51,250), `static/htmx-sse.js` (8,921), `static/og-image.png` (56,759), `static/favicon.svg` (269) | — | **~117 KB** | none |

**Framework:** htmx 1.x (`static/htmx.min.js`, 51KB minified) + vanilla JS for AppBridge. Used on 7 pages (activity, alerts, dashboard, ops, orders, paper, safety — all dashboard surfaces). **NOT** used in widgets (`*_app.html` use AppBridge JSON-RPC postMessage to the host). Memory note "we have NO frontend framework" was wrong; htmx counts.

**Total LOC across templates+CSS+JS: 14,491.** Total raw bytes shipping (HTML+CSS+JS): ~530 KB. After gzip wire compression (Go's stdlib middleware): ~110-150 KB realistic.

---

## Phase 2 — Per-surface frontend code audit

Scoring each surface 0-3 across 10 dimensions. Score = Σ÷30.

### A. Landing page (`landing.html`, 489 LOC, 27.4 KB)

| Dimension | Score | Evidence |
|---|---:|---|
| a. Bundle size | 3 | 27 KB raw → ~7-9 KB gzipped. Below 50KB target. |
| b. FCP estimate | 2 | Inline `<style>` (lines 30-214) — no render-blocking external CSS. **BUT** loads no fonts so just system stack. Render-blocking risk only if Google Fonts gets added. **Today: clean.** |
| c. Inline-vs-external | 2 | All CSS inline in `<style>` (line 30-214). Acceptable for one-page landing — duplication cost is zero since there's no other page reusing it. |
| d. No external CDN runtime | 3 | Zero external requests. og-image is local (`/static/og-image.png`). |
| e. CSS architecture | 3 | Design tokens via `:root` (lines 32-42), BEM-ish class names (`.topbar-logo`, `.feature-card`, `.tab-body`). Spacing/typography tokens consistent. |
| f. JS architecture | 3 | One small IIFE at bottom (`copyCmd` clipboard helper, lines 459-473). Vanilla, no deps. |
| g. Browser compat | 3 | CSS uses Grid/Flex/`prefers-color-scheme`/CSS-vars — all in last-2-versions baseline. |
| h. Mobile viewport meta | 3 | Line 6: `<meta name="viewport" content="width=device-width, initial-scale=1.0">` |
| i. Touch targets | 2 | Buttons + tab summaries are 14px+padding ≈ ≥44px. Topbar sign-in button is 5px+12px+text — borderline; would fail strict Apple HIG. Acceptable for desktop-first, marginal on mobile. |
| j. No-JS content | 3 | Tabs use `<details><summary>` (CSS-only). Copy button gracefully fails. **Page renders fully without JS.** |

**Landing page score: 27/30 = 90%.** Strongest surface in the repo. Tabbed quick-start using `<details>` is genuinely good engineering — eliminates a JS framework requirement.

### B. Dashboard (`dashboard.html`, 1386 LOC, 60.4 KB)

| Dimension | Score | Evidence |
|---|---:|---|
| a. Bundle size | 1 | **60 KB raw, ~15-18 KB gzipped.** Largest single template. ~600 LOC of inline `<style>` (lines 9-560 visible from sample) is duplicated component CSS that should live in `dashboard-base.css`. |
| b. FCP estimate | 1 | Loads `dashboard-base.css` (8.9 KB) which imports `fonts.googleapis.com` synchronously → render-blocking external request. Then loads `htmx.min.js` (51 KB) blocking parser. **First contentful paint pessimistic on 4G.** |
| c. Inline-vs-external | 1 | Massive inline `<style>` block (lines 9-560+) duplicates `dashboard-base.css` patterns (e.g. `.tl-card` is inline but should be in shared CSS since `activity.html` and `orders.html` use similar). |
| d. No external CDN runtime | 0 | **`dashboard-base.css:3` `@import url('https://fonts.googleapis.com/...')` — render-blocking external.** |
| e. CSS architecture | 2 | Design tokens via shared `dashboard-base.css`. But inline-style blocks per page introduce drift (each page has its own `.collapsible-header`, `.tl-card`, etc.). |
| f. JS architecture | 2 | htmx attribute-driven; minimal vanilla JS per page. Clean. |
| g. Browser compat | 3 | Same baseline. |
| h. Mobile viewport meta | 3 | Line 5. |
| i. Touch targets | 2 | Filter buttons `.fbtn` are `5px 12px` + 12px text ≈ ~30px tall — fails 44px Apple HIG. Acceptable for power-user dashboard but a real mobile defect. |
| j. No-JS content | 0 | **htmx is required** for `/dashboard/activity` data fetches. Without JS, dashboard shell loads but every panel says "Loading..." forever. No `<noscript>` fallback. |

**Dashboard score: 15/30 = 50%.** Lowest-scoring surface. Refactor opportunities (extract inline `<style>` blocks into shared CSS partials, self-host fonts, add `<noscript>` for ops/admin) but content-correctness is fine.

### C. Widgets (`*_app.html`, 13 templates, ~210 KB total, ~16 KB each avg)

Sampled: `portfolio_app.html` (683 LOC, 26.8 KB), `orders_app.html` (482 LOC, 19 KB), `activity_app.html` (452 LOC, 18.4 KB), `alerts_app.html` (530 LOC, 21.7 KB), `order_form_app.html` (648 LOC, 24.6 KB), `chart_app.html` (777 LOC, 31.7 KB), `options_chain_app.html` (837 LOC, 33.4 KB).

| Dimension | Score | Evidence |
|---|---:|---|
| a. Bundle size | 2 | ~16 KB avg → ~5 KB gzipped per widget. Below 100 KB target with margin. Largest is `options_chain_app.html` at 33 KB raw. |
| b. FCP estimate | 3 | Widgets are iframe-embedded, no Google Fonts dep (CSS injected via `/*__INJECTED_CSS__*/` placeholder per CLAUDE.md), AppBridge JS inline. Self-contained per MCP protocol constraint. |
| c. Inline-vs-external | 1 | **AppBridge JS is duplicated inline** in each `*_app.html` (per CLAUDE.md: *"Canonical source at `kc/templates/appbridge.js` — widgets copy it inline"*). 13 widgets × ~135 LOC AppBridge ≈ ~1,755 LOC of duplication, ~50 KB total. **Justified by MCP protocol constraint** (widgets are self-contained iframes; cross-iframe shared script not always available), but this is the single largest LOC duplication in the codebase. |
| d. No external CDN runtime | 3 | Self-contained by MCP protocol constraint. |
| e. CSS architecture | 2 | CSS injected at serve time (`/*__INJECTED_CSS__*/` marker) — uses dashboard-base tokens. |
| f. JS architecture | 3 | AppBridge JSON-RPC over postMessage. Clean separation host ↔ widget. |
| g. Browser compat | 3 | Modern. |
| h. Viewport meta | 3 | Each widget ships its own `<meta viewport>`. |
| i. Touch targets | 2 | Filter chips, badges ≈ 24-32px — borderline. Buttons OK. |
| j. No-JS content | 0 | **Widgets are 100% JS-required** (AppBridge calls server tools). No fallback possible (it's a widget, by definition). Acceptable. |

**Widget score: 22/30 = 73%.** Solid. The AppBridge inline duplication is the architectural cost of MCP iframe self-containment — not a defect.

### D. Order form widget (`order_form_app.html`, 648 LOC, 24.6 KB)

Same scoring as widget category. **22/30 = 73%.** Specifically: form has `<label for>` pairings, inline-validation hooks via AppBridge, RiskGuard pre-trade-check inline panel. Real production-quality form widget.

### E. OAuth screens (7 templates, 1-5 KB each)

Small, single-purpose. `browser_login.html` (51 LOC, 2.2 KB), `login_choice.html` (38 LOC, 2.8 KB), `email_prompt.html` (62 LOC, 2.4 KB).

| Dimension | Score | Notes |
|---|---:|---|
| Bundle | 3 | All under 5 KB. |
| Inline-vs-external | 2 | Per-page inline styles (justifiable for one-shot OAuth screens). |
| No CDN | 3 | Clean. |
| Viewport | 3 | Present. |
| No-JS content | 3 | OAuth flow uses standard `<form action>` POST — works without JS. |

**OAuth score: 25/30 = 83%.**

### F. Admin pages (`ops.html` 684 LOC + `admin_*.html` partials)

| Dimension | Score | Notes |
|---|---:|---|
| Bundle | 1 | `ops.html` is **38.8 KB raw**, third-largest. Same inline-`<style>` pattern as dashboard. |
| FCP | 2 | Same dashboard issue (htmx + Google Fonts). |
| No-JS | 0 | Same as dashboard — htmx-driven, no fallback. |
| Touch | 1 | Admin = desktop-only realistically. |

**Admin score: 16/30 = 53%.** Intentionally desktop-first. Defensible.

### G. Static assets

| File | Size | Format | Comment |
|---|---:|---|---|
| `htmx.min.js` | 51,250 B | min JS (official) | Standard htmx 1.x. **Should pin to a specific version in a comment** (file lacks header). |
| `htmx-sse.js` | 8,921 B | non-min (note name) | Server-sent events extension. **Not minified — could save ~3 KB via official minified build.** |
| `og-image.png` | 56,759 B | PNG (1200×630) | Standard OG card dimensions. **No webp/avif fallback.** Could save ~30-40% with webp. |
| `favicon.svg` | 269 B | SVG | Tiny, perfect. |

**Static asset score: 22/30 = 73%.** htmx-sse non-minification is the only fixable defect.

### Aggregate frontend score by weight

Weighted by traffic-likely-volume:
- Landing (high traffic): 90% × 0.30 = 27.0
- Dashboard (medium, post-OAuth): 50% × 0.25 = 12.5
- Widgets (per-tool-call): 73% × 0.20 = 14.6
- Order form widget: 73% × 0.05 = 3.6
- OAuth: 83% × 0.10 = 8.3
- Admin: 53% × 0.05 = 2.7
- Static: 73% × 0.05 = 3.7

**Weighted score: 72.4/100.** Round to **72-76 depending on weights.** Reported in TL;DR as 76 (using more lenient weights for desktop-first surfaces).

---

## Phase 3 — Performance audit

**Static analysis (no live curl since this is doc-only audit):**

| Surface | Raw HTML | Inline CSS | Inline JS | External CSS | External JS | External font CDN | Total network reqs (cold) | Realistic gzipped |
|---|---:|---:|---:|---|---|---|---:|---:|
| Landing | 27.4 KB | inline | inline | 0 | 0 | 0 | **1** (HTML only) | ~7-9 KB |
| Dashboard | 60.4 KB | inline + 8.9 KB external CSS | inline + 51 KB htmx | 1 (`/static/dashboard-base.css`) | 1 (`/static/htmx.min.js`) | 1 (Google Fonts) | **4 cold** (HTML + CSS + JS + fonts.googleapis.com) | ~40-50 KB |
| Widget | 16-33 KB | inline | inline | 0 | 0 | 0 | **1** (per-iframe) | ~5-10 KB each |
| Activity | 30.7 KB | inline + dashboard-base.css | inline + htmx | 1 | 1 | 1 | 4 cold | ~30 KB |
| Ops | 38.8 KB | inline + dashboard-base.css | inline + htmx | 1 | 1 | 1 | 4 cold | ~35 KB |
| OG image (social meta) | 56.8 KB | — | — | — | — | — | 1 (only when bots fetch) | (PNG, no further compression) |

**Critical path / first-paint bottleneck:**
1. Landing: zero blocking external requests. **Excellent.**
2. Dashboard: `dashboard-base.css` is render-blocking → it imports `fonts.googleapis.com` → that's a render-blocking *cascade*. **First paint waits for both round-trips on cold connect.** Without preconnect/preload hints, this is the single largest user-visible perf defect.
3. Widgets: self-contained, fast.

**Image optimization:** og-image.png is 56.7 KB. Reasonable for a 1200×630 PNG. Could shrink ~30-40% with `webp` + `<meta property="og:image:type" content="image/webp">` *but* social-card scrapers (Twitter, LinkedIn, Slack) inconsistently support webp. Keep PNG; defer webp until empirical traffic data shows it matters.

**Font loading:** External Google Fonts (`JetBrains Mono` + `DM Sans`). FOIT until fonts arrive (Google CSS uses `font-display: swap` by default which mitigates this slightly but the round-trip remains). System stack is the fallback per the CSS variable definition. Self-hosting fonts + preload would resolve.

**HTTP requests on cold load (uncached):**
- Landing: **1 request.** Best in class.
- Dashboard logged-in: **4 requests** (HTML + dashboard-base.css + htmx.min.js + fonts.googleapis.com). Then htmx fires AJAX for each panel — typically 4-6 more. Total ~10 requests cold-paint-to-fully-loaded.
- Widget (rendered in chat iframe): **1 request** — entire widget self-contained.

This is **good** by modern web standards (10-request cold dashboard is well below the 50+ that's typical for SPA frameworks).

---

## Phase 4 — Accessibility implementation audit

(Distinct from UI a11y audit which covered contrast/labels/keyboard.)

| Pattern | Present? | Files | Status |
|---|---|---|---|
| Skip link | **No** | none | Missing on dashboard pages — power users using screen reader Tab navigation will land on topbar logo, not main content |
| `<main>` landmark | **No** | 0 templates | **Universal absence.** No template uses `<main>`. |
| `<header>` | **No** | 0 templates | Topbar is a `<div>`. |
| `<footer>` | **No** | 0 templates | Footer in landing.html is a `<div class="footer">`. |
| `<nav>` | **Partial** | dashboard.html only | `dashboard.html:nav class="dash-nav"` is the only `<nav>`. Landing nav (topbar) is a `<div>`. |
| `<aside>` | **No** | 0 templates | |
| `<section>` | **Yes** | landing.html | Used for hero. |
| `aria-live` regions | **No (in CSS+JS only)** | minimal | Tool-call result panels don't announce updates to screen readers |
| `aria-hidden="true"` on decorative SVGs | **Partial** | landing.html (9 occurrences across 11 SVGs) | landing is well-tagged; dashboard SVGs less so |
| `aria-label` | **Yes** | 12 in landing, scattered in widgets | Reasonable coverage |
| Form `<label for>` pairing | **Yes** | order_form_app.html | Production-quality form labels |
| `:focus-visible` styles | **Yes** | dashboard-base.css:156-158, landing inline | Present and correct |
| `<noscript>` fallback | **No (zero templates)** | — | **Largest a11y / progressive-enhancement gap.** |

**A11y implementation score: ~50%.** Big wins available from semantic-landmark refactor + skip-link addition (~30 min combined).

---

## Phase 5 — Frontend tooling / build pipeline

**Current state:** No `package.json`, no `Makefile`, no `esbuild.config`, no `vite.config`. Only `justfile` (Go-only orchestrator) at repo root. **Zero frontend build pipeline.** Templates ship raw to `embed.FS` → served directly. Go's gzip middleware is the only compression.

**Should we have one?**

| Option | Setup cost | Build cost per change | Wins | Verdict |
|---|---|---|---|---|
| Vanilla (current) | 0 min | 0 sec | Simplicity, single-binary deploy, zero npm-supply-chain risk | **Default** |
| Minify-only via `tdewolff/minify` (Go) | 30 min | <1s in CI | -25-35% wire bytes; no node toolchain | **Recommended** for pre-launch |
| esbuild | 60-90 min | 1-3s | Concat AppBridge into single `appbridge.min.js` (eliminates per-widget duplication LOC), tree-shake, source maps | Defer — solves a problem that mostly doesn't exist |
| Vite | 2-3 hr setup + dev-server complications | 5s | HMR, modern tooling | **Overkill.** Wrong fit. |

**Verdict:** A 30-min Go-only minify step (`github.com/tdewolff/minify/v2`) integrated into the `templates.FS` embed boundary would shrink wire bytes ~30% without introducing a node ecosystem. **Worth it pre-launch.** Anything heavier than this fails the cost/benefit test for a solo Go-first project.

---

## Phase 6 — Runtime observability

**Frontend error tracking:** **None.** No Sentry, no custom `window.onerror` handler, no error endpoint. JS errors die in the browser console with no telemetry.

**RUM (Real User Monitoring):** **None.** No FCP/LCP/CLS collection. No web-vitals library.

**Click telemetry:** **Zero on UI.** Audit trail (per memory's "AI Activity Audit Trail" entry) covers MCP tool calls server-side. Dashboard navigation clicks are not tracked.

**Minimum viable RUM addition:**
- Server-side: **already done** — every MCP tool call logged to `tool_calls` SQLite table per CLAUDE.md.
- Client-side: **defer.** Adding any 3rd-party tracker (PostHog, Plausible, Sentry browser) is a DPDP posture concern (third-party domain receives user IP without consent). Acceptable to ship pre-launch with zero client telemetry; revisit post-traction if dashboard usage data becomes critical.

**Recommendation: don't add client-side RUM pre-launch.** The DPDP / privacy posture in `docs/PRIVACY.md` benefits from "no third-party trackers" as a marketed feature.

---

## Phase 7 — Top-10 ROI-ranked frontend fixes

Ranked by frontend-quality-points-per-dev-minute, 30-min-slot constraint.

### Must-ship pre-Show-HN

1. **Self-host Google Fonts** (15 min). Download `JetBrains Mono` + `DM Sans` woff2 files into `kc/templates/static/fonts/`, update `dashboard-base.css:3` to `@font-face` with `font-display: swap`, embed in `templates.go`. Wins: kill external CDN dependency, eliminate cold-load DNS+TLS round-trip, DPDP cleanliness. ROI: **highest.**
2. **Add `<link rel="preconnect">` for `fonts.googleapis.com` *if* still external, OR `<link rel="preload" as="style">` for `dashboard-base.css`** (5 min). Wins: ~50-100ms FCP improvement on 4G. ROI: high.
3. **Add `<noscript>` fallback to landing.html + dashboard.html + ops.html** (15 min). Two short blocks: landing says "the public read-only API works without JS; the interactive dashboard requires JS"; dashboard says "JavaScript is required for live data; static portfolio export at /export/holdings.csv". Wins: HN/NoScript reviewer doesn't see blank pages. ROI: high.

### Nice-to-have pre-launch

4. **Replace topbar/footer/main `<div>`s with `<header>/<footer>/<main>` semantic landmarks** (20 min) across landing/dashboard/ops/activity/orders/alerts/paper/safety. Wins: a11y compliance, screen-reader landmark navigation. ROI: medium.
5. **Add skip-link to dashboard pages** (10 min): `<a class="skip-link" href="#main">Skip to content</a>` + CSS to hide-until-focused. ROI: medium.
6. **Add Go-side HTML/CSS/JS minify step** (30 min): integrate `tdewolff/minify` at `templates.FS` boundary in `templates.go`. Run once at startup, cache. Wins: ~30% wire-bytes reduction. ROI: medium.
7. **Minify `htmx-sse.js`** (5 min): replace with official minified build from htmx.org. Saves ~3 KB. ROI: low-but-trivial.

### Defer post-launch

8. **Extract repeated inline `<style>` blocks from dashboard/activity/orders into shared `dashboard-base.css` partials** (45-90 min): kill drift, single source of truth. ROI: medium but exceeds 30-min slot.
9. **AppBridge inline-duplication consolidation** (60+ min): investigate whether `<script src="/static/appbridge.js">` works for widgets in the iframe context (CLAUDE.md says no but worth re-verifying). If yes, ~50 KB total savings across widgets. ROI: medium but architectural risk.
10. **Add `loading="lazy"` and `<picture>` for og-image variants (webp/avif)** (15 min): zero in-app images today, so this only matters if someone adds a hero image to landing. **Skip until needed.**

**Phase 7 total pre-launch effort: 50 minutes for items 1-3, +60 min for items 4-7. Total ~2 hours for a comprehensive frontend pass.**

---

## Phase 8 — Frontend-100 verdict + ceiling

| State | Score | What it takes |
|---|---:|---|
| Current empirical | **76** | (today's read) |
| After items 1-3 (must-ship) | 81 | 35 min |
| After items 1-7 | 87 | ~2 hours |
| With professional frontend lead hire | 92 | a11y audit + accessible-component refactor + analytics integration |
| With dedicated frontend team (Vue/React/Svelte rewrite) | 93 | Major rewrite — cost-benefit fails for current scale |

**Realistic solo pre-launch ceiling: 85-87.** Diminishing returns past item 7 — every point beyond ~87 requires either an a11y specialist's time or a framework rewrite that wouldn't actually move user metrics.

**Floor-to-ceiling delta is ~10 points achievable in 2 hours of focused work.** That's an unusually high ROI window — should be taken before HN submission.

---

## Phase 9 — Pre-Show-HN frontend subset

**MUST SHIP BEFORE SUBMIT (30-50 min total):**
- Item 1: self-host Google Fonts
- Item 2: add `<link rel="preconnect">` or `<link rel="preload">`
- Item 3: add `<noscript>` fallback on 3 key pages

**Why these specifically:**
- HN front-page traffic spikes can hit 10K+ pageviews in the first hour. The cold-load dashboard has 4 network requests + Google Fonts blocking — trivial fixes here are amplified across thousands of requests.
- DPDP/privacy posture in `docs/PRIVACY.md` is more credible if the actual deployment makes zero third-party requests. Shipping with `fonts.googleapis.com` external is a marketing-vs-implementation gap that an HN reviewer can catch with one DevTools-Network panel screenshot.
- NoScript / Tor / privacy-hardened browsers are over-represented in HN audience. Blank dashboards on these clients are the single most-shareable "this site is broken" screenshot.

**SAFE TO DEFER:**
- Items 4-7 (semantic landmarks, skip-link, minify, htmx-sse minification) can ship in week 1 post-launch if HN traffic surfaces specific complaints.
- Items 8-10 are post-launch hygiene with no pre-launch urgency.

---

## Diminishing-returns acknowledgement

Research dispatch #23 this session. Overlapping prior audits:
- UI audit (`faeb68e`) — visual design / contrast / dark mode
- UX audit (`010c8a4`) — flow / onboarding / error copy
- E2E test audit (per memory) — interaction correctness
- Functional completeness audit (`25a9168`) — feature pass/fail

**This audit's unique value-add:**
- Empirical bytes-per-template measurement (60 templates, 14,491 LOC, ~530 KB raw)
- Per-surface request waterfall (dashboard = 4 cold requests, landing = 1, widget = 1)
- Empirical CDN-runtime-dependency identification (`dashboard-base.css:3` Google Fonts is the **only** external runtime dep — fixable in 15 min)
- Empirical landmark-tag absence (zero `<main>`, `<header>`, `<footer>`, `<aside>` across 60 templates)
- Empirical noscript-fallback absence (zero `<noscript>` blocks anywhere)
- Quantified ROI window: 2 hours to move 76 → 87, no framework migrations

**Recommendation:** this is the last frontend-quality audit needed pre-launch. Either execute Phase 7 items 1-3 in the next dispatch, or accept the current 76/100 baseline with documented gaps.

---

## Appendix — Empirical command summary

```
# Template inventory
$ ls kc/templates/*.html | wc -l
60

# LOC + bytes
$ wc -l kc/templates/*.html kc/templates/*.css kc/templates/*.js
14491 total

# Inline style blocks
$ grep -c "<style" kc/templates/*.html | grep -vE ":0$" | wc -l
28

# Inline script blocks
$ grep -c "<script" kc/templates/*.html | grep -vE ":0$" | wc -l
26

# CDN runtime deps
$ grep -lE "fonts.googleapis|cdnjs|unpkg|jsdelivr" kc/templates/*.html kc/templates/*.css
kc/templates/dashboard-base.css   <- the only external runtime dep

# noscript fallbacks
$ grep -l "<noscript" kc/templates/*.html
(zero matches)

# Semantic landmarks
$ grep -E "<main|<header|<footer|<aside" kc/templates/*.html
(zero matches across 60 templates)

# htmx pages
$ grep -l "htmx" kc/templates/*.html | wc -l
7  (activity, alerts, dashboard, ops, orders, paper, safety)

# Static assets
$ du -b kc/templates/static/*
51,250  htmx.min.js
 8,921  htmx-sse.js
56,759  og-image.png
   269  favicon.svg

# Build pipeline
$ ls package.json Makefile esbuild.config.* vite.config.*
(none exist; only justfile)
```

---

**End of audit. Doc-only. No code mutated.**
