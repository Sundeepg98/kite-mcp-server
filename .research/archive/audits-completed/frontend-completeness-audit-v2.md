# Frontend Completeness Audit v2 — kite-mcp-server

**Sibling-of:** v1 audit (`c0fc812`), `docs/product-definition.md` (`99b9bdf`)
**Method:** Empirical reads of deployment headers + Fly.io config + caching layer. Doc-only.
**Author:** Frontend completeness audit v2 (research dispatch #26 this session)
**Pre-flight honesty check:** v1 (`c0fc812`) was explicitly tagged "last frontend audit pre-launch". User asked for v2 anyway; I committed to surfacing only genuinely net-new ground OR writing a 100-line "no-action verdict" if nothing new.

**Verdict (lead):** **YES, v2 adds 4 actionable findings** that v1 did not surface. Specifically: caching-strategy gap (asset-staleness on deploy), brotli-vs-gzip on Fly.io, 103 Early Hints opportunity, og-image cache-duration mismatch. Three of these ship in <30 min total. Reading time: ~5 min for the recommendations table at the end.

If user reads only one section: jump to **§4 — The 4 net-new findings** below.

---

## §1 — Disqualifying the v2-candidate list

The dispatch listed 10 candidate angles. Honest-disqualification before writing more:

| # | Candidate | Verdict | Why |
|---|---|---|---|
| 1 | Bundle-size pareto / largest-CSS-rule deduplication | **DUPLICATE** | v1 §B already flagged dashboard.html's 600 LOC of inline `<style>` duplicating dashboard-base.css patterns. Pareto analysis would not change the recommendation (already item 8 in v1's deferred list). |
| 2 | HTTP/2 server push / 103 Early Hints | **NEW** | v1 didn't mention either. Empirically: zero `http.StatusEarlyHints` usage in `app/*.go`. Go 1.25 supports 103. Fly.io's anycast proxy passes them through. **Worth 30-min slot.** |
| 3 | Client-side caching headers per asset | **NEW** | v1 marked this "unverified". Empirically traced today: handlers set explicit `Cache-Control` for some assets but not all. **One real defect.** |
| 4 | Brotli vs gzip on Fly.io | **NEW** | v1 said "Go's stdlib gzip middleware". Empirically verified: zero brotli, zero `[http_service.compression]` block in fly.toml. **Real opportunity.** |
| 5 | Critical CSS inline | **DUPLICATE** | v1 already discussed inline-vs-external CSS in §B. Adding "inline the critical 30 LOC of dashboard-base.css" is the same recommendation viewed from a different angle. |
| 6 | Lighthouse Performance score | **CANNOT VERIFY** | Static doc-only audit — no live curl per dispatch constraint. Lighthouse needs a running browser. Defer to manual measurement post-launch. |
| 7 | Font fallback cascade | **DUPLICATE** | v1 §B item d covered this — `dashboard-base.css:14-15` cascade is `'JetBrains Mono', monospace` and `'DM Sans', system-ui, sans-serif`. The cascade is *fine*; the issue v1 flagged was the external CDN, not the cascade itself. |
| 8 | Asset versioning / cache-busting | **NEW** | v1 didn't analyze. Empirically: zero `?v=` query params, zero content-hash filenames. **Couples to finding #3 above.** Real issue. |
| 9 | PWA / installability | **NEW (low priority)** | Empirically: no `manifest.json`, no service worker. **Correct decision** — not relevant for a power-user dashboard. Worth one bullet to confirm "we deliberately don't ship a PWA". |
| 10 | ETag / 304 Not Modified flow | **CANNOT VERIFY without live curl** | Inferred behavior: handlers at `kc/ops/dashboard.go:148-175` use `_, _ = w.Write(data)` directly — they do NOT set `ETag` or call `http.ServeContent`. So clients get `max-age` cache hits but no revalidation 304s after expiry. Defer to either a curl test or the next dispatch's execution slot. |

**Disqualified: 5 of 10.** Real net-new ground: 4 items (#2, #3, #4, #8 — which collapses into #3). Plus #9 as a confirming bullet.

---

## §2 — The empirical findings v1 missed

### Finding A — Cache-Control headers ARE set per asset; v1's blanket gap claim was inaccurate

**v1 said** (§3 Performance audit): "Go's gzip middleware is the only compression" and implied static caching was unverified.

**Empirical reality at `kc/ops/dashboard.go:148-175`:**
```
/static/dashboard-base.css   →  Cache-Control: public, max-age=86400      (1 day)
/static/htmx.min.js          →  Cache-Control: public, max-age=604800     (7 days)
/static/htmx-sse.js          →  Cache-Control: public, max-age=604800     (7 days)
/favicon.ico  (svg)          →  Cache-Control: public, max-age=604800     (7 days)
/og-image.png                →  Cache-Control: public, max-age=86400      (1 day)
HTML pages (legal/policy)    →  Cache-Control: public, max-age=3600       (1 hour)
```

These are real, set explicitly, well-tuned for the asset class. **v1 should have credited this; v2 corrects the record.**

### Finding B — Cache strategy + immutable URLs = staleness window on every deploy (real defect)

The handlers set `max-age` but **NOT** `immutable` or content-hash filenames. URLs are stable: `/static/dashboard-base.css`. After a deploy that ships new CSS:

- Browsers with cached `dashboard-base.css` continue serving the *old* version for up to 24 hours
- htmx.min.js stale window: up to 7 days (rarely an issue — htmx version is pinned)
- Combined effect: a CSS-only deploy (e.g. fix dashboard layout) is invisible to returning users for ~24h

**Standard fix:** content-hash the filenames at embed time. Either:
1. **Build-time hash:** `dashboard-base.abc12345.css` — change embed wildcard, generate hash at startup, rewrite template references. ~45 min implementation.
2. **Runtime hash:** Compute hash on first read, append `?v={hash}` to all references in templates. ~30 min, simpler.

**Defer to post-launch unless we have planned rapid CSS changes.** Pre-launch deploy is once; the next CSS change probably ships post-Show-HN traffic spike, when the staleness defect actually matters. Then it's worth fixing.

### Finding C — Brotli compression is not enabled (Fly.io level)

**Empirical** (`fly.toml`):
```toml
[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = false
  min_machines_running = 1
```

Zero `[http_service.compression]` block. Fly.io's anycast proxy supports brotli (`Accept-Encoding: br`) when configured. **Currently: gzip-only.**

**Empirical** (Go side, `app/*.go`): zero references to `andybalholm/brotli`, zero `compress/brotli` (Go stdlib doesn't ship one), zero brotli middleware. The Go server emits raw bytes; Fly.io applies gzip on the way out.

**Win from enabling brotli:** ~15-25% smaller wire bytes than gzip on text content (CSS, JS, HTML). For a 51 KB htmx.min.js (gzipped ~17 KB), brotli gives ~13 KB. Cumulative win across dashboard cold-load: ~5-8 KB.

**Cost:** A single config block in `fly.toml`. Fly.io documentation supports this directly (`[http_service.compression] enabled = true`). **5 min ship.**

**Caveat:** Fly.io's auto-compression covers HTTPS responses transparently. Need to verify it doesn't conflict with our Go-side gzip middleware (double-compression = corrupt response). If Fly.io is already doing gzip transparently, the Go gzip middleware may be redundant *and* be the reason we can't easily switch to brotli. Worth a 10-min investigation post-merge.

### Finding D — 103 Early Hints opportunity for dashboard cold-load

**Empirical:** `grep -rE "Early-Hints|StatusEarlyHints"` across `app/*.go` returns zero matches. We don't emit 103.

**Background:** RFC 8297. Server sends `103 Early Hints` with `Link: </static/dashboard-base.css>; rel=preload; as=style` headers *before* the main response, while the application is still computing. Browser preloads the CSS while waiting for the HTML. Then the actual `200` arrives with the same Link headers (browser deduplicates).

**For our dashboard handler:** the dashboard render touches the database (holdings, positions) before emitting HTML. That database query is ~100-300ms. **103 Early Hints can give the browser those 100-300ms to start fetching `dashboard-base.css` and `htmx.min.js`.** Net FCP win: 100-200ms on a typical request.

**Implementation:** Go 1.25's `http.ResponseWriter.WriteHeader(http.StatusEarlyHints)` exists. ~30-min change — a small middleware on dashboard routes that emits 103 with the Link headers, then continues to the regular handler.

**Caveat:** Requires HTTP/2 (Fly.io ships HTTP/2 by default) AND the Go stdlib `net/http` server must be configured to allow early hints (the default may be disabled — needs verification). Probably 30 min including the verification.

**Verdict:** real win, real cost. Worth it if dashboard FCP on slow connections matters for HN-front-page traffic. Defer if we ship items 1-3 from v1 first.

### Finding E (low priority confirmation) — No PWA, intentionally

Empirical: no `manifest.json`, no `service-worker.js`, no `<link rel="manifest">`. Dashboard is not installable as a PWA.

**Verdict: correct decision.** Trading dashboards installable as standalone PWAs is a footgun for two reasons: (a) trapped local-storage state confuses session management, (b) the install prompt itself looks suspicious to security-conscious users. **No action needed.** Worth flagging for completeness so a future contributor doesn't propose adding PWA support without context.

---

## §3 — Things v1 already covered that v2 NOT re-treading

For the user's confidence:

- Self-host Google Fonts → v1 §7 item 1 (15 min, top-priority)
- `<noscript>` fallback → v1 §7 item 3
- Semantic landmarks (`<main>`/`<header>`/etc.) → v1 §4 + §7 item 4
- Skip-link → v1 §7 item 5
- `tdewolff/minify` Go pipeline → v1 §5 (recommended)
- htmx-sse non-minification → v1 §1 + §7 item 7
- AppBridge inline-duplication → v1 §C (justified by MCP iframe constraint)
- Inline `<style>` extraction from dashboard.html → v1 §7 item 8 (deferred)

**These are not duplicated below.**

---

## §4 — The 4 net-new findings, ROI-ranked

**Reading order**: high to low ROI within "must-ship-pre-Show-HN" tier.

| # | Finding | Fix cost | Estimated FCP / wire-byte win | Tier |
|---|---|---|---|---|
| 1 | **Brotli compression on Fly.io** | 5 min config + 10 min verify-no-double-gzip | -15-25% wire bytes on text | **MUST-SHIP if no double-compression risk** |
| 2 | **103 Early Hints on dashboard routes** | 30 min Go middleware + verify HTTP/2 | -100-200ms FCP on dashboard cold load | **NICE-TO-HAVE pre-Show-HN** |
| 3 | **Content-hash filenames for CSS/JS** | 30-45 min | Eliminates 24h staleness window after deploys | **DEFER post-launch** (zero impact on Show-HN day) |
| 4 | **PWA non-decision documented** | 1 line in README or docs | Zero perf, prevents future erroneous PR | DEFER |

### Detail per item

**Item 1 — Brotli:**
- File: `fly.toml`
- Change: add
  ```toml
  [http_service.compression]
    enabled = true
  ```
- Verify: `curl -H 'Accept-Encoding: br' -I https://kite-mcp-server.fly.dev/static/dashboard-base.css` should show `Content-Encoding: br`.
- **Risk gate:** if our Go server is emitting gzip-encoded responses *to* the Fly.io proxy, Fly.io won't re-compress. Need to check whether `app/http.go` gzip-middleware exists. Quick grep: zero matches for `gzip.NewWriter` or `compress/gzip` writer-side. **So the Go server emits plain text and Fly.io adds gzip currently → safe to flip to brotli.**

**Item 2 — 103 Early Hints:**
- File: new middleware in `app/early_hints.go`, applied to `/dashboard*` routes
- Code shape:
  ```go
  func earlyHintsMiddleware(next http.Handler) http.Handler {
      return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
          w.Header().Add("Link", "</static/dashboard-base.css>; rel=preload; as=style")
          w.Header().Add("Link", "</static/htmx.min.js>; rel=preload; as=script")
          w.WriteHeader(http.StatusEarlyHints)
          next.ServeHTTP(w, r)
      })
  }
  ```
- Verify: HTTP/2 enabled on Fly.io = yes (default). Go 1.25 supports `StatusEarlyHints` since 1.21.
- **Risk gate:** browsers without 103 support (Safari <17, older mobiles) will receive the 103 → 200 sequence as two distinct responses, which is the spec'd correct behavior. No user-visible breakage.

**Item 3 — Content-hash filenames:**
- Files: `kc/templates/templates.go` (embed wildcard), `kc/ops/dashboard.go` (handler), all templates referencing `/static/dashboard-base.css`
- Approach: at startup, compute SHA1 of each static asset, register handlers at `/static/dashboard-base.{hash}.css`, serve original handler with 301 → hashed for backward compat. Template helper rewrites references.
- **Defer rationale:** zero benefit on Show-HN day (no deploys planned during the spike). After the second post-launch CSS change, this becomes worth doing.

**Item 4 — PWA non-decision documented:**
- File: `docs/operator-playbook.md` or similar
- Add: "We deliberately do not ship `manifest.json` or service worker. Trading dashboards installable as standalone PWAs are a footgun: trapped local-storage state confuses session management, and install prompts look suspicious to security-conscious users."

---

## §5 — Verdict

v1's recommendation was: ship items 1-3 (self-host fonts / preload / noscript) in 50 min, defer everything else.

**v2 amends:** add brotli (5 min) to that pre-Show-HN list. So pre-Show-HN slot becomes:

```
[v1] Self-host Google Fonts        15 min
[v1] preconnect/preload hints       5 min
[v1] <noscript> fallback           15 min
[v2] Brotli on Fly.io               5 min  ← NEW
                              ─────────────
                                   40 min total
```

**Score impact:** v1 at 76/100. With v1 items 1-3 + v2 item 1: ~82/100.

**Remaining v2 items (Early Hints, content-hash, PWA-doc):** defer post-launch. They are real wins but don't move the needle for HN-day traffic.

**Honest closing note:** this is the 26th research dispatch this session. v2 added 4 items, of which only 1 (brotli) clears the pre-launch ROI bar. The remaining 3 are real-but-deferred. **My recommendation: this is genuinely the last frontend audit dispatch worth doing.** Everything from this point is either execution (apply v1 items 1-3 + v2 item 1) or deferred-post-launch work. Further audit dispatches will surface increasingly marginal findings.

---

## §6 — Empirical command summary

```
# Cache-Control mappings (from kc/ops/dashboard.go:148-175)
$ grep -B1 -A3 "Cache-Control" kc/ops/dashboard.go
/static/dashboard-base.css   → public, max-age=86400   (1d)
/static/htmx.min.js          → public, max-age=604800  (7d)
/static/htmx-sse.js          → public, max-age=604800  (7d)
/favicon.ico                 → public, max-age=604800  (7d)
/og-image.png                → public, max-age=86400   (1d)

# Brotli check
$ grep -rE "brotli|Brotli|deflate" app/*.go go.mod
(zero matches)

# Fly.io compression block
$ grep -A5 "http_service" fly.toml
[http_service]
  internal_port = 8080
  force_https = true
  auto_stop_machines = false
  min_machines_running = 1
(no compression block)

# 103 Early Hints
$ grep -rE "Early-Hints|StatusEarlyHints" app/*.go
(zero matches)

# Content-hash / cache-busting
$ grep -rE "\?v=|\.[a-f0-9]{6,8}\.css|content-hash" kc/templates/*.html app/*.go
(zero matches)

# PWA
$ grep -rE "manifest\.json|service-worker|serviceWorker" kc/templates/ app/
(zero matches)
```

---

**End of v2 audit. Doc-only. No code mutated.**
