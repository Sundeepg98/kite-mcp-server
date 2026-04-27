# tests/e2e — Playwright thin-smoke suite

This directory holds the wire-level / browser-level smoke tests for
kite-mcp-server. The suite is **deliberately thin**: ~5 specs, ~400
LOC, focused on the question "is the surface alive?" — not "does
the layout match the design?".

## Why thin-smoke (not full E2E)

The original Wave C plan (see `.research/features-ux-coverage-audit.md`)
proposed a 17-spec full-coverage suite, ~800-1500 LOC. That was
**deferred** because the maintenance burden of pixel-perfect UI tests
historically swamped their value.

The re-evaluation in `.research/post-wave-d-skipped-items-reeval.md`
(commit `a66d807`) reduced scope to **just the contracts that
matter**:

1. Server boots and responds (`/healthz`).
2. Landing page renders without console errors.
3. OAuth funnel entry points don't 5xx.
4. MCP `tools/list` returns the locked tool surface.
5. Well-known discovery endpoints (server-card, OAuth metadata) serve
   valid JSON.

These are the contracts that **silently break deploys**. Layout
regressions, by contrast, are visible to humans — they don't need
automated coverage to catch.

## What this suite is NOT

- Not a visual regression suite (no screenshot diffs).
- Not a load test (no concurrent users).
- Not a security scanner (use `gosec` / `govulncheck`).
- Not a Kite-API integration test (no real broker calls — those
  require a sandbox developer app and live in `WC.2` of the original
  Wave C plan, NOT yet shipped).
- Not a widget render test (widgets need MCP-Apps host context;
  that's `WC.3`).

## Running locally

### Prerequisites

- Node.js 20+ (`nvm install 20`).
- The kite-mcp-server binary (built via `go build`).

### One-time setup

```bash
cd tests/e2e
npm install
npx playwright install --with-deps chromium
```

The `--with-deps` flag installs the Linux libs Playwright's bundled
chromium needs. On macOS / Windows it's a no-op.

### Run

In one terminal — boot the server with OAuth disabled (for `/mcp`
public access):

```bash
DEV_MODE=true BIND_ADDR=127.0.0.1:8080 ./kite-mcp-server
```

In another:

```bash
cd tests/e2e
npm test
```

To target a remote host (staging, fly.io preview):

```bash
TARGET_BASE_URL=https://kite-mcp-server-staging.fly.dev npm test
```

### Headed / debug

```bash
npm run test:headed    # browser visible
npm run test:ui        # Playwright UI inspector
```

### Reports

```bash
npm run report         # opens last HTML report in browser
```

The HTML report lives at `tests/e2e/playwright-report/`.

## CI integration

The suite runs in `.github/workflows/playwright.yml` on every PR that
touches:

- `app/**`, `mcp/**`, `kc/**`, `broker/**`, `oauth/**` (Go surfaces)
- `tests/e2e/**` (the suite itself)
- the workflow file

The CI job builds the server, boots it on `localhost:8080` with
OAuth disabled, and runs the smoke suite. On failure, the server log
and HTML report are uploaded as artifacts (7-day retention).

## Surface lock — keeping the hash in sync

The `tool-surface.spec.ts` pins a SHA256 over the sorted list of
tool names returned by `/mcp tools/list`. **The same hash is
pinned in Go**: `mcp/tool_surface_lock_test.go`'s
`expectedSurfaceHash`. The two values **must match** — they are the
same contract, recomputed from independent vantage points.

When you intentionally add or remove a tool:

1. Run `go test ./mcp/ -run TestToolSurfaceLock_Names`. Copy the new
   hash from the failure message.
2. Update `expectedSurfaceHash` in
   `mcp/tool_surface_lock_test.go`.
3. Update `EXPECTED_SURFACE_HASH` in
   `tests/e2e/specs/tool-surface.spec.ts`.
4. Update the `lockedSurfaceTools` golden list in the Go file (used
   only for diff-on-mismatch error messages).

If the hashes drift between Go and TS, the next CI run will catch it.

## Adding a new spec

The bar for new specs is **high**. Before adding one, ask:

1. **Is this catching a contract or a layout?** Layouts are out of
   scope. Contracts (HTTP status codes, JSON shapes, redirect targets)
   are in scope.
2. **Does the existing Go unit test already cover it?** If so, don't
   duplicate — the Go test runs in milliseconds; this suite costs a
   browser launch.
3. **Is the assertion stable across copy / styling changes?** If the
   answer is "I'd have to update this every time we re-do the landing
   page", tighten the assertion until it isn't.

When in doubt, lean toward NOT adding the spec. A 5-spec suite that
runs reliably is more valuable than a 50-spec suite that flakes
weekly.

## Troubleshooting

### "Tool surface drift detected"

The live `/mcp tools/list` returned a different set of tool names
than the locked hash expects. Either:

- A tool was added/removed/renamed intentionally — update both hashes
  per the section above.
- A tool registration regressed — figure out what got dropped and
  restore it.

### "/mcp returned 401 — server has OAuth enabled"

The `tool-surface.spec.ts` test skipped because the live server
required auth on `/mcp`. To exercise this spec locally, boot the
server WITHOUT setting `OAUTH_JWT_SECRET` (and without
`KITE_API_KEY` / `KITE_API_SECRET`). When all three are unset, the
OAuth handler is `nil` and `/mcp` is publicly accessible.

This is fine for smoke-testing — the OAuth path itself has unit
coverage in `oauth/`. We're testing wiring, not auth.

### Playwright browser fails to launch in CI

Check the workflow log for "Playwright deps". If the install step
errored, missing Linux libs are the usual cause —
`npx playwright install --with-deps chromium` should pull them.
GitHub-hosted ubuntu-latest runners have all the libs out of the
box.
