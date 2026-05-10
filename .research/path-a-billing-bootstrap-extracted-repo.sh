#!/usr/bin/env bash
# Path A.14 — kc/billing bootstrap.

set -euo pipefail

SCRATCH=/tmp/algo2go-billing-extract-dryrun/kite-mcp-billing-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep + rewrite first"; exit 1; }
cd "$SCRATCH"

echo "=== Phase 11: Set local git identity ==="
git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"

echo "=== Phase 11b: go mod tidy ==="
/usr/local/go/bin/go mod tidy 2>&1 | tail -3

echo "=== Phase 11c: Stage + commit module-path rewrite + workspace cleanup ==="
git add -A
git status --short | head -10
git commit -m "chore: rewrite module path + drop stale workspace artifacts

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/billing to
github.com/algo2go/kite-mcp-billing.

Drops dead 'replace zerodha/kite-mcp-server => ../..' + 'replace
.../testutil => ../../testutil' workspace artifacts (kc/billing
has zero actual root or testutil imports in source — verified
empirically). go mod tidy confirms by not re-adding them.

kc/billing's real deps are all algo2go-published v0.1.0 modules:
  - github.com/algo2go/kite-mcp-alerts (Path A.11)
  - github.com/algo2go/kite-mcp-domain (Path A.10)
  - github.com/algo2go/kite-mcp-logger (Path A.7)
  - github.com/algo2go/kite-mcp-oauth (Path A.13)
  + transitive: kite-mcp-broker, kite-mcp-isttz, kite-mcp-money,
    kite-mcp-templates, kite-mcp-users (all v0.1.0)

Standalone build PASS. Standalone go test ./... PASS.

This commit closes the original Path A.8 halt at commit 71f17eb —
the cluster cliff that motivated the 4-step billing-chain
unblocking sub-project (alerts -> users -> oauth -> billing) is
now fully resolved.

Mechanical rewrite via .research/path-a-billing-rewrite-dryrun.sh
on the kc/billing subtree extracted by
path-a-billing-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@7d3a3ce."

echo "=== Phase 12: Write LICENSE (MIT) ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/billing design — billing
                                  engine + Stripe checkout + tier
                                  middleware + webhooks + tier
                                  enforcement)
Copyright (c) 2026 algo2go contributors (extraction, packaging)

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.
LICENSE_EOF
echo "LICENSE written"

echo "=== Phase 13: CODEOWNERS ==="
mkdir -p .github
echo '* @Sundeepg98' > .github/CODEOWNERS

echo "=== Phase 14: .gitignore ==="
cat > .gitignore <<'GITIGNORE_EOF'
*.exe
*.dll
*.so
*.dylib
*.bin
*.test
*.prof
coverage.out
coverage.html
*.cov
*.tmp
*.log
.DS_Store
Thumbs.db
.vscode/
.idea/
*.swp
*.swo
*~
vendor/
.env
.env.local
GITIGNORE_EOF

echo "=== Phase 15: README.md ==="
cat > README.md <<'README_EOF'
# kite-mcp-billing

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-billing.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-billing)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Billing engine + Stripe checkout + tier middleware for the algo2go
ecosystem. Provides subscription tier management (Free / Trader /
Premium), Stripe Checkout + Customer Portal flows, webhook handling
(checkout.session.completed, customer.subscription.updated/deleted),
tier-aware MCP middleware for tool gating, and event emission via
`algo2go/kite-mcp-domain.TierChangedEvent`.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
for tier-gated MCP tools (Telegram trading, trailing stops, MF
orders, native alerts), Stripe billing flows, and admin tier
overrides.

## Why a separate module?

Billing is a substantial commercial-tier surface (~6K LOC) that
unrelated algo2go projects (broker dashboards, premium analytics,
future trading bots) may need independent of `kite-mcp-server`.
Hosting as a module:

- Centralizes the tier definition + Stripe integration across consumers
- Lets billing logic + tier semantics version independently
- Pairs cleanly with `algo2go/kite-mcp-domain` (Money + TierChangedEvent),
  `kite-mcp-alerts` (Store backend), `kite-mcp-oauth` (admin gating),
  `kite-mcp-logger` (structured logging) for the full commercial stack

## Closes original Path A.8 halt

This module's promotion was originally **halted at Path A.8**
(commit 71f17eb in kite-mcp-server) due to a 5+ internal-dep
cluster (templates + domain + alerts + users + oauth all in-tree).
Path A.9 through A.13 unblocked each cluster member sequentially:

- Path A.8' (kc/templates @ 1db565a)
- Path A.10 (kc/domain @ 9ee8212)
- Path A.11 (kc/alerts @ fd9d9fb)
- Path A.12 (kc/users @ e96b1c0)
- Path A.13 (oauth @ 6f2a2b0)

This is **Path A.14** — the FINAL step that closes the chain.

## Stability promise

**v0.x — unstable.** Type signatures may evolve as billing patterns
mature. Pin `v0.1.0` deliberately. v1.0 ships only after the public
API is reviewed for stability and at least one external consumer
ships against it.

## Install

```bash
go get github.com/algo2go/kite-mcp-billing@v0.1.0
```

## Public API (selected)

### Tiers
- `Tier` (int): TierFree, TierTrader, TierPremium
- `TierMonthlyINR(t Tier) domain.Money` — pricing
- `TierName(t Tier) string` — display name

### Store
- `Store` — subscription CRUD with `*alerts.DB` backend
- `NewStore(db *alerts.DB) *Store`
- `Store.SetEventDispatcher(d *domain.EventDispatcher)` — emits
  `domain.TierChangedEvent` on subscription changes

### Stripe integration
- `CheckoutSession(ctx, email, tier) (url, error)` — initiates
  Stripe Checkout for tier upgrade
- `CustomerPortal(ctx, email) (url, error)` — Stripe billing portal
- `WebhookHandler(...)` — verifies + dispatches Stripe webhooks

### Middleware
- `TierGate(minTier Tier) mcp.Middleware` — gates MCP tools by tier

## Dependencies

- `github.com/algo2go/kite-mcp-alerts` v0.1.0 — Store backend
- `github.com/algo2go/kite-mcp-domain` v0.1.0 — Money + TierChangedEvent
- `github.com/algo2go/kite-mcp-logger` v0.1.0 — structured logging
- `github.com/algo2go/kite-mcp-oauth` v0.1.0 — admin gating + JWT context
- `github.com/algo2go/kite-mcp-broker, kite-mcp-isttz, kite-mcp-money,
  kite-mcp-templates, kite-mcp-users` v0.1.0 (transitive)
- `github.com/stripe/stripe-go/v82` — Stripe SDK
- `github.com/mark3labs/mcp-go` — MCP middleware contract

All algo2go deps are published modules; no upstream `replace`
directives needed.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed by:
- `app/wire.go` — service wiring
- `app/providers/billing.go` — Fx provider for the DI graph
- `mcp/admin/admin_billing_tools.go` — admin tier override tools
- `kc/ops/admin_edge_billing_test.go` — admin dashboard tests
- 37 files total reference kc/billing types

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF
echo "README.md written"

echo "=== Phase 16: Commit bootstrap ==="
git add LICENSE .github/CODEOWNERS .gitignore README.md
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/billing history extracted
from Sundeepg98/kite-mcp-server's kc/billing/ subtree (2026-05-10)
plus the chore: rewrite module path + workspace-cleanup commit.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original billing
engine + Stripe checkout + tier middleware + webhooks design). Adds
2026 algo2go contributors line for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale (commercial-tier surface
across algo2go projects), public API summary (Tier constants,
Store, Stripe checkout/portal, WebhookHandler, TierGate middleware),
explicit dependency list (algo2go/kite-mcp-alerts/domain/logger/oauth
direct + 5 transitive, all v0.1.0; Stripe SDK + MCP middleware
contract external).

Notable: README explicitly documents that this commit closes the
original Path A.8 halt at commit 71f17eb in the parent repo —
the cluster cliff that motivated the 4-step billing-chain
unblocking sub-project (alerts -> users -> oauth -> billing) is
now fully resolved with this Path A.14 dispatch."

echo "=== Phase 17: Final commit log ==="
git log --oneline | head -5
