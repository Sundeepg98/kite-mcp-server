#!/usr/bin/env bash
# Path A.10 — kc/domain bootstrap.

set -euo pipefail

SCRATCH=/tmp/algo2go-domain-extract-dryrun/kite-mcp-domain-extract

if [ ! -d "$SCRATCH" ]; then
	echo "ERROR: $SCRATCH not found. Run prep + rewrite first."
	exit 1
fi

cd "$SCRATCH"

echo "=== Phase 11: Set local git identity ==="
git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"
echo ""

echo "=== Phase 11b: go mod tidy ==="
/usr/local/go/bin/go mod tidy 2>&1 | tail -3
echo ""

echo "=== Phase 11c: Commit module-path rewrite ==="
git add go.mod $(find . -maxdepth 1 -name '*.go' -type f)
[ -f go.sum ] && git add go.sum
git status --short | head -10
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-domain

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/domain to
github.com/algo2go/kite-mcp-domain. kc/domain has 3 internal deps
(broker, isttz, money) — all already external on algo2go @ v0.1.0,
so the upstream go.mod requires resolve cleanly via GOPROXY.

Two non-load-bearing 'zerodha/kite-mcp-server' references remain:
  1. session.go lines 31, 33 — comment block referring to old
     module paths in package documentation
  2. dep_cycle_test.go lines 26, 55 — string literal in an
     architectural-rule test that checks for unexpected zerodha/
     in-tree imports (test trivially passes post-cutover since
     all deps moved to algo2go; no functional regression)

Both are documentation/test-string artifacts, not import statements.
Standalone build + test PASSES.

Mechanical rewrite via .research/path-a-domain-rewrite-dryrun.sh
on the kc/domain subtree extracted by path-a-domain-prep-dryrun.sh
from Sundeepg98/kite-mcp-server@f16ad85."
echo ""

echo "=== Phase 12: Write LICENSE (MIT) ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/domain DDD value-object
                                  + entity design — Money, Quantity,
                                  Order, Position, Holding, Profile,
                                  Session, Alert, Family, Glossary +
                                  domain events)
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

echo ""
echo "=== Phase 13: CODEOWNERS ==="
mkdir -p .github
echo '* @Sundeepg98' > .github/CODEOWNERS

echo ""
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

echo ""
echo "=== Phase 15: README.md ==="
cat > README.md <<'README_EOF'
# kite-mcp-domain

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-domain.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-domain)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Domain-Driven Design (DDD) value objects + entities for the algo2go
ecosystem. Defines the canonical shape of trading-domain types
(Money, Quantity, Order, Position, Holding, Profile, Session, Alert,
Family, Glossary) plus domain events (TierChangedEvent,
OrderPlacedEvent, etc.) and an EventDispatcher.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
across 165+ files for trading domain modeling — riskguard checks,
billing tier changes, audit projections, paper-trading engine,
order workflows, alert evaluations, etc.

## Why a separate module?

Domain types are the canonical interop layer between trading-domain
consumers (broker dashboards, monitoring, future broker adapters,
tier billing). Hosting as a module:

- Centralizes the trading-domain vocabulary across consumers
- Lets DDD entities + value objects version independently of
  application logic
- Pairs cleanly with `algo2go/kite-mcp-broker` (DTO interop) and
  `algo2go/kite-mcp-money` (Money type) for a coherent
  trading-types stack

## Stability promise

**v0.x — unstable.** Type signatures may evolve as DDD review
surfaces issues. Pin `v0.1.0` deliberately. v1.0 ships only after
the public type surface (entities + value objects + events) is
reviewed for stability and at least one external consumer ships
against it.

## Install

```bash
go get github.com/algo2go/kite-mcp-domain@v0.1.0
```

## Public API (selected highlights)

### Value objects
- `Money` — wraps `algo2go/kite-mcp-money.Money` with domain semantics
- `Quantity` — order size with sign + precision
- `Specs` — instrument lookup keys

### Entities
- `Order` — order aggregate with invariants (CanPlace, IsTerminal, ...)
- `Position` — open/closed positions with PnL projection
- `Holding` — long-term holdings with FIFO cost basis
- `Profile` — user profile with tier + region
- `Session` — auth session with IST-timezone expiry
- `Alert` / `CompositeAlert` — threshold + multi-condition alerts
- `Family` — family-mode subscription ledger

### Domain events
- `TierChangedEvent`, `OrderPlacedEvent`, `OrderCancelledEvent`,
  `OrderFilledEvent`, `AlertTriggeredEvent`, ...
- `EventDispatcher` for in-process pub/sub

## Dependencies

- `github.com/algo2go/kite-mcp-broker` — DTO interop (Order/Position/Holding/Profile)
- `github.com/algo2go/kite-mcp-isttz` — IST timezone helper for Session
- `github.com/algo2go/kite-mcp-money` — Money value object
- `github.com/stretchr/testify` — assertions

All deps are algo2go-published modules; no upstream `replace`
directives needed.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed across:
- `kc/usecases/*.go` — every use case threads domain types
- `kc/eventsourcing/*.go` — aggregates project domain events
- `kc/riskguard/*.go` — checks operate on Order/Position
- `kc/billing/*.go` — TierChangedEvent + Money for tier accounting
- `kc/alerts/*.go` — Alert entity + AlertTriggeredEvent
- `kc/papertrading/*.go` — Order lifecycle in virtual portfolio
- `kc/audit/*.go` — domain-event projection for audit trail
- `mcp/trade/*.go`, `mcp/analytics/*.go` — domain types in tool args/returns

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original DDD design + entity implementations: [Sundeepg98](https://github.com/Sundeepg98)
(Zerodha Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF
echo "README.md written"

echo ""
echo "=== Phase 16: Commit bootstrap files ==="
git add LICENSE .github/CODEOWNERS .gitignore README.md
git status --short
echo ""
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/domain history extracted
from Sundeepg98/kite-mcp-server's kc/domain/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original DDD
value-object + entity design + domain events). Adds 2026 algo2go
contributors line for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise (type signatures may evolve
as DDD review continues), pkg.go.dev badge, install snippet,
why-a-separate-module rationale (canonical trading-domain interop
layer), public API summary (entities + value objects + events),
explicit dependency list (algo2go/kite-mcp-broker + isttz + money,
all v0.1.0), and 165+ file consumer breakdown."

echo ""
echo "=== Phase 17: Final commit log ==="
git log --oneline | head -5
echo ""
echo "Total commits: $(git log --oneline | wc -l)"
