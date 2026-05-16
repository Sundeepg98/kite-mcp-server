#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-usecases-extract-dryrun/kite-mcp-usecases-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep + rewrite first"; exit 1; }
cd "$SCRATCH"

git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"

/usr/local/go/bin/go mod tidy 2>&1 | tail -3

git add -A
git status --short | head
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-usecases

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/usecases to
github.com/algo2go/kite-mcp-usecases.

Drops stale 'replace zerodha/kite-mcp-server => ../..' AND
'replace zerodha/kite-mcp-server/testutil => ../../testutil'
workspace artifacts (kc/usecases had zero actual root or testutil
imports — both lines were stale carrying-cost from the in-tree
workspace days).

kc/usecases's algo2go deps (11 modules):
  - github.com/algo2go/kite-mcp-alerts (Path A.11)
  - github.com/algo2go/kite-mcp-broker (early Path A)
  - github.com/algo2go/kite-mcp-cqrs (Path A.19)
  - github.com/algo2go/kite-mcp-domain (Path A.10)
  - github.com/algo2go/kite-mcp-eventsourcing (Path A.20)
  - github.com/algo2go/kite-mcp-logger (Path A.7)
  - github.com/algo2go/kite-mcp-money (early Path A)
  - github.com/algo2go/kite-mcp-riskguard (Path A.22 — just landed)
  - github.com/algo2go/kite-mcp-ticker (Path A.18)
  - github.com/algo2go/kite-mcp-users (Path A.12)
  - github.com/algo2go/kite-mcp-watchlist (Path A.15)

Standalone build PASS. Standalone tests PASS.

Mechanical rewrite via .research/path-a-usecases-rewrite-dryrun.sh
on the kc/usecases subtree extracted by
path-a-usecases-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@32fb61c."

cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/usecases design — application
                                  use case layer: place/cancel/modify
                                  orders, portfolio, alerts, oauth bridge,
                                  sessions, tickers, options strategy,
                                  paper trading, family accounts, data
                                  export, telegram events, watchlist,
                                  consent, observability, ports & saga)
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

mkdir -p .github
echo '* @Sundeepg98' > .github/CODEOWNERS

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

cat > README.md <<'README_EOF'
# kite-mcp-usecases

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-usecases.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-usecases)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Application use case layer for the algo2go ecosystem. Implements
write-side CQRS commands + read-side queries across all major
trading domains: orders (place/modify/cancel/close), portfolio
(holdings, P&L, dividends, sectors, returns), alerts (price,
composite, native), oauth bridge, sessions, tickers, options
strategy, paper trading, family accounts, data export, telegram
events, watchlists, consent, observability, plus the Saga + Ports
contracts.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
as the contract layer between the kc/manager state machine and the
MCP tool layer; every user-visible MCP tool dispatches through one
or more use cases here.

## Why a separate module?

The use case layer is the most user-visible surface of the
trading-platform domain — externalizing it completes the "ports &
adapters" architecture migration. Hosting as its own module:

- Centralizes write-side commands + read-side queries
- Lets command/query signatures version independently from the
  monolith
- Decouples saga orchestration from any one runtime
- Provides a stable contract for any consumer wiring algo2go
  trading domain primitives (alerts/orders/portfolio/etc.) into a
  custom MCP server, REST API, or direct embedding

## Stability promise

**v0.x — unstable.** Pin `v0.1.0` deliberately.

## Install

```bash
go get github.com/algo2go/kite-mcp-usecases@v0.1.0
```

## Public API (high-level)

- **Order use cases** — PlaceOrder, ModifyOrder, CancelOrder,
  ClosePosition, CloseAllPositions, ConvertPosition, GetOrders,
  pretrade check
- **Portfolio use cases** — GetPortfolio, P&L, options strategy
- **Alert use cases** — CreateAlert, CreateCompositeAlert,
  TrailingStop, NativeAlert
- **Account use cases** — Account, Admin, Family, OAuthBridge,
  Session, Setup, Consent, DataExport, Margin
- **Domain use cases** — Watchlist, GTT, MF (mutual funds), Ticker,
  Telegram events, Widget, Native alerts
- **Paper trading** — virtual portfolio mode use cases
- **Cross-cutting** — Observability, Pretrade, Saga, Ports
  contracts

## Dependencies (11 algo2go modules)

- `github.com/algo2go/kite-mcp-alerts` v0.1.0
- `github.com/algo2go/kite-mcp-broker` v0.1.0
- `github.com/algo2go/kite-mcp-cqrs` v0.1.0
- `github.com/algo2go/kite-mcp-domain` v0.1.0
- `github.com/algo2go/kite-mcp-eventsourcing` v0.1.0
- `github.com/algo2go/kite-mcp-logger` v0.1.0
- `github.com/algo2go/kite-mcp-money` v0.1.0
- `github.com/algo2go/kite-mcp-riskguard` v0.1.0
- `github.com/algo2go/kite-mcp-ticker` v0.1.0
- `github.com/algo2go/kite-mcp-users` v0.1.0
- `github.com/algo2go/kite-mcp-watchlist` v0.1.0
- `github.com/stretchr/testify` v1.10.0

All algo2go deps published; no upstream `replace` directives needed.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed across 38 .go files: kc/manager_*, kc/ops/payoff.go,
app/*, mcp/* (admin, analytics, common, helpers, paper, plugin
widgets, portfolio, trade, watchlist, tax tools, tools_ext_apps).

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF

git add LICENSE .github/CODEOWNERS .gitignore README.md
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/usecases history extracted
from Sundeepg98/kite-mcp-server's kc/usecases/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original
application use case layer design — orders + portfolio + alerts +
oauth + sessions + tickers + options + paper + family + data export
+ telegram + watchlist + consent + observability + ports + saga).
Adds 2026 algo2go contributors line for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale (most user-visible surface
of the trading-platform domain — completes ports & adapters
migration), public API summary (orders/portfolio/alerts/account/
domain/paper/cross-cutting groupings), and explicit dependency list
(11 algo2go modules + stretchr/testify, all algo2go deps v0.1.0)."

git log --oneline | head -5
