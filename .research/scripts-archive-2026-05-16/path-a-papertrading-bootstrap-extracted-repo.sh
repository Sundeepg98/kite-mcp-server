#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-papertrading-extract-dryrun/kite-mcp-papertrading-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep + rewrite first"; exit 1; }
cd "$SCRATCH"

git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"

/usr/local/go/bin/go mod tidy 2>&1 | tail -3

git add -A
git status --short | head
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-papertrading

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/papertrading to
github.com/algo2go/kite-mcp-papertrading.

Drops stale 'replace zerodha/kite-mcp-server => ../..' AND
'replace zerodha/kite-mcp-server/testutil => ../../testutil'
workspace artifacts (kc/papertrading had zero actual root or testutil
imports — both lines were stale carrying-cost from the in-tree
workspace days).

kc/papertrading's algo2go deps:
  - github.com/algo2go/kite-mcp-alerts (Path A.11)
  - github.com/algo2go/kite-mcp-broker (early Path A; incl. /mock subpkg)
  - github.com/algo2go/kite-mcp-domain (Path A.10)
  - github.com/algo2go/kite-mcp-logger (Path A.7)
  - github.com/algo2go/kite-mcp-oauth (Path A.13)
  - github.com/algo2go/kite-mcp-riskguard (Path A.22 — just landed)

Standalone build PASS. Standalone tests PASS.

Mechanical rewrite via .research/path-a-papertrading-rewrite-dryrun.sh
on the kc/papertrading subtree extracted by
path-a-papertrading-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@d32b2a2."

cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/papertrading design — virtual
                                  portfolio engine: middleware
                                  interception, in-memory store with
                                  foreign-key integrity, background
                                  LIMIT fill monitor, leak sentinel,
                                  riskguard integration, money types)
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
# kite-mcp-papertrading

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-papertrading.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-papertrading)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Paper trading virtual portfolio engine for the algo2go ecosystem.
Provides middleware interception of order placement to redirect to
an in-memory portfolio with ₹1 crore default cash, background
monitor for LIMIT fills, store with foreign-key integrity,
leak-sentinel for goroutine cleanup, and integration with
`kite-mcp-riskguard` for the same pre-trade safety checks as live
trading.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
across kc/manager_*, app/*, kc/ops/* (paper handlers), kc/telegram/*
(paper-mode commands), mcp/* (paper tool group, helpers test).

## Why a separate module?

Paper trading is an end-user feature applicable to any algo2go
consumer that wants risk-free strategy testing without committing
real capital. Hosting as its own module:

- Centralizes the Engine + Store + Monitor + Middleware contracts
- Lets virtual-portfolio policies (default cash, slippage rules,
  fill-watcher cadence) version independently
- Decouples paper-mode middleware from any one MCP server runtime

## Stability promise

**v0.x — unstable.** Pin `v0.1.0` deliberately.

## Install

```bash
go get github.com/algo2go/kite-mcp-papertrading@v0.1.0
```

## Public API

- `Engine` — orchestrates order placement, fills, P&L, cash
  accounting
- `Store` — in-memory portfolio + orders + positions with
  foreign-key integrity
- `Monitor` — background LIMIT fill watcher; configurable cadence
- `Middleware` — middleware-mode interception of `place_order`
  tool calls; routes to engine instead of broker
- Riskguard integration — same 8+ safety checks as live trading

## Dependencies

- `github.com/algo2go/kite-mcp-alerts` v0.1.0
- `github.com/algo2go/kite-mcp-broker` v0.1.0 (incl. /mock subpkg)
- `github.com/algo2go/kite-mcp-domain` v0.1.0
- `github.com/algo2go/kite-mcp-logger` v0.1.0
- `github.com/algo2go/kite-mcp-oauth` v0.1.0
- `github.com/algo2go/kite-mcp-riskguard` v0.1.0
- `github.com/stretchr/testify` v1.10.0

All algo2go deps published; no upstream `replace` directives needed.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed across 18 .go files: kc/manager_*, kc/interfaces.go,
kc/broker_services.go, kc/ops/* (paper handlers, dashboard
credentials, admin dashboard, api handlers), kc/telegram/* (handler,
commands, bot edge), app/wire.go, app/app.go, mcp/helpers_test.go,
mcp/tools_session_test.go.

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF

git add LICENSE .github/CODEOWNERS .gitignore README.md
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/papertrading history extracted
from Sundeepg98/kite-mcp-server's kc/papertrading/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original virtual-
portfolio engine design — middleware interception, in-memory store
with foreign-key integrity, background LIMIT fill monitor, leak
sentinel, riskguard integration, money types). Adds 2026 algo2go
contributors line for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale (end-user feature for
risk-free strategy testing), public API summary (Engine + Store +
Monitor + Middleware + Riskguard integration), and explicit
dependency list (algo2go/kite-mcp-alerts + kite-mcp-broker +
kite-mcp-domain + kite-mcp-logger + kite-mcp-oauth + kite-mcp-
riskguard, all v0.1.0)."

git log --oneline | head -5
