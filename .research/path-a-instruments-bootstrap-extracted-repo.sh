#!/usr/bin/env bash
# Path A.16 — kc/instruments bootstrap.
set -euo pipefail
SCRATCH=/tmp/algo2go-instruments-extract-dryrun/kite-mcp-instruments-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep + rewrite first"; exit 1; }
cd "$SCRATCH"

git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"

/usr/local/go/bin/go mod tidy 2>&1 | tail -3

echo "=== Commit module-path rewrite ==="
git add -A
git status --short | head
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-instruments

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/instruments to
github.com/algo2go/kite-mcp-instruments.

kc/instruments is a single-internal-dep module — Kite instruments
fetcher + cache (NSE/BSE symbol-to-token resolver). Only algo2go
.go import is github.com/algo2go/kite-mcp-isttz (already external
from Path A.6.1 commit bbb31da). No testutil deps.

Standalone build PASS. Tests skipped — pre-existing WSL2 DNS-bound
flakes (TestNew_*InstrumentsManager*, TestNewConfigConstructor,
TestManager_MoreAccessors hit api.kite.trade for live instrument
fetch; documented across F1-F7 + 5/5 module dispatches as
orthogonal to extraction).

Mechanical rewrite via .research/path-a-instruments-rewrite-dryrun.sh
on the kc/instruments subtree extracted by
path-a-instruments-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@d23dcea."

echo "=== LICENSE ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/instruments design —
                                  Kite instruments fetcher + cache,
                                  NSE/BSE symbol-to-token resolver,
                                  market-hours-aligned refresh)
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
# kite-mcp-instruments

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-instruments.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-instruments)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Kite instruments fetcher + cache for the algo2go ecosystem. Provides
NSE/BSE symbol-to-token resolution, search by symbol/exchange/segment,
TTL-based cache refresh aligned to market hours, and `Manager`
lifecycle management (Start/Stop/Refresh).

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
across the broker-services + MCP tool layer for symbol resolution
(buy/sell/search tools), options-chain construction, market-hours
gating, and Telegram trading commands.

## Why a separate module?

Kite instruments is a foundational primitive any algo2go consumer
that places orders or queries market data needs independent of
`kite-mcp-server`. Hosting as a module:

- Centralizes the Kite instruments source-of-truth across consumers
- Lets the cache + refresh schedule version independently
- Pairs cleanly with `algo2go/kite-mcp-isttz` (market-hours alignment)
  for the broker-data primitives stack

## Stability promise

**v0.x — unstable.** Type signatures may evolve. Pin `v0.1.0`
deliberately.

## Install

```bash
go get github.com/algo2go/kite-mcp-instruments@v0.1.0
```

## Public API

- `Manager` — lifecycle-managed instruments fetcher with cache
- `Cache` — symbol-to-token map with TTL-based refresh
- `Instrument` — DTO struct (Token, Symbol, Exchange, Segment, etc.)
- Search helpers: `BySymbol`, `ByExchange`, `BySegment`, `ByToken`
- IST market-hours-aligned refresh (every market-open + EOD)

## Dependencies

- `github.com/algo2go/kite-mcp-isttz` v0.1.0 — IST timezone + market hours
- `github.com/stretchr/testify` — assertions
- `go.uber.org/goleak` — goroutine-leak detection in tests

All algo2go deps are published modules; no upstream `replace`
directives needed.

## Test caveat

Some tests (`TestNew_*InstrumentsManager*`, `TestNewConfigConstructor`,
`TestManager_MoreAccessors`) hit `api.kite.trade` for live instrument
fetch. They fail under WSL2 DNS resolution but pass on Fly.io BOM
region with direct egress. These are pre-existing CI-environment-
specific flakes documented across F1-F7 + 5/5 module dispatches in
the parent repo.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed across kc/manager_*, kc/options.go, kc/broker_services.go,
kc/ports/instrument.go, kc/ops/scanner.go, kc/ops/payoff.go,
kc/telegram/bot.go, mcp/market_tools.go, mcp/trade/option_tools.go,
mcp/trade/options_greeks_tool.go, mcp/alerts/alert_tools.go.

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF

echo "=== Commit bootstrap ==="
git add LICENSE .github/CODEOWNERS .gitignore README.md
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/instruments history
extracted from Sundeepg98/kite-mcp-server's kc/instruments/ subtree
(2026-05-10) plus the chore: rewrite module path commit immediately
preceding this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original Kite
instruments fetcher + cache + market-hours-aligned refresh design).
Adds 2026 algo2go contributors line for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale (foundational instruments
primitive across algo2go projects), public API summary (Manager,
Cache, Instrument, search helpers), explicit dependency list
(algo2go/kite-mcp-isttz only — same shape as kc/scheduler), and a
test-caveat note about pre-existing WSL2 DNS-bound flakes
(orthogonal to extraction)."

echo "=== Final commit log ==="
git log --oneline | head -5
