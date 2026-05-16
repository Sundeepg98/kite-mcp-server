#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-sectors-extract-dryrun/kite-mcp-sectors-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep + rewrite first"; exit 1; }
cd "$SCRATCH"

git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"

/usr/local/go/bin/go mod tidy 2>&1 | tail -3

git add -A
git status --short | head
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-sectors

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/sectors to
github.com/algo2go/kite-mcp-sectors.

NOTE: kc/sectors had ZERO replace directives in its go.mod (first
such case in the entire Path A arc) — pure stdlib + testify leaf
matching the kc/isttz precedent. Standard cleanup sed lines run
as no-ops.

kc/sectors's algo2go deps:
  - NONE (zero algo2go imports — pure data leaf with NSE/BSE
    symbol-to-sector mapping + NormalizeSymbol + Lookup helpers)
  - testify only (test dep)

Standalone build PASS. Standalone tests PASS in 3ms.

Mechanical rewrite via .research/path-a-sectors-rewrite-dryrun.sh
on the kc/sectors subtree extracted by
path-a-sectors-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@f77b9ad."

cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/sectors design — canonical
                                  NSE/BSE symbol-to-sector mapping
                                  with NormalizeSymbol + Lookup
                                  helpers; replaces duplicate
                                  mappings in mcp/portfolio +
                                  kc/ops; pure stdlib leaf)
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
# kite-mcp-sectors

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-sectors.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-sectors)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Canonical NSE/BSE symbol-to-sector mapping for the algo2go ecosystem.
Maps ~150 symbols across 20+ sectors (Banking, IT, Pharma, FMCG,
Auto, Energy, Telecom, Cement, Metals, etc.) with `NormalizeSymbol`
and `Lookup` helpers.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
across mcp/portfolio/sector_tool.go, kc/ops/scanner.go,
kc/ops/api_portfolio.go, kc/ops/dashboard_render_test.go.

## Why a separate module?

Sector classification is a foundational data primitive applicable
to any algo2go consumer doing portfolio analytics or sector-based
scanning — not just kite-mcp-server. Hosting as its own module:

- Eliminates duplicate mappings (formerly in
  mcp/portfolio.StockSectors + kc/ops.dashboardStockSectors)
- Provides a single source of truth for symbol normalization
- Decouples sector data from any one runtime
- Lets the symbol list version independently as new listings
  appear

## Stability promise

**v0.x — unstable.** Pin `v0.1.0` deliberately.

## Install

```bash
go get github.com/algo2go/kite-mcp-sectors@v0.1.0
```

## Public API

- `StockSectors` — canonical map[string]string (~150 symbols)
- `NormalizeSymbol(s string) string` — strips whitespace, uppercases,
  optionally strips exchange suffixes (.NSE, .BSE)
- `Lookup(symbol string) (sector string, ok bool)` — returns sector
  for a symbol after normalization

## Dependencies

- **NONE** (zero algo2go deps; pure stdlib + testify leaf — first
  such module in the algo2go ecosystem alongside kc/isttz)

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed across 4 .go files: mcp/portfolio/sector_tool.go,
kc/ops/scanner.go, kc/ops/api_portfolio.go,
kc/ops/dashboard_render_test.go.

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.

## Path A inauguration milestone

This is the **27th and FINAL** algo2go module promoted from
`Sundeepg98/kite-mcp-server`'s kc/* externalization arc. After this
release, every kc/* subdirectory with its own go.mod lives as an
external algo2go module. The kite-mcp-server repo becomes the
orchestrator: it imports all 27 algo2go modules and hosts the
root-level kc/manager_*.go runtime wiring, kc/ops/ handlers,
kc/ports/ interfaces, mcp/ tool layer, app/ HTTP+wiring, plugins/,
testutil/, and cmd/.
README_EOF

git add LICENSE .github/CODEOWNERS .gitignore README.md
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/sectors history extracted
from Sundeepg98/kite-mcp-server's kc/sectors/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original
canonical NSE/BSE symbol-to-sector mapping with NormalizeSymbol +
Lookup helpers; pure stdlib leaf). Adds 2026 algo2go contributors
line for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale (foundational data
primitive eliminating duplicate mappings), public API summary
(StockSectors map + NormalizeSymbol + Lookup helpers), zero-deps
fact, and Path A inauguration milestone note (27th and FINAL
algo2go module from kc/* externalization arc)."

git log --oneline | head -5
