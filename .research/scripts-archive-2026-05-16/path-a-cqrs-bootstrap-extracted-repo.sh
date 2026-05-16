#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-cqrs-extract-dryrun/kite-mcp-cqrs-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep + rewrite first"; exit 1; }
cd "$SCRATCH"

git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"

/usr/local/go/bin/go mod tidy 2>&1 | tail -3

git add -A
git status --short | head
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-cqrs

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/cqrs to
github.com/algo2go/kite-mcp-cqrs.

Drops stale 'replace zerodha/kite-mcp-server => ../..' workspace
artifact (kc/cqrs has zero actual root imports in source).

kc/cqrs's algo2go deps:
  - github.com/algo2go/kite-mcp-domain (Path A.10)
  - github.com/algo2go/kite-mcp-logger (Path A.7)
  - transitive: kite-mcp-broker, kite-mcp-isttz, kite-mcp-money

Standalone build PASS. Standalone tests PASS.

Mechanical rewrite via .research/path-a-cqrs-rewrite-dryrun.sh on
the kc/cqrs subtree extracted by path-a-cqrs-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@72303cd."

cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/cqrs design — CommandBus
                                  + dispatcher + query handlers,
                                  in-memory + saga-friendly + read-
                                  side projections)
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
# kite-mcp-cqrs

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-cqrs.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-cqrs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

CQRS infrastructure (CommandBus + dispatcher + query handlers) for
the algo2go ecosystem. Provides in-memory command bus with saga-
friendly transaction envelopes and read-side query handlers for
orders/holdings/positions/widgets.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
across the manager_commands_* + use case layer for write/read
segregation.

## Why a separate module?

CQRS is a foundational architectural primitive any algo2go consumer
that needs explicit read/write segregation can use independent of
`kite-mcp-server`. Hosting as a module:

- Centralizes the CommandBus + QueryDispatcher contract
- Lets command/query interface signatures version independently

## Stability promise

**v0.x — unstable.** Pin `v0.1.0` deliberately.

## Install

```bash
go get github.com/algo2go/kite-mcp-cqrs@v0.1.0
```

## Public API

- `CommandBus` — command dispatch with saga-friendly transaction
  envelopes
- `QueryDispatcher` — read-side projection lookup
- Command/Query interfaces for orders, holdings, positions, widgets

## Dependencies

- `github.com/algo2go/kite-mcp-domain` v0.1.0
- `github.com/algo2go/kite-mcp-logger` v0.1.0
- `github.com/stretchr/testify` — assertions

All algo2go deps published; no upstream `replace` directives needed.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed across kc/manager_commands_*, kc/manager_queries_*,
kc/manager_cqrs_register.go, app/wire.go, kc/usecases/*, mcp/trade/*,
mcp/portfolio/*, mcp/admin/*, mcp/alerts/*, mcp/analytics/*.

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF

git add LICENSE .github/CODEOWNERS .gitignore README.md
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/cqrs history extracted
from Sundeepg98/kite-mcp-server's kc/cqrs/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original CQRS
infrastructure design). Adds 2026 algo2go contributors line for
extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale (foundational CQRS
infrastructure across algo2go projects), public API summary
(CommandBus + QueryDispatcher + command/query interfaces), and
explicit dependency list (algo2go/kite-mcp-domain + kite-mcp-logger,
all v0.1.0)."

git log --oneline | head -5
