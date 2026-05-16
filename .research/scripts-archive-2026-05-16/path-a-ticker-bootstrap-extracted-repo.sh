#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-ticker-extract-dryrun/kite-mcp-ticker-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep + rewrite first"; exit 1; }
cd "$SCRATCH"

git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"

/usr/local/go/bin/go mod tidy 2>&1 | tail -3

git add -A
git status --short | head
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-ticker

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/ticker to
github.com/algo2go/kite-mcp-ticker.

kc/ticker's only algo2go deps are subpackages of algo2go/kite-mcp-broker
(ticker subpackage + zerodha subpackage; both same module). broker
is external (Path A inauguration commit 6626812). Transitive
algo2go/kite-mcp-money also external (Path B b92173b).

Standalone build PASS. Standalone go test ./... PASS.

Mechanical rewrite via .research/path-a-ticker-rewrite-dryrun.sh on
the kc/ticker subtree extracted by path-a-ticker-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@3f73a3f."

cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/ticker design — websocket
                                  ticker service, live tick subscription,
                                  leak sentinel, race-flag tests)
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
# kite-mcp-ticker

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-ticker.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-ticker)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Websocket ticker service for the algo2go ecosystem. Provides live
tick subscription via the Kite WebSocket API, callback dispatch,
leak-sentinel goroutine cleanup, and race-flag-on/off lifecycle
testing.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
for live market data subscription, alert evaluation triggers,
trailing-stop monitoring, and dashboard SSE streaming.

## Why a separate module?

Live tick subscription is a foundational primitive for any algo2go
project that consumes streaming market data independent of
`kite-mcp-server`. Hosting as a module:

- Centralizes the websocket lifecycle + callback dispatch contract
- Pairs with `algo2go/kite-mcp-broker` (Kite SDK adapter)

## Stability promise

**v0.x — unstable.** Pin `v0.1.0` deliberately.

## Install

```bash
go get github.com/algo2go/kite-mcp-ticker@v0.1.0
```

## Public API

- `Service` — websocket ticker lifecycle (Start/Stop/Subscribe/Unsubscribe)
- Callback registration for tick + connect + disconnect events
- Leak-sentinel goroutine accounting for tests

## Dependencies

- `github.com/algo2go/kite-mcp-broker` v0.1.0 — broker adapter +
  ticker port + zerodha subpackage
- `github.com/algo2go/kite-mcp-money` v0.1.0 (transitive)
- `github.com/zerodha/gokiteconnect/v4` — Kite SDK
- `github.com/stretchr/testify` — assertions
- `go.uber.org/goleak` — leak detection

All algo2go deps published; no upstream `replace` directives needed.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed across kc/manager_init.go, kc/broker_services.go,
kc/usecases/ticker_usecases.go, kc/ops/data.go, kc/telegram/bot.go,
mcp/alerts/alert_tools.go, mcp/misc/ticker_tools.go,
mcp/trade/trailing_tools.go.

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF

git add LICENSE .github/CODEOWNERS .gitignore README.md
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/ticker history extracted
from Sundeepg98/kite-mcp-server's kc/ticker/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original websocket
ticker service design). Adds 2026 algo2go contributors line for
extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale, public API summary
(Service + callback registration), and explicit dependency list
(algo2go/kite-mcp-broker direct + transitive kite-mcp-money;
gokiteconnect + goleak external)."

git log --oneline | head -5
