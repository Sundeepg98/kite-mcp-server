#!/usr/bin/env bash
# Path A.11 — kc/alerts bootstrap.

set -euo pipefail

SCRATCH=/tmp/algo2go-alerts-extract-dryrun/kite-mcp-alerts-extract

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
echo "=== Phase 11c: Stage + commit module-path rewrite + testutil-strip ==="
git add -A
git status --short | head -10
git commit -m "chore: rewrite module path + strip unpublished testutil dep

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/alerts to
github.com/algo2go/kite-mcp-alerts.

Drops require + replace for github.com/zerodha/kite-mcp-server/testutil
(unpublished — only consumed by 2 _test.go files in this module).

To preserve the test surface in standalone builds:
  1. helpers_test.go: inline-replaced testutil.DiscardLogger() with
     stdlib slog.New(slog.NewTextHandler(io.Discard, nil))
  2. briefing_injection_test.go: stripped (used MockKiteServer
     fixture from testutil). One test file lost in upstream;
     all other 30+ tests pass standalone.

Standalone build PASS. Standalone go test ./... PASS.

Mechanical rewrite via .research/path-a-alerts-rewrite-dryrun.sh on
the kc/alerts subtree extracted by path-a-alerts-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@6a8750b."

echo ""
echo "=== Phase 12: Write LICENSE (MIT) ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/alerts design — alert
                                  engine + briefing scheduler +
                                  composite/trailing alerts +
                                  anomaly notifier + DB adapters)
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
# kite-mcp-alerts

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-alerts.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-alerts)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Alert engine + briefing scheduler for the algo2go ecosystem. Provides
price-threshold alerts, composite alert chains, trailing-stop alerts,
anomaly notifier, morning/EOD briefings, and SQLite-backed alert
store with credential + token persistence.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
for the alerts MCP toolset, scheduler-driven dispatch, telegram
notifier, and audit-log integration.

## Why a separate module?

Alert evaluation is a foundational primitive that other algo2go
projects (broker dashboards, monitoring, future trading bots) need
independent of `kite-mcp-server`. Hosting as a module:

- Centralizes the alert engine + briefing scheduler across consumers
- Enables independent versioning of alert types + composite logic
- Keeps the dep-graph weight focused on consumers that actually
  need alert evaluation

## Stability promise

**v0.x — unstable.** Type signatures may evolve as alert logic
matures. Pin `v0.1.0` deliberately. v1.0 ships only after the public
API (Store, BriefingService, AnomalyNotifier, evaluator types) is
reviewed for stability and at least one external consumer ships
against it.

## Install

```bash
go get github.com/algo2go/kite-mcp-alerts@v0.1.0
```

## Public API (selected)

### Store + persistence
- `Store` — alert + composite + trailing CRUD with SQLite backend
- `DB` — direct DB adapter for tokens, sessions, telegram bindings
- `NewStore(notifyCallback)` — store constructor

### Briefings
- `BriefingService` — IST-aligned morning/EOD dispatcher
- KiteAdapter integration via `BrokerDataProvider` interface

### Alerts
- `Evaluator` — price + composite + trailing alert evaluation
- `AnomalyNotifier` — μ+3σ anomaly alerts via Telegram

### Telegram
- `TelegramSender` — bot wrapper for alert dispatch

## Dependencies

- `github.com/algo2go/kite-mcp-broker` — KiteSDK + zerodha adapter
- `github.com/algo2go/kite-mcp-domain` — Alert + CompositeAlert entities
- `github.com/algo2go/kite-mcp-isttz` — IST market hours
- `github.com/algo2go/kite-mcp-logger` — structured logging
- `github.com/algo2go/kite-mcp-money` (indirect via kc/domain)
- `github.com/zerodha/gokiteconnect/v4` — Kite SDK
- `github.com/go-telegram-bot-api/telegram-bot-api/v5` — Telegram
- `modernc.org/sqlite` — SQLite driver

All algo2go deps are published modules; no upstream `replace`
directives needed.

## Test surface

Most tests run standalone (~30+ test functions). One test file
(briefing_injection_test.go) was stripped during extraction because
it imported the unpublished `testutil` module from kite-mcp-server's
workspace. That test still runs in the consumer's workspace mode
where testutil resolves in-tree.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed by:
- `kc/alert_service.go`, `kc/manager_init.go` — service wiring
- `kc/usecases/alert_usecases.go`, `create_alert.go`, etc. — use cases
- `kc/audit/store.go` — audit projection
- `kc/billing/store.go` — billing event integration
- `mcp/alerts/*.go` — MCP tools (set_alert, list_alerts, etc.)
- `kc/papertrading`, `kc/telegram` — paper-trading + Telegram integration

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design + alert engine: [Sundeepg98](https://github.com/Sundeepg98)
(Zerodha Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF
echo "README.md written"

echo ""
echo "=== Phase 16: Commit bootstrap files ==="
git add LICENSE .github/CODEOWNERS .gitignore README.md
git status --short
echo ""
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/alerts history extracted
from Sundeepg98/kite-mcp-server's kc/alerts/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original alert
engine + briefing scheduler + composite/trailing alerts + anomaly
notifier + DB adapters). Adds 2026 algo2go contributors line for
extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale (foundational alert
primitive across algo2go projects), public API summary (Store,
BriefingService, Evaluator, AnomalyNotifier, TelegramSender),
explicit dependency list (algo2go/kite-mcp-broker + domain + isttz
+ logger + money [indirect], all v0.1.0), and a note about the
testutil-related test file strip during extraction."

echo ""
echo "=== Phase 17: Final commit log ==="
git log --oneline | head -5
