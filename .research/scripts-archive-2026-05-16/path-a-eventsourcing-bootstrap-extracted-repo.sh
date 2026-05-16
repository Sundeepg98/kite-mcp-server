#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-eventsourcing-extract-dryrun/kite-mcp-eventsourcing-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep + rewrite first"; exit 1; }
cd "$SCRATCH"

git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"

/usr/local/go/bin/go mod tidy 2>&1 | tail -3

git add -A
git status --short | head
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-eventsourcing

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/eventsourcing to
github.com/algo2go/kite-mcp-eventsourcing.

Drops stale 'replace zerodha/kite-mcp-server => ../..' workspace
artifact (kc/eventsourcing has zero actual root imports in source).

kc/eventsourcing's algo2go deps:
  - github.com/algo2go/kite-mcp-alerts (Path A.11)
  - github.com/algo2go/kite-mcp-broker (Path A early)
  - github.com/algo2go/kite-mcp-domain (Path A.10)
  - transitive: kite-mcp-isttz, kite-mcp-logger, kite-mcp-money

Standalone build PASS. Standalone tests PASS.

Mechanical rewrite via .research/path-a-eventsourcing-rewrite-dryrun.sh
on the kc/eventsourcing subtree extracted by
path-a-eventsourcing-prep-dryrun.sh from Sundeepg98/kite-mcp-server@17c0fca."

cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/eventsourcing design — domain
                                  event aggregate roots + outbox +
                                  projections + event store)
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
# kite-mcp-eventsourcing

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-eventsourcing.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-eventsourcing)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Event sourcing primitives — domain event aggregate roots (alerts,
orders, positions, sessions), outbox pattern for at-least-once event
delivery, read-side projections, and event store contract.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
to back the kc/manager state machine + the kc/usecases CQRS write
side.

## Why a separate module?

Event sourcing is a foundational primitive — any algo2go consumer
needing the aggregate-root + outbox + projection pattern can adopt it
without depending on `kite-mcp-server`'s broker integration. Hosting
as its own module:

- Centralizes the EventStore + Aggregate + Projection contracts
- Lets event-payload schemas version independently
- Keeps the outbox runtime decoupled from any one broker

## Stability promise

**v0.x — unstable.** Pin `v0.1.0` deliberately.

## Install

```bash
go get github.com/algo2go/kite-mcp-eventsourcing@v0.1.0
```

## Public API

- `Aggregate` — base interface for event-sourced aggregates
- `AlertAggregate`, `OrderAggregate`, `PositionAggregate`,
  `SessionAggregate` — domain aggregate roots
- `Store` — event store with append + load
- `Projection` — read-side materialized view contract
- `Outbox` — at-least-once event delivery integration

## Dependencies

- `github.com/algo2go/kite-mcp-alerts` v0.1.0
- `github.com/algo2go/kite-mcp-broker` v0.1.0
- `github.com/algo2go/kite-mcp-domain` v0.1.0
- `github.com/google/uuid` — event/aggregate IDs
- `github.com/stretchr/testify` — test assertions

All algo2go deps published; no upstream `replace` directives needed.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed across kc/eventing_service.go, kc/manager_init.go,
kc/manager_orders_fallback.go, kc/manager_reconstitution.go,
kc/manager_struct.go, kc/usecases/*, app/adapters.go, app/app.go,
app/wire.go, mcp/alert_history_tool_test.go,
mcp/order_history_tool_test.go, mcp/position_history_tool_test.go.

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF

git add LICENSE .github/CODEOWNERS .gitignore README.md
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/eventsourcing history extracted
from Sundeepg98/kite-mcp-server's kc/eventsourcing/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original event
sourcing infrastructure design). Adds 2026 algo2go contributors line
for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale (foundational event
sourcing primitives), public API summary (Aggregate +
4 aggregate roots + Store + Projection + Outbox), and explicit
dependency list (algo2go/kite-mcp-alerts + kite-mcp-broker +
kite-mcp-domain, all v0.1.0)."

git log --oneline | head -5
