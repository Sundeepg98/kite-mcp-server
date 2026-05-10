#!/usr/bin/env bash
# Path A.6.2 — kc/scheduler bootstrap.

set -euo pipefail

SCRATCH=/tmp/algo2go-scheduler-extract-dryrun/kite-mcp-scheduler-extract

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
git add go.mod scheduler.go scheduler_test.go provider.go provider_test.go edge_test.go helpers_test.go leak_sentinel_test.go
[ -f go.sum ] && git add go.sum
git status --short
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-scheduler

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/scheduler to
github.com/algo2go/kite-mcp-scheduler. Drops the relative
'replace github.com/algo2go/kite-mcp-isttz => ../isttz' directive
that worked in workspace mode but doesn't apply to the standalone
repo — the upstream require pins algo2go/kite-mcp-isttz v0.1.0
which resolves cleanly via GOPROXY (algo2go/kite-mcp-isttz was
published in Path A.6.1, just before this commit).

Mechanical rewrite via .research/path-a-scheduler-rewrite-dryrun.sh
on the kc/scheduler subtree extracted by
path-a-scheduler-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@bbb31da (= the kc/isttz Phase A canary
landing commit, immediate parent of this scheduler promotion)."
echo ""

echo "=== Phase 12: Write LICENSE (MIT) ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/scheduler design)
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
# kite-mcp-scheduler

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-scheduler.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-scheduler)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Goroutine-safe scheduler for the algo2go ecosystem. Provides
cron-style + interval ticker primitives with Clock injection for
deterministic testing, lifecycle management (Start/Stop), and
goroutine-leak sentinels.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
for IST-aligned background dispatch (morning briefings, EOD P&L,
audit-log retention sweeps, Telegram dispatch loops, alert evaluation
ticks).

## Why a separate module?

Background scheduling is an orthogonal infrastructure primitive —
usable by any algo2go project (broker dashboards, monitoring,
broker-adapter health checks, future trading bots) independent of
`kite-mcp-server`. Centralizing as a module:

- Lets the Clock-injection pattern + leak sentinels be shared
  consistently across consumers
- Encourages deterministic-test discipline (Clock injection +
  goroutine-leak detection together)
- Keeps the dep-graph weight minimal for users who only need
  scheduling

## Stability promise

**v0.x — unstable.** Public types may break between minor versions.
Pin `v0.1.0` deliberately. v1.0 ships only after the public API is
reviewed for stability.

## Install

```bash
go get github.com/algo2go/kite-mcp-scheduler@v0.1.0
```

## Dependencies

- `github.com/algo2go/kite-mcp-isttz` — IST timezone wrapper for
  market-hours-aligned ticks
- `go.uber.org/goleak` — goroutine-leak detection in tests
- `github.com/stretchr/testify` — assertions

## Public API (scheduler.go)

- `Scheduler` — lifecycle-managed scheduler with Start/Stop semantics
- `Clock` interface — Now() + tick scheduling; for deterministic tests
  inject `MockClock`
- Tick registration helpers: every-N-minutes, daily-at-IST,
  weekday-at-IST patterns

See pkg.go.dev for full type docs.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— wires Scheduler in `app/providers/scheduler.go` and consumes via:
- Morning briefing dispatch (9:00 IST weekdays)
- EOD P&L snapshot (15:35 IST weekdays)
- Alert evaluation tick (every 30s during market hours)
- Audit-log retention sweep (3:00 IST daily)

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF
echo "README.md written"

echo ""
echo "=== Phase 16: Commit bootstrap files ==="
git add LICENSE .github/CODEOWNERS .gitignore README.md
git status --short
echo ""
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/scheduler history extracted
from Sundeepg98/kite-mcp-server's kc/scheduler/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright. Adds 2026 algo2go
contributors line for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale (orthogonal scheduling
infrastructure with Clock injection + goleak sentinels), public API
summary, and dependency on algo2go/kite-mcp-isttz for IST-aligned
ticks."

echo ""
echo "=== Phase 17: Final commit log ==="
git log --oneline | head -5
echo ""
echo "Total commits: $(git log --oneline | wc -l)"
