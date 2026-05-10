#!/usr/bin/env bash
# Path A.7 — kc/logger bootstrap.

set -euo pipefail

SCRATCH=/tmp/algo2go-logger-extract-dryrun/kite-mcp-logger-extract

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
git add go.mod port.go capture.go noop.go slog_adapter.go logger_test.go
[ -f go.sum ] && git add go.sum
git status --short
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-logger

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/logger to
github.com/algo2go/kite-mcp-logger. kc/logger is a stdlib-only leaf
(log/slog wrapper + interface port + 3 implementations); only
external require is stretchr/testify for tests.

Mechanical rewrite via .research/path-a-logger-rewrite-dryrun.sh on
the kc/logger subtree extracted by path-a-logger-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@f560dcb."
echo ""

echo "=== Phase 12: Write LICENSE (MIT) ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/logger design + Logger
                                  interface + SlogAdapter/Noop/Capture
                                  implementations)
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
# kite-mcp-logger

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-logger.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-logger)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Context-aware structured logger port for the algo2go ecosystem.
Defines the `Logger` interface (over `log/slog`) plus three
implementations: `SlogAdapter` (production wrapper), `Noop` (silent
for tests/init), and `Capture` (in-memory accumulator for assertions).

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
across 100+ files for ctx-threaded structured logging — the
foundational logging primitive for every MCP tool handler, broker
adapter, scheduler tick, audit-log writer, and OAuth callback.

## Why a separate module?

A `Logger` interface is the cleanest cross-cutting primitive — every
algo2go consumer (broker dashboards, monitoring, future broker
adapters, trading bots) needs structured logging with a standard port.
Hosting the interface + adapters as a module:

- Standardizes the ctx-threaded logging contract across consumers
- Lets unrelated projects adopt `Capture` for table-driven tests
  without pulling in kite-mcp-server
- Reduces the dep-graph weight for users who only need logging

## Stability promise

**v0.x — unstable.** The `Logger` interface signatures may evolve.
Pin `v0.1.0` deliberately. v1.0 ships only after the public API
(interface methods + adapter constructors) is reviewed for stability
and at least one external consumer ships against it.

## Install

```bash
go get github.com/algo2go/kite-mcp-logger@v0.1.0
```

## Public API

### Interface (port.go)

```go
type Logger interface {
    Info(ctx context.Context, msg string, args ...any)
    Warn(ctx context.Context, msg string, args ...any)
    Error(ctx context.Context, msg string, args ...any)
    Debug(ctx context.Context, msg string, args ...any)
    With(args ...any) Logger
}
```

### Adapters

- `NewSlogAdapter(*slog.Logger) Logger` — production wrapper
- `NewNoop() Logger` — silent (tests, init paths)
- `NewCapture() *CaptureLogger` — in-memory accumulator with assertion
  helpers (`AssertContains`, `AssertCount`, `Records()`)

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— used in 100+ files including:
- `app/lifecycle.go` — startup/shutdown logging with structured fields
- `kc/usecases/*.go` — every use case threads ctx + Logger
- `kc/audit/store.go` — audit-log persistence with structured records
- `kc/papertrading/engine.go` — paper-trade lifecycle logging
- `kc/alerts/evaluator.go` — alert evaluation tracing

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

Adds project-meta files on top of the kc/logger history extracted
from Sundeepg98/kite-mcp-server's kc/logger/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original Logger
interface + SlogAdapter/Noop/Capture). Adds 2026 algo2go contributors
line for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise (v1.0 only after API review +
external consumer adoption), pkg.go.dev badge, install snippet,
why-a-separate-module rationale (orthogonal logging interface),
public API (Logger interface methods + 3 adapter constructors),
reference consumer link with 100+ file usage breakdown."

echo ""
echo "=== Phase 17: Final commit log ==="
git log --oneline | head -5
echo ""
echo "Total commits: $(git log --oneline | wc -l)"
