#!/usr/bin/env bash
# Path A — kc/decorators bootstrap (LICENSE + CODEOWNERS + .gitignore + README).
# Mirror of path-b-money-bootstrap-extracted-repo.sh.

set -euo pipefail

SCRATCH=/tmp/algo2go-decorators-extract-dryrun/kite-mcp-decorators-extract

if [ ! -d "$SCRATCH" ]; then
	echo "ERROR: $SCRATCH not found. Run prep + rewrite first."
	exit 1
fi

cd "$SCRATCH"

echo "=== Phase 11: Set local git identity (filter-repo strips it) ==="
git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"
echo "Identity: $(git config user.email) / $(git config user.name)"
echo ""

echo "=== Phase 11b: go mod tidy to regenerate go.sum ==="
/usr/local/go/bin/go mod tidy
echo ""

echo "=== Phase 11c: Commit module-path rewrite as separate commit ==="
git add go.mod go.sum decorators.go decorators_test.go
git status --short
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-decorators

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/decorators to
github.com/algo2go/kite-mcp-decorators. Regenerates go.sum via
go mod tidy (stretchr/testify is the only external require).

Mechanical rewrite via .research/path-a-decorators-rewrite-dryrun.sh
on the kc/decorators subtree extracted by
path-a-decorators-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@9b6209b."
echo ""

echo "=== Phase 12: Write LICENSE (MIT) ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/decorators design)
Copyright (c) 2026 algo2go contributors (extraction, packaging, type
                                          stability promise)

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
echo "=== Phase 13: Write CODEOWNERS ==="
mkdir -p .github
cat > .github/CODEOWNERS <<'CODEOWNERS_EOF'
# Default owner for all files. PRs auto-request review from this owner.
* @Sundeepg98
CODEOWNERS_EOF
echo "CODEOWNERS written"

echo ""
echo "=== Phase 14: Write .gitignore ==="
cat > .gitignore <<'GITIGNORE_EOF'
# Go build artifacts
*.exe
*.dll
*.so
*.dylib
*.bin

# Go test files
*.test
*.prof
coverage.out
coverage.html
*.cov

# Temporary files
*.tmp
*.temp
*.log

# OS generated files
.DS_Store
Thumbs.db

# IDE files
.vscode/
.idea/
*.swp
*.swo
*~

# Go vendor
vendor/

# Local env
.env
.env.local
GITIGNORE_EOF
echo ".gitignore written"

echo ""
echo "=== Phase 15: Write README.md ==="
cat > README.md <<'README_EOF'
# kite-mcp-decorators

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-decorators.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-decorators)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Function decorators for the algo2go ecosystem: retry-with-backoff,
rate-limit, circuit-breaker, and fallback wrappers. Used by
[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
to compose cross-cutting concerns around MCP tool handlers and broker
client calls.

## Why a separate module?

Decorators are a generic primitive — orthogonal to broker semantics,
to MCP tooling, to specific business logic. Hosting them in their own
module:

- Lets unrelated projects in the algo2go family adopt the same retry /
  rate-limit / circuit-breaker semantics without pulling in kite-mcp-server
- Keeps the public API independently versionable (a tightening of retry
  semantics shouldn't bump kite-mcp-server's version)
- Reduces the dep-graph weight of consumers that only need decorators

## Stability promise

**v0.x — unstable.** Function signatures may break between minor versions.
Pin `v0.1.0` deliberately. v1.0 ships only after the public function
surface is reviewed for stability and at least one external consumer
ships against it.

## Install

```bash
go get github.com/algo2go/kite-mcp-decorators@v0.1.0
```

## Public API (decorators.go)

Generic function wrappers via Go 1.25 type parameters:

- `Retry[T](fn, opts)` — exponential backoff retry with configurable
  attempts, base delay, max delay, jitter
- `RateLimit[T](fn, perSecond)` — token-bucket rate limiter
- `CircuitBreaker[T](fn, opts)` — half-open / open / closed state machine
- `Fallback[T](primary, fallback)` — primary-then-fallback chain

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— composes these around `kite-mcp-broker` client calls + `mcp/plugin`
hook chains. The decorator chain is wired in
`mcp/plugin/decorator_chain.go`.

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-06): algo2go contributors.
README_EOF
echo "README.md written"

echo ""
echo "=== Phase 16: Commit bootstrap files ==="
git add LICENSE .github/CODEOWNERS .gitignore README.md
git status --short
echo ""
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/decorators history extracted
from Sundeepg98/kite-mcp-server's kc/decorators/ subtree (2026-05-06)
plus the chore: rewrite module path commit immediately preceding this
one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original kc/decorators
design). Adds 2026 algo2go contributors line for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise (v1.0 only after public function
surface review + external consumer adoption), pkg.go.dev badge, install
snippet, why-a-separate-module rationale (orthogonal cross-cutting
primitives), public API summary."

echo ""
echo "=== Phase 17: Final commit log ==="
git log --oneline | head -5
echo ""
echo "Total commits: $(git log --oneline | wc -l)"
echo ""
echo "=== Bootstrap complete. Next: rename branch to main + push to algo2go/kite-mcp-decorators:main ==="
