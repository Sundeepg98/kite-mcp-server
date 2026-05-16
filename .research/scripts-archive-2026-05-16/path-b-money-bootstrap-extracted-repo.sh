#!/usr/bin/env bash
# Path B alt-1 A.2.2-A.2.3 bootstrap for kc/money.
# Mirror of path-a-bootstrap-extracted-repo.sh adapted for money.
# Adds LICENSE + CODEOWNERS + .gitignore + README to the extracted repo as
# a bootstrap commit on top of the 2-commit kc/money history, then sets up
# the remote.
#
# Pre-condition: path-b-money-prep-dryrun.sh + path-b-money-rewrite-dryrun.sh
# already executed.

set -euo pipefail

SCRATCH=/tmp/algo2go-money-extract-dryrun/kite-mcp-money-extract

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

echo "=== Phase 11b: Run go mod tidy (rewrite created stale go.sum) ==="
/usr/local/go/bin/go mod tidy
echo ""

echo "=== Phase 11c: Commit module-path rewrite as separate commit ==="
git add go.mod go.sum money.go money_property_test.go money_test.go
git status --short
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-money

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/money to
github.com/algo2go/kite-mcp-money. Regenerates go.sum via go mod tidy
(no functional changes — kc/money is a leaf module with only
stretchr/testify as a real require, plus indirects).

Mechanical rewrite via .research/path-b-money-rewrite-dryrun.sh on the
kc/money subtree extracted by path-b-money-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@3d2468f."
echo ""

echo "=== Phase 12: Write LICENSE (MIT) ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/money DDD-leaf design)
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
# kite-mcp-money

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-money.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-money)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Currency-aware decimal money type for the algo2go ecosystem. Used by
[`algo2go/kite-mcp-broker`](https://github.com/algo2go/kite-mcp-broker)
and consumers like
[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server).

## Why a separate module?

`Money` is a DDD-leaf primitive shared between the broker port (which
defines `Order.PnL` / `Holding.PnL` / `Position.PnL` as `Money`) and
downstream consumers (riskguard checks, dashboard renders, audit
projections). Hosting it in its own module:

- Lets `kite-mcp-broker`'s `go.mod` declare `require kite-mcp-money` as
  a real upstream dep — no upstream-relative `replace` workarounds
- Keeps the type identity stable across module-fetch boundaries (a
  consumer of `broker` and a direct consumer of `money` see the same
  `Money` type, because both import the same module path)
- Makes the type independently versionable from broker.

## Stability promise

**v0.x — unstable.** Method signatures may break between minor versions.
Pin `v0.1.0` deliberately. v1.0 ships only after the public method
surface (`Add`, `Sub`, `Mul`, `Div`, `Float64`, `IsPositive`,
`IsNegative`, `IsZero`, `MarshalJSON`, etc.) is reviewed for stability.

## Install

```bash
go get github.com/algo2go/kite-mcp-money@v0.1.0
```

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original DDD-leaf extraction: [Sundeepg98](https://github.com/Sundeepg98)
(Zerodha Tech). Multi-module promotion (2026-05-06): algo2go contributors.
README_EOF
echo "README.md written"

echo ""
echo "=== Phase 16: Stage + commit bootstrap files ==="
git add LICENSE .github/CODEOWNERS .gitignore README.md
git status --short
echo ""
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the 2-commit history extracted from
Sundeepg98/kite-mcp-server's kc/money/ subtree (2026-05-06) plus the
chore: rewrite module path commit immediately preceding this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original kc/money
DDD-leaf design). Adds 2026 algo2go contributors line for extraction
+ packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise (v1.0 only after public method
surface review), pkg.go.dev badge, install snippet, why-a-separate-
module rationale tying the existence to the broker module's transitive
type-identity requirement."

echo ""
echo "=== Phase 17: Final commit log (history visible to algo2go/kite-mcp-money) ==="
git log --oneline | head -5
echo ""
echo "Total commits: $(git log --oneline | wc -l) (2 history + 1 rewrite + 1 bootstrap = 4 expected)"
echo ""
echo "=== Bootstrap complete. Next: rename branch + push to algo2go/kite-mcp-money:main ==="
