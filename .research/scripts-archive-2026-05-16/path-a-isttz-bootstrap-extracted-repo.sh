#!/usr/bin/env bash
# Path A.6.1 — kc/isttz bootstrap.

set -euo pipefail

SCRATCH=/tmp/algo2go-isttz-extract-dryrun/kite-mcp-isttz-extract

if [ ! -d "$SCRATCH" ]; then
	echo "ERROR: $SCRATCH not found. Run prep + rewrite first."
	exit 1
fi

cd "$SCRATCH"

echo "=== Phase 11: Set local git identity ==="
git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"
echo "Identity: $(git config user.email) / $(git config user.name)"
echo ""

echo "=== Phase 11b: go mod tidy ==="
/usr/local/go/bin/go mod tidy 2>&1 | tail -3
echo ""

echo "=== Phase 11c: Commit module-path rewrite ==="
# go mod tidy may have removed go.sum; only add if exists
git add go.mod isttz.go isttz_test.go
[ -f go.sum ] && git add go.sum
git status --short
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-isttz

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/isttz to
github.com/algo2go/kite-mcp-isttz. kc/isttz is a stdlib-only leaf
(only time.Location wrappers + market-hours helpers); no external
deps, no go.sum required after tidy.

Mechanical rewrite via .research/path-a-isttz-rewrite-dryrun.sh
on the kc/isttz subtree extracted by path-a-isttz-prep-dryrun.sh
from Sundeepg98/kite-mcp-server@4ffbba7."
echo ""

echo "=== Phase 12: Write LICENSE (MIT) ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/isttz design)
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
echo "=== Phase 13: Write CODEOWNERS ==="
mkdir -p .github
cat > .github/CODEOWNERS <<'CODEOWNERS_EOF'
* @Sundeepg98
CODEOWNERS_EOF
echo "CODEOWNERS written"

echo ""
echo "=== Phase 14: Write .gitignore ==="
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
echo ".gitignore written"

echo ""
echo "=== Phase 15: Write README.md ==="
cat > README.md <<'README_EOF'
# kite-mcp-isttz

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-isttz.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-isttz)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

IST (Indian Standard Time) timezone helpers for the algo2go ecosystem.
Provides `time.Location` wrappers for `Asia/Kolkata` plus market-hours
helpers (NSE/BSE 09:15-15:30 IST) for Indian retail trading platforms.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
for scheduler tick alignment, briefing dispatch windows, and
audit-log timestamp formatting.

## Why a separate module?

IST + market-hours are orthogonal time primitives — usable by any
algo2go project (broker dashboards, alerts, monitoring, future broker
adapters) independent of `kite-mcp-server`. Centralizing as a module:

- Lets IST helpers version independently of consumer business logic
- Encourages consistent market-hours semantics across consumers
- Keeps the dep-graph weight minimal for users who only need time
  helpers

## Stability promise

**v0.x — unstable.** Function signatures may break between minor
versions. Pin `v0.1.0` deliberately. v1.0 ships only after the public
function surface is reviewed for stability.

## Install

```bash
go get github.com/algo2go/kite-mcp-isttz@v0.1.0
```

## Public API

- `Location() *time.Location` — returns Asia/Kolkata Location, panics on
  load failure (unrecoverable system tzdata absence)
- `Now() time.Time` — current time in IST
- Helpers for market-open / market-close / weekend detection (see
  `isttz.go` and pkg.go.dev for details)

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— used across:
- `kc/scheduler` for cron-style tick alignment
- `kc/alerts/briefing.go` for morning/EOD dispatch windows
- `kc/instruments/manager.go` for cache-refresh windows
- `kc/domain/session.go` for IST timestamp formatting

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

Adds project-meta files on top of the kc/isttz history extracted from
Sundeepg98/kite-mcp-server's kc/isttz/ subtree (2026-05-10) plus the
chore: rewrite module path commit immediately preceding this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original kc/isttz
design). Adds 2026 algo2go contributors line for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise (v1.0 only after API review),
pkg.go.dev badge, install snippet, why-a-separate-module rationale
(orthogonal IST + market-hours primitives), public API summary."

echo ""
echo "=== Phase 17: Final commit log ==="
git log --oneline | head -7
echo ""
echo "Total commits: $(git log --oneline | wc -l)"
