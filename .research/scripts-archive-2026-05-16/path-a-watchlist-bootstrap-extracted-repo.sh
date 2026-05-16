#!/usr/bin/env bash
# Path A.15 — kc/watchlist bootstrap.
set -euo pipefail
SCRATCH=/tmp/algo2go-watchlist-extract-dryrun/kite-mcp-watchlist-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep + rewrite first"; exit 1; }
cd "$SCRATCH"

git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"

/usr/local/go/bin/go mod tidy 2>&1 | tail -3

echo "=== Commit module-path rewrite ==="
git add -A
git status --short | head
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-watchlist

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/watchlist to
github.com/algo2go/kite-mcp-watchlist.

kc/watchlist is a true leaf — zero internal kc/* deps, zero
algo2go transitive deps. Only stdlib + uuid + testify + sqlite
external. Same shape as kc/legaldocs / kc/decorators.

Standalone build PASS. Standalone go test ./... PASS.

Mechanical rewrite via .research/path-a-watchlist-rewrite-dryrun.sh
on the kc/watchlist subtree extracted by
path-a-watchlist-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@9259e1c."

echo "=== LICENSE ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/watchlist design — per-
                                  user watchlist CRUD over SQLite)
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
# kite-mcp-watchlist

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-watchlist.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-watchlist)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Per-user watchlist CRUD with SQLite backend for the algo2go
ecosystem. Pure leaf — zero internal kc/* deps, zero algo2go
transitive deps. Stdlib + `google/uuid` + `modernc.org/sqlite`
(pure-Go, no CGO) only.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
for the watchlist MCP toolset (add/remove/list watchlist symbols
per user, with cross-device sync via the SQLite store).

## Why a separate module?

Per-user watchlist CRUD is a foundational primitive any algo2go
project (broker dashboards, monitoring, future trading bots) may
need independent of `kite-mcp-server`. Hosting as a module:

- Centralizes the watchlist storage contract across consumers
- Lets the SQLite schema + migrations version independently
- Pure leaf — zero deps on other algo2go modules; install cost
  is just the module + sqlite driver

## Stability promise

**v0.x — unstable.** Type signatures may evolve. Pin `v0.1.0`
deliberately.

## Install

```bash
go get github.com/algo2go/kite-mcp-watchlist@v0.1.0
```

## Public API

- `Store` — per-user watchlist CRUD (`Add`, `Remove`, `List`,
  `Clear`, `Count`)
- `DB` — schema + migrations + queries
- `NewStore(db *DB) *Store` — constructor
- `Item` — watchlist entry with uuid primary key

## Dependencies

- `github.com/google/uuid` — primary keys
- `github.com/stretchr/testify` — assertions
- `modernc.org/sqlite` — pure-Go SQLite driver

No internal kc/* or algo2go transitive deps.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed by:
- `kc/store_registry.go`, `kc/manager_struct.go`, `kc/manager_init.go` — service wiring
- `kc/usecases/watchlist_usecases.go` — watchlist use cases
- `kc/telegram/bot.go`, `kc/telegram/commands_test.go` — Telegram integration
- `mcp/watchlist_tools.go` — MCP tools (add_to_watchlist, list_watchlist, etc.)

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF

echo "=== Commit bootstrap ==="
git add LICENSE .github/CODEOWNERS .gitignore README.md
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/watchlist history extracted
from Sundeepg98/kite-mcp-server's kc/watchlist/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original per-user
watchlist CRUD design). Adds 2026 algo2go contributors line for
extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale (foundational watchlist
primitive across algo2go projects), public API summary (Store, DB,
Item types), and explicit dependency list (only uuid + testify +
sqlite — zero algo2go transitive deps)."

echo "=== Final commit log ==="
git log --oneline | head -5
