#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-registry-extract-dryrun/kite-mcp-registry-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep + rewrite first"; exit 1; }
cd "$SCRATCH"

git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"

/usr/local/go/bin/go mod tidy 2>&1 | tail -3

git add -A
git status --short | head
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-registry

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/registry to
github.com/algo2go/kite-mcp-registry.

Drops stale 'require zerodha/kite-mcp-server' + 'replace ../..'
workspace artifacts (kc/registry has zero actual root imports in
source — verified empirically). go mod tidy confirms by not
re-adding them.

kc/registry's only real algo2go dep is github.com/algo2go/kite-mcp-alerts
(Path A.11 external). Same shape as kc/users (Path A.12).

Standalone build PASS. Standalone go test ./... PASS.

Mechanical rewrite via .research/path-a-registry-rewrite-dryrun.sh
on the kc/registry subtree extracted by
path-a-registry-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@161301c."

cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/registry design — pre-
                                  registered Kite app credentials
                                  store backed by SQLite)
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
# kite-mcp-registry

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-registry.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-registry)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Pre-registered Kite app credentials store (admin-managed) for the
algo2go ecosystem. Backed by `algo2go/kite-mcp-alerts` shared SQLite
DB. Lets admins onboard Kite developer apps centrally so end-users
don't need to bring their own credentials.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
for admin-managed credential pool + per-user assignment via the
admin dashboard.

## Why a separate module?

Pre-registered credential storage is an admin-side primitive any
algo2go consumer that runs a hosted MCP server may need. Hosting as
a module:

- Centralizes the credential schema + lookup contract
- Pairs with `algo2go/kite-mcp-alerts` (shared DB)

## Stability promise

**v0.x — unstable.** Pin `v0.1.0` deliberately.

## Install

```bash
go get github.com/algo2go/kite-mcp-registry@v0.1.0
```

## Public API

- `Store` — credential CRUD with `*alerts.DB` backend
- `Credential` — DTO struct (Email, APIKey, APISecret, etc.)
- `NewStore(db *alerts.DB) *Store`

## Dependencies

- `github.com/algo2go/kite-mcp-alerts` v0.1.0 — shared DB backend

All algo2go deps published; no upstream `replace` directives needed.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed across kc/credential_service.go, kc/store_registry.go,
kc/manager_*, kc/ops/admin_edge_registry_test.go, kc/ops/handler.go.

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF

git add LICENSE .github/CODEOWNERS .gitignore README.md
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/registry history extracted
from Sundeepg98/kite-mcp-server's kc/registry/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original pre-
registered Kite app credentials store design). Adds 2026 algo2go
contributors line for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale, public API summary
(Store + Credential), and explicit dependency list (algo2go/kite-
mcp-alerts only)."

git log --oneline | head -5
