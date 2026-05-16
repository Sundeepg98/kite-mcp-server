#!/usr/bin/env bash
# Path A.12 — kc/users bootstrap.

set -euo pipefail

SCRATCH=/tmp/algo2go-users-extract-dryrun/kite-mcp-users-extract

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
echo "=== Phase 11c: Stage + commit module-path rewrite + stale-artifact cleanup ==="
git add -A
git status --short | head -10
git commit -m "chore: rewrite module path + drop stale root workspace artifact

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/users to
github.com/algo2go/kite-mcp-users.

Drops require + replace for github.com/zerodha/kite-mcp-server
(workspace artifact — kc/users.go has zero actual imports of root
module; verified empirically via grep at extraction time).

kc/users's only real algo2go dep is github.com/algo2go/kite-mcp-alerts,
which is already published at v0.1.0 (Path A.11 @ commit fd9d9fb).

Standalone build PASS. Standalone go test ./... PASS.

Mechanical rewrite via .research/path-a-users-rewrite-dryrun.sh on
the kc/users subtree extracted by path-a-users-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@8094ecc."

echo ""
echo "=== Phase 12: Write LICENSE (MIT) ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/users design — user
                                  identity CRUD + RBAC + bcrypt
                                  password + TOTP MFA + invitations)
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
# kite-mcp-users

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-users.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-users)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

User identity store for the algo2go ecosystem. Provides user CRUD,
role-based access control (admin/trader/viewer), bcrypt-hashed
password storage, TOTP-based MFA enrollment (admin-only), and
invitation tokens. SQLite-backed via the algo2go/kite-mcp-alerts
shared DB.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
for admin login, role gating, MFA enrollment, and invitation flows.

## Why a separate module?

User identity + RBAC + MFA are foundational primitives for any
algo2go consumer that needs admin/trader/viewer separation. Hosting
as a module:

- Centralizes the user store + RBAC contract across consumers
- Lets MFA + bcrypt + TOTP signatures version independently
- Pairs cleanly with `algo2go/kite-mcp-alerts` (shared DB) and
  upstream consumers needing admin gating

## Stability promise

**v0.x — unstable.** Type signatures may evolve as RBAC + MFA
patterns mature. Pin `v0.1.0` deliberately. v1.0 ships only after
the public API (Store, Role/Status constants, MFA enrollment, TOTP
helpers, invitation tokens) is reviewed for stability.

## Install

```bash
go get github.com/algo2go/kite-mcp-users@v0.1.0
```

## Public API (selected)

### Store
- `Store` — user CRUD with `*alerts.DB` backend
- `NewStore(db *alerts.DB) *Store` — constructor
- `Store.Create / Read / Update / Delete / List` — RBAC-aware CRUD

### Role + status constants
- `RoleAdmin`, `RoleTrader`, `RoleViewer`
- `StatusActive`, `StatusSuspended`, `StatusOffboarded`

### MFA (admin-only)
- `Store.SetEncryptionKey(key []byte)` — wires AES-256 key for TOTP
  secret encryption at rest
- `Store.EnrollMFA / VerifyMFA / DisableMFA` — admin TOTP lifecycle
- `ProvisioningURI(secret, issuer, account) string` — RFC 6238 URI
- `VerifyTOTP(secret, code) bool` — TOTP code verification

### Invitations
- `Store.CreateInvitation / RedeemInvitation` — token-based onboarding

## Dependencies

- `github.com/algo2go/kite-mcp-alerts` — shared DB backend
- `github.com/stretchr/testify` — assertions
- `golang.org/x/crypto/bcrypt` — password hashing

All algo2go deps are published modules; no upstream `replace`
directives needed.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed by:
- `app/wire.go`, `app/app.go` — service wiring + admin route gating
- `oauth/handlers_admin_mfa.go` — admin MFA enrollment flow
- `kc/manager_init.go`, `kc/store_registry.go` — service registry
- `kc/usecases/admin_usecases.go`, `family_usecases.go` — use cases
- `kc/ops/admin/render.go` — admin dashboard rendering
- `mcp/admin_tools_test.go` — admin MCP tool tests
- `plugins/rolegate/plugin.go` — RBAC viewer-blocks-write plugin
- `plugins/telegramnotify/plugin.go` — family-admin DM after-hook

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

Adds project-meta files on top of the kc/users history extracted
from Sundeepg98/kite-mcp-server's kc/users/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original user
identity + RBAC + bcrypt password + TOTP MFA + invitations design).
Adds 2026 algo2go contributors line for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale (foundational identity +
RBAC + MFA primitives), public API summary (Store, role/status
constants, MFA helpers, TOTP, invitations), and explicit dependency
list (algo2go/kite-mcp-alerts + bcrypt, all production-buildable
without replace directives)."

echo ""
echo "=== Phase 17: Final commit log ==="
git log --oneline | head -5
