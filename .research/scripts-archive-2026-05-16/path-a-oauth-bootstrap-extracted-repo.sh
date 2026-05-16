#!/usr/bin/env bash
# Path A.13 — oauth bootstrap.

set -euo pipefail

SCRATCH=/tmp/algo2go-oauth-extract-dryrun/kite-mcp-oauth-extract

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
echo "=== Phase 11c: Stage + commit module-path rewrite + workspace cleanup ==="
git add -A
git status --short | head -10
git commit -m "chore: rewrite module path + drop stale workspace artifacts

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/oauth to
github.com/algo2go/kite-mcp-oauth.

Drops stale workspace replace directives:
  - 'replace github.com/zerodha/kite-mcp-server => ../'
  - 'replace github.com/zerodha/kite-mcp-server/testutil => ../testutil'

Both are dead workspace artifacts — oauth has zero actual root or
testutil imports in source (verified empirically via grep at
extraction time). go mod tidy confirms by not re-adding them.

oauth's only real algo2go deps:
  - github.com/algo2go/kite-mcp-templates v0.1.0 (Path A.8')
  - github.com/algo2go/kite-mcp-users v0.1.0 (Path A.12)

Both already published; resolve cleanly via GOPROXY.

Standalone build PASS. Standalone go test ./... PASS.

Mechanical rewrite via .research/path-a-oauth-rewrite-dryrun.sh on
the oauth subtree extracted by path-a-oauth-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@10a1f5f."

echo ""
echo "=== Phase 12: Write LICENSE (MIT) ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original oauth design — OAuth 2.0
                                  flow + JWT sessions + dynamic client
                                  registration + Google SSO + admin
                                  MFA TOTP + ClientStore with AES-256-
                                  GCM encrypted client_secrets)
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
# kite-mcp-oauth

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-oauth.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-oauth)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

OAuth 2.0 + JWT session + dynamic client registration + Google SSO +
admin MFA TOTP for the algo2go ecosystem. Bundles authorize/token/
callback/registration handlers, RequireAuth middleware with token-
expiry detection, JWT issuance/verification, persistent ClientStore
(AES-256-GCM encrypted client_secrets), Google SSO callback flow,
and admin MFA TOTP enrolment + verification.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
for MCP client OAuth, dashboard SSO, admin RBAC gating, and
session lifecycle management.

## Why a separate module?

OAuth 2.0 + JWT + dynamic client registration is a substantial
authentication surface (~16K LOC). Hosting as a module:

- Centralizes the authentication contract across consumers
- Lets OAuth flow + JWT signature + ClientStore version
  independently of business logic
- Pairs cleanly with `algo2go/kite-mcp-templates` (callback HTML)
  and `algo2go/kite-mcp-users` (admin store + MFA backend) for
  the full identity stack

## Stability promise

**v0.x — unstable.** Type signatures and OAuth flow specifics may
evolve as MCP-Remote spec patterns mature. Pin `v0.1.0` deliberately.
v1.0 ships only after the public API (handlers, middleware, JWT
config, ClientStore methods) is reviewed for stability and at least
one external consumer ships against it.

## Install

```bash
go get github.com/algo2go/kite-mcp-oauth@v0.1.0
```

## Public API (selected)

### Handlers
- `NewHandler(...)` — composes the full OAuth handler set
- Authorize / Token / Callback / Registration HTTP handlers
- Browser login + admin MFA enrolment routes

### Middleware
- `RequireAuth(...)` — gates routes with JWT + token-expiry detection
- Returns 401 for unauthenticated AND expired Kite tokens (forces
  seamless re-auth via mcp-remote)

### JWT
- `JWTConfig` — config struct (24h MCP bearer, 7d dashboard cookie)
- `IssueJWT(email) string` / `VerifyJWT(token) (Session, error)`

### ClientStore
- `ClientStore` — persistent OAuth client_id → encrypted client_secret
  registry (AES-256-GCM via HKDF from OAUTH_JWT_SECRET)
- `RegisterClient(...)` / `LookupClient(client_id) (Client, error)`

### Google SSO
- Google SSO callback flow with userinfo + admin role injection

### Admin MFA
- TOTP enrolment + verification (admin-only per kc/users role gate)

## Dependencies

- `github.com/algo2go/kite-mcp-templates` v0.1.0 — callback HTML
- `github.com/algo2go/kite-mcp-users` v0.1.0 — admin store + MFA backend
- `github.com/algo2go/kite-mcp-alerts` v0.1.0 (indirect via users)
- `github.com/algo2go/kite-mcp-broker, kite-mcp-domain, kite-mcp-isttz,
  kite-mcp-logger, kite-mcp-money` (indirect via deeper transitive)
- `github.com/golang-jwt/jwt/v5` — JWT signing
- `golang.org/x/oauth2` — Google SSO flow
- `golang.org/x/crypto` — HKDF + AES-GCM
- `github.com/zerodha/gokiteconnect/v4` — Kite token validation
- `modernc.org/sqlite` — ClientStore backend

All algo2go deps are published modules; no upstream `replace`
directives needed.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed by 100+ files including app/, kc/audit, kc/billing,
kc/ops, kc/papertrading, kc/riskguard, mcp/admin, mcp/middleware,
plugins/rolegate, plugins/telegramnotify.

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

Adds project-meta files on top of the oauth history extracted from
Sundeepg98/kite-mcp-server's oauth/ subtree (2026-05-10) plus the
chore: rewrite module path commit immediately preceding this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original OAuth
2.0 + JWT + dynamic client registration + Google SSO + admin MFA
TOTP + ClientStore design). Adds 2026 algo2go contributors line for
extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale (substantial 16K-LOC
authentication surface centralized across algo2go projects), public
API summary (handlers, middleware, JWT config, ClientStore, Google
SSO, admin MFA), and explicit dependency list (algo2go/kite-mcp-
templates + kite-mcp-users direct; alerts/broker/domain/isttz/
logger/money indirect via users; jwt-go, oauth2, crypto, sqlite,
gokiteconnect external)."

echo ""
echo "=== Phase 17: Final commit log ==="
git log --oneline | head -5
