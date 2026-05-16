#!/usr/bin/env bash
# Path A.8' — kc/templates bootstrap.

set -euo pipefail

SCRATCH=/tmp/algo2go-templates-extract-dryrun/kite-mcp-templates-extract

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
git add go.mod templates.go
[ -f go.sum ] && git add go.sum
git status --short
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-templates

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/templates to
github.com/algo2go/kite-mcp-templates. kc/templates is a stdlib-only
embed leaf (single 11-LOC templates.go using go:embed to surface
60+ HTML files + dashboard-base.css + appbridge.js + static/* for
serving from the HTTP layer + MCP App widgets).

Mechanical rewrite via .research/path-a-templates-rewrite-dryrun.sh
on the kc/templates subtree extracted by
path-a-templates-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@71f17eb."
echo ""

echo "=== Phase 12: Write LICENSE (MIT) ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/templates design + HTML
                                  templates + appbridge.js + CSS)
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
# kite-mcp-templates

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-templates.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-templates)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Embedded HTML templates + static assets for the algo2go ecosystem.
Surfaces 60+ HTML templates (dashboard, landing, admin pages, MCP App
widgets, OAuth callback) plus CSS + appbridge.js + static/* via Go's
`embed` directive.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
for serving the dashboard, OAuth flow, and MCP App widget shells.

## Why a separate module?

HTML/CSS/JS templates are orthogonal UI primitives — usable by any
algo2go project (broker dashboards, monitoring, future broker
adapters) independent of `kite-mcp-server`. Hosting as a module:

- Centralizes template source-of-truth across consumers
- Lets template content version independently of server logic
- Reduces dep-graph weight for users who only need template
  rendering bytes

## Stability promise

**v0.x — unstable.** Embedded files may be added/removed/renamed
between minor versions; `var FS embed.FS` signature is stable but
file paths inside the FS aren't. Pin `v0.1.0` deliberately.
v1.0 ships only after the embedded-file inventory is reviewed for
stability.

## Install

```bash
go get github.com/algo2go/kite-mcp-templates@v0.1.0
```

## Public API (templates.go, 11 LOC)

```go
package templates

import "embed"

//go:embed [60+ HTML files] static/*
var FS embed.FS
```

That is the entire API. Use `templates.FS.ReadFile("dashboard.html")`,
`fs.Sub(templates.FS, "static")`, or pass the FS to
`html/template.ParseFS`.

## Embedded inventory

- **Dashboard pages**: dashboard.html, activity.html, orders.html,
  alerts.html, paper.html, scanner.html, payoff.html, safety.html, ...
- **Admin pages**: admin_login.html, admin_users.html,
  admin_metrics.html, admin_sessions.html, admin_alerts.html, ...
- **MCP App widgets**: portfolio_app.html, activity_app.html,
  orders_app.html, alerts_app.html, options_chain_app.html,
  chart_app.html, hub_app.html, paper_app.html, ...
- **OAuth flow**: login_choice.html, login_success.html,
  browser_login.html, email_prompt.html, credentials_app.html
- **MFA flow**: admin_mfa_enroll.html, admin_mfa_verify.html
- **Static assets**: appbridge.js, dashboard-base.css, static/*

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed by:
- `app/http.go` — landing + dashboard rendering
- `oauth/handlers.go` — OAuth callback + login success pages
- `kc/ops/handler.go` — admin/user dashboard rendering
- `mcp/ext_apps.go` — MCP App widget shells (with CSS injection)

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

Adds project-meta files on top of the kc/templates history extracted
from Sundeepg98/kite-mcp-server's kc/templates/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original design +
HTML templates + appbridge.js + CSS). Adds 2026 algo2go contributors
line for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise (file paths inside FS may
change), pkg.go.dev badge, install snippet, why-a-separate-module
rationale (orthogonal UI primitives), the entire 11-LOC public API,
and a categorized inventory of the 60+ embedded files."

echo ""
echo "=== Phase 17: Final commit log ==="
git log --oneline | head -5
echo ""
echo "Total commits: $(git log --oneline | wc -l)"
