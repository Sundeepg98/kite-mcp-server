#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-riskguard-extract-dryrun/kite-mcp-riskguard-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep + rewrite first"; exit 1; }
cd "$SCRATCH"

git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"

/usr/local/go/bin/go mod tidy 2>&1 | tail -3

git add -A
git status --short | head
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-riskguard

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/riskguard to
github.com/algo2go/kite-mcp-riskguard.

Drops stale 'replace zerodha/kite-mcp-server => ../..' AND
'replace zerodha/kite-mcp-server/testutil => ../../testutil'
workspace artifacts (kc/riskguard had zero actual root or testutil
imports — both lines were stale carrying-cost from the in-tree
workspace days). The single intra-module ref to checkrpc/ subpackage
rewrites in-place during this same commit.

kc/riskguard's algo2go deps:
  - github.com/algo2go/kite-mcp-alerts (Path A.11)
  - github.com/algo2go/kite-mcp-domain (Path A.10)
  - github.com/algo2go/kite-mcp-i18n (Path A.4)
  - github.com/algo2go/kite-mcp-logger (Path A.7)
  - github.com/algo2go/kite-mcp-oauth (Path A.13)

Standalone build PASS. Standalone tests PASS for both
github.com/algo2go/kite-mcp-riskguard and
github.com/algo2go/kite-mcp-riskguard/checkrpc.

Mechanical rewrite via .research/path-a-riskguard-rewrite-dryrun.sh
on the kc/riskguard subtree extracted by
path-a-riskguard-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@aac5af9."

cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/riskguard design — pre-trade
                                  risk safety controls: kill switch,
                                  order-value cap, qty cap, daily count,
                                  rate limit, dedup, daily-value cap,
                                  auto-freeze circuit breaker, OTR band,
                                  market-hours, plugin-discovery
                                  subprocess checks)
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
# kite-mcp-riskguard

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-riskguard.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-riskguard)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Pre-trade risk safety controls for the algo2go ecosystem. 8+ checks
gate every order before it reaches the broker: kill switch,
order-value cap, qty cap, daily count limit, per-second/per-minute
rate limit, duplicate detection, daily-value cap, auto-freeze circuit
breaker, OTR (Order-to-Trade Ratio) band check, market-hours guard,
margin check, and plugin-discovery subprocess checks for custom
extensions.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
as the gate between Audit and Elicitation in the order execution
chain: Audit -> Riskguard -> Elicitation -> Kite API.

## Why a separate module?

Risk gating is a foundational safety primitive that any algo2go
consumer placing orders should use independently of
`kite-mcp-server`'s broker integration. Hosting as its own module:

- Centralizes the Guard contract + 8+ check implementations
- Lets check thresholds + rate-limit policies version independently
- Decouples plugin-discovery subprocess hooks from any one runtime
- Provides a stable RPC contract (`checkrpc/`) for external check
  plugins written in any language

## Stability promise

**v0.x — unstable.** Pin `v0.1.0` deliberately.

## Install

```bash
go get github.com/algo2go/kite-mcp-riskguard@v0.1.0
```

## Public API

- `Guard` — orchestrates all checks; main entry point
- `KillSwitch`, `CircuitLimit`, `Limits`, `Trackers`, `PerSecond`,
  `Dedup`, `MarginCheck`, `MarketHours`, `OTRBand` — individual
  checks
- `SubprocessCheck` — plugin-discovery + RPC for external check
  plugins
- `Middleware` — Guard wrapped as a middleware for use-case chains
- `checkrpc/` — RPC types for external plugins (zero algo2go deps,
  embeddable in any language binding)

## Dependencies

- `github.com/algo2go/kite-mcp-alerts` v0.1.0
- `github.com/algo2go/kite-mcp-domain` v0.1.0
- `github.com/algo2go/kite-mcp-i18n` v0.1.0
- `github.com/algo2go/kite-mcp-logger` v0.1.0
- `github.com/algo2go/kite-mcp-oauth` v0.1.0
- `github.com/hashicorp/go-plugin` — RPC plugin framework
- `github.com/stretchr/testify` v1.10.0

All algo2go deps published; no upstream `replace` directives needed.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed across 53 .go files: kc/manager_*, kc/options.go,
kc/config.go, kc/broker_services.go, kc/ports/order.go,
kc/papertrading/*, kc/usecases/*, kc/telegram/*, kc/ops/*, app/*,
mcp/admin/*, mcp/middleware/*, mcp/common/*, mcp/misc/*,
mcp/tools_*_test.go, examples/riskguard-check-plugin/main.go.

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF

git add LICENSE .github/CODEOWNERS .gitignore README.md
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/riskguard history extracted
from Sundeepg98/kite-mcp-server's kc/riskguard/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original pre-trade
risk gating design — kill switch, value/qty/count/rate caps, dedup,
daily-value, circuit breaker, OTR band, market-hours, margin, plugin
subprocess checks). Adds 2026 algo2go contributors line for
extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale (foundational risk-gating
primitive across algo2go projects), public API summary (Guard
orchestrator + 8+ check implementations + middleware + checkrpc
subpackage for external plugins), and explicit dependency list
(algo2go/kite-mcp-alerts + kite-mcp-domain + kite-mcp-i18n +
kite-mcp-logger + kite-mcp-oauth, all v0.1.0)."

git log --oneline | head -5
