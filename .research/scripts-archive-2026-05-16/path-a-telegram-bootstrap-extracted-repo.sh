#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-telegram-extract-dryrun/kite-mcp-telegram-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep + rewrite first"; exit 1; }
cd "$SCRATCH"

git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"

/usr/local/go/bin/go mod tidy 2>&1 | tail -3

git add -A
git status --short | head
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-telegram

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/telegram to
github.com/algo2go/kite-mcp-telegram.

Drops stale 'replace zerodha/kite-mcp-server => ../..' workspace
artifact (kc/telegram had zero actual root imports — line was
stale carrying-cost from the in-tree workspace days).

kc/telegram's algo2go deps:
  - github.com/algo2go/kite-mcp-alerts (Path A.11)
  - github.com/algo2go/kite-mcp-broker (early Path A; incl.
    /ticker + /zerodha subpkgs)
  - github.com/algo2go/kite-mcp-domain (Path A.10)
  - github.com/algo2go/kite-mcp-instruments (Path A.16)
  - github.com/algo2go/kite-mcp-papertrading (Path A.24 — just landed)
  - github.com/algo2go/kite-mcp-riskguard (Path A.22)
  - github.com/algo2go/kite-mcp-ticker (Path A.18)
  - github.com/algo2go/kite-mcp-watchlist (Path A.15)

Standalone build PASS. Standalone tests PASS.

Mechanical rewrite via .research/path-a-telegram-rewrite-dryrun.sh
on the kc/telegram subtree extracted by
path-a-telegram-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@191ab09."

cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/telegram design — Telegram
                                  bot integration: trading commands
                                  /buy /sell /quick /setalert with
                                  inline keyboard confirmation,
                                  morning briefings, daily P&L,
                                  disclaimer flow, plugin commands,
                                  handler routing)
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
# kite-mcp-telegram

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-telegram.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-telegram)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Telegram bot integration for the algo2go ecosystem. Provides
mobile-friendly trading via inline-keyboard commands (/buy /sell
/quick /setalert) with confirmation flow, morning briefings (9 AM
IST: alerts + token status), daily P&L summary (3:35 PM IST:
holdings + positions, weekend skip + dedup, HTML formatted),
disclaimer/consent flow, and pluggable command extension via
plugin_commands.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
as the optional Telegram bot endpoint wired in app/app.go,
app/http.go, app/adapters.go.

## Why a separate module?

Telegram is a foundational mobile-first endpoint primitive
applicable to any algo2go consumer running a trading bot — not
just kite-mcp-server. Hosting as its own module:

- Centralizes the Bot + Handler + Commands + Briefings contracts
- Lets command syntax + keyboard layouts version independently
- Decouples Telegram-specific UI flow from any one runtime

## Stability promise

**v0.x — unstable.** Pin `v0.1.0` deliberately.

## Install

```bash
go get github.com/algo2go/kite-mcp-telegram@v0.1.0
```

## Public API

- `Bot` — Telegram client + dispatch
- `Handler` — message handler routing (auth, portfolio, trading,
  plugin commands)
- Trading commands — /buy, /sell, /quick (1-tap presets), /setalert
- Briefings — morning (9 AM IST) + daily P&L (3:35 PM IST)
  scheduler with weekend skip + dedup
- Disclaimer — consent flow before first trading command
- PluginCommands — extension hook for custom commands
- TradingFuzzTest — fuzz test harness for command parsing

## Dependencies (8 algo2go modules)

- `github.com/algo2go/kite-mcp-alerts` v0.1.0
- `github.com/algo2go/kite-mcp-broker` v0.1.0 (incl. /ticker +
  /zerodha subpkgs)
- `github.com/algo2go/kite-mcp-domain` v0.1.0
- `github.com/algo2go/kite-mcp-instruments` v0.1.0
- `github.com/algo2go/kite-mcp-papertrading` v0.1.0
- `github.com/algo2go/kite-mcp-riskguard` v0.1.0
- `github.com/algo2go/kite-mcp-ticker` v0.1.0
- `github.com/algo2go/kite-mcp-watchlist` v0.1.0
- `github.com/go-telegram-bot-api/telegram-bot-api/v5` v5.5.1
- `github.com/stretchr/testify` v1.10.0

All algo2go deps published; no upstream `replace` directives needed.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed across 3 .go files: app/app.go, app/http.go,
app/adapters.go (Telegram bot wiring + handler registration).

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF

git add LICENSE .github/CODEOWNERS .gitignore README.md
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/telegram history extracted
from Sundeepg98/kite-mcp-server's kc/telegram/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding
this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original Telegram
bot design — trading commands /buy /sell /quick /setalert with
inline keyboard confirmation, morning briefings, daily P&L,
disclaimer flow, plugin commands, handler routing). Adds 2026
algo2go contributors line for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale (foundational mobile-first
endpoint primitive across algo2go projects), public API summary
(Bot + Handler + Trading commands + Briefings + Disclaimer +
PluginCommands + TradingFuzzTest), and explicit dependency list
(8 algo2go modules + go-telegram-bot-api + stretchr/testify, all
algo2go deps v0.1.0)."

git log --oneline | head -5
