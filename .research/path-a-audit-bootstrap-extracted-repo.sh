#!/usr/bin/env bash
set -euo pipefail
SCRATCH=/tmp/algo2go-audit-extract-dryrun/kite-mcp-audit-extract
[ -d "$SCRATCH" ] || { echo "ERROR: run prep + rewrite first"; exit 1; }
cd "$SCRATCH"

git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"

/usr/local/go/bin/go mod tidy 2>&1 | tail -3

git add -A
git status --short | head
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-audit

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/audit to
github.com/algo2go/kite-mcp-audit.

Drops stale 'replace zerodha/kite-mcp-server => ../..' AND
'replace zerodha/kite-mcp-server/testutil => ../../testutil'
workspace artifacts (kc/audit has zero actual root or testutil
imports in source — both lines were stale carrying-cost from the
in-tree workspace days).

kc/audit's algo2go deps:
  - github.com/algo2go/kite-mcp-alerts (Path A.11)
  - github.com/algo2go/kite-mcp-domain (Path A.10)
  - github.com/algo2go/kite-mcp-logger (Path A.7)
  - github.com/algo2go/kite-mcp-oauth (Path A.13)

Standalone build PASS. Standalone tests PASS.

Mechanical rewrite via .research/path-a-audit-rewrite-dryrun.sh
on the kc/audit subtree extracted by path-a-audit-prep-dryrun.sh
from Sundeepg98/kite-mcp-server@0446f84."

cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/audit design — AI activity
                                  audit trail, anomaly detection,
                                  hash-publish integrity, retention,
                                  consent, sanitize, summarize)
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
# kite-mcp-audit

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-audit.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-audit)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

AI activity audit trail for the algo2go ecosystem. Captures every MCP
tool call to a per-user log with PII redaction, anomaly detection,
hash-chain integrity, configurable retention, consent management, and
summarization for human review.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
across kc/manager_*, app/*, kc/ops/* (dashboard timeline page),
mcp/admin/* (anomaly + cache-info admin tools).

## Why a separate module?

Audit is a foundational observability primitive applicable to any
AI-agent application — not just trading. Hosting as its own module:

- Centralizes the AuditEvent + Store + Middleware contracts
- Lets PII redaction rules + summary heuristics version independently
- Decouples retention/consent policy from any one consumer

## Stability promise

**v0.x — unstable.** Pin `v0.1.0` deliberately.

## Install

```bash
go get github.com/algo2go/kite-mcp-audit@v0.1.0
```

## Public API

- `Store` — buffered async writer to SQLite tool_calls table
- `Middleware` — `WithToolHandlerMiddleware` for MCP tool-call capture
- `AnomalyCache` — per-user baseline + flagged-call detection
- `Sanitize` — PII redaction (emails, tokens, credit cards)
- `Summarize` — per-tool human-readable summary heuristics
- `Retention` — configurable cleanup (default 90-day)
- `HashPublish` — integrity hashing + S3-compatible publishing
- `Consent` — per-user audit opt-in tracking
- `Histogram` — per-tool latency/error/count metrics
- `Plugin Event Types` — typed event constants

## Dependencies

- `github.com/algo2go/kite-mcp-alerts` v0.1.0
- `github.com/algo2go/kite-mcp-domain` v0.1.0
- `github.com/algo2go/kite-mcp-logger` v0.1.0
- `github.com/algo2go/kite-mcp-oauth` v0.1.0
- `github.com/google/uuid` v1.6.0
- `github.com/mark3labs/mcp-go` v0.46.0
- `github.com/stretchr/testify` v1.10.0

All algo2go deps published; no upstream `replace` directives needed.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— consumed across 75 .go files: kc/manager_*, kc/store_registry.go,
kc/options.go, kc/interfaces.go, kc/config.go, kc/usecases/*,
kc/ops/* (dashboard activity timeline), app/*, mcp/admin/*,
mcp/*_test.go.

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design: [Sundeepg98](https://github.com/Sundeepg98) (Zerodha
Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF

git add LICENSE .github/CODEOWNERS .gitignore README.md
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/audit history extracted from
Sundeepg98/kite-mcp-server's kc/audit/ subtree (2026-05-10) plus the
chore: rewrite module path commit immediately preceding this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original AI
activity audit trail design — store + middleware + anomaly +
hash-publish + retention + consent + sanitize + summarize +
histogram). Adds 2026 algo2go contributors line for extraction +
packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, pkg.go.dev badge, install
snippet, why-a-separate-module rationale (foundational observability
primitive for AI-agent apps), public API summary (10 components —
Store, Middleware, AnomalyCache, Sanitize, Summarize, Retention,
HashPublish, Consent, Histogram, Plugin Event Types), and explicit
dependency list (algo2go/kite-mcp-alerts + kite-mcp-domain +
kite-mcp-logger + kite-mcp-oauth, all v0.1.0)."

git log --oneline | head -5
