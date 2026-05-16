#!/usr/bin/env bash
# Path A inauguration A.2.2-A.2.3 bootstrap.
# Adds LICENSE + CODEOWNERS + .gitignore + README to extracted repo as a
# single bootstrap commit on top of the 41-commit broker history, then
# pushes to algo2go/kite-mcp-broker.
#
# Pre-condition: path-a-prep-dryrun.sh + path-a-prep-rewrite-dryrun.sh
# already executed on this scratch dir.

set -euo pipefail

SCRATCH=/tmp/algo2go-broker-extract-dryrun/kite-mcp-broker-extract

if [ ! -d "$SCRATCH" ]; then
	echo "ERROR: $SCRATCH not found. Run path-a-prep-dryrun.sh + rewrite first."
	exit 1
fi

cd "$SCRATCH"

echo "=== Phase 11: Set local git identity (filter-repo strips it) ==="
# Mirror parent repo's commit identity (verified via 'git log --pretty=format:%ae'
# on Sundeepg98/kite-mcp-server master). Uses GitHub's noreply form to avoid
# leaking a real personal address into public commit history.
git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"
echo "Identity: $(git config user.email) / $(git config user.name)"
echo ""

echo "=== Phase 12: Write LICENSE (MIT) ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original broker.Client design + Zerodha adapter)
Copyright (c) 2026 algo2go contributors (extraction, multi-broker port,
                                          conformance harness)

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
echo "LICENSE written ($(wc -l < LICENSE) lines)"
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
*.exe~
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

# Go module cache
go.sum.backup

# Temporary files
*.tmp
*.temp
*.log
*.pid
*.lock

# OS generated files
.DS_Store
.DS_Store?
._*
.Spotlight-V100
.Trashes
ehthumbs.db
Thumbs.db

# IDE and editor files
.vscode/
.idea/
*.swp
*.swo
*~
.project
.settings/

# Go vendor directory
vendor/

# Local env
.env
.env.local
.env.*.local
GITIGNORE_EOF
echo ".gitignore written"
echo ""

echo "=== Phase 15: Write README.md ==="
cat > README.md <<'README_EOF'
# kite-mcp-broker

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-broker.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-broker)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Multi-broker port for Indian retail trading platforms. Defines `broker.Client`
plus ancillary capability interfaces (`NativeAlertCapable`, `GTTManager`,
`MutualFundClient`) and ships the Zerodha adapter (`zerodha`) wrapping
[`gokiteconnect/v4`](https://github.com/zerodha/gokiteconnect).

## Status

**v0.x — unstable.** Adapter signatures may break between minor versions.
Pin `v0.1.0` deliberately. v1.0 ships only after at least one external adapter
(non-Zerodha) passes the conformance harness.

## Install

```bash
go get github.com/algo2go/kite-mcp-broker@v0.1.0
```

## Conformance harness

`conformance/` is the public test API for adapter authors. Four buckets:

- `PortContract` — required `broker.Client` methods
- `OptionalCapabilities` — feature-detect via type assertion (NativeAlerts,
  GTT, MutualFunds)
- `ErrorClassification` — transient/auth/rate-limit/validation taxonomy
- `TickerLifecycle` — websocket connect/subscribe/disconnect semantics

See `conformance/conformance.go` for entry points.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— MCP server with 100+ tools. The broker port lived in-tree there until
2026-05-05 when it was extracted to this repo to enable multi-broker
adoption + independent semver.

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original `broker.Client` design + Zerodha adapter:
[Sundeepg98](https://github.com/Sundeepg98) (Zerodha Tech).

Extraction + multi-broker port + conformance harness: algo2go contributors.

## Roadmap

- [x] v0.1.0 — Zerodha adapter
- [ ] v0.2.0 — Upstox adapter (community contribution welcome)
- [ ] v0.3.0 — Dhan adapter (community contribution welcome)
- [ ] v1.0.0 — frozen public API (after >=1 external adapter ships)

## Contributing

PRs welcome for: new broker adapters that pass `conformance.PortContract`,
documentation improvements, bug fixes. Feature requests via Issues. Commercial
support for adapter integration: contact via Issues.
README_EOF
echo "README.md written"
echo ""

echo "=== Phase 16: Stage + commit bootstrap files ==="
git add LICENSE .github/CODEOWNERS .gitignore README.md
git status --short
echo ""
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the 41-commit history extracted from
Sundeepg98/kite-mcp-server's broker/ subtree (2026-05-05).

LICENSE preserves Zerodha Tech 2025 MIT copyright (original broker.Client
design + Zerodha adapter). Adds 2026 algo2go contributors line for
extraction + multi-broker port + conformance harness work.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk. Trimmed from the
parent repo's .gitignore (dropped server-specific patterns like
kite-mcp-server, instruments.json, app_*.html, /admin.md scratch notes).

README documents v0.x unstable promise (v1.0 only after first external
adapter passes conformance), pkg.go.dev badge, install snippet, conformance
buckets, reference consumer link, MIT attribution, and adapter roadmap."

echo ""
echo "=== Phase 17: Final commit log (history visible to algo2go/kite-mcp-broker) ==="
git log --oneline | head -10
echo ""
echo "Total commits: $(git log --oneline | wc -l) (41 broker history + 1 bootstrap = 42 expected)"
echo ""

echo "=== Bootstrap complete. Next: push to algo2go/kite-mcp-broker:main ==="
