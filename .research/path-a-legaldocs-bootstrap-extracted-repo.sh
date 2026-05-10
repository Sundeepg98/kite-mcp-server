#!/usr/bin/env bash
# Path A.5 — kc/legaldocs bootstrap (LICENSE + CODEOWNERS + .gitignore + README).

set -euo pipefail

SCRATCH=/tmp/algo2go-legaldocs-extract-dryrun/kite-mcp-legaldocs-extract

if [ ! -d "$SCRATCH" ]; then
	echo "ERROR: $SCRATCH not found. Run prep + rewrite first."
	exit 1
fi

cd "$SCRATCH"

echo "=== Phase 11: Set local git identity (filter-repo strips it) ==="
git config user.email "69564967+Sundeepg98@users.noreply.github.com"
git config user.name "Sundeep"
echo "Identity: $(git config user.email) / $(git config user.name)"
echo ""

echo "=== Phase 11b: go mod tidy (kc/legaldocs has no external deps; nominally a no-op) ==="
/usr/local/go/bin/go mod tidy 2>&1 | tail -3
echo ""

echo "=== Phase 11c: Commit module-path rewrite as separate commit ==="
git add go.mod embed.go
git status --short
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-legaldocs

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/legaldocs to
github.com/algo2go/kite-mcp-legaldocs.

kc/legaldocs is a stdlib-only leaf (just embed.go exposing
PRIVACY.md + TERMS.md as []byte via go:embed). No external deps,
no go.sum changes from the rewrite.

Mechanical rewrite via .research/path-a-legaldocs-rewrite-dryrun.sh
on the kc/legaldocs subtree extracted by
path-a-legaldocs-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@813ae46."
echo ""

echo "=== Phase 12: Write LICENSE (MIT) ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/legaldocs design + draft
                                  Terms of Service + Privacy Notice)
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

NOTE: TERMS.md and PRIVACY.md are DRAFT legal documents bundled here
for software-engineering convenience (centralized embedded legal docs
across consumers). They are NOT legal advice. Consumers MUST review
and adapt them for their specific deployment, jurisdiction, and
regulatory context BEFORE serving them publicly. The MIT license
covers the embed.go scaffolding; the draft document content is
provided "AS IS" without warranty of legal sufficiency.
LICENSE_EOF
echo "LICENSE written"

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

# Temporary files
*.tmp
*.temp
*.log

# OS generated files
.DS_Store
Thumbs.db

# IDE files
.vscode/
.idea/
*.swp
*.swo
*~

# Go vendor
vendor/

# Local env
.env
.env.local
GITIGNORE_EOF
echo ".gitignore written"

echo ""
echo "=== Phase 15: Write README.md ==="
cat > README.md <<'README_EOF'
# kite-mcp-legaldocs

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-legaldocs.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-legaldocs)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Embedded legal documents (Terms of Service, Privacy Notice) for the
algo2go ecosystem. Exposes the documents as `[]byte` slices suitable
for direct serving or for goldmark-rendered HTML.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
for the `/terms` and `/privacy` HTTP routes.

## Why a separate module?

Centralizing the legal-doc source-of-truth means every algo2go consumer
serves the same up-to-date Terms + Privacy Notice without copy-pasting.
When the documents are updated upstream and a new tag is published, all
consumers can opt in via a `go get -u` bump.

The `embed.go` scaffolding is trivial (~11 LOC); the value is in the
content + the version-as-source-of-truth contract.

## ⚠️ DRAFT documents — read before deploying

**TERMS.md and PRIVACY.md are DRAFT legal documents.** They are NOT
legal advice. Before serving them publicly:

1. Review for your jurisdiction (this draft is India-context, governed
   by Indian law)
2. Adapt placeholders to your deployment
3. Have a lawyer review for your specific use case + regulatory context
4. Replace `sundeepg8@gmail.com` with your own product/grievance email
   (the draft uses the upstream maintainer's contact as a default —
   appropriate ONLY for that maintainer's reference deployment)

The MIT license covers the embed.go scaffolding. The document content
is provided "AS IS" without warranty of legal sufficiency.

## Stability promise

**v0.x — unstable.** Variable signatures (`Privacy`, `Terms` as
`[]byte`) are unlikely to change, but the document content WILL evolve
as legal review surfaces issues. v1.0 ships only after at least one
external consumer ships against it AND a real lawyer review of the
documents.

## Install

```bash
go get github.com/algo2go/kite-mcp-legaldocs@v0.1.0
```

## Public API (embed.go)

```go
package legaldocs

import _ "embed"

//go:embed PRIVACY.md
var Privacy []byte

//go:embed TERMS.md
var Terms []byte
```

That is the entire API. Use `legaldocs.Privacy` and `legaldocs.Terms`
directly as byte slices. For HTML rendering, pass through
[goldmark](https://github.com/yuin/goldmark) or any markdown renderer.

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— `app/legal.go` declares:

```go
var termsMarkdown = legaldocs.Terms
var privacyMarkdown = legaldocs.Privacy
```

Then renders them via goldmark for the `/terms` and `/privacy`
dashboard routes.

## License

MIT (scaffolding) — see [LICENSE](LICENSE). Document content provided
"AS IS" without warranty of legal sufficiency.

## Authors

Original design + draft documents: [Sundeepg98](https://github.com/Sundeepg98)
(Zerodha Tech). Multi-module promotion (2026-05-10): algo2go contributors.
README_EOF
echo "README.md written"

echo ""
echo "=== Phase 16: Commit bootstrap files ==="
git add LICENSE .github/CODEOWNERS .gitignore README.md
git status --short
echo ""
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/legaldocs history extracted
from Sundeepg98/kite-mcp-server's kc/legaldocs/ subtree (2026-05-10)
plus the chore: rewrite module path commit immediately preceding this
one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original kc/legaldocs
design + draft TERMS.md + PRIVACY.md). Adds 2026 algo2go contributors
line for extraction + packaging. Also adds an explicit DRAFT-content
disclaimer noting that the embedded markdown documents are NOT legal
advice and consumers must review/adapt before public deployment.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise (v1.0 only after external
consumer ships AND lawyer review of documents), pkg.go.dev badge,
install snippet, why-a-separate-module rationale (centralized source-
of-truth + opt-in version bumps), the entire 4-line public API
(Privacy + Terms as []byte), reference consumer link, and explicit
'⚠️ DRAFT documents — read before deploying' section warning."

echo ""
echo "=== Phase 17: Final commit log ==="
git log --oneline | head -5
echo ""
echo "Total commits: $(git log --oneline | wc -l)"
echo ""
echo "=== Bootstrap complete ==="
