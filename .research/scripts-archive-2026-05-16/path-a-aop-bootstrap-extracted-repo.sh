#!/usr/bin/env bash
# Path A.9 — kc/aop bootstrap.

set -euo pipefail

SCRATCH=/tmp/algo2go-aop-extract-dryrun/kite-mcp-aop-extract

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
git add go.mod aop.go aop_test.go example_audit_riskguard.go example_audit_riskguard_test.go proxy.go proxy_test.go
[ -f go.sum ] && git add go.sum
git status --short
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-aop

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/aop to
github.com/algo2go/kite-mcp-aop. kc/aop is gated by //go:build
research on every .go file — excluded from default go build/test
runs. Standalone build + test PASSES with -tags=research.

Mechanical rewrite via .research/path-a-aop-rewrite-dryrun.sh on
the kc/aop subtree extracted by path-a-aop-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@76ae3dc."
echo ""

echo "=== Phase 12: Write LICENSE (MIT) ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/aop reflective AOP design
                                  + audit/riskguard example aspects)
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
# kite-mcp-aop

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-aop.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-aop)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Reflective Aspect-Oriented Programming (AOP) primitives for the
algo2go ecosystem. Generates dynamic proxies that wrap target
struct methods with cross-cutting aspects (audit, rate-limit,
authorization, retry, etc.) — all gated by the `research` build
tag for opt-in experimentation.

## Build gate — `research` tag only

**This package is gated behind the `//go:build research` tag.**
It is EXCLUDED from default `go build ./...` and `go test ./...`
runs. To compile/test it locally:

```bash
go build -tags=research ./...
go test -tags=research ./...
```

This gating is intentional — the package is research-grade and not
production-bound. Reflective dispatch incurs runtime overhead that
production paths shouldn't bear.

## Why a separate module?

AOP infrastructure is an orthogonal cross-cutting research primitive
— useful for prototyping cross-cutting concerns (audit, rate limit,
RBAC, retry, fallback) without touching the target struct's source.
Hosting as a module:

- Lets the `research` tag stay opt-in across consumers
- Enables independent experimentation versioning
- Keeps the dep-graph weight zero for production consumers (the
  package is excluded from non-research builds)

## Stability promise

**v0.x — unstable.** Reflective AOP signatures may evolve. Pin
`v0.1.0` deliberately. v1.0 ships only after the public API stabilizes
across at least 2 external research consumers.

## Install

```bash
go get github.com/algo2go/kite-mcp-aop@v0.1.0
```

## Public API (aop.go + proxy.go)

- `Proxy[T]` — generic dynamic proxy that wraps a target with
  before/after/around aspects
- `Aspect` interface — pluggable cross-cutting hooks
- `BindAspect(target, aspect) Proxy[T]` — proxy construction helper
- See `example_audit_riskguard.go` for a worked audit + riskguard
  aspect composition

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— historical reference; package is unused in production paths
(verified by zero-import analysis at extraction time). Tests still
exercise the package under `-tags=research` as the F7 close-out
canary.

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

Adds project-meta files on top of the kc/aop history extracted from
Sundeepg98/kite-mcp-server's kc/aop/ subtree (2026-05-10) plus the
chore: rewrite module path commit immediately preceding this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright. Adds 2026 algo2go
contributors line for extraction + packaging.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise, the //go:build research
gate (with explicit -tags=research instructions), pkg.go.dev badge,
install snippet, why-a-separate-module rationale (orthogonal AOP
research primitive), public API summary."

echo ""
echo "=== Phase 17: Final commit log ==="
git log --oneline | head -5
echo ""
echo "Total commits: $(git log --oneline | wc -l)"
