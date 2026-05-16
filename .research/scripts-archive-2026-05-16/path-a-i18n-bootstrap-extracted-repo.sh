#!/usr/bin/env bash
# Path A.4 — kc/i18n bootstrap (LICENSE + CODEOWNERS + .gitignore + README).

set -euo pipefail

SCRATCH=/tmp/algo2go-i18n-extract-dryrun/kite-mcp-i18n-extract

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

echo "=== Phase 11b: go mod tidy to regenerate go.sum ==="
/usr/local/go/bin/go mod tidy
echo ""

echo "=== Phase 11c: Commit module-path rewrite as separate commit ==="
git add go.mod go.sum i18n.go i18n_test.go
git status --short
git commit -m "chore: rewrite module path to github.com/algo2go/kite-mcp-i18n

Renames module declaration in go.mod from
github.com/zerodha/kite-mcp-server/kc/i18n to
github.com/algo2go/kite-mcp-i18n. Regenerates go.sum via
go mod tidy (stretchr/testify is the only external require).

Mechanical rewrite via .research/path-a-i18n-rewrite-dryrun.sh on
the kc/i18n subtree extracted by path-a-i18n-prep-dryrun.sh from
Sundeepg98/kite-mcp-server@52204eb."
echo ""

echo "=== Phase 12: Write LICENSE (MIT) ==="
cat > LICENSE <<'LICENSE_EOF'
MIT License

Copyright (c) 2025 Zerodha Tech (original kc/i18n design + en/hi
                                  translations)
Copyright (c) 2026 algo2go contributors (extraction, packaging,
                                          translation extensibility)

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
# kite-mcp-i18n

[![Go Reference](https://pkg.go.dev/badge/github.com/algo2go/kite-mcp-i18n.svg)](https://pkg.go.dev/github.com/algo2go/kite-mcp-i18n)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

Locale-aware string lookups for the algo2go ecosystem. Embeds JSON
translation tables for English (`en`) and Hindi (`hi`); supports
`Accept-Language` header parsing, context-bound locale propagation,
and fallback to `en` for missing keys.

Used by [`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
for landing-page rendering, riskguard rejection messages, and OAuth
flow strings.

## Why a separate module?

Internationalization is an orthogonal cross-cutting primitive — usable
by any algo2go project (broker dashboards, payment flows, monitoring
UIs, future broker adapters) independent of `kite-mcp-server`. Hosting
it in its own module:

- Keeps translation contributions centralized (one repo to PR Hindi,
  Marathi, Tamil, etc.) instead of fragmenting per consumer
- Lets the `Locale` type and `Translate` API version independently of
  the server
- Reduces the dep-graph weight for consumers that only need locale
  resolution

## Stability promise

**v0.x — unstable.** Method signatures may break between minor versions.
Pin `v0.1.0` deliberately. v1.0 ships only after the public API
(`Locale`, `T`, `TFromContext`, `WithLocale`, `LocaleFromContext`,
`ParseAcceptLanguage`, `IsSupported`, `SupportedLocales`) is reviewed
for stability and at least one external consumer ships against it.

## Install

```bash
go get github.com/algo2go/kite-mcp-i18n@v0.1.0
```

## Public API (i18n.go)

- `type Locale string` — newtype for IETF BCP 47 language tags (`en`, `hi`, ...)
- `T(loc Locale, key string) string` — pure lookup, falls back to `en`
- `TFromContext(ctx, key) string` — context-aware lookup
- `WithLocale(ctx, loc) context.Context` / `LocaleFromContext(ctx) Locale`
- `ParseAcceptLanguage(header) Locale` — best-match from HTTP header
- `IsSupported(loc) bool`, `SupportedLocales() []Locale`
- `LocaleEN`, `LocaleHI` constants

## Translations

JSON files in `locales/`:
- `en.json` — English (canonical)
- `hi.json` — Hindi (Devanagari)

Keys are dot-namespaced (`error.action.home`, `landing.cta.signin`, ...).
PRs welcome for additional Indian-subcontinent locales (Marathi, Tamil,
Telugu, Bengali, etc.).

## Reference consumer

[`Sundeepg98/kite-mcp-server`](https://github.com/Sundeepg98/kite-mcp-server)
— used by:
- `app/http.go` for landing-page locale resolution + Accept-Language
- `kc/riskguard/middleware.go` for localized rejection messages
- OAuth + dashboard flows (via context propagation)

## License

MIT — see [LICENSE](LICENSE).

## Authors

Original design + en/hi translations: [Sundeepg98](https://github.com/Sundeepg98)
(Zerodha Tech). Multi-module promotion (2026-05-09): algo2go contributors.
README_EOF
echo "README.md written"

echo ""
echo "=== Phase 16: Commit bootstrap files ==="
git add LICENSE .github/CODEOWNERS .gitignore README.md
git status --short
echo ""
git commit -m "chore: initial bootstrap — LICENSE, CODEOWNERS, .gitignore, README

Adds project-meta files on top of the kc/i18n history extracted from
Sundeepg98/kite-mcp-server's kc/i18n/ subtree (2026-05-09) plus the
chore: rewrite module path commit immediately preceding this one.

LICENSE preserves Zerodha Tech 2025 MIT copyright (original kc/i18n
design + en/hi translations). Adds 2026 algo2go contributors line for
extraction + packaging + translation extensibility framing.

CODEOWNERS auto-routes PRs to @Sundeepg98 as initial maintainer.

.gitignore covers Go build artifacts, IDE files, OS junk.

README documents v0.x unstable promise (v1.0 only after API review +
external consumer adoption), pkg.go.dev badge, install snippet,
why-a-separate-module rationale (orthogonal i18n primitive,
contribution centralization), public API summary, locales/ directory
structure, and translation-PR welcome for additional Indian-subcontinent
languages."

echo ""
echo "=== Phase 17: Final commit log ==="
git log --oneline | head -5
echo ""
echo "Total commits: $(git log --oneline | wc -l)"
echo ""
echo "=== Bootstrap complete. Next: rename branch to main + push ==="
