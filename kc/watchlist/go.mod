module github.com/zerodha/kite-mcp-server/kc/watchlist

go 1.25.0

// kc/watchlist is a SQLite-backed leaf — per-user watchlist CRUD over
// modernc.org/sqlite (pure-Go SQLite, no CGO). Zero internal deps;
// google/uuid for primary keys; testify for tests. Same shape as
// kc/money but with two extra direct external deps.
//
// Tier 1 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): 6 zero-dep leaves extracted in a single dispatch.
// "Zero-dep" = zero INTERNAL deps; external deps are unconstrained
// per the audit.
require (
	github.com/google/uuid v1.6.0
	github.com/stretchr/testify v1.10.0
	modernc.org/sqlite v1.46.1
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/kr/pretty v0.3.1 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/tools v0.41.0 // indirect
	gopkg.in/check.v1 v1.0.0-20180628173108-788fd7840127 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)
