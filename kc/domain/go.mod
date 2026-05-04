module github.com/zerodha/kite-mcp-server/kc/domain

go 1.25.0

// kc/domain is the type-rich Anchor 4 module — DDD value objects and
// entities (Money, Quantity, Order, Position, Holding, Profile,
// Session, Alert, Family, Glossary). 143 importers across the
// codebase make it a hot zone — PR 4.1 (this commit) is the
// minimal-revert stub-add that establishes the go.mod + replace
// block WITHOUT migrating any types or rewriting any imports.
//
// Subsequent PRs (4.2-4.8 in later dispatches) do the incremental
// migration: each PR moves a single value-object cluster (Money,
// Quantity, Specs, etc.) out of root and into kc/domain proper, with
// the safety-net of revert-to-prior-PR if anything breaks. PR 4.1
// is the safe-revert anchor — if kc/domain ever needs to be backed
// out, this is the single commit to revert.
//
// Direct internal deps (validated by `grep github.com/zerodha kc/domain/*.go`
// at HEAD 68e92e1):
//   - github.com/zerodha/kite-mcp-server/broker (used in holding.go,
//     order.go, position.go, profile.go for broker DTO interop —
//     extracted at commit 5d74acf)
//   - github.com/zerodha/kite-mcp-server/kc/isttz (used in session.go
//     for ISTNow() — extracted at commit a2ad8e0)
//   - github.com/zerodha/kite-mcp-server/kc/money (used in money.go
//     for Money type embedding — extracted at commit b7fedcc)
//
// Replace count: 3 — no root replace because kc/domain doesn't import
// root packages, only already-extracted modules. broker transitively
// reaches kc/money, but listing kc/money explicitly keeps GOWORK=off
// resolution deterministic.
//
// Anchor 4 path (.research/disintegrate-and-holistic-architecture.md
// commit 7ac9d34 + 7e1700c re-audit): kc/domain is module-clean —
// no cyclic imports, no unjustified dependencies — so a stub-add
// is purely ceremony with zero behavior change. This is 20/24 in
// the broader zero-monolith plan (commit 4 of 4 in this dispatch).
require (
	github.com/zerodha/kite-mcp-server/broker v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/isttz v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/money v0.0.0-00010101000000-000000000000
)

require github.com/stretchr/testify v1.10.0

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gocarina/gocsv v0.0.0-20180809181117-b8c38cb1ba36 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/zerodha/gokiteconnect/v4 v4.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/zerodha/kite-mcp-server/broker => ../../broker
	github.com/zerodha/kite-mcp-server/kc/isttz => ../isttz
	github.com/zerodha/kite-mcp-server/kc/money => ../money
)
