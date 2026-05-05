module github.com/zerodha/kite-mcp-server/kc/ticker

go 1.25.0

// kc/ticker is a moderate-fan-in module — websocket ticker service
// (live tick subscription, leak sentinel, race-flag-on/off variants,
// callback dispatch). Direct internal deps:
//   - github.com/algo2go/kite-mcp-broker/ticker (subpackage of
//     extracted broker module — commit 5d74acf)
//   - github.com/algo2go/kite-mcp-broker/zerodha (subpackage of
//     extracted broker module — commit 5d74acf)
//
// Both subpackages live inside the broker module, so a single replace
// covers them. Transitively, broker reaches kc/money via broker/go.mod
// (commit 5d74acf documents this). Replace count: 2 — broker +
// kc/money.
//
// Tier 3 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): moderate-fan-in packages extracted in a single
// dispatch. This is 18/24 (commit 2 of 4 in this dispatch).
require (
	github.com/zerodha/gokiteconnect/v4 v4.4.0
	github.com/algo2go/kite-mcp-broker v0.0.0-00010101000000-000000000000
)

require (
	github.com/stretchr/testify v1.10.0
	go.uber.org/goleak v1.3.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gocarina/gocsv v0.0.0-20180809181117-b8c38cb1ba36 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/money v0.0.0-00010101000000-000000000000 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace (
	github.com/algo2go/kite-mcp-broker => ../../broker
	github.com/zerodha/kite-mcp-server/kc/money => ../money
)
