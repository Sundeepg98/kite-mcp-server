module github.com/zerodha/kite-mcp-server/broker

go 1.25.0

// In workspace mode (the canonical local + CI build path), kc/money is
// resolved via go.work at the repo root listing ./kc/money as a sibling
// member. The replace directive below is belt-and-suspenders so this
// module stays buildable from a partial checkout that omits go.work
// (e.g., if a future consumer vendors only this module, or for
// GOWORK=off diagnostics). Drop the replace once kc/money has its own
// published tag.
require (
	github.com/stretchr/testify v1.10.0
	github.com/zerodha/gokiteconnect/v4 v4.4.0
	github.com/zerodha/kite-mcp-server/kc/money v0.0.0-00010101000000-000000000000
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/gocarina/gocsv v0.0.0-20180809181117-b8c38cb1ba36 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/kr/text v0.2.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/rogpeppe/go-internal v1.9.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/zerodha/kite-mcp-server/kc/money => ../kc/money
