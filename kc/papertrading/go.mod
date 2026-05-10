module github.com/zerodha/kite-mcp-server/kc/papertrading

go 1.25.0

// kc/papertrading is a heavy-fan-in module — paper trading engine
// (virtual portfolio mode via middleware interception, background
// LIMIT fill monitor, ₹1 crore default cash). Direct internal deps:
//   - kc/alerts (extracted at commit 8878738) — used in store.go +
//     engine_test.go fixtures
//   - kc/domain (extracted PR 4.1 stub at commit d4bb3e6) — used in
//     engine.go, store.go, monitor.go for Order/Position/Holding
//   - kc/logger (extracted at commit 1b7dcbf) — logport interface
//   - kc/riskguard (extracted at commit 5982aff) — used in
//     riskguard_integration_test.go for cross-module fixtures
//   - broker + broker/mock (extracted at commit 5d74acf) — used in
//     engine_integration_test.go via mock client
//   - oauth (still in root) — used in middleware.go for session
//     extraction
//
// Replace block: 10 entries — empirically validated via `go mod tidy`.
// Plateau-breaking signal: this is the FIRST module to break the 5-7
// entry plateau established by Tiers 1-3. Cause: oauth (still in root)
// transitively imports kc/templates + kc/users (both extracted), and
// kc/riskguard's own go.mod (commit 5982aff) doesn't replace kc/i18n
// or kc/isttz — it relies on root for those, which works in workspace
// mode but requires explicit replaces here for GOWORK=off resolution.
//
// Replace inventory: root (for oauth) + broker + kc/alerts + kc/domain
// + kc/i18n (via kc/riskguard) + kc/isttz (via kc/alerts → kc/domain)
// + kc/logger + kc/money + kc/riskguard + kc/templates (via oauth) +
// kc/users (via oauth). 10 entries.
//
// Phase 2 PR 4.4 (kc/riskguard go.mod bump) addresses one root cause
// by adding kc/domain replace to kc/riskguard, which won't reduce
// THIS module's count but will reduce kc/usecases / kc/telegram
// (downstream consumers).
//
// Tier 4 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): heavy fan-in packages extracted in dep order.
// This is 22/24 (commit 2 of 4 in this dispatch — must come BEFORE
// kc/telegram which imports kc/papertrading).
require (
	github.com/stretchr/testify v1.10.0
	github.com/algo2go/kite-mcp-broker v0.1.0
	github.com/zerodha/kite-mcp-server/kc/alerts v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/domain v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/logger v0.0.0-00010101000000-000000000000
	github.com/algo2go/kite-mcp-money v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/riskguard v0.0.0-00010101000000-000000000000
	modernc.org/sqlite v1.46.1 // indirect
)

require (
	github.com/mark3labs/mcp-go v0.46.0
	github.com/zerodha/kite-mcp-server/oauth v0.0.0-00010101000000-000000000000
	go.uber.org/goleak v1.3.0
)

require (
	cloud.google.com/go/compute/metadata v0.9.0 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/fatih/color v1.13.0 // indirect
	github.com/go-telegram-bot-api/telegram-bot-api/v5 v5.5.1 // indirect
	github.com/gocarina/gocsv v0.0.0-20180809181117-b8c38cb1ba36 // indirect
	github.com/golang-jwt/jwt/v5 v5.3.1 // indirect
	github.com/golang/protobuf v1.5.4 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/jsonschema-go v0.4.2 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/go-plugin v1.7.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/mattn/go-colorable v0.1.12 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/oklog/run v1.1.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/spf13/cast v1.7.1 // indirect
	github.com/yosida95/uritemplate/v3 v3.0.2 // indirect
	github.com/zerodha/gokiteconnect/v4 v4.4.0 // indirect
	github.com/algo2go/kite-mcp-i18n v0.1.0 // indirect
	github.com/algo2go/kite-mcp-isttz v0.1.0 // indirect
	github.com/zerodha/kite-mcp-server/kc/templates v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/users v0.0.0-00010101000000-000000000000 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/net v0.49.0 // indirect
	golang.org/x/oauth2 v0.36.0 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/text v0.34.0 // indirect
	google.golang.org/genproto/googleapis/rpc v0.0.0-20251202230838-ff82c1b0f217 // indirect
	google.golang.org/grpc v1.79.3 // indirect
	google.golang.org/protobuf v1.36.10 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace (
	github.com/zerodha/kite-mcp-server => ../..
	github.com/zerodha/kite-mcp-server/kc/alerts => ../alerts
	github.com/zerodha/kite-mcp-server/kc/domain => ../domain
	github.com/zerodha/kite-mcp-server/kc/logger => ../logger
	github.com/zerodha/kite-mcp-server/kc/riskguard => ../riskguard
	github.com/zerodha/kite-mcp-server/kc/templates => ../templates
	github.com/zerodha/kite-mcp-server/kc/users => ../users
	github.com/zerodha/kite-mcp-server/oauth => ../../oauth
	github.com/zerodha/kite-mcp-server/testutil => ../../testutil
)
