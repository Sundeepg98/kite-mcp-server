module github.com/zerodha/kite-mcp-server/kc/eventsourcing

go 1.25.0

// kc/eventsourcing is a moderate-fan-in module — domain event aggregate
// roots (alerts, orders, positions, sessions) + outbox + projections
// + event store. Direct internal deps:
//   - kc/domain (still in root at this commit; PR 4.1 stub-adds
//     kc/domain/go.mod separately)
//   - broker (extracted at commit 5d74acf — used in order_aggregate.go
//     for OrderConfirmation type)
//   - kc/alerts (still in root — used in store.go + outbox_test.go +
//     store_test.go for alert event payloads)
//
// Replace block has 5 entries — root + broker + kc/isttz + kc/logger
// + kc/money — same shape as kc/cqrs (commit-prior). kc/alerts is
// reached via root (it lives in github.com/zerodha/kite-mcp-server),
// and kc/alerts itself transitively reaches kc/isttz, kc/logger,
// broker, kc/money — all already-extracted modules that need explicit
// replace lines so GOWORK=off resolution works.
//
// Tier 3 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): moderate-fan-in packages extracted in a single
// dispatch. This is 19/24 (commit 3 of 4 in this dispatch).
require (
	github.com/stretchr/testify v1.10.0
	github.com/algo2go/kite-mcp-broker v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/isttz v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/logger v0.0.0-00010101000000-000000000000 // indirect
	github.com/algo2go/kite-mcp-money v0.1.0 // indirect
)

require (
	github.com/google/uuid v1.6.0
	github.com/zerodha/kite-mcp-server/kc/alerts v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/domain v0.0.0-00010101000000-000000000000
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-telegram-bot-api/telegram-bot-api/v5 v5.5.1 // indirect
	github.com/gocarina/gocsv v0.0.0-20180809181117-b8c38cb1ba36 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/zerodha/gokiteconnect/v4 v4.4.0 // indirect
	golang.org/x/crypto v0.48.0 // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/sys v0.41.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.46.1 // indirect
)

replace (
	github.com/zerodha/kite-mcp-server => ../..
	github.com/algo2go/kite-mcp-broker => ../../broker
	github.com/zerodha/kite-mcp-server/kc/alerts => ../alerts
	github.com/zerodha/kite-mcp-server/kc/domain => ../domain
	github.com/zerodha/kite-mcp-server/kc/isttz => ../isttz
	github.com/zerodha/kite-mcp-server/kc/logger => ../logger
	github.com/algo2go/kite-mcp-money => ../money
)
