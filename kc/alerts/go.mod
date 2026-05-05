module github.com/zerodha/kite-mcp-server/kc/alerts

go 1.25.0

// kc/alerts is a heavy-fan-in module — price alert engine + briefing
// scheduler (morning/EOD) + composite alert chains + trailing alerts
// + anomaly notifier + database adapters. Direct internal deps:
//   - kc/domain (extracted PR 4.1 stub at commit d4bb3e6) — used in
//     alert_spec.go, store.go, briefing.go, composite_test.go, etc.
//   - kc/logger (extracted at commit 1b7dcbf) — logport interface
//   - kc/isttz (extracted at commit a2ad8e0) — IST market hours
//   - broker/zerodha (extracted at commit 5d74acf) — used in
//     briefing.go for KiteAdapter type
//   - testutil (still in root) — used in briefing_injection_test.go
//     and helpers_test.go for fixture setup
//
// Replace block has 6 entries — root (for testutil) + broker +
// kc/domain + kc/isttz + kc/logger + kc/money (transitive via
// kc/domain → broker → kc/money chain). One more replace than
// kc/cqrs / kc/eventsourcing because kc/alerts directly references
// testutil which still lives in root.
//
// Tier 4 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): heavy fan-in packages extracted in order to
// minimize transitive replaces. This is 21/24 (commit 1 of 4 in
// this dispatch — must come BEFORE kc/papertrading + kc/usecases +
// kc/telegram which all import kc/alerts).
require (
	github.com/go-telegram-bot-api/telegram-bot-api/v5 v5.5.1
	github.com/google/uuid v1.6.0
	github.com/stretchr/testify v1.10.0
	github.com/zerodha/gokiteconnect/v4 v4.4.0
	github.com/algo2go/kite-mcp-broker v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/domain v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/isttz v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/logger v0.0.0-00010101000000-000000000000
	github.com/zerodha/kite-mcp-server/kc/money v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/testutil v0.0.0-00010101000000-000000000000
	modernc.org/sqlite v1.46.1
)

require (
	go.uber.org/goleak v1.3.0
	golang.org/x/crypto v0.48.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/gocarina/gocsv v0.0.0-20180809181117-b8c38cb1ba36 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/tools v0.41.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
)

replace (
	github.com/zerodha/kite-mcp-server => ../..
	github.com/algo2go/kite-mcp-broker => ../../broker
	github.com/zerodha/kite-mcp-server/kc/domain => ../domain
	github.com/zerodha/kite-mcp-server/kc/isttz => ../isttz
	github.com/zerodha/kite-mcp-server/kc/logger => ../logger
	github.com/zerodha/kite-mcp-server/kc/money => ../money
	github.com/zerodha/kite-mcp-server/testutil => ../../testutil
)
