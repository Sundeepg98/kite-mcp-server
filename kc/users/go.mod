module github.com/zerodha/kite-mcp-server/kc/users

go 1.25.0

// kc/users is a single-internal-dep module — user identity store
// (CRUD + RBAC + bcrypt password hashing). Direct internal dep =
// kc/alerts (still in root module). Same transitive-replace shape
// as kc/registry (commit eb1577e): kc/alerts reaches kc/logger,
// kc/isttz, broker, and kc/money via kc/domain → broker → kc/money
// chain.
//
// Tier 2 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): single-dep packages extracted in a single
// dispatch. Replace count: 5.
require (
	github.com/stretchr/testify v1.10.0
	github.com/zerodha/kite-mcp-server v0.0.0-00010101000000-000000000000
	github.com/algo2go/kite-mcp-broker v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/isttz v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/logger v0.0.0-00010101000000-000000000000 // indirect
	github.com/zerodha/kite-mcp-server/kc/money v0.0.0-00010101000000-000000000000 // indirect
	golang.org/x/crypto v0.48.0
)

require (
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/dustin/go-humanize v1.0.1 // indirect
	github.com/go-telegram-bot-api/telegram-bot-api/v5 v5.5.1 // indirect
	github.com/gocarina/gocsv v0.0.0-20180809181117-b8c38cb1ba36 // indirect
	github.com/google/go-querystring v1.0.0 // indirect
	github.com/google/uuid v1.6.0 // indirect
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/mattn/go-isatty v0.0.20 // indirect
	github.com/ncruces/go-strftime v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	github.com/remyoudompheng/bigfft v0.0.0-20230129092748-24d4a6f8daec // indirect
	github.com/zerodha/gokiteconnect/v4 v4.4.0 // indirect
	golang.org/x/exp v0.0.0-20251023183803-a4bb9ffd2546 // indirect
	golang.org/x/sys v0.41.0 // indirect
	golang.org/x/tools v0.41.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
	modernc.org/libc v1.67.6 // indirect
	modernc.org/mathutil v1.7.1 // indirect
	modernc.org/memory v1.11.0 // indirect
	modernc.org/sqlite v1.46.1 // indirect
)

replace (
	github.com/zerodha/kite-mcp-server => ../..
	github.com/algo2go/kite-mcp-broker => ../../broker
	github.com/zerodha/kite-mcp-server/kc/isttz => ../isttz
	github.com/zerodha/kite-mcp-server/kc/logger => ../logger
	github.com/zerodha/kite-mcp-server/kc/money => ../money
)
