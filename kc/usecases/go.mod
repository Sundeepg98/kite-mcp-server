module github.com/zerodha/kite-mcp-server/kc/usecases

go 1.25.0

// kc/usecases is a heavy-fan-in module — clean-architecture use cases
// (account, admin, alert, order placement/cancel/modify, position close,
// composite alerts, consent, context, MF, GTT, Telegram trading, paper
// trading orchestration). Direct internal deps (validated by
// `grep github.com/zerodha kc/usecases/*.go`):
//   - broker (extracted at commit 5d74acf) — DTO + adapter
//   - kc/alerts (extracted at commit 8878738) — alert use cases
//   - kc/cqrs (extracted at commit 6ef0a79) — CommandBus + handlers
//   - kc/domain (extracted PR 4.1 stub at commit d4bb3e6) — entities
//   - kc/eventsourcing (extracted at commit 68e92e1) — aggregate roots
//   - kc/logger (extracted at commit 1b7dcbf) — logport
//   - kc/riskguard (extracted at commit 5982aff) — pre-trade checks
//   - kc/users (extracted at commit f32629f) — admin RBAC
//
// Replace block: 15 entries — even higher than kc/papertrading's 10
// (the new plateau-breaking record). kc/usecases has 13 direct
// internal imports vs kc/papertrading's 6, so this is the empirical
// fan-in ceiling. Each direct dep contributes one replace, plus
// transitive reach via root → oauth → kc/templates / kc/users /
// kc/i18n / kc/isttz adds the remainder.
//
// Replace inventory: root + broker + kc/alerts + kc/audit + kc/cqrs +
// kc/domain + kc/eventsourcing + kc/i18n + kc/isttz + kc/logger +
// kc/money + kc/riskguard + kc/templates + kc/ticker + kc/users +
// kc/watchlist. 16 entries.
//
// Tier 4 zero-monolith path (.research/zero-monolith-roadmap.md
// commit a5e7e76): heavy fan-in packages extracted in dep order.
// This is 23/24 (commit 3 of 4 in this dispatch).
require (
	github.com/google/uuid v1.6.0 // indirect
	github.com/stretchr/testify v1.10.0
	github.com/zerodha/kite-mcp-server v0.0.0-00010101000000-000000000000 // indirect
	github.com/algo2go/kite-mcp-broker v0.1.0
	github.com/algo2go/kite-mcp-alerts v0.1.0
	github.com/algo2go/kite-mcp-cqrs v0.1.0
	github.com/algo2go/kite-mcp-domain v0.1.0
	github.com/algo2go/kite-mcp-eventsourcing v0.1.0
	github.com/algo2go/kite-mcp-logger v0.1.0
	github.com/algo2go/kite-mcp-money v0.1.0
	github.com/zerodha/kite-mcp-server/kc/riskguard v0.0.0-00010101000000-000000000000
	github.com/algo2go/kite-mcp-users v0.1.0
)

require (
	github.com/algo2go/kite-mcp-audit v0.1.0
	github.com/algo2go/kite-mcp-ticker v0.1.0
	github.com/algo2go/kite-mcp-watchlist v0.1.0
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
	github.com/gorilla/websocket v1.5.3 // indirect
	github.com/hashicorp/go-hclog v1.6.3 // indirect
	github.com/hashicorp/go-plugin v1.7.0 // indirect
	github.com/hashicorp/yamux v0.1.2 // indirect
	github.com/mark3labs/mcp-go v0.46.0 // indirect
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
	github.com/algo2go/kite-mcp-templates v0.1.0 // indirect
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
	modernc.org/sqlite v1.46.1 // indirect
)

replace (
	github.com/zerodha/kite-mcp-server => ../..
	github.com/zerodha/kite-mcp-server/kc/riskguard => ../riskguard
)
