# Contributing

Contributions welcome! Check [open issues](https://github.com/Sundeepg98/kite-mcp-server/issues) for ideas.

## Requirements

- Go 1.25+ (uses `GOEXPERIMENT=synctest` for time-dependent tests)
- [just](https://github.com/casey/just) command runner (optional but recommended)

## Getting Started

```bash
git clone https://github.com/Sundeepg98/kite-mcp-server
cd kite-mcp-server
go build ./...       # or: just build
just test            # run all tests (CGO_ENABLED=0 GOEXPERIMENT=synctest)
just lint            # format + vet + golangci-lint
```

For local development with a Kite account:

```bash
cp .env.example .env  # fill in your Kite API key/secret
just run-env          # builds and runs with .env loaded
```

## Architecture

```
main.go              → entrypoint, version injection
app/                  → application wiring, config, HTTP setup
mcp/                  → MCP tool handlers (one file per tool group)
kc/                   → core packages:
  kc/manager.go       → per-user Kite client management
  kc/billing/         → Stripe billing tier enforcement
  kc/riskguard/       → 8 pre-trade safety checks
  kc/papertrading/    → simulated order engine
  kc/audit/           → tool call audit trail (SQLite)
  kc/alerts/          → price alerts + Telegram delivery
  kc/ops/             → admin + user dashboard handlers
  kc/templates/       → embedded HTML templates + static assets
  kc/telegram/        → Telegram bot commands
  kc/scheduler/       → cron-like scheduled tasks
oauth/                → OAuth 2.1 + PKCE provider
```

## Code Conventions

- **No CGO** for builds (`CGO_ENABLED=0`) — all SQLite uses the pure-Go driver.
- **Tests** use `GOEXPERIMENT=synctest` for deterministic time control.
- **Error handling**: wrap errors with context (`fmt.Errorf("action: %w", err)`).
- **Imports**: stdlib, blank line, third-party, blank line, internal packages.
- **Tool handlers** live in `mcp/` — one file per tool group, each tool gets an annotation in `mcp/annotations.go`.

## PR Checklist

- [ ] `go build ./...` compiles cleanly
- [ ] `go vet ./...` passes
- [ ] `just test` passes (or `CGO_ENABLED=0 GOEXPERIMENT=synctest go test ./...`)
- [ ] New tools have an entry in `mcp/annotations.go` with correct hints
- [ ] New tools have a tier entry in `kc/billing/tiers.go` (even if `TierFree`)
- [ ] Sensitive operations go through RiskGuard (`kc/riskguard/`)
- [ ] No secrets or credentials committed

## License

By contributing, you agree that your contributions will be licensed under the [MIT License](LICENSE).
