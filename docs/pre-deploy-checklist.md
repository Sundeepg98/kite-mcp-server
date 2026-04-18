# Pre-deploy Checklist

Run through this 5-minute checklist before every `flyctl deploy`. Copy into a commit message or paste into a Slack/note to create paper trail.

## Code quality
- [ ] `go build ./...` clean
- [ ] `go vet ./...` clean
- [ ] Tests pass on changed packages: `go test ./kc/riskguard ./mcp ./oauth ./app -count=1`
- [ ] No new lint warnings (`staticcheck ./...` optional)
- [ ] Any new env vars documented in `docs/env-vars.md`

## Security
- [ ] `ENABLE_TRADING` is `"false"` in `fly.toml` (Path 2 compliance)
- [ ] No credentials committed (grep for `_SECRET`, `_KEY`, `_TOKEN` in diff)
- [ ] New endpoints in the HTTP mux are wrapped by `withRequestID` middleware
- [ ] Any new tool calling `/orders/*` is gated by `ENABLE_TRADING`

## Compliance
- [ ] Disclaimer / draft banners still visible on TERMS.md, PRIVACY.md
- [ ] "Built on Zerodha's open-source Kite MCP Server (MIT)" still in landing.html footer
- [ ] Any new Telegram outbound message uses `sendFinancialHTML` (disclaimer-prefixed)
- [ ] Audit trail still enabled (`kc/audit/` not broken)

## Fly.io infra
- [ ] Fly.io rate limits not reduced inadvertently
- [ ] Static egress IP still `209.71.68.157` (bom region)
- [ ] `OAUTH_JWT_SECRET` still set as secret (not env var)
- [ ] `ADMIN_ENDPOINT_SECRET_PATH` still set
- [ ] Litestream backup path still configured (R2 credentials)

## Documentation
- [ ] CHANGELOG.md updated for this release
- [ ] README.md feature list still accurate (tool count)
- [ ] Any new docs cross-linked from README

## Communication
- [ ] Will notify `kiteconnect@zerodha.com` thread if any external-facing change (optional but polite)
- [ ] Incident response runbook still current (`docs/incident-response.md`)

## Actual deploy

```bash
# Verify commit SHA
git log --oneline -1

# Deploy (remote build on Fly.io)
flyctl deploy -a kite-mcp-server --remote-only

# Verify release version bumped
flyctl releases -a kite-mcp-server | head -3

# Health check
curl -s https://kite-mcp-server.fly.dev/healthz?format=json | jq

# Smoke test
./scripts/smoke-test.sh  # if exists
```

## Rollback

If health check fails or metrics spike:

```bash
# Immediate rollback to prior version
flyctl releases -a kite-mcp-server
flyctl rollback vN -a kite-mcp-server

# Or take machine offline
flyctl machine list -a kite-mcp-server
flyctl machine stop <machine-id> -a kite-mcp-server
```

## Post-deploy (within 30 min)

- [ ] Health check still green after 5 min
- [ ] Error rate in audit trail not elevated (check dashboard)
- [ ] No Zerodha API 429s spiking
- [ ] No user reports of broken widgets / missing tools

## If deploy triggers regulator inquiry

Jump to `docs/incident-response.md` Scenario 4. Do not proceed solo.
