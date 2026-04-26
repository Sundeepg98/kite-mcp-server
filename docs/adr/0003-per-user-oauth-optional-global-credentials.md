# ADR 0003: Per-User OAuth With Optional Global Kite Credentials

**Status**: Accepted (2026-04-26, retrospective — original decision Feb 2026)
**Author**: kite-mcp-server architecture
**Decision drivers**: Multi-user hosted deployment on Fly.io; Kite Connect's per-app
single-active-session constraint; SEBI-mandated developer-app credentials per user.

---

## Context

Kite Connect's authentication model has a hard architectural constraint:
**every user must authenticate through a Kite developer app, identified by
`api_key` + `api_secret`**. There is no shared "platform" identity; the
developer app credentials *are* the OAuth client.

A single developer app supports **one active user session at a time** (Kite
issues a fresh `access_token` per `request_token` exchange, but each
`api_key` has session-instance limits enforced server-side at Zerodha).
That is fine for a desktop MCP that one human runs against their own
account, but breaks the moment the server is hosted with multiple users
expected to coexist.

Pricing reinforces this: each developer app costs ₹500/month (Connect
tier, reduced from ₹2000 mid-2025), so the platform cannot silently rent
"its own" app to every user. SEBI also mandates the developer-app owner
take responsibility for the API access pattern — meaning the
human-in-the-loop must own their own app, not lease one anonymously
from us.

Original deployment (early Feb 2026) shipped a single global
`KITE_API_KEY` / `KITE_API_SECRET`. This worked for the first user,
who happened to be the operator. As soon as a second user attempted
to authenticate, both sessions raced and one was kicked. The fix had
to support both:

1. Local single-user dev (`KITE_API_KEY` + `KITE_API_SECRET` env, no OAuth
   layer needed — fastest path for personal testing).
2. Hosted multi-user (each user supplies their own developer app via
   MCP client config; server holds no global Kite credentials).

## Decision

Make global Kite credentials **optional**. Per-user credentials become
the primary path for any deployment with `OAUTH_JWT_SECRET` set
(the hosted-mode flag).

The startup gate at `app/app.go:517-525`:

```go
if app.Config.KiteAPIKey == "" || app.Config.KiteAPISecret == "" {
    if app.DevMode {
        app.logger.Info("DEV_MODE: Kite credentials not required — mock broker will be used")
    } else if app.Config.OAuthJWTSecret == "" {
        return fmt.Errorf("KITE_API_KEY and KITE_API_SECRET are required (or enable OAuth with OAUTH_JWT_SECRET for per-user credentials)")
    } else {
        app.logger.Info("No global Kite credentials — per-user credentials required via MCP client config (oauth_client_id/oauth_client_secret)")
    }
}
```

The `oauth.Config.KiteAPIKey` field is intentionally documented as
optional at `oauth/config.go:12,21`:

```go
KiteAPIKey  string  // Kite API key for generating login URLs (optional: per-user credentials via oauth_client_id)
```

When a dynamic-registration client tries to authorize without supplying
its own credentials *and* no global `KITE_API_KEY` is configured, the
authorize endpoint at `oauth/handlers_oauth.go:100-104` returns:

```
"No Kite API credentials configured. Set oauth_client_id and oauth_client_secret in your MCP client config."
```

— forcing the user to register their own developer app. Per-user
credentials are stored in `KiteCredentialStore` (AES-256-GCM, key
derived from `OAUTH_JWT_SECRET` via HKDF), persisted in the same
SQLite database as alerts and sessions.

## Alternatives considered and rejected

**A. Single shared developer app for all users.** Rejected because Kite
enforces one active session per `api_key`. Two concurrent users of the
hosted server would silently kick each other's session every few
seconds. Confirmed empirically before Feb 2026 — the symptom that
forced this ADR's underlying decision.

**B. Server provisions a developer app per user automatically.** Rejected
because Kite has no programmatic developer-app creation API. Apps are
manually created via `developers.kite.trade` web UI, requires Kite
admin approval (~1 business day), and is billed to the creator. Cannot
be automated and cannot be charged through to the user.

**C. Pool of N developer apps assigned round-robin.** Rejected on
SEBI/regulatory grounds: SEBI policy (NSE/INVG/69255 Annexure I) ties
algo identification to the developer app — an app shared across
unrelated users muddies attribution. Also degrades to A above when
N < concurrent users.

**D. Drop hosted multi-user; ship local-only.** Considered seriously.
Rejected because the entire MCP-on-Fly.io thesis (warm-intro from
Rainmatter, MCP Registry listing, ChatGPT Apps onboarding) requires a
hosted URL. Local-only would force users back to `npx mcp-remote`
plumbing every install.

**E. Make global creds mandatory + require OAuth even in dev.** Rejected
because it adds 30+ seconds of OAuth ceremony to every local test run.
DEV_MODE bypass + optional global creds preserves both paths.

## Consequences

**Positive**:
- Hosted Fly.io deployment runs with **zero global Kite credentials**
  (verified: `flyctl secrets list -a kite-mcp-server` shows no
  `KITE_API_KEY` / `KITE_API_SECRET`).
- Each user is fully isolated; one user's expired token cannot affect
  another's session.
- Compliance attribution is clean: SEBI/Zerodha can trace any order
  back to the user's own developer app, not a shared platform identity.
- Local single-user dev is unchanged — `KITE_API_KEY` env var still
  works the same way.
- DEV_MODE keeps mock-broker testing fast.

**Neutral**:
- Onboarding adds one step ("create your own Kite developer app at
  developers.kite.trade") that some users find friction-y. Cohort-1
  data shows ~20% drop-off here.
- Documentation at `docs/byo-api-key.md` exists specifically to walk
  new users through this. Without that doc, the feature would be
  unusable.

**Negative**:
- Two startup paths to reason about (`OAUTH_JWT_SECRET` set vs unset)
  doubles the test matrix for any auth-touching change. Mitigation:
  `app/server_oauth_test.go` exercises both paths.
- A misconfigured deployment (`OAUTH_JWT_SECRET` set, no `EXTERNAL_URL`)
  fails fast at startup (`app/app.go:528-530`) — visible as a startup
  crash, not a runtime mystery, but still a foot-gun.

## References

- `app/app.go:517-525` — credential-validity gate at startup
- `oauth/config.go:12,21` — `KiteAPIKey` documented as optional
- `oauth/handlers_oauth.go:100-104` — authorize-endpoint guidance message
- Commit `3fee49e` (2026-02-23) — "feat: make global Kite credentials
  optional when OAuth is enabled"
- Commit `2c5d4b2` (2026-02-23) — "fix: show login success page after
  OAuth callback instead of blank loading screen" (companion UX fix)
- `kc/credentialstore/` — AES-256-GCM encrypted per-user store
- `docs/byo-api-key.md` — user-facing onboarding doc for the
  per-user-credential flow
- MEMORY note: "Architecture: Per-user OAuth with optional global
  credentials (Feb 2026, commit `2c5d4b2`)"
