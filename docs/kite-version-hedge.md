# Kite Connect v4 Hedge Strategy

**Last updated:** 2026-04-17
**Owner:** Sundeep Govarthinam (current single operator)

## Risk

The entire trading surface of this server depends on **Kite Connect v3**
and the Go SDK `github.com/zerodha/gokiteconnect/v4` (whose import-path
`v4` tracks the Go SDK's semver, *not* the Kite API version — the SDK
v4.x line wraps Kite API v3).

Two failure modes concern us:

1. **Kite Connect API v4 ships** — Zerodha announces a new broker API
   version and begins deprecating v3. Every endpoint in this codebase
   (orders, holdings, positions, quotes, historical, GTT, MF, …) would
   need migration.
2. **Upstream Go SDK makes a breaking change** — `gokiteconnect` releases
   a new major (e.g. `v5`) with a changed import path or rearranged
   surface. `go get -u` would silently skip it, but a fresh `go mod tidy`
   run on a new machine could pick it up accidentally, or a CI cache miss
   could pull a divergent transitive dependency.

## Research conclusions (Agent 50, Apr 2026)

- **No Kite Connect v4 is on the public horizon** as of this writing.
  No v4 docs page, no developer-forum announcements, no email notice to
  Kite Connect app owners.
- **Historical precedent is ~5 months of migration runway.** Previous
  Zerodha API deprecations have given app operators multiple months
  between announcement and v3 shutdown — enough time to migrate even
  a large tool surface like ours.
- Despite the generous precedent, we want *day-zero awareness* so we
  can start planning the moment v4 docs land rather than finding out
  from a user report.

## Hedges in place

### 1. Pinned + vendorable Go SDK dependency

`go.mod` pins an exact version (no ranges, no `latest`):

```
github.com/zerodha/gokiteconnect/v4 v4.4.0
```

`go.sum` contains the cryptographic hash of that exact module version,
so a malicious or mistaken upstream republish would be rejected by the
Go toolchain.

### 2. On-demand vendoring (not committed)

The repo can be frozen to a full-source snapshot at any time via:

```bash
go mod vendor
```

This materializes **every transitive dependency's source** into
`vendor/`. Once generated, `go build` defaults to consuming from
`vendor/` (Go 1.14+), so the build is hermetic — no module proxy, no
network, no possibility of silent upstream drift.

**We do not commit `vendor/` to the repo.** The directory is 241 MB
(dominated by `modernc.org/sqlite` at 222 MB of Go-translated SQLite
C sources). Committing it would roughly triple clone size and poison
every future `git log` / `git blame` involving mass-regenerated files.

Instead:

- `vendor/` is in `.gitignore`.
- The Go module cache + `go.sum` already give us cryptographic pinning.
- **If** we lose confidence in upstream availability (Zerodha force-
  pushes history, GitHub goes down, the module proxy evicts an old
  version), the operator can regenerate `vendor/` locally, commit it
  to a recovery branch, and `go build -mod=vendor` from there.
- Deploy-time reproducibility is covered by `go.sum` + the Docker
  build copying `go.mod`/`go.sum` before running `go mod download`.

Regenerating the vendor snapshot:

```bash
cd D:\Sundeep\projects\kite-mcp-server
go mod vendor
# verify
go build -mod=vendor ./...
```

To temporarily commit the vendor tree (e.g. during a feared upstream
outage), force-add past gitignore:

```bash
git add -f vendor/
git commit -m "chore: vendor snapshot for <reason>"
```

Remember to remove before merging to master — a 241 MB commit is a
one-way door on clone size.

### 3. Nightly CI watchdog

`.github/workflows/v4-watchdog.yml` runs daily at 02:00 UTC
(~07:30 IST) and probes two signals:

| Signal | Check | Failure behaviour |
|---|---|---|
| `https://kite.trade/docs/connect/v4/` | `HTTP 200` | Workflow fails, `::warning::` annotation on Actions tab, default GitHub "workflow failed" email to repo owner |
| `zerodha/gokiteconnect` latest GitHub release | tag prefix `!= v4` | Same — catches a jump to `v5` |

The workflow runs on `schedule` + `workflow_dispatch` (so the operator
can also fire it manually when they see v4 rumours). It does not gate
PRs or merges; it is a pure alarm.

A failing run in GitHub Actions will:
- Show a red X in the Actions tab of the repo.
- Send an email to the repo owner's default notification address
  ("A workflow run for v4-watchdog failed").
- Surface in `gh run list --workflow=v4-watchdog.yml` for scripted
  polling.

## Response plan if v4 docs appear

The moment the watchdog fires (or we find out some other way) — open
a migration ticket and execute in this order:

1. **Read the v4 docs end-to-end** and catalogue the endpoint-by-endpoint
   diff vs v3 in a migration notes file (`docs/kite-v4-migration.md`).
2. **Freeze the v3 build** — cut a release tag (e.g. `v3-final`) and
   commit a `vendor/` snapshot to a `v3-preserved` branch. This gives
   us a buildable, source-complete copy of the v3 client forever,
   independent of Zerodha or GitHub.
3. **Wait for `gokiteconnect` v5** (the SDK will need to wrap the new
   API). Track its beta/alpha; don't migrate to a direct HTTP client
   unless the SDK stalls.
4. **Feature-flag the migration.** Add a `KITE_API_VERSION` env var.
   Run v3 and v4 adapters side-by-side behind the broker port
   (`kc/broker`). Our Clean Architecture / CQRS split makes this a
   swap of adapter implementations, not a rewrite of tool handlers.
5. **Migrate one endpoint category per PR**, in this order of user
   impact: orders, holdings/positions, quotes, historical, GTT, MF.
   Gate each category behind the feature flag until soak-tested.
6. **Dual-run for the migration window.** For each user, read from v3,
   write to v4 (or vice-versa per risk appetite). Compare results
   asynchronously and alert on divergence.
7. **Cut over** once error rates match. Drop the flag, delete the
   v3 adapter, delete this hedge doc's "response plan" (keep the
   rest as history).

The 5-month precedent is generous for a properly portable codebase.
Our risk is not the migration itself — it is *hearing about v4 late*.
The watchdog closes that specific gap.

## Non-hedges (explicitly not done)

- **We do not fork `gokiteconnect`.** Forking buys us nothing over
  vendoring and costs maintenance. If upstream ships a breaking change,
  we want to migrate, not diverge.
- **We do not pin to a specific Go patch version.** `go.mod` declares
  `go 1.25.0`; the CI and Docker images specify `go-version: '1.25.x'`
  which lets us pick up Go security patches without codebase change.
- **We do not self-host the module proxy.** Go's default `GOPROXY`
  (proxy.golang.org) has module immutability; our `go.sum` hashes
  detect any forced republish. A self-hosted proxy would be a
  maintenance burden with no incremental safety.

## Cross-references

- [cookbook.md](cookbook.md) — adapter layer architecture.
- [operator-playbook.md](operator-playbook.md) — Day-2 ops.
- [incident-response.md](incident-response.md) — if v3 breaks
  unexpectedly (Scenario 2: API).
- Upstream releases: <https://github.com/zerodha/gokiteconnect/releases>
- Kite Connect v3 docs: <https://kite.trade/docs/connect/v3/>
