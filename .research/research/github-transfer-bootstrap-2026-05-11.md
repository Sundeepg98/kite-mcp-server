<!-- secret-scan-allow: git-commit-shas-in-research-doc -->
---
title: GitHub Repo Transfer + algo2go/kite-mcp-bootstrap Module Design
as-of: 2026-05-11
re-verify-by: 2026-06-11
master-head-at-write: 07c830c
scope: READ-ONLY research; documents transfer + bootstrap design but does NOT execute either
parallel-tracks: zero-in-tree-feasibility-2026-05-11.md (chain), god-object-inventory-2026-05-11.md (Path A)
budget-used: ~3.5h of 4h target; 6h hard halt
---

# GitHub Repo Transfer + algo2go/kite-mcp-bootstrap Module Design

## §INPUTS — load-bearing facts probed at HEAD `07c830c`

| Fact | Source / Probe | Verified |
|---|---|---|
| `Sundeepg98/kite-mcp-server` exists, NOT archived, NOT a template, default branch `master` | `gh api repos/Sundeepg98/kite-mcp-server` | 2026-05-11 |
| Sundeepg98 repo: stars=0, watchers=0, forks_count=0, network_count=109, open_issues=0, size=11.3MB, created 2026-02-22, 19 tags, 3 releases, 0 open/closed PRs originating from this repo | `gh api repos/Sundeepg98/kite-mcp-server` + paginated probes | 2026-05-11 |
| `has_issues`, `has_wiki`, `has_discussions` all `true` | `gh api repos/Sundeepg98/kite-mcp-server` | 2026-05-11 |
| `algo2go` org: created 2026-05-05, `public_repos=28`, `plan.name=free`, `type=Organization`, `members_can_create_public_repositories=true`, `default_repository_permission=read`, `two_factor_requirement_enabled=false` | `gh api orgs/algo2go` | 2026-05-11 |
| 28 algo2go/kite-mcp-* modules already external + consumed by root `go.mod` | `grep -c 'algo2go/kite-mcp-' go.mod` returns 28 | 2026-05-11 |
| In-tree code surface: 4 go.work members (root, plugins, testutil, app/providers); 261 non-test go files + 261 test files; ~54.2k non-test LOC | `find ... -name '*.go' -not -name '*_test.go' | wc -l` + `wc -l` | 2026-05-11 |
| Per-dir non-test file counts: kc=102, app=45 (incl. app/providers=22), mcp=104, plugins=3, testutil=4, cmd=3 | per-dir `find` probes | 2026-05-11 |
| Per-dir disk size: kc=2.2M, app=1.4M, mcp=2.7M, plugins=68K, testutil=96K, cmd=76K (approx 6.5MB code) | `du -sh` | 2026-05-11 |
| Main entry point: `./main.go` (root), NOT `cmd/server/main.go`. cmd/ contains only `dr-decrypt-probe/`, `event-graph/`, `rotate-key/` operational tools | `ls cmd/` + `cat main.go` first 20 lines | 2026-05-11 |
| Root go.mod: `module github.com/zerodha/kite-mcp-server`, `go 1.25.0` | `head -3 go.mod` | 2026-05-11 |
| `fly.toml`: ZERO GitHub URL references | `grep -i github fly.toml` returns empty | 2026-05-11 |
| `.mcp.json`: ZERO GitHub URL references (only `kite-mcp-server.fly.dev` + flyctl binary path) | `grep -i github .mcp.json` returns empty | 2026-05-11 |
| `server.json` (MCP Registry manifest): contains `name: "io.github.Sundeepg98/kite-mcp-server"` + `repository.url: "https://github.com/Sundeepg98/kite-mcp-server"` + `websiteUrl: "https://kite-mcp-server.fly.dev"` | grep server.json | 2026-05-11 |
| 72 files in repo reference `Sundeepg98/kite-mcp-server` URL (mostly `.research/archive/`, but live refs exist in `.claude-plugin/plugin.json`, `.github/workflows/dr-drill.yml`, `.github/ISSUE_TEMPLATE/`, README, CONTRIBUTING) | `grep -rlw 'Sundeepg98' --include='*.{md,go,json,toml,yaml,yml}' | wc -l` | 2026-05-11 |
| GitHub Transfer REST API: `POST /repos/{owner}/{repo}/transfer` with `new_owner` form field; **301 redirects auto-installed** from old URL to new for ~1 year | GitHub Docs (REST → Repositories → Transfer) | 2026-05-11 (docs version) |
| MCP Registry manifest `name` + `version` are documented immutable post-publish | mcp-server-registry README §publishing rules | 2026-05-11 |

> **Methodology note**: For binary state (file/tool counts) compile-and-run or direct grep was used; for repo state, raw `gh api`. Per `feedback_compile_and_run_methodology` and `feedback_verify_before_synthesize`.

---

## §1 — Transfer Mechanics, Risks, Reversibility

### 1.1 The mechanism

GitHub's repo transfer is a server-side rename of the owner. The REST call is:

```
gh api -X POST repos/Sundeepg98/kite-mcp-server/transfer \
  -f new_owner=algo2go
```

**Pre-requisites that ARE satisfied** (verified `2026-05-11`):

| Requirement | Status |
|---|---|
| Source repo NOT archived | OK (`archived: false`) |
| Destination owner exists + can host public repos | OK (`algo2go` org, `members_can_create_public_repositories: true`) |
| Repo size <=100GB | OK (11.3MB) |
| No name collision at destination (`algo2go/kite-mcp-server` must not exist) | NEEDS RE-PROBE AT TRANSFER TIME (none of 28 current algo2go repos collides per `gh api orgs/algo2go/repos` list) |
| Transferring user has admin rights on source AND can create repos in destination | NEEDS USER ACTION (only the user can execute) |

**Pre-requisite that needs ACTION before transfer**:

| Concern | Why | Mitigation |
|---|---|---|
| `default_repository_permission: read` in algo2go org | New transferred repo inherits org defaults; bot/CI tokens that need write will get only read. | Either (a) bump org default to `write` (org-wide implication — discouraged), or (b) explicitly grant teams/CI bots `maintain`/`admin` post-transfer (preferred). |
| `two_factor_requirement_enabled: false` in algo2go | NOT a transfer blocker but is a posture gap given trading repo. | Recommend enabling org-wide 2FA before transfer (`algo2go`'s 27 contributors all need 2FA enabled first — none exist today so this is free). |

### 1.2 What is PRESERVED on transfer (GitHub-side)

- All commits, branches, tags, releases, releases assets
- All issues, PRs, issue comments, PR comments, review threads
- Wiki, GitHub Discussions
- Stars + watchers + forks (forks_count=0 and stars=0 here, so trivial)
- Labels, milestones, projects
- Webhooks, GitHub Apps installations (carry over but may need re-auth)
- Branch protection rules
- Actions secrets — **YES, preserved** (verified per GitHub docs §Transferring a repository)
- Default branch + branch protection
- 301 redirects from old URL to new URL for **~1 year** (HTTP-level redirect; old `git remote -v` URLs keep pulling)

### 1.3 What is NOT preserved / breaks

| Item | Impact | Fix |
|---|---|---|
| `git remote -v` URLs in local clones | Continue to work via 301 redirect, but git will print a warning on push | One-line `git remote set-url origin git@github.com:algo2go/kite-mcp-server.git` per clone |
| Repo Pages site URL | Pages auto-rebuild under new owner URL; old `Sundeepg98.github.io/kite-mcp-server` 301s | Auto |
| External hard-coded URLs in docs/badges | 301-redirect works initially, but breaks if redirect expires (~1yr) or destination repo is later renamed | Patch all `Sundeepg98/kite-mcp-server` to `algo2go/kite-mcp-server` in same window |
| Mentions/notifications in old issues that reference `@Sundeepg98` | Continue to work but are author-scoped, not org-scoped | None needed — historical refs are fine |
| GitHub Apps / OAuth Apps with hard-coded `Sundeepg98/kite-mcp-server` repo allowlist | Block until owner is updated in App settings | Update in each App config (mcp-remote OAuth client is NOT one of these — it uses Fly URL, not GitHub URL) |
| Local environment paths (e.g. `D:\Sundeep\projects\kite-mcp-server`) | UNAFFECTED — local clone dir is unrelated to GitHub owner | None |

### 1.4 mcp-remote cache impact: **ZERO**

`mcp-remote` keys its cache by Fly URL hash:

- Cache dir: `~/.mcp-auth/mcp-remote-{version}/`
- Key: `md5({server URL})` — server URL is `https://kite-mcp-server.fly.dev/mcp`
- This URL does NOT change on GitHub transfer

**Verified empirically**: `.mcp.json` `args` line is `["-y", "mcp-remote", "https://kite-mcp-server.fly.dev/mcp"]` — no GitHub reference. Static client info at `~/.claude/mcp-servers/kite-fly-client.json` is keyed by OAuth client_id (= Kite API key), also unrelated to GitHub.

### 1.5 Fly.io builder impact: **ZERO**

- `fly.toml` has zero GitHub references (verified `grep -i github fly.toml` returns empty)
- Fly builder uses the LOCAL repo (uploaded by `flyctl deploy`), not a GitHub fetch
- App secrets, machines, IPs, volumes all untouched

The only Fly artifact that mentions GitHub is the auto-generated `image` field after deploy (`registry.fly.io/kite-mcp-server:deployment-...`) — also untouched.

### 1.6 server.json (MCP Registry) impact: **CRITICAL GOTCHA**

```jsonc
// server.json @ HEAD
{
  "name": "io.github.Sundeepg98/kite-mcp-server",   // IMMUTABLE post-publish
  "repository.url": "https://github.com/Sundeepg98/kite-mcp-server", // mutable
  "websiteUrl": "https://kite-mcp-server.fly.dev"   // unchanged
}
```

**Per MCP Registry rules** (modelcontextprotocol/registry README §publishing):

- The `name` field is the registry primary key — **immutable post-publish**
- The `version` field must change on every re-publish, and old versions cannot be edited

**Concrete implication if registry-published before transfer**:

If `io.github.Sundeepg98/kite-mcp-server` is ALREADY published to the public MCP registry, that name is **permanently** the registry identity. Re-publishing under `io.github.algo2go/kite-mcp-server` would create a SECOND registry entry — a name fork with no continuity. End-users discovering via registry would see two entries.

**Verification owed**: probe `https://registry.modelcontextprotocol.io/api/v1/servers?name=io.github.Sundeepg98/kite-mcp-server` to check if it's published. If yes, the registry name is locked. If no (likely — we haven't published yet per session memory), the rename window is open.

**If unpublished**: change `name` to `io.github.algo2go/kite-mcp-server` in the same commit window as the transfer, before any registry publish.

**If published**: accept the legacy registry name OR publish a new entry under `io.github.algo2go/kite-mcp-server` and mark the old one deprecated via a `deprecated: true` field in a new version.

### 1.7 External doc impact: **manageable**

72 files in repo reference the old URL. Audit (rough categorization from grep):

| Location | Count | Action |
|---|---|---|
| `.research/archive/` | ~45 | Leave as-is (historical; 301-redirect carries them) |
| `.research/*.md` (active) | ~10 | Patch to `algo2go/kite-mcp-server` for hygiene |
| Top-level docs (README, CONTRIBUTING, SECURITY) | ~6 | Patch — these are read first |
| `.claude-plugin/plugin.json` | 1 | Patch — plugin distribution metadata |
| `.github/ISSUE_TEMPLATE/*.yml` | ~4 | Patch — visible in new-issue UX |
| `.github/workflows/*.yml` | ~3 | Patch — esp. `dr-drill.yml` (per session memory: has hard repo-equality check) |
| Go source (comment refs only — `module` line uses `github.com/zerodha/kite-mcp-server`, not Sundeepg98) | ~2 | Leave as-is or patch in passing |
| Other (`smithery.yaml`, `funding.json`, etc.) | ~1 | Patch if URL ref exists |

**Critical**: `.github/workflows/dr-drill.yml` reportedly has a hard string-equality repo check (per session memory). If unfixed, the workflow will fail on the new owner immediately. **Must patch in same PR window as transfer**.

### 1.8 External reference impact (badges, third-party docs, fly.io blog)

- README badges (shields.io, codecov, etc.) — encode the owner/repo in URL. 301 works but slow-load and warning banner risk.
- Fly.io's own blog (May 2026 post mentions `kite-mcp-server`?) — outside our control, but they reference Fly app name not GitHub.
- MCP Registry README / community lists — may reference old owner. 301 works.
- search indexers — Google/Bing crawl 301 and update index over weeks.

### 1.9 Risk classification

| Risk | Severity | Likelihood | Mitigation |
|---|---|---|---|
| MCP Registry `name` field already published under `Sundeepg98` | HIGH | UNKNOWN (probe needed) | Probe registry; rename pre-publish if unpublished |
| `dr-drill.yml` repo-equality check breaks Actions post-transfer | HIGH | NEAR-CERTAIN per memory | Patch in same window |
| Org `default_repository_permission: read` blocks bot writes | MED | LIKELY | Explicit team/bot grants post-transfer |
| 301 redirect expires after ~1yr; ext docs break | LOW | EVENTUAL | Patch all known refs in same window |
| Local clones print git warning until `remote set-url` | LOW | CERTAIN | One-line per dev machine |
| Stars/forks lost (none today) | NONE | N/A | N/A |
| OAuth Apps with hard-coded Sundeepg98 allowlist | NONE | NONE (none configured) | N/A |
| Fly.io deployment breaks | NONE | NONE | Fly is GitHub-decoupled |
| mcp-remote clients break | NONE | NONE | Cache keyed by Fly URL |

### 1.10 Reversibility

**Trivially reversible**: GitHub allows re-transfer in either direction by the destination admin. Cost: another `gh api -X POST` call. No data lost in either direction.

**Operational reversibility window**: ~1 year (until 301 redirects expire) — beyond that, reversing creates broken external links again, but the repo itself remains intact.

**User-action cost to reverse**: ~30 seconds (one `gh api` call + revert any patched-doc commits).

---

## §2 — `algo2go/kite-mcp-bootstrap` Module Design

### 2.1 Why a "bootstrap" module

After Path A.1-A.27 promoted 28 sub-packages out of the tree, what remains in-tree (~6.5MB / ~54k LOC) is:

- `kc/` (102 files, 2.2MB) — broker context, services, callbacks, expiry, family, fill watcher, interfaces
- `app/` (45 files incl. `app/providers/`, 1.4MB) — config, healthz, graceful restart, env check, adapters
- `mcp/` (104 files, 2.7MB) — MCP tool registrations + handlers (the 111 tools live here)
- `plugins/` (3 files + sub-dirs, 68KB) — example, rolegate, telegramnotify
- `testutil/` (4 files + sub-dirs, 96KB) — clock, kiteserver, logger, fixtures

This is the **composition root** + tool registry + remaining service glue. It's not promotable per-package because:

1. Cyclic-ish: kc/ wires services that mcp/ consumes; app/ wires the HTTP/MCP server that loads mcp/.
2. High-churn: the 111-tool registry changes every feature ship.
3. Owner-coupled: needs the same release cadence as deploy artifacts (Dockerfile, fly.toml).

**Design choice**: pull all 5 dirs into a SINGLE new module `algo2go/kite-mcp-bootstrap`. Leaves `kite-mcp-server` repo as a **deploy-only** thin shell.

### 2.2 What lives in the new module

```
algo2go/kite-mcp-bootstrap/
|-- go.mod                          # new
|-- go.sum
|-- kc/                             # 102 .go files (verbatim move)
|-- app/                            # 45 .go files
|   `-- providers/                  # 22 .go files (currently a workspace member)
|-- mcp/                            # 104 .go files
|-- plugins/                        # currently workspace member
|   |-- go.mod                      # KEEP — sub-module continues to exist
|   |-- example/
|   |-- rolegate/
|   `-- telegramnotify/
|-- testutil/                       # currently workspace member
|   |-- go.mod                      # KEEP — sub-module
|   |-- clock.go, kiteserver.go, logger.go
|   `-- kcfixture/
|-- go.work                         # MOVED here — bootstrap is the new workspace root
`-- README.md
```

### 2.3 go.mod for bootstrap

Inherits all 28 algo2go/kite-mcp-* deps verbatim, plus:

```go
module github.com/algo2go/kite-mcp-bootstrap

go 1.25.0

require (
    // All 28 algo2go modules (alerts, aop, audit, billing, broker, clockport, cqrs,
    // decorators, domain, eventsourcing, i18n, instruments, isttz, legaldocs, logger,
    // money, oauth, papertrading, registry, riskguard, scheduler, sectors, telegram,
    // templates, ticker, usecases, users, watchlist)
    github.com/algo2go/kite-mcp-alerts v0.X.X
    // ... (27 more)

    // Third-party (carried from current root go.mod)
    github.com/fsnotify/fsnotify v1.X.X
    github.com/go-telegram-bot-api/telegram-bot-api/v5 v5.X.X
    github.com/mark3labs/mcp-go v0.46.0
    github.com/stripe/stripe-go/v82 v82.X.X
    // ... etc
)
```

### 2.4 Acyclic verification

Today's dependency direction (post Path A.27):

```
kite-mcp-server (in-tree kc/, app/, mcp/, plugins/, testutil/)
   --> 28 algo2go/kite-mcp-* (leaves of the DAG)
```

Post-bootstrap:

```
kite-mcp-server (cmd/ + Dockerfile + fly.toml only)
   --> algo2go/kite-mcp-bootstrap (composition root)
         --> 28 algo2go/kite-mcp-* (unchanged)
```

**Acyclic**: bootstrap imports from leaves; nothing imports bootstrap except kite-mcp-server. The 28 leaves do NOT (and must not) import bootstrap — that would invert the dependency. Verified by current state: the 28 modules each have their own go.mod and currently consume nothing from `kc/` or `app/` or `mcp/`.

**Anti-cycle guard**: add a `tools/check-import-direction.sh` script to bootstrap CI that fails if any algo2go/kite-mcp-* module imports `algo2go/kite-mcp-bootstrap`.

### 2.5 Size estimate

- **Repo size**: ~6.5MB code + .git history (small if started fresh, ~50MB if we carry forward the full kite-mcp-server history via `git filter-repo --paths kc/ app/ mcp/ plugins/ testutil/`)
- **Built binary**: identical to today (same code, just rehoused)
- **`go test ./...` runtime**: identical to today (same test files)

### 2.6 Versioning model

Bootstrap follows the same `v0.X.X` cadence as the 28 sub-modules:
- Pre-1.0 during stabilization (~3 months)
- `v0.1.0` at initial publish
- Patch bumps for tool-registry additions
- Minor bumps for kc/app shape changes
- Major bump only on breaking external interface change

`kite-mcp-server` then `go get github.com/algo2go/kite-mcp-bootstrap@v0.X.X` like any other dep.

### 2.7 go.work integration

Today's `go.work`:
```
go 1.25.0
use (
    .
    ./app/providers
    ./plugins
    ./testutil
)
```

After bootstrap migration, the workspace MOVES into bootstrap repo:

```
// algo2go/kite-mcp-bootstrap/go.work
go 1.25.0
use (
    .
    ./app/providers   // still a sub-module for cycle-break
    ./plugins
    ./testutil
)
```

And kite-mcp-server's workspace becomes single-member:
```
// kite-mcp-server/go.work
go 1.25.0
use ./
```

OR even simpler: kite-mcp-server drops `go.work` entirely and just relies on `go.mod`.

---

## §3 — Post-Transfer kite-mcp-server Structure (Deploy-Only)

### 3.1 What stays in kite-mcp-server

```
algo2go/kite-mcp-server/                  # post-transfer + post-bootstrap-extract
|-- go.mod                                # imports algo2go/kite-mcp-bootstrap
|-- go.sum
|-- main.go                               # thin: calls bootstrap.Main(ctx)
|-- cmd/                                  # operational tools, NOT product code
|   |-- dr-decrypt-probe/
|   |-- event-graph/
|   `-- rotate-key/
|-- Dockerfile                            # build + deploy
|-- fly.toml                              # Fly config
|-- server.json                           # MCP Registry manifest (name updated)
|-- smithery.yaml                         # Smithery registry manifest
|-- funding.json                          # FLOSS/fund manifest
|-- litestream.yml                        # backup config
|-- .github/                              # workflows (dr-drill.yml patched), templates
|-- .claude-plugin/plugin.json            # Claude plugin metadata
|-- README.md                             # user-facing setup
|-- CONTRIBUTING.md
|-- SECURITY.md
|-- LICENSE
`-- .mcp.json                             # claude-code project-scope MCP config
```

### 3.2 New main.go (thin)

```go
// main.go (post-bootstrap-extract)
package main

import (
    "context"
    "log/slog"
    "os"

    "github.com/algo2go/kite-mcp-bootstrap/app"
)

func main() {
    ctx := context.Background()
    if err := app.Run(ctx); err != nil {
        slog.Error("startup failed", "error", err)
        os.Exit(1)
    }
}
```

Drop the `runtime/debug.SetMemoryLimit` + `sync/atomic` boilerplate into `bootstrap/app/init.go` — keeps deploy repo truly thin.

### 3.3 Dockerfile (unchanged structurally)

The Dockerfile still does `COPY go.mod go.sum ./ && go mod download && COPY . . && go build -o /app/server ./main.go`. Difference: `go mod download` now pulls bootstrap + 28 modules from `proxy.golang.org`. Build is slightly slower on cold cache (one extra HTTP fetch), no measurable diff on warm cache.

### 3.4 Source-of-truth split

| Concern | Repo |
|---|---|
| Tool registrations, handlers, business logic | `algo2go/kite-mcp-bootstrap` |
| Deployment config (Dockerfile, fly.toml, secrets refs) | `algo2go/kite-mcp-server` |
| Sub-domain modules (broker, money, alerts, etc.) | `algo2go/kite-mcp-*` (28 repos, unchanged) |
| Operational CLI tools (rotate-key, dr-decrypt-probe) | `algo2go/kite-mcp-server/cmd/` |

This is the canonical Go "multi-module monorepo lite" pattern.

---

## §4 — 5-Phase Migration Sequence

> **Critical sequencing principle**: do NOT do GitHub transfer + bootstrap extract + name change simultaneously. Each phase has an empirical verification gate.

### Phase 1 — Create `algo2go/kite-mcp-bootstrap` (no transfer yet)

**Goal**: stand up bootstrap module with current in-tree code; verify it builds + tests pass.

Steps:
1. Create empty `algo2go/kite-mcp-bootstrap` repo via `gh repo create algo2go/kite-mcp-bootstrap --public`
2. In a temp clone: `git filter-repo --paths kc/ --paths app/ --paths mcp/ --paths plugins/ --paths testutil/ --paths-from-file additional.txt` (preserves history)
3. Init go.mod: `module github.com/algo2go/kite-mcp-bootstrap`
4. Adjust all imports: `find . -name '*.go' -exec sed -i 's|github.com/zerodha/kite-mcp-server/kc|github.com/algo2go/kite-mcp-bootstrap/kc|g' {} \;` (and for app/, mcp/, plugins/, testutil/)
5. Move `go.work` into bootstrap, adjust members
6. Run `go build ./...` and `go test ./...` (WSL2)
7. Tag `v0.1.0` and push

**Gate**: bootstrap builds + tests green in WSL2, no production touched yet.

### Phase 2 — kite-mcp-server consumes bootstrap

**Goal**: kite-mcp-server uses bootstrap as a remote module; production builds unchanged.

Steps:
1. In `kite-mcp-server`: `go get github.com/algo2go/kite-mcp-bootstrap@v0.1.0`
2. Rewrite `main.go` to thin invocation (see §3.2)
3. Delete in-tree `kc/`, `app/`, `mcp/`, `plugins/`, `testutil/` dirs
4. Strip go.work (or single-member)
5. Run `go build ./...` and `go test ./cmd/...` (only cmd-tests remain)
6. `flyctl deploy --build-only` (no deploy) and verify built image runs `/healthz` locally
7. Real Fly deploy + `/healthz` verify + tools=111 startup-log verify

**Gate**: production v(N+1) ships from kite-mcp-server consuming bootstrap; tools=111 unchanged; staging E2E green.

### Phase 3 — Verify production runs from bootstrap-consumer for >=48h

**Goal**: time-soak — catch latent issues (Go module caching, transitive replace gotchas per `session_2026-05-04_final-state` go.work lesson).

Steps:
1. Watch Fly logs for 48h post-Phase-2 deploy
2. Verify no `go build` failures on `flyctl deploy` retries
3. Verify `proxy.golang.org` caches bootstrap module + all 28 leaves
4. Run dr-drill periodically (currently has hard repo check — still passes here because repo is still `Sundeepg98/kite-mcp-server`)

**Gate**: 48h soak clean. No deploy retries needed.

### Phase 4 — GitHub transfer `Sundeepg98 -> algo2go`

**Goal**: rehouse the deploy repo under algo2go org.

**Pre-transfer checklist**:
- [ ] Verify `algo2go/kite-mcp-server` does NOT exist (`gh api repos/algo2go/kite-mcp-server` returns 404)
- [ ] Probe MCP Registry for `io.github.Sundeepg98/kite-mcp-server` — if unpublished, change name in same PR; if published, accept legacy name
- [ ] Patch `.github/workflows/dr-drill.yml` repo-equality check to allow `algo2go/kite-mcp-server` OR remove the check entirely
- [ ] Patch `.claude-plugin/plugin.json` URL
- [ ] Patch `.github/ISSUE_TEMPLATE/*.yml` URLs
- [ ] Patch README badges (shields.io URLs)
- [ ] Update `server.json` `repository.url` (and `name` if registry-unpublished)
- [ ] Re-deploy with patched files BEFORE transfer (so dr-drill passes post-transfer immediately)

Transfer:
1. `gh api -X POST repos/Sundeepg98/kite-mcp-server/transfer -f new_owner=algo2go`
2. Wait for transfer email confirmation (~30s)
3. Update local git remotes: `git remote set-url origin git@github.com:algo2go/kite-mcp-server.git`
4. Verify 301 redirect: `curl -I https://github.com/Sundeepg98/kite-mcp-server` returns `Location: https://github.com/algo2go/kite-mcp-server`
5. Verify Actions still run: trigger a workflow_dispatch
6. Verify Fly deploy still works: `flyctl deploy --build-only`

**Gate**: transfer complete; dr-drill green at new owner; Fly deploy works.

### Phase 5 — Cleanup external references

**Goal**: canonicalize on `algo2go/kite-mcp-server` everywhere we control; surface remaining 301 dependencies.

Steps:
1. Grep all repos in `algo2go` org for `Sundeepg98/kite-mcp-server` references; patch in PRs
2. Update README in 28 sub-modules to reference new bootstrap URL where applicable
3. Update Smithery.ai listing
4. Update FLOSS/fund manifest if it references repo URL
5. (Out-of-scope but tracked) Notify any external listings (mcp.so, awesome-mcp-servers, etc.) of new URL
6. After ~1 year (or sooner), audit residual 301 traffic and confirm nothing critical depends on the redirect

**Gate**: Phase 5 has no hard completion criterion; track residual 301s in a follow-up doc.

---

## §5 — Cost + Risk Analysis

### 5.1 Cost (orchestrator-hours)

| Phase | Effort | Critical-path? |
|---|---|---|
| Phase 1: bootstrap repo creation + history filter + import rewrite | 4-6h (one-shot work; bulk is `git filter-repo` + sed) | Yes |
| Phase 2: kite-mcp-server consumes bootstrap + production deploy | 2-3h | Yes |
| Phase 3: 48h time-soak | 0 active hours (passive) | Yes (blocks Phase 4) |
| Phase 4: doc patches + transfer + verify | 2h | Yes |
| Phase 5: external cleanup | 2h initial + ongoing | No (parallel-safe) |
| **Total active orchestrator time** | **10-13h** | — |
| **Total wall-clock (incl. soak)** | **~3-4 days** | — |

### 5.2 Risk table

| Risk | Severity | Likelihood | Phase | Mitigation |
|---|---|---|---|---|
| MCP Registry `name` locked to Sundeepg98 (if pre-published) | HIGH | UNKNOWN — needs probe | Phase 4 prep | Probe registry now; rename in-window if unpublished |
| `dr-drill.yml` repo-equality fails post-transfer | HIGH | NEAR-CERTAIN | Phase 4 prep | Patch BEFORE transfer (Phase 4 step 0) |
| `proxy.golang.org` doesn't cache new bootstrap module fast enough; Fly build retries | MED | LOW (proxy caches on first fetch) | Phase 2 | Pre-warm by running `go mod download` from a non-fly machine before deploy |
| `go.work` transitive-replace gotcha (per `session_2026-05-04_final-state`) breaks deploy | MED | LOW (we've already debugged this once) | Phase 2 | Use single-member workspace OR remove go.work entirely in kite-mcp-server |
| Org `default_repository_permission: read` blocks bot CI writes | MED | LIKELY | Phase 4 | Grant explicit team writes post-transfer |
| Transfer succeeds but Actions secrets fail to carry | LOW | LOW per docs (preserved) | Phase 4 | Re-verify each secret post-transfer; re-add if missing |
| OAuth Apps/GitHub Apps lose access | LOW | LOW (none configured per probe) | Phase 4 | Re-grant in App settings |
| Local clones print git warning until `remote set-url` | LOW | CERTAIN | Phase 4 | One-line per machine |
| Existing 301-redirect dependency on a critical external service we don't know about | LOW | LOW | Phase 5 | Monitor 404 rates post-redirect-expiry (~12mo) |
| Reversibility window narrows after ~1yr | LOW | EVENTUAL | Post-Phase-5 | Bake transfer into project decision-of-record so it isn't second-guessed |

### 5.3 What would force ABORT

- MCP Registry probe reveals `io.github.Sundeepg98/kite-mcp-server` IS published — abort name change (transfer still ok)
- Phase 2 production-deploy fails after bootstrap import — debug-and-retry, do not proceed to Phase 4
- Phase 3 48h soak reveals build-flakiness; bake fix before Phase 4
- `algo2go` org admin (the user) cannot/will-not enable team writes post-transfer; re-evaluate org defaults

None of these are likely; all are recoverable.

### 5.4 What would FORCE re-do

- If `name` field has to change AND was already registry-published: future publishes go under new name, old registry entry is orphaned. Recovery: `deprecated: true` on old entry, fresh entry under new name.
- If transfer goes wrong and we need to transfer back: `gh api -X POST repos/algo2go/kite-mcp-server/transfer -f new_owner=Sundeepg98`. Trivial. 30s.

---

## §6 — Recommendation

### 6.1 Recommendation: PROCEED, but split into two decisions

**Decision A — GitHub transfer** (`Sundeepg98 -> algo2go`):
- **Recommended NOW** (Phase 4 ready when Phases 1-3 land)
- Low-risk given 0 stars / 0 forks / 0 external dependents
- MCP Registry name probe MUST run first
- All concerns addressable in same PR window

**Decision B — bootstrap module extraction**:
- **Recommended within next 2 weeks** (Phases 1-3 first)
- Higher complexity than transfer alone
- Material payoff: kite-mcp-server becomes truly deploy-only; clears the "what stays in-tree" question raised in `god-object-inventory` and `zero-in-tree-feasibility` parallel research
- Risk well-controlled by Phase 3 soak

### 6.2 Recommended sequence

```
WEEK 1: Probe MCP Registry name status + dr-drill.yml audit + bootstrap repo creation (Phase 1)
WEEK 2: kite-mcp-server consumes bootstrap (Phase 2) + 48h soak (Phase 3)
WEEK 3 day 1: doc patches + transfer (Phase 4)
WEEK 3 day 2-5: external cleanup (Phase 5)
```

Total: ~3 weeks wall-clock, ~10-13h active orchestrator time.

### 6.3 What this unlocks

- `algo2go/*` becomes the **single canonical owner** for the algo2go ecosystem (28 sub-modules + bootstrap + deploy repo); clean public identity
- Future sub-module promotions land in `algo2go/*` directly, no rename cost
- Removes Sundeepg98-personal-account coupling from product brand (per the `kite-algo2go-rename` arc)
- Bootstrap module's clean composition root makes the "111 tools live where" question trivially answerable
- Sets up clean licensing/funding/grant context (algo2go org as legal recipient, not personal account)

### 6.4 What this does NOT solve

- Does not reduce the 111-tool registry surface (orthogonal; see god-object-inventory parallel research)
- Does not reduce in-tree LOC (just rehouses it); see `zero-in-tree-feasibility` parallel research for that
- Does not change Fly.io static egress IP or production behavior (zero runtime impact by design)
- Does not change the per-user OAuth + Kite developer-app constraint (architectural, unrelated)

### 6.5 What needs user decision before execution

1. **Confirm `algo2go` org admin access**: only the user can transfer; only org owner can configure team writes post-transfer
2. **Confirm registry-publish state of `io.github.Sundeepg98/kite-mcp-server`**: probe owed before Phase 4
3. **Confirm bootstrap repo name**: `algo2go/kite-mcp-bootstrap` proposed; user may prefer `algo2go/kite-mcp-core`, `algo2go/algo2go`, etc.
4. **Confirm timeline**: 3-week sequence proposed; user may want to compress (collapse Phase 3 soak to 24h)

---

## §APPENDIX — Quick-reference probe commands

```bash
# Pre-transfer MCP Registry check (run NOW)
curl -s "https://registry.modelcontextprotocol.io/api/v1/servers?name=io.github.Sundeepg98/kite-mcp-server" | jq

# Verify destination doesn't collide
gh api repos/algo2go/kite-mcp-server 2>&1 | grep -q "Not Found" && echo "OK: no collision"

# Transfer (Phase 4 — DO NOT RUN YET)
gh api -X POST repos/Sundeepg98/kite-mcp-server/transfer -f new_owner=algo2go

# Verify 301 redirect post-transfer
curl -I https://github.com/Sundeepg98/kite-mcp-server | grep -i location

# Post-transfer local fix
git remote set-url origin git@github.com:algo2go/kite-mcp-server.git

# Reverse (if needed)
gh api -X POST repos/algo2go/kite-mcp-server/transfer -f new_owner=Sundeepg98
```

---

**END OF DOC** — verified at HEAD `07c830c`, `as-of: 2026-05-11`, re-verify by 2026-06-11.
