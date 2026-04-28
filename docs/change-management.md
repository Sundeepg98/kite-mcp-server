# Change Management — kite-mcp-server

*Last reviewed: 2026-04-26*
*Maps to NIST CSF 2.0: PR.IP-3 (Configuration change control), PR.IP-2 (System development life cycle), GV.OV (Oversight).*
*Companion to: [`pre-deploy-checklist.md`](pre-deploy-checklist.md), [`push-deploy-playbook.md`](push-deploy-playbook.md), [`config-management.md`](config-management.md), [`recovery-plan.md`](recovery-plan.md).*

This document is the operational policy for how code, configuration, and infrastructure changes flow from a developer workstation to the live Fly.io deployment. It is the authoritative answer to "what is your change-management process?" — referenced from compliance discussions, incident post-mortems, and SOC 2 / ISO 27001 prep.

---

## 1. Branching model

**Single primary branch.** `master` is the only long-lived branch. All work merges directly to `master` after review.

- **Local feature work**: short-lived branches (`fix/<slug>`, `feat/<slug>`, `refactor/<slug>`) created from `master`. Lifespan typically <1 day.
- **Worktrees**: parallel agent / multi-task work uses `git worktree add` with directories under `.claude/worktrees/` (gitignored). Each worktree is a sibling working tree on its own branch.
- **No `develop`**, no release branches, no long-lived integration branches. Releases are tagged commits on `master`.

Rationale: single maintainer + single deployable artefact + Fly.io rolling deploys make a Git-Flow / GitFlow / trunk-based-with-feature-branches structure unnecessary. Trunk + tags is the smallest viable model.

### Tag conventions

| Tag pattern | Use |
|---|---|
| `vX.Y.Z` | Release tag — corresponds to a `flyctl deploy`. Currently at `v1.0.0`. |
| `audit/YYYY-MM-DD` | External audit milestone (e.g. `audit/2026-02-15`). |
| `incident/YYYY-MM-DD` | Tagged at HEAD when an incident is declared, for postmortem reference. |

Tags are immutable. Re-tagging requires a new tag with a higher patch number.

---

## 2. Commit conventions

Conventional Commits format:

```
<type>(<scope>): <subject>

<body>

<footer>
```

| Type | Use |
|---|---|
| `feat` | New tool, new endpoint, new feature flag |
| `fix` | Bug fix (with reproducer in commit body or test) |
| `refactor` | Code restructure with no behavioural change |
| `docs` | Documentation only |
| `test` | Test-only changes |
| `chore` | Dependencies, build system, tooling |
| `perf` | Performance improvement (with measurement) |
| `security` | Security fix or hardening (with CVE / vuln-class reference) |

Common scopes: `audit`, `mcp`, `oauth`, `riskguard`, `kc`, `app`, `broker`, `ops`, `docs`.

**Examples** (from recent history at HEAD `3501a11`):
- `refactor(audit): retire SetLogger/StartWorker/Enqueue shims — close SOLID 99→100`
- `refactor(mcp): migrate around-hook chain onto kc/decorators typed pattern`
- `refactor(ops): retire deprecated *slog.Logger fields on DashboardHandler + Handler`

Footer must include `Co-Authored-By:` lines for AI agents. The repo's git log shows current `Co-Authored-By` patterns in use.

---

## 3. Review process

### 3.1 Local pre-commit gate

Every commit must pass these *before* `git commit`:

| Gate | Command | Required |
|---|---|---|
| Build | `go build ./...` | Yes (auto-run by IDE / hook) |
| Vet | `go vet ./...` | Yes |
| Format | `gofmt -l .` returns empty | Yes |
| Narrow tests | `go test ./<changed-package>/... -count=1` | Yes (full `./...` deferred to CI) |

Per [`.claude/CLAUDE.md`](../.claude/CLAUDE.md): TDD is mandatory for new features — tests first, see them fail, then implement.

WSL2 verification convention (see [`wsl2-setup-runbook.md`](wsl2-setup-runbook.md)): the team-agent shared-tree rule defers full `go test ./...` to CI; narrow per-package runs gate the commit.

### 3.2 Self-review checklist

Pulled directly from [`pre-deploy-checklist.md`](pre-deploy-checklist.md):

**Code quality**
- [ ] `go build ./...` clean
- [ ] `go vet ./...` clean
- [ ] Tests pass on changed packages
- [ ] No new lint warnings
- [ ] Any new env vars documented in [`env-vars.md`](env-vars.md)

**Security**
- [ ] `ENABLE_TRADING` is `"false"` in `fly.toml` (Path 2 compliance)
- [ ] No credentials committed (grep `_SECRET`, `_KEY`, `_TOKEN` in diff)
- [ ] New endpoints in HTTP mux are wrapped by `withRequestID` middleware
- [ ] Any new tool calling `/orders/*` is gated by `ENABLE_TRADING`

**Compliance**
- [ ] Disclaimer / draft banners still visible on `TERMS.md`, `PRIVACY.md`
- [ ] "Built on Zerodha's open-source Kite MCP Server (MIT)" still in landing.html footer
- [ ] Any new Telegram outbound message uses `sendFinancialHTML` (disclaimer-prefixed)
- [ ] Audit trail still enabled (`kc/audit/` not broken)

### 3.3 Pull request review (when applicable)

Single-maintainer projects skip formal PR review for routine commits. PR review IS required when:

1. **External contributor.** Anyone other than `Sundeepg98` opens a PR — full review per `CODEOWNERS`.
2. **Security-sensitive change.** Any change to `oauth/`, `kc/audit/`, `kc/credstore/`, `kc/riskguard/`, encryption code, or a new external integration.
3. **Schema migration.** Any `kc/alerts/db.go` migration that touches an existing table — peer review required for backward-compatibility check.
4. **Public API surface.** Changes to MCP tool descriptions, OAuth metadata, dashboard URLs (clients may have hardcoded these).

Review uses the `code-review` plugin (see `.claude/plugins/`) to surface common issues automatically before human review.

### 3.4 ADR (Architecture Decision Record) gate

A change qualifies for ADR documentation when ALL hold:

1. It introduces a load-bearing pattern (e.g. dependency-injection container, transport split).
2. The decision rejects an alternative (Wire vs Fx, SQLite vs Postgres, etc.).
3. Reverting later would cost >1 week of work.

Existing ADRs at `docs/adr/`: 0001 (broker port) through 0007 (canonical cross-language plugin IPC). New ADR drafts live in `.research/`; once accepted, they move to `docs/adr/NNNN-slug.md` with status `Accepted`.

ADR additions DO NOT block a PR — the ADR can be filed in a follow-up commit citing the PR. The architecture rule is the constraint, not the documentation cadence.

---

## 4. Deploy gates

Production deploy = `flyctl deploy -a kite-mcp-server` against the live Fly.io instance. Every deploy passes through three gates.

### Gate A — Pre-push (5 min)

Per [`push-deploy-playbook.md`](push-deploy-playbook.md) Phase 0:

```bash
git status                       # Working tree clean (no tracked modifications)
git log origin/master..master --oneline  # Inventory commits to push
go vet ./...                     # Static check
go build ./...                   # Compile clean
```

Block: any test or vet failure.

### Gate B — Push to GitHub (1 min)

```bash
git push origin master
```

GitHub Actions runs:

| Workflow | Purpose | Block deploy? |
|---|---|---|
| `ci.yml` | Build + test on Linux | Yes |
| `security.yml` | gosec + govulncheck (lightweight) | Yes (HIGH/CRITICAL only) |
| `security-scan.yml` | gosec SARIF + govulncheck (full, on every push to master) | No (Code Scanning is source of truth) |
| `test-race.yml` | `-race` flag across packages | Yes |
| `sbom.yml` | CycloneDX SBOM publish | No |
| `playwright.yml` | UI smoke tests | No |
| `mutation.yml` | Mutation testing on critical packages | No |
| `dr-drill.yml` | Monthly cron only | No |
| `v4-watchdog.yml` | Kite SDK major-version drift watcher | No |
| `release.yml` | On tag push only | N/A |

Gate B is the FIRST gate not running on the developer's machine — CI sees the canonical commit, not local-only state.

### Gate C — Deploy (2-5 min)

```bash
flyctl deploy -a kite-mcp-server --remote-only
```

Fly.io's deployer:

1. Builds the container remotely (Dockerfile in repo root).
2. Runs the embedded healthcheck (`fly.toml` `[checks]`) before swapping traffic.
3. Performs a rolling deploy: one machine drained → new image → healthcheck → swap.
4. Records release version (`flyctl releases` shows `vNNN`).

Deploy fails fast if:
- Container build fails (Go compile error, missing system dep).
- Healthcheck (`/healthz`) returns non-2xx within startup window (default 30s).
- Migration crashes the binary on first request (we use `kc/alerts/db.go` migrations; failure logs and exits).

---

## 5. Rollback procedures

Every change has a rollback path. The fastest available is always preferred.

### 5.1 Code rollback (5 min)

If a deploy lands and surfaces a bug:

```bash
flyctl releases -a kite-mcp-server   # List release history
flyctl rollback vN -a kite-mcp-server # Roll back to prior version
```

Fly.io re-deploys the previous image; SQLite state is preserved (Litestream replica).

### 5.2 Configuration rollback (2 min)

If only an env-var changed:

```bash
flyctl secrets set KEY=OLD_VALUE -a kite-mcp-server
```

Triggers a machine restart. No image rebuild required.

For multi-secret rollback (e.g. `OAUTH_JWT_SECRET` rotation), see [`config-management.md`](config-management.md) §"Secret rotation."

### 5.3 Feature-flag rollback (1 min)

`ENABLE_TRADING=false` is the **emergency kill switch** for all order-placement tools. The hosted instance defaults to `false`; flipping to `true` enables trading. Reversing is the regulator-panic-button referenced in `fly.toml`:

```bash
flyctl secrets set ENABLE_TRADING=false -a kite-mcp-server
```

Strips ~20 order tools from registration on restart. Read tools remain.

### 5.4 Database rollback (10-30 min)

If a schema migration corrupts data:

1. Take the machine offline:
   ```bash
   flyctl scale count 0 -a kite-mcp-server
   ```
2. Restore from Litestream replica (R2):
   ```bash
   bash scripts/dr-drill.sh   # Validates restore chain first
   ```
   (Production restore requires SSH'ing to the volume and replacing `/data/alerts.db`.)
3. Bring machine up: `flyctl scale count 1 -a kite-mcp-server`.

RPO is ~10 seconds (Litestream sync interval). RTO is ~10 min for a controlled restore. See [`recovery-plan.md`](recovery-plan.md).

### 5.5 Git history rollback (post-deploy issue)

If a bad commit landed on `master` and was deployed:

```bash
git revert <bad-sha>     # Creates a new commit reverting the change
git push origin master   # Push the revert
flyctl deploy -a kite-mcp-server --remote-only
```

NEVER `git push --force` to `master`. NEVER `git reset --hard origin/master` for a published commit. The revert commit is auditable; force-push is not.

---

## 6. Emergency change protocol

For incidents requiring out-of-band changes (live security incident, production data corruption):

1. **Tag** current HEAD with `incident/YYYY-MM-DD-<slug>` BEFORE making any change. Preserves the pre-incident reference for the post-mortem.
2. **Branch** off HEAD: `git checkout -b incident/YYYY-MM-DD-<slug>`. Even for one-line emergency fixes — never commit directly to `master` under stress.
3. **Minimum-viable fix**: smallest possible change that resolves the immediate issue. Code review can be self-review at this stage.
4. **Test the fix in isolation**: `go test ./<package>/... -count=1 -run <relevant-test>`. Skip full suite if the issue is unrelated.
5. **Merge to master**: fast-forward only. Do not squash — incident commits should be auditable individually.
6. **Deploy**: standard `flyctl deploy`. Do NOT skip the healthcheck.
7. **Post-incident**: write the post-mortem under `docs/post-mortems/YYYY-MM-DD-<slug>.md` per [`incident-response.md`](incident-response.md) within 30 days.
8. **Schedule a proper fix** if the emergency change is partial — e.g. emergency-disable a feature, then schedule a real fix in the next sprint.

---

## 7. Schema migration discipline

Schema changes are the highest-stakes change category. Every migration must:

1. **Be additive first.** New tables, new columns (nullable / with default). Never drop a column in the same release that adds its replacement — wait one full release cycle.
2. **Be idempotent.** Migrations run on every server boot; running twice must be a no-op (`CREATE TABLE IF NOT EXISTS`, etc.).
3. **Be ordered.** Migrations live in `kc/alerts/db.go` `migrations` slice. New migrations append; never reorder existing ones.
4. **Preserve hash chain integrity** if touching `tool_calls`. The chain spans schema versions — adding columns is safe; modifying existing columns risks chain divergence.
5. **Be tested against a non-empty fixture.** `kc/alerts/db_test.go` has fixture loaders; new migrations need a test case demonstrating the migration on existing data.

Backward-compatibility horizon: ONE release. The Fly.io deploy is a rolling deploy — for ~30 seconds during a release, requests can hit either the old or new binary. Schema must be readable by both.

---

## 8. Configuration change control

Configuration ≠ code in the change-management sense, but it follows analogous gates. See [`config-management.md`](config-management.md) for the full configuration-management policy. Summary:

- **Non-secret env** (`fly.toml` `[env]`): committed to git. Changes go through the same gates as code (Gate A → B → C).
- **Secret env** (`flyctl secrets set`): NOT in git. Changes are logged in a separate audit trail (Fly.io's release history shows the secret was changed but not the value).
- **`ADMIN_EMAILS`** changes are particularly sensitive: a new admin gains role on next restart. Two-person review recommended for production admin additions.

---

## 9. Audit trail of changes

Three artefacts together form the change-history record:

1. **Git history.** Every code/doc change is in `git log`. Signed commits (GPG) are not currently enforced; planned for `audit/2026-Q3`.
2. **Fly.io release history.** `flyctl releases -a kite-mcp-server` lists every deploy, with the image SHA and the user who triggered it.
3. **GitHub Actions log.** Every CI run is preserved for 90 days (Actions log retention). Workflow run URLs are linked from release notes.

Cross-referencing these three answers "who deployed what, when, and was CI green at the time?" — the standard SOC 2 query.

---

## 10. Out of scope

- **Feature flags as A/B tests.** We don't run A/B experiments. `ENABLE_TRADING` is a binary kill switch, not a percentage rollout.
- **Canary deploys.** Fly.io's rolling deploy is the closest equivalent; we don't run a separate canary fleet (single-region, single-machine baseline).
- **Blue-green.** Not warranted at current scale. Litestream + Fly.io rolling deploy gives sufficient RPO/RTO without the operational cost.

---

## 11. Cross-references

- [`pre-deploy-checklist.md`](pre-deploy-checklist.md) — 5-minute pre-deploy gate
- [`push-deploy-playbook.md`](push-deploy-playbook.md) — Phase 0–5 deploy walkthrough
- [`config-management.md`](config-management.md) — env vars, secrets, infra config
- [`recovery-plan.md`](recovery-plan.md) — RTO/RPO, DR drills, backup verification
- [`incident-response.md`](incident-response.md) — incident response runbooks
- [`SECURITY_POSTURE.md`](SECURITY_POSTURE.md) — SEBI CSCRF self-assessment
- [`adr/`](adr/) — accepted architectural decisions (0001-0007)
