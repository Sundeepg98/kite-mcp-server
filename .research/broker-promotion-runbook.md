# Broker Module → GitHub Repo Promotion Runbook

**Date**: 2026-05-04
**HEAD audited**: `5982aff` (commit 4/5 — kc/riskguard extracted). Runbook references **post-kc/billing state** (commit 5/5 in flight by architecture agent `ac06fb8a7f7d864a6`); after that commit lands, root `go.mod` will have 5 replace directives + Dockerfile will pre-stage 5 manifests + `go.work` will list 6 members.
**Charter**: read-only research. Single doc. NO code changes. **Trigger-fired execution only** — do NOT run any of the commands below until a trigger from `d72386a` re-eval fires (N≥7, external adapter PR, build >30s, 50★, second broker, external fork, senior contributor, Pre-Seed).

**Empirical at HEAD**:
- broker/ package: **126 files import it**, **143 import lines**, **72 non-test + 71 test imports**, **41 commits in `git log -- broker/`**, **10,977 LOC total**
- 16 packages span imports: `app`, `broker`, `broker/conformance`, `broker/mock`, `broker/ticker`, `broker/zerodha`, `kc`, `kc/alerts`, `kc/domain`, `kc/eventsourcing`, `kc/ops`, `kc/papertrading`, `kc/telegram`, `kc/ticker`, `kc/usecases`, `mcp`
- 1 internal dep: `kc/money` via `replace ../kc/money` in `broker/go.mod:30`
- Public API surface: `broker/conformance/conformance.go` (4 buckets — promoted commit `5d68310`)

---

## Section 1 — Pre-flight checklist

| # | Item | How | Verify |
|---|---|---|---|
| 1 | **Create `algo2go` GitHub org** | **Manual web UI only** at https://github.com/account/organizations/new — personal accounts can't create orgs via API even with `admin:org` scope. ~30s. Free tier OK. | `gh api orgs/algo2go` returns 200, not 404 |
| 2 | Create empty `kite-mcp-broker` repo | `gh repo create algo2go/kite-mcp-broker --public --description "Multi-broker port + Zerodha adapter for Indian retail trading"` | `gh repo view algo2go/kite-mcp-broker` |
| 3 | Branch protection on `main` | `gh api -X PUT repos/algo2go/kite-mcp-broker/branches/main/protection -f required_status_checks[strict]=true -f enforce_admins=true -f required_pull_request_reviews[required_approving_review_count]=1` | `gh api repos/algo2go/kite-mcp-broker/branches/main/protection` |
| 4 | OWNERS file | Single line: `* @Sundeepg98` (CODEOWNERS at `.github/CODEOWNERS`) | PR review gate fires |
| 5 | LICENSE | Copy parent repo LICENSE verbatim — **MIT, Copyright (c) 2025 Zerodha Tech**; preserve attribution per upstream-fork convention | `head -3 LICENSE` matches |
| 6 | `.gitignore` | Copy parent's Go gitignore subset (exclude root-only patterns like `kite-mcp-server.exe`) | |
| 7 | Org-level secrets stub | None required for v0.1.0 (no secrets in broker package); add later if Codecov/etc. wired | `gh secret list -R algo2go/kite-mcp-broker` empty |

---

## Section 2 — Git history extraction

**Empirical comparison:**

| Tool | Pros | Cons | Status |
|---|---|---|---|
| `git filter-repo` | Modern, fast, preserves authorship cleanly | Originally noted as not installed; **2026-05-05 dry-run verified `git-filter-repo` IS installed in WSL2 at `/usr/bin/git-filter-repo`** (likely came in via apt or earlier `pip` step). Filter-repo extracted broker subtree in 0.34s. | Recommended — confirmed available |
| `git subtree split` | Built into git, no install | Slower on large histories; can produce orphan refs | **Fallback if filter-repo unavailable** |
| `git filter-branch` | Built-in, ancient | Officially deprecated by git docs since 2.24 (man page advises filter-repo) | **Reject** |

**Chosen command** (filter-repo path):

```bash
# In a fresh clone (NEVER mutate working tree)
git clone https://github.com/Sundeepg98/kite-mcp-server kite-mcp-broker-extract
cd kite-mcp-broker-extract
git filter-repo --subdirectory-filter broker/ --tag-rename '':'broker-v'
```

This preserves all 41 broker-touching commits (verified via `git log --oneline -- broker/ | wc -l` = 41) and rewrites their paths so `broker.go` becomes the repo root. Authorship + commit dates preserved.

**Fallback** (subtree split):

```bash
git subtree split --prefix=broker -b broker-extract
git push https://github.com/algo2go/kite-mcp-broker broker-extract:main
```

Subtree split is acceptable for the first promotion; switch to filter-repo for subsequent extractions if history hygiene matters.

---

## Section 3 — Initial repo bootstrap

**README structure** (post-extract, in `kite-mcp-broker` repo root):

```markdown
# kite-mcp-broker

Multi-broker port for Indian retail trading platforms. Defines `broker.Client` + ancillary capability interfaces (NativeAlertCapable, GTTManager, MutualFundClient) and ships the Zerodha adapter (`broker/zerodha`) wrapping `gokiteconnect/v4`.

## Conformance harness

`broker/conformance/` is the public test API for adapter authors. See `conformance.PortContract`, `OptionalCapabilities`, `ErrorClassification`, `TickerLifecycle`.

## Used by

- [Sundeepg98/kite-mcp-server](https://github.com/Sundeepg98/kite-mcp-server) — reference consumer (MCP server with 111+ tools)

## License

MIT — see LICENSE.
```

**Exact `go.mod` content** (replaces current `broker/go.mod`):

```
module github.com/algo2go/kite-mcp-broker

go 1.25.0

require (
    github.com/stretchr/testify v1.10.0
    github.com/zerodha/gokiteconnect/v4 v4.4.0
    github.com/algo2go/kite-mcp-money v0.0.0-00010101000000-000000000000
)
// kc/money will be promoted as separate repo (algo2go/kite-mcp-money)
// in a later trigger; until then keep replace pointing at the in-tree
// path. v0.1.0 of broker carries this transitional require.
replace github.com/algo2go/kite-mcp-money => ../kc/money
```

**Initial commit message**: `chore: initial extract from Sundeepg98/kite-mcp-server@5982aff (post-kc/billing-extract head)`. Re-run `go mod tidy` after extract to regenerate `go.sum`.

---

## Section 4 — Tag + push v0.1.0

```bash
cd kite-mcp-broker-extract
git remote add origin https://github.com/algo2go/kite-mcp-broker.git
git push -u origin main
git tag -a v0.1.0 -m "Initial release. Extract from Sundeepg98/kite-mcp-server@5982aff."
git push origin v0.1.0
gh release create v0.1.0 --title "v0.1.0" --notes "Initial extraction. broker.Client + zerodha adapter + conformance harness."
```

---

## Section 5 — kite-mcp-server cutover

**Phase A — Transition (1 release cycle, ~1 month)**: keep both paths working.

- Edit root `go.mod`: replace `replace github.com/zerodha/kite-mcp-server/broker => ./broker` with `require github.com/algo2go/kite-mcp-broker v0.1.0` + `replace github.com/algo2go/kite-mcp-broker => ./broker`. The new replace keeps the in-tree directory canonical for builds while the require line declares the upstream.
- Rewrite all import lines across the consumer tree: `find . -name '*.go' -not -path './broker/*' | xargs sed -i 's#github.com/zerodha/kite-mcp-server/broker#github.com/algo2go/kite-mcp-broker#g'`. **Empirical at HEAD `725ac32` (2026-05-05 dry-run): 192 occurrences across 153 files in 16 packages — 39 more files / 49 more occurrences than the original 143/126 estimate due to Anchor 2 (app/providers) + Tier 6 (plugins) extractions plus organic growth.**
- **Sweep peer-module go.mod files (RUNBOOK GAP, discovered 2026-05-05 dry-run)**: 17 sibling go.mod files declare transitive deps on broker via `require` + `replace` directives. The `*.go` sed pass leaves them stale and breaks `go build` outside workspace mode. Add explicit go.mod sweep: `find . -path ./broker -prune -o -name 'go.mod' -type f -print | while read -r mod; do sed -i 's#github.com/zerodha/kite-mcp-server/broker#github.com/algo2go/kite-mcp-broker#g' "$mod"; done`. Affected files: oauth, app/providers, testutil, plugins, kc/{telegram,domain,usecases,audit,alerts,ticker,eventsourcing,papertrading,cqrs,registry,users,billing,riskguard}.
- Run `goimports -w .` to fix formatting.
- Update `go.work`: drop `./broker` from `use (...)` block (keeps 28 members at HEAD `725ac32`; the runbook's earlier "5 members" reflected the post-billing-extract state).
- Update Dockerfile: remove `COPY broker/go.mod broker/go.sum* broker/` line.
- CI green; production deploy.

**Dry-run scripts** (validated 2026-05-05): `.research/path-a-prep-dryrun.sh` (extracts broker subtree via `git filter-repo` to scratch), `.research/path-a-prep-rewrite-dryrun.sh` (rewrites extracted repo's module path + self-imports), `.research/path-a-prep-consumer-dryrun.sh` (mirrors consumer-side cutover including the peer go.mod sweep + `go build ./...` PASS verification).

**Phase B — Cutover (after 1 month canary)**: delete `./broker` directory + remove the `replace` from go.mod. Only `require github.com/algo2go/kite-mcp-broker v0.1.0` remains. From this point, broker bumps are upstream releases.

---

## Section 6 — Verify build

| Check | Command | Expected |
|---|---|---|
| Workspace mode | `go build ./...` | success at root |
| `GOWORK=off` | `GOWORK=off go build ./...` | success (replace directive resolves) |
| Dockerfile sim | `docker build -t kite-mcp-server:cutover .` | success |
| Tests | `go test ./...` (kc/riskguard, kc/billing, kc/audit + root in workspace) | green |
| Tool count | `grep -rE "mcp\.NewTool\(" mcp/*.go \| grep -vE "_test" \| wc -l` | **111** unchanged |
| Production deploy | `flyctl deploy -a kite-mcp-server` then `curl https://kite-mcp-server.fly.dev/healthz` | reports current commit + tools=111 |

---

## Section 7 — Rollback plan

Keep both clones for 1 week. If any verify-build step fails:

```bash
cd kite-mcp-server
git revert <cutover-commit-sha>
go work sync
flyctl deploy -a kite-mcp-server
```

The promoted `algo2go/kite-mcp-broker` repo stays untouched (no rollback needed there — it's just a published artifact). If production breaks: revert in consumer; broker repo continues to exist as v0.1.0 for the next attempt.

---

## Section 8 — Conformance harness API stability semver promise

`broker/conformance/` becomes broker-repo's **public API**. Promise:

- **v0.x** — adapter signatures may break between minor versions; document each break in CHANGELOG. Rationale: only Sundeep's adapter consumes it today.
- **v1.0** — semver-stable. Bucket signatures (`PortContract`, `OptionalCapabilities`, `ErrorClassification`, `TickerLifecycle`) frozen. New buckets added as additive functions, never modifying existing signatures. Breaking changes require v2.
- **Trigger to v1.0**: ≥1 external adapter ships AND passes conformance against broker v0.x. That's the empirical "real consumers exist" signal.

---

## Section 9 — Risk inventory

| Risk | Mitigation |
|---|---|
| 143 import-line rewrite (126 files, 16 packages) introduces typos | Use `sed -i` not manual; verify with `go build ./...` post-rewrite |
| Version-pin coordination between repos during transition | Phase A's `replace` keeps both paths in sync; Phase B happens only after 1 release cycle of stability |
| CI bootstrap on new repo (no workflows yet) | Day-1 add `.github/workflows/ci.yml` (build + test + race; mirror parent's `ci.yml`); defer benchmark / sbom / playwright until adoption proves needed |
| GitHub Actions setup secrets / token scopes | None needed for v0.1.0 (no Codecov, no DockerHub push, no signed releases) |
| `kc/money` transitive dep on broker breaks if money repo lags | Phase A keeps `kc/money` in-tree; broker's go.mod points at relative path — works until kc/money also promotes |
| Conformance API drift in v0.x catches adapter authors by surprise | Document v0.x = unstable in README hero; pin v0.1.0 deliberately and ship 0.2.0 only when an external adapter signals readiness |

---

## Section 10 — Estimated execution

**Calendar**: 3 working days end-to-end.
- Day 1: org creation (manual web UI, 30s) + repo bootstrap + filter-repo extract + initial push + v0.1.0 tag
- Day 2: kite-mcp-server cutover Phase A + CI green + production deploy
- Day 3: verify production stable + buffer

**₹ cost**: 0 unless TM filing for `algo2go` brand happens in same window (separately scoped at ₹19-23k per `1848a96` Path B). Org + repo creation are free GitHub tier.

**Pre-condition**: trigger from `d72386a` must fire first. Do not execute on a feels-right basis.

---

**End of runbook. No code changes. No tests run. Doc-only deliverable.**
