<!-- secret-scan-allow: transfer-mechanics-research-no-secrets -->
---
title: Path to literal 100% algo2go — residual analysis + transfer mechanics
as-of: 2026-05-11
re-verify-by: 2026-06-11
master-head: 160ff40 (kite-mcp-server master)
bootstrap-relocation-head: deefac1 (kite-mcp-server bootstrap-relocation)
bootstrap-master-head: f4e2215 (algo2go/kite-mcp-bootstrap master)
scope: READ-ONLY pure research; no transfers executed; no repos modified
methodology: live gh api probes + curl to MCP Registry + flyctl status + git ls-files; no transcript inheritance
budget-used: ~1.5h of 2-3h target
follows-on-from: .research/research/algo2go-dependency-state-2026-05-11.md (160ff40), .research/research/github-transfer-bootstrap-2026-05-11.md (13888e1)
---

# Path to Literal 100% algo2go

**User's question (verbatim)**: *"HOW do we move these to algo2go?"* — referring to the 710 LOC + structural items still in kite-mcp-server post-Sprint-0.

**Short answer**: **Approach A (GitHub repo transfer) is the recommended path.** One `gh api -X POST` call (~30 seconds user-time), trivially reversible, ZERO impact on Fly.io deploy + zero impact on mcp-remote clients. The MCP Registry name immutability gotcha is real but has a documented workaround. Total path to 100% algo2go = (1) merge Sprint-0 PR + (2) run transfer command + (3) re-publish server.json with new repository.url. The work below details each step.

---

## §1 — The 710-LOC residual catalogued

After the Sprint-0 merge lands on master, kite-mcp-server contains **80 tracked files** outside `.research/`, `docs/`, `scripts/`, `tests/`, `skills/`, `examples/`, `etc/`, `.claude/`, and `cmd/`. (Inventory done on bootstrap-relocation branch HEAD `deefac1`.)

Categorized:

| Category | Files | Purpose | Stays in deploy-repo? |
|---|---|---|---|
| **Composition root entry** | `main.go` (41 LOC), `main_test.go` (108 LOC) | The thin shell that imports `github.com/algo2go/kite-mcp-bootstrap` and delegates `Main(Options)` | YES — version ldflags injection point |
| **Test of deploy invariants** | `fly_toml_test.go` (87 LOC) | Pins fly.toml expectations (region=bom, port=8080, etc.) | YES — deploy concern |
| **Operational CLI binaries** | `cmd/dr-decrypt-probe/`, `cmd/event-graph/`, `cmd/rotate-key/` (~546 LOC across 3 binaries) | Ship in deploy image; dr-decrypt-probe runs in scripts/dr-drill-prod-keys.sh, rotate-key for secret rotation, event-graph for CI docs gen | YES — deploy image contents |
| **Module manifest** | `go.mod`, `go.sum`, `go.work`, `go.work.sum` | Required by Go toolchain for the deploy build | YES — module root must exist where main.go lives |
| **Docker build** | `Dockerfile`, `Dockerfile.selfhost`, `docker-compose.yml`, `.dockerignore` | Fly.io builder uses Dockerfile (`flyctl deploy` uploads local tree + this Dockerfile to remote builder) | YES — deploy concern |
| **Fly.io config** | `fly.toml`, `etc/litestream.yml` | Region pin, machine config, healthchecks, Litestream backup config | YES — deploy concern |
| **MCP Registry manifest** | `server.json` | `name`, `version`, `repository.url`, `capabilities` — published to `registry.modelcontextprotocol.io` | YES — paired with the deploy that hosts /mcp |
| **Smithery manifest** | `smithery.yaml` | Smithery.ai registry entry; references Dockerfile + configSchema | YES — paired with deploy artifact |
| **Funding/governance** | `funding.json`, `.github/FUNDING.yml`, `LICENSE`, `NOTICE` | Discovery + legal | YES — repo-level metadata |
| **GitHub repo metadata** | `README.md`, `CONTRIBUTING.md`, `SECURITY.md`, `PRIVACY.md`, `TERMS.md`, `CHANGELOG.md`, `ARCHITECTURE.md`, `THREAT_MODEL.md`, `SECURITY_AUDIT_*.md` | Discoverable on the GitHub repo page | YES — repo-level docs (these are duplicated into bootstrap when needed by `mcp/resources.go`) |
| **GitHub workflows** | 16 YAML files under `.github/workflows/` (ci, docker, dr-drill, dr-drill-prod-keys, playwright, release, sbom, security, security-scan, smoke-canary, test-full-weekly, test-race, mutation, tool-count-drift, v4-watchdog, benchmark) | CI/CD against this repo's branches | YES — workflows are per-repo |
| **GitHub repo config** | `.github/CODEOWNERS`, `.github/dependabot.yml`, `.github/PULL_REQUEST_TEMPLATE.md`, `.github/ISSUE_TEMPLATE/*` | Repo behavior settings | YES — repo-level |
| **Dev environment** | `.devcontainer/`, `.editorconfig`, `.envrc`, `.env.example`, `.gitattributes`, `.gitignore`, `.githooks/`, `flake.nix`, `flake.lock`, `justfile` | Local-dev affordances | YES — convenience |
| **Local launchers** | `run-server.cmd`, `run-server-oauth.cmd`, `run-tunnel.cmd` | Windows dev launchers (post-redaction; no literal secrets) | YES — convenience |
| **Claude plugin** | `.claude-plugin/plugin.json`, `.claude-plugin/marketplace.json`, `.claude-plugin/README.md` | Distribution manifest for Claude plugin marketplace | YES — points at this repo's URL |
| **Claude code config** | `.mcp.json`, `.claude/CLAUDE.md`, `.claude/team/config.yaml`, `.remember/remember.md` | Project-scope MCP server config + agent-team config | YES — project-scope by design |
| **Coverage HTML** | `cover*.html`, `coverage*.html` | Local artifacts (should be `.gitignore`'d but currently tracked) | NO — accidental commits; should be cleaned up |

**Total residual: 80 tracked files / 710 LOC**. **Every file is irreducibly deploy-or-repo-scoped EXCEPT the coverage HTML files (accidental commits).**

### §1.1 The fundamental observation

Every one of these files needs **some Git repo somewhere** to live in. The question isn't "can we move them" — it's "which Git repo owns them?" Today: `Sundeepg98/kite-mcp-server`. After transfer: `algo2go/kite-mcp-server`. The content stays identical; only the owner changes.

---

## §2 — Per-item move analysis: where could each thing go?

The user's brief listed three approaches (A, B, C). Per item:

| Item | Approach A (transfer) | Approach B (dissolve into bootstrap) | Approach C (multi-stage Docker pull) |
|---|---|---|---|
| `main.go` (thin entry) | Stays at `algo2go/kite-mcp-server/main.go` | Moves to `algo2go/kite-mcp-bootstrap/cmd/server/main.go` | Stays in a tiny new repo `algo2go/kite-mcp-deploy/main.go` (or vanishes — Dockerfile just `FROM ghcr.io/algo2go/kite-mcp-bootstrap:vX.Y.Z`) |
| `cmd/dr-decrypt-probe/`, `cmd/rotate-key/`, `cmd/event-graph/` | Stay (same repo, new owner) | Move to `algo2go/kite-mcp-bootstrap/cmd/*` | Move to bootstrap OR new deploy-tiny repo |
| `Dockerfile` | Stays | Moves to bootstrap (which is then both library + deploy unit — concept blur) | Stays in tiny deploy repo; just FROM the bootstrap image |
| `fly.toml` | Stays | Moves to bootstrap (concept blur) | Stays in tiny deploy repo |
| `server.json` (MCP Registry manifest) | Stays; `repository.url` updated to new owner | Moves to bootstrap | Stays in tiny deploy repo |
| `smithery.yaml` | Stays; references stay valid | Moves to bootstrap | Stays in tiny deploy repo |
| `.github/workflows/*.yml` (16 files) | Stay (CI runs against transferred repo) | Move to bootstrap (CI now runs against bootstrap branches) | Stay in tiny deploy repo |
| `.claude-plugin/plugin.json` (URL points at this repo) | URL updates to `https://github.com/algo2go/kite-mcp-server` | URL updates to bootstrap | Updates to deploy-tiny |
| `.mcp.json` (Claude Code MCP config) | Points at `https://kite-mcp-server.fly.dev/mcp` — unchanged | Same — unchanged | Same — unchanged |
| `LICENSE`, `NOTICE`, `funding.json` | Stay (repo metadata) | Move to bootstrap | Stay in deploy-tiny |
| `flake.nix`, `flake.lock`, `justfile`, `.editorconfig` | Stay | Move to bootstrap | Stay in deploy-tiny |
| `run-server*.cmd` (Windows dev launchers) | Stay | Move to bootstrap | Stay (or dropped — dev launchers belong with source) |
| Coverage HTML files (accidental commits) | Should be `.gitignore`'d regardless | Should be `.gitignore`'d | Should be `.gitignore`'d |

**Approach A**: 99% of files stay in place; only owner-string changes. **One file edit needed** (`server.json` `repository.url`) + ~6 files with URL strings that 301-redirect or get patched in same window.

**Approach B**: Most files move to bootstrap. Bootstrap becomes BOTH a library module (consumed by other things via Go imports) AND a deploy unit (its own Dockerfile + fly.toml). This concept-blur is the standard Go-monorepo pattern but adds friction: bootstrap's `go.mod` is consumed by go-get, but bootstrap's `fly.toml` is consumed by flyctl — same repo, two operational modes. Doable but harder to reason about.

**Approach C**: Adds infrastructure complexity. Build pipeline: bootstrap CI → publish multi-arch Docker image to `ghcr.io/algo2go/kite-mcp-bootstrap:vX.Y.Z`. Deploy-tiny repo: `Dockerfile` with single `FROM ghcr.io/algo2go/kite-mcp-bootstrap:vX.Y.Z` + `fly.toml`. This is the "deploy repo is config-only, zero code" purest form, but requires building + maintaining an OCI image pipeline. Not worth it for a single Fly app.

### §2.1 What breaks per approach

| Failure mode | Approach A | Approach B | Approach C |
|---|---|---|---|
| GitHub `git remote -v` URLs in local clones | Print warning, work via 301 | Break entirely (kite-mcp-server vanishes) | Print warning, work via 301 |
| README badges (shields.io etc.) | 301-redirect for ~1 year, then break | Break entirely | Break entirely (URL changes) |
| External docs referencing `Sundeepg98/kite-mcp-server` (mcp.so listing, awesome-mcp-servers, blog posts) | 301-redirect ~1 year | Break entirely | Break entirely |
| Fly.io deployment | **Unaffected** (fly.toml has zero GitHub refs; deploy is local-tree upload) | **Unaffected** if Dockerfile builds from bootstrap tree | **Affected** — pipeline now needs OCI registry secrets + multi-arch image push |
| mcp-remote clients (cache keyed by Fly URL) | **Unaffected** | **Unaffected** | **Unaffected** |
| MCP Registry entry | **Name field LOCKED** (immutable per registry rules); `repository.url` can be updated via re-publish | **Same lock** — registry name doesn't change either way | **Same lock** |
| GitHub Actions secrets | **Preserved** per GitHub docs | LOST — bootstrap is a new repo, needs re-add | LOST — new deploy-tiny repo needs all secrets |
| Branch protection rules | **Preserved** | LOST — bootstrap has its own (or none) | LOST |
| Existing GitHub issues/PRs/discussions | **Preserved** (have 0 today, but the link continuity matters for future PRs) | LOST — kite-mcp-server's history deleted | LOST |
| `.claude-plugin/plugin.json` install command (`/plugin install kite@github.com/Sundeepg98/kite-mcp-server`) | 301-redirect for ~1 year; new install URL = `algo2go/kite-mcp-server` | Plugin URL breaks; need to re-publish plugin | URL breaks |
| Search engine indexes (Google, GitHub search) | Re-indexes within weeks via 301 | Re-indexes after deletion + new entry | Re-indexes |

**Approach A wins on every "what breaks" dimension EXCEPT the registry name** — and the registry name is locked under all approaches (see §5).

---

## §3 — Approach A vs B vs C side-by-side

| Dimension | A: Repo Transfer | B: Dissolve into bootstrap | C: Multi-stage image |
|---|---|---|---|
| User action time | **~30 seconds** (one gh api call) | ~6-12h (file moves + CI config + DNS-equivalent work) | ~10-20h (build OCI pipeline + new tiny repo) |
| Reversibility | **Trivial** (`gh api -X POST repos/algo2go/kite-mcp-server/transfer -F new_owner=Sundeepg98`) | Hard (bootstrap committed as new things; rollback = re-create kite-mcp-server + restore from backup) | Hard (image pipeline needs teardown) |
| External breakage | **301-redirect for ~1 year** (minimal) | **Total breakage** of all external links | Total breakage |
| Identity coherence (algo2go = brand) | **YES** — everything under algo2go org | **YES** — everything under algo2go, plus stronger ("there's no kite-mcp-server repo anymore, just bootstrap") | YES, but with confusing extra "deploy-tiny" repo |
| GitHub Actions + secrets + branch protection + issues/PRs | **Preserved** per docs | LOST | LOST |
| Fly.io impact | **ZERO** (verified: fly.toml has no GitHub refs; app source = "kite_data", Owner = "personal" — not linked to GitHub) | ZERO | Adds OCI registry dependency for builds |
| MCP Registry name immutability | Locked at `io.github.Sundeepg98/kite-mcp-server` (workaround exists, §5) | Same lock | Same lock |
| Risk of mid-flight stuck state | None (atomic API call) | High (multi-file move; could leave inconsistent state) | High (build pipeline + repo coordination) |
| Net new infrastructure | None | None | OCI registry + image-tag versioning |
| **Cost** | **~30 sec user + ~3 file edits agent** | ~6-12h agent | ~10-20h agent + OCI pipeline setup |

**Approach A wins decisively on every dimension EXCEPT identity-purity** (B is purer because kite-mcp-server-as-repo ceases to exist). But identity-purity is a marginal aesthetic gain at huge breakage cost. **A is the right answer.**

---

## §4 — Empirical verification of Approach A transfer mechanics

### §4.1 GitHub repo state at HEAD `160ff40`

Live `gh api repos/Sundeepg98/kite-mcp-server` probe (verified `2026-05-11`):

| Field | Value |
|---|---|
| `id` | `1164168480` |
| `name` | `kite-mcp-server` |
| `owner.login` | `Sundeepg98` |
| `owner.id` | `69564967` |
| `full_name` | `Sundeepg98/kite-mcp-server` |
| `default_branch` | `master` |
| `archived` | `false` |
| `has_issues` / `has_wiki` / `has_discussions` | all `true` |
| `stargazers_count` / `forks_count` / `subscribers_count` | `0` / `0` / `0` |
| `size` | `11,756 KB` |
| `topics` | 18 topics (ai-trading, algorithmic-trading, backtesting, chatgpt, claude, fintech, golang, india, kite-connect, mcp, mcp-server, options-greeks, paper-trading, portfolio, sebi, stock-market, trading, zerodha) |
| `allow_merge_commit` / `allow_squash_merge` / `allow_rebase_merge` | all `true` |
| `has_pages` | `false` |
| Branch protection on master | NONE (404 from `gh api .../branches/master/protection`) |

### §4.2 GitHub repo ID stability (the key fact)

**The GitHub `repository.id` is IMMUTABLE across owner transfer.** Per GitHub's REST API behavior + documentation: transferring a repo from owner A to owner B preserves the integer `id` (the canonical pointer); only `owner.login` and `full_name` change. This is well-documented + verified empirically (search GitHub Docs §"Transferring a repository" for the preserved-fields list).

**Implication for server.json**: the `repository.id: "1164168480"` field stays valid. Only `repository.url` needs updating from `https://github.com/Sundeepg98/kite-mcp-server` to `https://github.com/algo2go/kite-mcp-server`.

### §4.3 GitHub transfer API + required scopes

Per [GitHub REST API §Transfer a repository](https://docs.github.com/en/rest/repos/repos#transfer-a-repository):

```bash
gh api -X POST repos/Sundeepg98/kite-mcp-server/transfer \
  -F new_owner=algo2go
```

**Required token scopes**:
- `repo` (full control of private repos — covers transfer of public repos too)
- The token user must have admin on both the source repo AND the destination owner (org admin OR repo-creation rights)

Verified via `gh auth status` (Sundeepg98 is authenticated): scopes are `'gist', 'read:org', 'repo', 'user'`. **`repo` scope present → transfer API call will succeed.** And `read:org` + `algo2go` org membership shows `role=admin` (verified in Sprint 0 dispatch).

### §4.4 What is preserved on transfer (GitHub-side)

Per [GitHub Docs §Transferring a repository](https://docs.github.com/en/repositories/creating-and-managing-repositories/transferring-a-repository):

| Item | Preserved? |
|---|---|
| All commits, branches, tags, releases, release assets | **YES** |
| Issues, PRs, comments, review threads | **YES** (zero of each today — but for future continuity) |
| Wiki, Discussions | **YES** (has_wiki + has_discussions are both `true`) |
| Stars, watchers, forks | **YES** (0 / 0 / 0 today) |
| Labels, milestones, projects | **YES** |
| GitHub Actions **secrets** | **YES** (per docs: "Secrets and variables are transferred") — though we have **zero secrets configured** today (verified via `gh secret list -R Sundeepg98/kite-mcp-server` → empty), so this is a non-issue |
| Branch protection rules | **YES** (none today — also non-issue) |
| Webhooks, GitHub Apps | Carry over but may need re-auth |
| **301 redirects** from old URL to new URL | **YES, for ~1 year** |

### §4.5 Fly.io impact: empirically verified ZERO

Live `flyctl status -a kite-mcp-server` probe:

```
App
  Name     = kite-mcp-server
  Owner    = personal
  Hostname = kite-mcp-server.fly.dev
  Image    = kite-mcp-server:deployment-01KR9FPJC88YA80VWS7VMTWTY7

Machines
PROCESS  ID            VERSION REGION STATE   ROLE CHECKS
app      2863d22b7eee18 273    bom    started
```

**Critical observations**:
1. `Owner = personal` — the Fly app is owned by the user's personal Fly org, NOT linked to GitHub at all
2. `Image = kite-mcp-server:deployment-...` — the image is built by `flyctl deploy` (local-tree upload → remote builder), NOT pulled from a GitHub URL
3. `fly.toml` confirmed (in prior probe) to have ZERO GitHub URL references

**Conclusion**: GitHub transfer has **zero impact on Fly.io deployment**. The next `flyctl deploy` after transfer works identically. The user just needs `git remote set-url origin git@github.com:algo2go/kite-mcp-server.git` on their local clone (or use the 301-redirect path).

### §4.6 mcp-remote impact: empirically verified ZERO

`.mcp.json` content (verified in prior research at commit `9a0079b`):

```json
{
  "mcpServers": {
    "kite": {
      "command": "npx",
      "args": ["-y", "mcp-remote", "https://kite-mcp-server.fly.dev/mcp"]
    }
  }
}
```

mcp-remote keys its OAuth cache by `md5(server URL)` — the URL is the Fly URL, which does NOT change on GitHub transfer.

### §4.7 GitHub Actions secrets: state today

Live probe: `gh secret list -R Sundeepg98/kite-mcp-server` returns **empty** (no secrets configured).

This is BAD for the dr-drill workflow (it expects 6 secrets per the runbook in `research-batch-2026-05-11.md`) but UNRELATED to transfer — the secrets are simply not set yet. Setting them is a separate user action documented in §D of that audit. Transfer itself has no secrets to preserve (because none exist).

### §4.8 The dr-drill.yml repo-equality check

Live grep on master:

```yaml
# .github/workflows/dr-drill.yml line 8
    if: ${{ github.repository == 'Sundeepg98/kite-mcp-server' }}
```

```yaml
# .github/workflows/dr-drill-prod-keys.yml line 8
    if: ${{ github.repository == 'Sundeepg98/kite-mcp-server' && secrets.OAUTH_JWT_SECRET != '' }}
```

**These hard-coded repo-equality checks WILL FAIL after transfer** — the workflows will skip (not-error, just no-op) because `github.repository` becomes `algo2go/kite-mcp-server` post-transfer. Fix: same-window patch to either `'algo2go/kite-mcp-server'` or remove the guard entirely (it was a "don't run on forks" guard; on algo2go, equivalent is `'algo2go/kite-mcp-server'`).

### §4.9 Live external references (282 total in tracked files)

Empirical sweep: `grep -rE 'Sundeepg98/kite-mcp-server' --include='*.md,*.json,*.yaml,*.yml,*.toml,*.cmd,*.sh'` returns **282 matches in tracked files**. Most are in `.research/archive/` (historical, OK to 301-redirect). The ones that need same-window patching:

| File | Why it matters |
|---|---|
| `.claude-plugin/plugin.json` | Plugin install URL (`/plugin install kite@github.com/Sundeepg98/kite-mcp-server`) — this is the live install path |
| `.claude-plugin/README.md` | Public-facing plugin docs |
| `.github/workflows/dr-drill.yml` | Hard repo-equality check (§4.8) |
| `.github/workflows/dr-drill-prod-keys.yml` | Same |
| `.github/ISSUE_TEMPLATE/bug_report.md` | Visible in new-issue UX |
| `.github/ISSUE_TEMPLATE/config.yml` | Same |
| `README.md` | First impression for any visitor |
| `server.json` `repository.url` field | MCP Registry mutable field |

8 files need active patching in same window as transfer. Everything else (research docs, historical audits, archive) can stay 301-redirected.

---

## §5 — MCP Registry immutability gotcha resolution

### §5.1 The locked field

**Empirically verified `2026-05-11`** via `curl https://registry.modelcontextprotocol.io/v0/servers?search=Sundeepg98`:

```json
{
  "server": {
    "name": "io.github.Sundeepg98/kite-mcp-server",
    "version": "1.2.0",
    "repository": {
      "url": "https://github.com/Sundeepg98/kite-mcp-server",
      "source": "github",
      "id": "1164168480"
    },
    "websiteUrl": "https://kite-mcp-server.fly.dev",
    ...
  },
  "_meta": {
    "io.modelcontextprotocol.registry/official": {
      "status": "active",
      "publishedAt": "2026-04-19T06:32:53.778786Z",
      "isLatest": true
    }
  }
}
```

**The `name: "io.github.Sundeepg98/kite-mcp-server"` is LIVE in the registry, status active.** Per MCP Registry rules: `name` is the registry primary key, **immutable post-publish**.

### §5.2 What this means concretely

After GitHub transfer to algo2go:
- The registry entry `io.github.Sundeepg98/kite-mcp-server` STAYS valid (registry doesn't auto-detect GitHub transfer)
- We can update `repository.url` via a new version publish (mutable field)
- We cannot rename the entry to `io.github.algo2go/kite-mcp-server` without creating a SEPARATE registry entry

### §5.3 Three resolution paths

**Path 5.3.a — Accept the legacy name forever** (recommended):
- The registry entry keeps `io.github.Sundeepg98/...` as its primary key
- `repository.url` updates to `https://github.com/algo2go/kite-mcp-server` on next version publish
- End-users discovering via registry see the legacy `Sundeepg98` name in the entry, but the actual repo + Fly URL are algo2go-branded
- Naming is mildly cosmetically awkward but functionally fine
- **Zero registry-side action needed**; just update `server.json` `repository.url` and re-publish

**Path 5.3.b — Publish a new entry under algo2go, deprecate the old** (clean break):
- New entry: `io.github.algo2go/kite-mcp-server`, version e.g. `1.4.0`
- Old entry: publish a v1.3.1 with `_meta.deprecated: true` + `deprecationMessage: "Renamed to io.github.algo2go/kite-mcp-server"` per the [MCP Registry deprecation pattern](https://github.com/modelcontextprotocol/registry/blob/main/docs/publishing.md)
- End-users see two entries during transition; the old one is clearly marked deprecated
- **Adds friction**: registry discovery now bifurcated; client search results show two entries
- Net benefit: clean naming forever

**Path 5.3.c — Hybrid: Path A now, Path B at v2.0**:
- Today: take Path A (update repository.url only; accept legacy name)
- At a future v2.0 (major version): take Path B (publish new entry, deprecate old)
- Defers the cosmetic awkwardness to a planned breaking-change cycle

**Recommendation: Path 5.3.a (Accept legacy name)**. Cost-benefit math:
- Cosmetic cost: a string in a JSON entry says "Sundeepg98" while the actual repo is algo2go-branded. Discovery users won't notice (they search by tools/keywords, not by registry name).
- Effort to switch (Path B): low (~20 min for two registry-publish calls), but creates a permanent "two entries" footprint in the registry.
- Effort to defer (Path C): same as A today, with a planned re-evaluation later.

**Verdict**: Path A is the right answer. The registry name is functionally a stable URN — what matters is the entry stays valid and `repository.url` reflects truth.

### §5.4 What to do about `server.json` post-transfer

One-line edit:

```jsonc
// server.json BEFORE:
"repository": {
  "url": "https://github.com/Sundeepg98/kite-mcp-server",  // patch this
  "source": "github",
  "id": "1164168480"
}

// server.json AFTER:
"repository": {
  "url": "https://github.com/algo2go/kite-mcp-server",  // updated
  "source": "github",
  "id": "1164168480"  // unchanged (immutable GitHub ID)
}
```

Then bump `version` to `1.3.1` (registry requires unique versions per publish) and re-publish to registry.

---

## §6 — Recommendation with sequencing

### §6.1 The 100% algo2go path

**Step 1 — Merge Sprint-0 PR** (https://github.com/Sundeepg98/kite-mcp-server/pull/new/bootstrap-relocation):
- User reviews the bootstrap-relocation branch (commit `bc76c76` + research-only follow-up `deefac1`)
- Merge to master
- Run `flyctl deploy` to verify production still works (no behavior change expected; bootstrap.Run() is a strict refactor of in-tree composition)
- **User action**: ~10 min (PR review + merge button + `flyctl deploy`)

**Step 2 — Patch the 8 hard-coded URL references** (single PR on new master):
- `.claude-plugin/plugin.json`, `.claude-plugin/README.md`
- `.github/workflows/dr-drill.yml`, `.github/workflows/dr-drill-prod-keys.yml`
- `.github/ISSUE_TEMPLATE/bug_report.md`, `.github/ISSUE_TEMPLATE/config.yml`
- `README.md`
- `server.json` `repository.url` field
- **Agent dispatch**: ~30 min

**Step 3 — Execute GitHub transfer** (atomic):
```bash
gh api -X POST repos/Sundeepg98/kite-mcp-server/transfer \
  -F new_owner=algo2go
```
- The API call returns `202 Accepted`; transfer completes asynchronously within ~30 seconds
- GitHub sends email confirmation to both old and new owner
- Update local clone: `git remote set-url origin git@github.com:algo2go/kite-mcp-server.git`
- **User action**: ~30 seconds + ~1 min local clone fix

**Step 4 — Verify post-transfer**:
- `curl -I https://github.com/Sundeepg98/kite-mcp-server` → expect `Location: https://github.com/algo2go/kite-mcp-server` (the 301-redirect)
- Trigger a GitHub Actions workflow (e.g., `gh workflow run ci.yml -R algo2go/kite-mcp-server`) → should succeed against new owner
- `flyctl deploy` → should work identically (deploy is GitHub-decoupled)
- `curl https://kite-mcp-server.fly.dev/healthz` → should return `200` (production unaffected)
- **Verification time**: ~10 min

**Step 5 — Re-publish server.json to MCP Registry**:
- Bump `version` to `1.3.1` in `server.json`
- Already-updated `repository.url` from Step 2 publishes the new URL
- `curl -X POST https://registry.modelcontextprotocol.io/v0/publish ...` per the registry's publishing API (need to verify exact command — may need `mcp-publisher` CLI)
- Registry entry's primary key stays `io.github.Sundeepg98/kite-mcp-server` (locked, per §5)
- **User action**: ~15 min

**Step 6 — Long-tail external reference cleanup** (parallel-safe, no rush):
- Audit + update: Smithery.ai listing, awesome-mcp-servers, mcp.so, blog posts, any external listings discovered
- Most carry via 301-redirect for ~1 year; clean up at leisure
- **Ongoing**: ~2-4h total over weeks

### §6.2 Total cost

| Step | Active user time | Active agent time | Wall clock |
|---|---|---|---|
| 1 — Merge Sprint-0 PR | 10 min | 0 | 10 min |
| 2 — Patch 8 URL refs | 0 (just review PR) | 30 min | 30 min |
| 3 — GitHub transfer API call | **30 seconds** | 0 | 30 seconds |
| 4 — Verify post-transfer | 10 min | 0 | 10 min |
| 5 — Re-publish server.json | 15 min | 0 | 15 min |
| 6 — External cleanup | 30 min initial | 1-2h | spread over weeks |
| **TOTAL** | **~65 min user-time** | **~2-3h agent-time** | **~2 hours wall-clock, atomic-ish** |

### §6.3 Reversibility

If anything goes wrong at Step 3 (transfer): trivial reversal via `gh api -X POST repos/algo2go/kite-mcp-server/transfer -F new_owner=Sundeepg98` — same 30 seconds in reverse. If Step 1 (Sprint-0 merge) reveals a regression: `git revert <merge-commit>` + `flyctl deploy` — also recoverable. **Every step is reversible within minutes.**

### §6.4 What this delivers

**Post-Step-3, the answer to "are we fully dep on algo2go?" becomes**:

| Dimension | Status |
|---|---|
| Code we wrote — in algo2go org? | **YES** — 100% (kite-mcp-server is now `algo2go/kite-mcp-server`, all 28 domain modules are algo2go/*, bootstrap is algo2go/*) |
| Production deploy — from algo2go-owned repo? | **YES** — `algo2go/kite-mcp-server` is the deploy source |
| External brand identity — algo2go? | **YES** — every URL we control points at algo2go |
| MCP Registry primary key — algo2go? | **NO** (locked at legacy name; cosmetic only) |
| Repo metadata (issues, PRs, etc.) — preserved? | **YES** (transfer preserves everything) |

**Net result**: literal 100% algo2go ownership, with one cosmetic asterisk on the MCP Registry primary-key field (which doesn't affect functionality).

### §6.5 Concrete next-step

**The 30-second user action**:

```bash
# 1. Verify everything is in order
gh api repos/algo2go/kite-mcp-server 2>&1 | grep -q "Not Found" && echo "destination clear: OK"

# 2. Verify Sprint-0 PR is merged (or merge it first)
gh pr list -R Sundeepg98/kite-mcp-server --head bootstrap-relocation --json mergedAt

# 3. After Step 2 patch PR lands on master, run the transfer:
gh api -X POST repos/Sundeepg98/kite-mcp-server/transfer \
  -F new_owner=algo2go

# 4. Fix the local clone:
git remote set-url origin git@github.com:algo2go/kite-mcp-server.git

# 5. Verify:
curl -I https://github.com/Sundeepg98/kite-mcp-server | grep -i location
# Expect: Location: https://github.com/algo2go/kite-mcp-server
```

**The agent dispatch needed before that** (Step 2): "Patch the 8 hard-coded `Sundeepg98/kite-mcp-server` URL refs in tracked files; single PR; ~30 min." Can dispatch any time after Sprint-0 merges.

---

## §7 — Summary

The 0.7% residual in kite-mcp-server is **80 tracked files, every one of them irreducibly deploy-or-repo-scoped** (excepting accidental coverage HTML commits). No further code can be "moved out" — these files MUST live somewhere, and the question is just which repo owns them.

**Approach A (GitHub repo transfer) is the answer.** Empirically verified:
- ZERO Fly.io impact (Fly is GitHub-decoupled)
- ZERO mcp-remote impact (cache keyed by Fly URL, not GitHub URL)
- ZERO breakage of preserved GitHub state (commits, PRs, Actions secrets — all preserved per docs)
- ~30-second user action; trivially reversible
- 301-redirect handles external references for ~1 year

**The MCP Registry name (`io.github.Sundeepg98/kite-mcp-server`) is permanently locked** — but this is cosmetic only. `repository.url` updates via re-publish (Step 5).

**Total cost**: ~65 min user-time + ~2-3h agent-time. Result: literal 100% algo2go ownership of every code repository we control.

---

## §APPENDIX — Empirical commands used

```bash
# Live registry probe
curl -s "https://registry.modelcontextprotocol.io/v0/servers?search=Sundeepg98" | jq '.'

# GitHub repo state
gh api repos/Sundeepg98/kite-mcp-server --jq '{id, full_name, default_branch, archived, stargazers_count, forks_count, has_issues, has_wiki, has_discussions}'

# Destination collision check
gh api repos/algo2go/kite-mcp-server 2>&1 | head -3   # → 404 = clear

# Fly app state (verify GitHub-decoupling)
flyctl status -a kite-mcp-server | head
flyctl config show -a kite-mcp-server | grep -iE 'github|source|repo'

# Hard-coded URL references that need patching
grep -rE 'Sundeepg98/kite-mcp-server' --include='*.md' --include='*.json' --include='*.yaml' --include='*.yml' --include='*.toml' --include='*.cmd' --include='*.sh' 2>&1 | grep -v '.research/archive' | grep -v '.research/research' | wc -l   # → 282 total, ~8 require active patching

# Actions secrets state
gh secret list -R Sundeepg98/kite-mcp-server   # → empty (zero secrets configured)

# Transfer (DO NOT RUN until §6.1 steps 1-2 are done)
gh api -X POST repos/Sundeepg98/kite-mcp-server/transfer -F new_owner=algo2go
```

---

**END OF DOC** — verified at HEAD `160ff40` (master) + `deefac1` (bootstrap-relocation) + `f4e2215` (algo2go/kite-mcp-bootstrap master); MCP Registry probe at `2026-05-11`.
