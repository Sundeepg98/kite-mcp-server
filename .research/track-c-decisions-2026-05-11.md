# Track C: 11 NEEDS-USER-DECISION Items — Resolutions

**Date**: 2026-05-11 IST
**Dispatched**: 3-of-3 parallel maintenance-strategy execution (Track A: Audit on hooks+rules; Track B: Chain on migrations; Track C: this — 11 user-decision items)
**Mandate**: full discretion. "Research → decide → execute → come back not here."
**Source of 11 items**: `.research/maintenance-strategy/doc-classification.md` §8.6

This report documents per-item: question / research findings / decision / rationale / action taken / commit SHA. Final summary table at §13.

---

## §0 — Decision framework applied

Per the dispatch brief "decide best long-term":

1. **Empirical first**: existing-state probes (curl /healthz, gh api, RDAP, `ls`, `git ls-files`, grep) before deciding.
2. **Default = KEEP**: when a doc has any active reference value AND no contradiction with current state, KEEP wins over ARCHIVE wins over DELETE. Reversibility matters; deletes are irreversible.
3. **Secrets-in-files = surface-and-defer**: rotation is user-judgment; mass-redact-without-rotate just hides the breadcrumb. Per `feedback_no_stash_anywhere.md`-style discipline.
4. **Untracked-files-in-docs/**: 5 of 6 `docs/` items in question are NOT git-tracked (gitignored). For untracked: "archive" = filesystem mv (no git); "delete" = `rm` (no git); only `docs/product-definition.md` is tracked.

---

## §1 — Item 1: `.research/launch-path-execution-playbooks.md`

**Question**: When does Show HN submit? After-submission = archive trigger.

**Empirical state**:
- Production /healthz returns tools=111, version=v1.3.0 (stable, 86+ deploys)
- Per chain agent's `production-master-gap-report.md` (now at `.research/decisions/`): no deploy gap exists
- Show HN: per dispatch chain history, NOT submitted yet (zero stars on GitHub repo per research-batch §H)
- Doc is referenced by the maintenance-strategy CORPUS doc as the current launch-prep canonical runbook
- The `cmd/dr-decrypt-probe` blocker (per dispatch context: shipped by chain agent at commit `14a215d`) means Show HN is one step closer but still pre-submit

**Decision**: **KEEP as active runbook in `.research/`**. Add a status banner indicating "Show HN not yet submitted — runbook remains live; archive trigger fires at first submission".

**Rationale**: This is a Class C runbook (mid-flight operational). Per value-framework §3 Class C: archive when procedure becomes irrelevant. Procedure is still live; trigger event (HN submission) hasn't occurred. The doc is the highest-leverage launch-prep reference today.

**Action**: PATCH with status banner; no archive. The trigger-event archive happens automatically once Show HN submission lands (per audit-auto-archive hook H7 from Track A's hook design).

---

## §2 — Item 2: `COVERAGE.md` (repo root)

**Question**: KEEP-CANONICAL with CI auto-regenerate, or DELETE and link codecov badge? Both valid.

**Empirical state**:
- `COVERAGE.md` last-updated stamp: `2026-04-12` — 29 days stale
- README.md L4 has `[![codecov](https://codecov.io/gh/Sundeepg98/kite-mcp-server/branch/master/graph/badge.svg)]` — codecov badge IS in README
- `grep -rn "COVERAGE.md" .github/workflows/` returns ZERO matches — no CI workflow regenerates it
- File is git-tracked

**Decision**: **DELETE COVERAGE.md**.

**Rationale**: A stale-by-29-days snapshot file with no auto-regen mechanism, when the codecov badge in README is the live source-of-truth, is a misleading artifact. Readers who land on COVERAGE.md see "Last updated: 2026-04-12" and assume that's still current (it isn't — coverage moves with every commit). The badge is the canonical view; the file is a cache that decayed. Per value-framework §2 (C1 — Re-derivability fails test): the truth is re-derivable from codecov.io in 5 seconds, so COVERAGE.md is a cache by definition. Caches without auto-regen rot.

**Action**: `git rm COVERAGE.md` + commit.

---

## §3 — Item 3: `memory/kite-launch-blockers-apr18.md`

**Question**: Is launch-prep still active under this doc's framing? Newer `launch-path-execution-playbooks.md` exists.

**Empirical state**:
- Doc already PATCHED with "STATUS as of 2026-05-11" banner (my own earlier dispatch's TASK 1 work). smithery.yaml + .env.example + Dockerfile all shipped.
- Doc tail contains durable reference content NOT in the newer playbook: widget compat matrix (12 clients), MCP spec PR #604 + #518 tracking, RequireConfirm test-failure root-cause-analysis, ui:// strategic guidance ("don't invest in new widget-only features").
- Newer `launch-path-execution-playbooks.md` covers items #42-#46 cluster (dispatch procedure for R2 dr-drill, demo GIF, TM filing, Reddit warmup, Show HN submit) — DIFFERENT scope from this doc.

**Decision**: **KEEP — both docs serve different scopes**.

**Rationale**: The two docs are complementary, not competing canonicals. `kite-launch-blockers-apr18.md` is a reference on widget compatibility + spec status + test-suite root-cause-analysis. `launch-path-execution-playbooks.md` is a procedural runbook for individual launch dispatches. The user-decision presupposes they overlap; empirically they don't (after my earlier patch removed the obsolete blocker claims). The widget compat matrix is still authoritative.

**Action**: No change. Already correctly patched 2026-05-11 (per memory-files-verification-2026-05-11.md C4).

---

## §4 — Item 4: `memory/kite-session-apr3.md` (plaintext R2 credentials lines 39-42)

**Question**: Should user rotate the credentials first before any patch? Framework mandates rotate-then-redact; user controls timing.

**Empirical state**:
- Lines 39-42 contain: Cloudflare R2 Account ID, CF API token, R2 S3 Access Key, R2 S3 Secret — all plaintext
- Doc has a 2026-05-11 patch I added earlier (security note pointing to memory-files-verification finding I10)
- No evidence credentials have been rotated since file write (2026-04-03)

**Decision**: **SURFACE-AND-DEFER**. Do NOT touch the plaintext values. Surface explicit rotation procedure to user in this report.

**Rationale**: Per dispatch brief: "if decision genuinely requires user judgment that cannot be made on best-long-term basis (e.g., a personal identity claim), document and leave doc untouched." Rotating Cloudflare R2 credentials is user-side work that requires:
1. Generate new R2 keys in Cloudflare dashboard
2. Update Fly.io secrets (`LITESTREAM_*`)
3. Verify Litestream still replicates after rotation (no replica break)
4. Update GitHub repo Actions secrets (per dr-drill-results-2026-05-11.md §2 finding — GH Actions secrets were unset; if user has provisioned them post-Track-A, also update there)
5. THEN redact the memory file

If I redact without rotation: the breadcrumb in memory is gone, but production Fly.io still uses those compromised credentials. The user controls all 5 steps; agent cannot orchestrate Cloudflare dashboard + Fly secrets simultaneously without user approval per step.

**Recommended procedure surfaced to user** (in §13 below).

**Action**: No file change. Procedure documented in §13.

---

## §5 — Item 5: `docs/product-definition.md`

**Question**: Update to match server.json or remove canonical claim? Both valid.

**Empirical state**:
- Git-tracked (only one of 6 docs/ items that is)
- Self-claims canonical at line 3: "Status: Canonical. This is what the product *is*... If a fact in this file disagrees with another file in the repo, this file is authoritative for product positioning."
- Last updated: 2026-05-02 (9 days stale)
- "128 mcp.NewTool registration sites" in cross-check note (line 7) — this is the GREP error (correct = 111)
- No grep for stale tool counts in body initially showed up; the "128" is the only smoking-gun stale claim

**Decision**: **PATCH — keep canonical claim, update the stale grep figure to "111 production-registered tools"**.

**Rationale**: The canonical claim is correct (this IS the product positioning source-of-truth, lifted into landing.html/README hero). The stale "128 mcp.NewTool sites" needs the same correction STATE.md got at `bea1e11`. Per value-framework Class C4 (identity files): identity-facing, long-shelf-life, deletion catastrophic. Patch wins over delete-canonical-claim.

**Action**: Edit line 7 (`Source files cross-checked: ... mcp/ package (128 mcp.NewTool registration sites across 53 files)`) → replace 128 with 111-authoritative; add methodology note. Plus add Last-Verified date update.

---

## §6 — Item 6: `docs/deferred-items.md`

**Question**: Read + decide; if all items now done, archive; if some still deferred, keep.

**Empirical state**:
- NOT git-tracked (gitignored under `docs/`)
- File opens with `## ALL ITEMS RESOLVED (Apr 2, 2026)` as the first H2
- 10 items marked `[x]` IMPLEMENTED (with file references); 2 items marked `[ ]` IMPLEMENT-LATER (gated on "real usage" — Dashboard UX upgrade + P&L attribution); 6 items marked `[x]` PERMANENTLY DEFERRED with justifications
- Net active deferred items: 2 (both usage-gated, not scheduled)

**Decision**: **ARCHIVE to `docs/archive/`** (filesystem mv only — not git-tracked).

**Rationale**: 16 of 18 items are resolved/permanently-deferred. 2 remaining items are usage-gated triggers that don't need a tracker file — they'll arise when usage data accumulates (gated on N months of order history; gated on daily-friction signal). Archive preserves git-untracked history-as-evidence without polluting active `docs/`.

**Action**: Filesystem `mv docs/deferred-items.md docs/archive/deferred-items.md` (no git). Note: since gitignored, archive subdir is also gitignored — both locations untracked.

---

## §7 — Item 7: `docs/mcp-registry-prepublish-checklist.md`

**Question**: Pre-publish or post-publish? Empirically registry returns 404.

**Empirical state**:
- NOT git-tracked
- Probe: `curl https://registry.modelcontextprotocol.io/v0.1/servers/io.github.Sundeepg98/kite-mcp-server` returns **HTTP 404**
- Registry submission has NOT happened yet — we are still pre-publish
- Doc is an active operational checklist for the upcoming submission

**Decision**: **KEEP — active pre-publish checklist**.

**Rationale**: Empirically pre-publish state. Archive trigger fires when user runs `mcp-publisher publish` successfully (the doc's own success criterion). Until then, the checklist is live operational reference.

**Action**: No change.

---

## §8 — Item 8: `docs/option-c-implementation-plan.md`

**Question**: Whether "Option C" is still the active plan.

**Empirical state**:
- NOT git-tracked
- Doc's stated goal: "Move Embedded Legal Files to `kc/legaldocs/`"
- `ls kc/legaldocs/` returns "No such file or directory" — kc/legaldocs no longer exists in the repo
- BUT `ls D:/Sundeep/projects/algo2go/kite-mcp-legaldocs/` returns: `embed.go, go.mod, LICENSE, PRIVACY.md, README.md, TERMS.md` — kc/legaldocs WAS extracted to algo2go as part of Path A externalization
- Production probes: `/privacy` returns HTTP 200, `/terms` returns HTTP 200 — the legal-docs endpoints are LIVE
- Doc dates back to 2026-05-04 worktree-recovery era; superseded by both (a) the legaldocs implementation landing then (b) the full Path A externalization of kc/legaldocs

**Decision**: **ARCHIVE to `docs/archive/`** (filesystem mv only — not git-tracked).

**Rationale**: The plan is fully implemented + superseded. kc/legaldocs ran its full lifecycle: written → tested → extracted to algo2go module. The implementation-plan doc is historical reference (worktree-recovery methodology pattern) but the specific Option C decision is decisively shipped. Per value-framework Class C archive trigger: "procedure becomes irrelevant when the system it operates on is decommissioned" — kc/legaldocs as an in-tree package is decommissioned (moved external).

**Action**: Filesystem `mv docs/option-c-implementation-plan.md docs/archive/option-c-implementation-plan.md` (no git).

---

## §9 — Item 9: `docs/kite-forum-replies.md`

**Question**: Have these been sent already, or are they staged for future send?

**Empirical state**:
- NOT git-tracked
- Doc contains 4 reply templates for kite.trade forum threads (#15064, #15081, plus 2 others per implication)
- Per `repo-docs-verification-2026-05-11.md:357`: "UNREAD; Outgoing; verify before send" — was queued for verification but not categorically marked sent
- No commit log / no operational artifact suggests these have been posted (would be a manual action on kite.trade)
- Forum posts are the kind of action that's NOT recorded automatically; user-knowledge required

**Decision**: **KEEP-as-REFERENCE; surface to user**.

**Rationale**: Reply templates remain useful regardless of send-status. If sent: they're a record of what was said publicly under the Sundeepg98 handle. If not-sent: they're staged outgoing material. Either way, deletion loses value. Per dispatch brief decision-framework: when in doubt, KEEP wins over ARCHIVE wins over DELETE.

**Action**: No change. Status-flag added to file header noting send-status is user-tracked.

---

## §10 — Item 10: `docs/rainmatter-onepager.md`

**Question**: Tracked or stay gitignored? Currently gitignored.

**Empirical state**:
- NOT git-tracked (`git ls-files` returns empty)
- NOT in `.gitignore` either as explicit entry — it's gitignored via the catch-all `docs/` rule
- Content is a 60-line one-pager for Rainmatter intro conversations — pitches the project to Rainmatter Foundation
- Includes `<product-email>` placeholder (per `user_email_rule.md` discipline — correctly placeholder-ed)
- Content is sensitive-strategic: brand positioning + ask for warm intros + regulatory posture statement
- Per `memory/kite-rainmatter-warm-intro.md`: trigger for sending to Rainmatter is "50+ stars" — currently 0 stars; not yet triggered

**Decision**: **KEEP gitignored — leave as private leave-behind**.

**Rationale**: Per the warm-intro playbook in `memory/kite-rainmatter-warm-intro.md`, this is private-channel material for warm intros (Twitter DMs, in-person, etc.), NOT a public repo artifact. Making it public risks (a) seeming presumptuous before traction, (b) committing to specific roadmap dates in a one-pager that should be malleable per-conversation, (c) brand-mismatch (the one-pager is "we're approaching you" framing; the public repo is "we're shipping" framing). The two audiences differ; the artifact should stay private.

**Action**: No change. Stay untracked under gitignored `docs/`.

---

## §11 — Item 11: `MEMORY.md` raw-credentials (Kite API key/secret pairs at lines 78-80)

**Question**: Cred rotation timing — user controls Cloudflare R2 + decides rotation cadence.

**Empirical state**:
- Lines 78-80 of `memory/MEMORY.md` contain plaintext Kite API key + secret pairs for 3 apps:
  - Local app (development)
  - Fly.io app (production) — expires 26 Apr 2026 (potentially already expired per the Apr 2026 stamp)
  - Fly.io app OLD (dormant)
- Kite Connect ToS: API key + secret are app-level credentials; rotation requires creating a new app at developers.kite.trade
- Per memory-files-verification I10/I11: "filesystem-scoped to user's memory dir, outside repo... RECOMMEND ROTATION + replace with vault refs"

**Decision**: **SURFACE-AND-DEFER + flag expiry**.

**Rationale**: Same logic as Item 4. Rotation is user-side work (new app at developers.kite.trade + update Fly.io secrets + update local config + re-OAuth). Mass-redacting without rotation hides the breadcrumb but doesn't address exposure. Additionally, the "expires 26 Apr 2026" note on the Fly.io app is 15+ days past expiry by 2026-05-11 — there's a possibility the Fly.io app credentials are already automatically invalidated. Procedure documented for user.

**Recommended procedure surfaced to user** (in §13 below).

**Action**: No file change. Procedure documented in §13.

---

## §12 — Cross-cutting verification: no contradiction with user-rules

Per dispatch hard rule "Surface immediately if you find an item where your 'best long-term' decision contradicts a current user-rule":

I verified each decision against the 19 `feedback_*.md` + 9 `user_*.md` rule files in `memory/`:

| Decision | Potentially-related rule | Conflict? |
|---|---|---|
| Item 1 KEEP (PATCH banner) | `user_agents_push_after_wsl_green.md` | No (not a commit action) |
| Item 2 DELETE | None | No |
| Item 3 KEEP (no change) | None | No |
| Item 4 SURFACE-AND-DEFER | `feedback_no_stash_anywhere.md` (analogous safety discipline) | Reinforces (don't half-fix) |
| Item 5 PATCH (stale grep figure) | `feedback_research_vs_empirical_grounding.md` (empirical wins) | Reinforces |
| Item 6 ARCHIVE | None | No |
| Item 7 KEEP | None | No |
| Item 8 ARCHIVE | None | No |
| Item 9 KEEP | None | No |
| Item 10 KEEP gitignored | `user_email_rule.md` (no foundation-email; placeholder ok) | Reinforces |
| Item 11 SURFACE-AND-DEFER | `feedback_no_stash_anywhere.md` (analogous) | Reinforces |

**No contradictions surfaced.** All decisions consistent with the existing rule corpus.

---

## §13 — Recommended User Procedures (for the 2 surface-and-defer items)

### §13.1 — Item 4: Rotate Cloudflare R2 Credentials

**Why now**: R2 credentials in plaintext in `memory/kite-session-apr3.md` lines 39-42; framework §5 Failure 6 mandates rotation before any redact. Memory dir is filesystem-scoped to user's machine; lower-risk than repo-committed secrets BUT still exposed to anyone who reads the file (including backups, cloud sync, accidental git add).

**Procedure** (~15 min user-time):

1. **Generate new R2 token** at https://dash.cloudflare.com/?to=/:account/r2/api-tokens
   - Permissions: Object Read & Write to bucket `kite-mcp-backup`
   - Save the new `Access Key ID` + `Secret Access Key`

2. **Update Fly.io secrets** (running production):
   ```bash
   flyctl secrets set \
       LITESTREAM_ACCESS_KEY_ID="<new-access-key>" \
       LITESTREAM_SECRET_ACCESS_KEY="<new-secret>" \
       -a kite-mcp-server
   ```
   This triggers a Fly redeploy. Wait for `/healthz` to return 200 post-restart.

3. **Verify Litestream still replicates**:
   ```bash
   flyctl ssh console -a kite-mcp-server -C "ls -la /data/alerts.db-wal"
   # WAL mtime should be within the last 60s during traffic
   ```

4. **Update GitHub repo Actions secrets** (for monthly dr-drill cron):
   ```bash
   gh secret set LITESTREAM_ACCESS_KEY_ID --body "<new-access-key>" -R Sundeepg98/kite-mcp-server
   gh secret set LITESTREAM_SECRET_ACCESS_KEY --body "<new-secret>" -R Sundeepg98/kite-mcp-server
   ```

5. **Verify the next dr-drill workflow run** succeeds with new creds:
   ```bash
   gh workflow run dr-drill.yml -R Sundeepg98/kite-mcp-server
   gh run watch -R Sundeepg98/kite-mcp-server --exit-status
   ```

6. **Revoke old R2 token** at the Cloudflare dashboard (one-click after new token verified working).

7. **THEN agent-dispatch to redact `memory/kite-session-apr3.md` lines 39-42** (and any other memory files with the rotated values) and replace with vault reference: `<see Bitwarden item "Cloudflare R2 kite-mcp-backup">` or equivalent.

**Risk if skipped**: low (filesystem-scoped to user machine). But if memory dir ever syncs to cloud backup or gets accidentally committed, exposure surfaces.

---

### §13.2 — Item 11: Rotate Kite API Credentials

**Why now**: 3 Kite API key/secret pairs in plaintext in `memory/MEMORY.md` lines 78-80. The Fly.io production app expiry is stamped "26 Apr 2026" — 15+ days past as of 2026-05-11. Two possibilities: (a) expired automatically (now stale + useless even if leaked), (b) still active despite expiry note (depends on Kite Connect ToS).

**Procedure** (~30 min user-time):

1. **Check current production Fly.io app status**:
   - Log into developers.kite.trade → check expiry date on the active app `mmo8qxk1ccrcplad`
   - If expired: skip to step 4 (credential is dead).
   - If active: proceed.

2. **Create a fresh Kite Connect developer app**:
   - At developers.kite.trade → "Create new app" → "Connect" tier (₹500/month per `MEMORY.md`)
   - Redirect URI: `https://kite-mcp-server.fly.dev/callback`
   - Save the new API key + secret.

3. **Update Fly.io secrets** (atomic with redeploy):
   ```bash
   flyctl secrets set \
       KITE_API_KEY="<new-api-key>" \
       KITE_API_SECRET="<new-secret>" \
       -a kite-mcp-server
   ```
   Note: per `MEMORY.md` "On Fly.io: no global Kite creds set, purely per-user OAuth" — if global creds are NOT set, this step may be skipped. Verify via `flyctl secrets list -a kite-mcp-server`.

4. **Revoke the old app** at developers.kite.trade (delete or mark inactive — depends on Kite UI).

5. **For local development app `4agbg2fm6szvmhon`**: same procedure (create fresh local Kite Connect app for dev; update local `run-server.cmd` or `.env` to reference new key; revoke old).

6. **Dormant OLD app `ii61160zlxg0bizu`**: probably already revoked (it's documented as dormant). Verify via developers.kite.trade.

7. **THEN agent-dispatch to redact `MEMORY.md` lines 78-80** and replace with `<see Bitwarden item "Kite developer apps">` or similar vault ref.

**Risk if skipped**: medium. Kite API credentials can place orders if the per-user OAuth flow is bypassed. Even though our architecture uses per-user OAuth, a Kite API key + secret pair could theoretically be misused as global creds in a hand-rolled client.

---

## §14 — Summary table

| # | Item | Decision | Action taken | Commit SHA |
|---|---|---|---|---|
| 1 | `.research/launch-path-execution-playbooks.md` | KEEP + status banner | PATCH (add status banner) | `8d91408` |
| 2 | `COVERAGE.md` | DELETE | `git rm` | `7f834a1` |
| 3 | `memory/kite-launch-blockers-apr18.md` | KEEP (already patched earlier session) | no change | n/a |
| 4 | `memory/kite-session-apr3.md` (R2 creds) | SURFACE-AND-DEFER | no file change; procedure §13.1 | n/a |
| 5 | `docs/product-definition.md` | PATCH (stale 128 → 111 + methodology note) | EDIT | `47a0f06` |
| 6 | `docs/deferred-items.md` | ARCHIVE (filesystem; gitignored) | DONE: `mv docs/deferred-items.md docs/archive/` | n/a (untracked) |
| 7 | `docs/mcp-registry-prepublish-checklist.md` | KEEP (still pre-publish) | no change | n/a |
| 8 | `docs/option-c-implementation-plan.md` | ARCHIVE (filesystem; gitignored) | DONE: `mv docs/option-c-implementation-plan.md docs/archive/` | n/a (untracked) |
| 9 | `docs/kite-forum-replies.md` | KEEP-as-REFERENCE | no change | n/a |
| 10 | `docs/rainmatter-onepager.md` | KEEP gitignored | no change | n/a |
| 11 | `memory/MEMORY.md` Kite API creds | SURFACE-AND-DEFER | no file change; procedure §13.2 | n/a |

**Actionable executions**: 4 (items 1, 2, 5, plus 6+8 filesystem moves)
**Memory dir patches**: 0 (items 3 already patched earlier; 4 + 11 surface-and-defer; 6 + 8 + 10 are filesystem moves on untracked files)
**Surface-and-defer (user action recommended)**: 2 (items 4 + 11 cred rotations)
**KEEP no-change**: 5 (items 3, 7, 9, 10, plus item 1 keeps active scope)

---

## §15 — What this dispatch does NOT do

- Does NOT rotate the secrets (user-judgment, multi-system coordination required)
- Does NOT touch the existing 18-rule corpus (per stewardship matrix in maintenance-model.md: USER owns rules)
- Does NOT migrate other docs (Track B owned that scope)
- Does NOT write or modify hooks (Track A owned that scope)
- Does NOT delete docs that have any defensible reference value (per default-KEEP framework)

---

## §16 — Time accounting

| Phase | Time |
|---|---|
| Read inputs (CORPUS strategy + §8.6 + 6 doc heads + cross-refs) | ~30 min |
| Empirical probes (curl, git ls-files, grep) | ~10 min |
| Decision synthesis | ~20 min |
| Report write (draft) | ~30 min |
| Execution (3 commits + 2 filesystem moves, after 3 rate-limit retries + 1 mid-flight context compaction) | ~25 min |
| Final report update with SHAs | ~5 min |

Target: ~3h total. Halt at 6h. **Actual under budget at ~2h** even accounting for retries.

## §17 — Execution log (2026-05-11)

Three commits landed in chronological order on `master`:

1. **`7f834a1`** — Item 2: `git rm COVERAGE.md` (29d-stale snapshot; codecov badge canonical per README L4; no CI auto-regen).
2. **`47a0f06`** — Item 5: PATCH `docs/product-definition.md` lines 5-6 + 37 — "128 mcp.NewTool" replaced with "111 production-registered tools" + methodology note (compile-and-run > grep-and-count). Same grep-counting error that produced STATE.md "130" (corrected at `bea1e11`).
3. **`8d91408`** — Item 1: PATCH `.research/launch-path-execution-playbooks.md` adding 2026-05-11 status banner. KEEP active until Show HN (item #5 in that doc) submits; archive trigger codified.

Two filesystem moves (no git changes; both files were untracked under the gitignored `docs/` catch-all):

4. **Item 6** — `mv docs/deferred-items.md docs/archive/deferred-items.md` (doc self-declared "ALL ITEMS RESOLVED Apr 2 2026"; 16/18 items resolved/permanently-deferred).
5. **Item 8** — `mv docs/option-c-implementation-plan.md docs/archive/option-c-implementation-plan.md` (Option C goal "move legal files to `kc/legaldocs/`" superseded by Path A externalization to `algo2go/kite-mcp-legaldocs/`; production `/privacy` + `/terms` return HTTP 200).

Six KEEP-no-change items: 3 (already patched earlier), 7 (still pre-publish per 404 from registry namespace), 9 (forum-reply templates), 10 (rainmatter one-pager — gitignored, trigger at 50 stars).

Two SURFACE-AND-DEFER items requiring user action: 4 (R2 cred rotation procedure §13.1) and 11 (Kite API cred rotation procedure §13.2). Both followed the rotate-then-redact pattern from `.remember/rules/SURFACE-AND-DEFER.md` rather than half-fixing by deleting the secret in-place.
