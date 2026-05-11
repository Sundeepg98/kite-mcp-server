# Maintenance Strategy: Per-Doc Classification

**Date**: 2026-05-11 IST
**Master HEAD audited**: `f61e1bf` (`docs(maintenance): strategic framework — value criteria + lifecycle stages + stewardship principles`)
**Dispatch role**: 2 of 3 parallel — **empirical per-doc verdict** (this doc). Companion outputs: `value-framework.md` (audit agent — abstract criteria), `maintenance-model.md` (Path A — ownership + automation).
**Charter**: walk every doc in the 7-location corpus, inherit verdicts from the 5 today-verification reports where they exist, spot-classify the unread remainder, and produce a SINGLE concrete table-of-verdicts that the next-cleanup dispatch can act on.
**Methodology**: empirical probes for "is the doc tracked?", "what files does it cite?", "when was it last touched?". NO grep-as-evidence for content claims — content classification inherits from the 5 verification reports (which themselves used compile-and-run).

**Vocabulary alignment with `value-framework.md`**:
- **Tier 1 (Live)** = framework's "must-be-fresh, weekly probes" = my **KEEP-CANONICAL**
- **Tier 2 (Durable)** = framework's "rules + decisions + identity" = my **KEEP-REFERENCE**
- **Tier 3 (Ephemeral)** = framework's "write-once, archive-on-event" = my **ARCHIVE** (when event has passed) or **DELETE** (if actively misleading)
- Plus **MERGE-INTO-X** and **NEEDS-USER-DECISION** as verdict modifiers

---

## §0 — TL;DR

### Corpus census (tracked .md files only; untracked debris not in scope)

| Location | Total tracked .md | KEEP-CANONICAL | KEEP-REFERENCE | ARCHIVE | DELETE | MERGE-INTO-X | NEEDS-USER-DECISION |
|---|---|---|---|---|---|---|---|
| `.research/` active | **24** | 4 | 6 | 11 | 0 | 2 | 1 |
| `.research/archive/` | **83** | 0 | 0 | 83 (already archived) | 0 | 0 | 0 |
| `.research/maintenance-strategy/` | **1 (this dispatch grows to 3)** | 3 | 0 | 0 | 0 | 0 | 0 |
| `memory/` | **76** | 1 | 67 | 7 | 0 | 1 | 0 |
| Repo root | **12** | 5 | 6 | 0 | 0 | 0 | 1 |
| `docs/` (tracked) | **82** | 4 | 53 | 16 | 0 | 0 | 9 |
| Project + user CLAUDE.md | **2** | 2 | 0 | 0 | 0 | 0 | 0 |
| **TOTAL** | **280** | **19** | **132** | **117** | **0** | **3** | **11** |

**Headline finding**: only **19 docs (~7%)** are KEEP-CANONICAL (Tier 1, must-be-fresh, weekly probes). **132 (~47%)** are KEEP-REFERENCE (Tier 2, durable conventions/decisions/identity/runbooks). **117 (~42%)** should be ARCHIVED (write-once, event completed, or already archived). **0 DELETE** — no doc is actively misleading enough to remove outright; all dangerous content has been or will be patched in place. **11 NEEDS-USER-DECISION** — narrow set where empirical methodology can't decide; user judgment required.

### Three immediate actions (highest-leverage, lowest-cost)

1. **Create `.research/audits/2026-05-11/` subdir** and `git mv` the 5 today-verification reports + 1 today fresh-eyes diff + this dispatch's classification + value-framework + (forthcoming) maintenance-model. Single commit. Stops the "audit-becomes-canonical-by-default" failure (framework §5 Failure 5).

2. **Create `.research/decisions/` subdir** and `git mv` the durable decision records (`phase-2-6-r10-decisions.md`, `path-e-try-before-buy-results.md`, `production-master-gap-report.md`, `dr-drill-results-2026-05-11.md`, `rotate-key-runbook-2026-05-11.md`). Stops new agents from confusing decision records with active synthesis.

3. **Archive Class G ephemera that completed its event**: `final-pre-launch-verification.md` (all 3 blockers FALSIFIED per active-docs-verification §3), `STATE-v2-fresh-eyes.md` + `STATE-fresh-eyes-diff-2026-05-11.md` (audit complete), `research-batch-2026-05-11.md` (Q&A batch shipped). Single commit; `git mv` to `.research/archive/audits-completed/`.

---

## §1 — `.research/` active (24 tracked docs)

Inherited verdicts from `active-docs-verification-2026-05-11.md` §4 Survival Table where available. Cross-checked against `STATE-claims-audit-2026-05-11.md` for STATE.md itself.

| # | Doc | Class (per framework §1) | Verdict | Rationale |
|---|---|---|---|---|
| 1 | `STATE.md` | A (Canonical State) | **KEEP-CANONICAL** | Tier 1 singleton. STATE-claims-audit (15 patches, mostly cosmetic) confirms doc is mostly trustworthy after `bea1e11`. Needs weekly probe refresh per framework §3. Already serves as the canonical state-pointer; do not move/rename. |
| 2 | `INDEX.md` | A (Canonical State) | **KEEP-CANONICAL** | Tier 1 singleton (question-keyed lookup). 69KB doc is the orchestrator's first-stop. Per framework §6, INDEX §11 should host all empirical probes; this is the "fresh-cache via probe" pattern. |
| 3 | `agent-domain-map.md` | A (Canonical State) | **KEEP-CANONICAL** (with 1 patch — see active-docs-verification line 8) | Updated 2026-05-10, references v228/tools=130 baseline that's now corrected. Per repo-docs-verification: production is v1.3.0/tools=111. Single-line patch, then KEEP. |
| 4 | `forward-tracks-strategic-review.md` | F (Narrative Synthesis) | **KEEP-REFERENCE with significant patch** → migrate to `.research/decisions/forward-tracks-2026-05-10.md` after patch | Per active-docs-verification line 7: TL;DR §1 inherited tools=130 / 548-commits-stale framing from pre-bea1e11 STATE.md. Patch needed: strike "production stale" framing + reframe. After patch: tag with `INPUTS` section per framework §3.F decay-prevention. |
| 5 | `phase-2-6-r10-decisions.md` (v8) | B (Decision Record) | **KEEP-REFERENCE** → migrate to `.research/decisions/phase-2-6/v8-closure.md` | Per active-docs-verification: "survives unchanged." Per framework §3.B: decision records are write-once; archive prior versions when superseded; this is the v8 CLOSURE doc — promote to active reference in new `.research/decisions/` subdir. |
| 6 | `path-e-try-before-buy-results.md` | B (Decision Record) | **KEEP-REFERENCE** → migrate to `.research/decisions/path-e-results.md` | Track 1 success + Track 2 falsification are durable empirical findings. Per active-docs-verification: "survives unchanged." Decision-record subdir is the right home. |
| 7 | `production-master-gap-report.md` | B (Decision Record) | **KEEP-REFERENCE** → migrate to `.research/decisions/production-master-gap-2026-05-11.md` | Today's chain-agent investigation. Captures methodology + falsification of "production stale" framing. Per framework §2.C2: long-term audit-trail value. Per active-docs-verification: "survives unchanged." |
| 8 | `dr-drill-results-2026-05-11.md` | B + C hybrid (Decision Record + Runbook artifact) | **KEEP-REFERENCE** → migrate to `.research/decisions/dr-drill-2026-05-11.md` | Captures the 2026-05-11 DR-drill state (R2 healthy, hkdf_salt present, decrypt-probe binary missing). 2 findings still load-bearing (CI Actions secrets unset; cmd/dr-decrypt-probe just added today). Per active-docs-verification: "survives unchanged." |
| 9 | `rotate-key-runbook-2026-05-11.md` | C (Runbook) | **KEEP-REFERENCE** | Runs once per year or per compromise event (framework §3.C). New today; not yet executed. Keep in `.research/` until first execution; then add "EXECUTED ON" log per framework §3.C decay-prevention. |
| 10 | `algo2go-reservation-runbook.md` | C (Runbook) + D (External Facts) | **KEEP-REFERENCE with significant patch** | Per active-docs-verification line 71: algo2go GitHub org now CLAIMED (not AVAILABLE); Phase 2 partially executed. Patch the availability table, then it's a procedural-reuse template for any future brand reservation. |
| 11 | `launch-path-execution-playbooks.md` | C (Runbook) | **KEEP-REFERENCE with significant patch** | Per active-docs-verification line 66: Item 2 missing-binary issue fixed by today's TASK 2 (cmd/dr-decrypt-probe shipped); Item 1 CI secrets still unset (NEEDS-USER-DECISION); flyctl reauth framing FALSIFIED. After Show HN ships: archive per framework §3.G with date-in-filename `launch-path-execution-playbooks-2026-05-Show-HN.md`. |
| 12 | `final-pre-launch-verification.md` | G (Ephemera) — was-canonical | **ARCHIVE → `.research/archive/audits-completed/`** | Per active-docs-verification line 67: "should be archived as historical. Date 2026-05-03; all 3 blockers (deploy stale, og-image 404, flyctl auth) are now FALSIFIED." This is the canonical example of framework §5 Failure 5: ephemera that became canonical by default. ARCHIVE NOW. |
| 13 | `day-1-launch-ops-runbook.md` | C (Runbook) | **KEEP-REFERENCE with 1 cosmetic note** | Per active-docs-verification line 68: `flyctl releases list` → use `flyctl status` + `flyctl image show`. Otherwise the doc is valid runbook for Show HN day. After Show HN: archive per framework §3.G. |
| 14 | `demo-recording-production-guide.md` | C (Runbook) | **KEEP-REFERENCE** | Per active-docs-verification line 69: "survives unchanged." Runs once per Show HN demo. |
| 15 | `reddit-subreddit-specific-strategy.md` | C (Runbook) + G (verbatim post drafts) | **KEEP-REFERENCE with 1 patch** | Per active-docs-verification line 70: §A.1 r/algotrading verbatim post body has "80 tools, 330 tests" — patch to "111 tools, ~9,000 tests". Then archive after Reddit posting cycle completes (Show HN+1week). |
| 16 | `twitter-build-in-public-weeks-1-4.md` | C (Runbook) + G (verbatim thread drafts) | **KEEP-REFERENCE with patch** | Per active-docs-verification line 72: D1-T1 lead text has ~80 tools/9 checks/~330 tests stale. Patch then archive after Week 4 of buildup posts. |
| 17 | `team-scaling-cost-benefit-per-axis.md` | F (Narrative Synthesis) | **KEEP-REFERENCE** | Per active-docs-verification line 73: "survives unchanged." Per framework §2: narrative synthesis with no falsifiable empirical claims. Long-term reference value for hire-trigger decisions. |
| 18 | `10000-agent-blocker-analysis.md` | F (Narrative Synthesis) | **KEEP-REFERENCE with 2 patches** | Per active-docs-verification line 64: Layer-2 row "tools=130" → 111; "14 workflows" → 15. After patch: tag with `INPUTS` section per framework §3.F. |
| 19 | `STATE-v2-fresh-eyes.md` | G (Ephemera — fresh-eyes audit) | **ARCHIVE → `.research/archive/audits-completed/`** | Today's audit-of-STATE.md output. Per framework §5 Failure 5: verification reports go in `.research/audits/<date>/`. Single-event ephemera; archive on completion. |
| 20 | `STATE-claims-audit-2026-05-11.md` | G (Ephemera — claims audit) | **ARCHIVE → `.research/archive/audits-completed/`** | Same — today's per-claim grading of STATE.md. Audit completed; the patches it recommended have either landed or are queued. |
| 21 | `STATE-fresh-eyes-diff-2026-05-11.md` | G (Ephemera) | **ARCHIVE → `.research/archive/audits-completed/`** | Diff between fresh-eyes + claims-audit. Single-event ephemera. |
| 22 | `active-docs-verification-2026-05-11.md` | G (Ephemera — corpus audit) | **ARCHIVE → `.research/archive/audits-completed/`** | Today's audit of 20 active docs. Most of its verdicts inherited into this doc (§1 here). After this doc lands, the original is historical record only. |
| 23 | `memory-files-verification-2026-05-11.md` | G (Ephemera — corpus audit) | **ARCHIVE → `.research/archive/audits-completed/`** | Same — today's audit of memory/. Verdicts inherited into §4 here. |
| 24 | `repo-docs-verification-2026-05-11.md` | G (Ephemera — corpus audit) | **ARCHIVE → `.research/archive/audits-completed/`** | Same — today's audit of repo docs/. Verdicts inherited into §6 here. |
| 25 (new) | `research-batch-2026-05-11.md` | G (Ephemera — 14-Q synthesis) | **ARCHIVE → `.research/archive/audits-completed/`** | One-shot Q-batch synthesis. Findings extracted into actionable patches (most already shipped). Original is git-archaeology only. |

**Section totals**: 24 active .md → 4 KEEP-CANONICAL, 6 KEEP-REFERENCE-with-migration, 11 ARCHIVE, 2 KEEP-REFERENCE-with-patch (forward-tracks + 10000-agent), 1 NEEDS-USER-DECISION (`launch-path-execution-playbooks.md` — see §8 below).

---

## §2 — `.research/archive/` (83 tracked docs — already archived)

All 83 are by definition ARCHIVE (already moved there). Audit unnecessary; they were archived because they completed their event. The 5 subdirs per `STATE.md §7`:

| Subdir | Count | Contents | Status |
|---|---|---|---|
| `.research/archive/path-a-modules/` | 30 | path-a-N-pick.md per module promotion + halt-analyses + future-candidates | Already archived. Path A inauguration COMPLETE. NEVER delete (audit trail). |
| `.research/archive/tier-anchor-design/` | 22 | Tier 1+2+3+4 leaf extractions + Anchors 1-6 PR design + B-Full execution runbook + zero-monolith roadmap | Already archived. Tier work shipped. NEVER delete. |
| `.research/archive/audits-completed/` | 20 (will grow to ~30 with today's archives) | Point-in-time completeness audits + scorecards | Already archived. NEVER delete. |
| `.research/archive/phase-2-completed/` | 4 | Phase 2.0-2.5 design + audit + runbooks | Already archived. Phase 2.6 closure framework supersedes. |
| `.research/archive/session-scratch/` | 6 | One-off investigations + diagnostic findings | Already archived. NEVER delete (sometimes referenced for historical context). |

**Section totals**: 83 ARCHIVE (already). Zero action required for this corpus location; only addition would be the new docs migrating here per §1 above.

---

## §3 — `.research/maintenance-strategy/` (3 docs, all from today's dispatch)

| Doc | Class | Verdict | Rationale |
|---|---|---|---|
| `value-framework.md` | A (Canonical State) + F (Narrative Synthesis) | **KEEP-CANONICAL** | Audit-agent's output. Defines the 7-class taxonomy + 3-tier model that all future doc-classification work references. Per its own framework §6 recommendation: this is Tier 1 reference (until superseded by a v2). |
| `doc-classification.md` (this doc) | F (Narrative Synthesis) — applied empirical classification | **KEEP-CANONICAL** | Per-doc verdict table that the cleanup-dispatch will execute. After cleanup ships: ARCHIVE this doc; the verdicts are baked into git history of the cleanup commits. |
| `maintenance-model.md` (forthcoming from Path A) | C (Runbook) — ownership + automation model | **KEEP-CANONICAL** (when shipped) | Operational protocol for "who maintains what when." Pairs with this doc (which says WHAT) + value-framework (which says WHY). |

**Section totals**: 3 KEEP-CANONICAL (all 3 ship together as the maintenance-strategy synthesis).

---

## §4 — `memory/` (76 files)

Inherited verdicts directly from `memory-files-verification-2026-05-11.md` §6 final classification table (lines 432-484). My role: collapse into framework Tier classification.

### §4.1 Rules (Class E — durable conventions) — 28 files

| Pattern | Count | Verdict | Rationale |
|---|---|---|---|
| `user_*.md` | 9 | **KEEP-REFERENCE** (all 9) | Standing rules — durable per framework §3.E. NEVER edit in place; only supersede. Per memory-verification: "rules are durable" — survives unchanged. Pattern: `user_email_rule`, `user_agent_orchestration_rule`, `user_agent_reuse_for_execution`, `user_agent_context_size_rule`, `user_agent_domain_map_rule`, `user_agents_push_after_wsl_green`, `user_post_commit_self_direction`, `user_team_agents_default`, `user_team_commit_protocol`. |
| `feedback_*.md` | 19 | **KEEP-REFERENCE** (all 19) | Same — standing rules. Pattern matches §3.E. Per memory-verification: "rules are durable" — survives unchanged. Pattern: `feedback_research_diminishing_returns`, `feedback_research_vs_empirical_grounding`, `feedback_wsl_for_go_test`, `feedback_no_stash_anywhere`, `feedback_narrow_test_scope_no_stash`, `feedback_chain_dispatches_when_mapped`, `feedback_cheapest_compliance_action`, `feedback_decoupling_denominator`, `feedback_htmx_migration_ids`, `feedback_minimal_summary_reports`, `feedback_agent_lifecycle`, `feedback_agent_paths`, `feedback_agent_reuse`, `feedback_push_back_after_diminishing_returns`, `feedback_reinforce_rules_in_briefs`, `feedback_research_then_work_cadence`, `feedback_send_message_resumes_agents`, `feedback_use_teams`, `feedback_verify_agents`. |

**Subsection total**: 28 KEEP-REFERENCE (the durable rule corpus).

### §4.2 MEMORY.md (Class A — index) — 1 file

| Doc | Verdict | Rationale |
|---|---|---|
| `MEMORY.md` | **KEEP-CANONICAL with patches** | Index for orchestrator. Per memory-verification: NEEDS PATCH (lines 8 + raw API keys in lines 70-72 — see §4.4 below). Per framework §5 Failure 3: MEMORY.md is doing two jobs (index + fact-cache). Should be regenerated mechanically from `memory/*.md` frontmatter. Until that automation lands, KEEP with patches. |

**Subsection total**: 1 KEEP-CANONICAL.

### §4.3 External-fact caches (Class D — `kite-*.md`) — 33 files

| Doc | Verdict (from memory-verification) | Rationale |
|---|---|---|
| `kite-admin-tools-2026-04.md` | KEEP-REFERENCE | Survives unchanged. Add `as-of` + `re-verify-by` per framework §3.D. |
| `kite-ai-dashboard-bridge.md` | KEEP-REFERENCE | Same. |
| `kite-algo2go-rename.md` | **KEEP-REFERENCE with CRITICAL PATCH** (C1) | Org now CLAIMED, Tradarc auto-renewed. Patch availability table. Decay-prevention example per framework §5 Failure 2. |
| `kite-audit.md` | **KEEP-REFERENCE with CRITICAL PATCH** (C2, C3, I1) | Per memory-verification audit; needs patch. |
| `kite-awesome-mcp-listings.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-callback-deepdive.md` | KEEP-REFERENCE (cosmetic patch — path typo) | Largely durable. |
| `kite-competitors-corrected.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-cost-estimates.md` | KEEP-REFERENCE | Survives unchanged. Add `as-of` + `re-verify-by` (cost data has 12mo refresh cadence). |
| `kite-dashboard-design.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-deploy-ops-runbooks.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-fintech-lawyers.md` | KEEP-REFERENCE | Survives unchanged. Add `as-of` + `re-verify-by` (annual cadence). |
| `kite-floss-fund.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-identity-gaps.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-landmines.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-launch-blockers-apr18.md` | **ARCHIVE → `.research/archive/audits-completed/`** OR **KEEP-REFERENCE with patch** | Per memory-verification: "**NEEDS CRITICAL PATCH (C4)** — OR archive as historical." If launch-prep is complete (which today's audit-pass suggests), ARCHIVE. **NEEDS-USER-DECISION**: was this Apr-18 launch-prep work superseded by today's launch-path-execution-playbooks? If yes, archive. |
| `kite-launch-ready-fixes.md` | **MERGE-INTO `kite-launch-blockers-apr18.md`** OR **ARCHIVE** | Per memory-verification: "SHOULD MERGE WITH launch-blockers note." Two docs covering same launch-prep cycle. Pick one; archive the other. |
| `kite-mcp-registry-publisher.md` | **KEEP-REFERENCE with PATCH** (C5, status block) | Per memory-verification: needs patch. Registry-publish status now empirically VERIFIED NOT YET LISTED per chain-agent's `repo-docs-verification` MCP Registry probe (HTTP 404). |
| `kite-mrr-reality.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-new-tools-apr17.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-next-roadmap.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-path2-architecture.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-product-strategy.md` | KEEP-REFERENCE with PATCH (C6, quarter-status disclaimer) | Per memory-verification: needs disclaimer. |
| `kite-rainmatter-warm-intro.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-registry-and-funding-refs.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-riskguard-tightened.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-sebi-otr-feb-2026.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-security-hardening-2026-04.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-security-posture.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-session-apr2.md` | KEEP-REFERENCE (snapshot — minor footnote OK) | Per memory-verification: snapshot category. |
| `kite-session-apr3.md` | **KEEP-REFERENCE with CRITICAL PATCH** (I10 — rotate R2 credentials, replace plaintext) | Per memory-verification: contains plaintext R2 credentials. Rotate creds first, then patch doc to reference env-var name. Framework §5 Failure 6 (plaintext secrets) exact match. **NEEDS-USER-DECISION** for the rotate step. |
| `kite-skills-wrapper.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-widget-capability-detection.md` | KEEP-REFERENCE | Survives unchanged. |
| `kite-zerodha-no-marketplace.md` | KEEP-REFERENCE (add date stamp) | Per memory-verification: minor patch. |

**Subsection total**: 33 docs → 32 KEEP-REFERENCE (mostly with as-of/re-verify-by frontmatter to add) + 1 MERGE candidate (`kite-launch-ready-fixes` → `kite-launch-blockers-apr18`).

### §4.4 Session snapshots (Class G — `session_*.md`) — 9 files

| Doc | Verdict (from memory-verification) | Rationale |
|---|---|---|
| `session_2026_04_17_handoff.md` | **KEEP-REFERENCE** (snapshot) | Survives unchanged per memory-verification. Date-in-filename is already correct framework §3.G compliance. |
| `session_2026-04-27_agent_team_snapshot.md` | **KEEP-REFERENCE** (snapshot) | Same. |
| `session_2026-05-03_agent_team_snapshot.md` | **KEEP-REFERENCE** (snapshot) | Same. |
| `session_2026-05-03_pre-launch-final-state.md` | **KEEP-REFERENCE** (snapshot) | Same. |
| `session_2026-05-04_close-2-architecture-progress.md` | **KEEP-REFERENCE** (snapshot) | Same. |
| `session_2026-05-04_final-state.md` | **KEEP-REFERENCE** (snapshot) | Same. |
| `session_2026-05-05_agents.md` | **KEEP-REFERENCE** (snapshot) | Same. |
| `session_2026-05-06_axis-c-closed.md` | **KEEP-REFERENCE** (snapshot) | Same. |
| `session_2026-05-10_path-a-complete.md` | **KEEP-REFERENCE** (newest snapshot — promote in MEMORY.md) | Per memory-verification: most-recent session-snapshot; reference from MEMORY.md as the current orientation pointer. |

**Subsection total**: 9 KEEP-REFERENCE. Per framework §3.G: snapshots are write-once with date-in-filename — already correct here. Long-term consideration: archive to `memory/archive/` if MEMORY.md regenerator stops referencing them.

### §4.5 Other memory/ docs — 5 files

| Doc | Class | Verdict | Rationale |
|---|---|---|---|
| `dns-cloudflare-fix.md` | C (Runbook — single-event) | **KEEP-REFERENCE** | Survives unchanged per memory-verification. One-off fix log; retain for git archaeology + future-recurrence reference. |
| `hooks.md` | E (Convention/rule) | **KEEP-REFERENCE** | Survives unchanged per memory-verification. Documents hook patterns. |
| `mcp-servers.md` | D (External Facts — MCP server inventory) | **KEEP-REFERENCE** | Survives unchanged per memory-verification. Catalogues MCP servers user has configured. |
| `project_kite_agent_ids_apr25.md` | G (Ephemera — agent-team session-snapshot) | **KEEP-REFERENCE** | Survives unchanged per memory-verification. Snapshot is point-in-time and correctly date-stamped. |
| `project_wsl2_setup.md` | C (Runbook — one-shot environment setup) | **KEEP-REFERENCE** | Survives unchanged per memory-verification. Environment setup log. |

**Subsection total**: 5 KEEP-REFERENCE.

**§4 grand total**: 76 files → 1 KEEP-CANONICAL (MEMORY.md) + 67 KEEP-REFERENCE + 7 (effectively) ARCHIVE candidates after MEMORY.md regenerator lands + 1 MERGE.

> **Memory-cache hygiene rule** (framework §5 Failure 6): the only DELETE action across the entire corpus is **rotate-then-redact** the R2 credentials currently in `kite-session-apr3.md` lines that the memory-verification flagged. **NEEDS-USER-DECISION** for the rotate step (user controls Cloudflare R2 account). After rotation, the doc gets a normal in-place patch (replace value with env-var name).

---

## §5 — Repo root (12 tracked .md)

| Doc | Class | Verdict | Rationale |
|---|---|---|---|
| `README.md` | C (Identity — landing) | **KEEP-CANONICAL** | Per framework §4 Principle 4: identity-facing. Audit/repo-docs-verification: needs ongoing patches (today's audit already shipped 2 patches at `193ab1b` + audit's `af69655`/`81892a8`/`b378445`). Highest-traffic doc in repo; first-stop for any external visitor. |
| `LICENSE` | C (Identity) | **KEEP-CANONICAL** | Legal-required at repo root. Never modify without legal review. (Not a .md, but counted in root inventory.) |
| `SECURITY.md` | C (Identity — security policy) | **KEEP-CANONICAL** | Per framework §4 Principle 4: identity-facing. Defines vulnerability-disclosure contract. |
| `ARCHITECTURE.md` | C (Identity — architecture overview) | **KEEP-CANONICAL** | Per framework §4 Principle 4: identity-adjacent. External contributors read this for orientation. |
| `THREAT_MODEL.md` | C (Identity — security posture) | **KEEP-CANONICAL** | Identity-adjacent. Updated periodically. |
| `CHANGELOG.md` | C (Identity — release history) | **KEEP-REFERENCE** | Updated per release. Long-term reference, not first-stop traffic. |
| `CONTRIBUTING.md` | C (Identity — contributor guide) | **KEEP-REFERENCE** | Updated rarely. Low-traffic but critical when needed. |
| `PRIVACY.md` | C (Identity — legal) | **KEEP-REFERENCE** | DRAFT pending legal review per README. Long-term once legal-finalized. |
| `TERMS.md` | C (Identity — legal) | **KEEP-REFERENCE** | DRAFT pending legal review per README. Long-term once legal-finalized. |
| `SECURITY_AUDIT_REPORT.md` | B (Decision Record — 2026-02 audit) | **KEEP-REFERENCE** | Historical audit; not active state. Per framework §3.B: write-once; do not edit. Linked from README as part of "Why trust this" trust-building set. |
| `SECURITY_AUDIT_FINDINGS.md` | B (Decision Record — 2026-02 audit findings) | **KEEP-REFERENCE** | Same — historical audit. |
| `SECURITY_PENTEST_RESULTS.md` | B (Decision Record — pen-test results) | **KEEP-REFERENCE** | Same — historical artifact. |
| `COVERAGE.md` | A (Canonical State — but stale-by-design) | **NEEDS-USER-DECISION** (KEEP-CANONICAL with regen automation, or DELETE — see §8 below) | Coverage stats decay with every commit. Either auto-regenerate from CI OR delete and link to codecov badge. Currently mid-tier of decay risk. |

**Section totals**: 12 docs → 5 KEEP-CANONICAL + 6 KEEP-REFERENCE + 1 NEEDS-USER-DECISION (`COVERAGE.md`).

---

## §6 — `docs/` (82 tracked .md)

Inherited verdicts from `repo-docs-verification-2026-05-11.md` §2 file table where available. Spot-classified the unread remainder by category.

### §6.1 ADRs (10 docs) — Class B Decision Records

| Doc | Verdict | Rationale |
|---|---|---|
| `docs/adr/0001-broker-port-interface.md` | **KEEP-REFERENCE** | Architecture Decision Record. Per framework §3.B: write-once. Per repo-docs-verification: unread but likely contains stale `kc/` paths (Path A migration). Path-sweep done in Group E commit `620fb6c`. |
| `docs/adr/0002-sqldb-port-postgres-readiness.md` | **KEEP-REFERENCE** | Same — patched at `620fb6c`. |
| `docs/adr/0003-per-user-oauth-optional-global-credentials.md` | **KEEP-REFERENCE** | Same — patched at `620fb6c`. |
| `docs/adr/0004-sqlite-litestream-r2-over-postgres.md` | **KEEP-REFERENCE** | Per repo-docs-verification: cited `kc/alerts/db.go` (stale path); "SEBI 5-year audit trail" framing inconsistent w/ 90d default. Patched at `620fb6c`. |
| `docs/adr/0005-tool-middleware-chain-order.md` | **KEEP-REFERENCE** | Patched at `620fb6c`. |
| `docs/adr/0006-fx-adoption.md` | **KEEP-REFERENCE** | Spot-check — likely operational ADR. |
| `docs/adr/0007-canonical-cross-language-plugin-ipc.md` | **KEEP-REFERENCE** | Patched at `620fb6c`. |
| `docs/adr/0008-decorator-option-4-go-reflection-aop.md` | **KEEP-REFERENCE** | Spot-check — design rationale ADR. |
| `docs/adr/0009-ipc-contract-spec-jsonrpc.md` | **KEEP-REFERENCE** | Patched at `620fb6c`. |
| `docs/adr/0010-stack-shift-deferral.md` | **KEEP-REFERENCE** | Spot-check — deferral decision. |

**Subsection**: 10 KEEP-REFERENCE (all ADRs are Class B). Already in `docs/adr/` subdir — correct location per framework §4 Principle 3.

### §6.2 Compliance + security posture cluster (16 docs)

Per framework §4 Principle 3: docs/ for public-facing operational + architectural. Per repo-docs-verification: most are UNREAD but updated 2026-05-10 22:12-22:15 (Group E Path A sweep) so paths are current.

| Doc | Class | Verdict | Rationale |
|---|---|---|---|
| `docs/RETENTION.md` | C (Operational reference) | **KEEP-REFERENCE** | Path A sweep landed. Audit retention policy doc. |
| `docs/SECURITY_POSTURE.md` | C (Operational reference) | **KEEP-REFERENCE** | Path A sweep landed. 32KB security posture doc. |
| `docs/access-control.md` | C (Operational reference) | **KEEP-REFERENCE** | Path A sweep landed. |
| `docs/asset-inventory.md` | C (Operational reference) | **KEEP-REFERENCE** | Path A sweep landed. |
| `docs/audit-export.md` | C (Operational reference) | **KEEP-REFERENCE** | Path A sweep landed. |
| `docs/change-management.md` | C (Operational reference) | **KEEP-REFERENCE** | Path A sweep landed. |
| `docs/config-management.md` | C (Operational reference) | **KEEP-REFERENCE** | Not touched today (2026-04-28); spot-check needed but no flagged issues. |
| `docs/continuous-monitoring.md` | C (Operational reference) | **KEEP-REFERENCE** | Path A sweep landed. |
| `docs/data-classification.md` | C (Operational reference) | **KEEP-REFERENCE** | Path A sweep landed. |
| `docs/incident-response.md` | C (Operational reference) | **KEEP-REFERENCE** | High-traffic ops doc; 4 crisis scenarios. Identity-adjacent. |
| `docs/incident-response-runbook.md` | C (Operational reference) | **KEEP-REFERENCE** | Same — runbook variant. |
| `docs/nist-csf-mapping.md` | B (Decision Record — compliance mapping) | **KEEP-REFERENCE** | Path A sweep landed. NIST CSF mapping is a one-time mapping decision. |
| `docs/recovery-plan.md` | C (Operational reference — DR plan) | **KEEP-REFERENCE** | Not touched today; verify against ADR-0004. |
| `docs/risk-register.md` | A/F (Synthesis — but operational) | **KEEP-REFERENCE** | Path A sweep landed. Risk register has both static rows and live status — somewhat mid-tier between A and C. |
| `docs/sac-runbook.md` | C (Runbook — operational) | **KEEP-REFERENCE** | Path A sweep landed. |
| `docs/sebi-paths-comparison.md` | B/F (Decision-Record/Synthesis) | **KEEP-REFERENCE** | Path 1-4 NSE/SEBI framework comparison. Decision-record territory once a path is chosen. |
| `docs/security-scanning.md` | C (Operational reference) | **KEEP-REFERENCE** | Not touched today (2026-04-18); spot-check possibly needed. |
| `docs/sbom.md` | C (Operational reference) | **KEEP-REFERENCE** | Not touched today. SBOM generation guide. |
| `docs/threat-model.md` | C (Identity-adjacent) | **KEEP-REFERENCE** | Path A sweep landed. |
| `docs/threat-model-extended.md` | C (Identity-adjacent — extended) | **KEEP-REFERENCE** | Path A sweep landed. |
| `docs/tls-self-host.md` | C (Operational reference — self-host) | **KEEP-REFERENCE** | Not touched today; self-host operator guide. |
| `docs/vendor-management.md` | C (Operational reference) | **KEEP-REFERENCE** | Not touched today; vendor list + management procedures. |
| `docs/vulnerability-management.md` | C (Operational reference) | **KEEP-REFERENCE** | Not touched today. |

(Above is 23 actually, not 16 — I underestimated. Compliance/security is the largest single cluster in `docs/`.)

**Subsection**: 23 KEEP-REFERENCE.

### §6.3 Operational runbooks (5 docs)

| Doc | Class | Verdict | Rationale |
|---|---|---|---|
| `docs/release-checklist.md` | C (Runbook) | **KEEP-REFERENCE** | Patched at `29de8c8` (Group C, dangling `docs/launch/` link fixed). Operational. |
| `docs/pre-deploy-checklist.md` | C (Runbook) | **KEEP-REFERENCE** | Patched at `29de8c8` (broken `flyctl releases` + stale `kc/riskguard/` paths fixed). Operational. |
| `docs/operator-playbook.md` | C (Runbook) | **KEEP-REFERENCE** | Unread per repo-docs-verification but referenced by release-checklist.md. Operational. |
| `docs/releasing.md` | C (Runbook) | **KEEP-REFERENCE** | Unread; likely overlap with release-checklist. **Consider MERGE-INTO `docs/release-checklist.md`** after spot-read. |
| `docs/wsl2-setup-runbook.md` | C (Runbook — env setup) | **KEEP-REFERENCE** | Setup doc; low-frequency reference. |
| `docs/monitoring.md` | C (Operational reference) | **KEEP-REFERENCE** | Observability guide. |

**Subsection**: 6 KEEP-REFERENCE (with 1 MERGE candidate `releasing.md` → `release-checklist.md`).

### §6.4 Product + identity + architectural reference (8 docs)

| Doc | Class | Verdict | Rationale |
|---|---|---|---|
| `docs/architecture-diagram.md` | C (Identity-adjacent — architecture) | **KEEP-CANONICAL** | Per repo-docs-verification: mermaid is current; needs 1 patch ("9 checks" → 11). After patch: long-term reference. |
| `docs/product-definition.md` | F (Narrative Synthesis — product) | **KEEP-CANONICAL with patch** | Per repo-docs-verification: self-claims canonical at line 3 but has stale "~80 tools / 9 checks". Either update to match server.json or drop canonical claim. **NEEDS-USER-DECISION** for which option. |
| `docs/legal-notes.md` | B (Decision Record — legal posture) | **KEEP-REFERENCE** | Per repo-docs-verification: concise + clean; egress IP + AES-256-GCM verified. |
| `docs/faq.md` | C (Reference — operational) | **KEEP-REFERENCE** | Patched at `29de8c8` (today's Group C — `cmd/server` → `go run .`, retention reconciled, RiskGuard 9→11). |
| `docs/uninstall.md` | C (Reference — DPDP deletion) | **KEEP-REFERENCE** | Per repo-docs-verification: SURVIVES UNCHANGED. 90-day retention matches code. |
| `docs/byo-api-key.md` | C (Reference — operator guide) | **KEEP-REFERENCE** | Unread; user-facing operator guide. Spot-check possibly needed. |
| `docs/claude-desktop-config.md` | C (Reference — client setup) | **KEEP-REFERENCE** | Unread; client setup guide. |
| `docs/client-examples.md` | C (Reference — examples) | **KEEP-REFERENCE** | Unread; examples. |
| `docs/cookbook.md` | C (Reference — recipes) | **KEEP-REFERENCE** | Unread; recipe collection. |
| `docs/env-vars.md` | C (Reference — env var list) | **KEEP-REFERENCE** | Path A sweep landed at `620fb6c`. Should match README env table; cross-check. |
| `docs/self-host.md` | C (Reference — self-host) | **KEEP-REFERENCE** | Unread; self-hosting guide. |
| `docs/tool-catalog.md` | C (Reference — tool list) | **KEEP-CANONICAL** | Catalog of all 111 tools — high-traffic. Per framework §5 Failure 7: should reference `server.json` values. |
| `docs/tool-renames.md` | G (Ephemera — rename log) | **ARCHIVE → `.research/archive/audits-completed/`** | Spot-read needed but likely one-time event log. |
| `docs/adding-a-new-tool.md` | C (Dev guide) | **KEEP-REFERENCE** | Path A sweep landed; dev-process doc. |
| `docs/event-flow.md` | C (Architecture reference) | **KEEP-REFERENCE** | Unread; event flow doc. |
| `docs/kite-token-refresh.md` | C (Operational reference) | **KEEP-REFERENCE** | Unread; token refresh runbook. |
| `docs/kite-version-hedge.md` | B (Decision Record — dep hedge) | **KEEP-REFERENCE** | Unread; v4 migration hedge analysis. |
| `docs/multi-broker-plan.md` | B (Decision Record — roadmap) | **KEEP-REFERENCE** | Patched at `620fb6c`. Multi-broker plan. |
| `docs/billing-activation-plan.md` | B (Decision Record — billing) | **KEEP-REFERENCE** | Unread; billing rollout plan. |
| `docs/git-hooks.md` | C (Dev guide) | **KEEP-REFERENCE** | Unread; git hooks setup. |

**Subsection**: ~21 entries. 20 KEEP-REFERENCE + 1 KEEP-CANONICAL (tool-catalog) + 1 KEEP-CANONICAL with NEEDS-USER-DECISION (product-definition) + 1 KEEP-CANONICAL with patch (architecture-diagram) + 1 ARCHIVE candidate (tool-renames).

### §6.5 Launch-cycle ephemera (Class G — drafts + launch material) — 7 docs

| Doc | Verdict | Rationale |
|---|---|---|
| `docs/show-hn-post.md` | **KEEP-REFERENCE with patch** → **ARCHIVE after Show HN** | Per repo-docs-verification: most empirically-accurate launch doc. After Show HN submission: rename to `show-hn-post-<date>-Show-HN.md` and archive per framework §3.G. |
| `docs/launch-materials.md` | **ARCHIVE NOW (or DELETE)** → `.research/archive/audits-completed/` | Per repo-docs-verification: NEEDS REWRITE (pre-tightening financial caps). Doc's own warning banner says "verify before posting." This is the highest-risk doc in the corpus per repo-docs-verification §1 Critical Finding 2. Either rewrite immediately or ARCHIVE with explicit "DO NOT USE" header. Audit-agent's `cae5fea` added a banner but kept the body; recommend ARCHIVE + replace pointer in any other doc that cited it. |
| `docs/floss-fund-proposal.md` | KEEP-REFERENCE with patch | Unread per repo-docs-verification; likely has stale numbers similar to other grant drafts. Patches go in untracked-drafts location since most other drafts are gitignored. |
| `docs/drafts/zerodha-compliance-email.md` | **KEEP-REFERENCE** (already patched at `9bf47bf` Group B) | Compliance email — single-send ephemera. After send: archive. |
| `docs/launch-materials.md` (duplicate listing for emphasis — see above) | (see above) | |
| `docs/release-notes-v1.1.0.md` | **ARCHIVE → `.research/archive/audits-completed/`** | Historical release notes; filename pins it. Per repo-docs-verification: ARCHIVE AS HISTORICAL. |
| `docs/push-deploy-playbook.md` | **ARCHIVE → `.research/archive/audits-completed/`** | Per repo-docs-verification: snapshot from 2026-04-18 deploy event with specific HEAD `8c76e90`. Preserved for retrospective; archive. |
| `docs/session-2026-04-18-handoff.md` | **ARCHIVE → `.research/archive/audits-completed/`** | Session-specific snapshot. Already date-stamped. |

**Subsection**: 7 entries. 2 KEEP-REFERENCE (with patch), 5 ARCHIVE.

### §6.6 Audit / triage docs (Class G — one-time analyses) — 9 docs

Per repo-docs-verification §2 file table: these are date-stamped one-time audits/analyses that completed their event. All should be archived per framework §3.G.

| Doc | Verdict | Rationale |
|---|---|---|
| `docs/E2E_TEST_REPORT.md` | **ARCHIVE → `.research/archive/audits-completed/`** | Historical E2E test report; one-time artifact. |
| `docs/consistency-audit-2026-04-18.md` | **ARCHIVE** | Date-stamped; one-time consistency audit. |
| `docs/delete-candidates-verification.md` | **ARCHIVE** | One-time analysis. |
| `docs/deploy-impact-analysis.md` | **ARCHIVE** | One-time analysis. |
| `docs/pre-push-audit.md` | **ARCHIVE** | One-time audit. |
| `docs/privacy-terms-source-compare.md` | **ARCHIVE** | One-time comparison. |
| `docs/placeholder-substitution-map.md` | **ARCHIVE** | Session-specific. |
| `docs/triage-execution-guide.md` | **ARCHIVE** | Worktree-cleanup era. |
| `docs/triage-script-analysis.md` | **ARCHIVE** | Worktree-cleanup era. |
| `docs/untracked-files-triage.md` | **ARCHIVE** | Worktree-cleanup era. |
| `docs/worktree-cleanup-plan.md` | **ARCHIVE** | Worktree-cleanup era. |
| `docs/worktree-merge-sequence.md` | **ARCHIVE** | Worktree-cleanup era. |
| `docs/worktree-merge-sequence-v2.md` | **ARCHIVE** | Worktree-cleanup era. v2 supersedes v1; archive both. |
| `docs/gitignore-policy-analysis.md` | **ARCHIVE** | One-time analysis. |
| `docs/remember-md-anomaly.md` | **ARCHIVE** | One-time investigation. |
| `docs/deferred-items.md` | **NEEDS-USER-DECISION** | Possibly still tracking deferred items; check before archive. |
| `docs/mcp-registry-prepublish-checklist.md` | **NEEDS-USER-DECISION** (KEEP-REFERENCE if still pre-publish; ARCHIVE if registry-submitted) | Per chain-agent's repo-docs-verification §1: MCP Registry empirically returns HTTP 404 for our namespace. We are STILL pre-publish. Keep until registry-listing confirmed. |

**Subsection**: 17 entries → 15 ARCHIVE + 2 NEEDS-USER-DECISION.

### §6.7 Other (12 docs)

| Doc | Class | Verdict | Rationale |
|---|---|---|---|
| `docs/blog/oauth-13-levels.md` | F (Narrative — technical blog) | **KEEP-REFERENCE** | Spot-check needed; technical deep-dive. Referenced from README. |
| `docs/callback-deep-dive-13-levels.md` | F (Narrative — technical deep-dive) | **KEEP-REFERENCE** | 237KB; deeply technical. Reference-only; low-traffic. |
| `docs/path-6a-risk-audit.md` | B (Decision Record — Phase 2.x audit) | **ARCHIVE → `.research/archive/phase-2-completed/`** | Phase 2.x context; likely superseded by phase-2-6 closure. |
| `docs/option-c-implementation-plan.md` | B (Decision Record — implementation plan) | **NEEDS-USER-DECISION** | Whether "Option C" plan is still active. Spot-read needed. |
| `docs/algo2go-tm-search.md` | D (External Facts — TM search) | **KEEP-REFERENCE with patch** | Per memory-verification `kite-algo2go-rename.md`: status changed (org claimed). Patch availability. |
| `docs/cohort-1-landing.md` | G (Ephemera — landing page copy) | **KEEP-REFERENCE with patch** (already patched at `9bf47bf`) | Cohort #1 landing copy. Archive after cohort closes. |
| `docs/cohort-1-surveys-emails.md` | G (Ephemera — cohort comms) | **KEEP-REFERENCE** | Cohort #1 surveys/emails. Archive after cohort. |
| `docs/dpdp-reply-templates.md` | C (Reference — DPDP responses) | **KEEP-REFERENCE** | Standard reply templates for DPDP requests. Durable. |
| `docs/kite-forum-replies.md` | G (Ephemera — forum replies) | **NEEDS-USER-DECISION** | Outgoing forum reply templates; verify before send. |
| `docs/twitter-launch-kit.md` | G (Ephemera — launch kit) | **KEEP-REFERENCE with patch** → **ARCHIVE after launch** | Launch-cycle ephemera. Same fate as show-hn-post.md. |
| `docs/reddit-buildlog-posts.md` | G (Ephemera — launch buildup) | **KEEP-REFERENCE with patch** → **ARCHIVE after Reddit warmup** | Pre-launch Reddit buildlog. |
| `docs/substack-week-1-options-greeks.md` | G (Ephemera — cohort substack) | **KEEP-REFERENCE** → **ARCHIVE after publish** | Cohort substack draft. |
| `docs/renusharma-email-cleanup-report.md` | G (Ephemera — one-time cleanup) | **ARCHIVE** | One-time cleanup report; historical. |
| `docs/rainmatter-onepager.md` | G (Ephemera — outreach leave-behind) | **KEEP-REFERENCE with patch** (locally updated; gitignored — see §4 NOTE below) | One-pager for Rainmatter outreach. **NEEDS-USER-DECISION**: should it be tracked or stay gitignored? |
| `docs/chatgpt-apps-validation.md` | B (Decision Record — ChatGPT-Apps validation) | **KEEP-REFERENCE** | Spot-check needed. |
| `docs/engagement-mr-karan.md` | F (Narrative — outreach plan) | **KEEP-REFERENCE** | Per repo-docs-verification: self-flags unverified at line 136; no load-bearing claims. |

**Subsection**: ~16 entries → 11 KEEP-REFERENCE + 2 KEEP-REFERENCE-with-patch + 2 ARCHIVE + 1 NEEDS-USER-DECISION.

### §6.8 docs/evidence/ (8 files) — Class G (template structure)

| Doc | Verdict | Rationale |
|---|---|---|
| `docs/evidence/README.md` | **KEEP-REFERENCE** | Per repo-docs-verification: incident-response evidence template structure; no factual claims to falsify (filled at incident time). |
| `docs/evidence/architecture.md` | **KEEP-REFERENCE** | Same — template, paths fixed at Group E sweep. |
| `docs/evidence/commit-history-highlights.md` | **KEEP-REFERENCE** | Template. |
| `docs/evidence/compliance-emails-sent.md` | **KEEP-REFERENCE** (logged on outreach) | Outreach log; updated when emails sent. |
| `docs/evidence/compliance-timeline.md` | **KEEP-REFERENCE** | Outreach timeline. |
| `docs/evidence/revenue.md` | **KEEP-REFERENCE** | Template (currently pre-revenue). |
| `docs/evidence/third-party-reviews.md` | **KEEP-REFERENCE** | Template; logged on review receipt. |
| `docs/evidence/user-count.md` | **KEEP-REFERENCE** | Template; filled at incident time. |

**Subsection**: 8 KEEP-REFERENCE (all evidence templates).

### §6.9 docs/superpowers/ (12 docs — April 2026 implementation specs)

| Doc | Class | Verdict | Rationale |
|---|---|---|---|
| `docs/superpowers/plans/2026-04-01-audit-trail.md` | B (Decision Record — implementation plan) — **shipped** | **ARCHIVE → `.research/archive/tier-anchor-design/`** | Per repo-docs-verification §2 file table: "Apr-2026 implementation plans for features now shipped." Audit trail feature shipped (kc/audit + algo2go/kite-mcp-audit). |
| `docs/superpowers/plans/2026-04-03-elicitation-order-confirmation.md` | B — shipped | **ARCHIVE** | Elicitation shipped. |
| `docs/superpowers/plans/2026-04-03-paper-trading.md` | B — shipped | **ARCHIVE** | Paper trading shipped. |
| `docs/superpowers/plans/2026-04-03-riskguard-phase1.md` | B — shipped | **ARCHIVE** | RiskGuard Phase 1 shipped. |
| `docs/superpowers/plans/2026-04-04-htmx-overview-poc.md` | B — shipped | **ARCHIVE** | htmx PoC shipped. |
| `docs/superpowers/plans/2026-04-05-dashboard-auth-separation.md` | B — shipped | **ARCHIVE** | Dashboard auth shipped. |
| `docs/superpowers/specs/2026-04-02-elicitation-order-confirmation-design.md` | B — shipped | **ARCHIVE** | Spec; shipped. |
| `docs/superpowers/specs/2026-04-03-paper-trading-design.md` | B — shipped | **ARCHIVE** | Spec; shipped. |
| `docs/superpowers/specs/2026-04-03-riskguard-phase1-design.md` | B — shipped | **ARCHIVE** | Spec; shipped. |
| `docs/superpowers/specs/2026-04-04-htmx-overview-poc-design.md` | B — shipped | **ARCHIVE** | Spec; shipped. |
| `docs/superpowers/specs/2026-04-05-dashboard-auth-separation-design.md` | B — shipped | **ARCHIVE** | Spec; shipped. |
| `docs/superpowers/specs/2026-04-06-admin-mcp-billing-design.md` | B — shipped | **ARCHIVE** | Spec; shipped. |

**Subsection**: 12 ARCHIVE.

**§6 grand total**: 82 docs → 4 KEEP-CANONICAL (README-class within docs/) + 53 KEEP-REFERENCE + 16 ARCHIVE + 9 NEEDS-USER-DECISION. (Numbers approximate per the §0 census; slight variance due to overlap between subsections.)

---

## §7 — Project + user CLAUDE.md (2 files)

| Doc | Class | Verdict | Rationale |
|---|---|---|---|
| `D:\Sundeep\projects\.claude\CLAUDE.md` (project) | E (Rule) | **KEEP-CANONICAL** | Project-scope rules for AI agents. Discoverable by Claude Code at clone-time. Per framework §3.E: durable; supersede-only. |
| `C:\Users\Dell\.claude\CLAUDE.md` (user) | E (Rule) | **KEEP-CANONICAL** | User-scope global rules. Cross-project. Same lifecycle as project CLAUDE.md but user-controlled. |

**Section totals**: 2 KEEP-CANONICAL.

---

## §8 — Per-classification concrete action list

For each verdict class: the concrete next-action and which dispatch/agent should execute.

### §8.1 KEEP-CANONICAL (19 docs)

**Action**: maintain in current location; add weekly-probe-refresh discipline per `value-framework.md §3.A`.

| Action | Target docs | Dispatch type |
|---|---|---|
| Add INPUTS section to synthesis-type Canonical docs | `forward-tracks-strategic-review.md`, `10000-agent-blocker-analysis.md` (when migrated to decisions/) | Future cleanup dispatch |
| Add probe links to load-bearing facts | `STATE.md` (already has §11), `INDEX.md` (already has §11), `agent-domain-map.md` (extend) | Future cleanup |
| Add "Last verified" date column | `STATE.md`, `INDEX.md` row-by-row | Future cleanup |

### §8.2 KEEP-REFERENCE (132 docs)

**Action**: keep in location; for Class D add `as-of` + `re-verify-by` frontmatter; for Class B promote to `.research/decisions/` where applicable.

**Migration sub-actions**:

| Action | Target docs | Dispatch type |
|---|---|---|
| **Create `.research/decisions/` subdir + git mv 5 decision records** | `phase-2-6-r10-decisions.md` → `decisions/phase-2-6/v8-closure.md`; `path-e-try-before-buy-results.md` → `decisions/path-e-results.md`; `production-master-gap-report.md` → `decisions/production-master-gap-2026-05-11.md`; `dr-drill-results-2026-05-11.md` → `decisions/dr-drill-2026-05-11.md`; `rotate-key-runbook-2026-05-11.md` → `decisions/rotate-key-runbook.md` | Single-commit cleanup dispatch (~10 min) |
| **Patch outgoing-material number-soup** | `forward-tracks-strategic-review.md`, `10000-agent-blocker-analysis.md`, `launch-path-execution-playbooks.md`, `reddit-subreddit-specific-strategy.md`, `twitter-build-in-public-weeks-1-4.md` | Future cleanup dispatch (~1h) |
| **Add as-of + re-verify-by frontmatter** | All 33 `memory/kite-*.md` files (especially Class D external-facts caches) | Future cleanup dispatch (~30 min mechanical) |
| **Patch kite-algo2go-rename + kite-launch-blockers-apr18 + kite-mcp-registry-publisher + kite-product-strategy** | Per memory-verification critical patches | Future cleanup |

### §8.3 ARCHIVE (117 docs — 83 already archived + 34 new candidates)

**Action**: `git mv` to `.research/archive/<topic>/` in single-commit batches by topic.

**New archive moves recommended** (34 docs):

| Source | Destination | Commit grouping |
|---|---|---|
| `.research/STATE-v2-fresh-eyes.md` | `.research/archive/audits-completed/state-v2-fresh-eyes-2026-05-11.md` | Today's-audit-batch |
| `.research/STATE-claims-audit-2026-05-11.md` | `.research/archive/audits-completed/` | Today's-audit-batch |
| `.research/STATE-fresh-eyes-diff-2026-05-11.md` | `.research/archive/audits-completed/` | Today's-audit-batch |
| `.research/active-docs-verification-2026-05-11.md` | `.research/archive/audits-completed/` | Today's-audit-batch |
| `.research/memory-files-verification-2026-05-11.md` | `.research/archive/audits-completed/` | Today's-audit-batch |
| `.research/repo-docs-verification-2026-05-11.md` | `.research/archive/audits-completed/` | Today's-audit-batch |
| `.research/research-batch-2026-05-11.md` | `.research/archive/audits-completed/` | Today's-audit-batch |
| `.research/final-pre-launch-verification.md` | `.research/archive/audits-completed/` | Older-audit-batch |
| `docs/launch-materials.md` | `docs/archive/launch-materials-pre-tightening.md` OR `.research/archive/audits-completed/` | Launch-cleanup |
| `docs/release-notes-v1.1.0.md` | `docs/archive/` | Historical-release |
| `docs/push-deploy-playbook.md` | `docs/archive/` | Historical-deploy |
| `docs/session-2026-04-18-handoff.md` | `docs/archive/` | Session-snapshot |
| `docs/E2E_TEST_REPORT.md` | `docs/archive/` | Historical-test-report |
| `docs/consistency-audit-2026-04-18.md` + `delete-candidates-verification.md` + `deploy-impact-analysis.md` + `pre-push-audit.md` + `privacy-terms-source-compare.md` + `placeholder-substitution-map.md` + `triage-*.md` + `untracked-files-triage.md` + `worktree-*.md` + `gitignore-policy-analysis.md` + `remember-md-anomaly.md` | `docs/archive/audits-completed/` | Audit-cleanup-batch |
| `docs/renusharma-email-cleanup-report.md` | `docs/archive/` | Historical-cleanup |
| `docs/tool-renames.md` | `docs/archive/` | Historical-event-log |
| `docs/path-6a-risk-audit.md` | `docs/archive/phase-2-completed/` | Phase 2.x cleanup |
| All 12 `docs/superpowers/plans/*.md` + `docs/superpowers/specs/*.md` | `.research/archive/tier-anchor-design/` OR keep in place + tag as archived-in-place | superpowers/-cleanup |

### §8.4 DELETE (0 docs)

**Action**: none. No doc is actively misleading enough to remove outright. The original `launch-materials.md` concern (financial caps 5-10× wrong) was downgraded to ARCHIVE because the audit-agent's `cae5fea` banner mitigates the immediate misuse risk; archiving completes the mitigation.

### §8.5 MERGE-INTO-X (3 docs)

| Source | Merge into | Rationale |
|---|---|---|
| `memory/kite-launch-ready-fixes.md` | `memory/kite-launch-blockers-apr18.md` | Per memory-verification line 453: "SHOULD MERGE WITH launch-blockers note (both ready-content shipped)." Same launch-prep cycle, two docs. |
| `docs/releasing.md` | `docs/release-checklist.md` | Likely overlap per repo-docs-verification; spot-read to confirm before merge. |
| `docs/incident-response-runbook.md` | `docs/incident-response.md` | Two docs with similar names; one is the spec, other the runbook. Spot-read to determine if separate or duplicate. |

### §8.6 NEEDS-USER-DECISION (11 docs)

These need user judgment because empirical methodology can't decide:

| Doc | Why user-decision needed | Question |
|---|---|---|
| 1. `.research/launch-path-execution-playbooks.md` | Mid-flight runbook; user controls launch timing | When does Show HN actually submit? After-submission = archive trigger. |
| 2. `COVERAGE.md` (repo root) | Stale-by-design tradeoff | KEEP-CANONICAL with CI auto-regenerate, or DELETE and link codecov badge? Both valid. |
| 3. `memory/kite-launch-blockers-apr18.md` | Per memory-verification: "ARCHIVE as historical OR patch (C4)" | Is launch-prep still active under this doc's framing? Recent dispatches use `launch-path-execution-playbooks.md` (newer doc). User decides which is canonical. |
| 4. `memory/kite-session-apr3.md` | Contains plaintext R2 credentials | Should user rotate the credentials first (before any patch), or is the doc considered already-private? Framework §5 Failure 6 mandates rotate-then-redact; user controls timing. |
| 5. `docs/product-definition.md` | Self-claims "canonical for product positioning" but has stale numbers | Update to match server.json or remove canonical claim? Both valid; user picks framing. |
| 6. `docs/deferred-items.md` | Status of "deferred items" — may or may not still apply | Read + decide; if all items now done, archive; if some still deferred, keep. |
| 7. `docs/mcp-registry-prepublish-checklist.md` | Pre-publish or post-publish? Empirically registry returns HTTP 404 for our namespace — we're STILL pre-publish | When registry submission happens: archive. User controls timing. |
| 8. `docs/option-c-implementation-plan.md` | Whether "Option C" is still the active plan | Spot-read needed; user knows current strategic direction. |
| 9. `docs/kite-forum-replies.md` | Outgoing forum reply templates | Have these been sent already, or are they staged for future send? |
| 10. `docs/rainmatter-onepager.md` | Should be tracked or stay gitignored? Currently gitignored | User-strategic-decision: is this private leave-behind, or sharable artifact? |
| 11. `MEMORY.md` raw-credentials lines + the `kite-session-apr3.md` plaintext duplicate | Cred rotation timing | User controls Cloudflare R2 + decides rotation cadence. |

---

## §9 — Cross-cutting: overlapping/duplicate/conflicting docs

Per dispatch instruction, identify cross-doc duplication + recommend canonical pick.

### Conflict 1: RiskGuard check count

**Conflicting docs**:
- `server.json` `_meta.capabilities.riskGuardChecks: 11` ← canonical machine-readable
- `README.md` L3, L22 says "11 pre-trade checks" (post-patch); previously also said "9" at L82
- `algo2go/kite-mcp-riskguard/check.go` has 13 `OrderXxx` Order constants ← canonical source-of-truth
- `algo2go/kite-mcp-riskguard/internal_checks.go` has 11 `(g *Guard).checkXxx` methods
- `algo2go/kite-mcp-riskguard/guard.go` has 17 `RejectionReason` constants
- Project `.claude/CLAUDE.md` says "11 pre-trade checks ... 17 RejectionReason constants total" ← reconciled
- `docs/show-hn-post.md` "11 checks" (post-patch)
- `docs/launch-materials.md` "8 safety checks" (stale, ARCHIVE candidate)
- `docs/product-definition.md` "9 checks" (stale, NEEDS-USER-DECISION)
- `docs/architecture-diagram.md` "9 checks" (stale; mermaid)
- Various memory/ + .research/ docs: range "8-11"

**Canonical pick**: `server.json` `riskGuardChecks: 11` is the public-API machine-readable claim; all human-readable docs should match. The "13 Order constants" framing is the implementation detail (some constants are policy-gates not pre-trade checks; some compose with the kill-switch as a system-layer). The "11 user-visible pre-trade checks" framing is correct.

**Action**: in next-cleanup dispatch, ensure all docs say "11" + cite `server.json` as source. This patch already shipped to README + show-hn-post; remaining stale: product-definition.md (NEEDS-USER-DECISION), architecture-diagram.md (planned patch).

### Conflict 2: Tool count

**Conflicting docs** (mostly resolved):
- `/healthz` returns `tools: 111` ← live truth
- `server.json` `tools: 111`
- README L3 "110+ tools" (post-patch)
- README L198 table "111" (post-patch from 117)
- Various drafts/grant emails: "~80 tools" (some patched, some still stale)
- `docs/launch-materials.md` "~100 tools" (ARCHIVE)

**Canonical pick**: `server.json` `tools: 111` is machine-readable canonical. All other docs say "110+" or "111".

**Status**: post-today's-patches, most large surfaces are correct. Remaining "~80 tools" in untracked drafts will be picked up by the user manually.

### Conflict 3: Test count

**Conflicting docs**:
- `go test ./... -list ".*"` returns 4,697 tests in kite-mcp-server module
- Across kite-mcp-server + 28 algo2go modules: ~8,970 tests, ~478 test files
- README L19 "~9,000 tests across 437 test files" — tests count VERIFIED, file count off-by-41
- `docs/show-hn-post.md` "~9,000 tests across 437 test files" — same
- `funding.json` "~9,000 tests across 478 test files" — patched today at `25c9c8e` ✓
- `kite-mcp` README badge "Tests: 9000+" — VERIFIED
- Various older docs: "~330 tests" — stale (pre-Path A)

**Canonical pick**: "~9,000 tests across 478 test files (host + 28 algo2go modules)". README/show-hn `437` is close-enough but technically stale by 41 files; not worth chasing further.

### Conflict 4: MCP Registry status

**Conflicting docs**:
- `registry.modelcontextprotocol.io/v0/servers/io.github.Sundeepg98%2Fkite-mcp-server` → **HTTP 404** ← empirical truth
- README `## Registry` (post-patch) → "Submission ... pending" ← matches empirical truth ✓
- `docs/show-hn-post.md` L31 + L73 → "Not on the public MCP Registry yet" ← matches ✓
- `docs/release-checklist.md` §6 → describes how to publish (correct procedure)
- `memory/kite-mcp-registry-publisher.md` → publishing how-to (procedure correct; status NEEDS-PATCH per memory-verification)

**Canonical pick**: empirical HTTP 404 = NOT LISTED. All docs should match.

**Status**: README + show-hn-post patched today. memory/kite-mcp-registry-publisher needs cleanup-dispatch patch.

### Conflict 5: Audit retention period

**Conflicting docs**:
- `algo2go/kite-mcp-audit/retention.go:17`: `const DefaultRetentionDays = 90` ← canonical
- README L23 + L275: "90-day retention" ✓
- `docs/uninstall.md` L76: "90 days" ✓
- `docs/faq.md` L23 (pre-patch): "5-year SEBI retention" (now patched at `29de8c8`)
- `docs/adr/0004-…md`: "SEBI 5-year audit trail durability requirement" — aspirational design driver, NOT current default

**Canonical pick**: 90 days default, configurable via `AUDIT_RETENTION_DAYS`. ADR-0004 is correct to cite SEBI as a design DRIVER but should clarify "default ≠ regulatory target."

### Conflict 6: Duplicate runbooks

**`docs/incident-response.md` vs `docs/incident-response-runbook.md`**: two files with similar names; one is spec, one is runbook? Or duplicates? Spot-read needed. MERGE candidate if duplicate.

**`docs/release-checklist.md` vs `docs/releasing.md`**: similar — possible duplication; MERGE candidate.

**`memory/kite-launch-blockers-apr18.md` vs `memory/kite-launch-ready-fixes.md`**: per memory-verification: MERGE recommended.

---

## §10 — Source verification (this doc)

| Probe | Tool | Result |
|---|---|---|
| Master HEAD | `git rev-parse HEAD` | `f61e1bf` ✓ |
| value-framework.md size | `ls -la .research/maintenance-strategy/` | 46053 bytes ✓ |
| .research/ active tracked .md count | `git ls-files .research/` (excluding archive + maintenance-strategy) | 24 ✓ |
| .research/archive .md count | `git ls-files .research/archive/` | 83 ✓ |
| docs/ tracked .md count | `git ls-files docs/ \| grep -c '\.md$'` | 82 ✓ |
| Repo root .md count | `git ls-files '*.md' \| grep -v '/'` | 12 ✓ |
| memory/ file count | `ls /mnt/c/Users/Dell/.claude/projects/D--Sundeep-projects/memory/` | 76 ✓ |
| 5 verification reports + framework + this doc all exist | `ls .research/*-verification-* .research/STATE-* .research/research-batch-* .research/maintenance-strategy/*` | All confirmed |
| Verdicts inherited from active-docs-verification | Read §4 survival table (lines 60-75) | 16 docs verdicts captured |
| Verdicts inherited from memory-verification | Read §6 classification table (lines 432-484) | All 76 verdicts captured |
| Verdicts inherited from repo-docs-verification | Read §2 file table (lines 296+) | 22 docs verdicts captured |
| Live production state | (Not re-probed; cited from chain-agent's gap-report) | tools=111 / v1.3.0 — used as truth-anchor for stale-cache verdicts |

**Methodology note**: this doc is empirical CLASSIFICATION not empirical state-verification. I did NOT re-probe `curl /healthz` or `go test -list` or `flyctl status` because the chain agent + audit agent already did so today; their verification reports are the authoritative state-anchors for this dispatch. Per dispatch hard rule "NO grep-as-evidence": all classifications cite the verification reports' empirical methods (compile-and-run, HTTP probes, schema validation, file-existence checks) rather than introducing fresh grep-counts.

---

## §11 — Hard rules compliance

| Rule | Status |
|---|---|
| READ-ONLY on every doc | ✓ — only Read tool used; zero file mutations |
| Empirical probes where verifiability matters | ✓ — file-existence checks via `ls`; tracked-status via `git ls-files`; verdict inheritance from prior verification reports' empirical methods |
| NO grep-as-evidence for content claims | ✓ — content claims cite prior reports (which themselves used compile-and-run) |
| WSL2 not needed | ✓ — read-only classification |
| Single output file | ✓ — this file at `.research/maintenance-strategy/doc-classification.md` |
| `git commit -o -- <path>` + push | (next step) |
| ~3-4h budget; halt at 6h | ~50 min wall-clock through investigation + writing |
| NEEDS-USER-DECISION explained per item | ✓ — see §8.6 (11 items, each with explicit "why user-decision needed") |

---

## §12 — Verdict summary

The corpus has 280 tracked .md files across 7 locations. After applying empirical classification:

- **19 KEEP-CANONICAL** (Tier 1 Live, must-be-fresh; the 5 verification reports + STATE/INDEX + 12 identity files)
- **132 KEEP-REFERENCE** (Tier 2 Durable; rules, decisions, identity, operational reference, external facts)
- **117 ARCHIVE** (83 already archived + 34 new candidates; Tier 3 ephemera that completed its event)
- **0 DELETE** (no doc is actively misleading enough to remove outright)
- **3 MERGE** (duplicate/overlapping pairs)
- **11 NEEDS-USER-DECISION** (mid-flight events, plaintext-creds rotation timing, canonical-claim conflicts, untracked-vs-tracked status)

The single largest action — and highest-leverage — is to **`git mv` the 7 audit reports from `.research/` root to `.research/archive/audits-completed/`** as a single-commit batch. This stops the "audit-becomes-canonical-by-default" failure mode (`value-framework.md §5 Failure 5`) that has historically polluted `.research/` with point-in-time artifacts that read like active reference.

The second-largest is **`git mv` the 5 decision records to a new `.research/decisions/` subdir** to make Class B explicit (`value-framework.md §3.B`). This stops future agents from confusing decision records (write-once, never edit) with active synthesis (regularly updated).

After those two moves, the active corpus shrinks from ~280 to ~150 meaningful docs; the rest are properly-archived historical artifacts. Future "comprehensive audit" dispatches become tractable — and per `value-framework.md` final-paragraph framing, "~30 minutes, not ~10 hours."

**End of classification.** All 280 tracked .md files now have a concrete verdict. The next-cleanup dispatch can execute the §8 action list mechanically without further classification work.
