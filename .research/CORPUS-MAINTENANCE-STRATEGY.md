# Corpus Maintenance Strategy — Canonical

**Date**: 2026-05-11 IST
**Master HEAD audited**: `2767143` (`docs(maintenance): per-doc classification — KEEP/ARCHIVE/DELETE/MERGE/USER-DECIDE verdicts`)
**Charter**: SINGLE user-facing strategy. Synthesizes three parallel inputs:
- `maintenance-strategy/value-framework.md` (`f61e1bf`, 541 lines) — 7 doc classes, 5 value tests, principles
- `maintenance-strategy/maintenance-model.md` (`7c24ce0`, 782 lines) — 4-owner stewardship matrix, 8 validator hooks, roadmap
- `maintenance-strategy/doc-classification.md` (`2767143`, 656 lines) — 280 tracked .md files verdict table
**Purpose**: user reads this single doc and knows (a) who maintains what, (b) which 11 decisions need user attention, (c) the ordered roadmap, (d) the 3 highest-leverage immediate actions to authorize now.

---

# §1 — Answer to the central question: who maintains the corpus?

The user asked: "should you (orchestrator/agents) keep it, or should I (user)?" **Answer: HYBRID with explicit boundaries.** Four owner-types, each owns a specific class of work:

| Owner | What they own | Why this owner |
|---|---|---|
| **USER** | Rules + Sensitive (secrets, costs, identity) + Final-decisions | High-judgment, low-frequency. User-rule authorship can only be done by the user; secret rotation, regulatory decisions, brand/identity calls cannot be delegated |
| **ORCHESTRATOR** | Cross-agent coordination + queue-reading + dispatch routing | In-session, medium-judgment. Knows which agent should do what; doesn't execute substantive work itself (per `user_agent_orchestration_rule.md`) |
| **AGENT** (sub-agents) | Research, verification, mechanical execution, decision-record authoring | Bounded task, can run probes, write decision records, regenerate indices |
| **HOOK** (automation) | Structural enforcement (no secrets, no missing frontmatter, no broken cross-refs) + read-time freshness surfacing | Zero-judgment, always-on; runs at write-time (blocks bad commits) or session-start (surfaces staleness) |

**The explicit boundary** that resolves the orchestrator-vs-probe tension (surfaced in value-framework §7):

- USER **does not** run grep, probe state, or maintain indices manually. User writes rules; approves archives; rotates secrets; makes regulatory/identity decisions.
- ORCHESTRATOR **reads** the queue (e.g., `.research/staleness-queue.md`) that HOOK + sub-agent produce; routes dispatches; never runs the probes itself.
- AGENT **runs** the probes (at SessionStart via a freshness-check sub-agent that the H2 hook enqueues); writes decision records; regenerates indices; executes `git mv` for archives.
- HOOK **enforces** at write-time (blocks commits with secret patterns, missing frontmatter, broken cross-refs); **surfaces** at read-time (staleness queue at session-start).

**Single-sentence answer**: USER owns judgment + identity + sensitive; HOOKS own enforcement; AGENTS own execution; ORCHESTRATOR owns coordination. Nobody owns "the corpus" — each location has a specific steward per the matrix in maintenance-model §1.

---

# §2 — The 3-tier collapse

The current corpus is 280 tracked .md files across 7 locations. Chain's empirical classification maps to value-framework's 3 tiers as follows:

| Tier | Definition | Current count | Examples |
|---|---|---|---|
| **Tier 1 — Live** (must-be-fresh) | Single source-of-truth pointers; weekly probe refresh | **19 docs** (7%) | STATE.md, INDEX.md, agent-domain-map.md, value-framework.md, doc-classification.md, maintenance-model.md, README.md, SECURITY.md, ARCHITECTURE.md, THREAT_MODEL.md, MEMORY.md, project/user CLAUDE.md, tool-catalog.md, architecture-diagram.md, product-definition.md, docs/show-hn-post.md |
| **Tier 2 — Durable** (rules + decisions + identity + ops) | Write-once or supersede-only; long-shelf-life | **132 docs** (47%) | All 28 `memory/user_*` + `memory/feedback_*` rules; 33 `memory/kite-*` external-fact caches; ADRs 0001-0010; runbooks (incident-response, operator-playbook, dr-drill, rotate-key); decision records (R-10 v8, path-e, production-master-gap); session snapshots |
| **Tier 3 — Ephemeral** (write-once, archive-on-event) | Date-bound; archive when event completes | **117 docs** (42%) | **83 already archived** + 34 candidates: today's 7 audit reports, 12 superpowers/ shipped-feature specs, 13 worktree-cleanup-era triage docs, 5 launch-cycle drafts, point-in-time verification reports |

**0 DELETE** — nothing is actively misleading enough to remove outright. Where stale content was a launch risk (`docs/launch-materials.md` financial caps 5-10× wrong), audit-agent's banner mitigates immediate misuse; archiving completes the mitigation.

**3 MERGE pairs** flagged: `memory/kite-launch-ready-fixes.md` → `kite-launch-blockers-apr18.md`; `docs/releasing.md` → `release-checklist.md`; `docs/incident-response-runbook.md` ↔ `incident-response.md` (verify before merge).

**11 NEEDS-USER-DECISION** — see §4.

---

# §3 — The principle stack

Four principles, each with concrete evidence from this session:

## Principle 1 — Re-derivability

**Rule**: if a fact can be re-derived from code/git/external-probe in <5 minutes, it's NOT load-bearing — it's a CACHE. Caches go stale silently. Move truth into the probe; doc records the probe command, not the answer.

**This session's evidence**: `STATE.md 1e80930` cached `tools=130 in-tree` from `grep mcp.NewTool( mcp/` which over-counted 19 `_test.go` fixtures. 4 downstream synthesis docs inherited the bad number. Cost: ~6h misdirected research. **Caught only when chain-agent ran compile-and-run** (the actual probe). After patch (`bea1e11`): tools=111 in production AND master-built binary, matching `/healthz` and `server.json`.

**Action**: INDEX.md §11 already implements this pattern (probe column for every load-bearing fact). Extend to STATE.md §1.1 row-by-row.

## Principle 2 — Decision-recorded

**Rule**: docs that capture WHY a path was chosen (preconditions, alternatives, falsifications) ARE durable. Docs that capture WHAT is currently true are caches subject to Principle 1.

**This session's evidence**: `path-e-try-before-buy-results.md` captures Track 1 Turso success + Track 2 DO BLR1 payment-method-gated falsification. Decision-stamped 2026-05-10; truth doesn't decay because it's "what we believed at write-time + the empirical evidence behind it." All 3 verification dispatches today verified this doc "survives unchanged."

R-10 v1→v8 series is the canonical multi-version decision chain: each version captures beliefs at that time + falsifications from the next round; v8 supersedes v7 explicitly. Even superseded versions retain audit value.

**Action**: create `.research/decisions/<topic>/v*-current.md` subdir convention. Migrate the 5 decision records currently in `.research/` root.

## Principle 3 — Authority gradient

**Rule**: every fact has an authority source. Doc's job = point to authority, not BE authority. When doc IS authority (rules, design decisions, narrative judgment), make that explicit.

**This session's evidence**: `server.json` ships `tools: 111` and `riskGuardChecks: 11` as machine-readable canonical. It IS the authority — `/healthz` reads from the same source. But ~12 docs had stale tool counts because each cached the value inline rather than referencing server.json. README L198 said "117 tools"; product-definition said "~80"; launch-materials said "~100"; show-hn-post said "110+"; all stale-by-different-amounts because they were caches of caches.

**Action**: in human-readable docs that quote numeric facts, cite server.json explicitly (`per server.json`); add CI build-time grep for cross-section numeric inconsistencies (hook H8 in maintenance-model §4).

## Principle 4 — One-fact-one-location

**Rule**: every load-bearing fact lives in EXACTLY ONE place. Synthesis docs cite the location; never cache values inline.

**This session's evidence**: tool count was cached in 12 different docs (README L3 + L198, product-definition, launch-materials, show-hn-post, twitter-thread, reddit-post, forward-tracks, launch-playbooks, 10000-agent, agent-domain-map, phase-2-6 v8 §2.1, plus various drafts). Each cache drifted independently. Patching took ~30 distinct edits across ~10 commits. **If the fact had lived in one place (server.json) + all docs cited it, this session's "tools=130 saga" wouldn't have happened**.

**Action**: Phase 5 of the roadmap (corpus migration) enforces this — synthesis docs gain INPUTS sections; numeric facts cite server.json; identity docs cite themselves as authority and other docs cite them.

---

# §4 — The 11 NEEDS-USER-DECISION items

These cannot be classified empirically. User input resolves each:

| # | Question | What user input resolves it | Default if user skips |
|---|---|---|---|
| 1 | **Approve dr-drill secret rotation in `memory/kite-session-apr3.md`?** Plaintext R2 credentials are in this doc. Rotate first, then patch. | User initiates Cloudflare R2 token rotation (cannot be delegated). | If skipped: doc retains plaintext but flagged for future cleanup. **NOT recommended** — exposure risk persists. |
| 2 | **Approve dr-drill secret rotation in `MEMORY.md` lines 70-72?** Kite API key/secret pairs cached inline. | Same — rotate Kite Connect app credentials (only user has Zerodha dashboard access). | If skipped: same exposure pattern. |
| 3 | **`memory/kite-launch-blockers-apr18.md`: ARCHIVE or PATCH?** Per memory-verification §4: "ARCHIVE as historical OR patch (C4)." Newer doc `launch-path-execution-playbooks.md` supersedes most content. | User decides if Apr-18 framing is still active OR fully superseded. | Default: ARCHIVE (newer doc is canonical). |
| 4 | **`COVERAGE.md` at repo root: KEEP with CI auto-regenerate OR DELETE + link codecov badge?** Both valid. | User's preference for CI-generated artifacts in repo. | Default: DELETE + link badge (less repo-noise). |
| 5 | **`docs/product-definition.md` self-claims "canonical"** but has stale "~80 tools / 9 checks". Update to server.json OR drop canonical claim? | User picks: is this canonical product positioning OR was the claim aspirational? | Default: drop canonical claim; keep as Class F narrative. |
| 6 | **`docs/deferred-items.md`**: archive or keep tracking? | User confirms if items listed are still deferred. | Default: spot-read, archive if all items shipped. |
| 7 | **`docs/mcp-registry-prepublish-checklist.md`**: keep until registry-listing? Empirically registry returns HTTP 404 for our namespace — still pre-publish. | User confirms registry submission timing. | Default: KEEP-REFERENCE until empirically listed; auto-archive on first 200 response. |
| 8 | **`docs/option-c-implementation-plan.md`**: still active plan? | User confirms strategic direction. | Default: archive (Phase 2.6 closure superseded Phase 2.x option-C planning). |
| 9 | **`docs/kite-forum-replies.md`**: sent already or staged for future? | User confirms send status. | Default: KEEP-REFERENCE (templates remain useful). |
| 10 | **`docs/rainmatter-onepager.md`**: track or stay gitignored? | User's strategic call: private leave-behind vs sharable artifact. | Default: stay gitignored (private outreach material). |
| 11 | **`launch-path-execution-playbooks.md`**: when does Show HN actually submit? After-submission = archive trigger. | User picks launch date OR signals "deferred." | Default: KEEP-REFERENCE in active `.research/` until launch event triggers archive. |

**Items 1+2 are time-sensitive** (plaintext credentials in repo-adjacent docs). Recommended user-action: rotate Cloudflare R2 + Kite API credentials this week, then dispatch an agent to patch the docs.

**Items 3-11 are low-urgency** and can be batched into a single dispatch where the user signals their preferences and an agent executes the archives/patches.

---

# §5 — The 6 cross-cutting conflicts — resolved

Chain's §9 surfaced 6 cases where docs disagree. Resolutions (with canonical authority):

| Conflict | Canonical truth + authority | Action |
|---|---|---|
| **RiskGuard check count** (9 vs 11 vs 12 vs 13 vs 17 across docs) | **11 user-facing pre-trade checks** per `server.json` `riskGuardChecks: 11` + project `.claude/CLAUDE.md` reconciliation. Implementation has 17 `RejectionReason` constants total (system-rejection layers + 11 pre-trade); the "13 OrderXxx constants" framing is implementation-detail. | All docs cite `server.json`. Already patched: README, show-hn-post, .claude/CLAUDE.md. Remaining: product-definition (NEEDS-USER-DECISION §4 #5), architecture-diagram.md. |
| **Tool count** (80 vs 100 vs 111 vs 117 vs 130 across docs) | **111** per `/healthz` (live truth) + `server.json` `tools: 111` + master-built compile-and-run `total_available=111`. The "130" was a grep over `mcp/` that included 19 test fixtures. | Already patched in major surfaces. Remaining: untracked drafts user picks up manually. |
| **Test count** (~330 vs ~9,000 vs 4,697 vs 8,970 across docs) | **~9,000 tests across 478 test files** (kite-mcp-server host + 28 algo2go modules). README + show-hn-post say "437 files" — close-enough; not worth chasing. funding.json patched today at `25c9c8e` to 478. | Action: future patches use "~9,000 tests across 478 test files." |
| **MCP Registry status** (LISTED vs NOT LISTED) | **NOT LISTED** — empirical: `curl registry.modelcontextprotocol.io/v0/servers/io.github.Sundeepg98%2Fkite-mcp-server` returns **HTTP 404**. | README + show-hn-post matched ("Submission pending"). Remaining: `memory/kite-mcp-registry-publisher.md` needs cleanup-dispatch patch. |
| **Audit retention** (90d vs 5y across docs) | **90 days default** per `algo2go/kite-mcp-audit/retention.go:17 DefaultRetentionDays = 90`, configurable via `AUDIT_RETENTION_DAYS`. The "5y SEBI" framing in ADR-0004 is **aspirational design driver**, not current behavior. | Already patched at `29de8c8` in `docs/faq.md`. ADR-0004 needs clarification "default ≠ regulatory target" but not urgent. |
| **3 duplicate runbook pairs** | (1) `memory/kite-launch-ready-fixes.md` + `kite-launch-blockers-apr18.md` — MERGE per memory-verification. (2) `docs/releasing.md` + `release-checklist.md` — spot-read; likely MERGE. (3) `docs/incident-response.md` + `incident-response-runbook.md` — verify before merge; one may be spec + other runbook. | Action: spot-read each pair; merge or differentiate via header. ~30min agent dispatch. |

---

# §6 — Implementation roadmap (5 phases)

Concrete order-of-operations from current state to maintenance-model-compliant. Phases independently shippable.

## Phase 1 — Critical hooks (4-6h, this week) — **KILLS 3 WORST FAILURE MODES**

| Step | Action | Effort | Owner |
|---|---|---|---|
| 1.1 | Write `validators/pre-write-secret-scan.py` (H1) — fail-CLOSED secret scanner | ~1h | AGENT |
| 1.2 | Wire H1 into `~/.claude/settings.json` PreToolUse matcher `Write\|Edit\|MultiEdit` | ~15min | USER (settings edit) |
| 1.3 | Test H1 against known-secret memory file content | ~30min | AGENT |
| 1.4 | Write `validators/session-start-freshness-check.py` (H2) — enqueue freshness task | ~1h | AGENT |
| 1.5 | Wire H2 into SessionStart | ~15min | USER |
| 1.6 | Document sub-agent dispatch pattern H2 prompts | ~30min | AGENT |
| 1.7 | Write `validators/pre-write-frontmatter-validator.py` (H3) | ~30min | AGENT |
| 1.8 | Wire H3 for `memory/kite-*.md` writes | ~15min | USER |
| 1.9 | Backfill `as-of` + `re-verify-by` frontmatter on existing 33 `memory/kite-*.md` files | ~2h | AGENT (one dispatch) |

**Phase 1 delivers**: secrets cannot be written; staleness surfaced at session-start; external-fact caches enforce frontmatter. **Kills failure modes F1 (grep-error), F2 (stale caches), F6 (plaintext secrets)** from maintenance-model §3.

## Phase 2 — New user-rules (~1-2h)

| Step | Action | Effort | Owner |
|---|---|---|---|
| 2.1 | Write `feedback_compile_and_run_methodology.md` user-rule | ~30min | USER (or USER-approved AGENT draft) |
| 2.2 | Write `feedback_verify_before_synthesize.md` (synthesis inputs must be re-verified) | ~30min | USER |
| 2.3 | Write `feedback_dated_synthesis.md` (synthesis docs must have INPUTS section with dates) | ~30min | USER |
| 2.4 | Write `feedback_empirical_probe_reference.md` (use INDEX §11 probes for state questions) | ~30min | USER |
| 2.5 | Update MEMORY.md User Rules with links | ~10min | HOOK (H6) auto-regenerates after Phase 3 |

**Phase 2 delivers**: 4 standing rules realized as rule files; future agents inherit them.

**Phase 2 also resolves the Audit §7 contradiction** (orchestrator-vs-probe): rule 2.4 codifies "use INDEX §11 probes" as the standard; H2 hook enqueues a sub-agent at session-start to run them; orchestrator reads the queue (which IS allowed under existing orchestrator-rule's "single-line health check" exception).

## Phase 3 — Medium hooks + memory-MD auto-regen (~3-4h)

| Step | Action | Effort | Owner |
|---|---|---|---|
| 3.1 | Write H6 `post-tool-memory-md-regen.py` | ~1h | AGENT |
| 3.2 | Wire H6 into PostToolUse | ~15min | USER |
| 3.3 | Manually verify MEMORY.md regen | ~30min | USER |
| 3.4 | Write H4 `pre-write-cross-ref-validator.py` | ~1h | AGENT |
| 3.5 | Wire H4 | ~15min | USER |
| 3.6 | Write H5 `post-tool-grep-trap.py` | ~45min | AGENT |
| 3.7 | Wire H5 PostToolUse on Bash | ~15min | USER |

**Phase 3 delivers**: MEMORY.md no longer hand-curated; cross-refs validated at write-time; grep-traps caught at use-time. **Kills F3 (line-limit), F4 (multi-version), F8 (dead refs), F9-F10 (number drift).**

## Phase 4 — Archive automation + numeric consistency (~2-3h)

| Step | Action | Effort | Owner |
|---|---|---|---|
| 4.1 | Write H7 `audit-auto-archive.py` | ~1h | AGENT |
| 4.2 | Wire H7 SessionStart with daily-throttle | ~30min | AGENT |
| 4.3 | Create `.research/audits/2026-05-11/` subdir + `git mv` today's 7 verification reports | ~1h | AGENT (one dispatch) |
| 4.4 | Write H8 `pre-write-numeric-consistency.py` | ~45min | AGENT |
| 4.5 | Wire H8 | ~15min | USER |

**Phase 4 delivers**: verification reports auto-archive; numeric drift caught at write-time.

## Phase 5 — Corpus migration per Chain's §8 action list (~6-8h, gradual)

| Step | Action | Effort | Owner |
|---|---|---|---|
| 5.1 | Create `.research/decisions/` subdir; `git mv` 5 decision records (R-10 v8, path-e, production-master-gap, dr-drill-results, rotate-key-runbook) | ~1h | AGENT |
| 5.2 | Add `INPUTS` sections to active Class F synthesis docs | ~2h | AGENT |
| 5.3 | Rename ephemera with date-in-filename | ~1h | AGENT |
| 5.4 | Resolve 11 NEEDS-USER-DECISION items via dispatch (after user signals preferences) | ~2h | AGENT |
| 5.5 | Update `.claude/CLAUDE.md` (repo) with methodology rule (compile-and-run > grep) | ~15min | USER |
| 5.6 | Update project-level `D:\Sundeep\projects\.claude\CLAUDE.md` if cross-repo guidance changes | ~15min | USER |

**Phase 5 delivers**: corpus is in maintenance-model-compliant shape.

---

# §7 — Three highest-leverage immediate actions

Per Chain's §0 + §12: three actions that, if authorized today, deliver disproportionate value. Each is agent-doable in ~30min with user authorization:

## Action 1 — `git mv` today's 7 audit reports to `.research/archive/audits-completed/`

**Why**: today's 7 audit reports (active-docs-verification, STATE-claims-audit, STATE-fresh-eyes-diff, STATE-v2-fresh-eyes, memory-files-verification, repo-docs-verification, research-batch) live in `.research/` root as if active reference. They're Tier 3 ephemera (date-bound). Leaving them in `.research/` root is the canonical failure mode F5 ("audit-becomes-canonical-by-default").

**Action**: single agent dispatch (~30min) — create `.research/archive/audits-completed/` (already exists), `git mv` each report with date-in-filename, single commit `chore(archive): move 2026-05-11 audit reports`, push.

**Authorizes**: user signals "yes." Agent does the rest.

## Action 2 — Create `.research/decisions/` subdir + `git mv` 5 decision records

**Why**: 5 decision records currently in `.research/` root would be confused with active synthesis by future agents:
- `phase-2-6-r10-decisions.md` → `decisions/phase-2-6/v8-closure.md`
- `path-e-try-before-buy-results.md` → `decisions/path-e-results.md`
- `production-master-gap-report.md` → `decisions/production-master-gap-2026-05-11.md`
- `dr-drill-results-2026-05-11.md` → `decisions/dr-drill-2026-05-11.md`
- `rotate-key-runbook-2026-05-11.md` → `decisions/rotate-key-runbook.md`

Class B decision records (write-once, supersede-only) deserve their own subdir per value-framework §3.B + maintenance-model §1.

**Action**: agent dispatch (~30min) — create subdir, `git mv` each file, update STATE.md §6 cross-references, single commit, push.

**Authorizes**: user signals "yes."

## Action 3 — Ship Phase 1 hooks (H1 + H2 + H3) — the OS foundation

**Why**: these 3 hooks structurally prevent the 3 worst failure modes (grep-error contamination, stale external caches, plaintext secrets). Each subsequent dispatch becomes faster + safer. Investment: ~4-6h. Payback: 1 audit cycle (~10h saved next time).

**Action**: agent dispatch writes H1 + H2 + H3 (~3h of agent work); user wires settings.json (~45min); single backfill dispatch adds frontmatter to 33 `memory/kite-*.md` files (~2h agent work).

**Authorizes**: user signals "yes" + accepts H1 fail-CLOSED behavior (blocks any write with secret pattern; user must redact + retry).

---

# §8 — Cost projection

| Scenario | Cost per "comprehensive audit" cycle | Annual cost (assuming 4 cycles/year) |
|---|---|---|
| **Status quo** (this session) | **~10h** of orchestrator + agent work to find + patch drift | ~40h/year |
| **After Phase 1+2** (~6h investment) | <2h per cycle (drift caught structurally before propagation) | ~8h/year |
| **Net savings** | ~8h per cycle | **~32h/year recovered** |

**Investment payback: 1 audit cycle.**

The math: this session's drift-cleanup ran ~10h across orchestrator + agents. If the H1+H2+H3 hooks had existed at start-of-session, secrets wouldn't have been writable into memory files (F6), staleness would have been surfaced at session-start as a queue rather than discovered via 5 verification dispatches (F2+F11), and the methodology rule preventing grep-error contamination (F1) would have been visible to the original STATE.md author.

Phase 3-5 (~9h additional investment) deliver further structural automation. The total ~14h investment recovers itself after ~2 audit cycles. After year 1, the maintenance OS pays back 2-3× annually.

---

# §9 — Open questions for user

Decisions only the user can make. Listed in order of urgency:

1. **Approve Phase 1+2 implementation start?**
   - Phase 1: write H1+H2+H3 hooks + frontmatter backfill (~4-6h agent work + ~1h user wiring)
   - Phase 2: write 4 new user-rules (~1-2h, mostly user authorship)
   - Net effect: closes 3 worst failure modes; sets methodology rules for future synthesis
   - **Default if user defers**: no rush; this session ends with manual cleanup; next "comprehensive audit" cycle takes another ~10h.

2. **Resolve Audit §7 contradiction (orchestrator-vs-probe)?**
   - Option A: amend `user_agent_orchestration_rule.md` to explicitly include "INDEX §11 probes at session-start" as orientation
   - Option B: adopt H2 freshness-check sub-agent pattern (orchestrator reads queue; sub-agent does probes); preserves orchestrator-only rule unchanged
   - **Recommendation**: Option B (per maintenance-model §1 resolution); user confirms.

3. **Accept H1 fail-CLOSED behavior?**
   - H1 blocks ANY write containing secret patterns (AWS keys, Stripe keys, GitHub tokens, Cloudflare tokens, ≥32-char hex strings)
   - Trade-off: false positives possible (a long hex string in a documentation example would be blocked); user must redact + retry
   - **Default**: accept; the cost of false positives << the cost of leaked secrets (the plaintext credentials currently in `MEMORY.md` + `kite-session-apr3.md` exist BECAUSE no such hook existed).

4. **Approve `git mv` migrations** for new subdirs `.research/audits/` and `.research/decisions/`?
   - Action 1 + Action 2 from §7 above
   - Each is single-commit + single agent dispatch
   - **Default**: approve both; reversible via git revert if needed.

5. **Decide on the 11 NEEDS-USER-DECISION items** (§4)?
   - Most can be batched into a single dispatch
   - Items 1+2 are time-sensitive (plaintext credential rotation)
   - Items 3-11 are low-urgency
   - **Default if deferred**: each item's "Default" column in §4 table represents the orchestrator's recommendation if user wants to skip.

6. **Approve the 4 new user-rules drafted in Phase 2.1-2.4?**
   - The orchestrator can draft each rule for user approval; final wording is user's prerogative.
   - **Default**: orchestrator drafts; user reviews + commits.

---

# §10 — How to use this strategy

**This single doc** is the canonical strategy. The three input docs become reference-only after this synthesis lands.

**Lookup paths**:
- "Who owns X?" → §1 (4-owner taxonomy) + maintenance-model §1 (stewardship matrix per location)
- "Should this doc be archived?" → §2 (3-tier classification) + doc-classification §8 (concrete action list)
- "Why is this principle important?" → §3 (with concrete this-session evidence)
- "What decisions does the user need to make?" → §4 (11 items) + §9 (6 open questions)
- "What's the next concrete action?" → §7 (3 highest-leverage immediate actions)
- "What's the full roadmap?" → §6 (5 phases, each independently shippable)

**Reading order for orientation**:
1. §1 (1 page) — the answer to the central question
2. §7 (1 page) — 3 actions to authorize right now
3. §9 (1 page) — decisions only the user can make
4. §6 (2 pages) — full roadmap if user wants the long view

**Reading order if returning to this doc in 1+ month** (after maintenance OS partially shipped):
1. §6 (which phases shipped? what's next?)
2. §4 (which NEEDS-USER-DECISION items resolved? which remain?)
3. §5 (have any new cross-cutting conflicts emerged?)

---

# §11 — Source verification

| Probe | Tool | Result |
|---|---|---|
| Master HEAD | `git log -1` | `2767143 docs(maintenance): per-doc classification` ✓ |
| value-framework.md | Read in full (541 lines) | absorbed 7 doc classes + 5 value tests + 3-tier model + 4 stewardship principles + 7 failure modes + §7 contradiction surface |
| maintenance-model.md | Read in full (782 lines) | absorbed 4-owner taxonomy + stewardship matrix (17 corpus locations) + 8 hook designs + 5-phase roadmap + cost analysis + Audit §7 contradiction resolution |
| doc-classification.md | Read in full (656 lines) | absorbed 280-doc verdict table + 6 cross-cutting conflicts + §8 concrete action list + §8.6 11 NEEDS-USER-DECISION items |
| Live production state | (cited from inputs; not re-probed) | tools=111 / v1.3.0 / 28 algo2go modules — used as truth-anchor |

**Methodology rule applied**: NO grep-as-evidence for any state claim. All numeric counts cited from inputs which themselves used compile-and-run / curl /healthz / file-existence checks. The 3 inputs serve as truth-anchors; this synthesis adds prioritization + decision-aid + user-facing condensation.

**Hard rules compliance**:
- READ-ONLY on the 3 input docs ✓ (no modifications)
- Aggressive compression ✓ (~470 lines vs 1,979 input lines = 4× compression while preserving decision-relevant content)
- Cite sources by section reference ✓
- Single output: `.research/CORPUS-MAINTENANCE-STRATEGY.md` ✓
- Don't reproduce verbatim ✓ (synthesis-not-summary throughout)

---

# §12 — Closing

The corpus accumulated organically. The result works in single-session bursts but rots between sessions because no maintenance OS exists. Three parallel dispatches today (value-framework + maintenance-model + doc-classification) named the structure that was hiding: 3 tiers, 7 doc classes, 4 owner types, 8 automation hooks, 280-doc verdict table, 11 user-decisions, 6 cross-cutting conflicts, 5-phase roadmap.

**The single most important takeaway**: the corpus stays healthy if the OPERATING SYSTEM around it does three things — **blocks at write-time** what cannot be safely written (H1+H3); **surfaces at read-time** what has drifted since last verified (H2 freshness queue); **auto-mechanizes** the regen + archive flows that don't need judgment (H6+H7). These three structural mechanisms — ~6h to ship Phase 1+2 — recover ~32h/year of maintenance load. **Investment payback: 1 audit cycle.**

The user owns judgment + identity + sensitive. Hooks own enforcement. Agents own execution. Orchestrator owns coordination. Nobody owns "the corpus" — each location has its specific steward. After today's three audit dispatches + this synthesis, the project has a coherent maintenance model. **The remaining question is whether to ship Phase 1 this week or defer.**
