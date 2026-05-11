# Maintenance Strategy: Value Framework

**Date**: 2026-05-11 IST
**Master HEAD audited**: `25c9c8e` (`docs(funding): bump to FLOSS/fund schema v1.1.0 + update description`)
**Dispatch role**: 1 of 3 parallel — **strategic framework** (this doc) + per-doc classification (chain agent) + ownership/automation (path-a-owner)
**Charter**: derive abstract criteria for long-term corpus value, lifecycle stages per doc class, and stewardship principles. NOT per-doc classification; NOT process discipline. Principles abstract enough to apply to the NEXT 5 months of accumulation.

**Grounding inputs** (read in full):
- `STATE.md`, `INDEX.md` (canonical state + question-keyed lookup)
- 5 verification reports (`active-docs-verification`, `STATE-claims-audit`, `STATE-fresh-eyes-diff`, `memory-files-verification`, `repo-docs-verification`)
- `research-batch-2026-05-11.md` (14-question synthesis)
- Sample of `memory/` rule files (`user_agent_orchestration_rule.md`, `user_email_rule.md`, `feedback_research_diminishing_returns.md`, `feedback_research_vs_empirical_grounding.md`)

**Concurrency**: chain agent classifying every doc as KEEP-CANONICAL/REFERENCE/ARCHIVE/DELETE in parallel; path-a-owner designing ownership-model + automation hooks. All three outputs deliberately disjoint by abstraction layer.

---

## TL;DR — three principles + one structural recommendation

1. **PRINCIPLE OF RE-DERIVABILITY**: a doc that captures a fact re-derivable from code/git/external-probe in <5min is NOT load-bearing. It's a cache. Caches go stale silently. Move the truth into the probe; let the doc record the probe command, not the answer.

2. **PRINCIPLE OF DECISION-RECORDED**: a doc that captures WHY a path was chosen (preconditions, alternatives considered, falsifications) IS load-bearing. It's the audit trail decisions reference. Decision records don't decay because their truth is "what we believed at write-time" not "what's true now."

3. **PRINCIPLE OF AUTHORITY GRADIENT**: every fact has an authority source. The doc's job is to point to authority, not to BE authority. When the doc IS authority (rules, design decisions, narrative judgment), make that explicit; otherwise, the doc is a cache and §1 applies.

4. **STRUCTURAL RECOMMENDATION**: collapse the 5-location corpus (`.research/active`, `.research/archive`, `memory/`, `MEMORY.md`, repo `docs/`) into **3 tiers by mutation cadence + stewardship**:
   - **Tier 1 — Live (high-mutation, must-be-fresh)**: STATE.md + INDEX.md + 1-2 active synthesis docs. In repo `.research/`. Verified weekly. Decay-safe by §1 (point to probes).
   - **Tier 2 — Rules + Decisions (low-mutation, durable)**: user rules + feedback rules + Decision Records (R-10 v8 closures, Phase 2.6 closure framework, etc). In `memory/` (rules) + `.research/decisions/` (decision records — NEW subdir recommended).
   - **Tier 3 — Drafts + Snapshots (write-once, archive-once)**: launch material drafts, session snapshots, point-in-time audits, verification reports. Written, used for one purpose, then ARCHIVED-on-completion (not just left-to-decay).

Everything else either belongs in code (probes, runbooks-as-scripts), in code COMMENTS (operational notes near the code they describe), or shouldn't be persisted at all.

---

# §1 — Taxonomy of doc classes

Across the 5-location corpus (~100+ docs accumulated this session + prior), seven distinct classes by their relationship to truth:

## Class A — Canonical State (single-source-of-truth, must-be-fresh)

**Examples**: `STATE.md`, `INDEX.md`, `agent-domain-map.md`
**Truth relationship**: docs that synthesize/index the current state of the world. Stale = misleading.
**Failure mode in this session**: `STATE.md 1e80930` shipped "tools=130 in-tree / 19-tool gap" which propagated as poisoned premise into 4 subsequent synthesis dispatches. Cost ~6h cleanup.
**Distinguishing test**: would re-running the synthesis today produce materially different content? If yes, this class. If no, it's Class B or C.

## Class B — Decision Records (write-once, immutable, historical)

**Examples**: R-10 v1→v8 series; `phase-2-6-r10-decisions.md` (the v8 closure); `path-e-try-before-buy-results.md` (Track 1 empirical results); `production-master-gap-report.md` (chain agent's investigation); `dr-drill-results-2026-05-11.md` (today's drill state)
**Truth relationship**: docs that capture WHY a path was chosen + what was falsified. Decision-stamp at write-time; truth doesn't decay.
**Failure mode in this session**: NONE for genuine decision records. The v1→v8 R-10 chain worked exactly as designed — v8 superseded earlier versions, but earlier versions remain valid as "what we believed at that point in the search."
**Distinguishing test**: does the doc become MORE valuable or LESS valuable as the decision recedes into the past? If MORE (audit trail, "why did we do X?" lookups), this class. If LESS (was current-state at write-time), it's Class A.

## Class C — Runbooks (operational, refresh-on-procedure-change)

**Examples**: `dr-drill-prod-keys.sh` (the actual script); `dr-drill-results-2026-05-11.md`; `launch-path-execution-playbooks.md`; `algo2go-reservation-runbook.md`; `rotate-key-runbook-2026-05-11.md`; `docs/incident-response.md`; `docs/operator-playbook.md`
**Truth relationship**: docs that prescribe HOW to do something. Truth = "this procedure works when run today."
**Failure mode in this session**: `launch-path-execution-playbooks.md` Item 2 prescribed `go build ./cmd/dr-decrypt-probe` — but the source dir didn't exist. The runbook claimed a procedure that wasn't executable.
**Distinguishing test**: would executing the steps in the doc TODAY produce the documented outcome? If no, doc is broken. Runbooks rot when (a) the system they describe changes, (b) dependencies they assume disappear, (c) commands they cite change syntax.

## Class D — External Facts (truth lives outside the repo; we cache it)

**Examples**: `memory/kite-cost-estimates.md` (SEBI RA fees, NSE empanelment costs, MCA Pvt Ltd costs); `memory/kite-sebi-otr-feb-2026.md` (regulatory framework); `memory/kite-rainmatter-warm-intro.md` (org-chart, contact info); `memory/kite-mcp-registry-publisher.md` (CLI procedures for external system); `memory/kite-fintech-lawyers.md` (lawyer firms + rates)
**Truth relationship**: docs that cache external truth (SEBI, NSE, IPIndia, Cloudflare, GitHub APIs, lawyer engagement costs).
**Failure mode in this session**: `memory/kite-algo2go-rename.md` 2026-04-17 claimed "Tradarc is solid as backup name" + "GitHub org `algo2go` AVAILABLE." Both falsified by 2026-05-03 / 2026-05-05 empirical re-probes (Tradarc auto-renewed; org claimed). The cache held but the source moved.
**Distinguishing test**: who controls the truth this doc cites? If anyone outside the repo (SEBI, NSE, IPIndia, Stripe, Cloudflare, a specific person's Twitter handle), this class. Decays at the rate the external source mutates.

## Class E — Rules + Standing Conventions (durable, supersede-only)

**Examples**: `user_email_rule.md`, `user_agent_orchestration_rule.md`, `user_team_commit_protocol.md`, `feedback_research_diminishing_returns.md`, `feedback_research_vs_empirical_grounding.md`, `feedback_wsl_for_go_test.md`, `feedback_no_stash_anywhere.md`, plus the project `CLAUDE.md` rules
**Truth relationship**: docs that prescribe HOW WE WORK (not how the world works, not what's true). Truth = "we agreed to do it this way."
**Failure mode in this session**: NONE — these rules held across the session and the rule-violations (e.g., grep-instead-of-compile-and-run) happened DESPITE the rule's existence (the methodology rule was added MID-session as `STATE.md §5.6` / §11). The rule corpus did its job once written.
**Distinguishing test**: would the rule be useful in 6 months if no code changed? If yes (user-rule territory), Class E. If no (described temporary state of code), Class A.

## Class F — Narrative Synthesis (judgment-load-bearing, not empirically falsifiable)

**Examples**: `forward-tracks-strategic-review.md`, `team-scaling-cost-benefit-per-axis.md`, `10000-agent-blocker-analysis.md`, `kite-product-strategy.md`, `kite-next-roadmap.md`, `kite-mrr-reality.md`
**Truth relationship**: docs that synthesize judgment (what to do next, which trade-offs matter, what the market looks like). Truth = "this is the analysis at write-time given the inputs known then."
**Failure mode in this session**: `forward-tracks-strategic-review.md` TL;DR §1 ("production deploy is the #1 unblock") was built on a Class A primitive (STATE.md's tools=130) that was empirically wrong. The narrative wasn't wrong-as-judgment; the inputs were wrong. **Synthesis docs inherit the staleness of their inputs.**
**Distinguishing test**: if two reasonable observers read the same facts, could they disagree on the conclusion? If yes, narrative synthesis. If no, empirical cache (Class A).

## Class G — Ephemera (write-once, use-once, no long-term value)

**Examples**: launch-material drafts (`docs/show-hn-post.md`, `docs/launch-materials.md`, `docs/twitter-launch-kit.md`, `docs/reddit-buildlog-posts.md`); pre-drafted DMs (`docs/drafts/jethwani-shenoy-dms.md`, `vishal-dhawan-dms.md`); pre-drafted emails (`docs/drafts/zerodha-compliance-email.md`); session snapshots (`memory/session_*.md` — but see §3.G nuance); verification reports of the form `<topic>-verification-2026-05-11.md` (today's 5)
**Truth relationship**: docs created to support a single bounded event (one Show HN, one launch, one session handoff, one verification cycle). Truth doesn't matter after the event.
**Failure mode in this session**: `docs/show-hn-post.md` accumulated 4 stale claims (tool count, test count, RiskGuard count, RiskGuard caps). Each one because the doc was kept "live" across the lead-up to launch instead of being a single point-in-time artifact. **Ephemera that gets re-edited drifts; ephemera that gets locked + replaced doesn't.**
**Distinguishing test**: after the event the doc supports, will it ever be re-read for its content (not just for git archaeology)? If no, Class G. Archive immediately after event.

---

# §2 — Long-term-value criteria

A doc has long-term value (worth maintaining forever) if and only if at least ONE of:

## C1 — Re-derivability fails (the doc captures non-trivially derivable truth)

**Test**: can the same content be re-derived in <5 minutes from probes (code, git, external API, file system)?
- YES → doc is a CACHE; truth lives in the probe; doc has bounded shelf life
- NO → doc IS authoritative; long-term value possible

**Examples**:
- "tools=111" → can be re-derived in 30s via `curl /healthz`. **CACHE.** Don't put in long-term doc; put PROBE in INDEX §11.
- "Phase 2.6 closure framework: Path 6 adopted, libsql-client-go is right choice despite deprecation banner because CGO-free" → cannot be re-derived from code alone. The empirical evidence is there (`alerts/db.go`), but the REASONING ("despite deprecation banner because…") is decision-recorded. **LONG-TERM VALUE.**
- "MCP bearer JWT expiry: 24 hours" → can be re-derived from `oauth/config.go:31`. **CACHE.** Put probe in INDEX, not in MEMORY.md as line 99.

## C2 — Decision is recorded (the doc captures WHY, not WHAT)

**Test**: does the doc explain preconditions + alternatives considered + falsifications, OR does it just state a current fact?
- WHY → long-term audit trail value
- WHAT → just a cache

**Examples**:
- R-10 v1→v8 series → each version captures the BELIEFS at that time + falsifications from the next round. Even v1 (now superseded) has audit value: "here's what we thought before Path E results came in." **LONG-TERM VALUE.**
- `path-e-try-before-buy-results.md` Track 2 falsification (DO BLR1) → captures WHY we ruled out DO. Future "should we use DO?" question gets answered without re-doing the work. **LONG-TERM VALUE.**
- `production-master-gap-report.md` → captures the methodology that proved no-gap-exists. Future "is production stale?" questions get answered by re-running the probes, but the methodology + cost-of-error documentation is reusable. **LONG-TERM VALUE.**

## C3 — Procedural reuse (the runbook will be executed more than once)

**Test**: will this procedure run more than once over the lifetime of the project?
- YES → maintain
- NO (truly one-off) → archive after first run

**Examples**:
- `dr-drill-prod-keys.sh` → run monthly (cron) + occasionally manual. **MAINTAIN.**
- `algo2go-reservation-runbook.md` → run ONCE (one TM filing per brand). **ARCHIVE after first use** (or convert to "if you need to file another TM in the future, here's how" generic guide).
- `launch-path-execution-playbooks.md` → run ONCE for one Show HN. Each step is a one-shot. **ARCHIVE after Show HN** (retain as template for any future re-launch).
- `rotate-key-runbook-2026-05-11.md` → run once per year (or per compromise event). **MAINTAIN as runbook.**

## C4 — Identity / brand (captures organizational identity)

**Test**: does the doc define WHO WE ARE (mission, brand, positioning, regulatory posture)?
- YES → long-shelf-life; updates rare; deletion catastrophic
- NO → not in this category

**Examples**:
- README.md → identity-facing (what kite-mcp-server is). **LONG-TERM.**
- `funding.json` → identity-facing (who we are, what we ask for, who's behind). **LONG-TERM.**
- `SECURITY.md` → identity-facing (security policy, contact). **LONG-TERM.**
- `THREAT_MODEL.md` → identity-adjacent (what threats we model). **LONG-TERM** (updated periodically).
- `docs/product-definition.md` → identity (what the product IS in clear words). **LONG-TERM.**

## C5 — Rule (durable convention)

**Test**: does the doc prescribe HOW WE WORK such that future-us needs to obey it without re-deriving?
- YES → maintain forever (only supersede via newer rule)
- NO → not a rule

**Examples**:
- `user_email_rule.md` → standing rule. **MAINTAIN FOREVER** until user signals change.
- `feedback_research_diminishing_returns.md` → standing rule. **MAINTAIN FOREVER.**
- `feedback_wsl_for_go_test.md` → standing rule. **MAINTAIN FOREVER.**

## Net rule

If a doc satisfies **none** of C1-C5, it should not exist as a long-term artifact. It's either:
- A debugging note (delete after issue resolved)
- A draft (archive after publish)
- A session snapshot (write once, never edit, retain for git archaeology only — but don't link from active docs)

---

# §3 — Lifecycle stages per class

For each Class A-G, define CREATE / UPDATE / ARCHIVE / DELETE triggers.

## Class A — Canonical State (STATE.md, INDEX.md, agent-domain-map.md)

| Stage | Trigger |
|---|---|
| CREATE | Once per repo. Treat as singleton. |
| UPDATE | Weekly OR after any structural commit (module promotion, phase closure, major decision). User dispatches "refresh STATE.md" as a recurring touchpoint. |
| ARCHIVE | NEVER while doc is the source-of-truth pointer. Only if SUPERSEDED by a renamed/restructured replacement (e.g., STATE.md → CORPUS-MAINTENANCE-STRATEGY.md). In that case, the old version is archived AND the new version explicitly inherits the relationships. |
| DELETE | Never. |

**Decay-prevention design**: Class A docs MUST cite probes (INDEX §11 pattern), MUST have "Last verified" dates per row, MUST distinguish FRESH vs STALE-PENDING status. Update protocol: re-run probes weekly; refresh status column. Failure of probe = trigger to re-derive; not silent stale.

**Failure mode prevented**: `STATE.md 1e80930`'s tools=130 grep-error contamination would have been caught at "Last verified" weekly cadence (probe was unchanged; result was wrong) IF the probe was canonical and the cached value was disclaimed.

## Class B — Decision Records (R-10 series, Phase 2.6 closure, Track 2 falsification)

| Stage | Trigger |
|---|---|
| CREATE | When a decision is being made AND alternatives exist AND falsifiability is possible. NOT for every "we decided to use X" choice; only when the decision is reversible AND understanding why matters. |
| UPDATE | NEVER — decision records are write-once. Newer decision = new doc (e.g., R-10 v8 doesn't edit v7; it supersedes). Cross-link explicitly. |
| ARCHIVE | When the decision is N+ generations stale AND a successor doc captures the lineage. E.g., R-10 v1-v7 archived after v8 ships; v8 is "active" reference; v1-v7 reachable from `.research/archive/` for audit. |
| DELETE | Never (audit trail). |

**Decay-prevention design**: each decision record has a date-stamp + "superseded by" pointer (or "active" if current). NEVER edit a decision record; ALWAYS write a successor. The discipline of "write-once" prevents the "patch over the record" failure mode.

**Subdir recommendation**: create `.research/decisions/` to make Class B explicit. Today these are mixed in with synthesis docs.

## Class C — Runbooks (dr-drill, rotate-key, launch playbooks, incident response)

| Stage | Trigger |
|---|---|
| CREATE | When a procedure will run more than once AND the steps are not trivially obvious from the code AND any step requires external coordination. |
| UPDATE | When (a) the underlying system changes (e.g., flyctl subcommand renamed), (b) the procedure produces an unexpected outcome on execution, (c) a step's external dependency changes (e.g., GitHub Actions secret schema). |
| ARCHIVE | When the procedure becomes irrelevant (e.g., the system it operates on is decommissioned). |
| DELETE | Only if the runbook is actively misleading AND no historical value remains. |

**Decay-prevention design**: every runbook must have an "EXECUTED ON" log at the bottom — a list of (date, executor, outcome, deviations-from-spec). The first time a step deviates is the trigger to UPDATE the spec.

**Failure mode prevented**: `launch-path-execution-playbooks.md` Item 2's `go build ./cmd/dr-decrypt-probe` reference would have been caught at the first attempt-to-execute. The "EXECUTED ON" log forces runbook verification before reliance.

## Class D — External Facts (SEBI fees, NSE list, lawyer rates, registrar prices)

| Stage | Trigger |
|---|---|
| CREATE | When external truth is needed for a decision AND re-verifying every time is expensive (e.g., calling Spice Route Legal for current consult fees). |
| UPDATE | Periodically — quarterly for high-stakes facts (regulatory thresholds), annually for low-stakes (TM filing fees). Decay-driven by external mutation rate, NOT by repo activity. |
| ARCHIVE | When the fact is no longer load-bearing on any decision (e.g., DPDP Phase 3 deadline after May 2027 passes). |
| DELETE | If actively misleading AND likely to be re-read (e.g., a stale TM filing fee quoted in a runbook) → patch the quote, optionally retain the historical figure in a footnote. |

**Decay-prevention design**: every Class D doc must have an "AS-OF" date in its frontmatter + a "RE-VERIFY BY" date based on the source's expected mutation rate. The orchestrator's monthly memory-audit pass surfaces docs past their RE-VERIFY date.

**Failure mode prevented**: `memory/kite-algo2go-rename.md` 2026-04-17's stale "Tradarc backup is solid" would have been re-verified at 2026-05-17 (1mo + buffer). Same for "GitHub org `algo2go` AVAILABLE" — that's an obvious re-verify candidate (status flips at any time).

## Class E — Rules (user_*, feedback_*, project CLAUDE.md)

| Stage | Trigger |
|---|---|
| CREATE | When the user articulates a standing rule OR when a failure mode has occurred 2+ times and a rule could prevent it (e.g., `feedback_no_stash_anywhere.md` after the 2nd cross-clone stash incident). |
| UPDATE | When a newer rule supersedes (write a new rule, cross-link, mark old as SUPERSEDED). NEVER edit the rule body — write a successor. |
| ARCHIVE | When the rule no longer applies because the system changed (e.g., if WSL2 became unnecessary, the WSL2 rule would archive). |
| DELETE | Never. |

**Decay-prevention design**: every rule has an "active since" date. Rules don't have "last verified" dates — they're durable until explicitly superseded. The discipline of newer-rule-supersedes-older-rule (not edits-in-place) is what makes the rule corpus reliable.

**Counter-example to avoid**: `MEMORY.md` line ~99's "MCP bearer JWT expiry: 24 hours" + explicit disclaimer "An earlier '4h expiry' note in this file was stale plan that never landed — do not quote it" — this is a HACK because the source-of-truth (Class A — code reality) leaked into the rule corpus. The right fix: put "JWT expiry" in INDEX as an empirical probe (`grep -nE 'JWTTimeout|24.\*Hour' oauth/config.go`), not in MEMORY.md as a cached fact.

## Class F — Narrative Synthesis (forward-tracks, team-scaling, 10K-blocker)

| Stage | Trigger |
|---|---|
| CREATE | When user dispatches "strategic review" / "should we do X?" / "what's the highest-leverage next move?" |
| UPDATE | NEVER in-place. New synthesis = new doc. Old synthesis flagged with "superseded by ..." pointer. **CRITICAL: synthesis docs MUST list their input docs at write-time**; when an input changes (and the input is Class A/D), the synthesis is presumptively stale. |
| ARCHIVE | When superseded by newer synthesis OR when the decisions implied by the synthesis are made (no longer "what should we do" but "we did it"). |
| DELETE | Never. |

**Decay-prevention design**: every synthesis doc has an "INPUTS" section at the top — explicit list of (doc, date-read, claim-quoted). When an input doc updates, automated tooling could flag every synthesis that cited it.

**Failure mode prevented**: `forward-tracks-strategic-review.md` 2026-05-10 cited `STATE.md` (which had tools=130 at write-time). When STATE.md patched at `bea1e11`, the synthesis became internally inconsistent. The INPUTS list would have made this automatable to detect.

## Class G — Ephemera (launch drafts, session snapshots, verification reports)

| Stage | Trigger |
|---|---|
| CREATE | For a single bounded event. Stamp the event-purpose explicitly in the doc header. |
| UPDATE | NEVER — if content needs to change, the event is ongoing and the doc should be rewritten (not patched) before the event closes. Patches-in-place are the source of drift. |
| ARCHIVE | At event completion (Show HN submitted; session ended; verification cycle complete). NOT "when someone notices it's stale." Automate via event-completion trigger. |
| DELETE | Optional. Most ephemera can be deleted after archive (snapshot is the git history; no need for separate doc). |

**Decay-prevention design**: ephemera doc filenames MUST include the event date AND end-state (`launch-path-execution-playbooks-2026-05-Show-HN.md` not `launch-path-execution-playbooks.md`). The date-in-filename is the visible "this is point-in-time" signal.

**Failure mode prevented**: `final-pre-launch-verification.md` 2026-05-03 was a Class G doc that became Class A by social default (people kept referencing it). The date-in-filename rule would have prevented this — visible decay-by-design.

---

# §4 — The CENTRAL question — user vs orchestrator stewardship

The session shipped ~30+ patches across ~100+ docs because nobody had a maintenance model. The empirical evidence points to a clear distribution:

## Principle 1: User-`memory/` is for ORCHESTRATOR rules + EXTERNAL truth caches

**What belongs in `memory/`**:
- **Class E (Rules)**: `user_*.md`, `feedback_*.md`. Cross-session, cross-repo durable conventions. The orchestrator MUST read these at session start.
- **Class D (External Facts)** that the orchestrator references mid-conversation: `kite-cost-estimates.md`, `kite-fintech-lawyers.md`, `kite-rainmatter-warm-intro.md`. These are not in the repo because they're not project-source; they're orchestrator-state.
- **Session snapshots** (`session_*.md`): write-once handoffs. Read at session start; never edited mid-session.

**Why**: `memory/` is orchestrator-private, loads automatically at session start, doesn't need to be discoverable to anyone who clones the repo. The signal-to-noise for an outside reader cloning kite-mcp-server is wrong if these live in the repo.

## Principle 2: Repo `.research/` is for CLASS A + B (project-collaborative state + decisions)

**What belongs in `.research/`**:
- **Class A (Canonical State)**: `STATE.md`, `INDEX.md`, `agent-domain-map.md`. Repo-internal, version-controlled, multi-agent-edited.
- **Class B (Decision Records)**: `phase-2-6-r10-decisions.md`, `path-e-try-before-buy-results.md`, `production-master-gap-report.md`. New subdir `.research/decisions/` recommended.
- **Class F (Narrative Synthesis)** that's mid-flight: `forward-tracks-strategic-review.md`, `10000-agent-blocker-analysis.md`. Until they reach steady state (or are archived).

**Why**: `.research/` is version-controlled (git diff visible), multi-agent-editable (collaborative), repo-scoped (an external contributor clones and sees the research artifacts). It's the right home for project-internal collaborative artifacts.

## Principle 3: Repo `docs/` is for PUBLIC-FACING content + ARCHITECTURAL reference

**What belongs in `docs/`**:
- **Class C (Runbooks)** that are operational + public: `docs/incident-response.md`, `docs/operator-playbook.md`, `docs/pre-deploy-checklist.md`. These are read by future operators (which might include external contributors).
- **Class C** (Identity/Architecture references): `docs/architecture-diagram.md`, `docs/adr/*` (architecture decision records — the formal-process variant of Class B that should live in `docs/` because they're public).
- **Class G (Ephemera-as-public-artifact)**: launch material drafts that need to be public-readable (show-hn-post, twitter-launch-kit). These live in `docs/` but with explicit date-of-relevance and clear "this is launch-cycle material" framing.

**Why**: `docs/` is conventionally public-facing in open-source projects. External readers expect operational + architectural docs here. Don't pollute with internal research; don't hide operational truth here either.

## Principle 4: Repo root is for IDENTITY (Class C — identity sub-class)

**What belongs in repo root**:
- `README.md`, `LICENSE`, `SECURITY.md`, `THREAT_MODEL.md`, `ARCHITECTURE.md`, `CONTRIBUTING.md`, `PRIVACY.md`, `TERMS.md`, `CHANGELOG.md`, `funding.json`, `server.json`, `smithery.yaml`.
- Plus: `.claude/CLAUDE.md` (project rules for AI agents — discoverable by Claude Code at clone-time).

**Why**: anything an external visitor at the repo's GitHub URL should see immediately. Discoverability is the criterion.

## Principle 5: Session-ephemeral state goes nowhere persistent

**What does NOT belong anywhere**:
- Debugging notes ("trying X, didn't work, trying Y") — should be in the agent's context window, not persisted.
- Per-task TODO lists — should be in `TodoWrite` state, not in memory files.
- Mid-execution status logs — should be in commit messages or git annotations, not in `.research/`.
- Hypothesis-test scratch ("if I run this, does X happen?") — context-window only.

**Failure mode prevented**: this session's `STATE-v2-fresh-eyes.md` + `STATE-claims-audit-2026-05-11.md` + `STATE-fresh-eyes-diff-2026-05-11.md` are debatably-Class-F-debatably-Class-G — they're verification artifacts of an event (the STATE.md audit), useful at audit-time, but persisted in `.research/` as if Class A. They should be in `.research/archive/audits/2026-05/` immediately after the audit cycle closes, not in `.research/` as if active.

## Single-paragraph distillation

User `memory/` = orchestrator rules + external truth cached for orchestrator. Repo `.research/` = project-internal canonical state + decision records + active synthesis. Repo `docs/` = public-facing operational + architectural references. Repo root = identity (what kite-mcp-server IS to a stranger). Anything session-ephemeral lives in agent context windows + git commits, NOT in persisted docs. **The location is determined by the AUDIENCE (orchestrator vs collaborator vs external visitor) × MUTATION CADENCE (live vs durable vs write-once), NOT by what's convenient.**

---

# §5 — Failure modes + structural prevention

What we empirically observed this session, with prevention designs:

## Failure 1 — Grep-error contamination through synthesis chains

**What happened**: `STATE.md 1e80930` claimed "tools=130 in-tree" from `grep mcp.NewTool(` over `mcp/` (which included 19 `_test.go` fixtures). 4 subsequent synthesis docs (`forward-tracks-strategic-review.md`, `launch-path-execution-playbooks.md`, `10000-agent-blocker-analysis.md`, `agent-domain-map.md`) inherited the bad number. Cost: ~6 hours of misdirected synthesis. Caught only by chain agent's compile-and-run.

**Why it happened structurally**:
- Class A doc cached a derivable fact instead of pointing to the probe.
- Class F synthesis docs trusted Class A without re-verifying the probe.
- No metadata link from synthesis-back-to-input meant updating STATE.md didn't auto-flag downstream synthesis as stale.

**Structural prevention**:
1. **In Class A docs**: every derivable fact has an authoritative-PROBE column (the INDEX §11 pattern). The fact-value column is a CACHE, refreshable from the probe.
2. **In Class F synthesis docs**: required INPUTS section listing (input-doc, date-quoted, claim-cited). When an input updates, the synthesis is auto-flagged as STALE-PENDING.
3. **Methodology rule** (Class E): "compile-and-run > grep-and-count" memorialized in `STATE.md §11`. Make it project-wide via repo `CLAUDE.md`.

## Failure 2 — Stale external-fact caches

**What happened**: `memory/kite-algo2go-rename.md` 2026-04-17 claimed "GitHub `algo2go` org AVAILABLE" and "Tradarc backup is solid." 23 days later (in this session), both falsified by re-probe (org claimed; Tradarc auto-renewed).

**Why it happened structurally**:
- Class D doc had no "AS-OF" date in a queryable format (just commit history; not surfaced).
- No "RE-VERIFY BY" date based on source mutation rate.
- Orchestrator didn't have a "stale-fact sweep" cadence.

**Structural prevention**:
1. **Class D docs MUST have frontmatter**: `as-of: 2026-04-17` + `re-verify-by: 2026-07-17` (3mo for TM/domain/regulatory; 12mo for stable like NSE list).
2. **Orchestrator monthly hook**: scan all `memory/kite-*.md` + `.research/*.md` for `re-verify-by` dates past current. Output as a "stale-facts queue" for the next session.
3. **Class D doc body should have a "PROBE" line**: "Re-verify via: `curl https://api.github.com/orgs/algo2go`" so the re-verification is one command, not a research project.

## Failure 3 — MEMORY.md hitting 200-line limit; details fragmented across pointer files

**What happened**: `MEMORY.md` is the user-rule index. As project complexity grew, MEMORY.md hit a soft line-limit (per the system reminder "MEMORY.md is 249 lines and 33.2KB. Only part of it was loaded"). Detail moved to subfiles. Subfiles became authoritative for facts that MEMORY.md's index merely points to. Subfiles drift; MEMORY.md doesn't reflect drift.

**Why it happened structurally**:
- MEMORY.md is doing TWO jobs: rule index (one-line summary of each rule) AND fact cache (some facts cached inline like "MCP bearer JWT expiry: 24 hours"). The dual purpose blew the line limit.
- The pointer-to-subfile pattern (`[rule name](file.md) — short description`) is the right index pattern but each subfile became authoritative for its claims; subfile mutations were invisible to MEMORY.md.

**Structural prevention**:
1. **MEMORY.md = pure index**: one line per rule/topic, only the pointer + ≤1-sentence WHY. No facts cached in MEMORY.md itself.
2. **Move all cached facts out of MEMORY.md** into either INDEX.md probes (Class A) or dedicated Class D files with proper frontmatter.
3. **Periodic regenerate**: rebuild MEMORY.md from `memory/*.md` frontmatter (name + description) on a schedule. Manual MEMORY.md edits become rare; mechanically-regenerated index becomes the norm.

## Failure 4 — Multi-version research (R-10 v1→v8) without clear superseded-by markers

**What happened**: 8 versions of `phase-2-6-r10-decisions.md`. v8 supersedes prior versions. But prior versions still readable; nothing explicitly says "v7 is now historical; go to v8." A new agent landing in `.research/` could read v6 and miss the v7+v8 updates.

**Why it happened structurally**:
- Filename has no version-superseded marker.
- v1-v7 weren't archived after v8 shipped; they're still in `.research/` as if active.
- No "supersedes" / "superseded by" pointer in the doc body.

**Structural prevention**:
1. **For multi-version decision chains**: use `.research/decisions/<topic>/v1.md, v2.md, ..., v8-current.md`. The version suffix is visible; `v8-current` is the only one that orchestrator-default loads.
2. **At each supersession**: the new version explicitly cites what it supersedes + WHY (which falsification triggered the new version).
3. **At decision closure**: archive all prior versions; only the closure-version stays in active `.research/decisions/<topic>/`.

## Failure 5 — Verification reports themselves becoming stale

**What happened**: today's 5 verification reports (active-docs, STATE-claims-audit, STATE-fresh-eyes-diff, memory-files, repo-docs) capture state at 2026-05-11. In 30 days they'll be partially stale; in 90 days mostly stale. They live in `.research/` as if active reference, but they're not — they're Class G ephemera of a verification event.

**Why it happened structurally**:
- Verification reports get persisted in the same dir as canonical state.
- No "this audit is point-in-time" framing in the filename.
- No automated archive-on-completion trigger.

**Structural prevention**:
1. **Verification reports go in `.research/audits/<YYYY-MM-DD>/` immediately on creation**, not in `.research/` root.
2. **Filename pattern**: `<audited-thing>-audit-<date>.md`. The date-in-filename is the visible "this is point-in-time" signal.
3. **Auto-archive trigger**: every audit doc gets archived to `.research/archive/audits/<YYYY-MM>/` after 30 days OR after a newer audit of the same scope. Whichever comes first.

## Failure 6 — Plaintext secrets in memory files

**What happened** (per `memory-files-verification` finding): some memory files contain plaintext sensitive values (API key/secret pairs for Kite Connect apps in MEMORY.md ~lines 70-72). These are personal-scope (single-user repo), but if memory ever gets backed up to cloud sync or shared, they're exposed.

**Why it happened structurally**:
- No discipline of "secrets go in env vars / secret manager; docs cite the variable name, not the value."
- Memory files are seen as private; user trust outweighs hygiene.
- No automated secret-scanning on memory writes.

**Structural prevention**:
1. **Rule (Class E, new)**: secrets never go in any doc. Doc cites the secret-manager name OR env-var name. The value lives in the secret-manager.
2. **Existing secrets**: rotate them, then patch the docs to reference the var name instead of the value.
3. **Optional automation**: pre-commit hook that scans memory files for high-entropy strings + known patterns (Stripe keys, AWS keys, OAuth secrets). Block commits.

## Failure 7 — README-style number-soup (intra-doc inconsistency)

**What happened**: README claims "11 pre-trade checks" (L3), "12 enumerated checks" (L22), "9 safety checks" (L82), "117 tools" (L198), "111 tools" (other places). Same doc, conflicting numbers, accumulated from successive edits not done atomically.

**Why it happened structurally**:
- Doc edited multiple times by different agents; each edit fixed ONE location, not all.
- No build-time grep for cross-section inconsistencies.
- Source-of-truth was distributed (server.json has 111; guard.go has 17 constants; agent-of-the-week eyeballed a different count).

**Structural prevention**:
1. **Canonical numeric facts go in `server.json`** (machine-readable, single line, version-controlled). All docs (README, show-hn, twitter, reddit) reference server.json values verbatim, ideally via a build step that substitutes templates.
2. **CI check**: build-time grep for `\b(\d+)\b (tools|checks|pre-trade)` across all markdown; flag inconsistencies. Fails CI if README L3 and L82 disagree.
3. **Single-edit discipline**: when patching a number, grep-and-replace ALL occurrences in the same commit. No "I'll fix the other places later."

---

# §6 — Recommendation: optimal distribution

Based on §1-§5, the framework recommends:

## Tier 1 — Live (must-be-fresh)

**Location**: repo `.research/`
**Contents**: STATE.md, INDEX.md, agent-domain-map.md, 1-2 active synthesis docs
**Refresh cadence**: weekly + on structural commits
**Maintenance protocol**: probes-with-cache pattern; INPUTS sections in synthesis; auto-flag stale on input mutation
**Steward**: orchestrator (writes); user (acceptance via dispatch confirmation)

**Total target doc count: 5-10**. Anything more belongs in Tier 2 or 3.

## Tier 2 — Durable (rules + decision records + identity + long-term reference)

**Location**:
- `memory/` for user-rules + external-fact caches needed mid-orchestration
- `.research/decisions/<topic>/` for project-internal decision chains (NEW subdir)
- `docs/adr/` for architecture decision records (already exists; expand convention)
- Repo root for identity files (README/SECURITY/THREAT_MODEL/funding.json)
- `docs/` for operational reference + public-facing material

**Refresh cadence**: write-once for decisions; quarterly/annually for external facts; never for rules (only supersede)
**Maintenance protocol**: AS-OF + RE-VERIFY-BY frontmatter for Class D; SUPERSEDES + SUPERSEDED-BY for Class B; date-in-filename for versioned decision chains
**Steward**: user (rules) + orchestrator (external facts, decision records); collaborative for docs/

**Total target doc count: 50-100**. Most of the current corpus belongs here.

## Tier 3 — Ephemeral (write-once, archive-once)

**Location**:
- `.research/audits/<YYYY-MM-DD>/` for verification reports (NEW subdir convention)
- `docs/drafts/` for launch material (already exists)
- `memory/session_*.md` for session snapshots (already exists; date-in-filename already used)
- After completion: archive to `.research/archive/<topic>/`

**Refresh cadence**: NEVER (write-once); archive-on-completion
**Maintenance protocol**: filename includes event-date; auto-archive trigger when event completes; never edit in place
**Steward**: orchestrator (writes); event-completion is the archive signal

**Total target doc count: bounded by event count**. Should not accumulate indefinitely.

## What goes where (concrete redistribution)

Of the ~120 docs currently across the 5-location corpus, the framework recommends:

| Currently in | Should be in | Examples |
|---|---|---|
| `.research/` (active) | Tier 1 (live, 5-10 docs) | STATE.md, INDEX.md, agent-domain-map.md, forward-tracks (while mid-flight) |
| `.research/` (active) | Tier 2 `.research/decisions/` | phase-2-6-r10-decisions.md, path-e-try-before-buy-results.md, production-master-gap-report.md, dr-drill-results-2026-05-11.md, rotate-key-runbook-2026-05-11.md |
| `.research/` (active) | Tier 3 `.research/audits/2026-05-11/` | active-docs-verification, STATE-claims-audit, STATE-fresh-eyes-diff, memory-files-verification, repo-docs-verification (all 5 of today's) |
| `.research/` (active) | Tier 3 archive | research-batch-2026-05-11.md (one-shot Q&A batch) |
| `memory/kite-*.md` | Tier 2 `memory/` with new frontmatter (as-of, re-verify-by) | cost-estimates, fintech-lawyers, rainmatter, sebi-otr, audit, etc. |
| `memory/session_*.md` | Tier 3 (write-once; already date-stamped) | session_2026-05-10_path-a-complete.md etc. |
| `memory/feedback_*.md`, `user_*.md` | Tier 2 `memory/` (no change) | (these are working correctly) |
| `MEMORY.md` | Tier 1 (live index — but pure-index, no facts) | regenerated mechanically from `memory/*.md` frontmatter |
| `docs/show-hn-post.md`, etc. | Tier 3 (event-stamped filename) → archive post-Show-HN | rename to `show-hn-post-2026-05-Show-HN.md` etc. |
| `docs/operator-playbook.md`, `docs/incident-response.md` | Tier 2 (operational reference, no change) | (correct location) |
| `docs/architecture-diagram.md`, `docs/adr/*` | Tier 2 (architecture reference, no change) | (correct location) |
| Repo root identity files | Tier 2 (identity, no change) | README/SECURITY/etc. |

## Effort to migrate

**Phase 1 (immediate, ~2-3h)**: create `.research/audits/2026-05-11/` and `.research/decisions/` subdirs; `git mv` the obviously-misplaced docs. Update STATE.md cross-references.

**Phase 2 (next session, ~2-3h)**: add frontmatter (`as-of`, `re-verify-by`) to all Class D memory files. Add `INPUTS` sections to all active synthesis docs. Add date-in-filename to all ephemera that lack it.

**Phase 3 (one-time, ~4-6h)**: build the orchestrator "stale-facts sweep" hook + the "MEMORY.md regenerate" hook. Document in `.claude/CLAUDE.md` as a standing rule.

**Phase 4 (recurring, weekly)**: the orchestrator runs the stale-facts sweep; surfaces queue; user authorizes patch dispatches. This is the maintenance cadence the corpus needs.

## Single-sentence recommendation

**Convert the corpus from "documents that record state" to "documents that point to probes (Tier 1), record decisions (Tier 2), or capture point-in-time events (Tier 3)" — and enforce the distinction via filename/frontmatter conventions so future agents cannot confuse the classes.**

---

# §7 — Principles that contradict current user rules — surface

Per dispatch hard rule "surface immediately if you find a PRINCIPLE that contradicts a current user-rule":

**Found 1 partial contradiction** (worth surfacing for user resolution):

## Contradiction 1: "Main agent is orchestrator only" vs "decay-prevention via probes-not-caches"

**Current rule** (`user_agent_orchestration_rule.md`): main session does NOT execute substantive work; dispatches sub-agents. Exception: "Single-line health checks (e.g., `curl /healthz` to verify an agent's deploy claim)."

**This framework's recommendation**: Tier 1 docs (STATE.md, INDEX.md) should cite empirical probes that the orchestrator runs IN-CONTEXT to verify caches before trusting them. Specifically: when reading STATE.md, the orchestrator should run the §11 probes for any load-bearing claim it's about to surface to the user.

**Partial contradiction**: running 5-10 probes per session-start could be construed as "substantive work" by the strict orchestrator-rule. Or it could fit the exception ("single-line health checks").

**Recommendation**: amend `user_agent_orchestration_rule.md` to explicitly allow "Tier 1 doc probes (INDEX.md §11 quick-reference, STATE.md §11) — these are single-line probes that verify cache-freshness before surfacing claims; they count as orientation, not work." Or: dispatch a "freshness-check" sub-agent at session-start that runs all Tier 1 probes and reports STALE-PENDING items.

**Verdict**: not a hard contradiction; needs user-disambiguation of which interpretation governs.

**No other principle-vs-rule contradictions found.** The rest of the framework is additive to the existing rule corpus (introduces new rules; doesn't conflict with existing ones).

---

# §8 — Source verification (this doc)

| Probe | Tool | Result |
|---|---|---|
| Master HEAD | `git log -1` | `25c9c8e docs(funding): bump to FLOSS/fund schema v1.1.0...` |
| Production state | `curl /healthz` (cited from STATE.md, not re-probed today) | tools=111, version=v1.3.0 (last verified 2026-05-11 per multiple session dispatches) |
| Active research docs | `ls .research/*.md` (cited from INDEX.md) | ~20 active md files |
| Memory files | `ls memory/*.md` (cited from `memory-files-verification`) | 76 md files |
| Verification reports referenced | Read in full: active-docs-verification, STATE-claims-audit, STATE-fresh-eyes-diff §2, memory-files-verification §0-§1, repo-docs-verification §1-§2 | all 5 read |
| Sample rule files | Read in full: user_agent_orchestration_rule.md, user_email_rule.md, feedback_research_diminishing_returns.md, feedback_research_vs_empirical_grounding.md | 4 read; rule corpus shape understood |
| Cross-reference accuracy | `STATE.md §11` for probe pattern; `INDEX.md §11` for empirical-probe quick reference | both verified consistent |
| Failure-mode evidence | every §5 failure cites the specific doc-and-line that exhibited it; all references traced through INDEX | verified |

**Methodology rule applied**: Class A claims about doc state cite Tier 1 docs (STATE.md, INDEX.md) which were freshly probed; Class B-G claims cite the verification reports that were produced today by parallel agents (chain, path-a-owner) and re-verified by reading. NO grep-as-evidence for any tool count or check count — those numbers came from running compile-and-run-derived authoritative sources (server.json, /healthz, the verification reports themselves).

**No new empirical probes ran for this dispatch** because the deliverable is principles, not empirical state. The framework is grounded in the EXISTING empirical record (which is itself fresh as of 2026-05-11).

---

## Closing

The corpus has accumulated organically — the result is a system that works in single-session bursts but rots between sessions. The 5-location structure was never designed; it grew. This framework names the structure that's hiding: 3 tiers, 7 doc classes, 5 principles for value, 7 failure modes with structural prevention.

**The one principle that, if adopted alone, prevents most of this session's failures**: every load-bearing fact lives in EXACTLY ONE place — either in code (probe-able), in `server.json` (machine-readable canonical), or in a Class D file with explicit `as-of` + `re-verify-by` frontmatter. Synthesis docs cite these locations; never cache values inline. **One value, one location, one verification path.**

If the next 5 months of accumulation maintain that invariant, the next "comprehensive audit" dispatch will be ~30 minutes, not ~10 hours.
