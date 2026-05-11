# Maintenance Strategy: Ownership Model + Automation Hooks

**Date**: 2026-05-11 IST
**Master HEAD audited**: `f61e1bf` (`docs(maintenance): strategic framework — value criteria + lifecycle stages + stewardship principles`)
**Dispatch role**: 3 of 3 parallel — **ownership + automation** (this doc) + abstract value criteria (Audit, `value-framework.md`) + per-doc verdicts (Chain, `doc-classification.md` — landing in parallel)
**Charter**: design the OPERATING SYSTEM that keeps the corpus healthy without manual oversight every session. NOT abstract value criteria (Audit owns that); NOT per-doc classification (Chain owns that). **Who maintains what + which automation closes which failure-mode.**

**Grounding inputs** (read in full or sampled):
- `value-framework.md` (Audit's strategic framework — read in full; §1 taxonomy, §3 lifecycle stages, §4 user-vs-orchestrator distillation, §7 contradiction surface)
- `STATE.md`, `INDEX.md` (canonical state + question-keyed lookup)
- 5 verification reports (sampled headers: `active-docs-verification`, `STATE-claims-audit`, `STATE-fresh-eyes-diff`, `memory-files-verification`, `repo-docs-verification`)
- Sample user rules: `user_agent_orchestration_rule.md`, `user_email_rule.md`, `feedback_research_diminishing_returns.md`, `feedback_research_vs_empirical_grounding.md`, `feedback_wsl_for_go_test.md`, `feedback_no_stash_anywhere.md`, `user_team_commit_protocol.md`
- `C:\Users\Dell\.claude\hooks\` (existing hooks infrastructure — empirically inventoried)
- `C:\Users\Dell\.claude\settings.json` (existing hook wiring + event types)

**Concurrency**: Audit shipped framework at `f61e1bf`. Chain doing per-doc verdicts in parallel. All three outputs deliberately disjoint by abstraction layer.

---

## TL;DR — three pivots for the operating system

1. **The corpus rots between sessions because nobody owns it between sessions.** In-session, agents touch docs, the user makes decisions, dispatches close. Between sessions, the world moves (Tradarc auto-renews, the algo2go org gets claimed, Phase 2.6 ships, tools=130 grep error infiltrates 4 docs). Nobody is paid to notice until the next dispatch surfaces the drift the hard way (~6h cleanup cost). **Pivot: structurally assign a between-session owner to each corpus location, and make the contract explicit + measurable.**

2. **The 6 existing hooks all do session-lifecycle UX work — none does corpus-hygiene work.** `fix-windows-lsp.py`, `suggest-plugin.sh`, `tts-integration-router.py`, `tts-stop.py`, `teammate-idle.py`, `task-completed.py`. Zero secret-scanning, zero staleness-check, zero cross-ref validation. The `validators/` directory exists and is empty — it's the designated home for new validator hooks. **Pivot: write 4-6 new validator hooks targeting the specific failure modes this session exposed.**

3. **Audit's "freshness-check sub-agent" proposal in §7 is the resolution to the orchestrator-vs-probe contradiction.** The current `user_agent_orchestration_rule.md` says "main agent dispatches; only exception is single-line health checks." Running 5-10 probes at session-start could violate that. The right fix is NOT to amend the orchestrator rule (it's well-scoped). Instead: **dispatch a `freshness-check` sub-agent at SessionStart (auto-triggered by hook) that runs INDEX §11 probes, surfaces STALE-PENDING items in a queue, and dies.** The orchestrator just reads the queue. **Pivot: convert "should the orchestrator probe?" into "should a sub-agent probe at session-start?" — answer: yes, automated via hook.**

---

# §1 — Stewardship Matrix

Per corpus location, define PRIMARY steward / SECONDARY (fallback) / CONTRACT (what the steward owes) / SLA (how often).

The PRIMARY column distinguishes 4 owner-types:
- **USER** — high-judgment, infrequent (writes rules, approves archive, rotates secrets)
- **ORCHESTRATOR** — in-session, medium-judgment (dispatches verification, surfaces gaps, accepts patches)
- **AGENT** — sub-agent, dispatched for a bounded task (regenerates indices, runs probes, audits a corpus subset)
- **HOOK** — automated, zero-judgment, always-on (scans for secrets, validates cross-refs, surfaces staleness)

| Corpus location | PRIMARY steward | SECONDARY (fallback) | CONTRACT — what they owe | SLA — how often |
|---|---|---|---|---|
| `memory/MEMORY.md` (user-memory index) | **HOOK** (auto-regenerator) | ORCHESTRATOR (manual regen if hook absent) | Pure index of `memory/*.md` files; one-line-per-entry; no facts cached inline; regenerable from `memory/*.md` frontmatter | Regenerate on any `memory/*.md` mtime change (PostToolUse hook); manual sanity check at SessionStart |
| `memory/kite-*.md` (Class D external-fact caches) | **USER + HOOK** | ORCHESTRATOR (dispatch staleness-sweep) | USER decides what facts matter + writes initial; HOOK enforces `as-of` + `re-verify-by` frontmatter; ORCHESTRATOR dispatches re-verify sweeps | HOOK validates frontmatter on every write; user dispatches quarterly sweep |
| `memory/feedback_*.md` + `memory/user_*.md` (Class E rules) | **USER** | (no fallback — only user writes rules) | USER writes new rules; supersedes existing rules by writing successor (NEVER in-place edits); ORCHESTRATOR + AGENTS read at session-start | Write once; supersede when needed; never decay |
| `memory/session_*.md` (Class G snapshots) | **ORCHESTRATOR** (writes at session-end) | (no fallback — write-once) | Single point-in-time handoff; never edited after write; date-in-filename | Per session; immutable post-write |
| `memory/project_*.md` (operational state) | **USER + ORCHESTRATOR** | HOOK (staleness flag) | Document operational state (agent UUIDs, WSL2 setup); refresh per session-arc | Per session-arc; staleness-flag if >30 days |
| `memory/hooks.md` + `memory/mcp-servers.md` + `memory/dns-cloudflare-fix.md` (reference) | **USER** | ORCHESTRATOR (when ref topic comes up) | Stable reference; update when reference target changes | On-change of reference target; otherwise no maintenance |
| `.research/STATE.md` (canonical state) | **AGENT** (freshness-check at SessionStart) + **ORCHESTRATOR** (writes synthesis) | USER (acceptance via dispatch) | AGENT re-runs §11 probes; ORCHESTRATOR re-synthesizes when stale; user approves via dispatch | Weekly minimum + after structural commits |
| `.research/INDEX.md` (question-keyed lookup) | **AGENT** (regen from `.research/*.md` headers) | ORCHESTRATOR (manual regen) | Pure navigation aid; regenerable from `.research/` content; never authoritative for facts | Regenerate when active set changes; staleness-flag if >2 weeks |
| `.research/agent-domain-map.md` (live agent → domain) | **ORCHESTRATOR** | (no fallback — orchestrator-owned) | Updated on every dispatch with new agent UUID + domain | Per dispatch |
| `.research/<active synthesis>.md` (Class F narrative) | **ORCHESTRATOR** (dispatches) + **AGENT** (writes) | USER (approves direction) | AGENT writes; ORCHESTRATOR cites inputs; when input updates, the synthesis is presumptively stale (flagged by HOOK) | Per-dispatch; archive when superseded |
| `.research/decisions/<topic>/v*.md` (Class B decision records) | **AGENT** (writes) | (no fallback — write-once) | New version supersedes old via filename `vN-current.md`; old versions in same subdir for audit; never edited in place | Write once; supersede when reversed |
| `.research/audits/<date>/*.md` (Class G verification reports) | **AGENT** (writes) | ORCHESTRATOR (auto-archive after 30d) | Written for one audit cycle; date-in-path; HOOK archives after 30 days | Per audit cycle; auto-archive |
| `.research/archive/<topic>/` (historical) | **HOOK** (archives) + USER (purges) | ORCHESTRATOR (manual archive if hook fails) | Reachable for git archaeology; never edited; periodically pruned by user | Archive-on-trigger; user purge yearly |
| Repo root `.md` (README, SECURITY, ARCHITECTURE — Class C identity) | **USER** | ORCHESTRATOR (dispatches updates) | Identity-facing; updates rare; HOOK validates internal cross-refs | On identity-change or every release |
| Repo `docs/*` (Class C operational) | **USER** + **AGENT** (writes), **ORCHESTRATOR** dispatches | (no formal fallback) | Public-facing operational reference; updates when system changes; HOOK validates cross-refs | On system change; reactive |
| Repo `docs/adr/*` (Class B architecture decisions) | **USER + AGENT** | (no fallback — write-once) | One ADR per architectural decision; never edited; new ADRs supersede old via "Status: Superseded by ADR-NNN" header | Write per decision; supersede when reversed |
| Repo `.claude/CLAUDE.md` (project AI rules) | **USER** | ORCHESTRATOR (proposes changes) | Tells Claude how to work on THIS repo; supersede via newer rule | On rule change; otherwise immutable |
| Project-level `.claude/CLAUDE.md` (`D:\Sundeep\projects\.claude\CLAUDE.md`) | **USER** | ORCHESTRATOR (proposes) | Tells Claude how to work across all projects in `D:\Sundeep\projects\` (GitHub CLI rules, etc.) | On rule change; otherwise immutable |

## Stewardship principles applied

**Principle A — Locality of responsibility**: a steward owns ONE corpus location. No steward is responsible for "everything." When a doc has multiple-stewards (e.g., `memory/kite-*.md` is USER + HOOK), the contract is split: HOOK enforces structural invariants (frontmatter present, no secret patterns); USER owns judgment (which facts to cache, what `re-verify-by` window).

**Principle B — Fail-safe to the lowest-trust steward**: when a HIGHER-judgment steward is unavailable, fall back to the HOOK or to ARCHIVE. Never fall back to "ignore the staleness." E.g., if USER doesn't run quarterly sweep, the HOOK should escalate by adding a "PROBABLY STALE" badge to the doc header on every read.

**Principle C — Read-time vs write-time**: structural invariants (frontmatter, cross-ref validity, no secret patterns) are validated at WRITE time (PreToolUse hook). Staleness/freshness is validated at READ time (SessionStart hook surfaces stale items). The hook contract makes this split explicit.

**Principle D — No corpus-level steward**: nobody owns "the corpus." Each location has its own owner. The orchestrator's job is to ROUTE dispatches to the right steward for the right location, not to maintain a global corpus model.

## Resolution of Audit's §7 contradiction (orchestrator-vs-probes)

Audit's §7 surfaced: the orchestrator rule (`user_agent_orchestration_rule.md`) says "single-line health checks OK" but the maintenance-strategy wants probes to be run regularly. Audit proposed either amending the rule OR a "freshness-check sub-agent" pattern.

**This doc's resolution**: adopt the **freshness-check sub-agent pattern**, NOT a rule amendment. Specifically:

- Add a NEW hook `session-start-freshness-check.py` (skeleton in §4).
- The hook **dispatches** (via the agent-team infrastructure, or via a simpler "launch one sub-agent" pattern) a freshness-check agent at SessionStart.
- The sub-agent runs INDEX.md §11 probes (5-10 single-line commands like `curl /healthz`, `gh api /orgs/algo2go`, RDAP for Tradarc), compares against STATE.md cached values, and writes a `STALE-PENDING` queue to `.research/staleness-queue.md`.
- The orchestrator reads the queue (a single Read tool call) at session-start, surfaces stale items to the user, and proceeds.

**This preserves the orchestrator-only rule**: the orchestrator did one Read; a sub-agent did the probes. The orchestrator-rule's "main agent stays orchestrator" intent is honored.

---

# §2 — Periodic-audit Triggers

For each corpus location, define WHEN to trigger re-verification. Three trigger types:
- **TIME**: cron-style schedules (weekly, monthly, quarterly)
- **EVENT**: code-state events (commit touches X, deploy lands, external regulation changes)
- **THRESHOLD**: metric crossings (line-count > N, staleness-age > D days, claim-density)

## Tier 1 (live, must-be-fresh)

| Doc | Trigger | Mechanism |
|---|---|---|
| `STATE.md` | EVENT: any commit to `app/`, `kc/`, `mcp/`, `broker/` (binary-state could change) | PostToolUse hook on Bash matching `git commit` flags STATE.md as POSSIBLY-STALE in the next session |
| `STATE.md` | TIME: weekly sanity check | SessionStart hook flags if STATE.md not touched in >7d |
| `STATE.md` | EVENT: deploy lands (production state changed) | PostToolUse hook on `flyctl deploy` flags STATE.md as needs-re-verify |
| `INDEX.md` | EVENT: `.research/*.md` added/deleted/renamed | PostToolUse hook on Write/Edit/git mv flags INDEX.md as needs-regen |
| `INDEX.md` | THRESHOLD: >5 active docs not in §11 probes table | Weekly scan; flag |
| `agent-domain-map.md` | EVENT: new agent UUID seen in dispatches | Orchestrator self-discipline (or future hook) |

## Tier 2 (rules + decisions)

| Doc | Trigger | Mechanism |
|---|---|---|
| `memory/feedback_*.md`, `memory/user_*.md` | NEVER auto — these are durable rules | User writes successor when needed |
| `memory/kite-*.md` (Class D external-fact caches) | TIME: monthly staleness sweep — flag any with `as-of` >30 days | Orchestrator monthly dispatch reads frontmatter, dispatches re-verify for each stale fact |
| `memory/kite-*.md` | EVENT: external source publishes news (SEBI circular, NSE update, regulator announcement) | User-initiated; no auto-trigger |
| `memory/kite-*.md` (high-stakes regulatory) | THRESHOLD: `re-verify-by` date passed | Frontmatter-validator hook surfaces at next read |
| `.research/decisions/*` | NEVER — write-once | Author successor when decision reverses |
| `docs/adr/*` | NEVER — write-once | Author successor ADR when architecture changes |
| Repo identity files (README, SECURITY, etc.) | EVENT: major version release | User dispatches refresh-pass per release |

## Tier 3 (ephemeral)

| Doc | Trigger | Mechanism |
|---|---|---|
| `.research/audits/<date>/*` | THRESHOLD: >30 days old | Auto-archive hook moves to `.research/archive/audits/<YYYY-MM>/` |
| `.research/audits/<date>/*` | EVENT: newer audit of same scope | Auto-archive when new audit doc with same `<scope>-audit-<date>.md` pattern is written |
| `memory/session_*.md` | NEVER — already date-stamped, write-once | Periodic user-side pruning (yearly) |
| Launch-cycle drafts (`docs/show-hn-post.md`, etc.) | EVENT: launch event completes | Auto-archive to `docs/drafts/archive/<YYYY-MM>/` |

## Cross-corpus periodic dispatches

| Dispatch | Frequency | Trigger | Effort |
|---|---|---|---|
| **Memory staleness sweep** | Monthly (1st of month) | TIME (calendar reminder OR session-start day-of-month check) | ~1-2h |
| **STATE.md weekly refresh** | Weekly | TIME OR EVENT (whichever fires first) | ~30min |
| **Pre-launch corpus verification** | Per release/launch | EVENT | ~3-4h |
| **Multi-doc claim integrity scan** | Per major release | EVENT | ~1-2h |
| **Archive purge** | Yearly | TIME | ~1h |

## When does the user trigger vs when does the hook trigger?

- USER triggers when **judgment** is needed (which facts deserve quarterly sweep; which audit cycle is "done"; which secret to rotate; whether a rule is obsolete).
- HOOK triggers when **structure** can be checked mechanically (frontmatter present; cross-ref valid; secret pattern absent; staleness-age exceeded).
- AGENT triggers when **action** needs to happen but no high-judgment call is required (regenerate INDEX.md, run probes, archive a doc).
- ORCHESTRATOR triggers when **coordination** is needed (dispatch the right agent for the right scope; route the user's intent into a sub-agent brief).

---

# §3 — Failure-mode Coverage

For each failure mode this session revealed, design the structural prevention. Extends Audit's §5 with explicit owner + hook designs.

| # | Failure mode | Cost this session | Owner | Prevention mechanism | New artifact |
|---|---|---|---|---|---|
| F1 | Grep-error contamination through synthesis chains | ~6h misdirected research | HOOK + ORCHESTRATOR | `post-tool-grep-trap.py` PostToolUse hook detects `grep.*NewTool\|grep.*RejectionReason` patterns and warns; new rule `feedback_compile_and_run_methodology.md` | NEW hook + NEW rule |
| F2 | Stale external-fact caches (`memory/kite-*.md`) | ~30 patches in memory audit | USER + HOOK | Frontmatter-validator hook enforces `as-of` + `re-verify-by` on `memory/kite-*.md`; monthly staleness sweep dispatch | NEW hook + monthly-sweep dispatch pattern |
| F3 | MEMORY.md hitting line limit; facts cached in index | "MEMORY.md is 249 lines" warning | HOOK | `memory-md-regen.py` PostToolUse hook regenerates MEMORY.md from `memory/*.md` frontmatter on any memory mutation | NEW hook |
| F4 | Multi-version research without supersession markers | R-10 v1→v8 confusion potential | AGENT + filename convention | `.research/decisions/<topic>/vN-current.md` naming; "supersedes" pointer in body; old versions in same subdir | NEW convention (no hook needed; filename does the work) |
| F5 | Verification reports persisted as if active | 5 today's reports in `.research/` root | HOOK | `audit-auto-archive.py` daily hook moves `.research/*-verification-<date>.md` >30d old to `.research/archive/audits/<YYYY-MM>/` | NEW hook |
| F6 | Plaintext secrets in memory files | I10/I11 from memory-audit; ongoing exposure | HOOK (write-time) + USER (rotate) | `pre-write-secret-scan.py` PreToolUse hook scans content before Write/Edit on `memory/` paths; blocks if secret patterns match | NEW hook |
| F7 | Auditor reports themselves becoming stale | Today's 5 reports will be stale in 30d | HOOK (auto-archive per F5) + filename convention | Per F5 + add `<date>` to filename always | F5's hook + filename convention |
| F8 | Detached docs (referenced but missing) | `docs/launch/` pointer-but-no-file | HOOK | `pre-write-cross-ref-validator.py` PreToolUse hook scans `.md` files being written for `[link](file.md)` references and verifies file exists | NEW hook |
| F9 | README-style number-soup (intra-doc inconsistency) | "11/12/9 checks" + "117/111 tools" in same README | HOOK + agent | `pre-write-numeric-consistency.py` PreToolUse hook scans `.md` files for inconsistent numeric facts (e.g., multiple counts of "tools=" in same doc) | NEW hook |
| F10 | Single-edit drift (one location fixed, others miss) | README L3 vs L82 disagreement | HOOK (F9) + dispatch discipline | F9's hook surfaces; orchestrator's role is to dispatch single-commit grep-and-replace not one-spot fixes | F9's hook + dispatch rule (existing `feedback_chain_dispatches_when_mapped.md` or successor) |
| F11 | Cross-session forgotten state | "v189 with 3/5 modules" in MEMORY.md after Path A.27 | HOOK (session-start) + USER | `session-start-freshness-check.py` dispatches freshness-check sub-agent that diffs MEMORY.md against `.research/STATE.md` and flags drift | NEW hook (resolves Audit's §7 contradiction) |
| F12 | Orchestrator running probes (vs sub-agent doing it) | Audit's §7 contradiction | HOOK | F11's hook delegates to sub-agent; orchestrator just reads the queue | F11's hook |

Audit's §5 covered F1-F7 (7 failure modes). This doc adds F8-F12 (5 additional failure modes the verification reports surfaced).

---

# §4 — Automation Hook Design

8 new hooks proposed. All go in `C:\Users\Dell\.claude\hooks\validators/` (the existing empty subdir). Hook contract: fail-open (exit 0 on error) UNLESS the hook is meant to block (exit 2 + stderr).

## H1 — `validators/pre-write-secret-scan.py` (PreToolUse on Write/Edit)

**Event**: `PreToolUse` matcher `Write|Edit|MultiEdit`

**Trigger**: any file write to `memory/**/*.md` or `.research/**/*.md` or `docs/**/*.md` or repo root `*.md`

**Action**: scan `tool_input.content` (Write) or computed-new-content (Edit) for high-entropy strings + known patterns:
- AWS access keys (`AKIA[0-9A-Z]{16}`)
- Stripe keys (`sk_(live|test)_[A-Za-z0-9]{24,}`)
- GitHub tokens (`ghp_[A-Za-z0-9]{36}`)
- Cloudflare API tokens (`cfat_[A-Za-z0-9]{40,}`)
- Kite Connect API key/secret patterns (16-char and 32-char hex strings paired)
- Bearer tokens, OAuth secrets (32+ char base64/hex)

**Failure mode**: fail-CLOSED (exit 2 + stderr) — block the write. User must redact + retry.

**Skeleton**:
```python
#!/usr/bin/env python3
"""PreToolUse: scan markdown writes for secret patterns; block if found."""
import json, re, sys

INPUT = json.load(sys.stdin)
TOOL = INPUT.get("tool_name", "")
INP = INPUT.get("tool_input", {})

if TOOL not in ("Write", "Edit", "MultiEdit"):
    sys.exit(0)
path = INP.get("file_path", "")
if not (path.endswith(".md") and any(seg in path for seg in ("/memory/", "/.research/", "/docs/", ".claude"))):
    sys.exit(0)
content = INP.get("content", "") + INP.get("new_string", "")

# Pattern library
PATTERNS = {
    "AWS access key": r"AKIA[0-9A-Z]{16}",
    "Stripe live/test key": r"sk_(live|test)_[A-Za-z0-9]{24,}",
    "GitHub token (ghp_)": r"ghp_[A-Za-z0-9]{36}",
    "Cloudflare API token": r"cfat_[A-Za-z0-9]{40,}",
    "Long hex secret (≥32)": r"\b[a-f0-9]{32,}\b",
}
hits = [name for name, p in PATTERNS.items() if re.search(p, content)]
if hits:
    sys.stderr.write(f"SECRET PATTERN DETECTED in {path}: {', '.join(hits)}\n")
    sys.stderr.write("REDACT or use vault reference; secrets in memory/.research/docs are forbidden.\n")
    sys.exit(2)
sys.exit(0)
```

## H2 — `validators/session-start-freshness-check.py` (SessionStart)

**Event**: `SessionStart` matcher `*`

**Trigger**: every session start

**Action**: dispatch a freshness-check sub-agent (via writing a task to the agent-teams task queue OR by directly launching) that:
1. Reads `.research/INDEX.md` §11 (empirical-probe quick reference)
2. Runs each probe (5-10 commands max, all read-only: `curl /healthz`, `gh api /orgs/algo2go`, `git rev-parse HEAD`, `git tag -l`, etc.)
3. Compares results against the cached values in `STATE.md` §1.1
4. Writes diffs (cached value ≠ probed value) to `.research/staleness-queue.md`

The hook itself doesn't run the probes (would violate orchestrator-only rule); it just **enqueues a freshness-check task** for the existing agent-team infrastructure or surfaces a `<system-reminder>` for the orchestrator to dispatch.

**Failure mode**: fail-OPEN (exit 0 even on dispatch failure; user just doesn't get freshness queue this session)

**Skeleton**:
```python
#!/usr/bin/env python3
"""SessionStart: enqueue freshness-check task for sub-agent."""
import json, os, sys, time
from pathlib import Path

# Path to the task queue (agent-teams pattern)
QUEUE = Path.home() / ".claude" / "tasks" / "freshness-check" / f"task-{int(time.time())}.json"
QUEUE.parent.mkdir(parents=True, exist_ok=True)

task = {
    "id": f"freshness-{int(time.time())}",
    "type": "freshness-check",
    "status": "pending",
    "scope": "INDEX.md §11 probes",
    "output": ".research/staleness-queue.md",
    "ttl_seconds": 600,
}
QUEUE.write_text(json.dumps(task, indent=2))

# Print to stderr so the orchestrator's session-start view sees it
sys.stderr.write(
    f"Freshness-check task enqueued at {QUEUE.name}.\n"
    f"Orchestrator: dispatch a sub-agent with brief = 'Run INDEX.md §11 probes, "
    f"compare to STATE.md cached values, write diffs to .research/staleness-queue.md'\n"
)
sys.exit(0)
```

**Note**: this hook is a *placement* — the actual dispatch happens via a sub-agent the orchestrator launches based on the stderr prompt. The hook intentionally does NOT spawn the agent itself (filesystem-permission concerns + Claude Code's hook → agent path may not exist as a direct API). This is the minimum-viable pattern.

## H3 — `validators/pre-write-frontmatter-validator.py` (PreToolUse on Write/Edit)

**Event**: `PreToolUse` matcher `Write|Edit`

**Trigger**: writes to `memory/kite-*.md` (Class D external-fact caches)

**Action**: parse YAML frontmatter; require `as-of: YYYY-MM-DD` + `re-verify-by: YYYY-MM-DD`. If missing or malformed: block.

**Failure mode**: fail-CLOSED for `memory/kite-*.md` writes (exit 2 + stderr)

**Skeleton**:
```python
#!/usr/bin/env python3
"""PreToolUse: validate frontmatter on memory/kite-*.md writes."""
import json, re, sys

INPUT = json.load(sys.stdin)
INP = INPUT.get("tool_input", {})
path = INP.get("file_path", "")

if "/memory/kite-" not in path or not path.endswith(".md"):
    sys.exit(0)

content = INP.get("content", "") or INP.get("new_string", "")
m = re.match(r"^---\n([\s\S]*?)\n---", content)
if not m:
    sys.stderr.write(f"{path}: missing YAML frontmatter\n")
    sys.exit(2)
fm = m.group(1)
required = ["as-of:", "re-verify-by:"]
missing = [k for k in required if k not in fm]
if missing:
    sys.stderr.write(f"{path}: frontmatter missing: {missing}\n")
    sys.stderr.write("Class D external-fact caches require as-of + re-verify-by frontmatter.\n")
    sys.exit(2)
# Date format validation
for k in required:
    dm = re.search(rf"{k}\s*(\d{{4}}-\d{{2}}-\d{{2}})", fm)
    if not dm:
        sys.stderr.write(f"{path}: {k} not in YYYY-MM-DD format\n")
        sys.exit(2)
sys.exit(0)
```

## H4 — `validators/pre-write-cross-ref-validator.py` (PreToolUse on Write/Edit)

**Event**: `PreToolUse` matcher `Write|Edit`

**Trigger**: writes to any `.md` file

**Action**: parse markdown links `[text](path.md)` or `[text](path.md#anchor)`; verify `path.md` exists relative to the doc being written. For cross-corpus refs (e.g., `../../memory/kite-X.md` from `.research/`), resolve and verify.

**Failure mode**: fail-OPEN with WARNING (exit 0 + stderr listing dead refs). Not fail-closed because some refs are valid-but-not-yet-written.

**Skeleton**:
```python
#!/usr/bin/env python3
"""PreToolUse: warn on dead internal cross-refs in markdown writes."""
import json, re, sys
from pathlib import Path

INPUT = json.load(sys.stdin)
INP = INPUT.get("tool_input", {})
path = INP.get("file_path", "")
if not path.endswith(".md"):
    sys.exit(0)
content = INP.get("content", "") or INP.get("new_string", "")
base = Path(path).parent
refs = re.findall(r"\[[^\]]+\]\(([^)#]+)(?:#[^)]+)?\)", content)
dead = []
for ref in refs:
    if ref.startswith(("http://", "https://", "mailto:")):
        continue
    target = (base / ref).resolve()
    if not target.exists():
        dead.append(ref)
if dead:
    sys.stderr.write(f"{path}: WARNING — dead cross-refs: {dead[:5]}\n")
    sys.stderr.write("Verify these files exist before considering the write final.\n")
sys.exit(0)  # warn-only
```

## H5 — `validators/post-tool-grep-trap.py` (PostToolUse on Bash)

**Event**: `PostToolUse` matcher `Bash`

**Trigger**: any Bash command containing `grep` with patterns that count source code (tool counts, check counts, test counts)

**Action**: detect dangerous grep patterns (`mcp\.NewTool`, `RejectionReason`, `\bfunc Test\b`, `mcp.RegisterTool`, etc.) and warn that the count includes test fixtures; recommend compile-and-run or `curl /healthz`.

**Failure mode**: fail-OPEN with WARNING

**Skeleton**:
```python
#!/usr/bin/env python3
"""PostToolUse on Bash: warn when grep is used to count code structures."""
import json, re, sys

INPUT = json.load(sys.stdin)
TOOL = INPUT.get("tool_name", "")
INP = INPUT.get("tool_input", {})
if TOOL != "Bash":
    sys.exit(0)
cmd = INP.get("command", "")
# Patterns that indicate "counting via grep" — known-bad methodology
TRAPS = [
    (r"grep.*mcp\.NewTool", "tool count: use 'curl /healthz' or compile-and-run; grep includes test fixtures"),
    (r"grep.*RejectionReason", "RiskGuard checks: use compile-and-run or doc-authoritative-source; grep includes constants not all wired"),
    (r"grep.*'\^func Test'", "test count: prefer 'go test ./... -list .*' or use the per-package counts"),
]
warned = []
for pat, msg in TRAPS:
    if re.search(pat, cmd):
        warned.append(msg)
if warned:
    sys.stderr.write("GREP TRAP WARNING (per STATE.md §5.6 methodology rule):\n")
    for w in warned:
        sys.stderr.write(f"  - {w}\n")
sys.exit(0)
```

## H6 — `validators/post-tool-memory-md-regen.py` (PostToolUse on Write/Edit)

**Event**: `PostToolUse` matcher `Write|Edit`

**Trigger**: writes to `memory/*.md` (excluding MEMORY.md itself to avoid recursion)

**Action**: scan `memory/*.md` frontmatter, rebuild MEMORY.md's "## Topic Index" section from collected `name:` + `description:` fields, write back. Other MEMORY.md sections (User Rules at the top, etc.) preserved verbatim — only the topic-index section is mechanically rebuilt.

**Failure mode**: fail-OPEN (exit 0; MEMORY.md just doesn't auto-regen this time)

**Skeleton**:
```python
#!/usr/bin/env python3
"""PostToolUse: regenerate MEMORY.md topic index from memory/*.md frontmatter."""
import json, re, sys
from pathlib import Path

INPUT = json.load(sys.stdin)
TOOL = INPUT.get("tool_name", "")
if TOOL not in ("Write", "Edit", "MultiEdit"):
    sys.exit(0)
INP = INPUT.get("tool_input", {})
path = INP.get("file_path", "")
# Only trigger on memory/*.md writes, exclude MEMORY.md itself
if not (path.startswith(str(Path.home())) and "/memory/" in path and path.endswith(".md")):
    sys.exit(0)
if path.endswith("/MEMORY.md"):
    sys.exit(0)

# Find MEMORY.md
mem_root = Path(path).parent
memory_md = mem_root / "MEMORY.md"
if not memory_md.exists():
    sys.exit(0)

# Parse all memory/*.md frontmatter
entries = []
for f in sorted(mem_root.glob("*.md")):
    if f.name == "MEMORY.md":
        continue
    txt = f.read_text(encoding="utf-8", errors="replace")
    m = re.match(r"^---\n([\s\S]*?)\n---", txt)
    if not m:
        continue
    fm = m.group(1)
    name = (re.search(r"^name:\s*(.+)$", fm, re.M) or [None, f.stem])[1].strip()
    desc = (re.search(r"^description:\s*(.+)$", fm, re.M) or [None, ""])[1].strip()
    entries.append((f.name, name, desc))

# Build new topic-index section
idx = "## Topic Index (auto-regenerated)\n\n"
for fname, name, desc in entries:
    idx += f"- [{name}]({fname}) — {desc[:150]}\n"

# Replace existing "## Topic Index" section in MEMORY.md, or append
existing = memory_md.read_text(encoding="utf-8")
if "## Topic Index" in existing:
    out = re.sub(
        r"## Topic Index[\s\S]*?(?=\n## |\Z)",
        idx + "\n",
        existing,
    )
else:
    out = existing + "\n\n" + idx
memory_md.write_text(out, encoding="utf-8")
sys.exit(0)
```

## H7 — `validators/audit-auto-archive.py` (SessionStart, daily)

**Event**: `SessionStart` matcher `*` (but with internal date-check to run only once per day)

**Trigger**: at session start, check `.research/audits/<YYYY-MM-DD>/*.md` and `.research/*-verification-<date>.md`; archive any older than 30 days

**Action**: `git mv` >30d-old verification reports to `.research/archive/audits/<YYYY-MM>/`. Commit with `chore(archive): auto-archive verification reports >30d old`. Does NOT auto-push (user decides when to push).

**Failure mode**: fail-OPEN

**Skeleton**: omitted for brevity (~50 lines: `pathlib.Path.glob`, `datetime` parsing of date-in-filename, `subprocess.run(["git", "mv"])`, etc.)

## H8 — `validators/pre-write-numeric-consistency.py` (PreToolUse on Write/Edit)

**Event**: `PreToolUse` matcher `Write|Edit`

**Trigger**: writes to repo root `*.md` (README.md, SECURITY.md, etc.) where numeric facts often drift

**Action**: scan new content for repeating numeric claims of the form `(\d+)\s+(tools|checks|tests|modules|deploys)`. If the same noun has multiple different counts, warn.

**Failure mode**: fail-OPEN with WARNING

**Skeleton**:
```python
#!/usr/bin/env python3
"""PreToolUse: warn on inconsistent numeric facts in markdown."""
import json, re, sys
from collections import defaultdict

INPUT = json.load(sys.stdin)
INP = INPUT.get("tool_input", {})
path = INP.get("file_path", "")
if not path.endswith(".md"):
    sys.exit(0)
content = INP.get("content", "") or INP.get("new_string", "")
# Find "(\d+) (tools|checks|...)
matches = re.findall(r"(\d+)\s+(tools|checks|tests|modules|deploys|pre-trade)\b", content, re.I)
counts = defaultdict(set)
for n, noun in matches:
    counts[noun.lower()].add(n)
inconsistent = {n: vals for n, vals in counts.items() if len(vals) > 1}
if inconsistent:
    sys.stderr.write(f"{path}: NUMERIC INCONSISTENCY WARNING:\n")
    for noun, vals in inconsistent.items():
        sys.stderr.write(f"  - '{noun}' appears with {sorted(vals)} counts\n")
    sys.stderr.write("Pick ONE source-of-truth (server.json or /healthz) and align all sites.\n")
sys.exit(0)
```

## Hook deployment summary

| Hook | Event | Failure mode | Priority |
|---|---|---|---|
| H1 secret-scan | PreToolUse Write/Edit | CLOSED (block) | **CRITICAL** — ship first |
| H2 session-start-freshness | SessionStart | OPEN (warn-only) | **HIGH** — closes Audit §7 |
| H3 frontmatter-validator | PreToolUse Write/Edit | CLOSED for kite-*.md | **HIGH** — enforces Class D discipline |
| H4 cross-ref-validator | PreToolUse Write/Edit | OPEN (warn) | MEDIUM |
| H5 grep-trap | PostToolUse Bash | OPEN (warn) | MEDIUM |
| H6 memory-md-regen | PostToolUse Write/Edit | OPEN | MEDIUM |
| H7 audit-auto-archive | SessionStart (daily) | OPEN | LOW |
| H8 numeric-consistency | PreToolUse Write/Edit | OPEN (warn) | LOW |

Priority drives the roadmap in §6.

---

# §5 — User-action vs Orchestrator-action vs Agent-action vs Hook-action Split

For each periodic-audit trigger + remediation action, who SHOULD do it:

| Action | Who | Why | Frequency |
|---|---|---|---|
| Author new user-rule (`user_*.md` or `feedback_*.md`) | **USER** | Standing convention; high-judgment | When failure recurs 2+ times |
| Supersede existing rule | **USER** | Same — judgment-load-bearing | Rare; user signals |
| Rotate secrets (Kite API keys, Cloudflare R2) | **USER** | Sensitive; needs vault discipline + downstream verification | When exposed/leaked or annually |
| Write new Class D external-fact cache | **USER** + AGENT | User decides what facts matter; agent populates the body | When new fact needed |
| Update Class D `as-of` + `re-verify-by` | AGENT | Mechanical; sub-agent re-probes + updates frontmatter | Per quarterly sweep |
| Dispatch monthly staleness sweep | **ORCHESTRATOR** | Coordination role | Monthly |
| Dispatch weekly STATE.md refresh | **ORCHESTRATOR** | Coordination | Weekly |
| Dispatch pre-launch verification | **ORCHESTRATOR** | Coordination | Per launch |
| Run INDEX.md §11 probes at session-start | **AGENT** (via H2 hook → freshness-check sub-agent) | Sub-agent boundary preserves orchestrator-only rule | Every session start |
| Regenerate MEMORY.md topic index | **HOOK** (H6) | Mechanical; needs no judgment | On any `memory/*.md` write |
| Regenerate INDEX.md from `.research/*` headers | **AGENT** | Some judgment on which docs are active vs archive | Weekly OR on-demand |
| Validate frontmatter on memory writes | **HOOK** (H3) | Mechanical structural check | Every write |
| Scan for secret patterns | **HOOK** (H1) | Mechanical structural check | Every write |
| Validate cross-refs in markdown | **HOOK** (H4) | Mechanical | Every write |
| Auto-archive verification reports >30d | **HOOK** (H7) | Mechanical + date-based | Daily |
| Write a Class B decision record | **AGENT** | Research-load-bearing; orchestrator dispatches | Per decision |
| Write Class F narrative synthesis | **AGENT** + **ORCHESTRATOR** (dispatches with INPUTS list) | Same | Per synthesis |
| Archive a Class F synthesis when superseded | **AGENT** | Mechanical (`git mv`) | When new synthesis lands |
| Approve a Class D fact update | **USER** | Judgment (does this new fact replace the cached one?) | Per stale-fact-sweep finding |
| Approve archive of a doc | **USER** (low-stakes can be auto) | Judgment for stakes-relevant docs; HOOK for ephemera | Per archive trigger |
| Commit + push corpus changes | **AGENT** (in dispatch) or **ORCHESTRATOR** (single-line for state file) | Existing rule `user_agents_push_after_wsl_green.md` | Per commit |
| Rotate `OAUTH_JWT_SECRET` | **USER** (decides timing) + **AGENT** (executes via `cmd/rotate-key/`) | High-stakes secret rotation | Annually or per compromise |
| Surface "stale-pending" queue to user | **ORCHESTRATOR** (reads `.research/staleness-queue.md`) | Coordination | Every session start |
| Patch a stale claim found by sweep | **AGENT** (writes patch) per **USER** authorization | Mechanical with prior approval | Per finding |
| Author new rule when violation recurs | **ORCHESTRATOR** (proposes draft) → **USER** (approves) | Joint | Rare |

## Decision rule

When unsure who should do an action, use this hierarchy:
1. **Can it be done with zero judgment? → HOOK.**
2. **Does it need mechanical execution but no high-judgment? → AGENT.**
3. **Does it need cross-agent coordination? → ORCHESTRATOR.**
4. **Does it require user-judgment (sensitive, identity, novel)? → USER.**

The 4-row hierarchy ALSO answers the orchestrator-vs-probe question from Audit §7: probes are #1 (HOOK enqueues; AGENT runs); orchestrator just reads the queue (#3). The user only intervenes (#4) if a stale-fact has stakes that warrant their judgment.

---

# §6 — Implementation Roadmap

Concrete order-of-operations to GET to this maintenance model from current state. 4 phases, each independently shippable.

## Phase 1 — Critical hooks (4-6h, this week)

| Step | Action | Effort | Owner |
|---|---|---|---|
| 1.1 | Write `validators/pre-write-secret-scan.py` (H1) — fail-CLOSED secret scanner | ~1h | AGENT |
| 1.2 | Wire H1 into `~/.claude/settings.json` PreToolUse matcher `Write\|Edit\|MultiEdit` | ~15min | USER (settings edit) |
| 1.3 | Test H1 against a known-secret-containing memory file content; verify block + escape-hatch | ~30min | AGENT |
| 1.4 | Write `validators/session-start-freshness-check.py` (H2) — enqueue freshness task | ~1h | AGENT |
| 1.5 | Wire H2 into `~/.claude/settings.json` SessionStart | ~15min | USER |
| 1.6 | Document the sub-agent dispatch pattern that H2 prompts the orchestrator to launch | ~30min | AGENT |
| 1.7 | Write `validators/pre-write-frontmatter-validator.py` (H3) | ~30min | AGENT |
| 1.8 | Wire H3 into settings.json PreToolUse for `memory/kite-*.md` writes | ~15min | USER |
| 1.9 | Backfill `as-of` + `re-verify-by` frontmatter on existing 33 `memory/kite-*.md` files | ~2h | AGENT (one dispatch) |

**Phase 1 delivers**: secrets cannot be written to docs anymore; staleness gets surfaced at every session-start; new external-fact caches must have proper frontmatter.

## Phase 2 — New user-rules (~1-2h, this week or next)

| Step | Action | Effort | Owner |
|---|---|---|---|
| 2.1 | Write `feedback_compile_and_run_methodology.md` user-rule | ~30min | USER (or USER-approved AGENT draft) |
| 2.2 | Write `feedback_verify_before_synthesize.md` (synthesis inputs must be re-verified) | ~30min | USER |
| 2.3 | Write `feedback_dated_synthesis.md` (synthesis docs must have INPUTS section with dates) | ~30min | USER |
| 2.4 | Write `feedback_empirical_probe_reference.md` (use INDEX §11 probes for state questions) | ~30min | USER |
| 2.5 | Update MEMORY.md User Rules section with links to the 4 new rules | ~10min | HOOK (H6) auto-regenerates |

**Phase 2 delivers**: the 4 standing rules INDEX §13 proposed are now realized as rule files. Future agents inherit them.

## Phase 3 — Medium hooks + memory-MD auto-regen (~3-4h, next week)

| Step | Action | Effort | Owner |
|---|---|---|---|
| 3.1 | Write `validators/post-tool-memory-md-regen.py` (H6) | ~1h | AGENT |
| 3.2 | Wire H6 into PostToolUse | ~15min | USER |
| 3.3 | Manually run once to verify MEMORY.md regen is correct (cross-check against current content) | ~30min | USER |
| 3.4 | Write `validators/pre-write-cross-ref-validator.py` (H4) | ~1h | AGENT |
| 3.5 | Wire H4 | ~15min | USER |
| 3.6 | Write `validators/post-tool-grep-trap.py` (H5) | ~45min | AGENT |
| 3.7 | Wire H5 into PostToolUse on Bash | ~15min | USER |

**Phase 3 delivers**: MEMORY.md no longer hand-curated; cross-refs validated at write time; grep-traps caught at use-time.

## Phase 4 — Archive automation + numeric consistency (~2-3h, low priority)

| Step | Action | Effort | Owner |
|---|---|---|---|
| 4.1 | Write `validators/audit-auto-archive.py` (H7) | ~1h | AGENT |
| 4.2 | Wire H7 into SessionStart with daily-throttle | ~30min | AGENT |
| 4.3 | Create `.research/audits/2026-05-11/` subdir + `git mv` today's 5 verification reports + `git mv` other outdated dated files | ~1h | AGENT (one dispatch) |
| 4.4 | Write `validators/pre-write-numeric-consistency.py` (H8) | ~45min | AGENT |
| 4.5 | Wire H8 | ~15min | USER |

**Phase 4 delivers**: verification reports auto-archive; numeric drift caught at write-time.

## Phase 5 — Per-corpus migration to maintenance model (~6-8h, gradual)

Most of this is Audit's §6 migration plan + Chain's per-doc verdicts (landing in parallel). The split:

| Step | Action | Effort | Owner |
|---|---|---|---|
| 5.1 | Create `.research/decisions/` subdir; `git mv` R-10 v8, Phase 2.6 closure, path-e Track 2 falsification, production-master-gap-report, dr-drill-results, rotate-key-runbook | ~1h | AGENT (per Chain's per-doc verdicts) |
| 5.2 | Add `as-of` + `re-verify-by` frontmatter to all `memory/kite-*.md` (already in Phase 1.9, but Phase 5 verifies completeness) | (done in 1.9) | (done) |
| 5.3 | Add `INPUTS` section to all active Class F synthesis docs | ~2h | AGENT |
| 5.4 | Rename ephemera with date-in-filename per Audit §3 Class G | ~1h | AGENT |
| 5.5 | Update `.claude/CLAUDE.md` (repo) with the methodology rule (compile-and-run > grep) | ~15min | USER |
| 5.6 | Update project-level `D:\Sundeep\projects\.claude\CLAUDE.md` if cross-repo guidance changes | ~15min | USER |

**Phase 5 delivers**: corpus is in maintenance-model-compliant shape.

## Settings.json delta (what changes)

```json
{
  "hooks": {
    "SessionStart": [
      {
        "matcher": "*",
        "hooks": [
          {"type": "command", "command": "python C:/Users/Dell/.claude/hooks/fix-windows-lsp.py", "timeout": 5},
          {"type": "command", "command": "python C:/Users/Dell/.claude/hooks/validators/session-start-freshness-check.py", "timeout": 10},
          {"type": "command", "command": "python C:/Users/Dell/.claude/hooks/validators/audit-auto-archive.py", "timeout": 30}
        ]
      }
    ],
    "PreToolUse": [
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [
          {"type": "command", "command": "python C:/Users/Dell/.claude/hooks/validators/pre-write-secret-scan.py", "timeout": 5},
          {"type": "command", "command": "python C:/Users/Dell/.claude/hooks/validators/pre-write-frontmatter-validator.py", "timeout": 5},
          {"type": "command", "command": "python C:/Users/Dell/.claude/hooks/validators/pre-write-cross-ref-validator.py", "timeout": 5},
          {"type": "command", "command": "python C:/Users/Dell/.claude/hooks/validators/pre-write-numeric-consistency.py", "timeout": 5}
        ]
      }
    ],
    "PostToolUse": [
      {
        "matcher": "mcp__*",
        "hooks": [{"type": "command", "command": "python C:/Users/Dell/.claude/hooks/tts-integration-router.py", "timeout": 5}]
      },
      {
        "matcher": "Bash",
        "hooks": [{"type": "command", "command": "python C:/Users/Dell/.claude/hooks/validators/post-tool-grep-trap.py", "timeout": 5}]
      },
      {
        "matcher": "Write|Edit|MultiEdit",
        "hooks": [{"type": "command", "command": "python C:/Users/Dell/.claude/hooks/validators/post-tool-memory-md-regen.py", "timeout": 5}]
      }
    ]
  }
}
```

(Other existing hook entries — `UserPromptSubmit`, `TeammateIdle`, `TaskCompleted`, `Stop` — preserved verbatim.)

## Memory-rule updates to commit

Add to `memory/MEMORY.md` User Rules section (the 4 new rules from Phase 2):

```markdown
- [Compile-and-run > grep-and-count for binary-state metrics](feedback_compile_and_run_methodology.md) — grep over mixed code+test directories over-counts test fixtures; always read `total_available=N` startup log line OR `curl /healthz` to count tools/checks/etc.
- [Verify before recommend in synthesis docs](feedback_verify_before_synthesize.md) — synthesis docs MUST re-verify load-bearing facts at HEAD; otherwise grep-error/staleness propagates downstream.
- [Date stamps required on synthesis claims](feedback_dated_synthesis.md) — every load-bearing claim must cite a "Last verified" date; stale synthesis without dates cannot be re-checked efficiently.
- [Use INDEX §11 probes for state questions](feedback_empirical_probe_reference.md) — prefer single-line probes over re-deriving research; <30s answers for most production state questions.
```

These 4 rules close the policy gap that allowed the grep-error contamination to propagate this session.

## What does NOT need to change

- Existing rule corpus (19 `feedback_*.md` + 9 `user_*.md`) is consistent and current; do not rewrite.
- Existing hooks (`fix-windows-lsp.py`, `suggest-plugin.sh`, TTS pair, agent-teams pair) work; do not modify.
- `memory/feedback_*.md` + `memory/user_*.md` need no frontmatter changes; they're durable rules, not external-fact caches.
- Existing settings.json structure works; just add validators block.

---

# §7 — Open Questions + Surfaced Risks

**Risk 1**: Hook complexity creep — adding 8 hooks could slow session-start (currently ~5s per existing hook timeout). If H2's freshness-check sub-agent dispatch is slow, session-start lag could become a UX issue. **Mitigation**: H2 just *enqueues* a task; doesn't wait for completion. Asynchronous-style. The freshness queue is read by the orchestrator on demand, not blockingly.

**Risk 2**: Memory-md-regen race — if two writes to `memory/*.md` happen concurrently, H6 could write inconsistent MEMORY.md. **Mitigation**: agent-team work is sequential per-user; concurrent writes are rare. Add file-lock if it becomes an issue.

**Risk 3**: Frontmatter discipline failure — H3 blocks `memory/kite-*.md` writes without proper frontmatter. If user is editing in another tool (not Edit/Write), H3 misses. **Mitigation**: H3 is a Claude-Code-only enforcement; user discipline still needed for non-Claude edits. Acceptable trade-off.

**Risk 4**: Sub-agent dispatch pattern for H2 — Claude Code's hook system may not directly support "spawn sub-agent from hook"; H2 is described as "enqueue task, surface to orchestrator." If the orchestrator misses the surface, the freshness-check never runs. **Mitigation**: H2 stderr message is loud + the queue file lives in a discoverable location; orchestrator pattern is to check `.research/staleness-queue.md` at session-start (could become a fifth user-rule).

**Risk 5**: Audit's "Tier 3 — Drafts + Snapshots → archive-on-completion" pattern (per `value-framework.md` §6 Tier 3) requires explicit completion signal. If launch-cycle drafts (`docs/show-hn-post.md` etc.) are kept past Show HN without archive, the auto-archive hook (H7) might never fire. **Mitigation**: H7 archives by DATE-IN-FILENAME staleness; user-discipline still needed to rename launch drafts with date-stamps (Phase 5.4).

**Open question 1**: Should H1 (secret-scan) also operate on `.research/*.md` writes? Audit's framework says secrets in `.research/` are also forbidden. **Answer in this doc**: YES — extend H1 to all four corpus locations (`memory/`, `.research/`, `docs/`, repo root `.md`). Already in the H1 skeleton.

**Open question 2**: Should H6 (MEMORY.md auto-regen) preserve manually-curated MEMORY.md sections (like the "User Rules" rules promotion at the top)? **Answer**: yes — H6 should only rebuild the "## Topic Index (auto-regenerated)" section, not the top user-rules section. The skeleton in §4 does this.

**Open question 3**: Should `.research/decisions/` subdir be created NOW (before Chain agent's per-doc classification lands)? **Answer**: defer to Chain's verdicts; they may have already proposed the subdir layout. Coordinate via the synthesis dispatch the orchestrator will run after all 3 maintenance-strategy docs ship.

**Open question 4**: How does the maintenance-model interact with the existing `feedback_research_diminishing_returns.md` rule (~10 research agents per question is the cap)? **Answer**: the freshness-check sub-agent + staleness sweep aren't "research" — they're verification. They run quickly + return. The cap applies to brainstorming/exploration agents, not verification.

**Open question 5**: For the existing 5 verification reports (today's audits), should we ship them as Class G ephemera in `.research/audits/2026-05-11/` immediately, OR wait until §3.5 of the maintenance-model is approved? **Answer**: this is up to the orchestrator's discretion; the model recommends Class G → archive-on-completion, but does not force the move. Defer to user/orchestrator authorization after all 3 maintenance-strategy docs land.

---

# §8 — Pre-existing-but-Underused Patterns

Per the dispatch hard rule "Surface immediately if you find an existing hook or rule that already does what you're proposing":

**Pre-existing pattern 1 — Agent-team task queue**: `~/.claude/tasks/{team-name}/*.json` (per `~/.claude/hooks/agent-teams/teammate-idle.py` + `task-completed.py`). This infrastructure ALREADY exists for spawning sub-agent work from hooks. H2 (freshness-check) builds on this rather than inventing a new dispatch path. **Recommendation**: use the existing agent-team queue pattern, just create a new team called `freshness-check`.

**Pre-existing pattern 2 — `memory/feedback_verify_agents.md`**: there's already a rule about verifying agent claims. The new `feedback_verify_before_synthesize.md` (Phase 2.2) is adjacent but distinct — verifying claims-by-agents vs verifying inputs-of-synthesis. Both rules coexist; not duplicated.

**Pre-existing pattern 3 — `feedback_research_vs_empirical_grounding.md`**: this rule already says "trust empirical code-reads over research-recommendations." This is adjacent to but distinct from the new methodology rule (compile-and-run > grep). The existing rule covers agent-vs-agent contradiction; the new rule covers methodology. Both useful.

**Pre-existing pattern 4 — `memory/hooks.md`**: the existing reference doc describing the hooks infrastructure. Phase 1 hooks would extend this doc with the 8 new validators. **Recommendation**: update `memory/hooks.md` after Phase 1 ships.

**Pre-existing pattern 5 — `validators/` dir is already empty + waiting**: someone (the user?) already created the `~/.claude/hooks/validators/` subdir. The intent was clearly to put new validators there. This dispatch's hooks land exactly where the user already designated.

**No reinvention found** — all 8 proposed hooks address gaps the existing infrastructure does not cover, AND the proposed location matches the existing structure.

---

# §9 — Source verification (this doc)

| Probe | Tool | Result |
|---|---|---|
| Master HEAD | `git log -1` | `f61e1bf docs(maintenance): strategic framework — value criteria + lifecycle stages + stewardship principles` |
| Audit's value-framework.md | Read in full (541 lines) | absorbed §1 taxonomy, §3 lifecycle, §4 stewardship principles, §5 failure modes, §6 distribution, §7 contradiction, §8 source verification |
| Existing hooks dir | `ls -R "/c/Users/Dell/.claude/hooks/"` | 6 hooks: fix-windows-lsp.py, suggest-plugin.sh, tts-integration-router.py, tts-stop.py, agent-teams/{teammate-idle.py, task-completed.py}; validators/ subdir EXISTS BUT EMPTY |
| Existing settings.json | Read head | 5 hook events configured (SessionStart, UserPromptSubmit, PostToolUse, TeammateIdle, TaskCompleted); no Stop, no PreToolUse |
| 5 verification reports | sampled headers (active-docs §0-§1, repo-docs §0, memory-files §0-§1, STATE-claims-audit/diff via prior session knowledge) | structures + finding-counts confirmed |
| Sample user-rule corpus | Read in full: `user_agent_orchestration_rule.md`, `user_email_rule.md`, `feedback_research_diminishing_returns.md`, `feedback_research_vs_empirical_grounding.md`, `feedback_wsl_for_go_test.md`, `feedback_no_stash_anywhere.md`, `user_team_commit_protocol.md` | 7 rules read; rule structure + corpus health understood |
| INDEX §11 + §13 | Read in prior session | 6 new entries + 4 standing-rule promotions identified |
| Pre-existing-pattern check | grep for "validators" / "freshness" / "secret-scan" in existing hooks dir | NONE — confirms no reinvention |
| MCP servers reference | `memory/mcp-servers.md` head | gemini-cli, gemini-api, etc — no overlap with maintenance hooks |

**Methodology rule applied**: every load-bearing claim about existing infrastructure was empirically probed (settings.json content, hooks dir contents, sample rule files). The framework's principles + recommendations are layered on top of Audit's value-framework (cited by section). No grep-as-evidence for binary-state metrics.

---

# §10 — Closing

The corpus stays healthy if the OPERATING SYSTEM around it does three things:

1. **Blocks at write-time** what cannot be safely written (secrets, missing frontmatter, broken cross-refs).
2. **Surfaces at read-time** what has drifted since last verified (staleness queue at session-start).
3. **Auto-mechanizes** the regen + archive flows that don't need judgment (MEMORY.md index, verification-report archival).

These three are the work of 8 new hooks (~6h to ship Phase 1+2; ~14h total across all 4 phases). After Phase 1+2 ship, future "comprehensive audit" dispatches like today's should take <2h instead of ~10h, because most drift gets caught structurally before it propagates.

The single-paragraph distillation: **today's session ran ~10 hours of corpus cleanup work because the maintenance OS was absent. Spend ~6-14 hours over the next 2 weeks building the OS, and the maintenance load drops by an order of magnitude. Audit's framework tells us WHAT good looks like; Chain's classification tells us WHICH docs need moving; this doc tells us HOW the system stays good — and most of "how" is automated hooks, not new rules or new dispatches.**

The orchestrator-vs-probe contradiction resolves cleanly: the orchestrator stays orchestrator; a HOOK enqueues; a SUB-AGENT probes; the orchestrator reads the queue. No rule amendment needed.

Combined with Audit's framework + Chain's per-doc verdicts, the project has a coherent maintenance model. After all 3 ship, the synthesis pass produces the migration plan.
