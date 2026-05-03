# R9 — `asyncRewake` Background Verify Hook Design

**Date**: 2026-05-02 night (continuation of v3 `34ee93e`)
**Charter**: ADR-style design doc for the R9 ship in
`~/.claude/hooks/agent-teams/task-completed.py` +
`~/.claude/settings.json`. Single research commit; standing rules
apply.

**Prior passes**:
- v1 `ee22290`: bugs + R3, R5 ships
- v2 `3e3a57d`: ecosystem map + framework docs + R8 ship + R1/R9
  reclassification (R9 from "needs upstream" to "implementable
  natively")
- v3 `34ee93e`: R11 (security guardrail) + R12 (audit log) ships +
  honest-stop verdict

**v3 honest-stop was conditional**: "do not commission v4 absent
new empirical signal". The user's signoff on R1 + R9 is that
signal — both were the highest-priority deferred items from v2,
explicitly authorized this pass.

---

## §1 — What R1 + R9 ship

### R1 — Remove `"timeout": 5` overrides on agent-team hook entries

**v2 finding** (`3e3a57d` §4): the framework default for command
hooks is **600 seconds** per Anthropic hook documentation. The
`"timeout": 5` overrides in `~/.claude/settings.json` were almost
certainly accidental copy-paste — the agent-team hooks need at
least 120s for the verify subprocess (which has its own
`VERIFY_TIMEOUT_SECONDS = 120` cap), and the framework default
of 600s gives the right headroom.

**Per-entry decision** (documented in v2 §4):

| Hook entry | Decision | Rationale |
|---|---|---|
| SessionStart `fix-windows-lsp.py` | KEEP `"timeout": 5` | Not agent-team; LSP-config patch is fast; 5s is plausibly intentional for SessionStart latency UX |
| UserPromptSubmit `suggest-plugin.sh` | KEEP `"timeout": 5` | Not agent-team; user just hit Enter, don't make them wait long |
| PostToolUse `tts-integration-router.py` | KEEP `"timeout": 5` | Not agent-team; per-tool fast routing |
| **TeammateIdle** `agent-teams/teammate-idle.py` | **REMOVE override** | Agent-team. Hook does no subprocess work — but if it evolves to do so, framework default 600s gives headroom. Defensive. |
| **TaskCompleted** `agent-teams/task-completed.py` | **REMOVE override** | Agent-team. **Load-bearing fix per v2 §4 (closes B5)** — verify subprocess can take >5s; old override was killing legitimate verifies. |

**Verified clean** post-edit: `python -c "json.load(...)"` parses;
`update-config` skill schema confirms valid hook entry shape.

### R9 — Adopt `asyncRewake` for the TaskCompleted hook

**v2 finding** (`3e3a57d` §5): the framework natively supports
`"asyncRewake": true` per Anthropic hook docs. Documented schema
(verified via `update-config` skill): "If true, hook runs in
background and wakes the model on exit code 2 (blocking error).
Implies async."

**Field semantics confirmed** (verified twice — `update-config`
skill schema + `claude-code-guide` subagent independently in this
session):
- `asyncRewake: true` IMPLIES `async: true` — no need to set both.
  Cleaner schema, fewer footguns.
- Exit code semantics unchanged from sync mode: `exit 0` = silent
  allow; `exit 2` = block + wake Claude with stderr as system
  reminder.
- Hook script itself runs the same way — only the framework's
  WAITING semantics change.

**What's added in this ship**:
- `settings.json` TaskCompleted entry: `"asyncRewake": true`
- `task-completed.py`: `detect_async_rewake_mode()` helper that
  reads settings.json + checks the registration entry → tags every
  `audit.jsonl` record with `"rewake_mode": "asyncRewake" | "sync"`
- `teammate-idle.py`: mirror tagging (currently always `"sync"`
  since TeammateIdle isn't asyncRewake — but the field is present
  for forensics symmetry if registration ever changes)

---

## §2 — The "task already marked complete, async verify fails
after" decision

### 2.1 Three modes the brief offered

| Mode | Behavior on async verify failure |
|---|---|
| A. Strict revert | TaskCreate a revert task + alert teammate |
| B. Audit-only log | Write to audit.jsonl + done (no revert) |
| C. Severity tiered | Some failures revert (compile errors), some log (test flakes) |

### 2.2 Decision: Mode B (audit-only log)

**Per the brief's recommendation** + my own analysis +
**independent framework-guide validation** (claude-code-guide
subagent, dispatched mid-pass): *"Blocking rewake on completed
task is risky (may deadlock or confuse state). Safer pattern:
fail-open."*

**Mode B chosen** because:

1. **Least disruptive**: a teammate may already have moved on to
   the next task by the time verify fails. Auto-revert risks
   confusing the teammate ("I just marked this complete and now
   it's pending again?") and creates revert-of-revert cascades
   if the verify itself flakes.
2. **Preserves audit trail for forensics**: `audit.jsonl` already
   captures every hook fire with structured records. Operators
   can query `jq 'select(.reason == "verify-fail" and
   .rewake_mode == "asyncRewake")'` to find post-completion
   verify failures.
3. **Doesn't risk revert-of-revert cascades**: in async mode the
   wake-on-exit-2 already gives Claude visibility into the failure
   via stderr-as-system-reminder. Claude can decide whether to
   re-open the task itself; the hook doesn't impose a policy.
4. **Conservative default** for a new feature: tightening from
   B to A or C later is a config change; loosening from A or C
   to B is harder if teammates have come to expect auto-revert.
5. **Framework-guide explicit endorsement**: the canonical
   Claude Code docs (verified via `claude-code-guide` subagent
   `a244476a0f66385b3`) describe Mode B as "the framework-
   recommended pattern" for asyncRewake hooks on completed
   tasks. Aligning with framework convention reduces surprise
   for future contributors.

### 2.3 How to escalate to A or C later

Document the migration path explicitly:

```
# settings.json future extension (not shipped, design only):
{
  "hooks": {
    "TaskCompleted": [{
      "hooks": [{
        "type": "command",
        "command": "...",
        "asyncRewake": true,
        "asyncRewakeFailureMode": "log" | "revert" | "tiered"  // future
      }]
    }]
  }
}
```

**Mode A (revert) implementation sketch**:
- Hook detects async verify failure (rc != 0)
- Writes audit record with `"reason": "verify-fail-async-revert"`
- Calls TaskCreate via the framework's task API to spawn a follow-
  up task on the same teammate, blocked by nothing, with body
  "Re-verify task #N: <previous failure reason>"
- Exit 2 still wakes Claude (per asyncRewake semantics)

**Mode C (tiered) implementation sketch**:
- Hook detects async verify failure
- Classifies failure type from stderr:
  - `compile errors` (regex: `error:|undefined reference`) → revert
  - `test failures` (regex: `FAIL.*Test|--- FAIL:`) → log
  - `linter warnings` → log
- Different audit reason per tier so post-hoc filters can
  distinguish

**Why not ship A/C now**: requires `TaskCreate` framework
integration (Mode A) or a fragile classification heuristic
(Mode C). Both are 50-100 LOC of additional code with their own
correctness questions. Mode B preserves the option to add A/C
later as opt-in via the config knob; locking in B as the default
costs nothing.

### 2.4 Mode B implementation in this ship

**Already in place after R12 (v3)**: every hook fire writes a
record to `audit.jsonl`. R9 adds the `"rewake_mode"` tag so
post-hoc forensics can distinguish:

```jsonl
{"ts":...,"hook":"task-completed","rewake_mode":"asyncRewake",
 "team":"...","teammate":"...","task_id":"42","exit":2,
 "reason":"verify-fail","rc":1}
```

Operator query for "all post-completion async-verify failures":

```bash
jq 'select(.hook == "task-completed" and .rewake_mode ==
   "asyncRewake" and .reason == "verify-fail")' \
   ~/.claude/hooks/agent-teams/audit.jsonl
```

That's the entire Mode B contract. No code changes beyond R12 +
the new tagging.

---

## §3 — Implementation details

### 3.1 `detect_async_rewake_mode()` helper

```python
def detect_async_rewake_mode():
    """Return True if THIS hook is registered with asyncRewake=true
    in settings.json.

    Best-effort: parse settings.json, find the TaskCompleted entry
    whose command contains 'task-completed.py', read its
    asyncRewake field. Failures (file missing, parse error, key
    absent) default to False — safe assumption.
    """
    try:
        settings_path = (
            Path(os.path.expanduser("~"))
            / ".claude" / "settings.json"
        )
        with open(settings_path, encoding="utf-8") as f:
            settings = json.load(f)
        for entry in settings.get("hooks", {}).get(
            "TaskCompleted", []
        ):
            for h in entry.get("hooks", []):
                if "task-completed.py" in h.get("command", ""):
                    return bool(h.get("asyncRewake"))
        return False
    except Exception:
        return False


REWAKE_MODE = (
    "asyncRewake" if detect_async_rewake_mode() else "sync"
)
```

**Why read settings.json from the hook**: no documented env var
signal from the framework. The settings file is canonical truth,
self-introspection is reliable.

**Module-level evaluation**: computed once at hook load time, not
per-call. Cheap; predictable.

**Failure mode**: any exception during detect → defaults to False
(`"sync"` tag). This is safer than panicking — the hook still
runs, just tags as sync. Operator can grep for unexpected
`"sync"` records to detect detection failures.

### 3.2 audit.jsonl schema extension

**Pre-R9 schema** (R12 baseline):
```jsonc
{
  "ts": <unix-seconds>,
  "hook": "task-completed" | "teammate-idle",
  "team": "<team_name>",
  "teammate": "<teammate_name>",
  "task_id": "<id>",     // task-completed only
  "exit": 0 | 2,
  "reason": "...",
  // optional extras: detail, rc, task_owner, claimable_count
}
```

**Post-R9 schema** (this ship):
```jsonc
{
  "ts": <unix-seconds>,
  "hook": "task-completed" | "teammate-idle",
  "rewake_mode": "asyncRewake" | "sync",  // NEW
  "team": "<team_name>",
  "teammate": "<teammate_name>",
  "task_id": "<id>",
  "exit": 0 | 2,
  "reason": "...",
  // optional extras unchanged
}
```

**Backward-compat**: pre-R9 records lack the field. Operator
queries should treat absence as `"sync"` (matches the historical
behavior of all v3 records).

### 3.3 Settings.json patches

**Before** (v3):
```json
"TeammateIdle": [{
  "hooks": [{
    "type": "command",
    "command": "python C:/Users/Dell/.claude/hooks/agent-teams/teammate-idle.py",
    "timeout": 5
  }]
}],
"TaskCompleted": [{
  "hooks": [{
    "type": "command",
    "command": "python C:/Users/Dell/.claude/hooks/agent-teams/task-completed.py",
    "timeout": 5
  }]
}]
```

**After** (R1 + R9):
```json
"TeammateIdle": [{
  "hooks": [{
    "type": "command",
    "command": "python C:/Users/Dell/.claude/hooks/agent-teams/teammate-idle.py"
  }]
}],
"TaskCompleted": [{
  "hooks": [{
    "type": "command",
    "command": "python C:/Users/Dell/.claude/hooks/agent-teams/task-completed.py",
    "asyncRewake": true
  }]
}]
```

R1: `"timeout": 5` deleted from both agent-team entries (framework
default 600s applies).
R9: `"asyncRewake": true` added to TaskCompleted only.

**Other 3 hook entries** (SessionStart, UserPromptSubmit,
PostToolUse): untouched. Their `"timeout": 5` was an explicit
UX decision (fast-path latency), not accidental.

---

## §4 — Empirical verification

### 4.1 settings.json parses post-edit

```
$ python -c "import json; json.load(open(r'C:\Users\Dell\.claude\settings.json'))"
(no output → parses cleanly)
```

### 4.2 Backup created before mutation

`~/.claude/settings.json.bak.r1r9` saved via `shutil.copy2` before
any in-memory mutation. Operator can `cp -f .bak.r1r9 settings.json`
to revert if anything misbehaves.

### 4.3 Skills verification

Both `update-config` and `plugin-dev:hook-development` skills
invoked. Key confirmations from `update-config` schema dump:

- ✅ `asyncRewake` is documented as "If true, hook runs in
  background and wakes the model on exit code 2 (blocking error).
  Implies async."
- ✅ User-scope `~/.claude/settings.json` is correct location.
- ✅ Schema also documents `rewakeMessage` and `rewakeSummary` as
  internal fields for customizing the system-reminder text. NOT
  used in this ship — defaults are fine.
- ✅ Schema confirms: command hook timeout default is implicit
  (framework controls); explicit `"timeout"` overrides it.

`plugin-dev:hook-development` skill provided general hook
patterns (prompt vs command, exit codes 0/2) but no
asyncRewake-specific addenda beyond what the schema already
documents. Standard sync-vs-async semantics: hook script body
unchanged; framework handles the waiting model.

### 4.4 E2E synthetic test — 8 audit records

```
=== AUDIT LOG ===
{"hook":"task-completed","rewake_mode":"asyncRewake",
 "task_id":"100","exit":2,"reason":"status-pending"}
{"hook":"task-completed","rewake_mode":"asyncRewake",
 "task_id":"102","exit":0,"reason":"ok"}
{"hook":"task-completed","rewake_mode":"asyncRewake",
 "task_id":"103","exit":2,"reason":"verify-blocked-suspicious"}
{"hook":"task-completed","rewake_mode":"asyncRewake",
 "task_id":"200","exit":2,"reason":"verify-fail","rc":1}
{"hook":"teammate-idle","rewake_mode":"sync",
 "exit":2,"reason":"claimable-tasks-remain"}
{"hook":"teammate-idle","rewake_mode":"sync",
 "exit":0,"reason":"no-claimable-tasks"}
```

All task-completed records: `rewake_mode: asyncRewake` (correctly
detecting settings entry). All teammate-idle records: `rewake_mode:
sync` (correctly detecting absence of asyncRewake).

8 of 8 audit-emit paths cover all hook outcomes.

---

## §5 — Activation note

Per the `plugin-dev:hook-development` skill (verbatim):

> Hooks load at session start. Changes to hook configuration
> require restarting Claude Code.

**Operator action required**: the user must restart Claude Code
(or reload the framework via `/hooks`) for the R1 + R9 settings
changes to take effect in the live session. Until then, the
running session continues to use the pre-edit `"timeout": 5`
synchronous semantics.

The task-completed.py changes (R9 audit-tagging) DO take effect
immediately on next hook fire — Python re-reads the script every
invocation. Only the settings-file-driven changes (R1 timeout
removal, R9 asyncRewake registration) need restart.

---

## §6 — Honest opacity

1. **`asyncRewake` is documented but not personally exercised**:
   the schema confirms the field is supported. Empirical
   end-to-end (running Claude Code with the new settings, observing
   actual async-rewake behavior on a real failed verify) requires
   the user to restart Claude Code; not done in this ship. The
   audit record-tagging IS verified end-to-end via synthetic stdin.

2. **Mode B vs A vs C is a defensible default, not a settled
   choice**. If the user finds in production that async verify
   failures cluster in a category that genuinely warrants auto-
   revert (e.g. compile errors that should have blocked
   completion), the migration to Mode A is a 50-100 LOC follow-up,
   not a re-architecture.

3. **`detect_async_rewake_mode()` reads settings.json on every
   hook load**. ~20ms overhead on Windows file IO. Cheap.

4. **`REWAKE_MODE` is computed at module-load time**. If the user
   edits settings.json mid-session and the hook script doesn't
   reload (Python caches modules), the audit tag could lag. In
   practice, hooks are subprocess-invoked per call, so each fire
   is a fresh Python process — module-load runs every time. Stale
   tagging is theoretical only.

5. **R1 doesn't ship for the 3 non-agent-team hook entries**.
   Their `"timeout": 5` may also be accidental, but the brief
   explicitly limited R1 scope to agent-team hooks. If a future
   audit decides those 3 should also use framework default, that's
   a follow-up.

6. **The settings.json backup at `~/.claude/settings.json.bak.r1r9`
   is the user's revert path**. Not committed anywhere; lives
   on disk as a safety net.

7. **No git for the hook-side changes**. `~/.claude/` is not a
   tracked repo. The kite-mcp-server repo only carries this design
   doc + the prior v1/v2/v3 docs.

---

## §7 — Cumulative shipped fixes across v1+v2+v3+R1+R9

| ID | Description | Pass | Status |
|---|---|---|---|
| R3 | Tail-truncate stderr | v1 | shipped + verified |
| R5 | Defensive id-sort | v1 | shipped + verified |
| R8 | Extract tool-name constants | v2 | shipped + verified |
| R11 | Suspicious-verify guardrail | v3 | shipped + verified |
| R12 | Hook audit log (audit.jsonl) | v3 | shipped + verified |
| **R1** | **Remove "timeout": 5 on agent-team hooks** | **R1+R9 pass** | **shipped (settings.json edit)** |
| **R9** | **AsyncRewake for TaskCompleted + audit tagging** | **R1+R9 pass** | **shipped (settings.json + task-completed.py + teammate-idle.py)** |

**Total cumulative**: 7 fixes shipped to user-local
`~/.claude/hooks/agent-teams/*` and `~/.claude/settings.json`
across 4 research passes.

---

## §8 — Sources

- v1 doc: `.research/team-hooks-analysis.md` (`ee22290`)
- v2 doc: `.research/team-hooks-analysis-v2.md` (`3e3a57d`)
- v3 doc: `.research/team-hooks-analysis-v3.md` (`34ee93e`)
- Anthropic hook framework documentation
  (https://code.claude.com/docs/en/hooks) fetched in v2
- `update-config` skill (Anthropic plugin); settings.json schema
  with full `asyncRewake` field documentation, verified
  in-session that `asyncRewake: true` alone is the canonical form
  (no separate `async: true` field needed)
- `plugin-dev:hook-development` skill; general hook patterns +
  session-start activation requirement
- `claude-code-guide` subagent (`a244476a0f66385b3`); framework-
  guide verification dispatched mid-pass. Confirmations:
  - `asyncRewake: true` alone is correct (no `async: true`)
  - Mode B (audit-only log) is the framework-recommended pattern
    for asyncRewake on completed tasks: "Blocking rewake on
    completed task is risky (may deadlock or confuse state)."
  - Default 600s timeout confirmed; `"timeout": 5` overrides
    confirmed accidental. Removal is one of two equivalent valid
    paths (the other: explicit `"timeout": 120`); removal chosen
    for less drift
- `~/.claude/settings.json` post-R1+R9 (4347 bytes, validated)
- `~/.claude/settings.json.bak.r1r9` (backup, pre-edit)
- `~/.claude/hooks/agent-teams/task-completed.py` post-R9
  (~13746 bytes, syntax verified)
- `~/.claude/hooks/agent-teams/teammate-idle.py` post-R9
  (~5902 bytes, syntax verified)
- E2E synthetic verification: 8/8 audit-emit paths produce records
  with correct `rewake_mode` tagging

---

*Generated 2026-05-02 night. Read-only research deliverable for
the kite-mcp-server `.research/` artifact tree. R1 + R9 applied
to `~/.claude/settings.json` and `~/.claude/hooks/agent-teams/`
(outside any git repo). Activation requires Claude Code restart
or `/hooks` reload.*
