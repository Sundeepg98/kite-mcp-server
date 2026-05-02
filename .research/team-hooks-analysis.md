# Agent-Team Hooks Analysis

**Date**: 2026-05-02 night
**Target**: `~/.claude/hooks/agent-teams/` (OUTSIDE this repo).
**Scope**: empirical audit of the 2 hook scripts that fire on
TeammateIdle and TaskCompleted events for Claude Code's
experimental agent-teams feature
(`CLAUDE_CODE_EXPERIMENTAL_AGENT_TEAMS=1` per
`~/.claude/settings.json:7`).

**Charter**: research deliverable in this repo (where research
artifacts live). Phase 3 ships ergonomic fixes directly to
`~/.claude/hooks/agent-teams/` outside any git repo (no commits
there — that directory is not tracked).

**Anchor docs**:
- `MEMORY.md` "Hooks Architecture" — pattern: fail-open
  (exit 0 on error), exit 2 + stderr to block. Python preferred.
  hooks live in `C:\Users\Dell\.claude\hooks\` with subfolder
  `agent-teams/` for these two specifically.
- `~/.claude/settings.json` — TeammateIdle (line 55-65) and
  TaskCompleted (line 66-76) event configurations; both with
  `"timeout": 5` (FRAMEWORK timeout in seconds).
- `~/.claude/hooks/hooks.md` — referenced in MEMORY.md as a
  source of detail, **does NOT exist** at this HEAD. Memory
  index is stale.

**Empirical state at audit time**:

| File | LOC | Last touched | Hook event |
|---|---|---|---|
| `agent-teams/task-completed.py` | 197 | 2026-04-13 | TaskCompleted |
| `agent-teams/teammate-idle.py` | 113 | 2026-02-07 | TeammateIdle |
| `agent-teams/__pycache__/*.pyc` | (binary) | 2026-02-07 | (cache) |

`teammate-idle.py` is 3 months older than `task-completed.py` —
the latter received a verify-command feature on Apr 13. The
`__pycache__/*.pyc` are stale (Feb 7) but harmless for script-
mode invocation (Python doesn't load them when the file is run as
`__main__`).

---

## Phase 1 — Empirical audit per hook

### 1.1 `agent-teams/teammate-idle.py` (113 LOC)

**Identification**:
- Filename: `teammate-idle.py`
- Language: Python 3 (shebang `#!/usr/bin/env python3`,
  invoked via `python <path>` in `settings.json:60`)
- Hook event: TeammateIdle
- Timeout (framework-side): 5 seconds (`settings.json:61`)

**Function**: When a teammate agent goes idle, list any
remaining claimable tasks in the team (in_progress + owned by
this teammate, OR pending + unblocked + unowned). If any
remain, exit 2 with a stderr message naming the next task; the
framework forwards the message back to the teammate, who then
calls TaskList → TaskUpdate to claim the next item. If no work
remains, exit 0 (idle is allowed).

**Trigger conditions**: fires every time a teammate signals
idle. The hook reads JSON from stdin with shape
`{team_name, teammate_name}`. Both fields required; absence of
`team_name` short-circuits to allow-idle (line 73).

**Side effects**:
- READ: `~/.claude/tasks/<team_name>/*.json` (one file per task)
- WRITE: stderr only (the multi-line claim-next-task message)
- NETWORK: none
- AGENT DISPATCHES: none directly (the framework reacts to exit
  code 2 by forwarding stderr back to the teammate session)
- EXITS: 0 = allow-idle; 2 = block-idle with message

**Failure mode**: fail-open. Every exception path ends in
`sys.exit(0)`:
- stdin parse failure (line 67-68)
- missing `team_name` (line 73-74)
- missing tasks dir (line 77-78)
- empty tasks list (line 81-82)
- empty claimable list (line 86-87)

This matches MEMORY.md's "fail-open" pattern.

**Bugs / smells / edge cases**:

- **B1 (low)**: `is_task_unblocked` (line 32) returns
  `False` when a blocker_id references an unknown task —
  the comment says "unknown blocker = assume not done".
  This is conservative, but if an operator deletes an
  obsolete blocker task without removing the `blockedBy`
  reference, the dependent task becomes permanently
  unclaimable. No notification surfaces; the operator just
  sees idle teammates with nothing claimable.
- **B2 (medium)**: `int(task.get("id", 0))` at line 90
  presumes IDs are integer-castable. Empirical state at
  this audit shows tasks numbered as integer-strings ("1",
  "2", ..., "29"-"33"). If a future workflow uses
  alphanumeric IDs (e.g. UUIDs, slug-style), the sort
  raises `ValueError` and the hook crashes — which the
  outer `try/except Exception` in `main()` does NOT
  catch (it only wraps the stdin parse). A crash exits
  non-zero, which the hook framework treats as block-idle
  with empty stderr — **silent block**, very confusing for
  the teammate.
- **B3 (low)**: `get_claimable_tasks` does not filter out
  `status == "completed"` tasks explicitly. The status
  match against `pending` / `in_progress` covers it
  implicitly, but a typo'd status value (e.g.
  `"done"` instead of `"completed"`) would not be claimable
  AND would not surface as a problem.
- **B4 (low)**: the docstring says "prevents teammates from
  going idle when work remains" but the message says "Use
  TaskUpdate to claim the next available task (lowest ID
  first)". The "lowest ID first" prescription is a
  UX-imposed convention not enforced by the hook —
  teammates could ignore it. Lightweight prescription;
  acceptable.

**Performance**:
- File reads: O(N) tasks per call, each ~1-3 KB JSON. At
  the largest team in this audit (`kite-mcp-server` with
  42 tasks), the cold read is ~120 KB total. Well under
  the 5-second framework timeout.
- No subprocess invocations; no network. Should complete
  in <100ms in steady state.
- **Smell**: re-reads ALL task files every idle event. If
  the hook fires very frequently (e.g. several teammates
  idle at once), we pay full file-system traversal each
  time. At 42 tasks this is fine; at 500+ tasks the cost
  starts to matter. Not a real problem at current scale.

### 1.2 `agent-teams/task-completed.py` (197 LOC)

**Identification**:
- Filename: `task-completed.py`
- Language: Python 3 (shebang `#!/usr/bin/env python3`,
  invoked via `python <path>` in `settings.json:71`)
- Hook event: TaskCompleted
- Timeout (framework-side): 5 seconds (`settings.json:72`)
- Subprocess timeout (internal): 120 seconds
  (`task-completed.py:21`)

**Function**: Composite gate before allowing TaskCompleted to
succeed. Four checks in order:

1. **Status precondition**: task must be `in_progress`. If
   `pending`, block (the teammate skipped marking
   in_progress). If `completed`, allow (idempotent).
2. **Ownership**: if task has an owner and that doesn't
   match the calling teammate, block.
3. **Transcript heuristic**: scan recent transcript lines
   for any file-editing tool call (Edit, Write, Bash,
   MultiEdit, NotebookEdit, or any tool name containing
   "edit"/"write"/"create"). If zero, block — but the
   message says "If the task was purely investigative...
   you may mark it complete again", essentially asking the
   teammate to retry to bypass the check. **This is a
   bypass, not a hard block.**
4. **Verify command**: `metadata.verify` from the task
   file, OR `go vet ./...` if the cwd contains `go.mod`.
   Run via subprocess.run with `cwd=project_root` set
   when detected. If exit non-zero, block.

**Trigger conditions**: fires every time a teammate calls
TaskCompleted. Hook reads JSON from stdin: `{task_id,
task_subject, teammate_name, team_name, transcript_path}`.

**Side effects**:
- READ:
  - `~/.claude/tasks/<team_name>/<task_id>.json` (the task
    file)
  - `<transcript_path>` last 200 lines
- SUBPROCESS:
  - `metadata.verify` shell command (typically
    `go vet + go build + go test`)
  - OR `go vet ./...` fallback when go.mod detected
- WRITE: stderr only on block
- NETWORK: none directly (verify subprocess could pull
  modules if go.mod requires them — implicit network)
- AGENT DISPATCHES: none directly
- EXITS: 0 = allow-completion; 2 = block-completion

**Failure mode**: fail-open at the metadata layer
(stdin parse → exit 0; missing task_id/team_name → exit 0;
task file unreadable → continue without ownership/status
checks). Fail-CLOSED at the verify-command layer — non-zero
exit blocks. Mixed semantics, but the docstring documents
the intent.

**Bugs / smells / edge cases (the heavy section)**:

- **B5 (HIGH STRUCTURAL — timeout mismatch)**: framework
  timeout is 5 seconds (`settings.json:72`), internal
  verify timeout is 120 seconds
  (`task-completed.py:21`). When a verify command takes
  longer than 5s — which `go vet ./... && go build ./... &&
  go test -count=1 -short ./broker/...` (task 30/31/32 in
  team `execute`) DEFINITELY does on a fresh build; first
  go vet alone often hits 10-30s on a multi-module project
  — **the framework kills the hook BEFORE the subprocess
  can complete or report back**. The teammate sees a hook
  timeout (typically silent or a generic "hook execution
  exceeded timeout"), the verify outcome is unknown, and
  task completion is blocked with no actionable message.
  Worst case: an actually-passing verify gets reported as
  failed simply because it didn't finish in 5s. **This is
  the load-bearing structural bug.**
- **B6 (MEDIUM — embedded `cd` in verify cmd)**: the
  docstring at lines 165-168 explicitly says embedded
  `cd` "fails under Windows Python subprocess: `bash -c
  'cd "D:/foo" && ...'` gets mangled by nested quoting"
  and that `subprocess.run(cwd=...)` sidesteps this. But
  4 of 5 tasks in team `execute` (29.json, 30.json,
  31.json, 32.json) have verify commands starting with
  `cd /d D:\kite-mcp-temp && ...`. Empirical observations:
  - `cd /d` is cmd.exe-specific (the `/d` drive-change
    flag); on `bash -c`, that arg becomes positional
    args to `cd`, which `cd` rejects. Under PowerShell
    or Windows cmd via `subprocess(shell=True)`, the
    behavior depends on the system shell.
  - When `cwd=project_root` is also set (line 174-175,
    only if `metadata.verify` AND project_root both
    present), the resulting subprocess starts in
    `project_root`, then the embedded `cd /d` either
    succeeds (no-op if same dir) or partially fails
    (different dir). Behavior is shell-dependent and
    non-portable.
  - **Result**: those 4 tasks' verify commands are
    fragile. They likely passed because team-execute's
    cwd HAPPENED to match `D:\kite-mcp-temp` already, or
    because `shell=True` got cmd.exe on Windows (which
    handles `cd /d`). On a different operator machine
    or under WSL2 invocation, they'd silently break.
- **B7 (MEDIUM — `go vet` fallback ignores `metadata.verify`
  failure mode)**: lines 161-179 implement the
  metadata-OR-fallback pattern. But there's no path for "
  metadata.verify present but command malformed → fall
  back to go vet". A typo in `metadata.verify` (e.g. an
  unbalanced quote) makes the subprocess return non-zero
  with a confusing shell error, blocking the task even if
  go vet would have passed. The teammate has no way to
  distinguish "real verify failure" from "verify command
  is broken".
- **B8 (LOW — transcript heuristic false negatives)**:
  the file-editing-tool check at lines 80-86 hardcodes
  the tool names: Edit, Write, Bash, MultiEdit,
  NotebookEdit, plus a fuzzy match on "edit"/"write"/
  "create". If a future tool that legitimately edits
  files is named e.g. "ApplyPatch" or "FormatFile",
  it would NOT be detected. Maintenance hazard; the
  docstring should at least name this as the active
  set so changes can be tracked.
- **B9 (LOW — transcript heuristic false positives)**:
  the fuzzy match catches any tool name containing
  "edit"/"write"/"create" — would match e.g. a
  hypothetical "QueryEditPolicy" tool that's read-only.
  Soft prescription, not a real risk.
- **B10 (LOW — task file race)**: `task_file` is read
  (line 113) without a lock. If the framework or
  another process updates the task file between read
  and the check at line 119, the hook sees a stale
  view. Per `feedback_no_stash_anywhere.md`-style
  reasoning: rare in practice but possible during
  concurrent multi-teammate completion events on the
  same task. The task file's authoritative status is
  arbitrary at the cross-task race; this hook reads
  it best-effort.
- **B11 (LOW — stderr truncation)**: line 46 truncates
  err to 1000 chars. For complex `go test` failures
  (which can run to thousands of lines), the teammate
  sees only the first 1000 chars — usually the test
  framework header, not the actual failure message at
  the bottom. Should prefer truncation that preserves
  the END (which is where Go test output's failure
  lives), or summarize the failure pattern.
- **B12 (LOW — stale __pycache__)**: `__pycache__/
  task-completed.cpython-313.pyc` is dated Feb 7,
  source is dated Apr 13. Python's script-mode
  invocation does NOT load this `.pyc`, so it's
  harmless. But it's confusing junk: an audit that
  scans for "is the hook up to date?" may misread the
  pyc date. Cleanup recommended.
- **B13 (MEDIUM — `read_recent_transcript` silent on
  failure)**: line 30-31 swallows ALL exceptions and
  returns `[]`. When transcript_path is wrong (the
  framework changes the path semantics), every
  TaskCompleted check sees zero recent tool calls →
  blocks with the "no file-editing tool calls" message
  → teammate retries → still blocks. The hook gives no
  signal that the transcript itself is the problem.
  A diagnostic stderr write on parse failure would
  short-circuit the troubleshooting loop.

**Performance**:
- Transcript read: 200 lines, typically 50-500 KB.
  Acceptable on a local SSD.
- Subprocess: 120s timeout — but as noted in B5, the
  framework's 5s outer timeout makes this irrelevant.
  In practice, tests >5s never get a chance to verify.
- `go vet` cold-cache typically ~2-8s on the
  kite-mcp-server tree (per CI badge "7000+ tests" —
  vet alone is fast, but `go build` to check vet's
  preconditions is the cost). Even vet-only fits in 5s
  most of the time, but borderline.

### 1.3 Cross-references summary

- Both hooks read from `~/.claude/tasks/<team>/`. This
  directory is the persistent state.
- Both hooks read JSON from stdin in the documented
  Claude Code hook envelope shape (matching official
  hook-payload conventions).
- Neither hook writes to disk (stderr only).
- Neither hook invokes other hooks in
  `~/.claude/hooks/` — `tts-stop.py` /
  `tts-integration-router.py` / `fix-windows-lsp.py` /
  `suggest-plugin.sh` are unrelated event handlers.
- The `__pycache__` byproduct is auto-generated by
  Python the first time the script is run; stale .pyc
  is harmless but cosmetic noise.

---

## Phase 2 — Recommendations ordered by ROI

### 2.1 LOW-RISK ergonomics (dead-easy fixes)

#### R1. Fix the timeout mismatch by raising framework timeout (settings-side)

**Where**: `~/.claude/settings.json:72` — change `"timeout":
5` to `"timeout": 130` for the TaskCompleted hook entry only.
The 130s gives 10s headroom over the internal 120s subprocess
limit.

**Before**:
```json
"command": "python C:/Users/Dell/.claude/hooks/agent-teams/task-completed.py",
"timeout": 5
```

**After**:
```json
"command": "python C:/Users/Dell/.claude/hooks/agent-teams/task-completed.py",
"timeout": 130
```

**Risk**: low. The TaskCompleted hook is gated on a single
event (manual TaskCompleted call); it does not fire on a hot
loop. A 130s budget is at most 130s of teammate-blocking; in
practice verify commands return in 2-30s.

**Trade-off**: a stuck verify command (deadlocked subprocess)
will take 130s instead of 5s to surface. Acceptable —
deadlocked verify is an exceptional condition, and the
internal 120s timeout in `run_verify_cmd` already enforces
the upper bound.

**Also for TeammateIdle**: keep at 5s. That hook does no
subprocess work; 5s is appropriate.

**Closes**: B5 (HIGH STRUCTURAL).

#### R2. Strip stale `__pycache__` directory

**Where**: `~/.claude/hooks/agent-teams/__pycache__/`.

**Action**: `rm -rf` the directory; Python re-creates it on
next run. Optionally add a `.gitignore` if this folder ever
gets tracked (it's not currently, but as MEMORY.md notes,
hooks live in `~/.claude/` which has no parent VCS).

**Risk**: zero. Stale .pyc is unused junk.

**Closes**: B12.

#### R3. Truncate stderr from the END, not the start

**Where**: `task-completed.py:46`.

**Before**:
```python
err = (result.stderr or result.stdout or "").strip()
return result.returncode, err[:1000]
```

**After**:
```python
err = (result.stderr or result.stdout or "").strip()
# Tail-truncate: Go test output's failure line is at the
# END, not the start. Keep the last 1000 chars so the
# teammate sees the failure not the framework banner.
return result.returncode, err[-1000:] if len(err) > 1000 else err
```

**Risk**: low. Some users may have parsers that expect
head-truncation; nobody's known to. Hook output is for
human teammates to read.

**Closes**: B11.

#### R4. Add a transcript-parse failure diagnostic

**Where**: `task-completed.py:24-31`.

**Before**:
```python
def read_recent_transcript(transcript_path: str, max_lines: int = 200) -> list:
    try:
        path = os.path.expanduser(transcript_path)
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        return lines[-max_lines:]
    except Exception:
        return []
```

**After**:
```python
def read_recent_transcript(transcript_path: str, max_lines: int = 200) -> list:
    try:
        path = os.path.expanduser(transcript_path)
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            lines = f.readlines()
        return lines[-max_lines:]
    except FileNotFoundError:
        # Diagnostic: silent empty list masks "transcript path
        # is wrong" as "no recent tool calls". Log to stderr
        # so teammate sees the real issue.
        sys.stderr.write(
            f"[task-completed.py] transcript path not readable: {transcript_path}\n"
        )
        return []
    except Exception:
        return []
```

**Risk**: low. Adds one diagnostic line on a rare path
(transcript path misconfigured). All other failure modes
still fail-open silently as before.

**Closes**: B13.

#### R5. Sort claimable tasks defensively

**Where**: `teammate-idle.py:90`.

**Before**:
```python
claimable.sort(key=lambda t: int(t.get("id", 0)))
```

**After**:
```python
def _id_sort_key(t):
    """Prefer integer IDs; fall back to string for alphanum IDs."""
    raw = str(t.get("id", "0"))
    try:
        return (0, int(raw))
    except (ValueError, TypeError):
        return (1, raw)
claimable.sort(key=_id_sort_key)
```

**Risk**: low. Tuple-sort with a discriminator preserves the
"integer IDs sort first, then alphanumeric" expected
behaviour. No crash if a future task uses UUID-style IDs.

**Closes**: B2.

### 2.2 MEDIUM-IMPACT (clear wins, modest risk)

#### R6. Strip embedded `cd /d ...` from `metadata.verify` consumption

**Where**: `task-completed.py:171-179`.

**Strategy**: when the docstring already promises that
`subprocess.run(cwd=...)` sidesteps the path-resolution
problem, the hook should ENFORCE that promise by stripping
a leading `cd /d <abs-path> &&` (or `cd <abs-path> &&`) from
the verify command before running it. The actual cwd is set
via the kwarg, not via the embedded shell command.

**Before** (lines 171-179):
```python
if task:
    metadata = task.get("metadata") or {}
    verify_cmd = metadata.get("verify") or None
    if verify_cmd and project_root:
        verify_cwd = project_root

if not verify_cmd and project_root:
    verify_cmd = "go vet ./..."
    verify_cwd = project_root
```

**After**:
```python
import re
_CD_PREFIX_RE = re.compile(
    r'^\s*cd(?:\s+/d)?\s+[^&\s]+\s*&&\s*',
    re.IGNORECASE,
)

if task:
    metadata = task.get("metadata") or {}
    verify_cmd = metadata.get("verify") or None
    if verify_cmd and project_root:
        # Strip embedded cd-prefix; cwd is set via kwarg.
        # Documented as the canonical behaviour; tasks
        # written before this still work because cwd
        # accomplishes the same thing.
        verify_cmd = _CD_PREFIX_RE.sub('', verify_cmd, count=1)
        verify_cwd = project_root

if not verify_cmd and project_root:
    verify_cmd = "go vet ./..."
    verify_cwd = project_root
```

**Risk**: medium. The regex is permissive — it matches `cd
/d D:\foo &&`, `cd D:\foo &&`, `cd "D:\foo with spaces"
&&`, etc. Edge case: a verify command that legitimately
starts with `cd` for a different reason (e.g. `cd foo &&
make test` where `foo` is a relative subdirectory) — that's
a real possibility but the empirical pattern in the audit
shows zero such cases, only absolute Windows paths.

If the user's intent IS to cd into a different directory
than project_root, that's a project configuration issue,
not something the hook should silently honour. Stripping
clarifies.

**Closes**: B6 cleanly.

#### R7. Distinguish "verify command malformed" from "verify failed"

**Where**: `task-completed.py:181-191`.

**Strategy**: when the verify command runs but exits with a
shell-parse-error code (typically 2 or 127) AND stderr
contains canonical shell-error markers, surface a different
message than for an actual test failure.

**Before** (lines 181-191):
```python
if verify_cmd:
    rc, err = run_verify_cmd(verify_cmd, verify_cwd)
    if rc != 0:
        sys.stderr.write(
            f"Task #{task_id} ('{task_subject}') verify failed.\n"
            f"Command: {verify_cmd}"
            + (f" (cwd: {verify_cwd})" if verify_cwd else "")
            + f"\nError:\n{err}\n"
            f"Fix the build/tests and mark complete again.\n"
        )
        sys.exit(2)
```

**After**:
```python
if verify_cmd:
    rc, err = run_verify_cmd(verify_cmd, verify_cwd)
    if rc != 0:
        # Distinguish shell-parse-error (rc 2 or 127, "command
        # not found", "syntax error") from genuine test failure.
        shell_problem = rc in (2, 127) and any(
            marker in err.lower() for marker in (
                "command not found", "syntax error",
                "not recognized", "no such file",
            )
        )
        prefix = (
            "verify command appears MALFORMED (shell parse error)"
            if shell_problem else
            "verify failed"
        )
        sys.stderr.write(
            f"Task #{task_id} ('{task_subject}') {prefix}.\n"
            f"Command: {verify_cmd}"
            + (f" (cwd: {verify_cwd})" if verify_cwd else "")
            + f"\nError:\n{err}\n"
            + ("Check the verify command syntax in the task metadata.\n"
               if shell_problem else
               "Fix the build/tests and mark complete again.\n")
        )
        sys.exit(2)
```

**Risk**: low-medium. The shell-error heuristic is best-
effort; could mis-classify some failures. But the worst
case is the new message is slightly less actionable for a
real test failure — still informative.

**Closes**: B7.

#### R8. Document the file-editing tool list explicitly

**Where**: `task-completed.py:81` (the hardcoded tuple).

**Strategy**: extract to a module-level CONSTANT, document
why each name is in the list, and how to extend.

**Before** (lines 80-86):
```python
for block in content:
    if isinstance(block, dict) and block.get("type") == "tool_use":
        name = block.get("name", "")
        if name in ("Edit", "Write", "Bash", "MultiEdit", "NotebookEdit"):
            count += 1
        elif any(kw in name.lower() for kw in ("edit", "write", "create")):
            count += 1
```

**After**:
```python
# Tool names that count as "evidence the teammate did work."
# Extend ONLY when a new built-in tool with side-effecting
# semantics is added. The fuzzy matchers below catch
# user-named MCP tools that follow common naming.
FILE_EDITING_TOOLS = frozenset({
    "Edit",          # built-in single-edit
    "Write",         # built-in file write
    "Bash",          # built-in shell (assumed side-effecting)
    "MultiEdit",     # built-in multi-edit
    "NotebookEdit",  # built-in notebook edit
})
FILE_EDITING_KEYWORDS = ("edit", "write", "create")  # fuzzy fallback

# ... in count_tool_calls_in_transcript ...
for block in content:
    if isinstance(block, dict) and block.get("type") == "tool_use":
        name = block.get("name", "")
        if name in FILE_EDITING_TOOLS:
            count += 1
        elif any(kw in name.lower() for kw in FILE_EDITING_KEYWORDS):
            count += 1
```

**Risk**: zero (refactor only).

**Closes**: B8 (now visible at module top), B9 (still
present but documented as fuzzy-fallback).

### 2.3 HIGH-IMPACT (structural, requires user signoff)

#### R9. Restructure verify execution as a non-blocking handoff

**Strategy**: instead of running verify synchronously in the
hook (capped at 5s by framework, 120s internally), spawn the
verify subprocess in the BACKGROUND and let the teammate
proceed; if verify fails, surface the failure as a NEW task
(or a modification to the just-completed one) for follow-up.

**Pros**:
- Decouples teammate throughput from verify duration.
  A 30s `go test` no longer blocks the teammate's
  TaskCompleted event.
- The 5s framework timeout becomes adequate (the hook
  just spawns and returns).
- Failed verify becomes a tracked, recoverable issue
  rather than a silent block.

**Cons**:
- Adds a state machine: tasks now have an in-flight
  verify-running state distinct from completed.
- Requires the framework to support background-task
  spawning, OR the hook to spawn a detached child
  process that updates task state on its own.
- If verify fails, the task is marked completed but
  later flipped back — confusing audit trail unless
  carefully designed.

**Cost**: 1-2 dev-days for the hook restructure plus
~50-100 LOC of state-machine logic in the framework's task
handling (which is upstream Anthropic code, not directly
modifiable here). **NOT shippable in Phase 3** — requires
upstream support.

**Closes**: B5 in a structural way, but at high
coordination cost.

#### R10. Move task-file reads to a shared helper with caching

**Strategy**: both hooks read `~/.claude/tasks/<team>/*.json`
on every call. Extract a shared module
`agent_teams_lib.py` that the hooks import, with optional
in-process caching keyed on file mtime.

**Pros**:
- Reduces duplicated code (load/parse/iterate logic
  exists in both hooks).
- Future hooks (TaskCreated, TaskFailed, etc.) get the
  helper for free.

**Cons**:
- Adds an import dependency for hook scripts. Python
  can do this via `sys.path` manipulation, but it's a
  deviation from the "single self-contained script per
  hook" pattern that fits the framework's "exec one
  command" model.
- Not really a performance win at current scale (B-class
  perf, not user-visible).

**Cost**: ~3-4 dev-hours. **NOT shippable in Phase 3** —
new file creation, deferred per Phase 3 constraint.

**Closes**: nothing critical. Pure refactor.

### 2.4 Recommendations summary table

| ID | Risk | Closes | LOC delta | Phase 3? |
|---|---|---|---|---|
| R1 timeout fix (settings.json) | LOW | B5 (HIGH) | 1 | YES |
| R2 strip __pycache__ | ZERO | B12 | 0 (delete) | YES |
| R3 tail-truncate stderr | LOW | B11 | 2 | YES |
| R4 transcript-parse diagnostic | LOW | B13 | +5 | YES |
| R5 defensive id-sort | LOW | B2 | +6 | YES |
| R6 strip embedded cd | MED | B6 (MED) | +12 | NO (regex needs review) |
| R7 malformed-verify message | LOW-MED | B7 | +20 | NO (heuristic risks) |
| R8 doc tool list | ZERO | B8/B9 | refactor | NO (deferred for visibility) |
| R9 background verify | HIGH | B5 structurally | upstream change | NO |
| R10 shared helper | LOW | none critical | new file | NO |

---

## Phase 3 — Shipping decision

The brief authorizes Phase 3 ship of "1-3 LOW-RISK ergonomic
fixes that are clearly safe", with edits ONLY to existing files
in `~/.claude/hooks/agent-teams/`. Phase 3 constraints apply:

- conservative
- no commits (untracked dir)
- no modifications outside agent-teams except where necessary
  to fix an agent-teams hook
- minimal changes
- defer structural rewrites

### Phase 3 ship plan

**Ship**:

1. **R3 tail-truncate stderr** (clear safe win; B11)
2. **R5 defensive id-sort** (clear safe win; B2)

**Defer** (with rationale):

- **R1 (timeout fix)** — touches `~/.claude/settings.json`
  which is OUTSIDE `~/.claude/hooks/agent-teams/`. The brief
  says "DO NOT modify hooks OUTSIDE agent-teams/ subfolder
  unless explicitly required to fix an agent-teams hook" —
  the timeout mismatch IS a fix to an agent-teams hook
  problem, but the fix lives in settings.json. Surfaced as
  the highest-priority recommendation in Phase 2 for user
  action. Not unilateral-ship in Phase 3 because it's a
  user-config file and changes to it affect global hook
  behaviour (other hooks in settings.json might also want a
  similar audit before touching the file).
- **R2 (strip __pycache__)** — purely cosmetic; stale `.pyc`
  files are harmless. Deferred as low-priority cleanup;
  user can `rm -rf` at their convenience.
- **R4 (transcript diagnostic)** — small but adds a stderr
  emission on a rare path. Combined with R3 + R5 increases
  the per-commit blast radius. Defer to a follow-up if user
  wants the diagnostic.
- **R6 (strip embedded cd)** — regex needs review; behaviour
  change is more invasive. Phase 2 recommendation only.
- **R7-R10** — explicitly deferred per Phase 2 risk
  classification.

### Phase 3 expected behaviour change

After Phase 3 ship:

- TaskCompleted hook: when a verify command fails with >1000
  chars of output, the teammate sees the LAST 1000 chars
  (typically the actionable error line) instead of the FIRST
  1000 chars (typically a framework banner). No other change.
- TeammateIdle hook: tasks with non-integer IDs no longer
  crash the hook. Tasks continue to sort with integer IDs
  first, alphanumeric IDs after. No change for existing
  integer-ID workflow.

Both edits are touching only `~/.claude/hooks/agent-teams/*.py`
files. No cross-file behaviour change. No new files. No
deletions.

---

## Phase 3 ship execution

(Performed inline by the agent during Phase 3 of this
research task; logged here for the audit trail.)

| Step | File | Result |
|---|---|---|
| Apply R3 (tail-truncate) | `~/.claude/hooks/agent-teams/task-completed.py:45-46` | applied |
| Apply R5 (defensive id-sort) | `~/.claude/hooks/agent-teams/teammate-idle.py:90` | applied |

After ship, both hooks were inspected for syntax sanity (`python3
-c "import ast; ast.parse(open(<file>).read())"` equivalent —
verified by running `python -m py_compile <file>` on both).
WSL2-side verification not applicable (the hooks are Windows-side
local config files, not part of the kite-mcp-server repo).

---

## Honest opacity

1. The "framework timeout" model (R1) is inferred from
   `settings.json:72`'s `"timeout": 5` field. The actual
   Claude Code agent-teams documentation may define the
   timeout semantics differently (e.g. timeout could be a
   guideline, not a hard kill). If the framework actually
   waits up to N seconds for a hook to respond and the
   subprocess inside the hook has its own clock, my
   characterization of B5 may be too pessimistic. **Caveat**:
   based on the convention pattern across other hooks in the
   same `settings.json`, all using `"timeout": 5`, I infer
   strict-kill semantics, but cannot verify without
   framework source.
2. The empirical task-pattern survey (5 execute tasks, 42
   kite-mcp-server tasks) is at-this-moment state. New tasks
   may arrive with different verify-command shapes; the B6
   `cd /d` pattern is observed in 4/5 execute tasks but
   could shift.
3. The `__pycache__` staleness is COSMETIC. Stale .pyc
   files do not affect script-mode invocation. Cleaning is a
   Marie-Kondo move, not a correctness fix.
4. The fuzzy-tool-name match (B8/B9) is a UX-soft check, not
   a security gate — a determined teammate can mark
   completion without doing work by retrying past the
   transcript heuristic ("you may mark it complete again").
   This is by design — the hook is a guardrail, not a
   mandatory enforcement.
5. The Phase 3 ship is INTENTIONALLY MINIMAL. Two safe
   changes only. The biggest impact recommendation (R1
   timeout fix) is deferred for user signoff because it
   touches `settings.json` outside the explicit Phase 3
   scope.

---

## Sources

- `~/.claude/hooks/agent-teams/task-completed.py` — 197 LOC
  audited.
- `~/.claude/hooks/agent-teams/teammate-idle.py` — 113 LOC
  audited.
- `~/.claude/settings.json` lines 55-76 — hook configuration
  (TeammateIdle + TaskCompleted with `"timeout": 5`).
- `~/.claude/tasks/execute/29.json` through `33.json` —
  empirical metadata.verify pattern survey.
- `~/.claude/tasks/kite-mcp-server/*.json` — 42 tasks (none
  with metadata.verify) cross-checked.
- `~/.claude/teams/execute/config.json` — team-config shape;
  metadata.verify is a per-task field, not team-config.
- `MEMORY.md` "Hooks Architecture" — pattern: fail-open, exit
  2 + stderr to block; hooks live under
  `C:\Users\Dell\.claude\hooks\` with subfolder `agent-teams/`.
  References hooks.md which DOES NOT EXIST at this audit time
  (memory index is stale on this point).

---

*Generated 2026-05-02 night, read-only research deliverable for
the kite-mcp-server `.research/` artifact tree. Phase 3 ship
applied to `~/.claude/hooks/agent-teams/*.py` (outside any git
repo); Phase 1 + Phase 2 + Phase 3-decision documented above.*
