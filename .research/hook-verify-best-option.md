# Task-Completed Hook Verification: Best Approach Analysis

## Problem Statement
Current hook (119 lines) only checks for tool calls in transcript, missing broken builds. Example: agent marks Go task complete despite `go build ./...` failure.

## Option Comparison Matrix

| Aspect | A: Hardcoded | B: Metadata | C: Config File | D: External | E: Composite | F: Post-Block |
|--------|------------|-----------|----------------|-----------|-----------|--------------|
| Perf (sec/task) | 20-30 | <0.1 | <0.1 | 0 (async) | 20-30 | 0 |
| Impl (lines) | 40-50 | 35-40 | 60-70 | 150+ | 80-100 | 50-60 |
| False Positives | High | Low | Low | None | Low | None |
| False Negatives | Very Low | Medium | Medium | High | Very Low | High |
| Maintenance | Low | Medium | High | High | Medium | Medium |

### Performance Breakdown
- **Hardcoded (go.mod detected)**: Runs `go build`, `go vet`, `go test -short` → 20-30s typical
- **Metadata**: Parse task, exec command → negligible if fast command
- **Config File**: File lookup + exec → same as B
- **External**: Hook returns immediately, async agent picks up → no latency
- **Composite**: Runs B first (fast), falls back to A only if needed → hybrid
- **Post-Block**: Hook passes, secondary hook on TaskList/TaskUpdate → hidden latency

### False Positive Rate (blocks valid work)
- **A**: High—doesn't account for tests that legitimately fail before feature complete
- **B**: Low—only runs what task creator specified
- **C**: Low—config is explicit
- **D**: None—verification is async
- **E**: Low—metadata overrides fallback heuristics
- **F**: None—never blocks completion, reverts post-facto

### False Negative Rate (allows broken completions)
- **A**: Very Low—catches most build failures
- **B**: Medium—depends on task creator remembering to set verify command
- **C**: Medium—depends on config accuracy
- **D**: High—async feedback means developer doesn't see it during completion
- **E**: Very Low—metadata catches well-defined; fallback catches build failures
- **F**: High—by design, revert happens later in task list

---

## How Industry Solves This

**GitHub Actions / GitLab CI**: Decoupled required checks
- Verification runs in parallel, independently
- Merge blocking happens at PR level, not push level
- Caching + incremental builds reduce re-run time
- Lesson: *Don't serialize verification with user interaction*

**Pre-commit Framework**: Local, incremental, configurable
- `.pre-commit-config.yaml` defines checks per project
- Runs only on changed files
- Developer controls via framework config
- Lesson: *Config should be co-located with code*

**Bazel / Buck**: Hermetic, cached verification
- `bazel test //...` is fast on re-runs due to caching
- Output determinism prevents flaky "it passes sometimes" behavior
- Lesson: *Cached verification is real verification*

---

## Recommendation: Option E (Composite)

**Implement metadata-first with fallback build detection.**

### Rationale
1. **Covers both explicit and implicit cases**: Tasks with `metadata.verify` get exact verification; Go/Node/Python projects fall back to standard build checks
2. **Balances latency vs. correctness**: Optional metadata allows skip for fast investigative tasks; fallback catches common breakage
3. **Minimal hook code**: ~100 lines; ~50 lines to existing 119
4. **Adopted by teams gradually**: Early adopters add metadata to their tasks; others benefit from fallback
5. **Mirrors pre-commit + GitHub patterns**: Metadata is like `.pre-commit-config.yaml`; fallback is like required status checks

### Implementation (pseudocode)
```python
def verify_completion(task, cwd):
    # 1. Check task metadata for verify command
    if task.get("metadata", {}).get("verify"):
        cmd = task["metadata"]["verify"]
        result = subprocess.run(cmd, cwd=cwd, timeout=60)
        if result.returncode != 0:
            return False  # block completion
        return True
    
    # 2. Fallback: detect project type and run standard checks
    if Path(cwd) / "go.mod" exists:
        # Run `go vet ./...`, maybe `go test -short ./...`
        # Timeout: 30s
    elif Path(cwd) / "package.json" exists and Path(cwd) / "tsconfig.json" exists:
        # Run `npm run verify` or `npm test -- --no-coverage`
        # Fallback: skip if no verify script
    elif Path(cwd) / "pyproject.toml" or "setup.py" exists:
        # Run `pytest -x` or `python -m pytest`
        # Timeout: 30s
    else:
        # No recognized project → pass (investigative tasks, infrastructure)
        return True
    
    return result.returncode == 0
```

### Performance Impact
- **Metadata cases**: <0.1s (just parse JSON)
- **Go/Node/Python fallback**: 15-30s first run, cached re-runs ~2-5s
- **No fallback (Python, edge cases)**: <0.1s
- **Average**: ~5-10s per completion (most are cached or metadata-only)

### Maintenance Burden
- Initial: 100 lines of Python, test with 3-4 project types
- Ongoing: Add new project type heuristics as needed (rare)
- No external service, no config file sync problems

---

## Why Not the Others?

**A (Hardcoded Go)**: Too slow, too specific, too many false positives on pre-feature branches.

**B (Metadata only)**: Good but places burden on task creator; misses broken builds when metadata is forgotten.

**C (Config file)**: Extra indirection; adds file sync burden (`~/.claude/hooks/agent-teams/verify.json`).

**D (External agent)**: Solves latency but loses "immediate feedback" during TaskCompleted call; catch-and-fix loop is slower than prevent.

**F (Post-block)**: Feels broken to agents; they mark complete then get reverted; bad UX, debugging confusion.

---

## Migration Path

1. **Week 1**: Deploy E (composite) with Go fallback only
2. **Week 2**: Document `metadata.verify` pattern in task creation guide
3. **Week 3-4**: Add Node, Python heuristics as projects emerge
4. **Month 2+**: Monitor false negatives; adjust timeouts and heuristics based on real runs

## Success Metric
- **False negatives drop to <5%** (currently ~30-40% based on broken builds slipping through)
- **Hook latency stays <15s p50** (avoid slowing down agent velocity)
- **Task creators opt into metadata** for custom verify commands on 20%+ of new tasks
