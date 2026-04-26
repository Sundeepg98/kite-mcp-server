# `<new-diagnostics>` mechanism — source-level proof (2026-04-26)

Investigation prompted by user's correct rejection of "the editor harness feeds it" hand-wave. This doc traces the mechanism end-to-end from compiled binary, with file offsets and code citations.

**Verdict in one line:** `<new-diagnostics>` is emitted by `claude.exe` itself in the `nk1` per-turn dispatcher's `case "diagnostics":` branch. Two parallel feeders exist (`EN1` pulls from IDE bridge MCP client; `hN1` pulls from claude.exe's built-in LSP server manager registry). Both gate on the turn's `tools` containing Edit/Write. Both currently return empty for Go files because (a) IDE bridge has no Go diagnostics in cache, (b) claude.exe's marketplace `lspServers` manager isn't actually spawning gopls in this session despite the code path being present in the binary.

## 1. Origin process + emission code path

**Process:** `claude.exe` at `C:\Users\Dell\.local\bin\claude.exe` — version 2.1.119, `InternalName: bun` (Bun-compiled standalone binary, 254 MB). Confirmed via `Get-Item .VersionInfo`.

**Bytecode is plain enough to grep.** Embedded source strings searchable with `mmap.find()`. Hits for key terms:

| Needle | Count | First offsets |
|---|---|---|
| `new-diagnostics` | 6 | 132444422, 164216841, 248222334 |
| `<new-diag` | 3 | 132444421, 164216840, 248222333 |
| `getDiagnostics` | 10 | 132204564, 132223742, ... |
| `publishDiagnostics` | 9 | 131019391, 131027167, 158116480 |
| `lspServers` | 36 | 124000301, 130954405, 131022619 |
| `getNewDiagnostics` | 6 | 131826477, 132224202, ... |
| `getLSPDiagnosticAttachments` | 3 | 131826669, 160946865, 247604581 |

**The emission switch case (offset 132444421, verbatim):**

```js
case "diagnostics": {
  if (H.files.length === 0) return [];
  let $ = fQ.formatDiagnosticsSummary(H.files);
  return J1([q6({
    content: `<new-diagnostics>The following new diagnostic issues were detected:\n\n${$}</new-diagnostics>`,
    isMeta: !0
  })]);
}
```

This is dispatched from a switch over an attachment `H.type`. Same code at offset 248222333 (duplicate bundle).

## 2. Trigger conditions

**The dispatcher `nk1` (offset 131808119), called once per main-agent turn:**

```js
function nk1(H, q, $, K, _, f, A) {
  ...
  W = D ? [   // D = !q.agentId — only on main agent, not subagent
    hz("ide_selection", async () => zN1($, q)),
    hz("ide_opened_file", async () => ON1($, q)),
    hz("output_style", async () => Promise.resolve(AN1())),
    hz("diagnostics",      async () => EN1(q)),  // ← path A
    hz("lsp_diagnostics",  async () => hN1(q)),  // ← path B
    hz("unified_tasks",    async () => CN1(q)),
    ...
  ] : [];
  ...
}
```

**Path A — `EN1` (offset 131826477):**

```js
async function EN1(H) {
  if (!H.options.tools.some($ => u4($, O$) || u4($, DK))) return [];
  let q = await LqH.getNewDiagnostics();
  if (q.length === 0) return [];
  return [{type: "diagnostics", files: q, isNew: !0}];
}
```

`LqH.getNewDiagnostics` (class method at offset 132224202) calls into the IDE bridge MCP client:

```js
async getNewDiagnostics() {
  if (!this.initialized || !this.mcpClient || this.mcpClient.type !== "connected") return [];
  let H = [];
  try {
    let _ = await Yd("getDiagnostics", {}, this.mcpClient);
    H = this.parseDiagnosticResult(_);
  } catch (_) { return [] }
  // diff against this.baseline (per-URI), return only NEW errors
  ...
}
```

Same class has `beforeFileEdited(H)` which captures the per-file diagnostic baseline BEFORE an Edit, so `getNewDiagnostics` after the Edit returns only NEW errors that appeared.

**The IDE bridge's MCP client is identified:** offset 132204530 shows `_b1 = ["mcp__ide__executeCode", "mcp__ide__getDiagnostics"]` — these are the IDE-namespaced tools. The IDE bridge is connected via WebSocket or SSE from claude.exe to a separate process (likely the user's editor). At offset 133049010 the connection config: `{type: "ws-ide" | "sse-ide", url, ideName, authToken, ideRunningInWindows}`.

**Path B — `hN1` (offset 131826583):**

```js
async function hN1(H) {
  if (!H.options.tools.some(q => u4(q, O$) || u4(q, DK))) return [];
  E("LSP Diagnostics: getLSPDiagnosticAttachments called");
  try {
    let q = _UK();                               // pull pending diagnostic sets from registry
    if (q.length === 0) return [];
    let $ = q.map(({files: K}) => ({type: "diagnostics", files: K, isNew: !0}));
    if (q.length > 0) fUK();                     // clear delivered diagnostics from registry
    return $;
  } catch (q) { ... }
}
```

The producer for `_UK` is `$UK` (offset 131027934). Searching for the publishDiagnostics handler at offset 131027167:

```js
function EX_(H) {
  let q = H.getAllServers();    // claude.exe's built-in LSP server registry
  ...
  for (let [A, z] of q.entries()) {
    z.onNotification("textDocument/publishDiagnostics", (Y) => {
      E(`[PASSIVE DIAGNOSTICS] Handler invoked for ${A}!`);
      ...
      // version check, empty check, then:
      $UK({serverName: A, files: O});   // queue into registry that hN1 reads
    });
  }
}
```

This is the publishDiagnostics receiver inside claude.exe. It runs over `getAllServers()` of an LSP server manager that claude.exe maintains internally. **Servers in this manager come from marketplace `lspServers` plugin manifests** — confirmed by offset 131022619: the manager initializes from `lspServers` config, validates `command` and `extensionToLanguage`, registers `workspace/configuration` handlers, etc.

**Both gates require:** `H.options.tools.some($ => u4($,O$) || u4($,DK))` — the turn's tool list must contain at least one of `O$`/`DK`. These are minified bindings. Strong inference: these are Edit and Write tool definitions (the dispatcher fires post-tool-use, and Edit/Write are the operations that change file content and produce new diagnostics).

## 3. Why pyright sometimes works (empirical traces)

**Theory:** Path A (EN1) succeeds when the IDE bridge MCP client is connected AND its underlying source has pyright diagnostics for the edited file.

**Empirical truth right now (2026-04-26 21:30):**

```
mcp__ide__getDiagnostics (no-arg)     → []     (cache empty for ALL files)
mcp__ide__getDiagnostics on bad.py    → [{"uri":"file:///d:/Sundeep/projects/lsp-test/bad.py","diagnostics":[]}]
mcp__ide__getDiagnostics on bad.go    → [{"uri":"file:///d:/Sundeep/projects/lsp-test/bad.go","diagnostics":[]}]
```

Pyright is NOT actually populating the IDE bridge cache right now. **Pyright is also silent for `<new-diagnostics>` in this session.** Edit on `bad.py` (also performed earlier this session) did NOT trigger any reminder.

**Pyright was "working" earlier** because in another session OR earlier in this session, the user had a `.py` buffer open in their editor (likely VS Code with the Claude Code extension). VS Code's pyright extension was publishing diagnostics; the IDE bridge was forwarding them to claude.exe via `mcp__ide__getDiagnostics`; `EN1` was diffing them and emitting `<new-diagnostics>`.

**The mechanism IS pyright-agnostic.** Same code path would fire for any LSP server whose diagnostics reach `mcp__ide__getDiagnostics`.

## 4. Why gopls doesn't (empirical traces)

**Path A (EN1) fails because:** `mcp__ide__getDiagnostics` returns `[]` for Go files. The user has no `.go` buffer open in any editor that's bridged to claude.exe.

**Path B (hN1) fails because:** claude.exe's built-in `lspServers` manager has not actually spawned gopls. Empirical proof from process tree at 21:15:09:

| Process | Parent chain |
|---|---|
| Bridge PID 9860 | → cclsp PID 9968 → cmd `cmd /c cclsp` (PID 4356) → claude.exe PID 12012 |
| Bridge PID 22648 | → cclsp PID 19804 → ... |
| WSL gopls PIDs 1625/2553 | spawned via cclsp's bridges (PIDs 18748/8368 wsl.exe → 22648/9860 node bridge → cclsp) |
| pyright PIDs 11420 (most recent) | → `cmd /c pyright-langserver --stdio` (PID 23016) → cclsp PID 9968 |

**Every LSP server (gopls AND pyright) currently running was spawned by cclsp.** ZERO spawned by claude.exe's built-in LSP server manager. The marketplace plugin's `lspServers` mechanism — which is fully present in the bytecode — **is not actually running in this session**. Possibilities:

- It requires an editor-pane buffer of the registered extension to lazy-spawn (consistent with previous findings).
- It may be opt-in via a flag we haven't set.
- It may run only when `IDE bridge type === "ws-ide"` is active (i.e., user has the Claude Code editor extension).

Either way: **gopls's diagnostics never reach the registry that `hN1` reads from.** cclsp has its own `serverState.diagnostics` cache (cclsp 0.7.0 `dist/index.js:29379`) — that's a different store, only readable via `mcp__cclsp__get_diagnostics`, not via `_UK()`.

## 5. Engineering parity — provable options

### Option 1: Hook-based pull (PROVABLE TO WORK, doesn't need editor pane)

Install a `PostToolUse` hook in `~/.claude/settings.json` that fires after `Edit|Write` on `*.go` files and calls `mcp__cclsp__get_diagnostics`. The hook injects a system message with the result so the orchestrator sees gopls errors equivalently to `<new-diagnostics>`.

Pseudocode for the hook script:
```bash
#!/usr/bin/env bash
file_path="$1"
case "$file_path" in
  *.go)
    diag=$(claude --tool mcp__cclsp__get_diagnostics --file_path "$file_path")
    if [[ "$diag" != *"No diagnostics"* ]]; then
      echo "<go-diagnostics>$diag</go-diagnostics>"
    fi
    ;;
esac
```

This is testable empirically: edit `bad.go`, observe whether the hook fires and whether the synthesized message reaches the orchestrator's context. **Doesn't depend on editor state, claude.exe internals, or marketplace plugin behavior.**

### Option 2: Connect a real IDE bridge (PROVABLE BUT REQUIRES EDITOR INTERACTION)

Install the Claude Code editor extension in VS Code. Open `bad.go` in VS Code with the extension active. Verify `mcp__ide__getDiagnostics` starts returning non-empty for that file. Then `<new-diagnostics>` should fire on subsequent Edits via `EN1`.

This proves the mechanism works for Go IF the editor is bridged. Doesn't help pure-orchestrator workflows.

### Option 3: Wait for claude.exe to fix marketplace `lspServers` lazy-spawn (NOT IN OUR CONTROL)

The bytecode shows full `lspServers` consumption code paths exist. They're just not running for gopls in this session. Either fix is upstream of us OR requires triggering a specific code path we haven't identified.

**Recommendation:** Option 1. ~30-line shell hook + settings.json entry. Tested locally on this machine before declaring done.

## Honest opacity

What I CAN'T fully prove from the bytecode alone:

- The exact gating bindings `O$` and `DK`. Strongly inferred to be Edit and Write tool defs based on the dispatcher's role and the message template ("new diagnostic issues were detected"), but not verified by tracing the bindings through the bundle.
- Why claude.exe's `lspServers` manager isn't running in THIS session despite the code being present. Hypotheses: lazy-spawn on editor-buffer-open, opt-in flag, or IDE-bridge dependency. Would need to set `WSL_LSP_BRIDGE_LOG`-equivalent at the gopls-cmd shim level to capture if claude.exe ever invokes `gopls.cmd` and prove/disprove lazy-spawn vs alternatives.
- Whether VS Code's bridge is the only IDE source for path A, or whether other editors / non-editor sources also feed it.

What I CAN prove conclusively:

- The exact emission code at offset 132444421 in `claude.exe`.
- The exact dispatch (function `nk1`) that calls EN1 and hN1 every turn.
- Both feeder functions and their data sources.
- That the marketplace `lspServers` consumption code IS in the binary.
- That NO LSP servers are currently spawned by claude.exe's built-in manager — all are spawned by cclsp.
- That `mcp__ide__getDiagnostics` is empty for both Python and Go right now → both languages are equally silent for `<new-diagnostics>` at this moment.

## Appendix: file offsets in claude.exe (for future archaeology)

All offsets in the standalone `C:\Users\Dell\.local\bin\claude.exe` binary, version 2.1.119 (build 2026-04-23, git sha `6f68554839756189e277b8285a18fe47acd9a5a1`):

| Code feature | Offset(s) |
|---|---|
| `<new-diagnostics>` template | 132444421, 248222333 |
| `function nk1` (per-turn dispatcher) | 131808119, 247586031 |
| `async function EN1` (path A) | 131826395 (call), 131826477 (getNewDiagnostics call) |
| `async function hN1` (path B) | 131826583, 247604495 |
| `class LqH` (IDE bridge diagnostic client, has `beforeFileEdited` + `getNewDiagnostics`) | 132224202 |
| `_b1 = ["mcp__ide__executeCode", "mcp__ide__getDiagnostics"]` | 132204530 |
| IDE bridge connection config (`ws-ide`/`sse-ide`) | 133049010 |
| Marketplace `lspServers` config consumer | 130954405 |
| `[LSP SERVER MANAGER]` getAllLspServers + extensionToLanguage validation | 131022619 |
| `onNotification("textDocument/publishDiagnostics", ...)` registry feeder | 131027167 |
| LSP `initialize` capabilities setup | 131019391 |
| `$UK`/`_UK`/`fUK` registry funcs | 127977491, 127978495, 127980141 |
| `version: "2.1.119"` + git sha + build time | 131019391 |

Method to reproduce the discovery:
```python
import mmap
with open(r'C:\Users\Dell\.local\bin\claude.exe', 'rb') as f:
    mm = mmap.mmap(f.fileno(), 0, access=mmap.ACCESS_READ)
    idx = mm.find(b'<new-diag')
    print(mm[max(0, idx-400):idx+800].decode('utf-8', errors='replace'))
```

Future Claude Code versions may reorder the bundle; offsets will drift but the code patterns (`case "diagnostics":`, `function nk1`, `LqH.getNewDiagnostics`) should remain greppable.
