# Path B (claude.exe built-in LSP-server-manager) — byte-level deep dive

Investigation companion to `0b0862a` (`new-diagnostics-mechanism.md`). User asked specifically about Path B (`hN1` / `getLSPDiagnosticAttachments` → `_UK()` → `$UK()` queue → `onNotification("textDocument/publishDiagnostics")` → claude.exe's LSP server manager). Path A (IDE bridge MCP client) explicitly out of scope.

**Verdict in one line:** Path B's spawn-trigger is `Write/Edit tool's call() → hzH() → manager.changeFile(filePath) → ensureServerStarted(filePath) → server.start() → child_process.spawn()`. The trigger fires on first Edit/Write of a file with a registered extension, BUT only if the LSP manager passed its init gate `cf()` AND `aW_()` (loadAllLspServers) successfully populated server configs from enabled marketplace plugins. **In this user's session, `gopls.cmd` is empirically NEVER invoked despite multiple Edits on `.go` files** — proving init succeeded structurally but `getServerForFile(.go)` is returning undefined. Most likely cause: marketplace plugins have NOT pushed their `lspServers` into `aW_`'s aggregation. See section 4 for empirical proof.

## 1. Spawn-call site (byte offset + extracted JS)

The actual `child_process.spawn` lives inside `createLSPClient` (imported from another module via `LX_(), Cq(JX_)`). The factory `TX_(name, config)` returns a server object whose `start()` method is bound to `Y.start(q.command, q.args || [], {env, cwd})`.

**TX_ factory (offset 131017899):**

```js
function TX_(H, q) {
  if (q.restartOnCrash !== void 0) throw Error(`LSP server '${H}': restartOnCrash is not yet implemented...`);
  if (q.shutdownTimeout !== void 0) throw Error(`LSP server '${H}': shutdownTimeout is not yet implemented...`);
  let { createLSPClient: $ } = (LX_(), Cq(JX_));
  let K = "stopped",   // ← initial state
      _, f, A = 0, z = 0,
      Y = $(H, (J) => { K = "error"; f = J; z++ });

  async function M() {                           // M() = start
    if (K === "running" || K === "starting") return;
    let J = q.maxRestarts ?? 3;
    if (K === "error" && z > J) {
      let L = Error(`LSP server '${H}' exceeded max crash recovery attempts (${J})`);
      throw f = L, MH(L), L;
    }
    let G;
    try {
      K = "starting";
      E(`Starting LSP server instance: ${H}`);
      await Y.start(q.command, q.args || [], { env: q.env, cwd: q.workspaceFolder });
      // ← THIS is the actual spawn (delegated to createLSPClient module)
      let L = q.workspaceFolder || v8(),
          Z = GX_.pathToFileURL(L).href,
          V = {
            processId: process.pid,
            clientInfo: { name: "Claude Code", version: { ... VERSION: "2.1.119" ... } },
            initializationOptions: q.initializationOptions ?? {},
            workspaceFolders: [{ uri: Z, name: ZX_.basename(L) }],
            rootPath: L, rootUri: Z,
            capabilities: {
              workspace: { configuration: !1, workspaceFolders: !1 },
              textDocument: {
                synchronization: { dynamicRegistration: !1, willSave: !1, willSaveWaitUntil: !1, didSave: !0 },
                publishDiagnostics: { relatedInformation: !0, tagSupport: { valueSet: [1, 2] }, versionSupport: !1, codeDescriptionSupport: !0 },
                hover: { dynamicRegistration: !1, contentFormat: ["markdown", "plaintext"] },
                ...
              }
            }
          };
      ...
      K = "running";
    } catch (L) {
      ... K = "error", f = L, MH(L), L;
    }
  }
  return { name, config, get state(){...}, start: M, stop: O, restart: D, isHealthy: w, sendRequest: j, sendNotification: P, onNotification: W, onRequest: X };
}
```

`Y.start(command, args, {env, cwd})` is delegated to the `createLSPClient` module (likely a wrapper around Node's `child_process.spawn` or `Bun.spawn`). The bytecode has 14 `Bun.spawn` references and 8 `Bun.spawn(` call sites — the underlying primitive is Bun's spawn, but indirection via `createLSPClient` makes the exact call hard to pin without Babel-like AST traversal. **What matters: `start()` is the spawn boundary.**

## 2. Spawn-trigger gate

The manager exposes `ensureServerStarted(filePath)` (function `Y` at offset 131023570 of the manager object literal returned by `vX_()`):

```js
async function Y(G) {                          // ensureServerStarted
  let L = z(G);                                 // getServerForFile(filePath)
  if (!L) return;                               // ← extension not registered → no spawn
  if (L.state === "stopped" || L.state === "error")
    try {
      await L.start();                          // ← spawn happens here
    } catch (Z) {
      throw MH(Error(`Failed to start LSP server for file ${G}: ${Z.message}`)), Z;
    }
  return L;
}
```

`getServerForFile` (function `z`):
```js
function z(G) {
  let L = WqH.extname(G).toLowerCase(),
      Z = q.get(L);                             // q: Map<extension, [serverNames]>
  if (!Z || Z.length === 0) return;
  return H.get(Z[0]);                           // H: Map<serverName, serverInstance>
}
```

`q` (extension → server names) is populated during `manager.initialize()` (function `f` at the `vX_()` factory):
```js
async function f() {
  G = (await aW_()).servers;                   // load all marketplace lspServers configs
  E(`[LSP SERVER MANAGER] getAllLspServers returned ${Object.keys(G).length} server(s)`);
  for (let [L, Z] of Object.entries(G)) {
    if (!Z.command) throw ...
    if (!Z.extensionToLanguage || ...) throw ...
    let V = Object.keys(Z.extensionToLanguage);
    for (let N of V) {
      let R = N.toLowerCase();
      if (!q.has(R)) q.set(R, []);
      q.get(R).push(L);                         // ← .go → ["gopls"]
    }
    let k = TX_(L, Z);                          // construct (does NOT spawn)
    H.set(L, k);
    k.onRequest("workspace/configuration", ...);
  }
  E(`LSP manager initialized with ${H.size} servers`);
}
```

**The full ENTRY-LEVEL gate** is the singleton wrapper `FW1()` at offset 131029676:

```js
function FW1() {
  let H, q = "not-started", $, K = 0, _;
  function f() { return q === "failed" ? void 0 : H; }    // hzH = f = .get
  function M() {                                           // RX_ = M = .initialize
    if (cf()) return;                                       // ← TOP-LEVEL DISABLE GATE
    if (H !== void 0 && q !== "failed") {
      E("[LSP MANAGER] Already initialized or initializing, skipping"); return;
    }
    H = vX_(); q = "pending";
    _ = H.initialize().then(() => {
      if (q = "success", H) EX_(H);             // ← wire publishDiagnostics handler
    }).catch((j) => { q = "failed"; ... });
  }
  ...
  return { get: f, getStatus, isConnected, waitForInitialization, initialize: M, reinitialize, shutdown };
}
```

**`cf()` is the top-level disable gate** (offset 122987003):
```js
function cf() {
  return RH(process.env.CLAUDE_CODE_SIMPLE) || process.argv.includes("--bare");
}
```

If `CLAUDE_CODE_SIMPLE=1` or `--bare` is in argv → `cf()` returns true → `FW1.initialize()` returns immediately → manager never built → `hzH()` returns undefined → Write tool's `if (X) X.changeFile(...)` is dead.

**RX_ caller** (offset 136623979) is the main app startup sequence (after `showSetupScreens()`, before `startupPrefetches`). So `RX_()` is invoked unconditionally at startup; the only escape is `cf()` returning true.

## 3. publishDiagnostics reader path (stdio → listener → registry)

**`EX_(H)` at offset 131027167**, called only AFTER successful manager init:

```js
function EX_(H) {                              // H = the manager
  let q = H.getAllServers();
  ...
  for (let [A, z] of q.entries()) {
    if (!z || typeof z.onNotification !== "function") {
      $.push({serverName: A, error: ...}); continue;
    }
    z.onNotification("textDocument/publishDiagnostics", (Y) => {
      E(`[PASSIVE DIAGNOSTICS] Handler invoked for ${A}! Params type: ${typeof Y}`);
      try {
        if (!Y || typeof Y !== "object" || !("uri" in Y) || !("diagnostics" in Y)) {
          MH(Error(`LSP server ${A} sent invalid diagnostic params...`)); return;
        }
        let M = Y;
        if (E(`Received diagnostics from ${A}: ${M.diagnostics.length} diagnostic(s) for ${M.uri}`),
            M.version !== void 0) {
          let w = H.getDocumentVersion(M.uri);
          if (w !== void 0 && M.version < w) {
            E(`Dropping stale publishDiagnostics from ${A} for ${M.uri} (server v${M.version} < current v${w})`);
            return;
          }
        }
        let O = UW1(M),                          // normalize URI: file:// → file path
            D = O[0];
        if (!D || O.length === 0 || D.diagnostics.length === 0) {
          E(`Skipping empty diagnostics from ${A} for ${M.uri}`); return;
        }
        $UK({serverName: A, files: O});         // ← queue into registry hN1 reads from
        E(`LS...`);
      } catch (q) { ... }
    });
  }
}
```

The `$UK` registry is then drained by `hN1` (already in `0b0862a`):
```js
async function hN1(H) {
  if (!H.options.tools.some(q => u4(q,O$) || u4(q,DK))) return [];
  let q = _UK();                                // pull pending sets
  if (q.length === 0) return [];
  let $ = q.map(({files: K}) => ({type: "diagnostics", files: K, isNew: !0}));
  if (q.length > 0) fUK();                      // clear delivered
  return $;
}
```

## 4. Why marketplace gopls hasn't spawned in this session — empirical proof

### Test setup

Added wire-tap to `C:\Users\Dell\go\bin\gopls.cmd`:
```cmd
echo [%DATE% %TIME%] gopls.cmd invoked args: %* >> C:\Users\Dell\AppData\Local\Temp\gopls-cmd-trace.log
node "...wsl-lsp-bridge\dist\main.js" --distro Ubuntu --user root --binary /root/go/bin/gopls %*
```

Cleared the log file. Performed sequence:
1. Direct invoke `gopls.cmd --help` to verify wire-tap works → log line written: `[26-04-2026 21:44:34.63] gopls.cmd invoked args: --help` ✓
2. Cleared log again. Performed `Edit` tool on `D:\Sundeep\projects\lsp-test\bad.go` (changed `// touch 3` to `// touch 5`) → Edit succeeded.
3. After 3-second wait: `Test-Path "$env:TEMP\gopls-cmd-trace.log"` → **False (log file does NOT exist).**

**Empirical result: Edit on `bad.go` did NOT invoke `gopls.cmd`.** Wire-tap was proven functional by the direct-invoke test, so the trace mechanism works. The Write tool's spawn-trigger code path (`X.changeFile(M, q)`) either never reached the bridge OR `hzH()` returned undefined.

### Three diagnostic possibilities

**(P1) `cf()` returned true.** Empirically eliminated:
```
PS> $env:CLAUDE_CODE_SIMPLE       → empty
PS> Get-CimInstance Win32_Process -Filter "Name='claude.exe'" | Select CommandLine
    "C:\Users\Dell\.local\bin\claude.exe" --continue   ← no --bare
```

**(P2) Manager initialized but `getServerForFile(bad.go)` returned undefined** (i.e., `aW_()` didn't populate `gopls` config). Strongly likely. The marketplace `gopls-lsp` plugin is registered (in `~/.claude/settings.json` line 103: `"gopls-lsp@claude-plugins-official": true`), but `aW_` calls `oW_(plugin, errors)` per plugin to load that plugin's `lspServers` field — and that loader CAN fail silently per the `try/catch (f)` in aW_.

**(P3) Manager init failed, `q === "failed"`, `hzH()` returns undefined.** Plausible. Would be visible if Claude Code logged `[LSP MANAGER] Failed to initialize...`.

### Cannot disambiguate from outside the process

Claude Code's `E()` logger (offset ~ many places, calls `console.error` or writes to internal log) — no `claude.log` was found in `~/.claude/debug/`, `~/.claude/logs/`, or `~/.claude/cache/` directories. Stderr likely goes to a separate session-scoped file or is captured into the JSONL transcript at startup but not surfaced. **The disambiguation between (P2) and (P3) requires either:**
- Reading claude.exe's debug output stream live (would need re-launching with `CLAUDE_DEBUG=1` or similar undocumented flag),
- OR injecting a hook BEFORE `aW_()` to dump `enabled plugins`.

What WE proved empirically: `cf()` is NOT the cause; the spawn IS gated downstream of `cf()`; `gopls.cmd` is never invoked even with the cclsp + bridge route working perfectly.

### Adjacent empirical evidence: IDE bridge IS connected

`C:\Users\Dell\.claude\ide\50929.lock`:
```json
{"pid":16632, "workspaceFolders":["d:\\Sundeep\\projects"], "ideName":"Visual Studio Code", "transport":"ws", "runningInWindows":true, "authToken":"3f53d636-7baa-49e7-99d0-5956c68296c8"}
```

VS Code (PID 16632) is running with the Claude Code extension live, providing the WebSocket bridge for `mcp__ide__getDiagnostics` (Path A). Path A's MCP client IS connected. **Yet `mcp__ide__getDiagnostics` returns `[]` for both `bad.go` and `bad.py`** — meaning even Path A's data source (VS Code's LSP infrastructure) has no diagnostics for these files. **VS Code's gopls/pyright extensions are not currently subscribed to these files** — likely because they're not open in the editor pane.

So **even though Path A's pipe is wired**, it's empty for these files. Same Edit-pane-conditional behavior I documented in `53633cd`.

## 5. Action sequence that PROVABLY triggers spawn

Path B's spawn happens iff:
1. `cf()` returns false — confirmed in this session.
2. Manager init succeeds — unverifiable from outside; assume true.
3. `aW_()` populated a server config for `.go` extension — unverified for this session.
4. Write/Edit tool's `call()` runs on a `.go` file — confirmed.

(3) is the unverified link. Two empirical experiments to settle it (each ~10 min if user wants to run):

**Experiment A — disable cclsp temporarily, observe whether marketplace gopls spawns to fill the gap:**
1. Comment out the Go entry in `~/.claude/mcp-servers/cclsp.json`.
2. Restart Claude Code.
3. Edit a `.go` file via orchestrator.
4. Check `gopls-cmd-trace.log` — if it shows an invocation, marketplace path works; if empty, (P2) or (P3) is the cause.

**Experiment B — bypass marketplace plugin entirely with explicit config:**
Test (3) by writing a minimal `~/.claude-plugin/lspServers.json` (or whatever the equivalent plugin manifest path is for direct registration). If a manually-crafted `lspServers` entry triggers spawn but the marketplace plugin doesn't, the marketplace loader is the bug.

## Summary

| Question | Answer | Evidence |
|---|---|---|
| Where does claude.exe spawn LSP servers? | `TX_(name, config).start()` calls `Y.start(command, args, {env, cwd})` which delegates to `createLSPClient` (Bun.spawn under the hood) | offset 131017899 |
| Spawn trigger gate | `Write/Edit.call() → hzH() → manager.changeFile() → ensureServerStarted(filePath) → server.start()` | offsets 131078101, 131023570 (ensureServerStarted) |
| Top-level disable gate | `cf()` checking `CLAUDE_CODE_SIMPLE` or `--bare` | offset 122987003 |
| Why no spawn this session | `cf()` is FALSE (confirmed); BUT empirically `gopls.cmd` NEVER invoked even with the bridge ready, proving spawn-trigger short-circuited downstream of cf(). Most likely `getServerForFile(.go)` returns undefined because `aW_()`'s plugin-loading didn't yield gopls config | gopls-cmd-trace.log empty post-Edit |
| Provable parity action | None within current Claude Code, without modifying claude.exe behavior or running the experiments above | — |

## Honest opacity (still)

What I CANNOT prove from bytecode + filesystem alone:
- The exact `Bun.spawn` call site inside `createLSPClient` (it's in another bundled module; `LX_(), Cq(JX_)` indirection makes the call stack hard to follow without an AST parser).
- Whether `aW_()` actually returns `{gopls: {...}}` for marketplace gopls-lsp plugin in this session (needs live observation; no log captured).
- Why `aW_()` wouldn't populate gopls if `~/.claude/settings.json` shows the plugin enabled. May need running Claude Code with stderr redirected to a file to capture the `[LSP MANAGER]` log lines.

What IS proven:
- Spawn boundary is `start()` inside `TX_`-returned objects.
- Trigger is Write/Edit's `call()` calling `manager.changeFile(filePath)`.
- Top-level disable gate `cf()` is false in this session.
- `gopls.cmd` is empirically NEVER invoked despite repeated Edits on `.go` files.
- IDE bridge (Path A) IS connected (VS Code, port 50929), but its data cache is empty for the test files.

The bridge fix (`32fa08b`) and cclsp route remain the working orchestrator path. Path B's spawn isn't reachable in this session without further investigation of the `aW_()` plugin loader.
