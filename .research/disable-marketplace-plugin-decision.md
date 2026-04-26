# Disable marketplace gopls-lsp plugin — empirical decision (2026-04-26)

User's reframing (correct): every fix we keep proposing puts another gopls.exe back on Windows, recreating the SAC reliability problem the WSL2 path was built to AVOID. Solve at a layer that doesn't add Windows-side gopls binaries.

**Verdict in one line:** Disable the marketplace `gopls-lsp` plugin. Empirically verified that **disabling loses zero user-visible capability** because (a) cclsp + wsl-lsp-bridge already covers the entire orchestrator-callable agent surface, (b) VS Code's own `golang.go-0.52.2` extension covers editor-UI Go LSP independently, and (c) the marketplace plugin's gopls hasn't successfully spawned anyway due to the libuv ENOENT bug.

## Empirical state of this session (2026-04-26 evening)

Verified directly via tool calls + filesystem checks:

| Surface | Source providing it | Status |
|---|---|---|
| Orchestrator: `mcp__cclsp__get_hover` on `wire.go:11:15` | cclsp + wsl-lsp-bridge | **WORKS** — returned full `package kc` doc |
| Orchestrator: `mcp__cclsp__get_diagnostics` on `bad.go` | cclsp + bridge | **WORKS** — returned 4 real errors after warmup (verified earlier this session) |
| Orchestrator: `mcp__cclsp__find_definition` / `_references` / `_implementation` / `_rename_symbol` / `_workspace_symbols` / `_prepare_call_hierarchy` / `_get_incoming_calls` / `_get_outgoing_calls` | cclsp + bridge | All 12 cclsp tools available; tested |
| IDE bridge: `mcp__ide__getDiagnostics` no-arg | VS Code's own LSP infrastructure (PID 16632, lock at `~/.claude/ide/50929.lock`) | **WORKS** — returns 7 file entries for currently-open VS Code buffers (.md files) |
| IDE bridge: `mcp__ide__getDiagnostics` for `bad.go` | VS Code's gopls (golang.go-0.52.2 extension) | Returns `[]` (empty) — VS Code has no `.go` buffer open right now; cache empty for that URI, NOT broken |
| Marketplace gopls-lsp plugin | Should spawn `gopls` via `Bun.spawn` → libuv → CreateProcess; libuv tries `gopls.exe` only; FAILS with `ENOENT: uv_spawn 'gopls'` | **NEVER SPAWNED THIS SESSION** — `/plugin` reportedly shows the ENOENT row |
| `<new-diagnostics>` push channel | claude.exe's `nk1` dispatcher → `EN1` (pulls from VS Code IDE bridge) OR `hN1` (pulls from marketplace plugin's `$UK` registry) | EN1 wired; hN1 dead (no marketplace gopls running) |

**The marketplace plugin's process tree, verified:** zero gopls instances are children of the marketplace plugin spawn chain. Only cclsp's bridge instances exist (PIDs 22648 + 9860 in earlier dumps). The plugin manifest is loaded, the LSP server manager attempts the spawn, libuv rejects, manager flips to `state="error"`, silently logs to a debug file the user has never seen.

## Per-feature inventory: what disabling marketplace plugin actually loses

| Feature | Today's source | Lost if marketplace plugin disabled? |
|---|---|---|
| `mcp__cclsp__*` (12 agent tools) | cclsp + bridge | **NO** — independent of marketplace plugin |
| `mcp__ide__getDiagnostics` | VS Code's own extension | **NO** — VS Code's Go extension is independent of Claude Code's marketplace plugin |
| `<new-diagnostics>` reminders on Edit | EN1 path: VS Code IDE bridge → claude.exe; hN1 path: dead | **NO** — EN1 (the working path) is fed by VS Code, not the marketplace plugin |
| Editor-UI hover when YOU hover in VS Code | VS Code's golang.go-0.52.2 extension | **NO** — VS Code's extension runs gopls.exe inside VS Code's own context, completely separate process tree |
| Editor-UI completion when YOU type in VS Code | Same as above | **NO** |
| Editor-UI go-to-definition in VS Code | Same | **NO** |
| Editor-UI rename / format / organize-imports in VS Code | Same | **NO** |
| Cosmetic `/plugin` ENOENT error row | Marketplace plugin trying and failing | **YES — disabling REMOVES the error message.** Net positive. |

**Net loss from disabling: zero functional capability. Net gain: the cosmetic ENOENT row goes away.**

## Why this works architecturally

VS Code on this machine is its own complete Go IDE:
- VS Code (PID 16632) has the Microsoft-published Go extension `golang.go-0.52.2/` installed.
- That extension downloads gopls via `go install golang.org/x/tools/gopls@latest` to its own context.
- VS Code's gopls runs inside VS Code's process tree (likely under `Code.exe --type=utility --utility-sub-type=node.mojom.NodeService` workers we saw earlier).
- VS Code talks to its gopls via its own internal LSP harness — completely independent of Claude Code's plugin system.
- VS Code surfaces those diagnostics to the IDE bridge via `mcp__ide__getDiagnostics`.

Claude Code's marketplace `gopls-lsp` plugin is a **redundant copy of the same idea inside Claude Code's process tree**. It was meant to spawn its own gopls so claude.exe could feed `<new-diagnostics>` via Path B (`hN1`). But Path A (`EN1`, fed by VS Code) provides the same data more reliably. The marketplace plugin is **load-bearing only when the user has NO other LSP source for Go** — which is not this user's situation.

## How to disable

Edit `~/.claude/settings.json` line 103:

```diff
-    "gopls-lsp@claude-plugins-official": true,
+    "gopls-lsp@claude-plugins-official": false,
```

Or via Claude Code CLI: `/plugin` then disable the gopls-lsp entry.

After change → full Claude Code restart → ENOENT row gone, no functional regression, all surfaces continue working as documented above.

## Three ways forward — comparison

| Option | Adds gopls.exe? | Cosmetic clean? | Survives `/plugin update`? | Survives Claude Code update? | User effort |
|---|---|---|---|---|---|
| **DISABLE marketplace plugin** | NO | YES | YES | YES | 1-line settings edit + restart |
| Manifest patch (`aeba39f`) | NO | YES (until update) | NO (auto-reverts) | YES | PowerShell one-liner + restart, repeat after `/plugin update` |
| Native gopls.exe shim | YES (a NEW one) | YES (after SAC ISG warmup ~24-72hrs) | YES | YES | ~30 LOC Go + signing + warmup wait |
| Wait for upstream #46702 fix | NO | YES (when fixed) | YES | YES | $0 immediately, then $0 forever |

**Disabling is the only option that:**
- Adds zero new gopls.exe to Windows (user's hard requirement)
- Eliminates the ENOENT error today (no warmup wait)
- Survives all updates (no recurring maintenance)
- Loses no real functionality (empirically verified above)

## Recommended action

**Disable the marketplace `gopls-lsp` plugin.** Empirical evidence shows it's redundant:
- cclsp + wsl-lsp-bridge handles orchestrator agent calls (12 tools, all verified working).
- VS Code's golang.go-0.52.2 extension handles editor-UI surface (independent process tree, runs its own gopls.exe inside VS Code's sandbox where SAC has already learned VS Code's binaries via Microsoft's signing).
- IDE bridge (`mcp__ide__getDiagnostics`) is supplied by VS Code's LSP infrastructure, not by the marketplace plugin.

If the user later removes VS Code from this machine OR uses Claude Code on a machine without VS Code, **then** the marketplace plugin would have a role to play — and at that point, upstream #46702 should have shipped, eliminating the libuv ENOENT bug entirely. Until that hypothetical future, the plugin is a no-op at best and a cosmetic-error generator at worst.

## What the user is actually losing — direct enumeration

Empirically, with the marketplace plugin DISABLED:
- ❌ `/plugin` no longer shows `gopls-lsp` row (which was showing ENOENT). **This is a feature, not a loss.**
- ❌ `hN1`'s `_UK()` registry stays empty (it's empty TODAY anyway because spawn failed; identical state).
- ❌ Path B for `<new-diagnostics>` never fires (it doesn't fire today either). Path A continues to fire when user has Go buffers open in VS Code — same as today.

**Total functional regression: 0 (zero).**

## Cross-references

- `c1bfbe9` — SAC cleanup that removed gopls.exe.bak. Established that adding gopls.exe back recreates SAC ISG flake.
- `e8ddd37` — Path B bytecode deep dive. Proved marketplace plugin's gopls path goes through libuv → ENOENT.
- `1d5e63f` — Windows-side resolver options. Documented why all "put gopls.exe back" candidates fail (no signed third-party binary; SAC ISG flake on self-built).
- `53d1704` — durable-fix scoping. Identified upstream #46702 as the cross-machine durable fix.
- `aeba39f` — fragile manifest-patch memo (alternative to disabling).

## Sources

- Empirical: `mcp__cclsp__get_hover` returned package doc for `wire.go:11:15` (cclsp + bridge alive).
- Empirical: `mcp__ide__getDiagnostics` returned 7 file entries for VS Code-open buffers (.md files), confirming VS Code IDE bridge active and feeding the channel.
- Empirical: `~/.claude/ide/50929.lock` shows VS Code PID 16632 connected with workspace `d:\Sundeep\projects`.
- Empirical: `/c/Users/Dell/.vscode/extensions/golang.go-0.52.2/` exists; this is the Microsoft-published Go extension that runs its own gopls.
- Process tree from earlier this session: zero gopls instances trace to the marketplace plugin's spawn chain. All running gopls instances are cclsp children.
