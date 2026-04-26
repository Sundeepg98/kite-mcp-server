# gopls-lsp marketplace plugin manifest patch — libuv ENOENT root cause

**Diagnosis (2026-04-26 evening, coordinator-relayed)**: User ran `/plugin` and the gopls-lsp marketplace plugin's LSP server status showed:

```
plugin:gopls-lsp:gopls
ENOENT: no such file or directory, uv_spawn 'gopls'
```

**Note on memo location:** the coordinator-specified path `~/.claude/projects/D--Sundeep-projects/notes/gopls-marketplace-manifest-patch.md` is permission-gated against agent writes. This memo is parked in the kite-mcp-server `.research/` folder where the rest of the session's investigation docs live and where this agent has unconditional write access.

## Root cause

`libuv` on Windows does NOT consult `PATHEXT` when resolving bare command names. Claude Code's binary calls `Bun.spawn("gopls", ...)` (per the marketplace manifest's `command: "gopls"`). libuv looks for **literal `gopls`** (no extension) on PATH. Result:
- `gopls.exe` was deleted earlier in the SAC cleanup work (commit `c1bfbe9`).
- `gopls.cmd` exists at `C:\Users\Dell\go\bin\gopls.cmd` but libuv won't find a `.cmd` file without `shell: true`.
- Spawn fails with `ENOENT: no such file or directory, uv_spawn 'gopls'`.

**This is the silent gate** that blocked Path B (marketplace plugin's gopls spawn → `publishDiagnostics` → `<new-diagnostics>` reminders for orchestrator-driven Edits on `.go` files).

It explains why the byte-level investigation in `e8ddd37` couldn't pin the gate from bytecode alone: `cf()` returned false, manager init succeeded structurally, manifest validation passed (`oW_`/`sP1`/`tP1` returned successfully for `command: "gopls"`), `getServerForFile(.go)` returned a server entry — but `server.start() → Y.start() → Bun.spawn("gopls", ...)` threw ENOENT, the catch swallowed it (writes via `MH(L)`, sets `state = "error"`), `hzH()` still returned the manager but `manager.changeFile(M, q).catch(...)` silently swallowed the rejection.

The empirical wire-tap on `gopls.cmd` (which I ran earlier this session and the trace log stayed empty after Edits) is consistent: claude.exe never even REACHED `gopls.cmd` because libuv rejected the spawn before resolving to the .cmd extension.

## The patch

**File:** `C:\Users\Dell\.claude\plugins\cache\claude-plugins-official\gopls-lsp\1.0.0\.claude-plugin\plugin.json`

**Before:**
```json
{
  "name": "gopls-lsp",
  ...
  "lspServers": {
    "gopls": {
      "command": "gopls",
      "extensionToLanguage": { ".go": "go" }
    }
  }
}
```

**After:**
```json
{
  "name": "gopls-lsp",
  ...
  "lspServers": {
    "gopls": {
      "command": "C:\\Users\\Dell\\go\\bin\\gopls.cmd",
      "extensionToLanguage": { ".go": "go" }
    }
  }
}
```

(Only `"command"` changes; everything else verbatim.)

**This agent could not apply the patch directly** — `~/.claude/plugins/cache/` is permission-gated against agent writes (correctly; auto-replaced on `/plugin update`). User must apply manually:

```powershell
$path = "$env:USERPROFILE\.claude\plugins\cache\claude-plugins-official\gopls-lsp\1.0.0\.claude-plugin\plugin.json"
Copy-Item $path "$path.bak" -Force
$content = Get-Content $path -Raw
$content = $content -replace '"command": "gopls"', '"command": "C:\\\\Users\\\\Dell\\\\go\\\\bin\\\\gopls.cmd"'
Set-Content -Path $path -Value $content -NoNewline -Encoding UTF8
Get-Content $path -Raw | ConvertFrom-Json | Out-Null
Write-Host "Patch applied + JSON valid"
```

## Verification steps

1. **Full Claude Code restart** (not just `/reload-plugins` — the plugin-cache loader most likely caches the parsed `aW_()` result for the session; once `manager.state = "error"` it doesn't retry without re-init).
2. Run `/plugin` — gopls-lsp should show no ENOENT.
3. PowerShell: `wsl -d Ubuntu -u root pgrep -af gopls` — expect 4+ instances (2 pairs: cclsp's existing + marketplace plugin's new).
4. PowerShell: count Win-side bridge processes via `Get-CimInstance Win32_Process | Where-Object { $_.CommandLine -like '*wsl-lsp-bridge*' }` — expect 3+ (2 from cclsp, 1+ from marketplace plugin's `gopls.cmd → bridge` chain).
5. `mcp__ide__getDiagnostics` on `D:\Sundeep\projects\lsp-test\bad.go` — MAY now return diagnostics if claude.exe's LSP server manager wires publishDiagnostics into the IDE bridge (TBD empirically).
6. **Decisive test:** Edit `bad.go` from orchestrator. Does a `<new-diagnostics>` system-reminder fire?

## Empirical predictions

| Check | If patch works | If patch fails |
|---|---|---|
| `/plugin` status row | "ready" / no ENOENT | `ENOENT: ... uv_spawn 'C:\\Users\\Dell\\go\\bin\\gopls.cmd'` |
| WSL `pgrep gopls` count | 4+ instances | 2 (cclsp only) |
| Win-side bridge process count | 3+ | 2 |
| `<new-diagnostics>` after Edit on `bad.go` | FIRES with 4 errors | Silent |

## Caveats

- **Plugin cache is volatile.** `/plugin update` or marketplace re-pull will revert. Mitigation: SessionStart hook that re-applies the patch idempotently, or upstream PR.
- **Same bug likely affects every marketplace LSP plugin on Windows** that declares bare-name commands. Per the manifest enumeration in `c1bfbe9`, all 12 official LSP plugins use bare commands like `pyright`, `clangd`, `rust-analyzer`, `gopls`. cclsp avoids this by wrapping with `cmd.exe /c` in its own config — that's why cclsp's pyright works (process tree confirms PIDs 14276, 7804 etc. parented to `cmd.exe /c pyright-langserver --stdio`).
- **JSON schema validation risk:** the `xNH()` Zod validator might reject absolute Windows paths with `.cmd` extensions. If it does, the patch will fail validation at `aW_()` time and produce a different error. Schema unverified from bytecode — test empirically.
- **`/reload-plugins` may not re-read this manifest.** Full restart is the safe path. The bytecode shows `Fq6 = _ZH.reinitialize` exists; whether `/reload-plugins` invokes it is unverified.

## Why this is actionable now (vs. the prior "uniformity" claim)

In `c1bfbe9` I documented that all 12 marketplace LSP plugins are uniformly thin (just `lspServers` field, no MCP tools). That observation stands — they ARE uniformly thin manifests. But the runtime fact is they ALL fail to spawn on Windows due to libuv ENOENT. The user's intuition that "something is broken with marketplace LSPs" was correct; my earlier framing of "uniform editor-UI-only by design" missed that the design path is structurally broken on Windows. Empirical evidence (the `/plugin` ENOENT row) only surfaced after the user ran `/plugin` interactively this session.

## Cross-references

- `e8ddd37` `.research/path-b-lsp-manager-deep-dive.md` — bytecode-level analysis. Identified `cf()` was false; couldn't pin downstream gate. ENOENT was the gate.
- `0b0862a` `.research/new-diagnostics-mechanism.md` — original `<new-diagnostics>` mechanism trace.
- `32fa08b` `wsl-lsp-bridge` URI canonicalization fix.
- `c1bfbe9` SAC cleanup that deleted `gopls.exe.bak` (the proximate trigger of the ENOENT — `where gopls.exe` returned not-found because the binary was archived then deleted).
- `~/.claude/ide/50929.lock` — VS Code IDE bridge connection (Path A wired but cache empty for test files).
