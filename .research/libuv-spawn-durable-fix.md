# libuv `uv_spawn` ENOENT — durable-fix scoping (2026-04-26)

User asked for a durable fix to the libuv ENOENT bug that's blocking marketplace `gopls-lsp` plugin spawn (root cause documented in `gopls-marketplace-manifest-patch.md`). Manifest patch is fragile (volatile plugin cache); user wants something that survives plugin updates.

## Bottom-line ranking

| # | Candidate | Cost | Durability | Actionable today? |
|---|---|---|---|---|
| **1** | **Subscribe to upstream fix (issue #46702)** + use cclsp + bridge in the meantime | $0, ~0 LOC | High once landed; in our control = subscribe | YES (subscribe + already have cclsp working) |
| 2 | Build Windows-side native `gopls.exe` shim that re-execs to WSL2 gopls | ~30 LOC Go, ~1 hr | Low–medium (SAC trips on unsigned PE; same problem as before) | Conditional |
| 3 | Submit upstream PR to `anthropics/claude-code` adding `shell: process.platform === "win32"` to LSP spawn | ~5 LOC, 1-3 weeks roundtrip | Highest if merged | No (out of our control) |
| 4 | Submit upstream PR to `anthropics/claude-plugins-official` for platform-conditional `command` | ~10 LOC, 1-3 weeks roundtrip | Medium (only fixes one plugin at a time) | No |
| 5 | Bun-level env override forcing shell mode | None exist | n/a | No |
| 6 | Windows App Paths registry alias | ~10 LOC reg edit | n/a — libuv doesn't honor it | No |
| 7 | Manifest patch (the original fragile fix) | 1 LOC | Low (volatile cache) | YES but explicitly the fragile path |

**Best durable option (rank 1):** subscribe to upstream issue #46702 and continue using cclsp + wsl-lsp-bridge for orchestrator-callable code intelligence (already verified working in `c1bfbe9`). Marketplace `gopls-lsp` provides editor-UI features which the user gets via VS Code's own Go extension, not via this plugin's spawn path. Once Anthropic ships the `shell: true` fix in a Claude Code release, the marketplace plugin will spawn correctly without any patch on our side.

**Direct answer to "should we install something on WSL?":** No. WSL-side install can't help — libuv runs Windows-side; the spawn syscall happens before any WSL involvement. The libuv ENOENT fires in the Windows process before `gopls.cmd` would invoke `wsl.exe`.

## Detailed candidate analysis

### Candidate 1 — Subscribe + use cclsp (RECOMMENDED)

**Status:** Anthropic has already partially fixed this bug via issue #27061 (closed 2026-03-31). The fix added `shell: process.platform === "win32"` to LSP server spawn for npm-installed binaries. But issue **#46702 (OPEN, last updated 2026-04-24)** reports the bug still affects pyright-lsp on Windows, indicating the previous fix was incomplete or there's a regression.

The user's Claude Code is version 2.1.119 (build 2026-04-23). #46702 was filed Apr 11 and updated Apr 24 — so the bug is being actively triaged at Anthropic AT this moment, against this very build.

**Cost:** ~5 minutes to subscribe to issue #46702 (`gh issue subscribe 46702 -R anthropics/claude-code`).

**Durability:** Once Anthropic ships the universal `shell: true` fix, ALL marketplace LSP plugins (gopls-lsp, pyright-lsp, typescript-lsp, php-lsp, etc.) start spawning correctly. No client-side patches needed.

**In the meantime:** keep using cclsp (which spawns LSP servers via its own `cmd.exe /c <name>` wrapper that bypasses libuv's PATHEXT-blindness). cclsp's process tree confirms this works: PIDs 14276, 7804 et al. parented to `cmd.exe /c pyright-langserver --stdio` — the `cmd.exe /c` IS the shell-mode invocation that libuv won't do natively.

### Candidate 2 — Native gopls.exe shim binary (HAS SAC PROBLEM)

A ~30-LOC Go program at `C:\Users\Dell\go\bin\gopls.exe` that re-execs to WSL2 gopls:

```go
package main

import (
  "os"
  "os/exec"
)

func main() {
  cmd := exec.Command("wsl.exe", append(
    []string{"-d", "Ubuntu", "-u", "root", "--",
      "env", "PATH=/usr/local/go/bin:/root/go/bin:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
      "/root/go/bin/gopls"},
    os.Args[1:]...)...)
  cmd.Stdin = os.Stdin
  cmd.Stdout = os.Stdout
  cmd.Stderr = os.Stderr
  os.Exit(runOrFail(cmd))
}

func runOrFail(c *exec.Cmd) int {
  if err := c.Run(); err != nil {
    if ee, ok := err.(*exec.ExitError); ok { return ee.ExitCode() }
    return 1
  }
  return 0
}
```

Compile with `go build -trimpath -ldflags="-buildid="` for deterministic hash, place at `C:\Users\Dell\go\bin\gopls.exe`. libuv finds it, spawns it, it transparently re-invokes the WSL2 gopls.

**The SAC problem:** as documented exhaustively in this session's `c1bfbe9` and prior, **a self-signed PE binary on this user's Windows 11 with Smart App Control evaluation mode hits the unsigned-binary block 30-50% of the time** depending on ISG cloud reputation flux. The earlier setup attempted exactly this (the now-deleted `gopls.exe.bak` was structurally similar) and the SAC blocks led to the entire WSL2 + bridge path being invented as a workaround.

**What's changed since:**
- The `gopls.exe.bak` was a `go install`-built **gopls itself**, ~40 MB. The proposed shim is ~5 MB, content-stable across rebuilds, hashes consistently. ISG might whitelist its hash faster than gopls' fluid hash (each `go install` produced a new hash).
- Microsoft Trusted Signing remains India-blocked + paid per `ms-trusted-signing-setup.md` Appendix C. Certum OS Code Signing remains €104 yr1 / €29/yr but requires DHL + smartcard; same finding as `c1bfbe9`.
- VSCode extension's bundled gopls — not relevant, it's spawned inside VSCode's sandbox, not on PATH.

**Net:** the shim is technically possible but inherits the same SAC reliability problem as gopls.exe.bak. **NOT durable** unless paired with a Trusted Signing or Certum cert, which the user already declined.

**Variant:** ship the shim **unsigned** but wrap it in `scripts/go-test-sac.cmd`-style ISG-cooldown logic. Fragile but might work if user accepts 30-50% retry rate. Less work than candidate 1 + 3 + 4.

### Candidate 3 — Upstream PR to claude-code adding shell: true (BEST IF MERGED)

**The fix from #27061 (already submitted, now closed):**
```javascript
spawn(command, args, {
  stdio: ["pipe", "pipe", "pipe"],
  shell: process.platform === "win32",  // ADD
  env: ...,
  cwd: ...,
  windowsHide: true
})
```

5-LOC change. Issue #46702's continued OPEN status suggests Anthropic might be reluctant to enable `shell: true` universally (security implications: shell injection if any LSP server name contains shell metacharacters). They may want a more targeted fix.

**Cost:** Outside our control — Anthropic must accept and ship.

**Variant — submit a NEW PR with our own targeted fix:** instead of `shell: true` everywhere, detect if `command` ends with `.cmd` / `.bat` and substitute `cmd.exe /c <command>`. Bypasses shell injection concern. Could be submitted by us. ~10 LOC. Roundtrip 1-3 weeks if accepted. Not actionable in same session.

### Candidate 4 — Upstream PR to claude-plugins-official

Per the marketplace plugin schema in `c1bfbe9`'s field-frequency table, no platform-conditional `command` field exists today. We'd be the first to add it. Alternative: ship a `gopls.cmd` shim INSIDE the plugin, manifest references that.

**Cost:** PR to `anthropics/claude-plugins-official`. Plugin schema may need extension to accept platform-keyed `command` objects. 1-3 weeks roundtrip.

**Durability:** Only fixes the plugins we PR. Each plugin would need a separate fix (or schema extension via a single PR). Better than candidate 7 (manifest patch) but slower than candidate 1 (subscribe + wait).

### Candidate 5 — Bun env-var override

Searched Bun docs for env var that toggles spawn shell mode. **None exists.** Bun's `BaseOptions` has explicit `shell: boolean` field but that's a SpawnOptions parameter, not an env override. Claude Code's bytecode at offset 131017899 shows `Y.start(q.command, q.args || [], { env, cwd })` — no `shell` field. **Out.**

### Candidate 6 — Windows App Paths registry alias

App Paths is documented as honored by `ShellExecute`/`ShellExecuteEx` only. **CreateProcess (which libuv `uv_spawn` uses) explicitly does NOT honor App Paths** — Microsoft's own docs: "Applications that use CreateProcess() to start apps would need to look in 'App Paths' manually if they want to utilize this functionality." libuv does no such manual lookup. **Out.**

### Candidate 7 — Manifest patch (the fragile path)

Already documented in `gopls-marketplace-manifest-patch.md` (this session). 1-LOC change to `~/.claude/plugins/cache/.../plugin.json`. Volatile (auto-replaced on `/plugin update`). Mitigation: SessionStart hook re-applying the patch.

**Better than nothing**, but rank 7 because the hook adds complexity for a fix that should live upstream.

## Decision matrix

| Goal | Recommended path |
|---|---|
| Get gopls working in cclsp/agent route TODAY | **Already done** (cclsp + bridge, verified in `c1bfbe9`) |
| Get gopls working in marketplace plugin TODAY | Candidate 7 (fragile manifest patch) — coordinator already started |
| Get gopls working durably with no upstream wait | Candidate 7 + SessionStart hook re-applier |
| Get gopls working durably across all users | Candidate 3 (upstream PR) — out of our hands |
| Get every marketplace LSP plugin working durably | Subscribe to #46702 + wait for Anthropic |

## Direct answers

**1. Best durable option (rank 1):** Subscribe to issue #46702 + use cclsp/bridge for orchestrator workflows. Marketplace `gopls-lsp` will resolve when Anthropic ships the universal `shell: true` fix; meanwhile cclsp covers the agent-callable surface and VS Code's Go extension covers the editor-UI surface.

**2. Actionable today?** YES for the subscribe-and-wait path (cclsp already works). The manifest patch (candidate 7) is also actionable today as a stopgap, with the volatility caveat documented.

**3. Fallback if best option is time-blocked:** the shim binary (candidate 2) is fully under our control but inherits the SAC reliability problem. Cost: ~30 LOC + ~1 hr. Reliability: 50-70% per session due to SAC's ISG-dependence. Acceptable if the user accepts the flake; not durable in the strict sense.

**4. WSL install help?** **NO.** libuv's spawn syscall fires Windows-side; nothing installed in WSL is reachable until after `wsl.exe` is invoked, which is after the Windows-side spawn-resolution that's failing.

## Sources

- [libuv process documentation — explicit "PATHEXT not used; only .com and .exe tried"](https://docs.libuv.org/en/v1.x/process.html)
- [How App Paths works — honored by ShellExecute, NOT CreateProcess](https://blog.codeinside.eu/2024/01/17/windows-path-and-app-paths/)
- [Bun.spawn API reference — `shell: boolean` is a parameter, no env override](https://bun.com/reference/bun/spawn)
- [anthropics/claude-code issue #27061 — original Windows LSP spawn ENOENT bug, CLOSED 2026-03-31](https://github.com/anthropics/claude-code/issues/27061)
- [anthropics/claude-code issue #46702 — pyright-lsp ENOENT, OPEN, last updated 2026-04-24](https://github.com/anthropics/claude-code/issues/46702)
- [anthropics/claude-code issue #32264 — TS LSP ENOENT, CLOSED 2026-03-18](https://github.com/anthropics/claude-code/issues/32264)
- [anthropics/claude-code issue #33955 — TS LSP MSYS2/Git Bash ENOENT, CLOSED 2026-03-21](https://github.com/anthropics/claude-code/issues/33955)
- This session's prior work: `c1bfbe9` (SAC cleanup), `e8ddd37` (Path B deep-dive), `gopls-marketplace-manifest-patch.md` (the fragile fix)
