# WSL-LSP path-translation bridge survey (Apr 26, 2026)

**Verdict: FOUND-BUT-UNFIT-AS-IS, but a near-direct fork target exists.**
The translation core is ~50 LOC of generic JSON-walker + URI rewriter,
already written and MIT-licensed at `lucasecdb/godot-wsl-lsp`. The only
work required is swapping its TCP-socket transport for stdio-spawn of
`wsl.exe gopls`. **Realistic effort: ~150 LOC TypeScript, half-day.**

## Current setup recap

cclsp on Windows spawns gopls via `wsl.exe -d Ubuntu -u root /root/go/bin/gopls`.
Today (post-`6153af0`) it works because:
- gopls inside WSL2 happens to handle cross-FS reads of `/mnt/d/Sundeep/...` via the
  9P bridge.
- cclsp's `rootDir: "."` resolves at spawn time relative to the working directory the
  MCP harness chose, not via URI.

But ANY LSP path payload (`textDocument.uri`, `workspaceFolders[].uri`,
`location.uri`, etc.) sent by cclsp will be Windows-flavoured
(`file:///D:/Sundeep/projects/kite-mcp-server/foo.go`). gopls inside WSL2 will
`fmt.Errorf("file URI does not refer to a path")` or silently drop the request
on Linux paths because the URI's `D:/` drive doesn't exist in WSL. **Some calls
work today only because cclsp may be passing relative paths or because gopls is
tolerant for hover/definition queries on already-loaded files**, not URI translation.

A WSL-LSP path bridge would deterministically fix this.

## Candidates surveyed

### 1. `lucasecdb/godot-wsl-lsp` — best fit for fork

| Field | Value |
|---|---|
| URL | https://github.com/lucasecdb/godot-wsl-lsp |
| License | MIT (set in `package.json`; LICENSE file missing in repo, but package field is authoritative) |
| Stars | 16 |
| Last push | **2026-02-05** — actively maintained |
| Language | TypeScript, Node ≥20 |
| Code size | 11 source files in `src/`, ~13 KB total |
| LSP framing | Yes — uses `ts-lsp-client`'s `JSONRPCTransform` (Content-Length headers) |
| Bidirectional URI rewrite | **Yes** — `transformRpcForWindows` + `transformRpcForLinux` walk every JSON object |
| Path conversion | Calls native `wslpath` binary (or `--experimentalFastPathConversion` regex shortcut) |
| Coverage | Walks ALL keys+values recursively in `traverse-json.ts`. Catches every URI field automatically without an allow-list — better than naive `textDocument.uri`-only rewriters |

**The translation core (`rpc-message-transformer.ts`, `wsl-path.ts`,
`traverse-json.ts`) is generic and reusable verbatim.** Godot-specific code is
isolated to `lsp-socket.ts` (TCP client to a Godot listener) and `main.ts` (CLI
flag wiring). Replacing those with a stdio-spawn of `wsl.exe gopls` is the
entire fork delta.

### 2. `venomlab/godot-wsl-proxy` — Python sibling

| Field | Value |
|---|---|
| URL | https://github.com/venomlab/godot-wsl-proxy |
| License | MIT (LICENSE file present) |
| Stars | 3 |
| Last push | 2025-01-10 |
| Language | Python (poetry, pip-installable) |
| Approach | Lower-level — no full LSP framing parser; regex-replaces paths in raw bytes |
| Note | Author cites `lucasecdb/godot-wsl-lsp` as inspiration, claims "faster" via byte-level work |

Less robust than the TS version (skips JSON-RPC framing, brittle on edge cases
in escaped JSON strings or split TCP packets). **Skip.**

### 3. `irth/wsl-lsp-proxy` — abandoned

| Field | Value |
|---|---|
| URL | https://github.com/irth/wsl-lsp-proxy |
| Stars | 0 |
| Last push | **2019** |
| State | Empty README, no description |

**Skip.**

### 4. cclsp itself — no native WSL mode

Reviewed `ktnyt/cclsp` README + DeepWiki. **No `transport: "wsl"` mode**, no
URI-rewriting middleware, no env var to toggle path translation. cclsp's only
WSL guidance is "use `cmd.exe /c` wrapper on Windows" (which we already do for
all other LSPs). The `command` array is a raw spawn — whatever paths the LSP
receives are whatever cclsp's MCP layer sends, untouched.

**No upstream fix path.** Filing a feature request is plausible but slow; not a
2026 dependency.

### 5. VS Code Remote-WSL — not extractable

The Remote-WSL extension solves the same problem differently: it runs the
**entire VS Code server** inside WSL, so the LSP and the editor share the Linux
filesystem view — no translation needed. The path-translation logic for the
edge cases (host-side terminals, port-forwarded URLs) lives deep inside
proprietary `vscode-server` binaries that are not OSS. **Not extractable as a
standalone library.**

### 6. JetBrains Gateway WSL — same answer

Architecturally identical to Remote-WSL: full IDE backend lives in WSL.
No path-translation library to lift.

### 7. Generic LSP proxies surveyed

| Repo | Path translation? | Notes |
|---|---|---|
| `qualified/lsp-ws-proxy` | No | WebSocket transport adapter only |
| `messense/multi-lsp-proxy` | No | Multiplexes across servers, no URI rewrite |
| `sourcegraph/lsp-adapter` | Partial | Adapts Sourcegraph LSP extensions to vanilla LSP — not WSL-relevant |
| `manateelazycat/lsp-bridge` | No | Emacs LSP client, not a proxy |
| `walcht/LSP-TCP-socket-adapter` | No | TCP↔stdio bridge only |

None are usable as-is for the cclsp+gopls+WSL2 case.

### 8. `wslu` / `wsl-utilities` Linux package — not LSP-relevant

`wslu` provides `wslpath`, `wslview`, etc. — useful primitives that
`godot-wsl-lsp` already calls into. No LSP-aware tooling.

## Path-translation requirements (LSP 3.17 reality check)

A correct WSL-LSP bridge must rewrite URIs in ALL of these locations (this is
why the recursive JSON walker in `traverse-json.ts` is the right approach,
versus a hand-coded allow-list):

- Requests: `textDocument.uri`, `params.textDocument.uri`,
  `params.documentChanges[].textDocument.uri`, `params.changes[].uri`,
  `params.workspaceFolders[].uri`, `params.rootUri`, `params.uri`,
  `arguments[].fsPath`.
- Responses: `result.uri`, `result.location.uri`, `result.targetUri`,
  `result.changes` (object keys are URIs!), `result.documentChanges[].textDocument.uri`,
  completion item `additionalTextEdits[].uri`, hover doc-link URIs.
- Notifications: `params.textDocument.uri` (didOpen/didChange/didSave/didClose),
  `params.uri` (publishDiagnostics), `params.changes[].uri`
  (workspace/didChangeWatchedFiles).
- Edge: `result.changes` in `WorkspaceEdit` uses URIs as **object keys** —
  the walker must rewrite keys too. `godot-wsl-lsp`'s `traverse-json.ts`
  handles this (line 23 `const newKey = await transformKey(key)`).

The `godot-wsl-lsp` recursive transform handles all of these by rewriting
every string-typed value that parses as a `file://` URI. **No allow-list to
maintain.** This is the right design.

## Realistic LOC estimate to fork for cclsp+gopls

Fork `lucasecdb/godot-wsl-lsp`. Delete `lsp-socket.ts` (1.7 KB, Godot
TCP-connect code). Replace `main.ts` (891 B) with a small stdio-spawn that
launches `wsl.exe -d Ubuntu -u root /root/go/bin/gopls` and pipes
stdin/stdout. Drop yargs CLI flags (--host, --useMirroredNetworking) — not
needed for stdio. Adjust `progress-reporter.ts` (3.9 KB) since there's no
"connecting to Godot" handshake — stdio is instant.

Keep verbatim: `rpc-message-transformer.ts` (1.7 KB), `wsl-path.ts` (1.2 KB),
`traverse-json.ts` (1.1 KB), `queue.ts` (927 B), `rpc.ts` (205 B),
`logger.ts` (1.3 KB), `cli-flags.ts` (916 B, simplified).

**Net delta: ~150 LOC TypeScript, half-day work.** Then in `~/.claude/cclsp.json`:

```json
{
  "extensions": ["go"],
  "command": ["node", "C:\\Users\\Dell\\.claude\\wsl-lsp-bridge\\dist\\main.js"],
  "rootDir": ".",
  "restartInterval": 60
}
```

The bridge runs as a stdio LSP server on the Windows side, spawning gopls in
WSL2 via wsl.exe, and rewriting URIs in both directions on every JSON-RPC
frame. SAC sees only `node.exe` (Microsoft-trusted, runs unsigned) and
`wsl.exe` (Microsoft-trusted) — no SAC blocks.

## Reference impl to fork: `lucasecdb/godot-wsl-lsp`

- Clone: `git clone https://github.com/lucasecdb/godot-wsl-lsp wsl-lsp-bridge`
- Strip Godot/TCP code (keep `rpc-message-transformer`, `wsl-path`,
  `traverse-json`, `queue`, `rpc`, `logger`).
- Replace `lsp-socket.ts` + `main.ts` with a `child_process.spawn('wsl.exe', ['-d', 'Ubuntu', '-u', 'root', '/root/go/bin/gopls'])` and pipe-through-`Server`.
- Build: `npm install && npm run build`. Output `dist/main.js` ~30 KB.
- License: MIT — fork-friendly. Attribution in fork README.

## Recommendation

**Do not invest now.** The current Phase 5 setup (cclsp + `wsl.exe ... gopls`,
no bridge) appears to work for hover / definition / completion on routine Go
files. The path-translation gap will surface as silent failures on
`workspace/applyEdit`, `rename`, multi-file refactors, and
`workspace/didChangeWatchedFiles` notifications — but those are infrequent in
LSP-via-MCP tool flows (Claude tends to ask for individual symbols, not bulk
edits via LSP).

**Revisit when:** the user reports gopls returning "file not found" on rename,
or workspace-wide refactors silently no-op. At that point, fork
`lucasecdb/godot-wsl-lsp`, ~150 LOC, half-day. Survey saved as a future entry
point.

## Sources

- [lucasecdb/godot-wsl-lsp](https://github.com/lucasecdb/godot-wsl-lsp)
- [venomlab/godot-wsl-proxy](https://github.com/venomlab/godot-wsl-proxy)
- [Setup gist explaining the path mismatch](https://gist.github.com/lucasecdb/2baf6d328a10d7fea9ec085d868923a0)
- [ktnyt/cclsp](https://github.com/ktnyt/cclsp) (no WSL mode upstream)
- [LSP 3.17 spec — URI fields](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/)
