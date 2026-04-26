# cclsp vs Claude Code marketplace LSP plugins — divergence analysis

**Verdict in one line:** cclsp is the agent-tool surface (`mcp__cclsp__find_definition` / `_references` / `_hover` / `rename_symbol` etc.); marketplace plugins are the editor-surface (`mcp__ide__getDiagnostics` and editor hover). Both are needed today and now coexist on this user's box; the right framing is **"keep cclsp until the marketplace plugin's MCP-tool surface reaches parity, then migrate"** — NOT "drop cclsp now". The maintainer's discontinuation announcement (Issue #40) is a real risk to factor in but doesn't force an immediate migration when no equivalent agent-callable tools exist for `find_definition`, `find_references`, `find_implementation`, `rename_symbol`, `find_workspace_symbols`, call-hierarchy, etc.

## TL;DR

- **Both routes work AS OF 2026-04-26 on this user's box.** cclsp re-enabled, hover + diagnostics confirmed via `mcp__cclsp__*` tools through `wsl-lsp-bridge` → WSL2 gopls. Marketplace gopls-lsp plugin via `gopls.cmd` shim → same bridge → same gopls. Both feed identical backing LSP.
- **They serve different surfaces.** cclsp = agent-callable MCP tools (~10 distinct LSP operations exposed to Claude). Marketplace plugin = editor-surface diagnostics + hover (`mcp__ide__getDiagnostics`). Not interchangeable — they overlap on hover/diagnostics but the agent-tool surface is cclsp-only today.
- **cclsp issue #40** (2026-02-14, [link](https://github.com/ktnyt/cclsp/issues/40)): maintainer ktnyt explicitly states "this whole thing has been vibe coded ... claude code's official plugin marketplace supports many languages and I'm assuming they are much more robust than this bodged up project ... due to shifts in my life it is becoming harder to maintain the project on a regular basis."
- **cclsp issue #43** (2026-02-21, OPEN): `find_workspace_symbols` returns "No Project" — same root-cause family as the bug user hit (workspaceSymbol routes to wrong server AND skips ensureFileOpen). Already 2+ months open, no fix landed.
- **Marketplace plugin org `claude-contrib/claude-languages`** (created 2026-03-05, last push 2026-04-23, [link](https://github.com/claude-contrib/claude-languages)): Anthropic-adjacent active. Currently ships `golang`, `rust`, `terraform` plugins. Go IS covered for editor-surface; **agent-tool surface coverage is incomplete** — that's why cclsp can't be retired yet.

## Architecture comparison

| Dimension | cclsp 0.7.0 | claude-contrib/claude-languages plugin |
|---|---|---|
| Source | [ktnyt/cclsp](https://github.com/ktnyt/cclsp), MIT, 620⭐, TypeScript | [claude-contrib/claude-languages](https://github.com/claude-contrib/claude-languages), MIT, 0⭐ (new), Nix flakes + plugin manifests |
| Author count / contributions | 8 contributors, top-heavy (ktnyt 110, secondcircle 22, others ≤2 commits) | community + Anthropic-adjacent; growing |
| Status | **"Discontinuation of active development"** (issue #40, Feb 2026) | **Active**, Apr 2026 commits |
| Total commits | 139 (lifetime) | growing fast (created Mar 2026) |
| Test coverage (LOC) | substantial — `lsp-client.test.ts` 51 KB, file-editor/scanner/get-diagnostics/multi-position/server-selection/setup all have test files | per-plugin; relies on language-server's own conformance |
| LSP harness | hand-rolled in `dist/index.js` (31 KB minified, ~30k+ lines) | Claude Code's first-party LSP client (closed source, but battle-tested by editor surface) |
| Surface to user | MCP server registered in Claude Code (`mcp__cclsp__*` tools) | Plugin auto-wires into Claude Code's editor LSP; LSP features surface natively |
| Config | manual `cclsp.json` per-extension command arrays | Claude Code plugin manifest |
| Server-per-file model | `getServer(filePath)` matches by extension; one server per ext | One plugin per language, lifecycle-managed by Claude Code |

## Why cclsp had MORE problems than the marketplace plugin

Three structural deficits, ranked by severity:

### 1. workspace_symbol routing is hard-coded to "first server" (BUG)

`dist/index.js:30242-30248` literally does:

```js
const servers = Array.from(this.servers.values());
if (servers.length === 0) return [];
const serverState = servers[0];          // <-- always first
```

Any `find_workspace_symbols` call routes to whichever LSP cclsp started first — which on this user's box is TypeScript (extension `.ts`/`.tsx` registered before `.go`). Even with the file path being a `.go` file passed in some other tools, `workspaceSymbol(query)` doesn't take a file argument, so cclsp can't match on extension. The correct fix would either:
(a) accept a `language` or `filePath` hint argument (would require MCP tool schema change), or
(b) fan out to ALL servers and merge results.

cclsp does neither. Marketplace plugins side-step this entirely because they're per-language single-server processes.

### 2. workspace_symbol skips `ensureFileOpen` (CONFIRMED BUG #43)

cclsp issue #43 (open since 2026-02-21) documents that `workspaceSymbol()` doesn't call `ensureFileOpen`, so TypeScript LSP returns "No Project" until a file-based call (hover/definition) primes the project. The author of #43 supplies the exact one-line patch and links to PR #30 which fixed the same omission for `find_references`. **2 months later, no PR has landed.** This is consistent with the maintenance status announced in #40.

Marketplace plugins inherit Claude Code's editor LSP client which always opens the file before requesting symbols (LSP spec compliance is more uniform there).

### 3. Silent error swallowing in `getDiagnostics` masks gopls errors (DESIGN BUG)

Lines 30141-30220 of `dist/index.js`: when `textDocument/diagnostic` fails (gopls returned `"no views"` because PATH was wrong before the bridge fix), cclsp catches the error at L30162 and falls back to `waitForDiagnosticsIdle` → eventually returns `[]`. The user sees "no diagnostics" — looks like success, actually masks a gopls workspace-load failure.

`hover` (L30222-30238) propagates errors raw — no try/catch — so the same gopls failure surfaces as `"no views"`. Inconsistent error handling between methods of the same class. **Marketplace plugins surface LSP errors uniformly via the editor's diagnostic channel** — the user would have seen the "Loading packages: go command required, not found" warning immediately in the IDE.

### 4. Workspace root resolution depends on cclsp's CWD

`pathToUri(serverConfig.rootDir || process.cwd())` (L29280) — when `rootDir: "."` and cclsp's CWD is whatever directory Claude Code spawned it in, the root may not contain `go.mod`. gopls searches up from there, so it usually works, but can quietly miss the right module if the directory tree is unusual.

Marketplace plugins receive workspace folders from Claude Code's editor model, which knows the active project root.

## Specific bugs the user hit, root-caused

| Symptom | Root cause | cclsp's role | Marketplace plugin's behavior |
|---|---|---|---|
| `get_hover` "no views" | `wsl.exe -- gopls` doesn't source `~/.bashrc`; PATH lacks `/usr/local/go/bin`; gopls fails to load workspace | Surfaced the error raw (good, but fix was in our bridge) | Would have hit the same env-PATH issue if it spawned gopls the same way; but Claude Code's plugin spawn typically respects user shell init better. Untested on this box. |
| `get_diagnostics` returned `[]` despite gopls "no views" error | Silent error swallow at L30162 | **Hid the bug for hours** | Editor diagnostic channel would have shown the "Loading packages" warning toast |
| `find_workspace_symbols` routed to TypeScript on a Go file | Hard-coded "first server" routing (L30248) — one of the three structural deficits above | **Confirmed bug #43, design limitation** | Per-language plugins; routing not possible to mis-route |

## Can cclsp be brought to parity? (upstream-PRable vs structural)

| Bug | Upstream-PRable? | LOC estimate | Status |
|---|---|---|---|
| #43: workspaceSymbol missing ensureFileOpen | Yes | ~3 LOC | Patch provided in issue, no upstream merge in 2+ months |
| Silent error swallow in getDiagnostics | Yes (controversial — some users WANT empty fallback) | ~10 LOC + flag | Not filed |
| Workspace_symbol "first server" routing | Partially — fan-out + merge is doable; per-file routing needs MCP schema change | ~30-50 LOC | Not filed |
| Workspace root resolution from CWD | Partially — could read closest `go.mod`/`tsconfig.json`/etc. | ~50 LOC | Not filed |
| Per-language adapter coverage (#18 Vue timeout, #20 TS diagnostics broken) | Yes case-by-case | varies | Backlog |

Even if all upstream PRs landed, **cclsp's hand-rolled LSP client carries inherent risk** vs the editor's first-party LSP client. The maintainer himself describes it as "vibe coded ... bodged up." The reasonable path forward is fork-and-maintain (high cost) or migrate (low cost).

## Honest verdict

**Keep cclsp running alongside the marketplace plugin** — that's what the user's setup now is, verified 2026-04-26. The two surfaces are complementary, not redundant:

| Surface | cclsp | Marketplace `golang` plugin |
|---|---|---|
| `mcp__ide__getDiagnostics` (editor-surface diagnostics) | duplicate (returns same data) | **primary** — first-party LSP harness, uniform error display |
| Editor hover in the IDE | n/a | **primary** |
| `mcp__cclsp__get_hover` (agent-callable hover) | **primary** | not exposed |
| `mcp__cclsp__find_definition` / `_references` / `_implementation` | **primary** | not exposed |
| `mcp__cclsp__rename_symbol` / `_strict` | **primary** | not exposed |
| `mcp__cclsp__find_workspace_symbols` | **primary, but BUGGY** (#43 open, routing to first server) | not exposed |
| `mcp__cclsp__prepare_call_hierarchy` / get_incoming_calls / get_outgoing_calls | **primary** | not exposed |

The MCP-tool surface for agent-driven LSP queries is **cclsp-only** today. Until the marketplace plugin (or another tool) exposes agent-callable equivalents for definition/references/rename/call-hierarchy, dropping cclsp loses agent capability that no replacement currently provides.

**The wsl-lsp-bridge investment is NOT lost regardless** — the bridge wraps any stdio LSP server and translates URIs. Both cclsp AND the marketplace plugin go through the same bridge to the same gopls. The path-translation layer is the durable asset; both clients ride on top.

## Recommendation

1. **Keep both routes active** (status quo as of 2026-04-26):
   - **Marketplace `golang` plugin** → bridge → WSL2 gopls — for `mcp__ide__getDiagnostics` + editor-surface hover.
   - **cclsp** → bridge → WSL2 gopls — for the 10+ agent-callable MCP tools.
   - Same gopls backend for both; consistency guaranteed.
2. **Avoid `mcp__cclsp__find_workspace_symbols`** until issue #43 lands or you fork — it routes to whichever LSP cclsp started first (often TypeScript). Use `mcp__cclsp__find_definition` with `symbol_name` instead, or fall back to `Grep` for now.
3. **File issue #43's PR upstream** (3 LOC) — quick-win, but don't block on the merge. Apply locally if needed.
4. **Watch for marketplace plugins to expose the missing agent-callable surface.** When `find_definition` / `rename_symbol` etc. show up as `mcp__*` tools from a plugin source, re-evaluate cclsp.
5. **Set a tripwire on cclsp's repo activity.** Maintainer's #40 is a slow-burn risk. If cclsp doesn't ship any commits in 6 months from Apr 2026, consider forking under your own user (rebase issue #43's patch + any other 3-LOC fixes that accumulate). The fork is cheap (it's published TypeScript; no native deps).

## Sources

- [cclsp issue #40 — Discontinuation announcement](https://github.com/ktnyt/cclsp/issues/40)
- [cclsp issue #43 — find_workspace_symbols missing ensureFileOpen](https://github.com/ktnyt/cclsp/issues/43)
- [cclsp source (dist/index.js)](https://github.com/ktnyt/cclsp/blob/main/dist/index.js) — workspaceSymbol L30239-30258, getDiagnostics L30125-30221, hover L30222-30238, ensureFileOpen L29539-29572, pathToUri L28789
- [claude-contrib/claude-languages](https://github.com/claude-contrib/claude-languages) — marketplace LSP plugin org, MIT, golang/rust/terraform plugins, last push 2026-04-23
- LSP 3.17 spec: [textDocument/didOpen](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_didOpen), [workspace/symbol](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#workspace_symbol)
- Empirical evidence from this session: bridge wire-log captured at `C:/Users/Dell/AppData/Local/Temp/wsl-lsp-bridge.log` showing gopls "Error loading workspace folders" + cclsp's silent fallback to `[]` for diagnostics
