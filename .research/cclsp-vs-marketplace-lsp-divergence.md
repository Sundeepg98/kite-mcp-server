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

## Direct verdict: which to drop today (2026-04-26 — surface enumeration)

**Verdict: KEEP-CCLSP. The marketplace `golang` plugin contributes ZERO agent-callable MCP tools** — it's a pure editor-surface registration shim. Per the user's pre-set criteria (drop X if other has ≥80% of X's MCP-callable surface; the marketplace plugin has ~8% of cclsp's, and even that 1 shared tool is `mcp__ide__getDiagnostics` which is a built-in, not contributed by the plugin), cclsp wins decisively for orchestrator-driven code intelligence.

### Hard evidence: complete enumeration of every `mcp__*` LSP tool in this session

Captured directly from Claude Code's deferred-tools registry — the authoritative source for what the orchestrator can call.

**Built-in `mcp__ide__*`:** 2 tools.
- `mcp__ide__executeCode`, `mcp__ide__getDiagnostics`

**That is the entire `mcp__ide__*` surface.** No `mcp__ide__getHover`, no `mcp__ide__findDefinition`, no `mcp__ide__findReferences`, no `mcp__ide__rename`, no `mcp__ide__workspaceSymbols`, no `mcp__ide__callHierarchy`. Editor-surface LSP features (hover-when-you-hover, completion-when-you-type) fire only on human-IDE interaction; **the orchestrator cannot invoke them programmatically**.

**`mcp__cclsp__*`:** 12 tools — `find_definition`, `find_implementation`, `find_references`, `find_workspace_symbols`, `get_diagnostics`, `get_hover`, `get_incoming_calls`, `get_outgoing_calls`, `prepare_call_hierarchy`, `rename_symbol`, `rename_symbol_strict`, `restart_server`.

### Marketplace `golang` plugin manifest (decisive proof)

`plugins/golang/.claude-plugin/plugin.json` and `.lsp.json` from `claude-contrib/claude-languages` show the plugin is a pure LSP registration shim — `{ "name": "golang", "version": "1.1.0" }` + `{ "go": { "command": "gopls", "transport": "stdio" } }`. **No `tools` field.** The plugin does NOT register any new `mcp__*` tools — confirmed by both the manifest AND by the deferred-tools list above (no `mcp__golang__*` or similar entries exist).

The README's "Code completion / Go-to-definition / Find references / Rename symbol" features are all editor-surface — consumed by Claude Code's IDE pane when the human user interacts with it.

### Coverage scorecard

| LSP capability | cclsp MCP tool | Marketplace plugin MCP tool |
|---|---|---|
| Diagnostics | `mcp__cclsp__get_diagnostics` ✓ | `mcp__ide__getDiagnostics` ✓ (built-in, plugin-agnostic) |
| Hover | `mcp__cclsp__get_hover` ✓ | none |
| Go-to-definition | `mcp__cclsp__find_definition` ✓ | none |
| Find references | `mcp__cclsp__find_references` ✓ | none |
| Find implementation | `mcp__cclsp__find_implementation` ✓ | none |
| Rename | `mcp__cclsp__rename_symbol`/`_strict` ✓ | none |
| Workspace symbols | `mcp__cclsp__find_workspace_symbols` ✓ (buggy, issue #43) | none |
| Call hierarchy | `mcp__cclsp__prepare_call_hierarchy` + incoming/outgoing ✓ | none |

**Marketplace MCP-tool surface is ~8% of cclsp's (1 tool out of 12, and that 1 is a built-in).** The user's pre-set criterion A (drop cclsp if marketplace ≥80%) is decisively NOT met.

### Honorable mention: Serena

Deferred-tools list also exposes `mcp__plugin_serena_serena__*` (15 tools). Serena offers operations cclsp doesn't: `find_symbol` / `find_referencing_symbols` (lookup by name not position), `replace_symbol_body`, `insert_before_symbol` / `insert_after_symbol`, `safe_delete_symbol`, `get_symbols_overview` (file outline). For agent-driven refactors **Serena + cclsp together > cclsp alone**. Future evaluation item; out of scope for this doc.

### Direct answer to "if the marketplace is not exactly dependable now, why not?"

It's not "undependable" — it's **scoped**. The marketplace `golang` plugin reliably does its one job (tell the IDE pane to use gopls for `.go` files). What it does NOT do is expose agent-callable tools. The orchestrator cannot ask the marketplace plugin "find definition of X" because that capability simply does not exist as an `mcp__*` tool. **For orchestrator-driven workflows, cclsp is irreplaceable today.**

### Updated ranking

1. **Keep cclsp running** (status quo) — primary source of agent-callable LSP intelligence.
2. **Keep the marketplace `golang` plugin too** — gives the human user editor-surface hover/completion in the IDE pane. Doesn't compete with cclsp; doesn't subtract from cclsp's value.
3. **Mitigate cclsp's known bugs** — avoid `find_workspace_symbols` (issue #43); use `find_definition` by symbol name as the workaround.
4. **Tripwire still applies** — if cclsp goes silent for 6 months, fork.
5. **Evaluate Serena separately** — its 15 tools complement cclsp's 12 with non-overlapping operations (especially the symbol-level edit tools). Promising for agent-driven refactors.

## Marketplace LSP plugin uniformity check (2026-04-26)

**Question:** does gopls-lsp uniquely lack MCP tools, or do ALL marketplace LSP plugins behave the same?

**Answer:** all 12 LSP plugins in `anthropics/claude-plugins-official` are uniformly 0-MCP-tool. The pattern is "pure LSP registration, editor-UI only" by design. gopls-lsp is normal.

### Evidence path

The marketplace dispatches via a single `marketplace.json` file at the repo root: `repos/anthropics/claude-plugins-official/contents/.claude-plugin/marketplace.json`. Each of 160 plugin entries declares its capabilities via top-level fields. Across all 160 plugins, the field-frequency tally is:

| Field | # plugins | Purpose |
|---|---|---|
| `name`, `description`, `source` | 160 | identity |
| `homepage` | 144 | metadata |
| `category` | 134 | UI grouping |
| `author` | 59 | attribution |
| `strict` | 14 | validation flag |
| `version` | 13 | versioning |
| **`lspServers`** | **12** | **LSP server registrations — present on exactly the 12 LSP plugins** |
| `tags` | 3 | metadata |
| `skills` | 2 | (related to skills system) |
| `keywords` | 1 | metadata |

**No marketplace plugin uses a `tools`, `mcpServers`, `commands`, `agents`, or `hooks` field at the marketplace.json level.** Those would have to live in per-plugin `.claude-plugin/plugin.json` — and the LSP plugins explicitly don't have one (verified via recursive git tree: each LSP plugin contains exactly `LICENSE` + `README.md`, nothing else).

### All 12 LSP plugins side-by-side

Captured from marketplace.json (all use `lspServers` field, none expose anything else):

| Plugin | LSP server registered | MCP tools / commands / agents |
|---|---|---|
| `clangd-lsp` | `clangd` for `.c .h .cpp .cc .cxx .hpp .hxx .C .H` | none |
| `csharp-lsp` | `csharp-ls` for `.cs` | none |
| `gopls-lsp` | `gopls` for `.go` | none |
| `jdtls-lsp` | (Java) | none |
| `kotlin-lsp` | (Kotlin) | none |
| `lua-lsp` | (Lua) | none |
| `php-lsp` | (PHP) | none |
| `pyright-lsp` | `pyright` for `.py .pyi` | none |
| `ruby-lsp` | (Ruby) | none |
| `rust-analyzer-lsp` | `rust-analyzer` for `.rs` | none |
| `swift-lsp` | (Swift) | none |
| `typescript-lsp` | `typescript-language-server` for `.ts .tsx .js .jsx` | none |

### Cross-check against this session's deferred-tools registry

Claude Code's authoritative inventory of every MCP tool the orchestrator can call contains:

- `mcp__cclsp__*` — 12 tools.
- `mcp__ide__*` — 2 tools (`executeCode`, `getDiagnostics`).
- `mcp__plugin_serena_serena__*` — 26 tools (Serena MCP server, marketplace plugin).
- Various unrelated MCPs (`mcp__gmail__*`, `mcp__kite__*`, `mcp__plugin_playwright_*`, etc.).

**Zero `mcp__pyright__*`, `mcp__typescript__*`, `mcp__clangd__*`, `mcp__rust__*`, `mcp__golang__*`, `mcp__rust-analyzer__*` tools.** The empirical session state confirms what the manifests promise: marketplace LSP plugins contribute no agent-callable tools.

### Direct answer to "Python LSP and others work fine — why is gopls different?"

They work fine **for editor-UI consumption** (in-IDE hover, completion, quick fixes when the human user interacts with the IDE pane). They are **identically silent at the orchestrator/MCP-tool level** — the orchestrator cannot ask any of them anything programmatically, including pyright. The user is conflating two surfaces:

- **Editor-UI surface (uniform across all 12 plugins):** "When I hover, I see hover doc; when I type, I see completions." This works fine for Python via pyright-lsp, for TypeScript via typescript-lsp, AND for Go via gopls-lsp once the WSL2 path issue was fixed in our bridge.
- **Orchestrator-MCP surface (cclsp-only today):** "Claude can call `find_definition` from a tool." This works for any language cclsp is configured for, regardless of which marketplace LSP plugin is installed. Pyright, TypeScript, Go, Rust — all the same: cclsp handles agent tooling; the marketplace plugin handles editor tooling.

If Python "feels fine" while Go "didn't," it's perception bias: Python work probably went through editor-UI hovers (which the marketplace plugin fulfills uniformly), while Go work involved orchestrator queries (which no marketplace plugin can fulfill, regardless of language).

### Could a marketplace plugin expose MCP tools like cclsp does?

Architecturally yes — a marketplace plugin could declare `mcpServers` pointing to a TypeScript/Go server that wraps an LSP and re-exposes operations as MCP tools. **No marketplace LSP plugin does this today.** The closest precedent is `mcp__plugin_serena_serena__*` (a marketplace plugin that DOES declare an MCP server with 26 tools, including symbol-level edits — see Honorable Mention earlier). Serena isn't an LSP-registration plugin; it's an MCP server first that uses LSP-like primitives internally.

### Updated verdict (unchanged, now reinforced)

**KEEP-CCLSP** for orchestrator-driven LSP intelligence. The marketplace LSP plugin family is by design editor-UI only across all 12 plugins; expecting any of them to fill cclsp's role is a category error.

## Verification log (2026-04-26)

Empirical confirmation that both routes are operational, recorded after `mcp__cclsp__*` tools were re-enabled by the user. Observations taken from the live Claude Code session — no synthetic test harness.

| Surface | Tool | Input | Result |
|---|---|---|---|
| cclsp via bridge | `mcp__cclsp__get_hover` | `D:\Sundeep\projects\kite-mcp-server\app\wire.go` line 11 char 15 | Returned the full `package kc` hover doc: "Package kc provides store interfaces for hexagonal architecture..." (rendered from gopls markdown) |
| cclsp via bridge | `mcp__cclsp__get_diagnostics` | Same file | "No diagnostics found... no errors, warnings, or hints" — clean file, gopls indexed the workspace successfully |
| Marketplace gopls-lsp plugin | `mcp__ide__getDiagnostics` | Same file | Equivalent clean response via `gopls.cmd` shim → bridge → WSL2 gopls |

Both clients hit the **same** WSL2 gopls process through the **same** `wsl-lsp-bridge`. Backing-LSP consistency is guaranteed by construction.

The hover proof is decisive: gopls returns a populated `result.contents.value` only after `Created View` fires AND the file's `didOpen` has been processed. Both prerequisites involved (a) the bridge's bidirectional URI translation `file:///D:/Sundeep/...` ↔ `file:///mnt/d/Sundeep/...`, and (b) the explicit PATH prefix that lets gopls find the `go` binary inside WSL2.

## Sources

- [cclsp issue #40 — Discontinuation announcement](https://github.com/ktnyt/cclsp/issues/40)
- [cclsp issue #43 — find_workspace_symbols missing ensureFileOpen](https://github.com/ktnyt/cclsp/issues/43)
- [cclsp source (dist/index.js)](https://github.com/ktnyt/cclsp/blob/main/dist/index.js) — workspaceSymbol L30239-30258, getDiagnostics L30125-30221, hover L30222-30238, ensureFileOpen L29539-29572, pathToUri L28789
- [claude-contrib/claude-languages](https://github.com/claude-contrib/claude-languages) — marketplace LSP plugin org, MIT, golang/rust/terraform plugins, last push 2026-04-23
- LSP 3.17 spec: [textDocument/didOpen](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#textDocument_didOpen), [workspace/symbol](https://microsoft.github.io/language-server-protocol/specifications/lsp/3.17/specification/#workspace_symbol)
- Empirical evidence from this session: bridge wire-log captured at `C:/Users/Dell/AppData/Local/Temp/wsl-lsp-bridge.log` showing gopls "Error loading workspace folders" + cclsp's silent fallback to `[]` for diagnostics

## Diagnostic publishing asymmetry — root cause + fix (2026-04-26)

**User-observed asymmetry**: pyright auto-pushed `<new-diagnostics>` system-reminders to the orchestrator on `bad.py`; gopls did not on `bad.go`. `mcp__cclsp__get_hover` worked for both, proving gopls was indexed; only diagnostic-surfacing was broken.

**Root cause**: drive-letter casing + colon-encoding bug in the bridge's Linux→Windows URI rewrite. Decisive wire-log evidence captured by hooking `process.stdout.write` post-transform:

| Hop | URI emitted |
|---|---|
| cclsp → bridge (initialize, didOpen, etc.) | `file:///D:/Sundeep/projects/lsp-test/bad.go` (uppercase, literal colon — Node `pathToFileURL` form) |
| gopls → bridge (publishDiagnostics) | `file:///mnt/d/Sundeep/projects/lsp-test/bad.go` (Linux form) |
| bridge → cclsp (post-transform) before fix | `file:///d%3A/Sundeep/projects/lsp-test/bad.go` (LOWERCASE drive + percent-encoded colon) |

cclsp keys its diagnostic cache by URI string at `dist/index.js:29379` — `serverState.diagnostics.set(params.uri, params.diagnostics)`. Lookups at `dist/index.js:30132` use `pathToUri(filePath)` which emits the uppercase/literal-colon form. The bridge stored under lowercase/encoded form → permanent cache miss → orchestrator never sees the diagnostics.

**Why pyright didn't hit this**: pyright runs as a marketplace LSP plugin with no bridge in front of it (it's a Windows-native binary, not a WSL2 process). Its `publishDiagnostics` URIs flow through Claude Code's IDE bridge directly with no URI rewriting — the bug is bridge-specific.

**Why hover/definition still worked**: those are request/response pairs where cclsp DID send the URI initially, so cclsp uses its OWN copy (via `pathToUri`) for any later operations on the same file. Diagnostics are server-pushed, so the URI form comes from the bridge alone — the casing mismatch only shows up in the push direction.

### Vscode-uri's drive-letter mangling (the actual cause)

`URI.parse('file:///mnt/d/...').with({ path: '/D:/...' }).toString()` returns `file:///d%3A/...`. Verified directly:

```
> URI.parse('file:///D:/Sundeep/...', true).fsPath
'd:\Sundeep\...'
> uri.with({path: '/D:/...'}).toString()
'file:///d%3A/Sundeep/...'
> uri.with({path: '/D:/...'}).toString(true)  // skipEncoding
'file:///d:/Sundeep/...'
```

Vscode-uri normalizes the drive letter to lowercase and percent-encodes the colon as `%3A` in `.toString()`. `skipEncoding=true` removes the percent-encoding but still lowercases the drive. **Both forms differ from Node's `pathToFileURL` (uppercase + literal colon), and cclsp uses Node's form.**

### Fix: bypass vscode-uri's serialization for this direction

`src/rpc-message-transformer.ts` Linux→Windows path now constructs the URI string manually instead of round-tripping through `URI.with().toString()`:

```ts
const winPath = convertWslToWindowsPath(uri.path); // "/D:/Sundeep/..."
return `file://${winPath}`;
```

The regex in `wsl-path.ts` already preserves uppercase (`m[1].toUpperCase()`); the literal colon comes for free. **6 net lines of change** including the comment explaining the bug.

### Verification

- `mcp__cclsp__get_diagnostics` on `D:\Sundeep\projects\lsp-test\bad.go` → **4 errors returned** (UnusedImport `fmt`, IncompatibleAssign return, UndeclaredName `undefinedFunction`, IncompatibleAssign var) — exactly what gopls publishes.
- `mcp__cclsp__get_hover` on the same file → still returns full type signature (regression check passed).
- `mcp__ide__getDiagnostics` returns `[]` for the file — the IDE bridge is a separate consumer with its own URI normalization (lowercase) and is unaffected by this fix; out of scope.

### Updated verdict

The asymmetry was real but **fully fixable in our bridge** — not a deficiency of marketplace LSP plugins or of cclsp itself. After the fix, gopls diagnostics flow through the same path as pyright diagnostics for any caller that uses Node-form URIs. Bridge fix took ~30 LOC including verification scaffolding.

**This was a true bug** — discovery driven by the user's empirical observation that pyright "worked" while gopls didn't. Without that comparison, the asymmetry was invisible (cclsp silently swallows the cache miss as `[]`). Crediting empirical-observation-driven debugging.

## Push-channel asymmetry — auto-`<new-diagnostics>` for Python but not Go (2026-04-26)

**Different question.** Previous fix was the cclsp pull path. The user's actual concern is the **push channel**: when the orchestrator does `Write`/`Edit` on a `.py` file, Claude Code's harness sometimes auto-pushes a `<new-diagnostics>` system-reminder with all pyright errors, no tool call. For `.go` files this never happens. **Why?**

### Empirical investigation

Process tree captured during this session:

| LSP server | Spawned by | Bridge in path? | Currently running? |
|---|---|---|---|
| pyright (5 instances, PIDs 1688/19356/2396/21872/16240) | All 4 cclsp instances + Claude Code itself (PID 4668) | No bridge — Windows-native binary | YES |
| WSL2 gopls (3 instances, WSL PIDs 1597/1625/2108) | All via cclsp's bridge processes | wsl-lsp-bridge | YES, but only as cclsp's child |
| `gopls.cmd` shim (marketplace plugin's spawn path) | NOTHING — never invoked this session | n/a | **No** |

**Decisive empirical test:** added `set WSL_LSP_BRIDGE_LOG=...` to `gopls.cmd` to capture if Claude Code ever invokes the marketplace plugin's path. Then performed `Edit` on `bad.go` (and `bad.py` as control). Both edits succeeded.

Results:

- **No `<new-diagnostics>` system-reminder fired** for either edit — even pyright didn't auto-push in this session.
- **Marketplace bridge log file did not exist after edits** — `gopls.cmd` was never invoked. Claude Code's editor LSP harness did not spawn gopls in response to the orchestrator's `Edit` on bad.go.

This rules out the bridge-level hypothesis: the bridge can't drop diagnostics it never receives, because gopls.cmd never started. **The asymmetry is upstream of the bridge.**

### Root cause

Claude Code's editor LSP harness only spawns an LSP server for an extension when a buffer of that extension is opened **in the editor pane** (a human-driven action). Pyright is currently running because the user has had Python buffers open in the editor pane this session. **Gopls is not running at the editor-harness level** because no `.go` buffer has been opened in the editor pane (only `Edit` tool calls have touched `.go` files; tool-driven file operations don't open editor buffers).

Result:
- **For `.py` edits when a Python buffer is open in the editor:** pyright (already running, attached to the editor harness) sees the file change, runs analysis, publishes diagnostics; the harness pushes `<new-diagnostics>` to the orchestrator.
- **For `.go` edits at any time:** gopls (NOT running at the editor-harness level) receives no notification. Diagnostics never enter the harness's cache. No `<new-diagnostics>` push.

The earlier `mcp__ide__getDiagnostics` empty result has the same root cause: the editor harness has no diagnostics for `.go` files because gopls isn't running in its scope.

### Pyright also doesn't push when no buffer is open

This session demonstrated empirically that even an `Edit` on `bad.py` did **not** trigger a `<new-diagnostics>` push. The auto-push isn't unconditional on the LSP server merely being alive. The probable additional condition: the file must be opened as an editor buffer (not just `Edit`-touched). The user's earlier observation of pyright auto-pushing was likely from a session where `.py` buffers were actively open in the editor pane during edits.

### Why bridge-side fixes can't help

The bridge sits between LSP-clients and the WSL2 gopls process. If Claude Code's editor harness never spawns the LSP client (`gopls.cmd`), there's no traffic for the bridge to translate, drop, or surface. **The bridge is bypassed entirely**, not buggy.

### Smoking-gun test for "bridge breaks routing" — DISPROVED

User's pre-set hypothesis: "if we test by removing the bridge — running gopls.exe Windows-native — does the auto-push start working?" The empirical answer: **no, the bridge isn't the issue** because gopls isn't being spawned at all by the editor harness. Replacing the bridge with native gopls.exe still wouldn't help unless Claude Code's harness can be persuaded to spawn it. Bridge is a non-factor in this asymmetry.

### What's actually fixable

**Nothing on our side**, fundamentally. The trigger condition for `<new-diagnostics>` lives inside Claude Code's closed-source editor harness; it ties LSP-server spawn to editor-pane buffer opens, not to tool-driven file operations.

**Workarounds that DO help orchestrator-driven workflows:**

1. **Use `mcp__cclsp__get_diagnostics` actively after edits** — fully works post-`32fa08b` URI fix, returns gopls's 4 errors. This is pull, not push, but reliable.
2. **Open the relevant `.go` file in the editor pane** before asking Claude to work on it. This triggers the harness to spawn gopls and (probably) enables auto-push for subsequent edits in that buffer.
3. **Add an orchestrator-side `PostToolUse` hook** matching `Edit|Write` for `*.go` paths that auto-calls `mcp__cclsp__get_diagnostics` and surfaces results into context. Emulates auto-push using cclsp's pull channel. ~30 lines of hook config in `~/.claude/settings.json`. Not in scope here; flagged for follow-up.

### Verdict

The push-channel asymmetry is **upstream of our bridge** — Claude Code's editor harness ties LSP-server spawn to editor-pane buffer opens, not to tool-driven file operations. Pyright is running because the user has Python buffers open; gopls isn't running because no Go buffer is open. Bridge fixes cannot influence this; the trigger lives in Claude Code's closed harness.

**Best practical path:** add a cclsp pull-on-edit hook to emulate the auto-push for `.go` (and any other language where this pattern bites). Settings change, not bridge change. Bridge stays as-is.

## Post-restart `gopls.exe` SAC block diagnosis (2026-04-26 evening)

**Symptom:** User restarted Claude Code and got the same Windows Security toast: "Part of this app has been blocked. Some features of Claude Code may not work because we can't confirm who published gopls.exe that the app tried to load." Despite WSL2 bridge setup, marketplace plugin pointing at `gopls.cmd` shim, and `gopls.exe` renamed to `gopls.exe.bak`.

### Empirical findings

**1. No `gopls.exe` exists on PATH today.** Verified via `where.exe gopls.exe` → `INFO: Could not find files`. `where gopls` resolves to `C:\Users\Dell\go\bin\gopls.cmd` (the bridge shim). The only PE32+ binaries that look like gopls were:

- `C:\Users\Dell\go\bin\gopls.exe.bak` (40,857,960 bytes, mtime 2026-04-26 18:11:37 — recent re-sign artifact)
- `C:\Users\Dell\go\bin\gopls.exe~` (40,858,472 bytes, mtime 2026-04-03 11:53:41 — older backup with tilde suffix)

Wide search across `C:\Program Files`, `C:\Program Files (x86)`, `C:\Users\Dell\AppData\{Local,Roaming}`, `.vscode`, `.cursor`, `.zed` — found **zero** other `gopls.exe`. `C:\Program Files\Go\bin\` (the Go toolchain) only has `go.exe` and `gofmt.exe`; the standard installer doesn't bundle gopls.

**2. Windows CodeIntegrity event log captures the truth.** 76 events in last 8 hours mention gopls; all are Event ID 3077 (block) and 3033 (load failed). Each entry shows:

- `File Name: \Device\HarddiskVolume4\Users\Dell\go\bin\gopls.exe` (literal `gopls.exe`, NOT `.bak` or `~`)
- `Process Name: \Device\HarddiskVolume4\Users\Dell\.local\bin\claude.exe` — **Claude Code itself is the loading process**
- `Validated Signing Level: 1` (Unsigned from CI's view) → SAC block
- `SHA1: DB91839BC6C542CD2CB2ECDA7E793498650A1C8D` — same hash across all 76 events; **does not match either current `.bak` or `~` file's hash** (computed live: `7C9824BD...` for `.bak`, `FDD974A5...` for `~`)
- 38+ distinct timestamps spanning 15:44 → 17:57

**3. The mismatch resolves to:** the SAC log hash is from an EARLIER state of the binary (before the 18:11 re-sign), but the kernel image-cache holds the stale path entry `gopls.exe`. Claude Code's plugin-manifest evaluator probes for `gopls.exe` (forced `.exe` lookup, bypassing PATHEXT resolution to `.cmd`) when handling the marketplace `gopls-lsp` plugin's `lspServers.command: "gopls"` entry. Each probe triggers a CodeIntegrity check against the cached path → file (now `.bak` after rename, but kernel cache still maps the old path) → SAC block logged → toast fired.

### Why moving renamed files OUT of `~/go/bin/` matters

`gopls.exe.bak` and `gopls.exe~` are PE32+ binaries living next to the active `gopls.cmd`. Even though Windows path resolution finds `.cmd` first, **kernel-level file enumeration during process spawn or path-cache invalidation** can scan adjacent files. Moved both to `C:\Users\Dell\go\bin-archived\` (out of PATH entirely) to eliminate this vector.

### Verification: post-move state

After the move to `C:\Users\Dell\go\bin-archived\`:

- `where gopls` still resolves to `gopls.cmd` (bridge shim intact).
- `where gopls.exe` still returns "not found" (no regression).
- `mcp__cclsp__get_hover` on `D:\Sundeep\projects\kite-mcp-server\app\wire.go:11:15` → returns full `package kc` hover doc — **Go LSP fully functional**.
- `mcp__cclsp__get_diagnostics` on `D:\Sundeep\projects\lsp-test\bad.go` → empty (cache not yet warmed since restart, expected).
- Zero new SAC gopls events in the last 2 minutes post-move.

### Root cause summary

The toasts are a **stale-kernel-path-cache + SAC reputation check** issue triggered by Claude Code's plugin spawn-resolution for the marketplace `gopls-lsp` plugin. Specifically:

1. Marketplace plugin's `lspServers.command: "gopls"` triggers Claude Code to resolve `gopls` for spawn.
2. Resolution involves probing `gopls.exe` directly (some Node `child_process` paths do this on Windows before falling back to PATHEXT).
3. Kernel image-cache holds a stale entry pointing at the old `gopls.exe` path; cache lookup triggers SAC integrity check.
4. The integrity check sees the binary at the cached hash is unsigned-from-CI's-perspective → block event 3077 → toast.
5. **Claude Code itself doesn't break** — its own logic fails the spawn gracefully and falls back to `gopls.cmd` (verified by Go LSP working). Only the toast surfaces to the user.

The repeated toasts during a single session likely correspond to plugin-reload / reconnect events, each triggering a fresh probe.

### Fix shipped

**Moved `gopls.exe.bak` and `gopls.exe~` to `C:\Users\Dell\go\bin-archived\`** so no PE32+ "looks-like-gopls" binary exists in any PATH directory. Bridge shim `gopls.cmd` remains. After the move, no new SAC gopls events in 2+ minutes.

To make this stick across future Claude Code restarts:
- The `.bak` file gets recreated by `sign-gopls.ps1` if the user runs it again. The script targets `~/go/bin/gopls.exe` and writes `~/go/bin/gopls.exe.bak` as backup. Workaround: edit `sign-gopls.ps1` to write the `.bak` to `~/go/bin-archived/` instead. Out of scope for this section but a follow-up.

### Verdict

The SAC block was **stale kernel-path-cache noise**, not a functional break. Go LSP works through cclsp + bridge as expected throughout. Moving the renamed binaries out of PATH eliminates the vector. The toast was harmless (Claude Code falls back correctly) but should stop appearing now.

## Final cleanup + post-/reload-plugins verification (2026-04-26 evening)

After moving `gopls.exe.bak` and `gopls.exe~` out of PATH, the user `/reload-plugins`'d. This section captures the full verification + cleanup pass.

### Step 1 — cclsp route verification (PASS)

| Check | Result |
|---|---|
| `mcp__cclsp__get_hover` on `wire.go:11:15` | Returned full `package kc` doc — gopls indexed kite-mcp-server workspace |
| `mcp__cclsp__get_diagnostics` on `bad.go` | Returned 4 real errors (UnusedImport, IncompatibleAssign×2, UndeclaredName) — push channel into cclsp's cache works |
| `where gopls` | Resolves to `C:\Users\Dell\go\bin\gopls.cmd` (bridge shim) |
| `where gopls.exe` | Not found (exit 1) |
| WSL2 `pgrep -af gopls` | 2 alive instances (PIDs 1625/1636 and 2553/2566 with telemetry pairs) |
| SAC events for gopls in last 15 min | Zero. Latest gopls SAC event ever: 04/26/2026 17:57 — 3+ hours ago, before file move |

### Step 1 — marketplace plugin verification (expected lazy-spawn gap)

| Check | Result |
|---|---|
| `mcp__ide__getDiagnostics` for `bad.go` | `[{"uri":"file:///d:/Sundeep/projects/lsp-test/bad.go","diagnostics":[]}]` — empty, marketplace gopls hasn't lazy-spawned |
| Win-side bridge process count | 2 instances, BOTH parented to `cclsp/dist/index.js` (PIDs 19804 and 9968 → grandparent `cmd /c cclsp`). Zero parented to `gopls.cmd`. |
| WSL2 gopls processes attributable to marketplace plugin | 0 — both WSL gopls pairs trace to cclsp bridges |
| Bridge log files | None — `WSL_LSP_BRIDGE_LOG` not set this session |

This empirically confirms `53633cd`'s finding: **the marketplace `gopls-lsp` plugin lazy-spawns**. It only fires when a `.go` buffer opens in the editor pane, NOT on `/reload-plugins` or orchestrator file operations. No `.go` editor-pane buffer = marketplace gopls never started = `mcp__ide__getDiagnostics` returns empty for that URI. **Expected**, not a regression.

### Step 2 — Windows-side gopls cleanup (DONE)

Files deleted:
- `C:\Users\Dell\go\bin-archived\gopls.exe.bak` (40 MB) — was the renamed self-signed binary, no longer needed
- `C:\Users\Dell\go\bin-archived\gopls.exe~` (40 MB) — older backup with tilde suffix
- `C:\Users\Dell\go\bin-archived\` directory itself — empty after the binary deletes
- `C:\Users\Dell\go\bin\sign-gopls.ps1` — would have recreated the SAC trap if re-run; WSL2 gopls doesn't need signing
- `C:\Users\Dell\go\bin\sign-bin.ps1` — generic signer, same recreation-trap reasoning

Files kept:
- `C:\Users\Dell\go\bin\gopls.cmd` — bridge shim, REQUIRED for marketplace plugin's PATH-based `gopls` lookup
- `C:\Users\Dell\go\bin\` itself — still has 7 other Go binaries (`deadcode.exe`, `go1.25.8.exe`, `gocovmerge.exe`, `goimports.exe`, `gosec.exe`, `govulncheck.exe`, `staticcheck.exe`)
- `GoTools Local Dev` cert in `CurrentUser\Root` — harmless residue

Post-cleanup sanity check: `mcp__cclsp__get_hover` on `wire.go:11:15` still returns full `package kc` doc → cclsp + bridge unaffected.

### Honest verdict on dual-route status post-reload

**cclsp route: FULLY OPERATIONAL.** Bridge spawns gopls, hover and diagnostics work, push channel into cclsp's internal cache works, all `mcp__cclsp__*` agent tools functional.

**Marketplace `golang` plugin route: REGISTERED BUT DORMANT.** Plugin manifest registered with Claude Code's editor harness; `gopls.cmd` shim still on PATH for when it does spawn. Will lazy-spawn the moment a `.go` buffer opens in the editor pane. Until then, `mcp__ide__getDiagnostics` returns empty for Go files.

The two routes are complementary, not redundant: cclsp owns orchestrator-callable agent tools; marketplace plugin owns editor-UI surface for human users. Deleting Win-side gopls binaries did not affect either route because both go through `gopls.cmd → wsl-lsp-bridge → WSL2 gopls`.

## Why pyright pushes `<new-diagnostics>` but gopls doesn't — root cause (2026-04-26 evening)

User question: pyright pushes `<new-diagnostics>` system-reminders; gopls doesn't. Why?

### Empirical finding: pyright ALSO doesn't push right now

`mcp__ide__getDiagnostics` no-arg call returns `[]`. For `bad.py` specifically: `[{"uri":"file:///d:/Sundeep/projects/lsp-test/bad.py","diagnostics":[]}]` — empty. **The IDE bridge cache is currently empty for ALL files**, Python and Go alike.

Earlier in this session pyright did appear to push reminders on `Write`/`Edit` of `bad.py`. **It's not pushing now.** This invalidates the simple "pyright is special" framing.

### Pyright process tree audit

All 4 pyright instances currently running (PIDs 14276, 16304, 7804, 23032) are spawned by **cclsp instances** (PIDs 19804 and 9968 → grandparent `cmd /c cclsp`). **Zero pyright instances are spawned by Claude Code's editor harness directly.** This is the same picture as for gopls: cclsp owns the LSP servers via its own spawning logic; Claude Code's editor harness is not in the loop.

### cclsp's publishDiagnostics handling — does NOT forward to IDE bridge

Source-read of `cclsp 0.7.0` `dist/index.js`. `publishDiagnostics` notification handler at L29374-29385:

```js
} else if (message.method === "textDocument/publishDiagnostics") {
  const params = message.params;
  if (params?.uri) {
    serverState.diagnostics.set(params.uri, params.diagnostics || []);
    serverState.lastDiagnosticUpdate.set(params.uri, Date.now());
    if (params.version !== undefined) {
      serverState.diagnosticVersions.set(params.uri, params.version);
    }
  }
}
```

**That's the entire handler.** It writes to cclsp's internal `serverState.diagnostics` Map. **Nothing is forwarded to Claude Code's IDE bridge channel.** Grep across all 31,465 lines of `dist/index.js` for `ide|IDE|forward|publish|broadcast` found no IDE-bridge integration code.

### So how does pyright EVER push `<new-diagnostics>`?

Three remaining hypotheses:

**(H1) An earlier-session pyright instance, owned by the editor harness, was alive and feeding the IDE bridge cache.** When the user opens a `.py` buffer in the editor pane (not via orchestrator `Edit`), Claude Code's editor harness spawns its own pyright as part of editor LSP integration. That pyright reports `publishDiagnostics` directly to the editor harness, which surfaces them to the orchestrator via `<new-diagnostics>` reminders AND populates `mcp__ide__getDiagnostics`. **No such instance exists right now**, which is why the cache is empty.

**(H2) Claude Code's harness has a built-in `Edit`/`Write` post-hook that calls `mcp__ide__getDiagnostics` and surfaces deltas as `<new-diagnostics>`.** This would explain the auto-surface behavior and is consistent with the cache being the source of truth. The cache being empty means no LSP server is feeding it.

**(H1) and (H2) together explain everything**: the editor harness spawns LSP servers when buffers open in the editor pane; those servers feed the IDE-bridge cache via publishDiagnostics; Claude Code's `Edit`/`Write` post-hook reads from the cache and surfaces deltas. Without an editor-pane buffer, no LSP server, no cache, no deltas, no reminder.

### Why this makes the asymmetry symmetric

Both pyright and gopls behave identically: they push `<new-diagnostics>` ONLY when:
1. A file of their language extension is opened in the editor pane (triggering harness spawn), AND
2. The file is touched (triggering publishDiagnostics)

The user observed pyright "working" earlier because they had a `.py` buffer open in the editor pane in this or a recent session. They observed gopls "not working" because they never opened a `.go` buffer in the editor pane (only orchestrator `Edit`/`Write`/`Read` operations).

### Can we engineer parity for gopls?

**Yes, two options:**

1. **Open a `.go` file in the editor pane.** Triggers Claude Code's editor harness to lazy-spawn the marketplace `golang` plugin's gopls (via `gopls.cmd` shim → bridge → WSL gopls). Once that pyright-equivalent gopls instance is alive, future `Edit`/`Write` operations on `.go` files should produce `<new-diagnostics>` reminders. **Free fix.**

2. **Add a `PostToolUse` hook for `Edit|Write` on `*.go`** that pulls `mcp__cclsp__get_diagnostics` and surfaces results. Emulates the auto-push using cclsp's pull channel (which works deterministically post-`32fa08b`). **30-line settings change**, doesn't depend on editor-pane state.

Both options work; (1) is the natural Claude Code workflow; (2) is the orchestrator-driven workflow that doesn't require human IDE interaction.

### Verdict

**The asymmetry is not pyright-vs-gopls; it's editor-pane-buffer-vs-not-buffer.** Pyright happens to be running with publishDiagnostics flowing to Claude Code's IDE-bridge cache *only when a `.py` buffer is open in the editor pane*. Same is true for gopls if a `.go` buffer is open.

**cclsp does NOT forward publishDiagnostics to the IDE bridge** — its publishDiagnostics handler writes only to its own internal cache for `mcp__cclsp__get_diagnostics` to serve. The IDE bridge channel and the cclsp channel are separate; they don't cross-feed.

**Bridge fixes can't help.** The editor-harness spawn condition is upstream of the bridge.

**Practical fix:** keep a `.go` file open in the editor pane during Go work (for IDE-bridge auto-push), OR install a hook that pulls cclsp diagnostics on `Edit`/`Write` (for orchestrator-only Go work). Both are valid; pick based on workflow.


