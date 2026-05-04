# Anchor 1 PR 1.1 Redesign — Cycle-Break for mcp/common Extraction

**Date**: 2026-05-04
**HEAD audited**: `d54315f` (Anchor 6 PRs 6.7/6.9/6.11/6.13 landed; Anchor 3 PR 3.1 landed)
**Builds on**: `04e069a anchor-1-and-3-pr-design.md` (challenged by execution-agent empirical findings)
**Charter**: read-only research. Doc-only. NO code changes.

**Empirical cycle map** (verified at HEAD):

```
  mcp/mcp.go:14         type Tool interface           ─── used by ───┐
  mcp/mcp.go:34         GetAllTools() []Tool                          │
  mcp/mcp.go:49         GetAllToolsForRegistry(reg *Registry) []Tool ─┤
  mcp/plugin_registry.go:43  type Registry struct{ toolPlugins []Tool }├── BIDIRECTIONAL
  mcp/plugin_registry.go:49  toolPlugins []Tool ─── needs Tool type ───┘
  mcp/integrity.go:75   ComputeToolManifest(tools []Tool) ─── needs Tool type
  mcp/common.go:64      for _, t := range GetAllTools() ─── calls GetAllTools
```

**Cycle**: `Tool` (in mcp.go) ↔ `Registry` (in plugin_registry.go). Both use the other's type at struct-field level, not just method signature. **Cannot put Tool in mcp/common while Registry stays in mcp/plugin** — compilation fails because `mcp/plugin/Registry.toolPlugins []Tool` requires importing mcp/common, while `GetAllToolsForRegistry(*Registry)` declared in mcp/common requires importing mcp/plugin. Standard Go import-cycle violation.

**External callers verified** (outside mcp/): `app/app.go:125,136,529` (`mcp.Registry`), `app/http.go:342,619,1346` (`mcp.GetAllTools`). 6 external call sites depending on the current public surface.

**ToolHandler pinning** verified: 4 files (common.go, common_deps.go, common_response.go, common_tracking.go) all define methods on `*ToolHandler` declared at `common_deps.go:94`. Go forbids cross-package method declarations on a non-local type, so these 4 files **must move atomically together**.

---

## Q1 — Pick the option

**Recommended: Option (B) — Restructure mcp.go to split Tool interface from Registry-using functions.**

**Empirical justification**:

1. **Option (A) — move both mcp.go + plugin_registry.go to mcp/common — REJECTED**.
   - Plugin_registry.go is **571 LOC** in current location with rich content (hooks, middleware, widgets, event subscriptions — verified via the multi-mutex struct fields at lines 43-83). Bundling all that into `mcp/common` would make common ~30% larger than its current 9-file scope, violating the "common is a leaf with the small shared kernel" architectural intent. Loses the per-sub-package cohesion that the broader Anchor 1 split is supposed to achieve.

2. **Option (B) — split mcp.go**: place `Tool` interface alone in mcp/common; keep `GetAllTools/GetAllToolsForRegistry/Registry` together in mcp/. Fixes the cycle because:
   - mcp/common only exposes the Tool interface (zero Registry dependency).
   - Both `mcp/mcp.go` (functions) and `mcp/plugin_registry.go` (struct) import mcp/common for the Tool type only.
   - mcp/common has zero imports of either mcp/* sub-package — true leaf.
   - Empirical evidence this works: `mcp/common.go:64` only needs `Tool` to iterate via `GetAllTools()`. If `GetAllTools()` is re-exported from the parent mcp/ package (1-line passthrough), common can call back through the public mcp surface, which itself imports mcp/common — directional, not cyclic.

3. **Option (C) — RegistryProvider interface — REJECTED**.
   - Adds an extra indirection layer for zero benefit. The real cycle is on the *concrete `Tool` type*, not on Registry methods. RegistryProvider would still need to return `[]Tool`, requiring Tool to live somewhere both packages can import. That somewhere is mcp/common per Option B. Option C just adds ceremony around the same end-state.

**Verdict: Option (B) is the empirical fit.**

---

## Q2 — Concrete PR 1.1 plan (Option B)

### File-by-file move list

**Phase 1 — Create mcp/common with leaf-only types**:
1. **NEW `mcp/common/tool.go`** (~25 LOC). Hosts:
   - `Tool` interface (moved from `mcp/mcp.go:14-17`)
   - Type alias in original location for backward-compat: `// Deprecated: use mcp/common.Tool. type Tool = common.Tool`
2. **MOVE 4 ToolHandler files atomically** to `mcp/common/`:
   - `mcp/common.go` → `mcp/common/handler_methods.go` (~530 LOC)
   - `mcp/common_deps.go` → `mcp/common/handler_deps.go` (~250 LOC)
   - `mcp/common_response.go` → `mcp/common/handler_response.go` (~80 LOC)
   - `mcp/common_tracking.go` → `mcp/common/handler_tracking.go` (~30 LOC)
3. **NEW `mcp/common/cache.go`**: move `mcp/cache.go` (~150 LOC).
4. **NEW `mcp/common/decorator_chain.go`**: move `mcp/decorator_chain.go` (~80 LOC).
5. **NEW `mcp/common/elicit.go`**: move `mcp/elicit.go` (~50 LOC).
6. **NEW `mcp/common/integrity.go`**: move `mcp/integrity.go` (~110 LOC). **Critical**: `ComputeToolManifest` accepts `[]Tool` — works because Tool is in same package now.

**Phase 2 — Keep mcp/ root with Registry-using functions**:
- `mcp/mcp.go` retains **only**: `GetAllTools()`, `GetAllToolsForRegistry(*Registry)`, `RegisterInternalTool`, `internalToolRegistry` package-level state. Imports `mcp/common` for the `Tool` type. ~150 LOC after the split (down from 259).
- `mcp/plugin_registry.go` stays at root (or moves to mcp/plugin in PR 1.3). Imports `mcp/common` for `Tool`. **No change needed in PR 1.1** — defer to PR 1.3.

**Phase 3 — Resolve `common.go:64` callback**:
- The line `for _, t := range GetAllTools()` in (now-renamed) `mcp/common/handler_methods.go:64` would create cycle: common imports root mcp/ which imports common. **Fix**: change `buildWriteTools()` to accept the tool slice as a parameter:
  ```go
  func buildWriteTools(tools []Tool) {  // was: GetAllTools()
      writeTools = make(map[string]bool)
      for _, t := range tools { ... }
  }
  ```
  And restructure the once-guard so root mcp/ calls `common.BuildWriteToolsFromAllTools()` at app startup with the slice already resolved. This breaks the directional dependency cleanly.

### Backward-compat shims

In **`mcp/mcp.go` (root, post-split)**:
- `type Tool = common.Tool` — type alias preserves all 60 tool registrations using `mcp.Tool`
- `var WithViewerBlock = common.WithViewerBlock` (etc., for any exported helpers)
- `func NewToolHandler(m *kc.Manager) *common.ToolHandler { return common.NewToolHandler(m) }` — passthrough wrapper if production callers reach `mcp.NewToolHandler`

### Build verification gate

```
cd /mnt/d/Sundeep/projects/kite-mcp-server
go build ./...                          # workspace mode, expect green
GOWORK=off go build ./...               # standalone build, expect green
go vet ./mcp/...                        # vet the affected sub-tree
go test ./mcp/common/... -count=1       # new sub-package tests pass
go test ./mcp/... -count=1              # entire mcp/ tree, no regressions
grep -rE "mcp\.NewTool\(" mcp/*.go mcp/common/*.go | grep -vE "_test" | wc -l   # tools=111 unchanged
flyctl deploy -a kite-mcp-server        # production deploy gate
```

### Acceptance

1. **`mcp/common/` is a true leaf**: `cd mcp/common && grep -rE "github.com/zerodha/kite-mcp-server/mcp\b" *.go` returns zero matches.
2. **All 60 tool registrations compile** (verified via tool count grep).
3. **External callers preserved**: `app/app.go:125,136,529` and `app/http.go:342,619,1346` continue to compile via the type-alias + passthrough shims.
4. **24h production observation green**.

---

## Q3 — Adjusted estimate

**Was**: ~45 min (per `04e069a`).

**New realistic**: **~90 min review + merge**.

Breakdown:
- Phase 1 file moves: ~30 min mechanical (4 ToolHandler files + 4 leaf files + 1 new tool.go).
- Phase 3 `buildWriteTools` parameterization: ~25 min (touches 1 file but requires careful once-guard restructuring + verification that init() ordering still works).
- Type alias + passthrough shim setup: ~10 min.
- Build/test verification across both modes: ~15 min.
- Buffer for cycle-detection iteration: ~10 min.

**Doubles the prior estimate** — `04e069a` undercounted the structural work. The cycle is a **real blocker** to a naive "move 9 files" approach.

---

## Q4 — Cascade impact on PRs 1.2-1.10

**Limited impact. The 9-way fan-out plan stands.**

- **PR 1.3 (mcp/plugin extraction)**: now can proceed normally because plugin_registry.go imports `mcp/common.Tool` instead of declaring its own dependency on a same-package type. The Registry struct moves to mcp/plugin cleanly. **No design change.**
- **PRs 1.2, 1.4-1.10**: each tool-cluster sub-package imports `mcp/common` for the Tool interface + ToolHandler factory (no change from `04e069a` design).
- **PR 1.7 (mcp/analytics)** and **PR 1.8 (mcp/alerts)**: empirically these don't import mcp.Registry directly — only Tool — so unaffected.
- **PR 1.10 (mcp/misc)**: `observability_tool.go:145` calls `len(GetAllTools())`. Since GetAllTools stays in mcp/ root (per Phase 2 above), this caller goes to mcp/ root, which is the natural place. **No special handling needed.**

**One small new constraint**: PR 1.3 (mcp/plugin) must merge BEFORE the 9 tool-cluster PRs are deployed (1.12), because Registry is needed by tool-registration and the `app.Registry()` external callsite at `app/app.go:529`. **This is already the topological intent in `04e069a` — explicit confirmation here.**

**External callers (`app/app.go`, `app/http.go`) require zero changes** because the type alias at mcp/ root preserves `mcp.Registry`, `mcp.Tool`, `mcp.GetAllTools` as public symbols. Migration is fully internal to the mcp/ tree.

---

## Net Anchor 1 calendar update

- PR 1.1: was 45 min → now **90 min** (+45 min)
- PRs 1.2-1.10: unchanged (~30 min each, parallel-safe)
- PR 1.11: unchanged (~30 min)
- PR 1.12: unchanged (~30 min + 24h observation)

**Anchor 1 total at N=20**: ~2 days unchanged (the 24h observation gate dominates; PR 1.1's extra 45 minutes does not cross a calendar-day boundary).

**B-Full total**: still ~21-26 days at N=20 per `04e069a` final tally.

**Green-light recommendation**: dispatch PR 1.1 with Option (B) plan. Cycle is real but solvable; 90-min PR vs 45-min PR is the only material change.

---

**End. Doc-only. No code mutated. No tests run.**

Last section completed: **Net Anchor 1 calendar update** (final).
