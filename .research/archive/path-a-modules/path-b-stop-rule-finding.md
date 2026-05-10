# Path B Phase B Halt — Type-Identity Blocker via kc/money Transitive Dep

**Date**: 2026-05-06
**HEAD audited**: `1408871` (master)
**Halt trigger**: stop-rule per orchestrator brief — "if Phase B reveals dependency-graph issues that >2 day budget, halt + surface (treat as research-vs-empirical trigger)."

---

## TL;DR

**Phase B (drop in-tree `./broker/` + replace, fetch upstream `algo2go/kite-mcp-broker@v0.1.0`) is structurally blocked.** The blocker is not mechanical sweep effort but a fundamental Go module-identity issue caused by a transitive dependency on an unpublished module (`algo2go/kite-mcp-money`).

The Phase A canary was empirically validated for 3 consecutive deploys (v224, v225, v226) holding tools=111. **Phase A canary should remain in place indefinitely** until kc/money is also promoted to its own GitHub repo + tag, or until consumer-side imports are migrated to the algo2go/kite-mcp-money path.

---

## Empirical evidence

### 1. Upstream `algo2go/kite-mcp-broker@v0.1.0` go.mod fetched cleanly from GOPROXY

```bash
GO111MODULE=on go mod download github.com/algo2go/kite-mcp-broker@v0.1.0
# proxy.golang.org/github.com/algo2go/kite-mcp-broker/@v/v0.1.0.info  → 200 OK
# sum.golang.org/lookup/github.com/algo2go/kite-mcp-broker@v0.1.0     → 200 OK
```

Module is publicly fetchable via the Go proxy. Sum-DB checksum verified. Not the blocker.

### 2. Upstream go.mod declares unsatisfiable transitive require

Upstream `algo2go/kite-mcp-broker@v0.1.0/go.mod`:

```
require (
    github.com/algo2go/kite-mcp-money v0.0.0-00010101000000-000000000000
)
replace github.com/algo2go/kite-mcp-money => ../kc/money
```

`github.com/algo2go/kite-mcp-money` is **not a published Go module** — no `algo2go/kite-mcp-money` GitHub repo exists. The `replace ../kc/money` is upstream-relative.

**Per Go's documented behavior** (`go help modules` / Go 1.25 release notes / cmd/go/internal/modload semantics):

> "Replace directives only apply in the main module's go.mod file (or in a workspace go.work file). Replace directives in modules other than the main module are ignored when building the main module."

Therefore the upstream broker's `replace ../kc/money` is **silently dropped** when consumed as a dep. Go falls back to fetching `algo2go/kite-mcp-money@v0.0.0-00010101000000-000000000000` from GOPROXY, which 404s.

### 3. Consumer-side shim DOES make the build resolve modules — but breaks types

Hypothesis tested: consumer-side `replace github.com/algo2go/kite-mcp-money => ./kc/money` in the main module's go.mod (which IS honored, unlike upstream replaces).

```sh
# Phase B mutations applied:
- Drop replace github.com/algo2go/kite-mcp-broker => ./broker
- Add replace github.com/algo2go/kite-mcp-money => ./kc/money  (shim)
- Drop ./broker from go.work use block
- Move ./broker/ out of tree (test-only, scratch)
- Sweep 17 peer go.mod files (drop broker replace, pin require to v0.1.0)

go build ./...
```

Result:

```
# github.com/zerodha/kite-mcp-server/kc/domain
kc/domain/holding.go:57:9: cannot use h.dto.PnL (variable of struct type
  "github.com/algo2go/kite-mcp-money".Money) as Money value in return statement
kc/domain/position.go:90:9: cannot use p.dto.PnL (variable of struct type
  "github.com/algo2go/kite-mcp-money".Money) as Money value in return statement
```

### 4. Root cause — Go's module-path-based type identity

- Upstream broker source files (`broker.go`, `mock/demo.go`, `mock/client_test.go`, `zerodha/convert.go`) `import "github.com/algo2go/kite-mcp-money"`. Type assertions, struct field types, function signatures all bind to **`github.com/algo2go/kite-mcp-money.Money`**.
- Consumer `kc/domain/holding.go` (and 11 other files) `import "github.com/zerodha/kite-mcp-server/kc/money"`. They bind to **`github.com/zerodha/kite-mcp-server/kc/money.Money`**.
- Per Go's spec ([Type identity](https://go.dev/ref/spec#Type_identity)): two named types are identical only if they have the same identifier (defined in the same package). Different module paths = different packages = different types, **even if they're structurally identical**.
- The `replace` workaround makes both module paths point to the same source files, so the *implementation* compiles successfully — but the *consumer's references* to `Money` come out as different types depending on which import path they use.
- Result: `holding.dto.PnL` (typed `algo2go.Money`) cannot be assigned to a return value typed `zerodha.Money`. This is a Go type-system rule, not a workspace mechanic.

**Empirical census in scratch tree post-shim**: all 12 consumer kc/money imports use `github.com/zerodha/kite-mcp-server/kc/money`. None use the algo2go path. This is the Phase A canonical state and changing it requires sweeping 12 consumer .go files + the kc/money module path itself.

---

## Why Phase A canary worked but Phase B doesn't

In Phase A canary state:
- Root go.mod has `replace github.com/algo2go/kite-mcp-broker => ./broker`
- The in-tree `./broker/go.mod` declares `module github.com/algo2go/kite-mcp-broker` AND has `require github.com/algo2go/kite-mcp-money v0.0.0-...` + `replace github.com/algo2go/kite-mcp-money => ../kc/money`
- BUT in workspace mode (`go.work` lists both `./broker` and `./kc/money`), the workspace-level resolution makes `algo2go/kite-mcp-money` and `zerodha/kite-mcp-server/kc/money` resolve to the **same on-disk source tree** (`./kc/money/`)
- Workspace mode treats sibling modules as if they were a single big module for type-identity purposes — Go's `cmd/go/internal/modload/init.go` documents this as the "main-module set"
- So in workspace mode, both import paths produce the same `Money` type — there's no clash

When Phase B drops the replace + go.work entry:
- broker becomes a fetched-from-GOPROXY dep, no longer in the main-module set
- Its imports of `algo2go/kite-mcp-money` go through the dependency-resolution path (which ignores upstream replaces)
- The consumer's `zerodha/kc/money` imports stay local, in the main-module set
- The two `Money` types are now structurally identical but type-system-distinct

---

## Resolution paths (any one unblocks Phase B)

### Path B.alt-1 — Promote kc/money to algo2go/kite-mcp-money (mirror Path A.2 entire process)

- Engineering effort: ~2-4 hours agent-pace (scripts already proven on broker; copy-paste mechanic for kc/money)
- New artifacts: `algo2go/kite-mcp-money` GitHub repo + v0.1.0 tag + branch protection
- Sweep: 12 consumer `kc/money` imports in .go files + kc/money/go.mod module-path declaration + 17 peer go.mod require/replace + Dockerfile pre-stage line
- Then re-tag broker as v0.2.0 with `require kc/money v0.1.0` (drops the upstream replace) — OR leave broker at v0.1.0 (consumer's main-module replace still works since published kc/money exists)
- **Verdict**: shippable but not in scope of "Phase B canary close" — requires user authorization to extend Path A scope

### Path B.alt-2 — Sweep all 12 consumer kc/money imports to algo2go path

- Engineering effort: ~30 min sed sweep + WSL2 verify
- Mutates: kc/money/go.mod (`module algo2go/kite-mcp-money`), 12 consumer .go files, peer go.mod requires/replaces
- Risk: until kc/money is published, the consumer's main-module replace `algo2go/kite-mcp-money => ./kc/money` keeps the build working — but any external consumer of kite-mcp-server itself (not present today) can't resolve algo2go/kite-mcp-money via GOPROXY
- **Verdict**: works for the in-tree consumer but creates a pseudo-published-but-actually-unpublished module name. Strictly worse than Path B.alt-1 in semver hygiene.

### Path B.alt-3 — Re-tag broker v0.2.0 with kc/money type-aliases inlined

- Inline `type Money = money.Money` re-exports in upstream broker, where `money` is upstream's view of the package. Doesn't actually solve the type-identity issue — type aliases preserve identity, but the upstream module still imports `algo2go/kite-mcp-money` to get the alias source.
- **Verdict**: doesn't work. Type aliases don't bridge module identity.

### Path B.alt-4 (default) — Stay in Phase A canary indefinitely

- Phase A is operationally identical to Phase B from production's perspective: the same v0.1.0-tagged broker history is what `./broker/` holds, the upstream tag exists for external adopters, and all consumer behavior is unchanged.
- Maintenance cost: ~30 min/week per the abc-100pct doc's empirical estimate. At 6-12 months pre-trigger, ~12-24h sunk maintenance.
- **Verdict**: this is the empirical-default path until kc/money also promotes (Path B.alt-1), or until an external consumer requests true upstream-only consumption.

---

## Recommendation

**Halt Phase B.** Surface to orchestrator. Default to Path B.alt-4 (stay in Phase A canary).

If user-orchestrator authorizes Path B.alt-1 (promote kc/money), reuse the proven Path A scripts (`path-a-prep-dryrun.sh`, `path-a-prep-rewrite-dryrun.sh`, `path-a-bootstrap-extracted-repo.sh`, `path-a-consumer-cutover-apply.sh`) with `kc/money` substituted for `broker`. Total agent time: ~2-4 hours. Same dry-run-first methodology that caught the 17-peer-go.mod gap on broker.

The audit agent's Phase (a) refactor on mcp/trade/ + kc/usecases/ is **disjoint from this halt** — they continue independently. No deploy-ready signal needed for chain agent because nothing in master changes.

---

## Production state (unchanged)

- v226 LIVE: tools=111, version v1.3.0
- master HEAD: `1408871` (was `1408871` at brief dispatch — no commits added by this halt research)
- algo2go/kite-mcp-broker@v0.1.0: LIVE on GitHub, fetchable from GOPROXY
- Phase A canary state holds: in-tree `./broker/` + replace directives intact

## Cross-session domain reset

Per brief: "After Phase B closes, your domain becomes 'Path A canary closed; ongoing external-adapter PR coordinator' — idle until the next external trigger."

Adjusted: domain stays as **"Path A inauguration owner; Phase B halted on type-identity blocker; awaiting kc/money promotion authorization."** Idle until orchestrator decides on Path B.alt-1 vs B.alt-4.

---

**End. Doc-only. No master mutations. No deploy-ready signal.**
