# ADR 0007: Canonical Cross-Language Plugin IPC

**Status**: Accepted (2026-04-27)
**Author**: kite-mcp-server architecture
**Decision drivers**: Cross-language plugin extensibility without
inverting the host's import graph; isolation of plugin failures from
the host process; sustainable contract for third-party plugin
authors; alignment with the language-fit evaluation finding (commit
`e84a8f4`) that subprocess RPC is the right vehicle for cross-
language extension.

---

## Context

`kite-mcp-server` has two parallel plugin patterns today:

1. **In-process register-on-import** (`mcp/plugin_registry.go`,
   ~691 LOC, ~114 `RegisterInternalTool(&...)` call sites). Plugins
   are Go packages compiled into the server binary; registration
   runs at startup. This is the path for first-party Go plugins
   where rebuild-the-binary is acceptable. The Plugin
   architecture-rubric dimension is at 100/100 on the strength of
   this pattern.

2. **Subprocess RPC via `hashicorp/go-plugin`**
   (`kc/riskguard/checkrpc/`, 216 LOC; host adapter in
   `kc/riskguard/subprocess_check.go`, 391 LOC; reference plugin in
   `examples/riskguard-check-plugin/main.go`). Plugins are
   independent binaries (potentially in any language). Communication
   is gob-over-stdio via Go's net/rpc. Crashes are isolated.

The first pattern has been formalised; the second has not. The
language-fit evaluation in `.research/go-irreducible-evaluation.md`
(commit `e84a8f4`) found that the subprocess RPC seam is the right
mechanism for cross-language plugin extension — superior to WASM
(100ms cold-start tax), superior to Go's `plugin.Open` (Linux/macOS
only, fragile build alignment), and complementary to in-process
register-on-import. The evaluation explicitly recommended
"promoting `kc/riskguard/checkrpc/` to a first-class IPC contract
that any subsystem can opt into."

This ADR ratifies that recommendation.

---

## Decision

The `kc/riskguard/checkrpc/` package is the **canonical
cross-language plugin IPC contract** for `kite-mcp-server`. New
plugin domains that need cross-language extension SHOULD follow the
pattern this package establishes: gob-over-stdio netRPC via
`hashicorp/go-plugin`, with handshake-protected magic cookies and
forward/backward-compatible wire types.

The pattern is documented in `kc/riskguard/checkrpc/README.md` §
"Adding a new plugin domain". The smoke-test discipline that
package establishes (`types_test.go`: gob round-trip,
forward-compat with truncated payloads, backward-compat with
extended payloads, handshake stability) is the canonical regression
suite for any new plugin domain.

Domain-specific RPC packages live alongside their host domain
(e.g., `kc/audit/audithookrpc/` if audit-hook plugins are added,
NOT inside `checkrpc/`). `checkrpc/` itself does NOT grow into a
generic-RPC pseudo-package; it stays the riskguard-Check wire
contract by design. The pattern is the canonical part, not any
single package's contents.

---

## Consequences

### Positive

- **Cross-language plugin extensibility** is now a documented,
  regression-tested pattern with a working reference
  implementation. A plugin author in any language that can speak
  netRPC over stdio can ship a riskguard Check today; future
  domains opt in by following the same pattern.
- **The Go-irreducible framing** raised in
  `.research/go-irreducible-evaluation.md` (Item #1, Plugin
  loader) is closed. The Plugin dimension at 100/100 is honest
  on BOTH axes: in-process registry for Go plugins AND
  cross-language subprocess RPC for everything else.
- **Failure isolation** is structural. A plugin crash, infinite
  loop, or memory leak cannot corrupt the host process; the worst
  case is one Evaluate returns an "unavailable" rejection and the
  host re-launches the subprocess on the next call.
- **Build/deploy independence**. Plugin binaries can be redeployed
  without rebuilding the server. Operators can ship custom Checks
  out-of-band of the main release cycle.
- **Wire-format discipline is testable**. The `types_test.go`
  contract makes accidental wire breakage surface at code-review
  time, not at customer sites.

### Negative

- **Latency cost**: each Evaluate adds ~1-2ms over localhost stdio.
  Acceptable for the pre-trade path (riskguard's 9 in-process
  checks add similar overhead per call) but NOT for tight inner
  loops (e.g. per-tick computations). Plugin domains that need
  sub-millisecond latency must stay in-process.
- **Operational surface**: subprocess plugins introduce process
  lifecycle concerns (launch, restart on crash, graceful shutdown,
  resource limits). The host adapter pattern in
  `subprocess_check.go` handles these; new plugin domains inherit
  the obligation to do the same.
- **Wire-version ceremony**: bumping `Handshake.ProtocolVersion`
  is a flag-day operation requiring every deployed plugin binary
  to be rebuilt. The discipline is documented; the cost is real.
- **gob-specific encoding**: `hashicorp/go-plugin`'s netRPC
  transport uses gob. Migrating to gRPC (which go-plugin also
  supports) would require a wire-format migration; the contract
  here ties us to the netRPC choice for as long as it's in place.

### Neutral

- The Plugin architecture-rubric dimension remains at 100/100. The
  scorecard footnote (`.research/scorecard-final.md` row 7,
  "Plugin") credits "universal `RegisterInternalTool` self-
  registration" as the closing rationale. This ADR adds the
  cross-language axis as a complementary rationale — not a score
  change, just a sharper articulation. The scorecard will be
  updated to reference both patterns.

---

## Rejected alternatives

### A1: WASM via `wazero` or `wasmtime-go`

WASM runtimes offer cross-language plugin loading with sandboxing
and cross-platform support (including Windows, where Go's
`plugin.Open` doesn't work).

**Rejected because**: cold-start latency in 2026 is ~100ms on
mainstream Go WASM runtimes — unacceptable for the order-placement
hot path. Reconsider in 2027+ if cold-start drops below 10ms AND
a third-party plugin marketplace becomes a real product surface.

### A2: Go's `plugin.Open` for dynamic .so loading

Go has a built-in `plugin` package that loads `.so` files at
runtime.

**Rejected because**: `plugin.Open` is Linux/macOS only (no
Windows support); plugin binaries must be built with the EXACT
same Go version + build tags + GOPATH layout as the host (any
drift = crash on load); not cross-language by design (only Go
plugins). The combination of fragility + platform limit + Go-only
makes it a worse choice than subprocess RPC for the cross-language
extension use case.

### A3: REST/HTTP microservice per plugin

Plugins as standalone HTTP services on localhost ports.

**Rejected because**: per-call overhead is dominated by HTTP/JSON
serialisation (~10-20ms) vs ~1-2ms for stdio gob; port management
and auth complicate operational story; plugin authors would need
to handle HTTP server boilerplate that `hashicorp/go-plugin.Serve`
hides. The HTTP path is reserved for plugins that are already
HTTP services for other reasons.

### A4: Generalising `checkrpc/` into a generic plugin RPC package

A `kc/pluginrpc/` package that defines a generic
`<T1, T2> Plugin[T1, T2]` interface and lets every plugin domain
parameterise on it.

**Rejected because**: Go's lack of higher-kinded types makes the
"generic" version more verbose than the per-domain pattern, NOT
less. Each plugin domain has different metadata methods (Name,
Order, RecordOnRejection for Checks; presumably different ones for
audit hooks or ticker sources) that don't generalise cleanly. The
pattern-as-canonical (this ADR's choice) preserves clarity at the
cost of a small per-domain duplication; the duplicated code is
~200 LOC and the duplication makes wire contracts independently
versionable.

---

## Validation

- **Reference plugin**: `examples/riskguard-check-plugin/main.go`
  (~120 LOC, including doc-comments). Compiles + runs against the
  current host.
- **Smoke tests**: `kc/riskguard/checkrpc/types_test.go` (6 tests,
  ~140 LOC) pin gob round-trip, forward-compat, backward-compat,
  handshake stability, dispense-key contract.
- **Integration tests**: `kc/riskguard/subprocess_check_test.go` (8
  tests, ~365 LOC) exercise the end-to-end host adapter:
  launch-on-missing-binary, stale-executable fallback, full
  evaluate round-trip, panic-in-plugin fails closed, concurrent
  evaluate is safe, reload reconnects, register on guard, config
  validation.
- **Reference doc**: `kc/riskguard/checkrpc/README.md` (~270 LOC)
  documents the contract surface, the "Adding a new plugin domain"
  pattern, the wire discipline, and the handshake flag-day rule.

---

## See also

- `kc/riskguard/checkrpc/README.md` — the canonical reference for
  the contract.
- `kc/riskguard/checkrpc/types_test.go` — the wire-contract
  regression suite.
- `kc/riskguard/subprocess_check.go` — the host adapter pattern.
- `examples/riskguard-check-plugin/main.go` — the reference
  plugin binary.
- `.research/go-irreducible-evaluation.md` (commit `e84a8f4`) —
  the language-fit evaluation that established subprocess RPC as
  the right cross-language plugin vehicle.
- ADR 0001 (broker port) — the other "canonical wire-typed
  boundary" pattern in this codebase. ADR 0007 generalises the
  same DTO discipline to a process-boundary contract.
- ADR 0006 (Fx adoption) — Phase 2 lifecycle hooks would let a
  subprocess plugin's lifecycle (start at boot, stop on shutdown)
  attach to `fx.Lifecycle` if desired. Not required by this ADR;
  noted for forward reference.
