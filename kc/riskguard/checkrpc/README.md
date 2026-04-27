# `kc/riskguard/checkrpc` — canonical cross-language plugin IPC

This package is the **canonical IPC contract** for cross-language
plugins in `kite-mcp-server`. It is small (one Go file, ~216 LOC) by
design — every byte is part of a wire contract that plugin binaries
in any language can target.

The contract is `hashicorp/go-plugin` over `net/rpc` (gob over stdio).
A subprocess plugin built against this contract is launched by the
host, dispenses a typed proxy, and serves RPC calls until the host
closes the connection. Crashes are isolated: a plugin panic surfaces
as a broken pipe to the host, which marks the subprocess dead and
relaunches on the next call.

The first consumer is **riskguard subprocess Checks** — third-party
pre-trade safety rules that run as separate binaries. The contract
generalises naturally to any plugin domain (audit hooks, alternate
ticker sources, analytics kernels) where a process boundary buys
isolation, language flexibility, or both.

---

## When to use this contract

Use the subprocess RPC contract when ANY of the following hold:

- The plugin will be authored in a non-Go language (Rust, Python,
  TypeScript via Bun, etc.). Any language that can produce a
  binary speaking netRPC over stdio is eligible.
- The plugin's failure modes (panics, infinite loops, memory leaks)
  must NOT be able to corrupt the host process.
- The plugin needs OS-level isolation (cgroups, Windows Job Objects,
  seccomp, distinct user account) for regulatory / auditability
  reasons.
- The plugin's build, deploy, or rebuild cycle must be independent
  of the host's. Subprocess plugins can be redeployed without
  rebuilding the server binary.

For in-process Go plugins where none of the above apply, use the
in-process registry pattern in `mcp/plugin_registry.go` (universal
across the tool surface, ~114 self-registration call sites today).
That registry is preferred for first-party Go plugins where
register-on-import is acceptable; this RPC contract is preferred
for everything else.

---

## Architecture

```
┌──────────────────────────┐                ┌─────────────────────────┐
│  kite-mcp-server (host)  │   stdio +      │  plugin binary          │
│                          │   netRPC       │  (any language)         │
│  riskguard.Guard         │ ◄─────────────►│                         │
│   └─> SubprocessCheck    │   gob over     │  e.g.                   │
│        └─> CheckRPC ─────┼───►  pipe ─────┼──► riskguard-check-     │
│                proxy     │                │       plugin (Go)       │
│                          │                │                         │
└──────────────────────────┘                └─────────────────────────┘
       host imports                                plugin imports
       this package                                this package
       to dial                                     to serve
```

The host (riskguard) imports this package to:

- Drive the dial side: launch the subprocess via
  `hashicorp/go-plugin.Client`, dispense the proxy via
  `DispenseKey`, call `Evaluate` for each pre-trade event.

The plugin binary imports this package to:

- Implement the `CheckRPC` interface.
- Wrap the implementation in `CheckPlugin{Impl: ...}`.
- Call `hashicorp/go-plugin.Serve` with `Handshake` + `PluginMap`.

Both sides import the SAME `Handshake`, `PluginMap`, `DispenseKey`,
and wire structs (`OrderCheckRequestWire`, `CheckResultWire`) from
this package. Any drift between host and plugin views of those types
is a wire-format break that this package makes structurally
impossible: there is exactly one source of truth.

---

## Adding a new plugin domain

The current contract is specialised to riskguard pre-trade Checks.
To add a new plugin domain (e.g. an audit-hook plugin or a custom
ticker-source plugin), follow this pattern:

1. **Create a sibling package** alongside `checkrpc/`. Suggested
   naming: `kc/<domain>/<domain>rpc/` (e.g.
   `kc/audit/audithookrpc/`, `kc/ticker/tickersourcerpc/`).
2. **Define wire structs** for the domain's request and response.
   Keep them in `types.go` with field-by-field documentation. Use
   exported fields, no struct tags (gob ignores tags), conservative
   field-addition discipline (forward-compat: new fields land at
   the end and default to zero on old plugins).
3. **Define the RPC interface** the plugin binary implements
   (mirror of `CheckRPC` for your domain).
4. **Define the netRPC adapters** — Server (plugin side) and Client
   (host side) wrappers that bridge the interface to net/rpc's
   `Method(args, reply) error` shape. Mirror `CheckRPCServer` and
   `CheckRPCClient`.
5. **Define the `plugin.Plugin` adapter** wrapping the RPC interface.
   Mirror `CheckPlugin`.
6. **Define `Handshake`, `PluginMap`, `DispenseKey`** as package
   constants. Use a domain-specific magic cookie (NOT
   `KITE_RISKGUARD_CHECK_PLUGIN` — collisions cause a plugin to
   accept calls from the wrong host).
7. **Mirror the smoke-test discipline** in this package:
   `types_test.go` with gob round-trip, forward-compat (old payload
   into current type), backward-compat (future payload into current
   type), and handshake stability.
8. **Ship a reference plugin** in `examples/<domain>-plugin/main.go`.
   The current example at `examples/riskguard-check-plugin/main.go`
   is the template — fork it.
9. **Document the domain in this README** (add a row to the
   "Active plugin domains" table below) AND link from the
   referencing ADR (currently ADR 0007).

The host adapter (the `SubprocessCheck` analogue) lives in the
domain's own package, NOT in `checkrpc/`. This package stays a pure
wire-types package with zero domain knowledge — its only job is the
contract surface.

---

## Active plugin domains

| Domain | Wire pkg | Host adapter | Reference plugin |
|---|---|---|---|
| **Riskguard pre-trade Check** | `kc/riskguard/checkrpc` (this package) | `kc/riskguard/subprocess_check.go` | `examples/riskguard-check-plugin/main.go` |

Future entries in this table indicate the contract has been adopted
by additional plugin domains. The pattern shown in §"Adding a new
plugin domain" is the canonical onboarding path.

---

## Wire discipline

The wire types are gob-serialised at the host ↔ subprocess boundary.
gob is forgiving in some directions and strict in others. The
discipline below prevents silent breakage:

- **Field additions are SAFE** — new fields land at the end with
  conservative defaults; old plugin binaries see zero values for
  unknown fields. `TestOrderCheckRequestWire_ForwardCompat` pins
  this property.
- **Unknown-field tolerance is SAFE** — gob silently drops fields
  the receiver doesn't recognise. A future plugin can add fields
  the host doesn't know about and the host will still decode the
  parts it does know. `TestOrderCheckRequestWire_BackwardCompat`
  pins this.
- **Field RENAMES are BREAKING** — gob keys decoding by field name.
  Renaming `Tradingsymbol` to `Symbol` makes every existing plugin
  binary deliver garbage. If you must rename, bump
  `Handshake.ProtocolVersion` and treat as a flag-day migration.
- **Type CHANGES are BREAKING** — changing `Quantity int` to
  `Quantity int64` makes gob raise a type-mismatch error. Same
  flag-day rule as renames.
- **REORDERING fields is SAFE** — gob is name-keyed, not
  position-keyed.
- **Unexported fields are INVISIBLE** to gob and MUST NOT carry
  contract-relevant state. If you need internal helper fields,
  put them in a separate non-wire struct.
- **Tagged fields are IGNORED** — `json:"foo"` and `gob:"-"` tags
  on these wire types do NOT affect gob behaviour (gob doesn't
  read struct tags). Don't add tags expecting them to do anything.

`types_test.go` enforces the contract; CI fails on any drift.

---

## The handshake — a flag-day rule

`Handshake.ProtocolVersion` is the integer version both sides agree
on. Every plugin binary AND the host both declare the same value.
A mismatch surfaces at connect time as "not our plugin" and the
host refuses to dispatch.

To bump the protocol:

1. Update `Handshake.ProtocolVersion` here.
2. Rebuild every plugin binary in production AND every plugin
   binary in third-party deployments — they will not work against
   the new host until rebuilt.
3. Document the break in `CHANGELOG.md` and the relevant ADR.
4. Update `TestHandshake_StableProtocol` to expect the new value.
5. Coordinate the rollout — a host with the new version cannot
   talk to plugins on the old version, and vice versa.

This is intentionally a high-friction operation. The smoke test
in `types_test.go` makes accidental bumps visible at code-review
time.

---

## See also

- `kc/riskguard/subprocess_check.go` — the host adapter that drives
  the contract end-to-end (launch, dispense, evaluate, isolation,
  reload, panic recovery).
- `examples/riskguard-check-plugin/main.go` — the reference plugin.
  Fork this when authoring a new Check.
- `docs/adr/0007-canonical-cross-language-plugin-ipc.md` — the ADR
  that ratifies this contract as the canonical pattern for
  cross-language plugin extension.
- `.research/go-irreducible-evaluation.md` — the language-fit
  evaluation (commit `e84a8f4`) that established subprocess RPC
  as the right answer for cross-language plugins (vs WASM, vs
  Go's `plugin.Open`, vs in-process register-on-import).
