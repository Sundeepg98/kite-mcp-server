# ADR 0009: IPC Contract Spec — JSON-RPC 2.0 over stdio

**Status**: Accepted (2026-04-28)
**Author**: kite-mcp-server architecture
**Decision drivers**:
- Cross-language plugin extensibility beyond riskguard, scoped against
  the empirical Tier-3 promotion-trigger matrix in
  `.research/fork-loc-split-and-tier3-promotion.md` (`d0e999d`)
  showing P(≥1 component promotes in 24mo) ≈ 31-40%.
- Need to unblock the `parallel-stack-shift-roadmap.md` (`8361409`)
  Foundation phase §1.1 deliverable so any future track activation
  is not bottlenecked on encoding-format selection.
- Asymmetric per-call constraints: Track C (Rust riskguard, 1ms p99
  latency hedge) and Track B (Python analytics, multi-MB payloads)
  have different optimal encodings; the spec must accommodate both
  without forcing a single answer that fits neither well.
- Backward compatibility with the canonical `kc/riskguard/checkrpc/`
  pattern (ADR 0007) — no flag-day migration of the existing gob
  consumer.

---

## Context

ADR 0007 (`docs/adr/0007-canonical-cross-language-plugin-ipc.md`,
shipped at `202b993`) canonicalized `hashicorp/go-plugin`-via-netRPC
over stdio as the cross-language plugin IPC contract. Its scope was
narrow: it ratified the existing `kc/riskguard/checkrpc/` pattern (gob
encoding, single domain) as canonical for new plugin authors.

Since ADR 0007 shipped, three pieces of context have moved:

1. **Tier-3 promotion-trigger matrix** (`d0e999d`) quantified the
   probability of cross-language component activation. P(zero
   promotions in 24mo) ≈ 31%; P(exactly 2) ≈ 19%; P(≥3) ≈ 12%.
   Foundation-phase IPC infrastructure pays off at the 2+ inflection.

2. **Stack-shift roadmap** (`8361409`) called Foundation §1.1 — an
   extended IPC contract spec covering wire format, schema, capability
   negotiation, lifecycle, cancellation, observability, versioning, and
   per-track contract subsets — as the gating sequential investment
   before any track can start.

3. **Empirical re-measurement** in `scorecard-final-v2.md` (`8361409`)
   showed `mcp/` is NOT thin transport (62% of tools have leaked
   business logic), changing the cost-shape of any track that would
   port mcp/-side code.

The `4fa5a39` IPC contract spec research deliverable
(`.research/ipc-contract-spec.md`, ~700 lines) drafted the extended
contract against the four candidates evaluated in ADR 0007's
language-fit research: protobuf+gRPC, JSON-RPC 2.0, MessagePack,
Cap'n Proto.

This ADR captures the verdict from `.research/ipc-contract-spec.md`
§1.3 so the wire-format decision is a stable reference point future
contributors can check against when adding cross-language consumers
beyond the existing `checkrpc/` pattern.

---

## Decision

**Adopt JSON-RPC 2.0 over stdio with optional JSON Schema
descriptors** as the wire format for new cross-language plugin
domains beyond `kc/riskguard/checkrpc/`. The existing gob-over-netRPC
path stays in place for the riskguard plugin domain (no flag-day
migration); new domains use JSON-RPC 2.0.

### What this means concretely

For any new cross-language plugin domain:

1. **Wire encoding**: JSON-RPC 2.0 framed messages, one per line
   (newline-delimited), over stdio. Request shape:
   `{"jsonrpc":"2.0","id":N,"method":"X","params":{...}}`. Response
   shape: `{"jsonrpc":"2.0","id":N,"result":{...}}` or
   `{"jsonrpc":"2.0","id":N,"error":{"code":N,"message":"...","data":{...}}}`.

2. **Schema discipline**: optional JSON Schema descriptors per method.
   Tracks that want compile-time validation (Python with `pydantic`,
   TypeScript with `zod`) opt in by registering `<method>.schema.json`
   alongside the method. Tracks that don't (Rust hot-path riskguard)
   stay schema-free.

3. **Capability negotiation**: handshake message exchanges supported
   methods + capabilities. Host filters method calls against the
   plugin's declared capabilities; plugins reject calls outside their
   declared set with JSON-RPC error code `-32601 (Method not found)`.

4. **Lifecycle**: process-per-plugin (matching `hashicorp/go-plugin`
   shape), reused across calls (no per-call boot tax). Graceful
   shutdown via JSON-RPC `shutdown` method. Crash isolation preserved.

5. **Cancellation**: per-method timeout + ctx cancellation propagated
   via JSON-RPC `$/cancelRequest` extension (LSP-style). Aborts the
   in-flight method on the plugin side.

6. **Observability**: optional `$/log` notification stream from plugin
   to host for structured log forwarding. Trace IDs threaded via
   `_meta` field on params.

7. **Versioning**: protocol version in handshake; semver-bounded
   plugin/host mismatch produces a clear startup error rather than
   a runtime mystery.

### Per-track contract subsets

Each track activates only the subset of the spec it needs:

| Track | Subset | Hot path |
|---|---|---|
| A (TS widgets / mcp/ port) | Full spec — schema, capabilities, observability | Per-tool-call; payload size moderate |
| B (Python analytics) | Full spec + JSON Schema for DataFrame slice validation | Per-analytics-call; payload up to multi-MB |
| C (Rust riskguard hedge) | Schema-free hot path; capabilities minimal | <1ms p99 budget; payload small (~200 bytes) |

### What stays canonical

The canonical part is `(stdio + RPC + handshake + capability discovery
+ schema discipline)` — NOT the specific encoding bytes. ADR 0007's
"pattern as canonical, not single-package" framing is preserved. gob
remains valid for the riskguard plugin domain; JSON-RPC 2.0 is the
default for new cross-language consumers.

---

## Why JSON-RPC 2.0 over the alternatives

The full evaluation lives in `.research/ipc-contract-spec.md` §1.1-1.3.
Summary:

| Format | Wire size | Schema | Codegen | Debuggability | Pattern fit |
|---|---|---|---|---|---|
| **gob** (status quo for riskguard) | ~30% smaller than JSON | Implicit (Go reflection) | None | Opaque (binary) | Exact — no migration |
| **Protobuf + gRPC** | Smallest (~2× smaller than JSON) | Strong (`.proto`) | Required (protoc + per-language plugins) | Opaque without `protoc --decode_raw` | NEW pattern — full migration cost |
| **JSON-RPC 2.0** | Largest (~2× protobuf) | JSON Schema (optional descriptor) | None | Trivial (`tee plugin.log` + `jq`) | NEW pattern but trivially adjacent |
| **MessagePack** | Mid (~30% smaller than JSON) | Implicit / by-convention | None for ad-hoc | Opaque without `msgpack-cli` | NEW pattern; toolchain less mature than JSON |
| **Cap'n Proto** | Smallest with zero-copy | Strong (`.capnp`) | Required | Opaque without `capnp decode` | NEW pattern; toolchain less mature than protobuf |

JSON-RPC 2.0 wins the codebase's actual constraint set — not because
it's universally best, but because:

1. **Zero codegen tax**. No `protoc`, no `.proto` source-of-truth
   alongside Go types, no per-language plugin configuration in CI.
2. **Agent-friendly debugging**. This codebase has heavy multi-agent
   development (per `MEMORY.md` standing rules). Agents that can
   `cat plugin.log | jq` while investigating a regression are
   dramatically more efficient than agents that need to install
   protoc and rebuild a parser. JSON's debuggability is the
   operational equalizer.
3. **Cross-runtime parity**. Mature, low-friction client libraries
   exist in Go (`net/rpc/jsonrpc` plus third-party), TypeScript
   (`json-rpc-2.0`), Python (built-in `json` plus light shim),
   Rust (`jsonrpsee`).
4. **Per-track per-call overhead is mitigatable**. Track C's 1ms p99
   budget survives via:
   - Subprocess reuse (no per-call process boot)
   - Compact schema (~200 bytes per Check)
   - Unix-socket fallback for stdio overhead reduction (deferred work
     per spec §11)
5. **Protobuf migration option preserved**. If Track B (Python
   analytics) ships multi-megabyte DataFrame slices and JSON parse
   becomes the bottleneck, protobuf can be added LATER as an
   alternative transport for that specific track without disturbing
   the JSON-RPC default. The spec's framing-vs-encoding split keeps
   this option open.

---

## Consequences

### What enables

1. **Foundation phase §1.1 unblocked**. Any future track activation
   has a stable spec to build against — no per-track encoding-format
   debate.
2. **Cross-language plugin extension beyond riskguard becomes
   expressible**. The spec covers what was previously domain-specific
   in `checkrpc/`.
3. **Trigger-condition checks become tractable**. ADR 0010 (the
   stack-shift deferral ADR) cites quantified triggers per track
   (paying-customer demand for second broker, sustained widget UX
   bottleneck, etc.). When a trigger fires, the team can start the
   track without re-evaluating wire format.
4. **Schema discipline opt-in path**. Tracks that benefit from
   compile-time validation (TS/Python) get it; Tracks that don't
   (Rust hot path) skip it without breaking compatibility.

### What stays constrained

1. **The status-quo `checkrpc/` gob path stays the in-process Go
   default** for backward-compat with existing plugin binaries. No
   flag-day migration. ADR 0007 remains in force for the riskguard
   plugin domain.
2. **Spec is draft until first cross-language consumer activates**.
   The detailed per-section design in `.research/ipc-contract-spec.md`
   is provisional; first activation will surface the gaps. Deferred
   work explicitly listed in spec §11 (Unix-socket transport,
   bidirectional streaming, multiplexed methods, structured tracing).
3. **No reference implementation shipped**. This ADR ratifies the
   wire-format choice. Concrete implementation lands when first
   track activates per ADR 0010's trigger conditions.

### What is rejected

1. **Protobuf+gRPC as default**. Codegen tax + opacity + adjacent
   tooling outweigh the wire-size win at current and projected scale.
   Available later as per-track alternative transport if Track B's
   payloads demand it.
2. **MessagePack as default**. Marginal wire-size win over JSON,
   adds opacity, less mature TS/Python/Rust ecosystems than JSON-RPC.
3. **Cap'n Proto as default**. Zero-copy gains are dominated by very
   large payloads we don't currently send and don't project sending
   in the 24-month horizon.
4. **Single global spec for ALL plugin domains including riskguard**.
   Re-encoding the existing gob `checkrpc/` consumer would be a flag-
   day rewrite with no behavior change. Punted indefinitely; the
   per-track subset framing accommodates the divergence.

---

## Trigger conditions for revisiting

Per `parallel-stack-shift-roadmap.md` §10 and `feedback_decoupling_denominator.md`'s
three-axis ROI framework, this ADR is revisited when ANY of:

1. **Track activates**. First cross-language plugin domain beyond
   riskguard ships and surfaces a spec gap. Update spec; if the gap
   requires wire-format change, supersede this ADR.
2. **Payload size pressure**. Any track ships multi-MB payloads on
   per-call hot paths AND JSON parse exceeds 5% of call latency.
   Add per-track protobuf transport without changing default.
3. **Latency pressure**. Any track ships sub-1ms p99 latency
   requirement AND JSON encode/decode exceeds the budget.
   Investigate Unix-socket transport (spec §11 deferred item) before
   considering wire-format change.
4. **Schema drift**. Two-plus tracks active; spec evolution requires
   coordination across language clients. Add formal schema-bumping
   process (semver-bounded `protocolVersion` in handshake).

If none of the above fire within 24 months, this ADR holds. Per the
Tier-3 promotion-trigger matrix (`d0e999d`), expected triggers within
24mo: 0-1 across all four conditions, weighted ~31% probability of
zero triggers.

---

## References

- `.research/ipc-contract-spec.md` (`4fa5a39`) — full ~700-line spec
  draft this ADR distills
- `docs/adr/0007-canonical-cross-language-plugin-ipc.md` (`202b993`) —
  canonical pattern this spec extends; remains in force for riskguard
- `kc/riskguard/checkrpc/types.go` (216 LOC) — existing wire contract
  reference implementation; provides forward/backward-compat test
  pattern that translates to JSON-RPC 2.0
- `.research/parallel-stack-shift-roadmap.md` (`8361409`) — Foundation
  phase §1.1 brief that scoped this spec; track-by-track subset
  alignment in §2-4
- `.research/fork-loc-split-and-tier3-promotion.md` (`d0e999d`) —
  per-component promotion triggers + 24-month probability matrix
- `.research/scorecard-final-v2.md` (`8361409`) — empirical
  re-measurement; `mcp/` 62%-leaked-business-logic finding informed
  Track A subset
- `feedback_decoupling_denominator.md` — three-axis ROI framework
  (user-MRR / agent-concurrency / tech-stack-portability)
- ADR 0010 (next) — stack-shift deferral; cites this ADR's
  trigger-conditions framework
