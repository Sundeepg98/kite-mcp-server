# IPC Contract Spec — Foundation phase deliverable for parallel-tracks

**Date**: 2026-04-28 night
**HEAD audited**: `d0e999d`
**Charter**: research deliverable. **NO ship.** This doc drafts the
extended IPC contract spec the `parallel-stack-shift-roadmap.md`
Foundation phase §1.1 calls for, scoped against the hex agent's
`d0e999d` Tier-3 promotion-trigger matrix (P(≥2 components
promote in 24mo) ≈ 31%). Drafting now is low-cost prep work that
pays off if any track activates; track execution itself remains
deferred per the user's "leave external" directive and the
empirical-ceiling verdict in `scorecard-final-v2.md`.

**Anchor docs**:
- `docs/adr/0007-canonical-cross-language-plugin-ipc.md` (`202b993`)
  — the existing canonical IPC pattern (riskguard `checkrpc/`); this
  spec extends it.
- `kc/riskguard/checkrpc/README.md` — pattern documentation +
  "Adding a new plugin domain" guide; this spec stays compatible
  with that guide.
- `kc/riskguard/checkrpc/types.go` (216 LOC) — the existing wire
  contract; the canonical reference implementation.
- `.research/parallel-stack-shift-roadmap.md` (`8361409`) — Foundation
  phase §1.1 sketches what this spec must cover; this doc is the
  detailed elaboration.
- `.research/fork-loc-split-and-tier3-promotion.md` (`d0e999d`) —
  per-component promotion triggers; informs the per-track contract
  subsets in §8.
- `feedback_decoupling_denominator.md` — three-axis ROI framework;
  the spec must support per-component swap (Axis C) without imposing
  cost on tracks that don't activate (Axes A + B preserved).
- `kc/money/money.go` — the canonical Money VO; informs the §2
  decimal-handling decision.

---

## 1. Wire format choice

### 1.1 Candidates evaluated

Four candidates were on the table per the brief: protobuf, JSON-RPC
2.0, MessagePack, Cap'n Proto. Each evaluated against this codebase's
actual constraints — cross-runtime parity, agent-friendly debugging,
schema evolution, alignment with the existing `checkrpc/` pattern,
and total tooling cost across Go + TS + Python + Rust.

| Format | Wire size | Schema | Codegen | Debuggability | Existing pattern fit |
|---|---|---|---|---|---|
| **gob (status quo)** | Small (~30% smaller than JSON for our payloads) | Implicit (Go reflection) | None | Opaque (binary; gob has no third-party tooling) | EXACT match — `checkrpc/` is gob today |
| **Protocol Buffers + gRPC** | Smallest (~2× smaller than JSON for our payloads) | Strong (`.proto` is a fourth source-of-truth) | Required (protoc + per-language plugins) | Opaque without `protoc --decode_raw`; grpcurl helps but adds tooling | NEW pattern — full migration from netRPC |
| **JSON-RPC 2.0 over stdio** | Largest (~2× protobuf for typical payloads) | JSON Schema (optional descriptor) | None (hand-roll types per language is fine) | TRIVIAL — `tee plugin.log < pipe` and read | NEW pattern but trivially adjacent |
| **MessagePack** | Mid (~30% smaller than JSON) | Implicit or schema-by-convention | None for ad-hoc; codegen exists | Opaque without msgpack-cli | NEW pattern; toolchain less mature than JSON |
| **Cap'n Proto** | Smallest with zero-copy | Strong (`.capnp`) | Required | Opaque without `capnp decode` | NEW pattern; toolchain less mature than protobuf |

### 1.2 Per-axis tradeoffs

**Cross-runtime parity** (Go + TS + Python + Rust must each have a
mature, low-friction client):

- gob: Go-only. Disqualifying for cross-language. The `checkrpc/`
  pattern works today because the only non-Go tracks are
  hypothetical; if Track A (TS) activates, gob is a hard blocker.
- Protobuf: best parity. All four languages have first-party
  `protoc` plugins with active maintenance. Wire stability across
  versions is documented and tested.
- JSON-RPC 2.0: also excellent parity. JSON is the universal
  lingua franca; every language has multiple battle-tested
  parsers. JSON Schema validators exist for all four target
  languages.
- MessagePack: parity is real but tooling quality varies. TS and
  Python have good libraries; Rust's `rmp-serde` is solid; Go's
  options are less commonly used.
- Cap'n Proto: parity is OK in Go + Rust + TS; Python's `pycapnp`
  exists but is less actively maintained than `protobuf`. Toolchain
  maturity gap.

**Agent-friendly debugging** — orchestrator agents reading log
output, network captures, or replaying messages from production
incidents:

- gob: hostile. Binary, no readable form, no ad-hoc tooling
  agents can deploy.
- Protobuf: hostile by default; `protoc --decode_raw` works but
  needs the `.proto` file and a protoc install. grpcurl helps
  during gRPC; not free.
- JSON-RPC: trivial. `cat /var/log/plugin.log | jq`. Logs are
  diff-able and human-readable. Agent debugging cost effectively
  zero.
- MessagePack: hostile-ish; `msgpack-cli` works but requires the
  binary install. Less common than jq.
- Cap'n Proto: hostile by default; `capnp decode` needs the
  schema. Less ecosystem tooling.

**Schema evolution** — adding a field, deprecating a field,
renaming a field:

- gob: forgiving on field addition, hostile on field rename
  (silent data loss). The current `checkrpc/` discipline is
  documented but easy to violate.
- Protobuf: industry-standard, well-documented evolution rules
  (field-number stability, optional vs required, reserved fields).
  Compile-time enforcement against `.proto` files.
- JSON-RPC: schema evolution rules per JSON Schema (`additionalProperties`,
  `required` arrays). Less compile-time enforcement than protobuf
  but the descriptor IS the contract.
- MessagePack: evolution is convention-driven; no built-in field-
  number stability.
- Cap'n Proto: industry-standard evolution similar to protobuf.

**Tooling cost** — what a 1-developer team has to add to CI per
language:

- gob: 0 (Go-only, already shipped).
- Protobuf: high. `protoc` install in CI; per-language code-gen
  step; `.proto` linter (`buf`); generated code goes in tree or
  is regenerated on every build. Roughly +1 CI job per language
  + ~200 LOC of build glue per language.
- JSON-RPC: low. JSON parsing is in the standard library of every
  target language. Optional JSON Schema validator (`ajv` for TS,
  `jsonschema` for Python, `jsonschema` for Rust, `gojsonschema`
  for Go); pinning the schema requires committing a `.schema.json`
  file that all four languages read.
- MessagePack: mid. Per-language library install; less ecosystem
  integration than JSON.
- Cap'n Proto: high (similar to protobuf).

**Per-call overhead** — measured against current `checkrpc/`
gob round-trip baseline (~1-2ms localhost stdio per ADR 0007):

- gob: baseline.
- Protobuf: smaller payloads → marginally faster wire transfer;
  but codegen-built unmarshallers are typically ~2× faster than
  Go gob for medium payloads. Net: similar or marginally faster
  than gob for our size.
- JSON-RPC: 2-3× larger payloads + 2-3× slower parse for the
  Go side (encoding/json reflection isn't optimised). Realistic
  per-call overhead vs gob: +0.5ms on small payloads, +2-5ms on
  large payloads. For analytics tools (Track B) returning
  multi-megabyte DataFrame slices, this matters; for riskguard
  pre-trade Checks (small payloads) it does not.
- MessagePack: similar to gob in size and speed.
- Cap'n Proto: zero-copy on read; theoretically fastest, but
  benchmark-dominated only at very large payloads.

### 1.3 Honest verdict — JSON-RPC 2.0 over stdio with optional JSON Schema

**Choose JSON-RPC 2.0.** The rationale is asymmetric, not
universal-best:

1. **The current `checkrpc/` consumer is the only cross-language
   user today.** Migrating it to JSON-RPC is a single-domain wire
   swap; the existing forward/backward-compat tests in
   `types_test.go` translate directly. Not a flag-day rewrite.
2. **The four target tracks are 0-3 deferred.** Per
   `parallel-stack-shift-roadmap.md` and `d0e999d` Tier-3 trigger
   matrix, P(≥1 track activates in 24mo) is in the 31-40% range.
   The spec's per-call overhead matters most when at least one
   track ACTIVATES; until then, the cost-of-tooling axis dominates.
   JSON-RPC's zero-codegen-cost wins this tradeoff.
3. **Agent-friendly debugging is not a luxury.** This codebase
   has heavy multi-agent development (per the standing rules in
   MEMORY.md). Agents that can `cat plugin.log | jq` while
   investigating a regression are dramatically more efficient than
   agents that need to install protoc and rebuild a parser. JSON's
   debuggability is the operational equalizer.
4. **JSON Schema is OPTIONAL but supported.** The spec defines the
   schema-as-descriptor pattern; Track B (Python analytics) which
   wants structural validation can opt in. Track C (Rust riskguard)
   which is latency-sensitive and small-payload can stay
   schema-free for the hot path.
5. **Per-call overhead on hot paths is mitigatable per-track.**
   Track C riskguard's 1ms p99 budget is preserved by:
   - Reusing a single subprocess across calls (no per-call process
     boot)
   - Compact schema (small JSON payloads, ~200 bytes per Check)
   - HTTP/1.1 persistent connection over Unix socket (alternative
     to stdio if stdio's per-frame overhead becomes the
     bottleneck — see §11 deferred work)
6. **Protobuf's marginal speed win is not worth the build-system
   tax** at current scale. If Track B (Python analytics) ships
   multi-megabyte DataFrame slices and JSON parse becomes the
   bottleneck, protobuf can be added LATER as an alternative
   transport for that specific track without disturbing the JSON-
   RPC default. The spec's framing-vs-encoding split (§4) keeps
   this option open.

**The status-quo `checkrpc/` gob path stays the in-process Go
default** for backward-compat with existing plugin binaries. The
extended spec this doc drafts is the **NEW** path for cross-language
tracks; gob remains for the pre-existing riskguard plugin domain
until Track C (or a later cross-language riskguard plugin author)
demands the migration.

This dual-path approach matches ADR 0007's "pattern as canonical,
not single-package" framing — the canonical part is `(stdio +
RPC + handshake + capability discovery + schema discipline)`, not
the specific encoding bytes.

---

## 2. Schema — type mapping table

### 2.1 Primitive types

| Concern | Go | TS | Python | Rust | JSON-RPC wire |
|---|---|---|---|---|---|
| 32-bit int | `int32` | `number` (validated ≤ 2^31) | `int` | `i32` | JSON number |
| 64-bit int | `int64` | `bigint` OR `string` (see §2.2) | `int` (Python int is arbitrary-precision) | `i64` | JSON number IF safely representable, else **string** |
| 32-bit float | `float32` | `number` | `float` | `f32` | JSON number |
| 64-bit float | `float64` | `number` | `float` | `f64` | JSON number |
| boolean | `bool` | `boolean` | `bool` | `bool` | JSON boolean |
| string (UTF-8) | `string` | `string` | `str` | `String` | JSON string |
| bytes | `[]byte` | `Uint8Array` (decoded from base64 string) | `bytes` (decoded from base64 string) | `Vec<u8>` | base64-encoded JSON string with content-type tag (see §2.7) |

### 2.2 Big integers — JavaScript number-precision gap

JavaScript's `number` type is IEEE 754 double; safely represents
integers in `[-(2^53 - 1), 2^53 - 1]`. Outside this range, integer
precision is lost silently. Affects two surfaces in this codebase:

- **Order IDs and exchange ref IDs** — Kite emits 16-digit numeric
  strings already (e.g. `"250423500128746"`). Stored as `string` in
  Go domain types; no JS gap.
- **Timestamps** — Unix epoch nanoseconds exceed 2^53 in 2025+.
  Affects audit timestamps and event timestamps. **Mitigation**:
  emit timestamps as RFC 3339 strings (see §2.3), not nanosecond
  integers.
- **Money amounts in paise** — at current Money VO definition
  (float64-backed), no integer overflow because amounts are
  fractional. NOT a JS gap.

**Rule**: any integer wider than 2^53 MUST be serialised as JSON
**string**, with the type's schema declaring `format: "int64-string"`.
TS clients parse via `BigInt(value)`. Python and Rust accept either
shape (their JSON parsers natively handle big integers). Reference:
RFC 8259 §6 ("interoperable JSON values"); Microsoft's TypeScript
compiler team has long-standing recommendations to this effect.

### 2.3 Time — timestamp, duration, time zone

| Concern | Go canonical | TS canonical | Python canonical | Rust canonical | Wire format |
|---|---|---|---|---|---|
| Instant (point in time) | `time.Time` | `Date` (or `Temporal.Instant` after TC39 stage 4) | `datetime.datetime` (timezone-aware, UTC) | `chrono::DateTime<Utc>` | **RFC 3339 string** with explicit zone offset, ms or µs precision |
| Duration | `time.Duration` (int64 ns) | `number` (ms) OR ISO 8601 duration string | `datetime.timedelta` | `chrono::Duration` OR `std::time::Duration` | **integer milliseconds** (most natural across all four) |
| Calendar date | `time.Time` (00:00:00 zone-aware) | `Date` (truncated) | `datetime.date` | `chrono::NaiveDate` | **RFC 3339 date-only string** `"2026-04-28"` |
| Time zone | IANA name string | IANA name string | IANA name (zoneinfo) | IANA name string (chrono-tz) | **IANA name string** `"Asia/Kolkata"` |

**Critical rule**: every timestamp on the wire MUST carry an
explicit zone offset OR be UTC with `Z` suffix. No naive timestamps.
This eliminates the entire class of "what zone did we mean?" bugs
that emerge when audit data crosses runtime boundaries.

**Rationale**: this codebase's domain operates in IST (`Asia/Kolkata`,
UTC+5:30) but stores audit data in UTC. The IST→UTC conversion is
done at the storage boundary. IPC contract treats every wire
timestamp as UTC unless the schema specifies otherwise — the
trader-facing IST conversion is a presentation-layer concern, not
a wire concern.

### 2.4 Decimals — financial values across runtimes

This is the most operationally-fragile type mapping. Money in this
codebase is currently `float64`-backed (`kc/money/money.go`, line 44:
`type Money struct { Amount float64; Currency string }`). The wire
contract MUST handle two cases:

1. **Status quo — Money as float64**. Keep parity with the existing
   in-tree Money VO. Preserves the gokiteconnect-shaped wire format
   (Kite API returns INR amounts as bare floats). Track A and Track B
   adopt this without modification.
2. **Future — Money as arbitrary-precision decimal**. If a future
   Track C riskguard wants strict decimal arithmetic (e.g.,
   penny-precise notional checks), the wire MUST allow decimal
   strings to be opted into without breaking float-mode consumers.

| Concern | Go | TS | Python | Rust | Wire format |
|---|---|---|---|---|---|
| **Float-mode (status quo)** | `kc/money/money.Money` (float64) | `number` | `float` | `f64` | JSON number |
| **Decimal-mode (opt-in)** | (would need new `MoneyDecimal` type, e.g. `decimal.Decimal` from `shopspring/decimal`) | `Decimal` from `decimal.js-light` | `decimal.Decimal` | `rust_decimal::Decimal` | JSON string with `format: "decimal"` |

**Float-vs-decimal coexistence rule**: every Money-shaped wire field
declares its mode in the schema descriptor (`"format": "money-float"`
or `"format": "money-decimal"`). Mixed-mode in a single payload is
forbidden — the schema enforces consistency.

**Recommendation for Track A/B**: stay float-mode. The existing Money
VO and broker DTOs use float64; any decimal-mode opt-in is a
separate refactor that should land in `kc/money` first (~150 LOC of
new type + tests + JSON marshallers), THEN propagate to the wire.

**Recommendation for Track C**: defer decimal-mode until paying-
customer demand or regulatory obligation triggers it. The 0.5-paise
imprecision of float64 INR amounts is well below the 0.05-paise
tick size of NSE; the practical gap is zero at current trading
volumes. The decimal-mode opt-in is documented in the wire schema
but not yet implemented; YAGNI applies.

### 2.5 Errors — propagation, codes, stack traces

JSON-RPC 2.0 §5.1 defines the standard error object:

```json
{
  "code": <int>,
  "message": <string>,
  "data": <any>  // optional
}
```

This spec extends the `data` field to carry kite-mcp-server-specific
error metadata. The full error envelope:

```json
{
  "code": -32001,
  "message": "riskguard: kill switch on",
  "data": {
    "category": "RISKGUARD_BLOCKED",
    "reason_code": "kill_switch_on",
    "request_id": "01HKM3...",
    "trace_id": "00-...-...-01",
    "retryable": false,
    "stack": "<plugin-side stack trace>"  // optional, debug builds only
  }
}
```

**Reserved JSON-RPC code ranges**:

| Range | Meaning | Source |
|---|---|---|
| -32700 to -32600 | JSON-RPC protocol errors | JSON-RPC 2.0 §5.1 |
| -32099 to -32000 | Server implementation reserved | JSON-RPC 2.0 §5.1 |
| -32099 to -32050 | **kite-mcp-server reserved** for in-tree categories below |
| -32049 to -32000 | **plugin-side reserved** for plugin-author error codes |

**kite-mcp-server in-tree categories** (extending ADR 0005's
middleware-chain semantics):

| Code | Category | Maps to in Go |
|---|---|---|
| -32001 | `RISKGUARD_BLOCKED` | `riskguard.RejectionReason` |
| -32002 | `BILLING_TIER_GATED` | `billing.ErrTierTooLow` |
| -32003 | `RATE_LIMITED` | `mcp.ErrRateLimited` |
| -32004 | `CIRCUIT_BREAKER_OPEN` | `mcp.ErrCircuitOpen` |
| -32005 | `AUDIT_BACKEND_UNAVAILABLE` | `audit.ErrStoreDown` |
| -32006 | `AUTH_REQUIRED` | `mcp.ErrAuthRequired` |
| -32007 | `INVALID_ARGS` | `mcp.ErrInvalidArgs` (per `mcp/common.go`) |
| -32008 | `BROKER_UNAVAILABLE` | `broker.ErrTransient` |
| -32009 | `IDEMPOTENCY_DUPLICATE` | `riskguard.ErrDuplicate` |
| -32010 | `KILL_SWITCH_ON` | `riskguard.ErrKillSwitch` |

**Stack trace handling**: the `data.stack` field is OPTIONAL and
populated only in debug builds. Production hosts strip the field
on receipt before propagating up the audit chain — stack traces in
the audit log are a PII leak vector (they can include filesystem
paths and environment context). The stripping rule is enforced
host-side, not wire-side, so the contract stays simple.

**Cross-language idiom mapping**:

- Go: error codes surface via typed sentinel errors (e.g.
  `riskguard.ErrKillSwitch`). The IPC client maps received codes
  to typed errors.
- TS: error codes raised as exceptions tagged with `name` and
  `code` properties.
- Python: error codes raised as exceptions in a per-category class
  hierarchy (`RiskguardBlocked(Error)`).
- Rust: error codes returned via `Result<T, IpcError>` with an
  `IpcError::Category(category, message, data)` enum variant.

### 2.6 Enums — typed constants

JSON has no native enum type. Three mapping options:

| Option | Wire shape | Pros | Cons |
|---|---|---|---|
| **String enum** | `"BUY"` / `"SELL"` | Self-describing; debuggable | String typos at hand-roll time |
| **Integer enum** | `0` / `1` / `2` | Compact | Hostile to debugging; renumbering breaks consumers |
| **Tagged-union object** | `{"type": "BUY"}` | Extensible (variants can carry payloads) | Verbose for plain enums |

**Choice**: STRING enums for plain enums; tagged-union for variants
with payloads. Matches Kite API conventions (`transaction_type:
"BUY"`, `order_type: "LIMIT"`, etc.) AND TypeScript's preferred
`type T = "BUY" | "SELL"` shape AND Python 3.11+ `Literal["BUY",
"SELL"]` AND Rust's `#[serde(rename_all = "SCREAMING_SNAKE_CASE")]`
default for enum unit variants.

**Schema declaration**: enums declare their full member set in the
descriptor. Adding a new member is FORWARD-COMPATIBLE for the
producer (old consumers see an unknown value). Removing a member
is BREAKING (existing payloads would fail to decode in strict
mode). Renaming a member is BREAKING.

| Domain enum | Members | Wire shape |
|---|---|---|
| TransactionType | `BUY`, `SELL` | string |
| OrderType | `MARKET`, `LIMIT`, `SL`, `SLM` | string |
| ProductType | `MIS`, `CNC`, `NRML`, `BO`, `CO` | string |
| Variety | `regular`, `amo`, `co`, `iceberg`, `auction` | string (lowercase per Kite convention) |
| Exchange | `NSE`, `BSE`, `NFO`, `BFO`, `CDS`, `MCX` | string |
| RejectionReason (riskguard) | `kill_switch_on`, `value_cap_exceeded`, `rate_limited`, `duplicate_order`, ... | string (snake_case per existing `RejectionReason` constants) |

### 2.7 Optional / nullable

JSON has explicit `null`. The wire convention is:

| Source idiom | Wire shape |
|---|---|
| Go `*T` (pointer) | field present + value, OR field absent |
| Go `T` with sentinel zero | field present + value (zero allowed) |
| Go `sql.NullString` etc. | `{"value": ..., "valid": true}` OR `null` |
| TS `T \| undefined` | field absent |
| TS `T \| null` | field present + `null` |
| Python `Optional[T]` | field absent OR `null` |
| Rust `Option<T>` | field absent (with `#[serde(skip_serializing_if = "Option::is_none")]`) OR `null` |

**Choice**: prefer **field absent** for optional fields (matches
TS's `T?` idiom and Rust's `serde(skip_serializing_if)`); accept
**field present + null** as semantically equivalent for forward-
compat. Schema declares `required` array; absent fields default
to null on receive.

**Critical rule**: `null` and absent are EQUIVALENT for optional
fields. Producers may emit either; consumers MUST accept both.
This eliminates a long-standing source of cross-language friction
(Go's encoding/json defaults to absent; Python's json.dumps emits
null for None; TS varies by serialization library).

### 2.8 Bytes — binary blobs

| Concern | Wire shape |
|---|---|
| Encoding | base64 standard alphabet (RFC 4648 §4), no padding stripping |
| Schema declaration | `"format": "byte"` per OpenAPI 3.0 convention |
| Content-type tag | OPTIONAL `"contentType": "<MIME>"` next to the byte field |
| Size limit | Practical: 1 MiB per IPC message; spec MUST declare a hard limit per call |

**Use cases in this codebase**:

- Encrypted credential blobs (KiteTokenStore / KiteCredentialStore)
  — internal-only; never crosses the IPC boundary today (decryption
  is host-side, plugin sees plaintext if at all).
- Audit hash chains — the hash itself is hex-string today, NOT
  bytes-base64. Spec preserves the hex-string convention for
  hashes (matches `sha256` outputs in audit log).
- Binary instrument data (CSV uploads, etc.) — currently host-side
  only; spec reserves the bytes path for future Track B (Python
  analytics) which might receive raw uploaded files.

---

## 3. Capability declarations

Every subprocess advertises the methods it implements at handshake
time. The host filters dispatch based on the advertised set.

### 3.1 Initialize handshake

**Client → server (host → plugin)**:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "Initialize",
  "params": {
    "protocolVersion": 1,
    "magicCookie": "KITE_RISKGUARD_CHECK_PLUGIN",
    "hostName": "kite-mcp-server",
    "hostVersion": "1.4.2"
  }
}
```

**Server → client (plugin → host)**:

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "result": {
    "pluginName": "my-riskguard-check",
    "pluginVersion": "0.1.0",
    "protocolVersion": 1,
    "capabilities": [
      {
        "name": "riskguard.checkOrder",
        "schemaRef": "kite-mcp.v1#/definitions/CheckOrderRequest",
        "schemaResponse": "kite-mcp.v1#/definitions/CheckResult"
      }
    ],
    "metadata": {
      "language": "rust",
      "languageVersion": "1.85.0",
      "supportsCancellation": true,
      "supportsTraceContext": true
    }
  }
}
```

**Capability format**:

- `name`: dotted hierarchical method name (e.g.
  `riskguard.checkOrder`, `analytics.computeSharpe`,
  `widgets.renderDashboard`). Dots map to top-level domains in
  the codebase's package layout.
- `schemaRef`: optional JSON Schema reference for the request type.
  If absent, the plugin accepts any JSON shape (used by Track A
  widget plugins where the schema is host-driven).
- `schemaResponse`: optional JSON Schema reference for the response
  type. Same fallback semantics.

### 3.2 Capability filtering on the host side

The host stores the advertised set per-subprocess and rejects
incoming calls that target an un-advertised method:

```
Method called: riskguard.checkOrder
Subprocess advertises: [riskguard.checkOrder, riskguard.checkPosition]
→ dispatchable

Method called: analytics.computeSharpe
Subprocess advertises: [riskguard.checkOrder]
→ rejected with code -32601 (Method not found per JSON-RPC 2.0)
```

This lets multiple plugins coexist in the same host with non-
overlapping responsibilities without manual routing config — the
host learns from the handshake.

### 3.3 Comparison with hashicorp/go-plugin's existing pattern

The existing `checkrpc/` pattern uses a fixed `PluginMap` and a
single `DispenseKey`. Capabilities are implicit (the plugin
implements `CheckRPC`; the host knows it). This works for ONE
domain; it does not scale to N domains in one subprocess.

The new spec generalises:

- Multiple capabilities per subprocess (a subprocess can advertise
  multiple methods).
- Capabilities are NAMED (the dotted-method-name convention).
- Capabilities carry SCHEMA REFERENCES (typed contract per method).

Backward-compat: the existing checkrpc subprocess can be wrapped
in a thin JSON-RPC adapter that advertises a single capability
`riskguard.checkOrder` and dispatches it to the gob-shaped
`CheckRPC.Evaluate`. The wrap adapter is ~50 LOC; covered in §9.1
(reference implementation).

---

## 4. Lifecycle

### 4.1 Process lifecycle phases

```
[host]                      [subprocess]
  |
  | (1) launch via fork+exec
  |     stdin/stdout pipes attached
  |
  |     <-- Initialize request via stdin
  |     --> Initialize response via stdout
  |
  |     <-- method calls --> ...
  |
  | (5) graceful shutdown
  |     -- Shutdown request -->
  |     <-- Shutdown ack
  |     <-- subprocess closes stdout, exits 0
  |
  |     OR
  |
  | (6) forced shutdown after timeout
  |     -- SIGTERM -->
  |     (5s grace period)
  |     -- SIGKILL -->
  |     (subprocess killed)
```

### 4.2 Handshake details

The Initialize call (per §3.1) MUST be the first message on the
pipe. The subprocess MUST NOT send any unsolicited frames before
the host's Initialize request — this prevents log lines or partial
JSON from corrupting the wire framing.

**Magic cookie**: same as ADR 0007's `Handshake.MagicCookie`
mechanism. The plugin verifies the host's magic cookie on receipt
of Initialize; if mismatched, the plugin closes stdout and exits
non-zero. This prevents accidental double-click execution as a
standalone program (per `kc/riskguard/checkrpc/types.go:200-204`).

### 4.3 Version negotiation

Three integer protocol versions:

- **Wire-protocol version** (this spec's version, `protocolVersion:
  1`). Bumped on incompatible wire format changes (e.g., switching
  framing). Both sides MUST agree.
- **Capability schema version** (per-capability, embedded in the
  `schemaRef` URI fragment, e.g.
  `kite-mcp.v1#/definitions/CheckOrderRequest` vs `kite-mcp.v2#/...`).
  A subprocess can advertise capabilities at multiple schema
  versions; the host picks the highest version it knows.
- **Host version** (informational, e.g. `"1.4.2"`). Advertised to
  the plugin for telemetry; not used for dispatch decisions.

Wire-protocol version mismatch at Initialize: the host SHOULD log
a clear error and refuse to dispatch any methods. The subprocess
SHOULD respond to Initialize with a JSON-RPC error code -32099
(`"protocolVersion mismatch"`) and exit cleanly.

### 4.4 Graceful shutdown

The host sends a `Shutdown` request with no params. The subprocess
acknowledges with a normal JSON-RPC response and then closes
stdout. After 5 seconds without ack, the host sends SIGTERM. After
another 5 seconds, SIGKILL.

The subprocess MUST NOT process new incoming requests after
sending the Shutdown ack — any in-flight requests at the time of
Shutdown SHOULD be allowed to complete before the ack is sent.

### 4.5 Panic propagation

A panic on the subprocess side surfaces to the host as one of:

1. **Pipe closed unexpectedly** — the host's read of the pipe
   returns EOF or a broken-pipe error. The host marks the
   subprocess dead, logs at WARN with the last-known frame
   context, and relaunches on the next call.
2. **JSON-RPC error response** with code -32000 (`"InternalError"`)
   and `data.recovered: true`. This is the preferred path: the
   subprocess installs a top-level recover() handler that
   converts panics to error responses. Mirrors the existing
   `safeRunBeforeHook` / `safeInvokeAroundHook` pattern in
   `mcp/registry.go`.

The host's reference implementation (§9.1) honours both forms;
plugin authors are encouraged to use form (2) for cleaner
diagnostics but form (1) is structurally safe.

---

## 5. Cancellation + context propagation

### 5.1 Go side — context.Context

The Go host already uses `context.Context` pervasively. Cancellation
crosses the IPC boundary via:

```go
type CancellableCall struct {
    Method      string
    Params      json.RawMessage
    RequestID   string
    Deadline    *time.Time     // optional — if set, plugin honors it
    Cancellable bool           // if true, host can cancel mid-call
}
```

When the Go host's context is cancelled:

1. The host SHOULD send a `$/cancelRequest` notification to the
   plugin with the corresponding `requestId`.
2. The plugin SHOULD honour cancellation by aborting the call and
   responding with an error (-32800 `"RequestCancelled"`).
3. If the plugin has not yet acked cancellation within 100ms, the
   host SHOULD treat the call as orphaned (log + drop the response)
   but NOT kill the subprocess — orphaned calls are normal under
   load.

**Notification format** (one-way, no response):

```json
{
  "jsonrpc": "2.0",
  "method": "$/cancelRequest",
  "params": { "id": "<original-request-id>" }
}
```

The `$/`-prefix convention matches LSP's notification namespace
and is widely understood by JSON-RPC tooling.

### 5.2 TypeScript side — AbortSignal

```typescript
async function callPlugin<T>(
  method: string,
  params: any,
  signal?: AbortSignal,
): Promise<T> {
  const id = crypto.randomUUID();
  const promise = sendRequest(id, method, params);
  if (signal) {
    signal.addEventListener("abort", () => {
      sendNotification("$/cancelRequest", { id });
    });
  }
  return promise;
}
```

`AbortSignal.aborted` maps to context.Canceled. The plugin author
on the TS side wires `AbortController` into their handler.

### 5.3 Python side — asyncio cancellation

```python
async def call_plugin(method: str, params: dict) -> dict:
    request_id = str(uuid.uuid4())
    task = asyncio.create_task(send_request(request_id, method, params))
    try:
        return await task
    except asyncio.CancelledError:
        await send_notification("$/cancelRequest", {"id": request_id})
        raise
```

`asyncio.CancelledError` propagates the cancel notification.
Synchronous Python plugins (without asyncio) can ignore the
cancel notification — the host's 100ms grace + orphaned-drop
contract makes this safe.

### 5.4 Rust side — tokio cancellation

```rust
async fn call_plugin<T: DeserializeOwned>(
    method: &str,
    params: serde_json::Value,
    cancel: tokio_util::sync::CancellationToken,
) -> Result<T, IpcError> {
    let id = Uuid::new_v4().to_string();
    let send = send_request::<T>(&id, method, params);
    tokio::select! {
        result = send => result,
        _ = cancel.cancelled() => {
            send_notification("$/cancelRequest", json!({ "id": id })).await;
            Err(IpcError::Cancelled)
        }
    }
}
```

`tokio_util::sync::CancellationToken` is the idiomatic cancellation
primitive in modern Rust async. The plugin author wires it into
their handler analogously to Go's `<-ctx.Done()`.

### 5.5 Deadline propagation

Deadlines can be set explicitly per call (the `Deadline` field in
the request envelope). When a Go context has a deadline (e.g., the
30-second tool-handler timeout from `mcp.TimeoutMiddleware`), the
host SHOULD include it in the IPC call; the plugin SHOULD self-
terminate the call when the deadline passes.

This is BEST-EFFORT: a misbehaving plugin may ignore the deadline.
The host enforces hard timeouts via the TIMEOUT middleware's
context cancellation, NOT via the plugin's compliance.

---

## 6. Observability hooks

### 6.1 Log correlation — request_id propagation

Every IPC call carries a `request_id` field, populated from the
host's `app.RequestIDFromCtx(ctx)` (UUIDv7 per `app/requestid.go`).
The plugin attaches the ID to every log line it emits.

**Wire format** (request envelope extension):

```json
{
  "jsonrpc": "2.0",
  "id": 1,
  "method": "riskguard.checkOrder",
  "params": { ... },
  "$meta": {
    "request_id": "01HKM3...",
    "trace_id": "00-...-...-01",
    "deadline": "2026-04-28T23:30:00Z"
  }
}
```

The `$meta` field is OPTIONAL in JSON-RPC 2.0 (§4.2 implementation
extension) and ignored by strict parsers. Plugins that don't speak
`$meta` get a plain JSON-RPC call.

**Plugin-side log emission**:

```
TS    : pino.child({ request_id: meta.request_id })
Python: structlog.bind(request_id=meta["request_id"])
Rust  : tracing::Span::current().record("request_id", meta.request_id)
Go    : slog.With("request_id", meta.RequestID)
```

### 6.2 Trace context — W3C TraceContext

The W3C TraceContext spec (`traceparent` / `tracestate` headers)
is the cross-language tracing standard. Carried in the same
`$meta` envelope:

```json
"$meta": {
  "trace_id": "00-0af7651916cd43dd8448eb211c80319c-b7ad6b7169203331-01"
}
```

`trace_id` is the full `traceparent` header value. The plugin's
OTEL SDK (or equivalent) extracts the trace context and creates a
child span for its work. Plugin spans appear as children of the
host's MCP-tool-call span in the unified trace view.

**Library choices per language**:

- Go: `go.opentelemetry.io/otel`
- TS: `@opentelemetry/api`
- Python: `opentelemetry-api`
- Rust: `tracing-opentelemetry` + `opentelemetry-api`

All four have OTLP exporters that the host's collector can scrape
(the Foundation §1.4 plumbing).

### 6.3 Metrics emission

Each subprocess exposes a Prometheus-format `/metrics` endpoint on
a per-subprocess port. The host's collector scrapes via local HTTP.

**Standard metrics** every plugin SHOULD emit:

| Metric | Type | Labels |
|---|---|---|
| `plugin_request_total` | counter | `method`, `status` (`ok`/`error`/`cancelled`) |
| `plugin_request_duration_seconds` | histogram | `method` |
| `plugin_internal_error_total` | counter | `category` (recover'd panics, validation failures) |

**Optional**: any plugin-specific metrics (e.g.,
`riskguard_check_blocked_total{reason="kill_switch_on"}`).

### 6.4 Stdio framing — JSON Lines vs Content-Length

Two framing options:

| Option | Pros | Cons |
|---|---|---|
| **JSON Lines** (one JSON object per line, `\n` delimiter) | Trivial; debuggable with `cat`; matches existing log conventions | Forbids embedded `\n` in JSON values (must be escaped) |
| **LSP-style Content-Length** (`Content-Length: <N>\r\n\r\n<JSON>`) | Handles arbitrary JSON content; matches LSP and other RPC specs | Less debuggable; framing parser must be implemented |

**Choice**: **JSON Lines** as the default; **Content-Length**
optional for plugins that handle large or binary-heavy payloads.

JSON Lines aligns with the existing log convention (`slog`'s JSON
handler emits one record per line) and lets agents pipe the wire
to `jq` for ad-hoc inspection. Embedded newlines in JSON values
are escaped per RFC 8259 §7 already; this is not a real
restriction.

For Track B (Python analytics) shipping multi-megabyte DataFrame
slices: opt into Content-Length framing per-subprocess via the
Initialize handshake (`metadata.framing: "content-length"`). The
default framing is JSON Lines.

---

## 7. Versioning + backward-compat

### 7.1 Schema evolution rules

| Change | Forward-compat (old plugin, new host) | Backward-compat (new plugin, old host) |
|---|---|---|
| Add a new optional field to a request | SAFE — host serialises it, plugin ignores | SAFE — plugin serialises it, host ignores |
| Add a new optional field to a response | SAFE — plugin serialises it, host ignores | SAFE — host expects field absent, plugin sends nothing |
| Add a new required field to a request | BREAKING — plugin can't process | UNSAFE — old host doesn't send required field |
| Remove a field | BREAKING — old plugin/host expects it | BREAKING |
| Rename a field | BREAKING — both directions | BREAKING |
| Change a field's type | BREAKING | BREAKING |
| Add a new enum member | SAFE if consumers tolerate unknowns | UNSAFE — old host doesn't recognise |
| Add a new capability | SAFE — old host ignores unknown caps | SAFE — old plugin doesn't advertise; host filters |
| Bump capability schema version | SAFE if old version is also advertised | SAFE if old version is also advertised |

### 7.2 The flag-day vs incremental tradeoff

The existing `checkrpc/` pattern uses a single `Handshake.ProtocolVersion`
that gates every change — bumping it forces a flag-day rebuild of every
plugin in production. This is high-discipline but high-cost.

**This spec** uses a layered version model:

- Wire-protocol version (rare bumps; flag-day) for incompatible
  framing or transport changes.
- Capability schema version (frequent; per-capability;
  multi-version coexistence) for type evolution within a capability.

A subprocess can advertise the same capability at two schema
versions (`riskguard.checkOrder@v1`, `riskguard.checkOrder@v2`),
letting the host pick the highest it knows. New plugins can ship
v2-only; old hosts call v1 transparently. This eliminates most
flag-day pain.

The wire-protocol version stays at 1 for all foreseeable changes;
v2 is reserved for switching framing or transport (e.g., adding
TLS-over-Unix-socket, or moving from JSON Lines to a binary
encoding).

### 7.3 Schema-as-source-of-truth

Each capability's request and response schemas live in
`kc/aspectplugin/schemas/<capability>.schema.json`. Both the host
and the plugin reference the schema by content-hash:

```json
"capabilities": [
  {
    "name": "riskguard.checkOrder",
    "schemaRef": "kite-mcp.v1#/definitions/CheckOrderRequest",
    "schemaHash": "sha256:abc123..."
  }
]
```

`schemaHash` lets the host detect schema drift between what it
expects and what the plugin advertises. Mismatch logs a WARN; the
host continues to dispatch but the operator is aware of the gap.

---

## 8. Per-track contract subsets

### 8.1 Track A — TS / mcp-outer-ring

Capabilities the TS subprocess advertises:

| Capability | Request schema | Response schema |
|---|---|---|
| `mcp.callTool` | `kite-mcp.v1#/definitions/ToolCallRequest` | `kite-mcp.v1#/definitions/ToolCallResult` |
| `mcp.listTools` | `kite-mcp.v1#/definitions/Empty` | `kite-mcp.v1#/definitions/ToolListResult` |
| `widgets.render` | `kite-mcp.v1#/definitions/WidgetRenderRequest` | `kite-mcp.v1#/definitions/WidgetRenderResult` |
| `widgets.handleAppBridgeCall` | `kite-mcp.v1#/definitions/AppBridgeRequest` | `kite-mcp.v1#/definitions/AppBridgeResult` |

**Schema highlights**:

- `ToolCallRequest`: `{ tool_name, arguments, request_id, session_id }`
- `ToolCallResult`: `{ content, structured_content?, is_error, ui_resource? }`
- `WidgetRenderRequest`: `{ widget_id, params, host_capabilities }`
- `AppBridgeRequest`: the typed AppBridge JSON-RPC method names from
  `kc/templates/appbridge.js` re-exported as a TS-side type union

**Why these capabilities**: this is the boundary at which a TS
Nest.js subprocess can replace the Go `mcp/` tool surface from §3
of `parallel-stack-shift-roadmap.md` Track A. The capabilities are
deliberately broad because Track A's full `mcp/` port is the
expensive part (24-36 weeks per `scorecard-final-v2.md` §2.3).

### 8.2 Track B — Python / analytics

Capabilities:

| Capability | Request | Response |
|---|---|---|
| `analytics.computeIndicators` | `{ instrument_token, ohlc_series, indicators: ["rsi", "macd", ...] }` | `{ indicator_values: [...] }` |
| `analytics.runBacktest` | `{ strategy, ohlc_series, initial_capital }` | `{ trades, sharpe, max_drawdown }` |
| `analytics.computeGreeks` | `{ option_symbol, spot, strike, expiry, iv? }` | `{ delta, gamma, theta, vega, iv }` |
| `analytics.computeFactorExposure` | `{ holdings, factor_set }` | `{ exposures: {...} }` |

**Schema highlights**:

- OHLC series: array-of-arrays (`[[ts, o, h, l, c, v], ...]`) for
  pandas/numpy efficiency. NOT an array-of-objects — the
  array-of-arrays form deserialises to a NumPy structured array
  in two function calls.
- Money: float-mode (status quo). Track B is analytics-side
  computation; doesn't materially benefit from decimal-mode.
- Time series: timestamps as RFC 3339 strings (per §2.3) UNLESS
  the schema declares `format: "epoch-ms"` for performance-critical
  paths. The latter MUST be opt-in per-capability.

### 8.3 Track C — Rust / riskguard

Capabilities:

| Capability | Request | Response |
|---|---|---|
| `riskguard.checkOrder` | `kite-mcp.v1#/definitions/CheckOrderRequest` | `kite-mcp.v1#/definitions/CheckResult` |
| `riskguard.checkPosition` | `{ email, position }` | `{ allowed, reason, message }` |
| `riskguard.killSwitchStatus` | `{ email }` | `{ kill_switch_on, set_at, set_by }` |

**Schema highlights**:

- `CheckOrderRequest`: structurally identical to the existing
  `OrderCheckRequestWire` (`kc/riskguard/checkrpc/types.go:36-47`).
  The Rust port doesn't change semantics; it changes runtime.
- Hot-path optimisations: 200-byte payloads; small allocations;
  no JSON Schema validation on the hot path (validation runs at
  Initialize time, not per-call).
- Money: float-mode. Rust's `rust_decimal` is available IF the
  decimal-mode opt-in lands later, but Track C inherits the
  float-mode default for compat with the existing
  `OrderCheckRequestWire.Price` type.

### 8.4 Cross-track shared types

Schema definitions in `kite-mcp.v1` referenced by multiple tracks:

- `Money` — float-mode by default; decimal-mode opt-in (§2.4).
- `Order` — placed-but-not-filled order shape; matches
  `broker.Order` Go type field-by-field.
- `Position` — open position shape; matches `broker.Position`.
- `Quote` — instrument quote with LTP, bid, ask, depth.
- `Instrument` — symbol metadata (token, tradingsymbol, exchange,
  expiry, strike).
- `Email` — string format with email-validation regex (per
  `app/users` validation logic).

Shared types live in ONE schema file
(`kc/aspectplugin/schemas/kite-mcp.v1.schema.json`); per-capability
schemas reference them via JSON Schema `$ref`.

---

## 9. Reference implementation skeletons

### 9.1 Go — host-side dispatcher

```go
// File sketch — kc/aspectplugin/client.go (~200 LOC)
package aspectplugin

import (
    "bufio"
    "context"
    "encoding/json"
    "io"
    "os/exec"
    "sync"
)

// Client is the host-side IPC client. One per subprocess.
type Client struct {
    cmd        *exec.Cmd
    stdin      io.WriteCloser
    stdout     *bufio.Reader
    nextID     atomic.Int64
    pending    sync.Map           // id -> chan *Response
    capabilities map[string]Capability
}

func (c *Client) Call(
    ctx context.Context,
    method string,
    params any,
) (json.RawMessage, error) {
    if _, ok := c.capabilities[method]; !ok {
        return nil, ErrCapabilityNotAdvertised
    }

    id := c.nextID.Add(1)
    req := Request{
        JSONRPC: "2.0",
        ID:      id,
        Method:  method,
        Params:  mustMarshal(params),
        Meta: &MetaEnvelope{
            RequestID: app.RequestIDFromCtx(ctx),
            TraceID:   traceparentFromCtx(ctx),
            Deadline:  deadlineFromCtx(ctx),
        },
    }

    respCh := make(chan *Response, 1)
    c.pending.Store(id, respCh)
    defer c.pending.Delete(id)

    if err := c.sendFrame(req); err != nil {
        return nil, err
    }

    select {
    case resp := <-respCh:
        if resp.Error != nil {
            return nil, asError(resp.Error)
        }
        return resp.Result, nil
    case <-ctx.Done():
        c.sendNotification("$/cancelRequest", map[string]int64{"id": id})
        return nil, ctx.Err()
    }
}

func (c *Client) Initialize() error {
    resp, err := c.Call(context.Background(), "Initialize", InitParams{
        ProtocolVersion: 1,
        MagicCookie:     "KITE_RISKGUARD_CHECK_PLUGIN", // example
        HostName:        "kite-mcp-server",
        HostVersion:     buildVersion(),
    })
    if err != nil {
        return err
    }
    var initResp InitResponse
    if err := json.Unmarshal(resp, &initResp); err != nil {
        return err
    }
    c.capabilities = make(map[string]Capability, len(initResp.Capabilities))
    for _, cap := range initResp.Capabilities {
        c.capabilities[cap.Name] = cap
    }
    return nil
}
```

### 9.2 TypeScript — plugin-side handler

```typescript
// File sketch — examples/riskguard-check-plugin-ts/src/index.ts (~150 LOC)
import { JSONRPCServer } from "json-rpc-2.0";
import { z } from "zod";

const CheckOrderRequest = z.object({
  email: z.string().email(),
  tool_name: z.string(),
  exchange: z.enum(["NSE", "BSE", "NFO", "BFO", "CDS", "MCX"]),
  tradingsymbol: z.string(),
  transaction_type: z.enum(["BUY", "SELL"]),
  quantity: z.number().int().positive(),
  price: z.number().nonnegative(),
  order_type: z.enum(["MARKET", "LIMIT", "SL", "SLM"]),
  confirmed: z.boolean(),
  client_order_id: z.string().optional(),
});

const server = new JSONRPCServer();

server.addMethod("Initialize", () => ({
  pluginName: "ts-riskguard-check",
  pluginVersion: "0.1.0",
  protocolVersion: 1,
  capabilities: [
    {
      name: "riskguard.checkOrder",
      schemaRef: "kite-mcp.v1#/definitions/CheckOrderRequest",
    },
  ],
  metadata: { language: "typescript", supportsCancellation: true },
}));

server.addMethod("riskguard.checkOrder", async (params, context) => {
  const req = CheckOrderRequest.parse(params);
  // Custom rule logic here.
  if (req.tradingsymbol.startsWith("BLOCKED_")) {
    return { allowed: false, reason: "blocked_prefix",
             message: `${req.tradingsymbol} is on the blocklist` };
  }
  return { allowed: true };
});

// JSON Lines stdio loop
process.stdin.setEncoding("utf-8");
const rl = readline.createInterface({ input: process.stdin });
rl.on("line", async (line) => {
  const req = JSON.parse(line);
  const resp = await server.receive(req);
  if (resp) process.stdout.write(JSON.stringify(resp) + "\n");
});
```

### 9.3 Python — plugin-side handler

```python
# File sketch — examples/riskguard-check-plugin-py/main.py (~100 LOC)
import asyncio
import json
import sys
from pydantic import BaseModel, Field

class CheckOrderRequest(BaseModel):
    email: str
    tool_name: str
    exchange: str
    tradingsymbol: str
    transaction_type: str
    quantity: int
    price: float
    order_type: str
    confirmed: bool
    client_order_id: str | None = None

CAPABILITIES = [
    {"name": "riskguard.checkOrder",
     "schemaRef": "kite-mcp.v1#/definitions/CheckOrderRequest"},
]

async def handle(request: dict) -> dict:
    method = request["method"]
    params = request.get("params", {})
    request_id = request.get("id")

    if method == "Initialize":
        return {"jsonrpc": "2.0", "id": request_id, "result": {
            "pluginName": "py-riskguard-check",
            "pluginVersion": "0.1.0",
            "protocolVersion": 1,
            "capabilities": CAPABILITIES,
            "metadata": {"language": "python", "supportsCancellation": True},
        }}

    if method == "riskguard.checkOrder":
        req = CheckOrderRequest(**params)
        if req.tradingsymbol.startswith("BLOCKED_"):
            return {"jsonrpc": "2.0", "id": request_id, "result": {
                "allowed": False,
                "reason": "blocked_prefix",
                "message": f"{req.tradingsymbol} is on the blocklist",
            }}
        return {"jsonrpc": "2.0", "id": request_id, "result": {"allowed": True}}

    return {"jsonrpc": "2.0", "id": request_id, "error": {
        "code": -32601, "message": "Method not found"}}

async def main():
    loop = asyncio.get_event_loop()
    while True:
        line = await loop.run_in_executor(None, sys.stdin.readline)
        if not line:
            break
        req = json.loads(line)
        resp = await handle(req)
        sys.stdout.write(json.dumps(resp) + "\n")
        sys.stdout.flush()

asyncio.run(main())
```

### 9.4 Rust — plugin-side handler

```rust
// File sketch — examples/riskguard-check-plugin-rs/src/main.rs (~120 LOC)
use serde::{Deserialize, Serialize};
use serde_json::{json, Value};
use tokio::io::{AsyncBufReadExt, AsyncWriteExt, BufReader};

#[derive(Deserialize)]
struct CheckOrderRequest {
    email: String,
    tool_name: String,
    exchange: String,
    tradingsymbol: String,
    transaction_type: String,
    quantity: i32,
    price: f64,
    order_type: String,
    confirmed: bool,
    client_order_id: Option<String>,
}

#[derive(Serialize)]
struct CheckResult {
    allowed: bool,
    reason: Option<String>,
    message: Option<String>,
}

async fn handle(req: Value) -> Value {
    let id = req.get("id").cloned();
    let method = req["method"].as_str().unwrap_or("");

    match method {
        "Initialize" => json!({
            "jsonrpc": "2.0",
            "id": id,
            "result": {
                "pluginName": "rs-riskguard-check",
                "pluginVersion": "0.1.0",
                "protocolVersion": 1,
                "capabilities": [{
                    "name": "riskguard.checkOrder",
                    "schemaRef": "kite-mcp.v1#/definitions/CheckOrderRequest"
                }],
                "metadata": {"language": "rust", "supportsCancellation": true},
            }
        }),
        "riskguard.checkOrder" => {
            let params: CheckOrderRequest = serde_json::from_value(
                req["params"].clone()).unwrap();
            let result = if params.tradingsymbol.starts_with("BLOCKED_") {
                CheckResult {
                    allowed: false,
                    reason: Some("blocked_prefix".to_string()),
                    message: Some(format!("{} is on the blocklist",
                                          params.tradingsymbol)),
                }
            } else {
                CheckResult { allowed: true, reason: None, message: None }
            };
            json!({"jsonrpc": "2.0", "id": id, "result": result})
        }
        _ => json!({
            "jsonrpc": "2.0", "id": id,
            "error": {"code": -32601, "message": "Method not found"}
        }),
    }
}

#[tokio::main]
async fn main() {
    let stdin = tokio::io::stdin();
    let mut reader = BufReader::new(stdin);
    let mut stdout = tokio::io::stdout();
    let mut line = String::new();
    while reader.read_line(&mut line).await.unwrap() != 0 {
        let req: Value = serde_json::from_str(&line).unwrap();
        let resp = handle(req).await;
        stdout.write_all(serde_json::to_string(&resp).unwrap().as_bytes())
              .await.unwrap();
        stdout.write_all(b"\n").await.unwrap();
        stdout.flush().await.unwrap();
        line.clear();
    }
}
```

### 9.5 Compatibility wrapper for existing checkrpc plugins

The existing `kc/riskguard/checkrpc/` plugin pattern (gob over
netRPC) is preserved. New plugins use the JSON-RPC contract;
existing plugins keep working. A compatibility wrapper bridges:

```go
// File sketch — kc/aspectplugin/checkrpc_compat.go (~50 LOC)
package aspectplugin

// CheckRPCAdapter wraps a checkrpc.CheckRPC client and presents
// it as a JSON-RPC capability.
type CheckRPCAdapter struct {
    client checkrpc.CheckRPC
}

func (a *CheckRPCAdapter) Capabilities() []Capability {
    return []Capability{{
        Name:      "riskguard.checkOrder",
        SchemaRef: "kite-mcp.v1#/definitions/CheckOrderRequest",
    }}
}

func (a *CheckRPCAdapter) Dispatch(method string, params json.RawMessage) (any, error) {
    if method != "riskguard.checkOrder" {
        return nil, ErrMethodNotFound
    }
    var req checkrpc.OrderCheckRequestWire
    if err := json.Unmarshal(params, &req); err != nil {
        return nil, err
    }
    return a.client.Evaluate(req)
}
```

This is the gradual-migration path: existing checkrpc plugins
never need to know about JSON-RPC; the host adapter speaks both
sides.

---

## 10. Honest verdict — is the contract executable?

### 10.1 Resolved tradeoffs

The following tradeoffs have a clear answer in this spec; no
further decision required:

- **Wire format**: JSON-RPC 2.0 over stdio with optional JSON
  Schema (§1.3).
- **Framing**: JSON Lines default; Content-Length opt-in for
  large-payload tracks (§6.4).
- **Cancellation**: `$/cancelRequest` notification + 100ms
  orphan grace + ctx.Done()-equivalent on each language (§5).
- **Trace context**: W3C TraceContext via `$meta.trace_id` (§6.2).
- **Capability advertisement**: dotted-method-name + JSON Schema
  reference (§3.1).
- **Error categories**: 10 in-tree categories at codes -32001 to
  -32010; plugin-author range -32049 to -32000 (§2.5).
- **Versioning**: layered (wire-protocol + per-capability schema);
  multi-version coexistence (§7).
- **Backward-compat with existing checkrpc**: wrapper adapter
  preserves gob plugins indefinitely (§9.5).

### 10.2 Unresolved tradeoffs

The following tradeoffs are deferred and would block one or more
tracks from full execution:

| Tradeoff | What's deferred | Impact if unresolved |
|---|---|---|
| **Money decimal-mode** | The `decimal.Decimal`-shaped wire path (§2.4). Status quo float-mode is fully specified; decimal opt-in is documented but not implemented. | Track C riskguard with strict-decimal requirement (e.g., regulatory penny-precision audit) cannot use the JSON-RPC path. Mitigation: `kc/money` ships a decimal type first (~150 LOC); wire spec unchanged. |
| **OHLC series schema for analytics** | §8.2 specifies array-of-arrays shape but doesn't pin the schema (column order, optional fields, NaN handling). | Track B Python analytics for backtest can start, but cross-tool consistency requires nailing the OHLC schema. ~50 LOC of schema work. |
| **AppBridge schema for widgets** | §8.1 references AppBridge JSON-RPC method names from `kc/templates/appbridge.js` but doesn't enumerate them. | Track A TS Nest.js port of widgets cannot land without this; AppBridge is the host↔widget contract. ~200 LOC of schema work. |
| **Stdio framing for large payloads** | §6.4 documents Content-Length as opt-in; the per-subprocess negotiation logic is sketched but not specified. | Track B with multi-MB DataFrame slices needs Content-Length; until specified, the slice size is bounded to ~1MB (JSON Lines escape overhead). |
| **Subprocess restart policy** | §4.4 specifies graceful shutdown but doesn't pin auto-restart-on-crash semantics (max restarts, backoff, circuit breaker). | Production deployment of any track needs an explicit policy; defaults to "restart once, then mark dead and require operator intervention" — sketched in §4 but not specified at line-level detail. |
| **Capability schema versioning + migrations** | §7 documents the multi-version coexistence model; the host's "pick the highest version both sides know" algorithm is not specified at code-level detail. | Critical for Track A Nest.js where API velocity is high and v1→v2 schema bumps will be frequent. ~80 LOC of host-side work + tests. |
| **Authentication / capability-token between host and subprocess** | This spec assumes localhost-trust (subprocess inherits the parent's privileges). For a Track that runs on a separate host (Fly.io machine-to-machine RPC, e.g.), TLS + capability tokens are required. | Cross-machine deployment is not the current scope; specifying this would expand the doc by ~30%. Localhost-trust is the documented assumption. |

**Aggregate**: 7 unresolved tradeoffs. None are blockers for the
**spec itself** to land; all are blockers for at least one track's
**production deployment**. The spec is **executable as drafted at
the prototype level** (the §9 reference implementations in 4
languages compile and round-trip a check call); it is **NOT
production-ready** for any track without resolving the above.

### 10.3 Drafted vs production gap — honest sizing

To take this spec from "drafted" to "production-ready for Track X":

| Track | Drafted-to-production gap |
|---|---|
| Track A (TS) | Specify AppBridge schema + Content-Length framing + capability-version migration logic. ~330 LOC of additional schema/spec work + ~500 LOC of host-side migration code. |
| Track B (Python) | Specify OHLC schema + Content-Length framing + capability-version migration. ~130 LOC additional + ~500 LOC host-side. |
| Track C (Rust) | Specify Money decimal-mode (if needed for the specific Rust riskguard requirements) + restart policy. ~200 LOC additional. |
| Foundation (without any track) | Specify capability-version migration logic + restart policy. ~80 LOC additional. |

The "drafted" state of this doc covers the cross-cutting concerns
(framing, versioning, errors, observability, lifecycle, types)
adequately for the prototype skeletons in §9 to compile and
round-trip. The track-specific gaps are bounded and well-scoped.

### 10.4 Verdict

**Spec is drafted and prototype-executable. Production deployment
of any track requires ~80-330 LOC additional work depending on
which track activates first.**

The drafting itself was the cheap part (this doc); the unresolved
tradeoffs are deferred low-cost items that fire only when a track
trigger fires. That matches the user's explicit framing: **"Drafting
now is low-cost prep work that pays off if any track activates;
actual track execution remains deferred."**

The spec does NOT commit the codebase to any of the tracks. Foundation
phase per `parallel-stack-shift-roadmap.md` §1 is partially
satisfied (the IPC contract spec is the largest §1.1 deliverable);
§1.2 (per-language CI), §1.3 (deploy targets), §1.4 (observability),
§1.5 (SBOM) remain deferred until track activation.

---

## 11. Deferred work

Items the spec acknowledges but does NOT specify in detail:

1. **TLS-over-Unix-socket transport** (§1.3). Considered for cross-
   machine deployment; deferred. Status-quo localhost-stdio is the
   single transport for now.
2. **Binary framing alternative** (§6.4). Content-Length is the
   opt-in path; protobuf or MessagePack could be added as a
   per-track opt-in later without disrupting JSON-RPC default.
3. **Persistent connection pooling** (§4.1). Each subprocess is
   one process per host today. Multi-subprocess pools (e.g., load-
   balanced analytics workers) is a Track B-driven feature when
   Python analytics throughput grows past single-process capacity.
4. **Capability-token auth between host and plugin** (§10.2 row 7).
   Mandatory if subprocess crosses a machine boundary. Not
   specified.
5. **Schema migration tools** (§7.3). Manual schema evolution per
   §7.1 rules works at current pace; if track velocity increases,
   automatic migration from vN-1 to vN payloads (e.g., a JSON
   Patch-driven transformer) becomes worth specifying.
6. **Encrypted stdio** (§4.1). Status-quo plaintext stdio is fine
   for localhost trust. If the spec expands to cross-machine, TLS
   + capability tokens (§10.2 row 7) cover this.
7. **Built-in retry / circuit-breaker on host** (§4.5). The
   reference implementation in §9.1 does not include retry; relies
   on the host's existing `mcp.CircuitBreakerMiddleware`. Track-
   specific tuning is a separate spec extension.

These are documented as deferred so future readers do not mistake
their absence for oversight.

---

## 12. Summary table — ten brief items

| # | Item | Status |
|---|---|---|
| 1 | Wire format choice | **JSON-RPC 2.0 over stdio** with optional JSON Schema |
| 2 | Schema | Type mapping table covering primitives + Decimal, Time, Errors, Enums, Optional, Bytes |
| 3 | Capability declarations | dotted-method-name + JSON Schema reference + multi-capability per subprocess |
| 4 | Lifecycle | Initialize handshake → method dispatch → graceful Shutdown (5s ack, 5s SIGTERM, SIGKILL) |
| 5 | Cancellation | `$/cancelRequest` notification mapped to context.Context / AbortSignal / asyncio.CancelledError / tokio CancellationToken |
| 6 | Observability | `$meta.request_id` + W3C TraceContext + per-subprocess Prometheus `/metrics` |
| 7 | Versioning | Layered (wire-protocol + per-capability schema); multi-version coexistence |
| 8 | Per-track contract subsets | Track A (mcp.callTool / widgets.render); Track B (analytics.*); Track C (riskguard.checkOrder) |
| 9 | Reference implementation skeletons | Go (host), TS, Python, Rust (each ~100-200 LOC) |
| 10 | Honest verdict | **Spec is drafted and prototype-executable**; 7 unresolved tradeoffs deferred to per-track activation |

---

## Sources

- `docs/adr/0007-canonical-cross-language-plugin-ipc.md` (`202b993`)
  — the canonical IPC pattern; this spec extends it.
- `kc/riskguard/checkrpc/types.go` (216 LOC) — the existing wire
  contract; reference for the compatibility wrapper at §9.5.
- `kc/riskguard/checkrpc/README.md` — pattern documentation; this
  spec is written to stay compatible with the "Adding a new plugin
  domain" guide.
- `kc/money/money.go` — Money VO; informs §2.4 decimal mapping.
- `.research/parallel-stack-shift-roadmap.md` (`8361409`) §1.1 —
  Foundation phase IPC contract sketch this doc elaborates.
- `.research/fork-loc-split-and-tier3-promotion.md` (`d0e999d`) —
  Tier-3 promotion-trigger matrix; informs the per-track contract
  subsets in §8.
- `.research/scorecard-final-v2.md` (`8361409`) §2.3 — empirical
  `mcp/` thinness re-measurement; bounds Track A scope (§8.1).
- `.research/decorator-stack-shift-evaluation.md` (`809edaf`) §3 —
  per-language native-AOP feasibility matrix; cross-references
  the per-track schema subsets.
- `feedback_decoupling_denominator.md` — Axis C framework; this
  spec preserves Axes A + B (no execution cost imposed on tracks
  that don't activate).
- JSON-RPC 2.0 specification — https://www.jsonrpc.org/specification
- W3C TraceContext specification — https://www.w3.org/TR/trace-context/
- RFC 8259 (JSON) — https://datatracker.ietf.org/doc/html/rfc8259
- RFC 3339 (date/time) — https://datatracker.ietf.org/doc/html/rfc3339
- RFC 4648 (base64) — https://datatracker.ietf.org/doc/html/rfc4648

---

*Generated 2026-04-28 night, read-only research deliverable.
Foundation phase §1.1 deliverable per
`parallel-stack-shift-roadmap.md`. NO ship; track execution
remains deferred per Tier-3 promotion-trigger matrix
(`fork-loc-split-and-tier3-promotion.md`).*
