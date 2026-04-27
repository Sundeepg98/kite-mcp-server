# Money VO Sweep — Slice 6 / 7 Scoping

**Date**: 2026-04-27
**HEAD**: `e37e9d5` (post-Slice 1-5 + case study)
**Predecessors**:
- Slice 1 `5ce3eb0` — UserLimits.Max*INR
- Slice 2 `0e516e7` — OrderCheckRequest.Price
- Slice 3 `5b5a54e` — DailyPlacedValue + briefings P&L
- Slice 4 `fb4ff33` — billing tier amounts
- Slice 5 `aeb6f6a` — paper trading cash + balance

This doc scopes the two remaining `float64`-money surfaces flagged by
the Slice 3 agent as out-of-band:

1. **`broker.Holding/Position.PnL` passthrough** — the broker DTO layer
2. **`kc/alerts/pnl.go DailyPnLEntry`** — SQL-persisted P&L journal

Both surfaces touch broker boundary types and SQL persistence in ways
that make them riskier than Slices 1-5.

---

## Candidate 1 — `broker.Holding/Position.PnL`

### 1.1 Where the field is defined

```go
// broker/broker.go
type Holding struct {
    ...
    PnL          float64 `json:"pnl"`
    ...
}
type Position struct {
    ...
    PnL          float64 `json:"pnl"`
}
type MFHolding struct {
    ...
    PnL          float64 `json:"pnl"`
}
```

These are the **broker-port DTOs** (broker/broker.go:43-65, 281-289).
Every adapter (`broker/zerodha`, `broker/mock`) populates them; every
in-process consumer reads them.

The DTOs are the boundary contract between broker plugins and the
domain. Changing them is more invasive than Slices 1-5 because the
contract is (a) implemented by multiple adapters, and (b) consumed by
~35 production sites across `kc/usecases`, `kc/alerts`,
`kc/telegram`, and `mcp/`.

### 1.2 Adapter conversion sites (writers)

| File:Line | Role |
|---|---|
| `broker/zerodha/convert.go:60` | `convertHoldings` writes `PnL: h.PnL` |
| `broker/zerodha/convert.go:87` | `convertPositions` writes `PnL: p.PnL` |
| `broker/zerodha/convert.go:343` (approx) | `convertMFHoldings` writes `PnL: h.PnL` |
| `broker/mock/client.go` | Mock adapter populates literal floats |

### 1.3 Consumers (35 production read sites)

**Already routed through `domain.Position.PnL() Money`** (good —
Slice 6 partially landed via the rich entity):
- `mcp/analytics_tools.go:415,419,430` — `pos.PnL().Amount`
  inside `computePositionAnalysis`
- `kc/domain/position.go:86-88` — exposes the Money accessor

**Bare `.PnL` field reads** (full Slice 6 conversion targets):
- `mcp/context_tool.go:182,192,201,267` — trading_context aggregations
- `mcp/pretrade_tool.go:276,323` — pre-trade existing-position warning
- `mcp/plugin_widget_returns_matrix.go:69,72,74,77` — returns matrix widget
- `mcp/backtest_tool.go:216,226,527` — backtest trade aggregator (note:
  this `.PnL` is the local `BacktestTrade.PnL`, NOT broker — leave alone)
- `kc/alerts/pnl.go:89` — `entry.PositionsPnL += p.PnL`
- `kc/alerts/briefing.go:419` — daily summary positions sum
- `kc/usecases/widget_usecases.go:168,173,181,184` — portfolio widget
- `kc/usecases/close_position.go:191` — `PositionPnL: matched.PnL` in
  `ClosePositionResult`
- `kc/telegram/commands.go:222,240,243,327` — open positions + handlePnL

**JSON wire format consumers**:
- All MCP tool responses serialize broker DTOs verbatim (including
  the `pnl` field) — external clients (claude.ai, Claude Desktop,
  ChatGPT widgets, Telegram messages) all expect numeric `pnl`.

### 1.4 Option matrix

| Option | Approach | Wire impact | LOC |
|---|---|---|---|
| **A** | Add `Holding.PnLMoney() Money` + `Position.PnLMoney() Money` accessor methods. Migrate consumers one at a time. Field stays `float64`. | None — JSON tag stays. | ~80-150 |
| **B** | Wholesale type change: `PnL float64` → `PnL Money` on Holding/Position/MFHolding. Add custom MarshalJSON to keep wire `{"pnl": 1234.56}`. | Internal only — wire preserved via custom marshaller. | ~600-900 (cascades through 35+ sites + adapters + tests) |
| **C** | Defer entirely. Document `domain.Position.PnL() Money` as the canonical read path; freeze further bare-field reads via lint rule; revisit when a second broker adapter or cross-currency need lands. | None. | ~5 (lint comment) |

### 1.5 Recommendation: **Option A** with a strong "minimum viable"
flavour.

**Rationale**:

1. **The keystone work is done already**. `kc/domain/position.go`
   already wraps broker.Position and exposes `PnL() Money`. Three
   call sites in `mcp/analytics_tools.go` already use it. The
   pattern is proven and idiomatic.

2. **Wholesale (B) is high-risk-low-value at current scale**. 35
   read sites + custom MarshalJSON + adapter cascades is ~600-900
   LOC for zero behavioural improvement (every value will still be
   INR, since Indian-only deployment means no production currency
   diversity). The DDD lift is real but small — Slices 1-5 covered
   the high-value surfaces (limits, prices, cash, MRR) where
   currency-aware comparison genuinely changes failure modes. PnL
   passthrough is observation, not arithmetic — a cross-currency
   coercion bug here would be visible (wrong rupee figure on a
   dashboard) rather than silent (wrong limit check).

3. **Defer (C) leaves the keystone half-built**. We already have
   `domain.Position.PnL() Money` and three callers — extending the
   pattern is mechanical follow-through, not architectural debt.

**Slice 6 budget**: target ~150 LOC across 4-5 files —
`mcp/context_tool.go`, `mcp/pretrade_tool.go`, `kc/usecases/widget_usecases.go`,
`kc/usecases/close_position.go`. Each consumer migrates from
`p.PnL` (bare float) to `domain.NewPositionFromBroker(p).PnL().Float64()`
or `.Amount` at the JSON-emit boundary. Stop at the broker DTO —
do **not** change the field type (Option A explicitly avoids this).

**Risk**: Low. Each call site is independent — one commit per file
acceptable. Test cascade is minimal (the existing `pos.PnL()`
sites in analytics_tools have no test churn from the prior
migration).

**Out of scope for Slice 6**: `broker.Holding` doesn't yet have a
domain wrapper. Either add `domain.Holding` mirroring `domain.Position`
(adds ~30 LOC scope) or skip Holding consumers in Slice 6 and queue
them as Slice 6b. **Recommend the latter** — `domain.Holding` is a
new abstraction worth its own design conversation.

---

## Candidate 2 — `kc/alerts/pnl.go DailyPnLEntry`

### 2.1 Surface inventory

**Struct definition** (`kc/alerts/db.go:307-316`):

```go
type DailyPnLEntry struct {
    Date          string  `json:"date"`
    Email         string  `json:"email"`
    HoldingsPnL   float64 `json:"holdings_pnl"`
    PositionsPnL  float64 `json:"positions_pnl"`
    NetPnL        float64 `json:"net_pnl"`
    HoldingsCount int     `json:"holdings_count"`
    TradesCount   int     `json:"trades_count"`
}
```

**Aggregate result** (`kc/alerts/pnl.go:11-24`):

```go
type PnLJournalResult struct {
    Entries       []*DailyPnLEntry `json:"entries"`
    CumulativePnL float64          `json:"cumulative_pnl"`
    BestDay       *DailyPnLEntry   `json:"best_day,omitempty"`
    WorstDay      *DailyPnLEntry   `json:"worst_day,omitempty"`
    AvgDailyPnL   float64          `json:"avg_daily_pnl"`
    ...
}
```

**SQL schema** (`kc/alerts/db.go:208-217`):

```sql
CREATE TABLE IF NOT EXISTS daily_pnl (
    date           TEXT NOT NULL,
    email          TEXT NOT NULL,
    holdings_pnl   REAL NOT NULL DEFAULT 0,
    positions_pnl  REAL NOT NULL DEFAULT 0,
    net_pnl        REAL NOT NULL DEFAULT 0,
    holdings_count INTEGER NOT NULL DEFAULT 0,
    trades_count   INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (date, email)
);
```

### 2.2 Callers

**Writers**:
- `kc/alerts/pnl.go:74-97 buildPnLEntry` — pure aggregation from
  broker holdings + positions
- `kc/alerts/pnl.go:151 SaveDailyPnL` — scheduler at 3:40 PM IST

**Readers**:
- `kc/alerts/pnl.go:163-232 GetJournal` — computes streaks, best/worst,
  cumulative
- `kc/usecases/pnl_usecases.go:14` — `GetJournal` interface in usecase
- `kc/usecases/pnl_usecases.go:20 GetPnLJournalUseCase` — wraps the
  service for the `get_pnl_journal` MCP tool
- `mcp/tool_handlers_test.go` — get_pnl_journal MCP tool

**Persistence boundary**:
- `kc/alerts/db_commands.go:313-324 SaveDailyPnL` — INSERT OR REPLACE
- `kc/alerts/db_queries.go:301-323 LoadDailyPnL` — SELECT for date range

**Consumers of `PnLJournalResult` JSON**:
- `mcp/` tool serializes verbatim to the LLM (claude.ai, Telegram briefings)
- No web dashboard widget references it directly (audit confirmed —
  `dashboard.go` does not consume `PnLJournalResult`)

### 2.3 Option matrix

| Option | Approach | DB migration | Wire impact | LOC |
|---|---|---|---|---|
| **A** | Add sibling `currency TEXT NOT NULL DEFAULT 'INR'` column. Backfill INR for existing rows (default handles it). Dual-write window: `holdings_pnl_inr REAL` + `currency TEXT` for one release, deprecate float column over N releases. | Medium — ALTER TABLE + backfill, idempotent. | None initially; eventually `{"holdings_pnl": {"amount": 100, "currency": "INR"}}` if struct exposes Money directly. | ~250-400 |
| **B** | Change column to TEXT-storing-JSON-Money (e.g. `holdings_pnl_money TEXT NOT NULL DEFAULT '{"amount":0,"currency":"INR"}'`). Forward-compat read path (parse JSON; fall back to float on legacy rows). | High — schema change + data migration script (TEXT-encoded JSON requires application-side parse on every Scan). | None if struct exposes float via `.Float64()` accessor. | ~400-600 |
| **C** | Defer. Keep struct float-only at the persistence layer; reconstruct `Money` only at the in-memory aggregation level (`buildPnLEntry` returns `domain.Money` while DTO stays float). | None. | None. | ~80 (in-memory wrap only) |

### 2.4 Recommendation: **Option C**, with explicit deferral note.

**Rationale**:

1. **No current cross-currency need**. The `daily_pnl` table is INR-
   only by construction — Indian equity markets, Indian users, Zerodha
   broker. The cross-currency risk that justifies Money on
   `UserLimits` (where a USD-denominated config could silently match
   an INR check) does not apply here: every writer feeds INR, every
   reader assumes INR.

2. **The schema is wider than the slice**. `holdings_pnl`,
   `positions_pnl`, `net_pnl` are three separate REAL columns, plus
   `cumulative_pnl` and `avg_daily_pnl` aggregate over them. Option
   A's "sibling currency column" approach is a nightmare of
   redundancy (one currency per amount? one per row?), and Option
   B's JSON-in-TEXT trades the SQLite-native REAL aggregation
   (e.g. `SELECT SUM(net_pnl) FROM daily_pnl WHERE...`) for a
   forced application-side roll-up.

3. **In-memory wrap (Option C-lite) gets us most of the benefit at
   minimal cost**. Make `PnLJournalResult` carry `domain.Money`
   (CumulativePnL, AvgDailyPnL, BestDay.NetPnL via accessor) while
   the persisted DTO stays float. ~80 LOC. Same boundary pattern
   as Slice 4's `Subscription.MonthlyAmount` round-trip but
   inverted: persistence is INR-implicit, in-memory is INR-explicit.

4. **DDD lift here is symbolic, not behavioural**. Cumulative P&L
   is read-only — there's no GreaterThan check, no cross-currency
   add to fail-safe. The Money lift would mean "the function returns
   a typed value" rather than "the function rejects an invalid
   currency". Worth doing eventually, but the budget should match
   the value (low both ways).

**Slice 7 budget if approved**: target ~80 LOC. Add
`domain.Money` fields to `PnLJournalResult` (the in-memory aggregate),
keep `DailyPnLEntry` (the persisted DTO) float-only, document the
boundary in `kc/alerts/pnl.go` comments. Stop there.

**Risk**: Very low. No DB migration, no wire format change, no test
cascade beyond the unit tests in `kc/alerts/store_test.go` that
assert on `result.CumulativePnL` (these go from `assert.InDelta(t,
1850.0, result.CumulativePnL, 0.01)` to `assert.InDelta(t, 1850.0,
result.CumulativePnL.Float64(), 0.01)` — search-and-replace).

**If Slice 7 is rejected**: do nothing. Status quo is fine. The
deferral case is the strongest of the three options.

---

## Honest assessment — ship Slices 6+7 or defer?

### Slice 6 (broker.Position.PnL passthrough): **YES, but small**

- The keystone (`domain.Position.PnL()`) is done; extending the
  pattern is mechanical.
- ~150 LOC for ~5 file changes — fits in a single commit.
- Strict cap: do NOT change the broker DTO field type (Option B
  rejected explicitly).
- Defer Holding consumers to a Slice 6b that scopes
  `domain.Holding` separately.

### Slice 7 (DailyPnLEntry SQL persistence): **DEFER**

- No current cross-currency demand. INR-only schema, INR-only readers.
- Behavioural lift is zero (read-only path, no cross-currency
  comparison).
- DB migration costs (Options A or B) outweigh the symbolic DDD lift.
- Option C-lite (in-memory wrap of `PnLJournalResult` only) is
  available as a ~80 LOC follow-up if a future requirement makes it
  worth ~80 LOC, but ship neither A nor B.

### Scale-gating signal for revisit

Either of these resurfaces in priority **only if**:

- A second broker adapter (Upstox / Angel One / Dhan) lands. Multi-
  broker means the broker port DTOs become a true contract surface
  worth typing aggressively → Slice 6 expands to Option B scope.
- A non-INR market is added (BSE-USD pairs, ADRs via CDSL, etc.) →
  Slice 7 needs Option A's currency column and the Money lift becomes
  behavioural, not symbolic.

Without those triggers, the Money VO sweep is functionally complete
at Slices 1-5. The DDD score lift from completing 6+7 is
~+0.1 — the same lift Slice 4 contributed against ~390 LOC, here
available at ~150 LOC for partial 6 and ~0 for deferred 7. Cost-
adjusted Slice 6 is worth the ship; Slice 7 is not.

---

## TL;DR

| Slice | Verdict | LOC | Why |
|---|---|---|---|
| 6 (broker.Position.PnL) | **Ship Option A** (accessor migration, no DTO type change) | ~150 | Keystone exists; mechanical extension |
| 6b (broker.Holding.PnL) | Queue separately | ~30+150 | Needs `domain.Holding` design first |
| 7 (DailyPnLEntry SQL) | **Defer indefinitely** | 0 (or ~80 in-memory only) | INR-only schema, zero behavioural lift, DB migration costs > benefit |

After Slice 6 lands, the Money VO sweep is at 95%+ coverage of
behaviourally-meaningful surfaces. Calling it done is honest.
