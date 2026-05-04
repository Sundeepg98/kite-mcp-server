// Package ticker defines the broker-agnostic live-tick (websocket)
// port. Adapters in broker/<vendor>/ticker_adapter.go translate
// vendor-specific ticker SDKs (Zerodha kiteticker, future Upstox /
// Dhan / Angel One streaming APIs) to this canonical surface.
//
// Why a separate package: the parent broker package's Client interface
// (broker/broker.go) covers REST-shaped operations (orders, holdings,
// quotes, GTT, mutual funds, margins). Live ticks are streaming and
// callback-driven; bundling them onto Client would force every REST-
// only adapter (test mocks, alternative brokers without websocket)
// to satisfy methods they don't support. Keeping Ticker as its own
// optional sub-interface follows the broker.NativeAlertCapable
// precedent at broker/broker.go:620 — type assertion gates capability.
//
// Consumers obtain a Ticker via a broker-specific factory (e.g.
// zerodha.NewTickerAdapter(apiKey, accessToken)) and depend only on
// this package's types. kc/ticker/service.go orchestrates per-user
// Ticker instances and lifecycle (start, stop, token refresh,
// resubscribe-on-reconnect).
//
// Source-of-truth: Q3 of .research/port-adapter-framework-design.md
// (commit 61da394) — the port surface that closes leak (c) flagged
// in Q2.
package ticker

import "time"

// Mode identifies the granularity of tick data subscribed to. Adapter
// authors translate vendor-specific mode codes (e.g. Zerodha's
// kiteticker.ModeLTP / ModeQuote / ModeFull) to these constants.
//
// Modes are defined as a typed string for forward-compatibility — a
// future Mode that some brokers don't support (e.g. ModeOptions for
// options-chain streaming) can be added without breaking existing
// adapters because the interface signature stays Mode-keyed.
type Mode string

// Mode constants — exhaustive set of broker-agnostic tick granularities.
//
//   - ModeLTP: last traded price only (cheapest, lowest bandwidth).
//   - ModeQuote: LTP + bid/ask top-of-book + day OHLC + day volume.
//   - ModeFull: ModeQuote + 5-level market depth + open interest.
//
// Adapters must accept all three; if an adapter's broker doesn't
// support a richer mode, it should silently downgrade (e.g.
// ModeFull → ModeQuote) and document the behaviour in the adapter's
// godoc rather than returning an error. Returning an error from
// SetMode breaks the resubscribe-on-reconnect loop in kc/ticker/
// service.go's onConnect handler.
const (
	ModeLTP   Mode = "ltp"
	ModeQuote Mode = "quote"
	ModeFull  Mode = "full"
)

// TickOHLC holds the day's open / high / low / previous-close values
// carried alongside a tick. Adapters fill this from the broker's
// reference OHLC (typically the previous close at market open,
// updated intraday for high/low).
type TickOHLC struct {
	Open  float64 `json:"open"`
	High  float64 `json:"high"`
	Low   float64 `json:"low"`
	Close float64 `json:"close"`
}

// Tick is the broker-agnostic live-tick DTO. Adapters fill this from
// their broker-specific tick representation (e.g. Zerodha's
// gokiteconnect/v4/models.Tick) inside the OnTick callback before
// dispatching to the registered TickHandler.
//
// Fields are nullable-by-zero — an adapter that doesn't carry
// AverageTradePrice (some brokers omit it) leaves the field at zero;
// downstream consumers (alert evaluator, watchlist push, dashboard)
// already tolerate zero values per the existing Zerodha-only contract.
//
// Mode echoes the subscription mode the tick was delivered under; LTP
// ticks have only LastPrice + LastQuantity populated, ModeFull ticks
// carry the full struct.
type Tick struct {
	// InstrumentToken is the broker's numeric instrument identifier.
	// Adapters that use string identifiers (e.g. some non-Zerodha
	// brokers) must hash to a stable uint32 in the adapter — the
	// kc/ticker subscriptions map is keyed by uint32 token.
	InstrumentToken uint32 `json:"instrument_token"`

	// LastPrice is the most recent traded price.
	LastPrice float64 `json:"last_price"`

	// LastQuantity is the size of the most recent trade.
	LastQuantity uint32 `json:"last_quantity,omitempty"`

	// AverageTradePrice is the volume-weighted average price for the
	// day (omitted in LTP-only mode).
	AverageTradePrice float64 `json:"average_trade_price,omitempty"`

	// Volume is the total traded volume for the day.
	Volume uint32 `json:"volume,omitempty"`

	// BuyQuantity is the total buy-side volume on the order book.
	BuyQuantity uint32 `json:"buy_quantity,omitempty"`

	// SellQuantity is the total sell-side volume on the order book.
	SellQuantity uint32 `json:"sell_quantity,omitempty"`

	// OHLC is the day's reference open/high/low/previous-close.
	OHLC TickOHLC `json:"ohlc,omitempty"`

	// ChangePercent is the percentage change from previous close
	// (LastPrice / OHLC.Close - 1) * 100. Adapters MAY pre-compute
	// this from broker payload or leave at zero for downstream
	// computation.
	ChangePercent float64 `json:"change_percent,omitempty"`

	// Mode echoes the subscription mode for this tick. Useful for
	// downstream code that needs to distinguish "LTP-only update" vs
	// "full quote refresh".
	Mode Mode `json:"mode,omitempty"`

	// Timestamp is the broker's reported tick time. Zero if the
	// broker doesn't carry a server-side timestamp; downstream code
	// should fall back to client-arrival time in that case.
	Timestamp time.Time `json:"timestamp,omitempty"`
}

// TickHandler is the canonical callback signature invoked once per
// incoming tick. Registered via Ticker.OnTick(handler). The handler
// runs on the websocket reader goroutine — keep work bounded; offload
// heavy computation (alert evaluation, persistence) to a separate
// goroutine via a channel so a slow handler doesn't stall the stream.
type TickHandler func(Tick)

// Ticker is the broker-agnostic live-tick port. Adapters
// (broker/zerodha/ticker_adapter.go) implement this interface by
// wrapping their broker's streaming SDK; consumers (kc/ticker/
// service.go) depend only on this surface.
//
// Lifecycle:
//
//  1. Construct via a broker-specific factory (e.g.
//     zerodha.NewTickerAdapter).
//  2. Register handlers via On* methods BEFORE the underlying
//     transport connects — the OnConnect handler is the right place
//     to call Subscribe/SetMode for the initial token set.
//  3. Adapter starts the underlying transport (typically
//     adapter-internal — the consumer doesn't need to call ServeWith-
//     Context or similar).
//  4. Subscribe / Unsubscribe / SetMode mutate the active subscription
//     set; calls before connection are queued and applied in
//     OnConnect, matching the Zerodha kiteticker behaviour kc/ticker/
//     service.go's resubscribe-on-reconnect logic depends on.
//  5. Close releases the transport and unblocks any internal goroutines.
//
// All methods are safe to call concurrently — adapters guard internal
// state with appropriate locks.
type Ticker interface {
	// Subscribe queues the given instrument tokens for live-tick
	// delivery. If the underlying transport is connected, takes effect
	// immediately; otherwise applied in the OnConnect callback.
	Subscribe(tokens []uint32) error

	// Unsubscribe stops live-tick delivery for the given tokens.
	// Idempotent — unsubscribing tokens that were never subscribed
	// returns nil error.
	Unsubscribe(tokens []uint32) error

	// SetMode changes the subscription mode for the given tokens.
	// Tokens not currently subscribed are subscribed implicitly at the
	// new mode (matches Zerodha kiteticker behaviour).
	SetMode(mode Mode, tokens []uint32) error

	// OnTick registers the per-tick callback. Replaces any prior
	// handler — only the most-recently-registered handler fires.
	OnTick(handler TickHandler)

	// OnConnect registers a callback invoked when the underlying
	// transport completes its initial handshake (or successfully
	// reconnects). Adapters call the handler synchronously on the
	// transport goroutine; consumers must not block.
	OnConnect(handler func())

	// OnError registers a callback for transport-level errors that
	// don't terminate the connection. Handler is invoked once per
	// error; adapters MAY coalesce rapid-fire errors.
	OnError(handler func(error))

	// OnClose registers a callback invoked when the transport closes.
	// Code is the broker-specific close code; reason is a free-form
	// string. Adapters that don't carry close codes should pass 0 +
	// the human-readable reason.
	OnClose(handler func(code int, reason string))

	// OnReconnect registers a callback invoked when the adapter
	// schedules a reconnect attempt. Attempt is 1-indexed; delay is
	// the backoff before the next attempt.
	OnReconnect(handler func(attempt int, delay time.Duration))

	// OnNoReconnect registers a callback invoked when the adapter has
	// exhausted its reconnect budget and stops trying. Attempt is the
	// final attempt count.
	OnNoReconnect(handler func(attempt int))

	// Close releases the underlying transport and unblocks any
	// internal goroutines. Safe to call multiple times — second and
	// subsequent calls return nil. After Close, the Ticker is
	// terminal; consumers that need a fresh connection construct a
	// new adapter via the factory.
	Close() error
}
