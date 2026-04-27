package mcp

import (
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// ReadDepsFields is the read/observability-context subset of
// ToolHandlerDeps: cross-cutting infrastructure (logger, metrics,
// app config) plus read-side services (CQRS bus pair, watchlist,
// ticker, instruments) that read tools depend on uniformly.
//
// Adding a new pure-read port here does NOT collide with session,
// alert, order, or admin agent edits.
//
// Investment K — see session_deps.go for rationale.
//
// Wave D Phase 3 Package 6a (Logger sweep): both Logger (slog-typed,
// deprecated) and LoggerPort (kc/logger.Logger port) are populated
// from the same source. The 58 unmigrated `deps.Logger.X(...)` call
// sites continue compiling against the slog field; sub-commits
// 6b-6e migrate them to the ctx-aware LoggerPort surface. After all
// consumers migrate, the slog Logger field is removed.
type ReadDepsFields struct {
	Logger      *slog.Logger // Deprecated: use LoggerPort
	LoggerPort  logport.Logger
	Metrics     kc.MetricsRecorder
	Config      kc.AppConfigProvider
	CommandBusP kc.CommandBusProvider
	QueryBusP   kc.QueryBusProvider
	Watchlist   kc.WatchlistStoreProvider
	Ticker      kc.TickerServiceProvider
	Instruments kc.InstrumentsManagerProvider
}

func newReadDeps(manager *kc.Manager) ReadDepsFields {
	return ReadDepsFields{
		Logger:      manager.Logger,
		LoggerPort:  logport.NewSlog(manager.Logger),
		Metrics:     manager,
		Config:      manager,
		CommandBusP: manager,
		QueryBusP:   manager,
		Watchlist:   manager,
		Ticker:      manager,
		Instruments: manager,
	}
}
