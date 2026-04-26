package mcp

import (
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc"
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
type ReadDepsFields struct {
	Logger      *slog.Logger
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
		Metrics:     manager,
		Config:      manager,
		CommandBusP: manager,
		QueryBusP:   manager,
		Watchlist:   manager,
		Ticker:      manager,
		Instruments: manager,
	}
}
