package mcp

import (
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
// LoggerPort field carries the kc/logger.Logger port. The duplicate
// slog Logger field was retired during the SOLID 99→100 deprecation-
// shim sweep — all 58 consumer call sites migrated through Wave D
// Packages 6b-6e already use LoggerPort with ctx threading.
type ReadDepsFields struct {
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
