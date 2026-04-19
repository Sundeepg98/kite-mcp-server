package kc

import (
	"log/slog"
	"sync"
	"time"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/domain"
	"github.com/zerodha/kite-mcp-server/testutil"
)

// fill_watcher.go — real-flow bridge for domain.OrderFilledEvent.
//
// Problem
// -------
// OrderFilledEvent is dispatched from paper trading (kc/papertrading) but
// never from the live Kite flow, because the Kite REST API reports fills
// via polling get_orders rather than via a push callback. That left a
// gap in the domain audit log: real trades enter with OrderPlacedEvent
// and then vanish from the event stream until a human refreshes the
// dashboard.
//
// Design
// ------
// FillWatcher is a stopgap poller. For every OrderPlacedEvent dispatched
// on the domain event bus, it launches a short-lived goroutine that
// polls broker.OrderManager.GetOrderHistory at PollInterval. When the
// history reaches a terminal "COMPLETE" status, the watcher dispatches
// OrderFilledEvent exactly once and exits. If MaxDuration expires first,
// the goroutine gives up — we accept that very slow fills will be
// invisible until a real push channel is wired.
//
// Why not a Scheduler TaskProvider?
// ---------------------------------
// scheduler.Task is IST-time-of-day + trading-day deduplication — the
// right fit for "9:00 AM morning brief" and "3:35 PM EOD summary".
// Fill polling is per-order, 5s-interval, 60s-budget — a fundamentally
// different cadence. Running 12 five-second polls inside a 60-second
// Scheduler tick would break the scheduler's "tasks are fixed at Start"
// invariant (new orders arrive continuously) and the "one fire per
// trading day" dedup (we want one fire per order).
//
// Resource cost
// -------------
// Each placed order launches one goroutine for at most MaxDuration
// (default 60s), doing one HTTP call per PollInterval (default 5s). For
// a 100-order/minute burst that is 100 concurrent goroutines × 12 calls
// = 1200 GetOrderHistory calls peak. Kite's per-user rate cap is 10/sec,
// so we back this off if needed (future work); today's trading volumes
// are well below that ceiling.
//
// Stopgap disclaimer
// ------------------
// This file is intentionally a stopgap. The correct long-term fix is
// either (a) a Kite postback-URL listener or (b) the gokiteconnect
// websocket feed's order-update stream. Both require server-side
// infrastructure outside this package. Until then, polling is the
// pragmatic answer; mark removal as a follow-up when either (a) or
// (b) lands.

// FillWatcherBroker is the narrow broker surface the watcher depends on.
// Satisfied by broker.Client (which embeds broker.OrderManager). Tests
// use a hand-rolled fake instead of the full broker/mock — the
// GetOrderHistory-only dependency is intentional.
type FillWatcherBroker interface {
	GetOrderHistory(orderID string) ([]broker.Order, error)
}

// FillWatcherBrokerResolver resolves a FillWatcherBroker by email.
// In production this is satisfied by SessionService.GetBrokerForEmail —
// see app/wire.go for the adapter. Tests can return a fake broker
// directly without resolving through the session service.
type FillWatcherBrokerResolver interface {
	GetBrokerForEmail(email string) (FillWatcherBroker, error)
}

// staticBrokerResolver always returns the same broker regardless of
// email. Used by tests that exercise the poll loop directly without
// session plumbing.
type staticBrokerResolver struct{ b FillWatcherBroker }

func (r staticBrokerResolver) GetBrokerForEmail(_ string) (FillWatcherBroker, error) {
	return r.b, nil
}

// sessionSvcBrokerAdapter adapts *SessionService to FillWatcherBrokerResolver.
// SessionService.GetBrokerForEmail returns broker.Client, which already
// satisfies FillWatcherBroker (broker.Client embeds broker.OrderManager
// which supplies GetOrderHistory), but Go interface rules require
// exact return-type match so we provide a 3-line adapter here.
type sessionSvcBrokerAdapter struct{ s *SessionService }

func (a sessionSvcBrokerAdapter) GetBrokerForEmail(email string) (FillWatcherBroker, error) {
	return a.s.GetBrokerForEmail(email)
}

// FillWatcherResolverFromSessionSvc returns a FillWatcherBrokerResolver
// backed by a SessionService. Factored into a named constructor so
// app/wire.go has an explicit, named API rather than passing an ad-hoc
// struct literal.
func FillWatcherResolverFromSessionSvc(s *SessionService) FillWatcherBrokerResolver {
	if s == nil {
		return nil
	}
	return sessionSvcBrokerAdapter{s: s}
}

// FillWatcherConfig is the constructor payload. All fields are required
// except PollInterval/MaxDuration, which default to 5s and 60s.
//
// Exactly one of Broker or Resolver must be set. Broker wraps a single
// static broker in a resolver for tests; production callers pass a real
// per-email Resolver.
type FillWatcherConfig struct {
	Broker       FillWatcherBroker
	Resolver     FillWatcherBrokerResolver
	Dispatcher   *domain.EventDispatcher
	Logger       *slog.Logger
	Clock        testutil.Clock // nil => testutil.RealClock{}
	PollInterval time.Duration  // default: 5 * time.Second
	MaxDuration  time.Duration  // default: 60 * time.Second
}

// FillWatcher polls the broker for order completion and dispatches
// OrderFilledEvent. Safe for concurrent Watch calls — each invocation
// spawns its own goroutine, and the dispatcher is itself concurrency-
// safe. See fill_watcher_test.go for the contract.
type FillWatcher struct {
	resolver     FillWatcherBrokerResolver
	dispatcher   *domain.EventDispatcher
	logger       *slog.Logger
	clock        testutil.Clock
	pollInterval time.Duration
	maxDuration  time.Duration

	// wg tracks goroutines so Wait() can synchronise in tests without
	// resorting to blanket time.Sleeps.
	wg sync.WaitGroup
}

// NewFillWatcher constructs a FillWatcher from config. Callers must
// separately invoke Start() to wire the OrderPlacedEvent subscription,
// or drive Watch() directly for tight control in tests.
//
// If Resolver is nil but Broker is non-nil, the broker is wrapped in a
// static resolver (useful for tests). Either form requires Dispatcher
// and Logger.
func NewFillWatcher(cfg FillWatcherConfig) *FillWatcher {
	clock := cfg.Clock
	if clock == nil {
		clock = testutil.RealClock{}
	}
	pollInterval := cfg.PollInterval
	if pollInterval <= 0 {
		pollInterval = 5 * time.Second
	}
	maxDuration := cfg.MaxDuration
	if maxDuration <= 0 {
		maxDuration = 60 * time.Second
	}
	resolver := cfg.Resolver
	if resolver == nil && cfg.Broker != nil {
		resolver = staticBrokerResolver{b: cfg.Broker}
	}
	return &FillWatcher{
		resolver:     resolver,
		dispatcher:   cfg.Dispatcher,
		logger:       cfg.Logger,
		clock:        clock,
		pollInterval: pollInterval,
		maxDuration:  maxDuration,
	}
}

// Start subscribes the watcher to domain.OrderPlacedEvent so every
// placed order automatically spawns a poll goroutine. Idempotent only
// across distinct Dispatchers — subscribing twice to the same
// dispatcher will produce two goroutines per event.
func (w *FillWatcher) Start() {
	if w.dispatcher == nil {
		return
	}
	w.dispatcher.Subscribe("order.placed", func(e domain.Event) {
		placed, ok := e.(domain.OrderPlacedEvent)
		if !ok {
			return
		}
		w.Watch(placed)
	})
}

// Watch spawns a goroutine that polls the broker for the given order.
// Returns immediately — callers that need to synchronise should use
// Wait().
//
// The ticker is created on the caller goroutine (before we spawn the
// poll loop) so tests using testutil.FakeClock have a happens-before
// guarantee that the first Advance() will find a registered ticker.
// If the ticker were created inside the goroutine, a race between
// test-thread Advance and goroutine NewTicker would silently drop
// the first tick.
func (w *FillWatcher) Watch(placed domain.OrderPlacedEvent) {
	if w.resolver == nil || w.dispatcher == nil {
		return
	}
	if placed.OrderID == "" {
		return
	}
	ticker := w.clock.NewTicker(w.pollInterval)
	w.wg.Add(1)
	go w.pollLoop(placed, ticker)
}

// Wait blocks until every in-flight poll goroutine has exited, or the
// timeout fires (whichever comes first). Primary use is test
// synchronisation — production code should not call this.
func (w *FillWatcher) Wait(timeout time.Duration) {
	done := make(chan struct{})
	go func() {
		w.wg.Wait()
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(timeout):
	}
}

// pollLoop runs until the order reaches a terminal COMPLETE state or
// the MaxDuration budget is exhausted. Transient broker errors are
// logged and swallowed — the poller exists to tolerate the exact
// failure modes (rate limit, timeouts) that would cause a caller to
// abandon the fill notification entirely.
//
// ticker is owned here — Watch creates it on the caller goroutine for
// the FakeClock race-safety reason documented on Watch. The loop
// stops the ticker on any exit path.
func (w *FillWatcher) pollLoop(placed domain.OrderPlacedEvent, ticker testutil.Ticker) {
	defer w.wg.Done()

	start := w.clock.Now()
	deadline := start.Add(w.maxDuration)
	defer ticker.Stop()

	// Resolve the broker once up-front. If resolution fails (e.g. user
	// session already terminated by the time the event drains), there
	// is nothing to poll — exit silently.
	bc, berr := w.resolver.GetBrokerForEmail(placed.Email)
	if berr != nil || bc == nil {
		w.logger.Debug("FillWatcher: no broker for email, skipping",
			"order_id", placed.OrderID,
			"email", placed.Email,
		)
		return
	}

	for {
		select {
		case <-ticker.C():
			// Budget check runs before each poll — we refuse to issue a
			// new HTTP call once the wall-clock (fake or real) exceeds
			// the deadline. This is how the "12 polls for a 60s budget"
			// contract is enforced deterministically.
			now := w.clock.Now()
			if !now.Before(deadline) {
				w.logger.Debug("FillWatcher: budget exhausted, giving up",
					"order_id", placed.OrderID,
					"email", placed.Email,
				)
				return
			}

			history, err := bc.GetOrderHistory(placed.OrderID)
			if err != nil {
				// Transient failure: log at info (not error) because
				// rate limits during peak trading are expected, and
				// continue polling until budget runs out.
				w.logger.Info("FillWatcher: poll failed, retrying",
					"order_id", placed.OrderID,
					"email", placed.Email,
					"error", err.Error(),
				)
				continue
			}

			latest := latestComplete(history)
			if latest == nil {
				continue
			}

			// Terminal COMPLETE reached — fire the event and exit.
			// We do not consult the domain.Order rich type here because
			// Quantity values that hit the bus must pass NewQuantity's
			// positive-only validation; a zero-filled order would still
			// be "terminal" but carries no fill to report.
			qty, qerr := domain.NewQuantity(latest.FilledQuantity)
			if qerr != nil {
				w.logger.Warn("FillWatcher: invalid filled qty, not dispatching",
					"order_id", placed.OrderID,
					"filled_qty", latest.FilledQuantity,
					"error", qerr.Error(),
				)
				return
			}
			w.dispatcher.Dispatch(domain.OrderFilledEvent{
				Email:       placed.Email,
				OrderID:     placed.OrderID,
				FilledQty:   qty,
				FilledPrice: domain.NewINR(latest.AveragePrice),
				Timestamp:   w.clock.Now().UTC(),
			})
			return
		}
	}
}

// latestComplete returns the last COMPLETE entry in an order history
// slice, or nil if none is terminal. Kite's GetOrderHistory returns
// state transitions oldest-first, so the last COMPLETE entry carries
// the final fill price and quantity. Uses the domain.Order wrapper
// for status classification so the "complete-ness" rule stays in one
// place.
func latestComplete(history []broker.Order) *broker.Order {
	for i := len(history) - 1; i >= 0; i-- {
		if domain.NewOrderFromBroker(history[i]).IsComplete() {
			h := history[i]
			return &h
		}
	}
	return nil
}
