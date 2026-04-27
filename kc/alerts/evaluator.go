package alerts

import (
	"context"
	"log/slog"

	"github.com/zerodha/gokiteconnect/v4/models"

	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// Evaluator checks incoming ticks against active alerts.
//
// Wave D Phase 3 Package 4 (Logger sweep): logger is typed as the
// kc/logger.Logger port. NewEvaluator takes *slog.Logger for caller
// compatibility (kc/manager_init.go) and converts at the boundary
// via logport.NewSlog. Internal log calls use context.Background()
// — Evaluator is invoked from a long-lived ticker goroutine with
// no request ctx in scope.
type Evaluator struct {
	store  *Store
	logger logport.Logger
}

// NewEvaluator creates a new alert evaluator.
func NewEvaluator(store *Store, logger *slog.Logger) *Evaluator {
	return &Evaluator{
		store:  store,
		logger: logport.NewSlog(logger),
	}
}

// Evaluate checks if a tick triggers any active alerts for the given instrument.
func (e *Evaluator) Evaluate(email string, tick models.Tick) {
	alerts := e.store.GetByToken(tick.InstrumentToken)
	if len(alerts) == 0 {
		return
	}

	for _, alert := range alerts {
		if alert.ShouldTrigger(tick.LastPrice) {
			if !e.store.MarkTriggered(alert.ID, tick.LastPrice) { // COVERAGE: unreachable without race — GetByToken filters triggered alerts; only reachable if another goroutine triggers between GetByToken and MarkTriggered
				continue
			}

			logAttrs := []any{
				"alert_id", alert.ID,
				"email", alert.Email,
				"instrument", alert.Exchange + ":" + alert.Tradingsymbol,
				"target", alert.TargetPrice,
				"current", tick.LastPrice,
				"direction", alert.Direction,
			}
			if alert.IsPercentageAlert() {
				logAttrs = append(logAttrs, "reference_price", alert.ReferencePrice)
			}
			e.logger.Info(context.Background(), "Alert triggered", logAttrs...)

			if e.store.onNotify != nil {
				e.store.onNotify(alert, tick.LastPrice)
			}
		}
	}
}

