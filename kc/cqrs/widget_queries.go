package cqrs

import "context"

// widget_queries.go lands the final batch of the cqrs-keystone migration:
// the four MCP App widget DataFuncs in mcp/ext_apps.go previously
// constructed use cases directly (usecases.NewXxxForWidgetUseCase(...)
// .Execute). These four Query types are dispatched on the QueryBus so the
// widget calls inherit the same observability, logging, and latency
// tracking as every other read-side tool.
//
// Naming deliberately mirrors the use case type names
// (NewGetPortfolioForWidgetUseCase → GetPortfolioForWidgetQuery) rather
// than the older GetWidgetXxxQuery set in queries.go. The old structs are
// kept because the use cases still consume them internally; the Query
// types here are the public bus contract.

// GetPortfolioForWidgetQuery requests portfolio data formatted for the
// portfolio widget (holdings + positions + summary).
type GetPortfolioForWidgetQuery struct {
	Email string `json:"email"`
}

// GetActivityForWidgetQuery requests recent audit-trail entries for the
// activity widget. Limit caps the number of entries returned; when zero,
// the handler applies the default (20 entries, 7-day window).
type GetActivityForWidgetQuery struct {
	Email string `json:"email"`
	Limit int    `json:"limit,omitempty"`
}

// GetOrdersForWidgetQuery requests recent order tool-calls enriched with
// broker status for the orders widget.
type GetOrdersForWidgetQuery struct {
	Email string `json:"email"`
}

// GetAlertsForWidgetQuery requests alerts enriched with current LTP for
// the alerts widget.
type GetAlertsForWidgetQuery struct {
	Email string `json:"email"`
}

// widgetAuditStoreCtxKey carries a per-dispatch audit store so the widget
// QueryBus handlers can honor a test-supplied store that isn't attached to
// the Manager. The pattern mirrors nativeAlertClientCtxKey (see
// queries_remaining.go): widget tests construct a local audit store and
// pass it here; production callers rely on the Manager's attached store.
type widgetAuditStoreCtxKey struct{}

// WithWidgetAuditStore attaches an audit store (typed as any to avoid an
// import cycle with kc/audit) to the context so widget QueryBus handlers
// can reach a test-scoped store.
func WithWidgetAuditStore(ctx context.Context, store any) context.Context {
	if ctx == nil || store == nil {
		return ctx
	}
	return context.WithValue(ctx, widgetAuditStoreCtxKey{}, store)
}

// WidgetAuditStoreFromContext returns the audit store attached by
// WithWidgetAuditStore, or nil if none was attached.
func WidgetAuditStoreFromContext(ctx context.Context) any {
	if ctx == nil {
		return nil
	}
	return ctx.Value(widgetAuditStoreCtxKey{})
}
