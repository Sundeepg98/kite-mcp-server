package cqrs

import "context"

// queries_remaining.go supports the batch-D QueryBus migration (read tools →
// QueryBus). All 22 migrated tools reuse Query types already defined in
// queries.go / queries_ext.go — no new Query types land here.
//
// A handful of read tools require per-request, session-scoped collaborators
// (e.g. a broker-specific NativeAlertClient assembled from the active Kite
// session). Because dispatcher signatures are (ctx, msg), these collaborators
// ride on the context via the helpers below. Handlers registered on the bus
// pull them out; if absent, they return a descriptive error.

// nativeAlertClientCtxKey is the context key carrying a NativeAlertClient
// for native alert queries dispatched through the QueryBus.
type nativeAlertClientCtxKey struct{}

// WithNativeAlertClient attaches a NativeAlertClient (typed as any to avoid
// an import cycle with kc/usecases) to the context so the QueryBus handler
// for ListNativeAlertsQuery / GetNativeAlertHistoryQuery can reach it.
func WithNativeAlertClient(ctx context.Context, client any) context.Context {
	return context.WithValue(ctx, nativeAlertClientCtxKey{}, client)
}

// NativeAlertClientFromContext returns the NativeAlertClient attached by
// WithNativeAlertClient, or nil if none was attached.
func NativeAlertClientFromContext(ctx context.Context) any {
	if v := ctx.Value(nativeAlertClientCtxKey{}); v != nil {
		return v
	}
	return nil
}
