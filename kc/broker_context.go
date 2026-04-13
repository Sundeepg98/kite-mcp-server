package kc

import (
	"context"

	"github.com/zerodha/kite-mcp-server/broker"
	"github.com/zerodha/kite-mcp-server/kc/usecases"
)

// brokerCtxKey is an unexported context key used to pass a
// session-pinned broker.Client from the MCP tool layer into CQRS
// CommandBus handlers without a second credential lookup.
//
// The mcp package's tool handlers already resolve the per-session
// broker inside WithSession; instead of throwing that away at the
// bus boundary and re-resolving via SessionService, we stash the
// resolved client on ctx so the manager-side CommandBus handler
// can wrap it in a one-off resolver before constructing the use
// case. This preserves the sessionBrokerResolver optimization and
// keeps the "do not move session plumbing into kc/" rule from
// path-to-100.md intact.
type brokerCtxKey struct{}

// WithBroker returns a new context carrying the given broker.Client.
// Tool handlers call this immediately before dispatching a write
// command on the CommandBus so the handler can pick up the already-
// resolved client.
func WithBroker(ctx context.Context, client broker.Client) context.Context {
	if ctx == nil || client == nil {
		return ctx
	}
	return context.WithValue(ctx, brokerCtxKey{}, client)
}

// BrokerFromContext returns the session-pinned broker.Client
// previously attached via WithBroker, or nil if none is present.
// CommandBus handlers use this to build a one-off usecases.BrokerResolver
// that returns the pre-resolved client without a repeat lookup.
func BrokerFromContext(ctx context.Context) broker.Client {
	if ctx == nil {
		return nil
	}
	c, _ := ctx.Value(brokerCtxKey{}).(broker.Client)
	return c
}

// pinnedBrokerResolver satisfies usecases.BrokerResolver by
// returning a pre-resolved broker.Client regardless of which email
// is passed in. It is only instantiated on the hot path of a write
// command whose ctx carries a broker via WithBroker.
type pinnedBrokerResolver struct {
	client broker.Client
}

func (r *pinnedBrokerResolver) GetBrokerForEmail(_ string) (broker.Client, error) {
	return r.client, nil
}

// resolverFromContext returns a usecases.BrokerResolver derived
// from the session-pinned client on ctx. When no client is
// attached, it falls back to the manager's SessionService so the
// handler still works for callers (e.g., tests) that dispatch
// directly without touching the MCP layer.
func (m *Manager) resolverFromContext(ctx context.Context) usecases.BrokerResolver {
	if c := BrokerFromContext(ctx); c != nil {
		return &pinnedBrokerResolver{client: c}
	}
	return m.sessionSvc
}
