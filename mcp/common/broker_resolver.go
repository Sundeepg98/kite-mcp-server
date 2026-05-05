package common

import (
	"github.com/algo2go/kite-mcp-broker"
)

// sessionBrokerResolver wraps an already-resolved broker.Client so that
// usecases.BrokerResolver can be satisfied without a second credential lookup.
// This is the per-request adapter created inside WithSession callbacks.
//
// Anchor 1 PR 1.1 (Option B): relocated from mcp/post_tools.go because
// handler_methods.go's WithTokenRefresh constructs one inline. Keeping
// it co-located with the only consumer in mcp/common avoids an import
// of the mcp parent package back into common.
type sessionBrokerResolver struct {
	client broker.Client
}

func (r *sessionBrokerResolver) GetBrokerForEmail(_ string) (broker.Client, error) {
	return r.client, nil
}
