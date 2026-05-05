package mcp

import "github.com/algo2go/kite-mcp-broker"

// sessionBrokerResolver is the legacy in-mcp-package adapter retained
// purely for tools_validation_test.go's pre-PR-1.5 test fixture.
// Anchor 1 PR 1.5: the original lived in mcp/post_tools.go which
// moved to mcp/trade. mcp/common has its own (unrelated) copy via
// PR 1.1. This local copy preserves the test ergonomic without
// cross-package import.
type sessionBrokerResolver struct {
	client broker.Client
}

func (r *sessionBrokerResolver) GetBrokerForEmail(_ string) (broker.Client, error) {
	return r.client, nil
}
