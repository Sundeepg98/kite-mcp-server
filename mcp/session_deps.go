package mcp

import (
	"github.com/zerodha/kite-mcp-server/kc"
	"github.com/zerodha/kite-mcp-server/kc/ports"
)

// SessionDepsFields is the session-context subset of ToolHandlerDeps:
// session lifecycle, credential retrieval, user identity, and token
// storage. Adding a new session-related port should touch ONLY this file
// + the corresponding wire in newSessionDeps below — not the cross-cutting
// ToolHandlerDeps struct in common_deps.go.
//
// Investment K (per .research/agent-concurrency-decoupling-plan.md §K):
// the builder pattern decomposes the previously monolithic NewToolHandler
// constructor so that agents adding a new field per bounded context
// don't collide on common_deps.go. The unified ToolHandlerDeps still
// exists (tests + accessor methods reference it directly), but its
// constructor now composes from per-context builders.
type SessionDepsFields struct {
	Sessions    ports.SessionPort
	Credentials ports.CredentialPort
	UserStore   kc.UserStoreInterface // may be nil
	TokenStore  kc.TokenStoreInterface
	Tokens      kc.TokenStoreProvider
	CredStore   kc.CredentialStoreProvider
	Users       kc.UserStoreProvider
}

// newSessionDeps populates the session-context subset from a Manager.
// *kc.Manager satisfies every port/provider, so the wire is mechanical;
// the value is the bounded-context grouping, which lets per-context
// changes happen without cross-context merge friction.
func newSessionDeps(manager *kc.Manager) SessionDepsFields {
	return SessionDepsFields{
		Sessions:    manager,
		Credentials: manager,
		UserStore:   manager.UserStore(),
		TokenStore:  manager.TokenStore(),
		Tokens:      manager,
		CredStore:   manager,
		Users:       manager,
	}
}
