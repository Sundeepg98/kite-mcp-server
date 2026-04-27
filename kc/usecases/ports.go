package usecases

import "github.com/zerodha/kite-mcp-server/broker"

// ports.go is the architectural anchor for use-case-level interface
// contracts (hexagonal "driven" ports — what the use case requires of
// its collaborators). Wave D Phase 1 introduces this file as the home
// for BrokerResolver; subsequent waves may consolidate other ports
// here as their consumer surface stabilises.
//
// Why not in kc/ports? That package holds bounded-context interfaces
// the *Manager* satisfies — its consumers are tool handlers reaching
// across context boundaries (mcp/, kc/ops/). BrokerResolver is the
// inverse: a port USE CASES depend on, with implementations supplied
// from outside (kc.SessionService, mcp.sessionBrokerResolver, test
// mocks). Putting it under kc/ports would mean kc/usecases imports
// kc/ports, which inverts the hexagonal dependency direction — the
// inner ring (use cases) would depend on a package that itself
// imports kc (the outer ring).

// BrokerResolver resolves a broker.Client for a given user email.
//
// CONTRACT
//
// Signature:
//
//	GetBrokerForEmail(email string) (broker.Client, error)
//
// Return semantics:
//
//	(client, nil) — successful resolution. The returned client is
//	  ready to use. Implementations MAY return the same client
//	  instance for repeated calls (cache hits) or a fresh instance
//	  per call (cold construction); use cases MUST NOT assume
//	  identity across invocations.
//
//	(nil, err)   — resolution failed. The error MUST be non-nil and
//	  the client MUST be nil. Use cases wrap and propagate; they do
//	  NOT retry at the port level. Common error shapes today:
//	    - "no Kite access token for {email}" — user not authed
//	    - broker-factory construction failure
//	    - downstream credential-store lookup error
//
// Email argument:
//
//	The port DOES NOT mandate an email-validity check. Implementations
//	differ:
//	  - *kc.SessionService.GetBrokerForEmail (production) — looks up
//	    the email first in the active-session map (in-memory hit) and
//	    falls back to credential-store + token-store reconstruction.
//	    Returns an error when no token is cached for the email.
//	  - *mcp.sessionBrokerResolver.GetBrokerForEmail (mcp pre-dispatch)
//	    — IGNORES the email and returns its pre-resolved client. Used
//	    only by ToolHandler.WithTokenRefresh for the cheap profile-
//	    probe outside the bus; bus-routed handlers always reach the
//	    SessionService impl above.
//	  - test mocks (kc/usecases/mocks_test.go mockBrokerResolver) —
//	    pass the email through; behaviour follows the test fixture's
//	    configured client/error pair.
//
//	Use cases that need email-shape validation (non-empty, well-formed)
//	MUST validate before calling GetBrokerForEmail. The port itself
//	is pass-through.
//
// Thread-safety:
//
//	Implementations MUST be safe for concurrent calls from multiple
//	goroutines. The bus dispatches commands and queries from the MCP
//	tool layer's per-request goroutines; a use case constructed once
//	at startup (Wave D's eventual end-state) sees its resolver hit
//	from N concurrent request paths simultaneously. Production
//	implementations honor this via internal mutex / sync.Map; test
//	mocks should as well if exercised under -race.
//
// Lifetime:
//
//	The resolver is constructed once per Manager (production) or per
//	test fixture, and lives for the Manager's lifetime. Use cases
//	hold the interface value, not a pointer-to-interface — replacing
//	the resolver implementation requires reconstructing the use case.
//	(Wave D Slice D-final wires this through Wire/fx providers; until
//	then, manager_init.go is the construction site.)
//
// "No broker for this ctx" sentinel:
//
//	The port has no sentinel — it is email-keyed, not ctx-keyed. After
//	Wave D Slice D7, ctx no longer carries a per-request broker; every
//	bus-routed use case receives m.sessionSvc as its BrokerResolver
//	at construction time and reaches the broker via the SessionService
//	in-memory active-session map (cost: one in-memory map lookup per
//	dispatch, ~100 ns; see .research/wave-d-resolver-refactor-plan.md
//	§5). The previous WithBroker / pinnedBrokerResolver / resolverFromContext
//	machinery has been removed (commit at end of Wave D Phase 1).
//
// IMPLEMENTATIONS
//
//	Production:
//	  - *kc.SessionService           (kc/session_service.go:541)
//	  - *mcp.sessionBrokerResolver   (mcp/post_tools.go:19, used by
//	                                   WithTokenRefresh and similar
//	                                   pre-dispatch session probes;
//	                                   out of scope for Wave D Phase 1)
//
//	Tests:
//	  - mockBrokerResolver           (kc/usecases/mocks_test.go:62)
//	  - brokerResolverTestImpl       (kc/usecases/ports_test.go,
//	                                   test-only, mirrors the
//	                                   "ignore-email" shape for
//	                                   contract coverage)
type BrokerResolver interface {
	GetBrokerForEmail(email string) (broker.Client, error)
}
