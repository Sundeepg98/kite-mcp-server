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
// from outside (kc.SessionService, kc.pinnedBrokerResolver,
// mcp.sessionBrokerResolver, test mocks). Putting it under kc/ports
// would mean kc/usecases imports kc/ports, which inverts the hexagonal
// dependency direction — the inner ring (use cases) would depend on a
// package that itself imports kc (the outer ring).

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
//	  - *kc.SessionService.GetBrokerForEmail (production fallback) —
//	    looks up the email in the credential store; returns an error
//	    when no token is cached.
//	  - *kc.pinnedBrokerResolver.GetBrokerForEmail (per-request
//	    optimization) — IGNORES the email and returns its
//	    pre-resolved client; safe because the caller has already
//	    bound the client to the request session.
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
//	The port itself has no sentinel — it is email-keyed, not
//	ctx-keyed. The "no pinned broker on ctx" decision is made
//	UPSTREAM at *kc.Manager.resolverFromContext(ctx) (kc/broker_context.go),
//	which returns either &pinnedBrokerResolver{ctx-bound} or
//	m.sessionSvc as the BrokerResolver. From the use case's
//	perspective, both flavors satisfy the same port; the only
//	observable difference is the pinned variant ignores the email.
//	Wave D Slice D7 removes the resolverFromContext fork; after that,
//	use cases ALWAYS receive m.sessionSvc as their resolver and the
//	per-request optimization is dropped (~100ns extra map read per
//	command — see .research/wave-d-resolver-refactor-plan.md §5).
//
// IMPLEMENTATIONS (as of Slice D1)
//
//	Production:
//	  - *kc.SessionService           (kc/session_service.go:541)
//	  - *kc.pinnedBrokerResolver     (kc/broker_context.go:51, slated
//	                                   for removal in Slice D7)
//	  - *mcp.sessionBrokerResolver   (mcp/post_tools.go:19, used by
//	                                   WithTokenRefresh and similar
//	                                   pre-dispatch session probes;
//	                                   out of scope for Wave D Phase 1)
//
//	Tests:
//	  - mockBrokerResolver           (kc/usecases/mocks_test.go:62)
//	  - brokerResolverTestImpl       (kc/usecases/ports_test.go,
//	                                   test-only, mirrors the
//	                                   pinned variant's "ignore-email"
//	                                   shape for contract coverage)
type BrokerResolver interface {
	GetBrokerForEmail(email string) (broker.Client, error)
}
