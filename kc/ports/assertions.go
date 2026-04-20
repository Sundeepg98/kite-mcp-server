package ports

import "github.com/zerodha/kite-mcp-server/kc"

// Compile-time satisfaction checks. Each bounded-context port must be
// implemented by *kc.Manager — if a Manager method signature drifts,
// the build fails here rather than at a consumer site.
//
// These live in kc/ports (not in kc) so that kc stays free of
// ports-package imports; only ports imports kc, keeping the graph
// acyclic.
var (
	_ SessionPort    = (*kc.Manager)(nil)
	_ CredentialPort = (*kc.Manager)(nil)
	_ AlertPort      = (*kc.Manager)(nil)
	_ OrderPort      = (*kc.Manager)(nil)
)
