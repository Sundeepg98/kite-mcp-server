// Package ports — credential-port leaf-stability assertion test.
//
// Anchor 5 PR 5.1 (per .research/anchor-5-prs-design.md): pins the
// invariant that kc/ports/credential.go is ALREADY-INVERTED — it has
// no `import "github.com/zerodha/kite-mcp-server/kc"` (parent kc
// package) line. credential.go is the only one of the 6 port files
// today that satisfies this invariant; alert.go, instrument.go,
// order.go, session.go, and assertions.go all still import the kc
// parent (intentional in some cases — see anchor-5-prs-design.md
// table at lines 32-42).
//
// The eventual Wave B-3 close-out test (PR 5.8) will generalise this
// pattern to assert leaf-stability across alert.go + credential.go
// + instrument.go + session.go (4 of 6 ports — assertions.go and
// order.go intentionally retain their kc-parent imports per the
// audit's design at PR 5.7). This PR establishes the pattern in
// 1-port-scope so the generalised test is built on proven scaffolding.
//
// Why test source-level imports rather than `go list -deps`? Because
// `go list -deps` returns the TRANSITIVE closure — credential.go's
// transitive set includes kc parent today only because OTHER files
// in the kc/ports package (alert.go, session.go, assertions.go) still
// import kc. The leaf-stability invariant for credential.go is a
// FILE-level claim, not a package-level one. We assert it by parsing
// credential.go's import block via go/parser and checking the import
// paths directly.
package ports_test

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// TestCredentialPortLeafStability asserts that kc/ports/credential.go
// does NOT import the kc parent package. This is the empirical
// invariant cited in kc/ports/session.go:1-15 ("kc package does NOT
// import kc/ports — so the import graph stays acyclic") seen from
// the credential file's own perspective: credential.go is the one
// port file already free of the kc-parent dependency.
//
// Adding `import "github.com/zerodha/kite-mcp-server/kc"` to
// credential.go fails this test — the contributor must justify why
// the credential port needs to reach into the kc parent before
// landing the change.
func TestCredentialPortLeafStability(t *testing.T) {
	const target = "github.com/zerodha/kite-mcp-server/kc"

	path, err := filepath.Abs("credential.go")
	if err != nil {
		t.Fatalf("resolve credential.go path: %v", err)
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse credential.go imports: %v", err)
	}

	for _, imp := range file.Imports {
		// imp.Path.Value is the quoted import path, e.g. `"context"`.
		// Strip the surrounding quotes for comparison.
		if len(imp.Path.Value) < 2 {
			continue
		}
		path := imp.Path.Value[1 : len(imp.Path.Value)-1]
		if path == target {
			t.Errorf("credential.go imports kc parent (%q) — leaf-stability invariant broken; see anchor-5-prs-design.md PR 5.1", target)
		}
	}
}
