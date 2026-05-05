// Package ports — full leaf-stability invariant pin (Anchor 5 PR 5.8 — Wave B-3).
//
// Anchor 5 PR 5.8 closes Anchor 5 by pinning the leaf-stability
// invariant for all 4 inverted port files. Wave B-1 (PRs 5.1-5.6,
// shipped in v204+v205) relocated AlertStoreInterface to kc/alerts,
// InstrumentManagerInterface to kc/instruments, and KiteSessionData
// to kc/domain. Wave B-2 (PRs 5.3+5.5+5.7, shipped in v206) rewrote
// alert.go, instrument.go, and session.go to reference the relocated
// types directly, dropping their kc-parent imports.
//
// This test generalises the per-file import-parser pattern that
// credential_leaf_test.go (PR 5.1) established for the single
// already-inverted port. Adding `import "github.com/zerodha/kite-
// mcp-server/kc"` to any of the 4 leaf ports fails this test — the
// contributor must justify why the leaf invariant should be relaxed
// before landing the change.
//
// INTENTIONAL EXCLUSIONS (per anchor-5-prs-design.md PR 5.7):
//
//   - kc/ports/order.go — retains *kc.OrderService reference for
//     now. OrderService is a write-side service type with method
//     receivers that Anchor 6 will redesign as part of the kc-root
//     god-struct cleanup. Inverting it ahead of that cleanup would
//     force a premature OrderService relocation. Tracked in
//     anchor-5-prs-design.md PR 5.7 deliberately.
//
//   - kc/ports/assertions.go — retains kc import to verify that
//     *kc.Manager satisfies all five ports at compile time. The
//     compile-time check can ONLY live in a package that imports kc,
//     and ports is the appropriate location. This is structural — no
//     amount of refactoring will eliminate this single import without
//     moving the assertion to a different package (which would
//     defeat the assertion's locality benefit).
//
// These two exclusions are EXPECTED, not regressions. A separate test
// pins them as still-importing-kc so a future contributor who tries
// to "clean up" the imports doesn't accidentally remove a load-bearing
// reference.
//
// Why test source-level imports rather than `go list -deps`? Because
// `go list -deps` returns the TRANSITIVE closure — each leaf port's
// transitive set includes kc parent today only because OTHER files
// in the kc/ports package (order.go, assertions.go) still import kc.
// The leaf-stability invariant is a FILE-level claim, not a package-
// level one. We assert it by parsing each file's import block via
// go/parser and checking the import paths directly.
package ports_test

import (
	"go/parser"
	"go/token"
	"path/filepath"
	"testing"
)

// kcParentImportPath is the canonical import path of the kc parent
// package — the leaf-stability target.
const kcParentImportPath = "github.com/zerodha/kite-mcp-server/kc"

// leafPorts lists the four port files that MUST be free of any
// `import "github.com/zerodha/kite-mcp-server/kc"` line. Adding to
// this list (e.g., when order.go's kc dependency is severed in
// Anchor 6) requires a paired update to expectedKcImporters below.
// Anchor 6 PR 6.8: order.go promoted to leafPorts list when
// Manager.OrderSvc() was deleted. The OrderPort interface dropped
// its OrderSvc() *kc.OrderService method (the only thing that
// required the kc-parent import); OrderPort now contains only the
// RiskGuard() *riskguard.Guard method which doesn't need kc-parent.
var leafPorts = []string{
	"alert.go",
	"credential.go",
	"instrument.go",
	"order.go",
	"session.go",
}

// expectedKcImporters lists the port files that INTENTIONALLY retain
// their kc-parent import per anchor-5-prs-design.md PR 5.7. Tested
// for completeness — if a future contributor accidentally removes one
// of these imports, the corresponding compile-time check or service
// reference would silently break, and we'd want a loud test failure
// rather than a runtime regression.
//
// Anchor 6 PR 6.8: order.go removed from this list — see leafPorts
// above. Only assertions.go remains because the compile-time
// `_ OrderPort = (*kc.Manager)(nil)` check is structural — the
// assertion can ONLY live in a package that imports kc.
var expectedKcImporters = []string{
	"assertions.go", // *kc.Manager compile-time satisfaction check
}

// fileImportsKcParent reports whether the given Go file imports the
// kc parent package. Pure source-level parse — does NOT walk
// transitive deps via `go list`. Returns an error only on parse
// failure (file missing, malformed Go).
func fileImportsKcParent(t *testing.T, fileName string) (bool, error) {
	t.Helper()

	path, err := filepath.Abs(fileName)
	if err != nil {
		return false, err
	}

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly)
	if err != nil {
		return false, err
	}

	for _, imp := range file.Imports {
		// imp.Path.Value is the quoted import path, e.g. `"context"`.
		// Strip the surrounding quotes for comparison.
		if len(imp.Path.Value) < 2 {
			continue
		}
		p := imp.Path.Value[1 : len(imp.Path.Value)-1]
		if p == kcParentImportPath {
			return true, nil
		}
	}
	return false, nil
}

// TestLeafPortsHaveNoKcParentImport asserts that the four inverted
// port files (alert.go, credential.go, instrument.go, session.go)
// do NOT import the kc parent package. This is the Wave B-3 closure
// of Anchor 5 — generalising the PR 5.1 single-port pattern across
// all four leaf ports.
//
// Failing this test means a contributor added `import
// "github.com/zerodha/kite-mcp-server/kc"` to one of the listed
// files. The justification must be reviewed before landing because
// the leaf-stability invariant unblocks Anchor 6's kc-root shrink.
func TestLeafPortsHaveNoKcParentImport(t *testing.T) {
	for _, fileName := range leafPorts {
		fileName := fileName // capture for parallel subtests
		t.Run(fileName, func(t *testing.T) {
			t.Parallel()
			imports, err := fileImportsKcParent(t, fileName)
			if err != nil {
				t.Fatalf("parse %s imports: %v", fileName, err)
			}
			if imports {
				t.Errorf("%s imports kc parent (%q) — leaf-stability invariant broken; see anchor-5-prs-design.md PR 5.8", fileName, kcParentImportPath)
			}
		})
	}
}

// TestExpectedKcImportersStillImportKc asserts that the two ports
// which INTENTIONALLY retain their kc-parent imports (order.go and
// assertions.go) continue to do so. This is the symmetric guard:
// if a future contributor accidentally removes one of these imports
// (e.g. while doing an unrelated cleanup), the corresponding
// compile-time check or service reference would silently break.
//
// This test serves as documentation: order.go imports kc for
// *kc.OrderService (Anchor 6 territory), and assertions.go imports
// kc to verify *kc.Manager satisfies all five ports at compile time.
// Both are load-bearing per anchor-5-prs-design.md PR 5.7.
func TestExpectedKcImportersStillImportKc(t *testing.T) {
	for _, fileName := range expectedKcImporters {
		fileName := fileName
		t.Run(fileName, func(t *testing.T) {
			t.Parallel()
			imports, err := fileImportsKcParent(t, fileName)
			if err != nil {
				t.Fatalf("parse %s imports: %v", fileName, err)
			}
			if !imports {
				t.Errorf("%s no longer imports kc parent — this was load-bearing per anchor-5-prs-design.md PR 5.7. Verify the compile-time satisfaction check (assertions.go) or *kc.OrderService reference (order.go) still works before landing the change.", fileName)
			}
		})
	}
}
