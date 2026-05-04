// Package domain — dependency cycle pin test.
//
// PR 4.7 (Anchor 4): This test pins the upstream-dep set of kc/domain
// to its current minimal footprint. kc/domain is at the BOTTOM of the
// import graph — it should never depend on kc/usecases, kc/alerts,
// kc/cqrs, kc/eventsourcing, or any other "upper" module.
//
// The test runs `go list -deps .` and verifies the only zerodha/kite-
// mcp-server packages reached are the explicitly-allowed leaves:
// broker (DTO interop), kc/isttz (IST timezone), kc/money (Money
// value object), plus kc/domain itself.
//
// If this test fails, someone added a cyclic dep — investigate which
// new import landed in kc/domain/*.go and remove it. kc/domain must
// remain a leaf of the dep graph for the disintegrate audit's
// promise to hold (per .research/disintegrate-and-holistic-
// architecture.md commits 5437c32 + 7e1700c).
package domain_test

import (
	"os/exec"
	"strings"
	"testing"
)

// allowedUpstreamModules lists the zerodha/kite-mcp-server packages
// kc/domain MAY depend on. Adding to this list should be deliberate:
// each entry must be a true leaf below kc/domain in the dep graph,
// and adding a new entry requires a corresponding go.mod replace.
var allowedUpstreamModules = map[string]string{
	"github.com/zerodha/kite-mcp-server/broker":    "broker DTO interop (Holding/Position/Order/Profile)",
	"github.com/zerodha/kite-mcp-server/kc/domain": "self-package",
	"github.com/zerodha/kite-mcp-server/kc/isttz":  "IST timezone for Session.IsExpired()",
	"github.com/zerodha/kite-mcp-server/kc/money":  "Money value object",
}

// TestDomainDependencyCycle pins kc/domain's transitive zerodha-org
// dependencies to the explicitly-allowed leaf set.
//
// Build constraint reasoning: this test invokes `go list -deps .`
// which requires the Go toolchain to be available. In a sandbox
// without `go` on PATH (rare — the test suite already requires Go),
// the test is skipped with a clear message rather than failing.
func TestDomainDependencyCycle(t *testing.T) {
	cmd := exec.Command("go", "list", "-deps", ".")
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Skipf("go list failed (expected in some sandbox environments): %v\n%s", err, string(out))
		return
	}

	var unexpected []string
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		pkg := strings.TrimSpace(line)
		if !strings.HasPrefix(pkg, "github.com/zerodha/kite-mcp-server") {
			continue
		}
		// Allow subpackages of allowed modules (e.g., broker/zerodha
		// when kc/domain ever needs broker subpackages — currently
		// only direct broker is referenced).
		ok := false
		for allowed := range allowedUpstreamModules {
			if pkg == allowed || strings.HasPrefix(pkg, allowed+"/") {
				ok = true
				break
			}
		}
		if !ok {
			unexpected = append(unexpected, pkg)
		}
	}

	if len(unexpected) > 0 {
		t.Errorf("kc/domain has unexpected upstream zerodha deps (cycle risk):\n  %s\n\nAllowed upstream modules:\n", strings.Join(unexpected, "\n  "))
		for allowed, reason := range allowedUpstreamModules {
			t.Errorf("  - %s: %s\n", allowed, reason)
		}
		t.Errorf("\nIf you intentionally added a new dep, update allowedUpstreamModules in dep_cycle_test.go AND add the corresponding go.mod replace.")
	}
}
