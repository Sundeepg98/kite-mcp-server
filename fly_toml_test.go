package main

// fly_toml_test.go — pin invariants that operations rely on across
// fly.toml. The deploy pipeline parses these expectations from this
// file; a future config change that drifts must be deliberate (the
// test fails) rather than silent.

import (
	"os"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// readFlyToml returns the textual content of fly.toml at the repo root.
// Path is relative to the test binary's working directory, which Go
// sets to the package directory at test time — same place fly.toml
// lives in this repo.
func readFlyToml(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("fly.toml")
	require.NoError(t, err, "fly.toml must be present at repo root")
	return string(b)
}

// TestFlyToml_PrimaryRegionPinned ensures the active region stays bom.
// SEBI April-2026 mandate ties our static egress IP to bom; an
// accidental flip would break every user's Kite IP allow-list.
func TestFlyToml_PrimaryRegionPinned(t *testing.T) {
	t.Parallel()
	body := readFlyToml(t)
	assert.Contains(t, body, `primary_region = "bom"`,
		"primary_region must remain bom — see docs/incident-response.md "+
			"'Region failover (deferred)' for the SEBI static-IP rationale")
}

// TestFlyToml_SecondaryRegionDocumentedNotActivated pins PR-MR's
// posture: sin is documented as a candidate secondary, but no
// active regions list / clone directive — the matching activation
// criteria are described in incident-response.md.
//
// If a future commit activates the sin machine (post non-Kite
// broker), this test fails as a useful reminder to flip the
// associated docs from "deferred" to "active".
func TestFlyToml_SecondaryRegionDocumentedNotActivated(t *testing.T) {
	t.Parallel()
	body := readFlyToml(t)

	// Documentation present.
	assert.Contains(t, body, `Secondary region prepared for future activation: "sin"`,
		"fly.toml must document the sin secondary candidate")
	assert.Contains(t, body, "non-Kite broker",
		"fly.toml must document the activation gate")

	// NOT activated — no live secondary_region directive at top level.
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		assert.NotEqual(t, `secondary_region = "sin"`, trimmed,
			"sin secondary should still be deferred; flip incident-response.md from 'deferred' to 'active' when activating")
	}
}

// TestFlyToml_HasMinMachinesRunning ensures the always-on machine
// directive is present. min_machines_running=1 is the load-bearing
// guarantee that /healthz returns 200 even with auto-stop disabled
// elsewhere; PR-A's deep-probe assumes a live machine.
func TestFlyToml_HasMinMachinesRunning(t *testing.T) {
	t.Parallel()
	body := readFlyToml(t)
	assert.Contains(t, body, "min_machines_running = 1")
}

// TestFlyToml_EnableTradingFalse pins the Path-2 compliance flag.
// Hosted multi-user MUST default ENABLE_TRADING=false; flipping it
// puts us under NSE Annexure I Para 2.8 "Algo Provider"
// classification. Local single-user builds override in their shell.
func TestFlyToml_EnableTradingFalse(t *testing.T) {
	t.Parallel()
	body := readFlyToml(t)
	assert.Contains(t, body, `ENABLE_TRADING = "false"`,
		"hosted build must default ENABLE_TRADING=false — see Path 2 compliance")
}
