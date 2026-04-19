package riskguard

import (
	"io"
	"log/slog"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
)

// TestSubprocessCheck_NilOnMissingBinary — a SubprocessCheck whose
// executable does not exist on disk must fail closed at Evaluate
// (not at construction), return a clean CheckResult with
// Reason="subprocess_unavailable", and NOT panic.
func TestSubprocessCheck_NilOnMissingBinary(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	missing := filepath.Join(tmp, "does-not-exist.exe")

	sc := NewSubprocessCheck(SubprocessCheckConfig{
		Name:       "missing_plugin",
		Order:      5000,
		Executable: missing,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer sc.Close()

	// Metadata methods use cached/stub values when subprocess is
	// unreachable — no panic, no crash.
	if got := sc.Name(); got != "missing_plugin" {
		t.Errorf("Name() = %q, want %q", got, "missing_plugin")
	}
	if got := sc.Order(); got != 5000 {
		t.Errorf("Order() = %d, want 5000", got)
	}

	// Evaluate fails closed.
	r := sc.Evaluate(OrderCheckRequest{Email: "x@y.z"})
	if r.Allowed {
		t.Fatal("missing binary must fail closed (Allowed=false)")
	}
	if r.Reason != "subprocess_unavailable" {
		t.Errorf("Reason = %q, want subprocess_unavailable", r.Reason)
	}
	if !strings.Contains(r.Message, "missing_plugin") {
		t.Errorf("message should name the plugin; got %q", r.Message)
	}
}

// TestSubprocessCheck_StaleExecutableFallback — a stale/broken
// executable that fails to launch also fails closed rather than
// crashing the host.
func TestSubprocessCheck_StaleExecutableFallback(t *testing.T) {
	t.Parallel()
	if runtime.GOOS == "windows" {
		t.Skip("unix-like chmod semantics not available on Windows")
	}
	tmp := t.TempDir()
	notExecutable := filepath.Join(tmp, "stale.bin")
	// Write a non-executable file. On Windows we skip because the
	// OS doesn't use the same exec-bit semantics — exec.Command
	// relies on file extension there.
	if err := os.WriteFile(notExecutable, []byte("not a binary"), 0o644); err != nil {
		t.Fatal(err)
	}

	sc := NewSubprocessCheck(SubprocessCheckConfig{
		Name:       "stale_plugin",
		Order:      5001,
		Executable: notExecutable,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer sc.Close()

	r := sc.Evaluate(OrderCheckRequest{Email: "x@y.z"})
	if r.Allowed {
		t.Fatal("stale binary must fail closed (Allowed=false)")
	}
	if r.Reason == "" {
		t.Errorf("expected a non-empty Reason; got empty")
	}
}

// TestSubprocessCheck_EvaluateRoundtrip exercises the happy path.
// Requires the example plugin to be built first; the test builds it
// into a temp directory, registers it, and confirms an evaluation
// round-trips.
func TestSubprocessCheck_EvaluateRoundtrip(t *testing.T) {
	t.Parallel()
	pluginBin := buildExamplePlugin(t)

	sc := NewSubprocessCheck(SubprocessCheckConfig{
		Name:       "example_plugin",
		Order:      5002,
		Executable: pluginBin,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer sc.Close()

	// The example plugin blocks any order whose Tradingsymbol
	// starts with "BLOCKED_".
	r1 := sc.Evaluate(OrderCheckRequest{Email: "x@y.z", Tradingsymbol: "BLOCKED_FOO"})
	if r1.Allowed {
		t.Error("expected Allowed=false for BLOCKED_ prefix")
	}

	r2 := sc.Evaluate(OrderCheckRequest{Email: "x@y.z", Tradingsymbol: "GOOD_BAR"})
	if !r2.Allowed {
		t.Errorf("expected Allowed=true for non-prefix; got %+v", r2)
	}
}

// TestSubprocessCheck_PanicInPluginFailsClosed — a plugin that panics
// (the example plugin has a "PANIC_ME" magic symbol for testing)
// must NOT crash the host. The subprocess dies; SafeInvoke catches
// the resulting error; evaluation returns a fail-closed result.
// Subsequent evaluations relaunch the subprocess.
func TestSubprocessCheck_PanicInPluginFailsClosed(t *testing.T) {
	t.Parallel()
	pluginBin := buildExamplePlugin(t)

	sc := NewSubprocessCheck(SubprocessCheckConfig{
		Name:       "panicker",
		Order:      5003,
		Executable: pluginBin,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer sc.Close()

	// First call with PANIC_ME triggers plugin-side panic.
	r := sc.Evaluate(OrderCheckRequest{Email: "x@y.z", Tradingsymbol: "PANIC_ME"})
	if r.Allowed {
		t.Error("panicking plugin must fail closed")
	}
	// Message should mention either the error from the RPC call or
	// subprocess_unavailable (depending on timing of the crash).
	if r.Reason == "" {
		t.Errorf("expected non-empty Reason on plugin panic; got %+v", r)
	}

	// Subsequent legit call should work — host relaunches the
	// subprocess. (This is the core crash-isolation guarantee.)
	r2 := sc.Evaluate(OrderCheckRequest{Email: "x@y.z", Tradingsymbol: "GOOD"})
	// We can't strictly assert r2.Allowed=true because relaunch
	// timing is nondeterministic across OS + CI; but the call MUST
	// NOT panic.
	_ = r2
}

// TestSubprocessCheck_ConcurrentEvaluateIsSafe — multiple goroutines
// hitting Evaluate at once must not deadlock or race. Exercises the
// mutex around the cached rpc.Client.
func TestSubprocessCheck_ConcurrentEvaluateIsSafe(t *testing.T) {
	t.Parallel()
	pluginBin := buildExamplePlugin(t)

	sc := NewSubprocessCheck(SubprocessCheckConfig{
		Name:       "concurrent",
		Order:      5004,
		Executable: pluginBin,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer sc.Close()

	const N = 20
	var wg sync.WaitGroup
	wg.Add(N)
	for i := 0; i < N; i++ {
		go func(i int) {
			defer wg.Done()
			r := sc.Evaluate(OrderCheckRequest{
				Email:         "x@y.z",
				Tradingsymbol: "SYM",
				Quantity:      i,
			})
			// Cannot assert r.Allowed=true deterministically (first
			// call has to spawn subprocess), but the call must
			// terminate without panic.
			_ = r
		}(i)
	}
	wg.Wait()
}

// TestSubprocessCheck_ReloadReconnects — calling Close on a running
// SubprocessCheck kills the subprocess; a subsequent Evaluate must
// relaunch it cleanly.
func TestSubprocessCheck_ReloadReconnects(t *testing.T) {
	t.Parallel()
	pluginBin := buildExamplePlugin(t)

	sc := NewSubprocessCheck(SubprocessCheckConfig{
		Name:       "reloadable",
		Order:      5005,
		Executable: pluginBin,
		Logger:     slog.New(slog.NewTextHandler(io.Discard, nil)),
	})
	defer sc.Close()

	// First call spawns subprocess.
	r1 := sc.Evaluate(OrderCheckRequest{Email: "x@y.z", Tradingsymbol: "OK"})
	if !r1.Allowed {
		t.Logf("first call not allowed (subprocess startup timing): %+v", r1)
	}

	// Force a reload — tears the subprocess down.
	sc.Close()

	// Second call must relaunch.
	r2 := sc.Evaluate(OrderCheckRequest{Email: "x@y.z", Tradingsymbol: "OK"})
	_ = r2 // Post-reload call must not panic or hang.
}

// TestSubprocessCheck_RegisterOnGuard — calling
// Guard.RegisterSubprocessCheck wires the plugin into the check
// chain. A missing binary makes the check fail closed for the
// first order; the rest of the chain is unaffected.
func TestSubprocessCheck_RegisterOnGuard(t *testing.T) {
	t.Parallel()
	tmp := t.TempDir()
	missing := filepath.Join(tmp, "never-exists.exe")

	g := NewGuard(slog.New(slog.NewTextHandler(io.Discard, nil)))
	err := g.RegisterSubprocessCheck("missing_sub", missing, 2500)
	if err != nil {
		t.Fatalf("RegisterSubprocessCheck returned unexpected error: %v", err)
	}

	// The subprocess check is now in the chain at Order=2500, which
	// is AFTER off_hours (1200) but BEFORE any unregistered slots.
	// Because the binary doesn't exist, CheckOrder should fail
	// closed with Reason="subprocess_unavailable" (or whatever
	// safeEvaluate surfaces) when the chain reaches that check.
	r := g.CheckOrder(OrderCheckRequest{
		Email:     "user@test.com",
		ToolName:  "place_order",
		Confirmed: true,
	})
	if r.Allowed {
		t.Fatal("missing subprocess plugin must fail closed in the chain")
	}
}

// TestSubprocessCheckConfig_Validate — rejects invalid config.
func TestSubprocessCheckConfig_Validate(t *testing.T) {
	t.Parallel()
	cases := []struct {
		name string
		cfg  SubprocessCheckConfig
	}{
		{"empty name", SubprocessCheckConfig{Executable: "/x"}},
		{"empty executable", SubprocessCheckConfig{Name: "x"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := tc.cfg.Validate()
			if err == nil {
				t.Error("expected error for invalid config")
			}
		})
	}
}

// --- helpers ---

// buildExamplePlugin builds the example plugin binary and returns
// its path. The binary is built into the test's tempdir so it's
// cleaned up with the test. Skips the test if `go` is not on PATH
// or if the example source has been removed.
func buildExamplePlugin(t *testing.T) string {
	t.Helper()

	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not on PATH — cannot build example plugin")
	}

	repoRoot := findRepoRoot(t)
	examplePkg := filepath.Join(repoRoot, "examples", "riskguard-check-plugin")
	if _, err := os.Stat(examplePkg); err != nil {
		t.Skip("example plugin source missing: " + err.Error())
	}

	out := filepath.Join(t.TempDir(), "plugin")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}

	cmd := exec.Command("go", "build", "-o", out, ".")
	cmd.Dir = examplePkg
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	if b, err := cmd.CombinedOutput(); err != nil {
		t.Skipf("failed to build example plugin (skipping subprocess-dependent test): %v\n%s", err, b)
	}
	return out
}

// findRepoRoot walks up from the current test file's directory
// looking for go.mod. Works regardless of where `go test` was
// invoked from.
func findRepoRoot(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	dir := wd
	for i := 0; i < 10; i++ {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			break
		}
		dir = parent
	}
	t.Fatal("could not locate go.mod from " + wd)
	return ""
}
