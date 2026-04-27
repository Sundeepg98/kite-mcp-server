package providers

import (
	"path/filepath"
	"strings"
	"testing"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/riskguard"
)

// riskguard_test.go covers InitializeRiskGuard. Wave D Phase 2
// Slice P2.4c (Batch 2.1). The provider takes a pre-constructed
// *riskguard.Guard and runs DB init + LoadLimits, optionally wiring
// FreezeQuantityLookup/LTPLookup/BaselineProvider. Returns
// *InitializedRiskGuard with a LimitsLoaded boolean for the caller.

// stubFreezeLookup is the smallest possible FreezeQuantityLookup
// implementation for tests — always returns "no quota set."
type stubFreezeLookup struct{}

func (stubFreezeLookup) GetFreezeQuantity(_, _ string) (uint32, bool) {
	return 0, false
}

// stubLTPLookup is the smallest possible LTPLookup implementation —
// always returns "no quote available."
type stubLTPLookup struct{}

func (stubLTPLookup) GetLTP(_, _ string) (float64, bool) {
	return 0, false
}

// TestInitializeRiskGuard_NoDB_DevMode_DefaultsLoaded verifies the
// in-memory mode path: no DB, DevMode=true, the guard runs with
// SystemDefaults and LimitsLoaded stays true (matches wire.go:312
// "Default to 'loaded' — DevMode without ALERT_DB_PATH"). No error.
func TestInitializeRiskGuard_NoDB_DevMode_DefaultsLoaded(t *testing.T) {
	t.Parallel()

	guard := riskguard.NewGuard(testLogger())
	in := riskguardInitInput{
		Guard:  guard,
		DB:     nil,
		Config: RiskGuardConfig{DevMode: true},
		Logger: testLogger(),
	}
	got, err := InitializeRiskGuard(in)
	if err != nil {
		t.Fatalf("expected nil error in DevMode no-DB; got %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil wrapper")
	}
	if got.Guard != guard {
		t.Errorf("expected wrapper.Guard to be the same pointer as input")
	}
	if !got.LimitsLoaded {
		t.Errorf("expected LimitsLoaded=true in DevMode no-DB path; got false")
	}
}

// TestInitializeRiskGuard_NoDB_ProductionMode_ReturnsError verifies
// the fail-fast contract: in production with no DB, the function
// returns an error matching wire.go:330's "no alert DB configured"
// message prefix.
func TestInitializeRiskGuard_NoDB_ProductionMode_ReturnsError(t *testing.T) {
	t.Parallel()

	guard := riskguard.NewGuard(testLogger())
	in := riskguardInitInput{
		Guard:  guard,
		DB:     nil,
		Config: RiskGuardConfig{DevMode: false},
		Logger: testLogger(),
	}
	got, err := InitializeRiskGuard(in)
	if err == nil {
		t.Fatal("expected non-nil error in production mode without DB")
	}
	if !strings.Contains(err.Error(), "riskguard required in production") {
		t.Errorf("expected production error prefix; got %v", err)
	}
	if got != nil {
		t.Errorf("expected nil wrapper on production error; got non-nil")
	}
}

// TestInitializeRiskGuard_LiveDB_LoadsLimits verifies the happy
// path: with a live DB, InitTable + LoadLimits both succeed, the
// wrapper is non-nil with LimitsLoaded=true.
func TestInitializeRiskGuard_LiveDB_LoadsLimits(t *testing.T) {
	t.Parallel()

	dbPath := filepath.Join(t.TempDir(), "riskguard_init_test.db")
	db, err := alerts.OpenDB(dbPath)
	if err != nil {
		t.Fatalf("OpenDB: %v", err)
	}
	t.Cleanup(func() { _ = db.Close() })

	guard := riskguard.NewGuard(testLogger())
	in := riskguardInitInput{
		Guard:  guard,
		DB:     db,
		Config: RiskGuardConfig{DevMode: false},
		Logger: testLogger(),
	}
	got, err := InitializeRiskGuard(in)
	if err != nil {
		t.Fatalf("expected nil error; got %v", err)
	}
	if got == nil {
		t.Fatal("expected non-nil wrapper")
	}
	if !got.LimitsLoaded {
		t.Errorf("expected LimitsLoaded=true after successful InitTable+LoadLimits")
	}
}

// TestInitializeRiskGuard_StubLookups_WireCleanly verifies that
// supplying FreezeQuantityLookup + LTPLookup interfaces (via stub
// implementations) wires them without error. We don't assert on
// behavior — kc/riskguard's own tests cover that — only that the
// provider accepts the dependencies and doesn't panic.
func TestInitializeRiskGuard_StubLookups_WireCleanly(t *testing.T) {
	t.Parallel()

	guard := riskguard.NewGuard(testLogger())
	in := riskguardInitInput{
		Guard:        guard,
		DB:           nil,
		FreezeLookup: stubFreezeLookup{},
		LTPLookup:    stubLTPLookup{},
		Config:       RiskGuardConfig{DevMode: true},
		Logger:       testLogger(),
	}
	got, err := InitializeRiskGuard(in)
	if err != nil {
		t.Fatalf("expected nil error; got %v", err)
	}
	if got == nil || got.Guard == nil {
		t.Fatal("expected non-nil wrapper with non-nil Guard")
	}
}

// TestInitializeRiskGuard_NilGuard_ReturnsError verifies the
// "missing precondition" contract: a nil *riskguard.Guard input is
// a programmer error (the composition site MUST construct the
// guard before calling). Provider returns a clear error rather
// than nil-panicking.
func TestInitializeRiskGuard_NilGuard_ReturnsError(t *testing.T) {
	t.Parallel()

	in := riskguardInitInput{
		Guard:  nil,
		DB:     nil,
		Config: RiskGuardConfig{DevMode: true},
		Logger: testLogger(),
	}
	_, err := InitializeRiskGuard(in)
	if err == nil {
		t.Fatal("expected non-nil error for nil guard input")
	}
	if !strings.Contains(err.Error(), "guard") {
		t.Errorf("expected error mentioning guard; got %v", err)
	}
}
