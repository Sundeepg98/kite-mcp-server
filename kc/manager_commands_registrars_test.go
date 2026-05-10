package kc

// Coverage for the 7 package-level pure-function command registrars
// extracted in Tier 2.2 + Tier 2.3 (commits 41b9e90 + 4ed17ae through
// 08cc719). Each registrar is a one-shot stateless function that takes
// (bus, deps, logger) and registers a fixed set of CQRS command handlers
// onto the bus.
//
// What these tests prove (closes Tier 2 design-doc claim that was
// previously empirically unvalidated):
//
//   1. Each registrar runs cleanly against a minimal deps fixture
//      (no full Manager construction needed).
//   2. The reusability claim — "registrar can be called against multiple
//      bus instances" — holds: invoking the same registrar against two
//      separate fresh buses succeeds twice.
//   3. Re-invoking the registrar against the SAME bus errors with a
//      duplicate-registration message, proving the bus wired correctly
//      the first time.
//
// Test discipline (matches kc/ convention):
//   - Hand-rolled assertions (no testify)
//   - Each test t.Parallel()
//   - In-memory stores; no SQLite, no goroutines, no I/O
//   - Stub-style minimal deps (nil-tolerant where the registrar handles it)

import (
	"io"
	"log/slog"
	"strings"
	"testing"

	"github.com/algo2go/kite-mcp-alerts"
	"github.com/algo2go/kite-mcp-cqrs"
	"github.com/algo2go/kite-mcp-registry"
	"github.com/algo2go/kite-mcp-users"
)

// quietRegistrarLogger discards log output for hermetic tests.
func quietRegistrarLogger() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

// freshTestBus returns a fresh in-memory CommandBus for one test invocation.
// Each call creates a new instance so duplicate-registration assertions are
// deterministic.
func freshTestBus() *cqrs.InMemoryBus {
	return cqrs.NewInMemoryBus()
}

// assertDuplicateRegistrationError verifies that re-invoking a registrar
// against the same bus produces an error mentioning duplicate / already.
// Each registrar's first call should succeed; the second must fail because
// command-type registrations are unique per bus.
func assertDuplicateRegistrationError(t *testing.T, err error, registrarName string) {
	t.Helper()
	if err == nil {
		t.Fatalf("%s: expected duplicate-registration error on second call, got nil", registrarName)
	}
	msg := strings.ToLower(err.Error())
	if !strings.Contains(msg, "already") && !strings.Contains(msg, "duplicate") && !strings.Contains(msg, "registered") {
		t.Errorf("%s: error message %q should mention already/duplicate/registered", registrarName, err.Error())
	}
}

// ---------------------------------------------------------------------------
// Tier 2.2: registerOAuthBridgeCommandsOnBus
// ---------------------------------------------------------------------------

func TestRegisterOAuthBridgeCommandsOnBus_Registers(t *testing.T) {
	t.Parallel()
	bus := freshTestBus()
	deps := OAuthBridgeRegistrarDeps{
		UserStore:       users.NewStore(),
		TokenStore:      NewKiteTokenStore(),
		CredentialStore: NewKiteCredentialStore(),
		RegistryStore:   registry.New(),
		AlertDBGetter:   func() *alerts.DB { return nil }, // lazy nil-safe
	}
	if err := registerOAuthBridgeCommandsOnBus(bus, deps, quietRegistrarLogger()); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	err := registerOAuthBridgeCommandsOnBus(bus, deps, quietRegistrarLogger())
	assertDuplicateRegistrationError(t, err, "registerOAuthBridgeCommandsOnBus")
}

// TestRegisterOAuthBridgeCommandsOnBus_Reusability proves the design-doc
// claim: the registrar can be invoked against multiple bus instances.
// Each fresh bus accepts the same registrar without conflict.
func TestRegisterOAuthBridgeCommandsOnBus_Reusability(t *testing.T) {
	t.Parallel()
	deps := OAuthBridgeRegistrarDeps{
		UserStore:       users.NewStore(),
		TokenStore:      NewKiteTokenStore(),
		CredentialStore: NewKiteCredentialStore(),
		RegistryStore:   registry.New(),
		AlertDBGetter:   func() *alerts.DB { return nil },
	}
	bus1 := freshTestBus()
	bus2 := freshTestBus()
	if err := registerOAuthBridgeCommandsOnBus(bus1, deps, quietRegistrarLogger()); err != nil {
		t.Fatalf("bus1 registration: %v", err)
	}
	if err := registerOAuthBridgeCommandsOnBus(bus2, deps, quietRegistrarLogger()); err != nil {
		t.Fatalf("bus2 registration: %v", err)
	}
}

// ---------------------------------------------------------------------------
// Tier 2.3 slice 1: registerAdminUserCommandsOnBus
// ---------------------------------------------------------------------------

func TestRegisterAdminUserCommandsOnBus_Registers(t *testing.T) {
	t.Parallel()
	bus := freshTestBus()
	deps := AdminUserRegistrarDeps{
		UserStore:        users.NewStore(),
		RiskGuardGetter:  nil, // nil-safe; handler bodies guard
		SessionManager:   nil,
		DispatcherGetter: nil,
	}
	if err := registerAdminUserCommandsOnBus(bus, deps, quietRegistrarLogger()); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	err := registerAdminUserCommandsOnBus(bus, deps, quietRegistrarLogger())
	assertDuplicateRegistrationError(t, err, "registerAdminUserCommandsOnBus")
}

// ---------------------------------------------------------------------------
// Tier 2.3 slice 2: registerAdminRiskCommandsOnBus
// ---------------------------------------------------------------------------

func TestRegisterAdminRiskCommandsOnBus_Registers(t *testing.T) {
	t.Parallel()
	bus := freshTestBus()
	deps := AdminRiskRegistrarDeps{
		RiskGuardGetter: nil, // nil-safe; handler bodies guard
	}
	if err := registerAdminRiskCommandsOnBus(bus, deps, quietRegistrarLogger()); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	err := registerAdminRiskCommandsOnBus(bus, deps, quietRegistrarLogger())
	assertDuplicateRegistrationError(t, err, "registerAdminRiskCommandsOnBus")
}

// ---------------------------------------------------------------------------
// Tier 2.3 slice 3: registerAdminAlertsCommandsOnBus
// ---------------------------------------------------------------------------

func TestRegisterAdminAlertsCommandsOnBus_Registers(t *testing.T) {
	t.Parallel()
	bus := freshTestBus()
	deps := AdminAlertsRegistrarDeps{
		AlertStore:        alerts.NewStore(nil),
		InstrumentsGetter: nil,
		DispatcherGetter:  nil,
		EventStoreGetter:  nil,
	}
	if err := registerAdminAlertsCommandsOnBus(bus, deps, quietRegistrarLogger()); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	err := registerAdminAlertsCommandsOnBus(bus, deps, quietRegistrarLogger())
	assertDuplicateRegistrationError(t, err, "registerAdminAlertsCommandsOnBus")
}

// ---------------------------------------------------------------------------
// Tier 2.3 slice 4: registerAdminMFCommandsOnBus
// ---------------------------------------------------------------------------

func TestRegisterAdminMFCommandsOnBus_Registers(t *testing.T) {
	t.Parallel()
	bus := freshTestBus()
	deps := AdminMFRegistrarDeps{
		SessionSvc:       nil, // not dereferenced at registration time
		DispatcherGetter: nil,
		EventStoreGetter: nil,
	}
	if err := registerAdminMFCommandsOnBus(bus, deps, quietRegistrarLogger()); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	err := registerAdminMFCommandsOnBus(bus, deps, quietRegistrarLogger())
	assertDuplicateRegistrationError(t, err, "registerAdminMFCommandsOnBus")
}

// ---------------------------------------------------------------------------
// Tier 2.3 slice 5: registerAdminTickerCommandsOnBus
// ---------------------------------------------------------------------------

func TestRegisterAdminTickerCommandsOnBus_Registers(t *testing.T) {
	t.Parallel()
	bus := freshTestBus()
	deps := AdminTickerRegistrarDeps{
		TickerServiceGetter: nil, // nil-safe; handler bodies guard
	}
	if err := registerAdminTickerCommandsOnBus(bus, deps, quietRegistrarLogger()); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	err := registerAdminTickerCommandsOnBus(bus, deps, quietRegistrarLogger())
	assertDuplicateRegistrationError(t, err, "registerAdminTickerCommandsOnBus")
}

// ---------------------------------------------------------------------------
// Tier 2.3 slice 6: registerAdminNativeAlertsCommandsOnBus
// ---------------------------------------------------------------------------

func TestRegisterAdminNativeAlertsCommandsOnBus_Registers(t *testing.T) {
	t.Parallel()
	bus := freshTestBus()
	deps := AdminNativeAlertsRegistrarDeps{
		SessionSvc:       nil, // not dereferenced at registration time
		DispatcherGetter: nil,
		EventStoreGetter: nil,
	}
	if err := registerAdminNativeAlertsCommandsOnBus(bus, deps, quietRegistrarLogger()); err != nil {
		t.Fatalf("first registration: %v", err)
	}
	err := registerAdminNativeAlertsCommandsOnBus(bus, deps, quietRegistrarLogger())
	assertDuplicateRegistrationError(t, err, "registerAdminNativeAlertsCommandsOnBus")
}

// ---------------------------------------------------------------------------
// Cross-registrar reusability proof: all 7 registrars on a single bus
// without conflict (different command types per registrar means no
// duplicate-type collision).
// ---------------------------------------------------------------------------

func TestAllRegistrars_OnSingleBus_NoConflict(t *testing.T) {
	t.Parallel()
	bus := freshTestBus()
	logger := quietRegistrarLogger()

	if err := registerOAuthBridgeCommandsOnBus(bus, OAuthBridgeRegistrarDeps{
		UserStore:       users.NewStore(),
		TokenStore:      NewKiteTokenStore(),
		CredentialStore: NewKiteCredentialStore(),
		RegistryStore:   registry.New(),
		AlertDBGetter:   func() *alerts.DB { return nil },
	}, logger); err != nil {
		t.Fatalf("oauth: %v", err)
	}
	if err := registerAdminUserCommandsOnBus(bus, AdminUserRegistrarDeps{
		UserStore: users.NewStore(),
	}, logger); err != nil {
		t.Fatalf("admin-user: %v", err)
	}
	if err := registerAdminRiskCommandsOnBus(bus, AdminRiskRegistrarDeps{}, logger); err != nil {
		t.Fatalf("admin-risk: %v", err)
	}
	if err := registerAdminAlertsCommandsOnBus(bus, AdminAlertsRegistrarDeps{
		AlertStore: alerts.NewStore(nil),
	}, logger); err != nil {
		t.Fatalf("admin-alerts: %v", err)
	}
	if err := registerAdminMFCommandsOnBus(bus, AdminMFRegistrarDeps{}, logger); err != nil {
		t.Fatalf("admin-mf: %v", err)
	}
	if err := registerAdminTickerCommandsOnBus(bus, AdminTickerRegistrarDeps{}, logger); err != nil {
		t.Fatalf("admin-ticker: %v", err)
	}
	if err := registerAdminNativeAlertsCommandsOnBus(bus, AdminNativeAlertsRegistrarDeps{}, logger); err != nil {
		t.Fatalf("admin-native-alerts: %v", err)
	}
}
