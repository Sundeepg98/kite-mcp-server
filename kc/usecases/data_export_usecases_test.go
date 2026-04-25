package usecases

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// --- Per-port stubs ---

type stubToolCallExporter struct {
	rows []any
	err  error
}

func (s *stubToolCallExporter) ExportToolCalls(_ string, _ time.Time) ([]any, error) {
	return s.rows, s.err
}

type stubAlertExporter struct {
	rows []any
	err  error
}

func (s *stubAlertExporter) ExportAlerts(_ string) ([]any, error) { return s.rows, s.err }

type stubWatchlistExporter struct{ rows []any }

func (s *stubWatchlistExporter) ExportWatchlists(_ string) ([]any, error) { return s.rows, nil }

type stubPaperExporter struct{ rows []any }

func (s *stubPaperExporter) ExportPaperTrades(_ string) ([]any, error) { return s.rows, nil }

type stubSessionExporter struct {
	sessions []any
	creds    []any
}

func (s *stubSessionExporter) ExportSessions(_ string) ([]any, error)    { return s.sessions, nil }
func (s *stubSessionExporter) ExportCredentials(_ string) ([]any, error) { return s.creds, nil }

type stubConsentExporter struct{ rows []any }

func (s *stubConsentExporter) ExportConsentLog(_ string) ([]any, error) { return s.rows, nil }

type stubDomainEventExporter struct{ rows []any }

func (s *stubDomainEventExporter) ExportDomainEvents(_ string, _ time.Time) ([]any, error) {
	return s.rows, nil
}

func discardLoggerExport() *slog.Logger {
	return slog.New(slog.NewTextHandler(io.Discard, nil))
}

func TestExportMyData_FullyWired(t *testing.T) {
	t.Parallel()
	ports := DataExportPorts{
		ToolCalls:    &stubToolCallExporter{rows: []any{"tc1", "tc2"}},
		Alerts:       &stubAlertExporter{rows: []any{"a1"}},
		Watchlists:   &stubWatchlistExporter{rows: []any{"w1", "w2", "w3"}},
		PaperTrades:  &stubPaperExporter{rows: []any{}},
		Sessions:     &stubSessionExporter{sessions: []any{"s1"}, creds: []any{"c1"}},
		Consent:      &stubConsentExporter{rows: []any{"g1", "w1"}},
		DomainEvents: &stubDomainEventExporter{rows: []any{"e1", "e2", "e3", "e4"}},
		Hasher:       stubHasher{},
	}
	uc := NewExportMyDataUseCase(ports, discardLoggerExport())

	fixed := time.Date(2026, 5, 1, 10, 0, 0, 0, time.UTC)
	uc.SetClock(func() time.Time { return fixed })

	out, err := uc.Execute(context.Background(), cqrs.ExportMyDataCommand{
		Email: "Alice@Example.COM",
	})
	require.NoError(t, err)

	// Identity normalised + hashed.
	assert.Equal(t, "alice@example.com", out.Email)
	assert.Equal(t, "h:alice@example.com", out.EmailHash)
	assert.Equal(t, fixed, out.GeneratedAtUTC)
	// 5 years before fixed.
	assert.Equal(t, fixed.Add(-DataExportRetention), out.RetentionFrom)

	// Section counts.
	assert.Equal(t, 2, out.ToolCalls.Count)
	assert.Equal(t, 1, out.Alerts.Count)
	assert.Equal(t, 3, out.Watchlists.Count)
	assert.Equal(t, 0, out.PaperTrades.Count)
	assert.Equal(t, 1, out.Sessions.Count)
	assert.Equal(t, 1, out.Credentials.Count)
	assert.Equal(t, 2, out.Consent.Count)
	assert.Equal(t, 4, out.DomainEvents.Count)

	// JSON shape stable + parseable.
	blob, err := json.Marshal(out)
	require.NoError(t, err)
	require.Contains(t, string(blob), `"email":"alice@example.com"`)
	require.Contains(t, string(blob), `"email_hash":"h:alice@example.com"`)
	require.Contains(t, string(blob), `"tool_calls":`)
	require.Contains(t, string(blob), `"consent_log":`)
}

func TestExportMyData_UnwiredSectionsHaveNote(t *testing.T) {
	t.Parallel()
	// DevMode: only tool_calls + consent are wired. Other sections must
	// produce a structured "not wired" note rather than panicking.
	ports := DataExportPorts{
		ToolCalls: &stubToolCallExporter{rows: []any{"tc"}},
		Consent:   &stubConsentExporter{rows: []any{"g"}},
		Hasher:    stubHasher{},
	}
	uc := NewExportMyDataUseCase(ports, discardLoggerExport())
	out, err := uc.Execute(context.Background(), cqrs.ExportMyDataCommand{Email: "alice@example.com"})
	require.NoError(t, err)

	// Wired sections populate Rows.
	assert.Equal(t, 1, out.ToolCalls.Count)
	assert.Equal(t, 1, out.Consent.Count)

	// Unwired sections expose the note + zero count.
	assert.Equal(t, 0, out.Alerts.Count)
	assert.Contains(t, out.Alerts.Note, "alerts")
	assert.Contains(t, out.Alerts.Note, "not wired")
	assert.Equal(t, 0, out.Watchlists.Count)
	assert.Contains(t, out.Watchlists.Note, "watchlists")
	assert.Equal(t, 0, out.DomainEvents.Count)
	assert.Contains(t, out.DomainEvents.Note, "domain_events")
}

func TestExportMyData_SectionErrorIsCaptured(t *testing.T) {
	t.Parallel()
	// A port that errors must NOT fail the whole export — the user
	// still gets every section that succeeded.
	ports := DataExportPorts{
		ToolCalls: &stubToolCallExporter{err: errors.New("audit DB locked")},
		Alerts:    &stubAlertExporter{rows: []any{"a"}},
		Hasher:    stubHasher{},
	}
	uc := NewExportMyDataUseCase(ports, discardLoggerExport())
	out, err := uc.Execute(context.Background(), cqrs.ExportMyDataCommand{Email: "alice@example.com"})
	require.NoError(t, err, "section errors must NOT bubble up — the user gets a partial export")

	// Errored section: 0 count + Note carries the error string.
	assert.Equal(t, 0, out.ToolCalls.Count)
	assert.Contains(t, out.ToolCalls.Note, "audit DB locked")

	// Sibling sections still populate.
	assert.Equal(t, 1, out.Alerts.Count)
}

func TestExportMyData_EmptyEmailRejected(t *testing.T) {
	t.Parallel()
	uc := NewExportMyDataUseCase(DataExportPorts{Hasher: stubHasher{}}, discardLoggerExport())
	_, err := uc.Execute(context.Background(), cqrs.ExportMyDataCommand{Email: " "})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "email is required")
}

func TestExportMyData_NoHasher(t *testing.T) {
	t.Parallel()
	uc := NewExportMyDataUseCase(DataExportPorts{}, discardLoggerExport())
	_, err := uc.Execute(context.Background(), cqrs.ExportMyDataCommand{Email: "a@b.com"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no email hasher")
}

func TestExportMyData_RetentionWindowIs5Years(t *testing.T) {
	t.Parallel()
	// Pin the retention constant — DPDP guidance changed once before
	// (3y → 5y in the 2024 draft); a regression here would silently
	// drop user records older than the new window.
	assert.Equal(t, 5*365*24*time.Hour, DataExportRetention)
}
