package usecases

// data_export_usecases.go — DPDP Act 2023 §11 right-to-portability flow.
//
// §11 entitles every Data Principal to receive a "personal data
// portability" export "in a structured, commonly-used and machine-
// readable format." For our service that's a single JSON document
// containing every record we hold under their identity:
//
//   - tool_calls     (last 5 years; matches DPDP retention guidance)
//   - alerts         (active + history)
//   - watchlists     (and items)
//   - paper_trades   (paper engine state)
//   - sessions       (consent + Kite session metadata)
//   - credentials    (encrypted blob — user can verify presence
//                     without us exposing the plaintext)
//   - consent_log    (full grant + withdraw history)
//   - domain_events  (per-user-hash via PR-D Item 2)
//
// PII handling: the export ships plaintext to the requester (it's
// THEIR data — that's the whole point). Internal correlations between
// tables continue to use email_hash; the use case rehydrates plaintext
// only at the export boundary.
//
// Streaming: the result is built in memory (JSON Marshal) before
// return. For typical users the export is < 5 MB; if a future user
// accumulates more, switch the use case to streaming via json.Encoder
// against a temp file. The MCP tool wrapping this use case caps
// response size separately.

import (
	"context"
	"fmt"
	"log/slog"
	"strings"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// DataExportRetention is the lookback window applied to time-bounded
// tables (tool_calls, domain_events). 5 years matches the most
// conservative DPDP retention guidance for trading-related records.
const DataExportRetention = 5 * 365 * 24 * time.Hour

// --- Ports ---
//
// All sources are narrow ports so the use case stays free of
// kc-internal-package imports (kc → usecases creates a cycle for
// store types that reference each other).
//
// Each port returns its rows as a []any so the use case doesn't need
// to know any record's concrete shape — the JSON marshaller does the
// work. nil port = "section unavailable" (DevMode, missing store).

// ToolCallExporter retrieves tool_call rows for the user.
type ToolCallExporter interface {
	ExportToolCalls(email string, since time.Time) ([]any, error)
}

// AlertExporter retrieves alerts for the user.
type AlertExporter interface {
	ExportAlerts(email string) ([]any, error)
}

// WatchlistExporter retrieves watchlists + items for the user.
type WatchlistExporter interface {
	ExportWatchlists(email string) ([]any, error)
}

// PaperTradeExporter retrieves paper-trading state for the user.
type PaperTradeExporter interface {
	ExportPaperTrades(email string) ([]any, error)
}

// SessionExporter retrieves session/credential metadata.
// Credentials must already be encrypted-at-rest; the export ships the
// encrypted blob.
type SessionExporter interface {
	ExportSessions(email string) ([]any, error)
	ExportCredentials(email string) ([]any, error)
}

// ConsentExporter retrieves the full consent_log history.
type ConsentExporter interface {
	ExportConsentLog(emailHash string) ([]any, error)
}

// DomainEventExporter retrieves domain events keyed by email_hash.
type DomainEventExporter interface {
	ExportDomainEvents(emailHash string, since time.Time) ([]any, error)
}

// DataExportPorts groups all eight port types in one struct so the
// use-case constructor signature stays manageable. Any field may be
// nil — the corresponding section will be reported as unavailable.
type DataExportPorts struct {
	ToolCalls     ToolCallExporter
	Alerts        AlertExporter
	Watchlists    WatchlistExporter
	PaperTrades   PaperTradeExporter
	Sessions      SessionExporter
	Consent       ConsentExporter
	DomainEvents  DomainEventExporter
	Hasher        EmailHasher // reused from consent_usecases.go
}

// DataExportSection wraps a section's rows + an optional unavailability
// note. Unavailable sections retain their key in the output JSON so
// downstream automated tooling sees a stable schema regardless of
// which stores are wired.
type DataExportSection struct {
	Rows  []any  `json:"rows,omitempty"`
	Count int    `json:"count"`
	Note  string `json:"note,omitempty"`
}

// DataExport is the canonical export shape returned to the user.
// JSON keys are stable and lower_snake_case so external automation
// can rely on them across versions.
type DataExport struct {
	GeneratedAtUTC time.Time `json:"generated_at_utc"`
	Email          string    `json:"email"`
	EmailHash      string    `json:"email_hash"`
	RetentionFrom  time.Time `json:"retention_from_utc"`

	ToolCalls    DataExportSection `json:"tool_calls"`
	Alerts       DataExportSection `json:"alerts"`
	Watchlists   DataExportSection `json:"watchlists"`
	PaperTrades  DataExportSection `json:"paper_trades"`
	Sessions     DataExportSection `json:"sessions"`
	Credentials  DataExportSection `json:"credentials"`
	Consent      DataExportSection `json:"consent_log"`
	DomainEvents DataExportSection `json:"domain_events"`
}

// ExportMyDataUseCase orchestrates the §11 portability dump. Any
// per-section error is captured into that section's Note so a
// partial-data store doesn't fail the whole export. Hard errors
// (validation, missing hasher) return up the stack.
type ExportMyDataUseCase struct {
	ports  DataExportPorts
	logger *slog.Logger
	now    func() time.Time
}

// NewExportMyDataUseCase builds the use case.
func NewExportMyDataUseCase(ports DataExportPorts, logger *slog.Logger) *ExportMyDataUseCase {
	return &ExportMyDataUseCase{
		ports:  ports,
		logger: logger,
		now:    func() time.Time { return time.Now().UTC() },
	}
}

// SetClock overrides the time source. Tests use this to assert
// deterministic generated_at_utc.
func (uc *ExportMyDataUseCase) SetClock(now func() time.Time) {
	uc.now = now
}

// Execute runs the export. Validates inputs, then queries every port
// in turn. A single nil port produces a section with Note="not wired"
// and proceeds. A port that errors produces a section with the error
// recorded in Note (keeping the schema stable for downstream tooling).
func (uc *ExportMyDataUseCase) Execute(_ context.Context, cmd cqrs.ExportMyDataCommand) (*DataExport, error) {
	email := strings.TrimSpace(cmd.Email)
	if email == "" {
		return nil, fmt.Errorf("usecases: export my data: email is required")
	}
	if uc.ports.Hasher == nil {
		return nil, fmt.Errorf("usecases: export my data: no email hasher wired")
	}

	emailHash := uc.ports.Hasher.HashEmail(email)
	if emailHash == "" {
		return nil, fmt.Errorf("usecases: export my data: hasher returned empty for %q", email)
	}

	now := uc.now()
	since := now.Add(-DataExportRetention)
	out := &DataExport{
		GeneratedAtUTC: now,
		Email:          strings.ToLower(email),
		EmailHash:      emailHash,
		RetentionFrom:  since,
	}

	out.ToolCalls = exportSection("tool_calls", uc.ports.ToolCalls != nil, func() ([]any, error) {
		return uc.ports.ToolCalls.ExportToolCalls(email, since)
	})
	out.Alerts = exportSection("alerts", uc.ports.Alerts != nil, func() ([]any, error) {
		return uc.ports.Alerts.ExportAlerts(email)
	})
	out.Watchlists = exportSection("watchlists", uc.ports.Watchlists != nil, func() ([]any, error) {
		return uc.ports.Watchlists.ExportWatchlists(email)
	})
	out.PaperTrades = exportSection("paper_trades", uc.ports.PaperTrades != nil, func() ([]any, error) {
		return uc.ports.PaperTrades.ExportPaperTrades(email)
	})
	out.Sessions = exportSection("sessions", uc.ports.Sessions != nil, func() ([]any, error) {
		return uc.ports.Sessions.ExportSessions(email)
	})
	out.Credentials = exportSection("credentials", uc.ports.Sessions != nil, func() ([]any, error) {
		return uc.ports.Sessions.ExportCredentials(email)
	})
	out.Consent = exportSection("consent_log", uc.ports.Consent != nil, func() ([]any, error) {
		return uc.ports.Consent.ExportConsentLog(emailHash)
	})
	out.DomainEvents = exportSection("domain_events", uc.ports.DomainEvents != nil, func() ([]any, error) {
		return uc.ports.DomainEvents.ExportDomainEvents(emailHash, since)
	})

	if uc.logger != nil {
		uc.logger.Info("data export generated",
			"email_hash", emailHash,
			"tool_calls", out.ToolCalls.Count,
			"alerts", out.Alerts.Count,
			"watchlists", out.Watchlists.Count,
			"paper_trades", out.PaperTrades.Count,
			"sessions", out.Sessions.Count,
			"credentials", out.Credentials.Count,
			"consent_log", out.Consent.Count,
			"domain_events", out.DomainEvents.Count,
		)
	}
	return out, nil
}

// exportSection wraps a per-section query. wired=false produces a
// "not wired" note section without invoking fn (so nil-port paths
// don't panic). A returned error becomes the Note text.
func exportSection(name string, wired bool, fn func() ([]any, error)) DataExportSection {
	if !wired {
		return DataExportSection{Note: name + ": not wired (DevMode or store not initialised)"}
	}
	rows, err := fn()
	if err != nil {
		return DataExportSection{
			Note:  fmt.Sprintf("%s: query error: %v", name, err),
			Count: 0,
		}
	}
	return DataExportSection{Rows: rows, Count: len(rows)}
}
