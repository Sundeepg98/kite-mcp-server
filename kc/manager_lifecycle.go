package kc

import (
	"fmt"
	"html/template"
	"time"

	"github.com/zerodha/kite-mcp-server/kc/alerts"
	"github.com/zerodha/kite-mcp-server/kc/templates"
)

// manager_lifecycle.go holds the Manager's startup/shutdown surface:
// the two unexported init helpers called from New(), the Shutdown
// teardown sequence, the template setup function, and the sessionDBAdapter
// bridge used to thread the shared alerts.DB into SessionRegistry.
//
// Extracted from manager.go in the SOLID-S split so the constructor
// stays in manager.go and the lifecycle mechanics live alongside other
// lifecycle code. Pure file move — no behavior change.

// initializeTemplates sets up HTML templates.
func (m *Manager) initializeTemplates() error {
	templates, err := setupTemplates()
	if err != nil {
		return fmt.Errorf("failed to setup templates: %w", err)
	}
	m.templates = templates
	return nil
}

// initializeSessionSigner sets up HMAC session signing.
func (m *Manager) initializeSessionSigner(customSigner *SessionSigner) error {
	if customSigner != nil {
		m.sessionSigner = customSigner
		return nil
	}

	signer, err := NewSessionSigner()
	if err != nil {
		return fmt.Errorf("failed to create session signer: %w", err)
	}
	m.sessionSigner = signer
	return nil
}

// Shutdown gracefully shuts down the manager and all its components.
func (m *Manager) Shutdown() {
	m.Logger.Info("Shutting down Kite manager...")

	// Stop session cleanup routines
	m.sessionManager.StopCleanupRoutine()

	// Shutdown metrics manager (stops cleanup routine)
	if m.metrics != nil {
		m.metrics.Shutdown()
	}

	// Shutdown ticker service (stops all WebSocket connections)
	m.tickerService.Shutdown()

	// Close alert DB after ticker (ticker's OnTick writes through to DB)
	if m.alertDB != nil {
		if err := m.alertDB.Close(); err != nil {
			m.Logger.Error("Failed to close alert DB", "error", err)
		}
	}

	// Shutdown instruments manager (stops scheduler)
	m.Instruments.Shutdown()

	m.Logger.Info("Kite manager shutdown complete")
}

// setupTemplates parses the HTML templates embedded in kc/templates.
func setupTemplates() (map[string]*template.Template, error) {
	out := map[string]*template.Template{}

	templateList := []string{indexTemplate}

	for _, templateName := range templateList {
		// Parse template with base template for composition support
		templ, err := template.ParseFS(templates.FS, "base.html", templateName)
		if err != nil {
			return out, fmt.Errorf("error parsing %s: %w", templateName, err)
		}
		out[templateName] = templ
	}

	return out, nil
}

// sessionDBAdapter bridges alerts.DB to the SessionDB interface expected by SessionRegistry.
type sessionDBAdapter struct {
	db *alerts.DB
}

func (a *sessionDBAdapter) SaveSession(sessionID, email string, createdAt, expiresAt time.Time, terminated bool) error {
	return a.db.SaveSession(sessionID, email, createdAt, expiresAt, terminated)
}

func (a *sessionDBAdapter) LoadSessions() ([]*SessionLoadEntry, error) {
	entries, err := a.db.LoadSessions()
	if err != nil {
		return nil, err
	}
	result := make([]*SessionLoadEntry, len(entries))
	for i, e := range entries {
		result[i] = &SessionLoadEntry{
			SessionID:  e.SessionID,
			Email:      e.Email,
			CreatedAt:  e.CreatedAt,
			ExpiresAt:  e.ExpiresAt,
			Terminated: e.Terminated,
		}
	}
	return result, nil
}

func (a *sessionDBAdapter) DeleteSession(sessionID string) error {
	return a.db.DeleteSession(sessionID)
}
