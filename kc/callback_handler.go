package kc

import (
	"errors"
	"fmt"
	"net/http"
)

// TemplateData holds data for template rendering on callback success.
type TemplateData struct {
	Title       string
	RedirectURL string // optional: used by login_success.html for auto-redirect
}

// HandleKiteCallback returns an HTTP handler for Kite authentication callbacks.
// Kept as a Manager method for backward compatibility with existing callers
// in app/http.go and the test suite.
func (m *Manager) HandleKiteCallback() func(w http.ResponseWriter, r *http.Request) {
	return func(w http.ResponseWriter, r *http.Request) {
		m.Logger.Debug("Received Kite callback request", "url", r.URL.String())
		requestToken, mcpSessionID, err := m.extractCallbackParams(r)
		if err != nil {
			m.handleCallbackError(w, missingParamsMessage, http.StatusBadRequest, "Invalid callback parameters", "error", err)
			return
		}

		m.Logger.Debug("Processing Kite callback for MCP session ID", "session_id", mcpSessionID, "request_token", requestToken)

		// G99 — rotate the session ID after successful Kite auth.
		// Returning the new ID via the success template is downstream
		// work (cookie + AppBridge propagation); for now we just log
		// it so operators correlate. Crucially, the OLD id is now
		// terminated — an attacker that pre-set it cannot use it.
		newSessionID, err := m.CompleteSessionAndRotate(mcpSessionID, requestToken)
		if err != nil {
			m.handleCallbackError(w, sessionErrorMessage, http.StatusInternalServerError, "Error completing Kite session", "session_id", mcpSessionID, "error", err)
			return
		}

		m.Logger.Info("Kite session completed and rotated", "old_session_id", mcpSessionID, "new_session_id", newSessionID)

		if err := m.renderSuccessTemplate(w); err != nil {
			m.Logger.Error("Template failed to load - this is a fatal error", "error", err)
			http.Error(w, "Internal server error: template not available", http.StatusInternalServerError)
			return
		}

		m.Logger.Info("Kite callback completed successfully", "session_id", mcpSessionID)
	}
}

// handleCallbackError handles error responses for callback processing.
// keyvals must be slog-style key-value pairs (e.g. "key", value, "key2", value2).
func (m *Manager) handleCallbackError(w http.ResponseWriter, message string, statusCode int, logMessage string, keyvals ...any) {
	m.Logger.Error(logMessage, keyvals...)
	http.Error(w, message, statusCode)
}

// extractCallbackParams extracts and validates callback parameters with signature verification.
func (m *Manager) extractCallbackParams(r *http.Request) (kiteRequestToken, mcpSessionID string, err error) {
	qVals := r.URL.Query()
	kiteRequestToken = qVals.Get("request_token")
	signedSessionID := qVals.Get("session_id")

	if signedSessionID == "" || kiteRequestToken == "" {
		return "", "", errors.New("missing required parameters (MCP session_id or Kite request_token)")
	}

	// Verify the signed session ID
	mcpSessionID, err = m.sessionSigner.VerifySessionID(signedSessionID)
	if err != nil {
		m.Logger.Error("Failed to verify session signature", "error", err)
		return "", "", fmt.Errorf("invalid or tampered session parameter: %w", err)
	}

	return kiteRequestToken, mcpSessionID, nil
}

// renderSuccessTemplate renders the success page template.
func (m *Manager) renderSuccessTemplate(w http.ResponseWriter) error {
	templ, ok := m.templates[indexTemplate]
	if !ok {
		return errors.New(templateNotFoundError)
	}

	data := TemplateData{
		Title: "Login Successful",
	}

	return templ.ExecuteTemplate(w, "base", data)
}
