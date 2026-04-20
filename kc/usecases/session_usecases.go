package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// SessionDataClearer abstracts the session-data clearing operation. Narrow
// port (one method) so the use case does not pull in the full SessionPort /
// SessionProvider surface just to perform a single lifecycle write. The kc
// package's SessionService satisfies this natively via its ClearSessionData
// method, so no adapter is required at the wiring site.
type SessionDataClearer interface {
	ClearSessionData(sessionID string) error
}

// ClearSessionDataUseCase clears the Kite session data attached to an MCP
// session without terminating the session itself. Owns the persistence
// step — the handler in kc/manager_commands_setup.go invokes Execute, and
// mcp/ tool handlers must not reach past the bus to call ClearSessionData
// directly (Round-5 Phase B contract for sessions).
type ClearSessionDataUseCase struct {
	sessions SessionDataClearer
	logger   *slog.Logger
}

// NewClearSessionDataUseCase creates a ClearSessionDataUseCase with the
// session clearer injected via the narrow SessionDataClearer port. sessions
// may be nil during partial bootstrap; Execute returns an error in that case
// so a missing dependency surfaces rather than silently succeeding.
func NewClearSessionDataUseCase(sessions SessionDataClearer, logger *slog.Logger) *ClearSessionDataUseCase {
	return &ClearSessionDataUseCase{sessions: sessions, logger: logger}
}

// Execute clears the session data for the command's SessionID. Reason is
// logged at Info level so audit trails can correlate the clear with the
// lifecycle narrative (post-credential-register vs profile-check-failed).
func (uc *ClearSessionDataUseCase) Execute(ctx context.Context, cmd cqrs.ClearSessionDataCommand) error {
	if cmd.SessionID == "" {
		return fmt.Errorf("usecases: session_id is required")
	}
	if uc.sessions == nil {
		return fmt.Errorf("usecases: session clearer not configured")
	}
	if err := uc.sessions.ClearSessionData(cmd.SessionID); err != nil {
		return fmt.Errorf("usecases: clear session data: %w", err)
	}
	if uc.logger != nil {
		reason := cmd.Reason
		if reason == "" {
			reason = "unspecified"
		}
		uc.logger.Info("Session data cleared via command bus", "session_id", cmd.SessionID, "reason", reason)
	}
	return nil
}
