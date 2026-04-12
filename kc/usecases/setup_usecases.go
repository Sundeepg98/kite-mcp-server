package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
)

// --- Login ---

// LoginUseCase validates login command parameters.
// The actual session creation and URL generation remain in the tool handler
// because they require MCP session context and Manager internals.
type LoginUseCase struct {
	logger *slog.Logger
}

// NewLoginUseCase creates a LoginUseCase with dependencies injected.
func NewLoginUseCase(logger *slog.Logger) *LoginUseCase {
	return &LoginUseCase{logger: logger}
}

// Validate checks login command parameters for correctness.
func (uc *LoginUseCase) Validate(_ context.Context, cmd cqrs.LoginCommand) error {
	if cmd.APIKey != "" && cmd.APISecret == "" {
		return fmt.Errorf("usecases: both api_key and api_secret are required (provide both or neither)")
	}
	if cmd.APISecret != "" && cmd.APIKey == "" {
		return fmt.Errorf("usecases: both api_key and api_secret are required (provide both or neither)")
	}

	if cmd.APIKey != "" && !isAlphanumeric(cmd.APIKey) {
		return fmt.Errorf("usecases: invalid api_key: must contain only alphanumeric characters")
	}
	if cmd.APISecret != "" && !isAlphanumeric(cmd.APISecret) {
		return fmt.Errorf("usecases: invalid api_secret: must contain only alphanumeric characters")
	}

	return nil
}

// isAlphanumeric returns true if s is non-empty and contains only ASCII letters and digits.
func isAlphanumeric(s string) bool {
	for _, r := range s {
		if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9')) {
			return false
		}
	}
	return len(s) > 0
}

// --- Open Dashboard ---

// OpenDashboardUseCase validates dashboard page requests.
type OpenDashboardUseCase struct {
	logger *slog.Logger
}

// NewOpenDashboardUseCase creates an OpenDashboardUseCase with dependencies injected.
func NewOpenDashboardUseCase(logger *slog.Logger) *OpenDashboardUseCase {
	return &OpenDashboardUseCase{logger: logger}
}

// Validate checks that the dashboard query is valid.
func (uc *OpenDashboardUseCase) Validate(_ context.Context, query cqrs.OpenDashboardQuery) error {
	if query.Page == "" {
		return fmt.Errorf("usecases: page is required")
	}
	return nil
}
