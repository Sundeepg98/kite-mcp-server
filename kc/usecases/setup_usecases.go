package usecases

import (
	"context"
	"fmt"
	"log/slog"

	"github.com/zerodha/kite-mcp-server/kc/cqrs"
	logport "github.com/zerodha/kite-mcp-server/kc/logger"
)

// --- Login ---

// SessionLoginURLProvider is the narrow port LoginUseCase needs from the
// Manager to generate a Kite login URL for a given MCP session. Keeping the
// dependency narrow matches the batch C adapter pattern and lets the use case
// own the full validation+URL-generation flow without pulling in Manager
// internals.
type SessionLoginURLProvider interface {
	SessionLoginURL(mcpSessionID string) (string, error)
}

// LoginResult is what LoginUseCase.Execute returns after a successful
// validation + URL generation. The tool handler is responsible for
// presentation (the warning banner, markdown link formatting, etc.) and for
// infrastructure side-effects like opening the browser.
type LoginResult struct {
	URL string `json:"url"`
}

// LoginUseCase validates login command parameters and, given a
// SessionLoginURLProvider, generates the Kite login URL.
type LoginUseCase struct {
	urls   SessionLoginURLProvider
	logger logport.Logger
}

// NewLoginUseCase creates a LoginUseCase with dependencies injected. The
// SessionLoginURLProvider may be nil for call-sites that only use Validate
// (e.g. legacy tests); Execute will return an error in that case.
func NewLoginUseCase(urls SessionLoginURLProvider, logger *slog.Logger) *LoginUseCase {
	return &LoginUseCase{urls: urls, logger: logport.NewSlog(logger)}
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

// Execute validates the login command and generates the Kite login URL for
// the given MCP session. Returns the URL wrapped in a LoginResult so the tool
// handler can format the response and auto-open the browser.
func (uc *LoginUseCase) Execute(ctx context.Context, cmd cqrs.LoginCommand) (*LoginResult, error) {
	if err := uc.Validate(ctx, cmd); err != nil {
		return nil, err
	}
	if uc.urls == nil {
		return nil, fmt.Errorf("usecases: LoginUseCase has no SessionLoginURLProvider")
	}
	if cmd.MCPSessionID == "" {
		return nil, fmt.Errorf("usecases: mcp_session_id is required to generate login URL")
	}
	url, err := uc.urls.SessionLoginURL(cmd.MCPSessionID)
	if err != nil {
		return nil, fmt.Errorf("usecases: generate kite login url: %w", err)
	}
	return &LoginResult{URL: url}, nil
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
	logger logport.Logger
}

// NewOpenDashboardUseCase creates an OpenDashboardUseCase with dependencies injected.
func NewOpenDashboardUseCase(logger *slog.Logger) *OpenDashboardUseCase {
	return &OpenDashboardUseCase{logger: logport.NewSlog(logger)}
}

// Validate checks that the dashboard query is valid.
func (uc *OpenDashboardUseCase) Validate(_ context.Context, query cqrs.OpenDashboardQuery) error {
	if query.Page == "" {
		return fmt.Errorf("usecases: page is required")
	}
	return nil
}
