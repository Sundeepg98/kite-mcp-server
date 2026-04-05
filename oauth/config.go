package oauth

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Config holds OAuth 2.1 configuration.
type Config struct {
	KiteAPIKey  string        // Kite API key for generating login URLs (optional: per-user credentials via oauth_client_id)
	JWTSecret   string
	ExternalURL string   // e.g. https://kite-mcp-server.fly.dev
	TokenExpiry time.Duration
	Logger      *slog.Logger
}

// Validate checks that all required fields are set.
func (c *Config) Validate() error {
	// KiteAPIKey is optional — if empty, only per-user Kite credentials (via oauth_client_id) work
	if c.JWTSecret == "" {
		return fmt.Errorf("JWTSecret is required")
	}
	if c.ExternalURL == "" {
		return fmt.Errorf("ExternalURL is required")
	}
	// Strip trailing slash
	c.ExternalURL = strings.TrimRight(c.ExternalURL, "/")
	if c.TokenExpiry == 0 {
		c.TokenExpiry = 24 * time.Hour
	}
	return nil
}
