package oauth

import (
	"fmt"
	"log/slog"
	"strings"
	"time"
)

// Config holds OAuth 2.1 configuration.
type Config struct {
	GoogleClientID     string
	GoogleClientSecret string
	JWTSecret          string
	AllowedEmails      []string // if empty, any Google account is allowed
	ExternalURL        string   // e.g. https://kite-mcp-server.fly.dev
	TokenExpiry        time.Duration
	Logger             *slog.Logger
}

// Validate checks that all required fields are set.
func (c *Config) Validate() error {
	if c.GoogleClientID == "" {
		return fmt.Errorf("GoogleClientID is required")
	}
	if c.GoogleClientSecret == "" {
		return fmt.Errorf("GoogleClientSecret is required")
	}
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

// IsEmailAllowed checks if the given email is permitted.
func (c *Config) IsEmailAllowed(email string) bool {
	if len(c.AllowedEmails) == 0 {
		return true
	}
	for _, e := range c.AllowedEmails {
		if strings.EqualFold(e, email) {
			return true
		}
	}
	return false
}
