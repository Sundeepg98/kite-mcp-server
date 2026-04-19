package kc

import (
	"fmt"
	"net/url"
	"os/exec"
	"runtime"
)

// config_manager.go holds the Manager's configuration accessors — pure
// getters over immutable values captured from Config at construction time
// (appMode, externalURL, adminSecretPath, apiKey, devMode). Extracted from
// manager.go in the SOLID-S split so config concerns sit in one focused
// file and the core Manager definition stays minimal.
//
// Also co-locates OpenBrowser because it gates on IsLocalMode() and has no
// other home that fits better — it's a config-aware IO utility that only
// runs in local/STDIO mode.
//
// All behavior here is read-only and unchanged from its previous inline
// form in manager.go.

// IsLocalMode returns true when running in STDIO mode (local process, not remote HTTP).
func (m *Manager) IsLocalMode() bool {
	return m.appMode == "" || m.appMode == "stdio"
}

// ExternalURL returns the configured external URL (e.g. "https://kite-mcp-server.fly.dev").
func (m *Manager) ExternalURL() string {
	return m.externalURL
}

// AdminSecretPath returns the configured admin secret path.
func (m *Manager) AdminSecretPath() string {
	return m.adminSecretPath
}

// DevMode returns true if the server is running in development mode with mock broker.
func (m *Manager) DevMode() bool {
	return m.devMode
}

// APIKey returns the global Kite API key.
func (m *Manager) APIKey() string {
	return m.apiKey
}

// OpenBrowser opens the given URL in the user's default browser.
// Only works in local/STDIO mode where the server runs on the user's machine.
func (m *Manager) OpenBrowser(rawURL string) error {
	if !m.IsLocalMode() {
		return nil
	}

	// Validate URL scheme to prevent command injection via crafted URIs
	parsed, err := url.Parse(rawURL)
	if err != nil || (parsed.Scheme != "http" && parsed.Scheme != "https") {
		return fmt.Errorf("invalid URL scheme: only http and https are allowed")
	}

	var cmd *exec.Cmd
	switch runtime.GOOS {
	case "windows":
		cmd = exec.Command("rundll32", "url.dll,FileProtocolHandler", rawURL) // #nosec G204 -- URL is validated above (scheme whitelist)
	case "darwin":
		cmd = exec.Command("open", rawURL) // #nosec G204 -- URL is validated above (scheme whitelist)
	default:
		cmd = exec.Command("xdg-open", rawURL) // #nosec G204 -- URL is validated above (scheme whitelist)
	}
	return cmd.Start()
}
