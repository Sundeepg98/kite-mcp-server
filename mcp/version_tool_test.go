package mcp

import (
	"encoding/json"
	"regexp"
	"runtime"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
)

// TestServerVersionTool_ToolDefinition verifies the tool registration metadata
// (name, description, read-only annotation) so the tool is surfaced correctly
// to MCP clients.
func TestServerVersionTool_ToolDefinition(t *testing.T) {
	t.Parallel()
	tool := (&ServerVersionTool{}).Tool()
	assert.Equal(t, "server_version", tool.Name)
	assert.NotEmpty(t, tool.Description)
	assert.NotNil(t, tool.Annotations)
	assert.NotNil(t, tool.Annotations.ReadOnlyHint, "server_version must be marked read-only")
	assert.True(t, *tool.Annotations.ReadOnlyHint, "server_version must be marked read-only")
	assert.NotNil(t, tool.Annotations.IdempotentHint, "server_version should be idempotent")
	assert.True(t, *tool.Annotations.IdempotentHint, "server_version should be idempotent")
}

// TestServerVersion_Registered verifies the tool appears in GetAllTools so it
// actually ships to clients — catches wiring regressions.
func TestServerVersion_Registered(t *testing.T) {
	t.Parallel()
	names := make(map[string]bool)
	for _, td := range GetAllTools() {
		names[td.Tool().Name] = true
	}
	assert.True(t, names["server_version"], "server_version must be registered in GetAllTools")
}

// TestServerVersion_HandlerResponse verifies the handler returns a well-formed
// structured response with every documented field.
func TestServerVersion_HandlerResponse(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolWithManager(t, mgr, "server_version", "trader@example.com", map[string]any{})
	assert.False(t, result.IsError, "server_version should never error, got: %s", resultText(t, result))

	text := resultText(t, result)
	var parsed serverVersionResponse
	err := json.Unmarshal([]byte(text), &parsed)
	assert.NoError(t, err, "response must be valid JSON: %s", text)

	// git_sha: present (value may be "unknown" in test, or a short SHA from VCS BuildInfo).
	assert.NotEmpty(t, parsed.GitSHA, "git_sha must always be set (even if 'unknown')")

	// build_time: non-empty string.
	assert.NotEmpty(t, parsed.BuildTime, "build_time must always be set")

	// region: 'local' by default in tests, or a Fly.io region if FLY_REGION is set.
	assert.NotEmpty(t, parsed.Region, "region must always be set")

	// go_version: runtime.Version() (e.g. go1.25.8).
	assert.Equal(t, runtime.Version(), parsed.GoVersion, "go_version should equal runtime.Version()")
	assert.True(t, strings.HasPrefix(parsed.GoVersion, "go"), "go_version should start with 'go'")

	// uptime_s: non-negative.
	assert.GreaterOrEqual(t, parsed.UptimeSeconds, int64(0), "uptime_s must be non-negative")

	// env_flags: non-nil map, has enable_trading key.
	assert.NotNil(t, parsed.EnvFlags, "env_flags must be populated")
	_, hasTrading := parsed.EnvFlags["enable_trading"]
	assert.True(t, hasTrading, "env_flags must include enable_trading")
}

// TestServerVersion_NoSecretLeaks is a paranoia scan: we must never surface
// API keys, bearer tokens, AWS creds, DB paths, or other sensitive env in the
// response. The set of patterns mirrors what we grep for in prod log sanitizers.
func TestServerVersion_NoSecretLeaks(t *testing.T) {
	t.Parallel()
	mgr := newDevModeManager(t)
	result := callToolWithManager(t, mgr, "server_version", "trader@example.com", map[string]any{})
	assert.False(t, result.IsError)

	text := resultText(t, result)
	forbidden := []*regexp.Regexp{
		regexp.MustCompile(`(?i)api[_-]?key\s*[:=]`),             // "api_key:" or "api-key="
		regexp.MustCompile(`(?i)api[_-]?secret\s*[:=]`),          // "api_secret:" / "api-secret="
		regexp.MustCompile(`AKIA[0-9A-Z]{16}`),                   // AWS access key IDs
		regexp.MustCompile(`(?i)bearer\s+[a-zA-Z0-9._\-]+`),      // JWT-ish bearer tokens
		regexp.MustCompile(`(?i)secret\s*[:=]\s*["']?[^,}\s"']+`), // generic "secret:value"
		regexp.MustCompile(`ALERT_DB_PATH`),                      // DB path env var name
		regexp.MustCompile(`OAUTH_JWT_SECRET`),                   // JWT signing secret
		regexp.MustCompile(`TELEGRAM_BOT_TOKEN`),                 // telegram bot
		regexp.MustCompile(`KITE_API_SECRET`),                    // global Kite secret
		regexp.MustCompile(`KITE_ACCESS_TOKEN`),                  // access token env
	}
	for _, pat := range forbidden {
		assert.Falsef(t, pat.MatchString(text),
			"server_version response leaked a secret-looking pattern %q: %s", pat.String(), text)
	}
}

// TestParseEnableTradingFlag verifies the pure ENABLE_TRADING parser.
// Default (empty / "false") → false, "true"/"1"/"yes"/"on" → true.
// Pure parser — no env read, so the test runs in parallel.
func TestParseEnableTradingFlag(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name string
		raw  string
		want bool
	}{
		{"empty defaults to false", "", false},
		{"explicit false", "false", false},
		{"explicit true", "true", true},
		{"mixed-case True", "True", true},
		{"1 is true", "1", true},
	}
	for _, tc := range tests {
		tc := tc
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got := parseEnableTradingFlag(tc.raw)
			assert.Equal(t, tc.want, got, "parseEnableTradingFlag(%q)", tc.raw)
		})
	}
}
