package kc

import (
	"net/http"
	"net/http/httptest"
	"testing"
)

// TestDetectClientHintFromUserAgent verifies that User-Agent strings map to
// the expected normalized hint. These cases mirror the real UAs seen in
// production traffic from each supported MCP client surface.
func TestDetectClientHintFromUserAgent(t *testing.T) {
	tests := []struct {
		name      string
		userAgent string
		want      string
	}{
		// Claude Desktop — appends "Claude/<ver>" with platform annotation.
		{name: "claude_desktop_macos", userAgent: "Claude/1.2.3 (macOS; arm64)", want: "claude-desktop"},
		{name: "claude_desktop_windows", userAgent: "Claude/0.9.5 (Windows NT 10.0; x64)", want: "claude-desktop"},
		{name: "claude_desktop_lowercase", userAgent: "claude-desktop/1.0", want: "claude-desktop"},

		// Claude Code CLI — sends "claude-code/<ver>".
		{name: "claude_code_cli", userAgent: "claude-code/2.4.1", want: "claude-code"},
		{name: "claude_code_cli_mixed_case", userAgent: "Claude-Code/3.0.0 (1M context)", want: "claude-code"},

		// Cursor — embedded MCP client.
		{name: "cursor_mac", userAgent: "Cursor/0.42.0 (darwin)", want: "cursor"},
		{name: "cursor_windows", userAgent: "cursor/0.50.1", want: "cursor"},

		// ChatGPT — via chatgpt.com or the OpenAI desktop app.
		{name: "chatgpt_web", userAgent: "chatgpt.com/1.0", want: "chatgpt"},
		{name: "chatgpt_desktop", userAgent: "ChatGPT/1.2024.330 (macOS)", want: "chatgpt"},

		// VS Code — via the built-in MCP support or Copilot.
		{name: "vscode_mcp", userAgent: "vscode/1.95.0 (mcp-client)", want: "vscode"},
		{name: "vscode_node", userAgent: "Visual Studio Code (1.96.0)", want: "vscode"},

		// Claude.ai web surface — served from claude.ai, usually via mcp-remote proxy.
		{name: "claude_ai_web", userAgent: "claude.ai/web", want: "claude-web"},

		// mcp-remote proxy — the Node.js helper that brokers most of the
		// above. Its UA looks like "node" or includes mcp-remote identifiers.
		// Identifying it as "mcp-remote" is the safest lowest-common
		// fallback so telemetry knows the hop but not the final surface.
		{name: "mcp_remote_default", userAgent: "mcp-remote/0.1.20", want: "mcp-remote"},
		{name: "mcp_remote_node_wrapper", userAgent: "node-fetch/1.0 (+https://github.com/bitovi/mcp-remote)", want: "mcp-remote"},

		// Unknown user agent — fall back to "unknown".
		{name: "empty", userAgent: "", want: "unknown"},
		{name: "random_browser", userAgent: "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36", want: "unknown"},
		{name: "unrecognized_tool", userAgent: "MyCustomBot/1.0", want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectClientHint(tt.userAgent, "", "")
			if got != tt.want {
				t.Errorf("DetectClientHint(ua=%q) = %q, want %q", tt.userAgent, got, tt.want)
			}
		})
	}
}

// TestDetectClientHintFromOAuthMetadata verifies fallback to the OAuth
// dynamic client registration's client_name when the User-Agent is empty
// or unrecognized. This path matters for clients that register via the
// /oauth/register endpoint before issuing an MCP call.
func TestDetectClientHintFromOAuthMetadata(t *testing.T) {
	tests := []struct {
		name           string
		oauthClientName string
		want           string
	}{
		{name: "claude_desktop_registration", oauthClientName: "Claude Desktop", want: "claude-desktop"},
		{name: "claude_code_registration", oauthClientName: "Claude Code", want: "claude-code"},
		{name: "cursor_registration", oauthClientName: "Cursor", want: "cursor"},
		{name: "chatgpt_registration", oauthClientName: "ChatGPT", want: "chatgpt"},
		{name: "vscode_registration", oauthClientName: "Visual Studio Code", want: "vscode"},
		{name: "claude_web_registration", oauthClientName: "Claude (claude.ai)", want: "claude-web"},
		{name: "mcp_remote_registration", oauthClientName: "mcp-remote", want: "mcp-remote"},
		{name: "unknown_registration", oauthClientName: "SomeRandomApp", want: "unknown"},
		{name: "empty_registration", oauthClientName: "", want: "unknown"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectClientHint("", tt.oauthClientName, "")
			if got != tt.want {
				t.Errorf("DetectClientHint(oauth=%q) = %q, want %q", tt.oauthClientName, got, tt.want)
			}
		})
	}
}

// TestDetectClientHintFromMCPInitialize verifies fallback to the MCP
// initialize payload's clientInfo.name when both User-Agent and OAuth
// metadata are absent or unrecognized.
func TestDetectClientHintFromMCPInitialize(t *testing.T) {
	tests := []struct {
		name               string
		mcpClientInfoName string
		want               string
	}{
		{name: "claude_desktop_init", mcpClientInfoName: "claude-ai", want: "claude-web"},
		{name: "claude_code_init", mcpClientInfoName: "claude-code", want: "claude-code"},
		{name: "cursor_init", mcpClientInfoName: "cursor-vscode", want: "cursor"},
		{name: "vscode_init", mcpClientInfoName: "Visual Studio Code Copilot", want: "vscode"},
		{name: "empty_init", mcpClientInfoName: "", want: "unknown"},
		{name: "random_init", mcpClientInfoName: "ExperimentalClient", want: "unknown"},
		{name: "mcp_remote_init", mcpClientInfoName: "mcp-remote", want: "mcp-remote"},
		{name: "claude_desktop_init", mcpClientInfoName: "claude-desktop", want: "claude-desktop"},
		{name: "claude_desktop_init_spaced", mcpClientInfoName: "Claude Desktop", want: "claude-desktop"},
		{name: "chatgpt_init", mcpClientInfoName: "chatgpt", want: "chatgpt"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectClientHint("", "", tt.mcpClientInfoName)
			if got != tt.want {
				t.Errorf("DetectClientHint(mcp=%q) = %q, want %q", tt.mcpClientInfoName, got, tt.want)
			}
		})
	}
}

// TestDetectClientHintPrecedence verifies that when multiple sources are
// available, the User-Agent wins over OAuth metadata, which wins over the
// MCP initialize payload. This matches the priority order defined in the
// task brief: UA is most reliable (sent on every HTTP request), while
// the MCP initialize name is self-reported by the client and can be empty
// or truncated across transports.
func TestDetectClientHintPrecedence(t *testing.T) {
	tests := []struct {
		name              string
		userAgent         string
		oauthClientName   string
		mcpClientInfoName string
		want              string
	}{
		{
			name:              "ua_wins_over_oauth_and_mcp",
			userAgent:         "Claude/1.2.3 (macOS)",
			oauthClientName:   "Cursor",
			mcpClientInfoName: "vscode",
			want:              "claude-desktop",
		},
		{
			name:              "oauth_wins_when_ua_unknown",
			userAgent:         "Mozilla/5.0",
			oauthClientName:   "Cursor",
			mcpClientInfoName: "chatgpt",
			want:              "cursor",
		},
		{
			name:              "mcp_wins_when_ua_and_oauth_unknown",
			userAgent:         "Mozilla/5.0",
			oauthClientName:   "SomeRandomApp",
			mcpClientInfoName: "claude-code",
			want:              "claude-code",
		},
		{
			name:              "all_unknown_returns_unknown",
			userAgent:         "Mozilla/5.0",
			oauthClientName:   "FooBar",
			mcpClientInfoName: "BazQux",
			want:              "unknown",
		},
		{
			name:              "all_empty_returns_unknown",
			userAgent:         "",
			oauthClientName:   "",
			mcpClientInfoName: "",
			want:              "unknown",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectClientHint(tt.userAgent, tt.oauthClientName, tt.mcpClientInfoName)
			if got != tt.want {
				t.Errorf("DetectClientHint(ua=%q, oauth=%q, mcp=%q) = %q, want %q",
					tt.userAgent, tt.oauthClientName, tt.mcpClientInfoName, got, tt.want)
			}
		})
	}
}

// TestDetectClientHintFromRequest verifies the HTTP-request helper that
// callers use from inside HTTP handlers. Handles the nil-request case
// that can arise when the mcp-go library calls ResolveSessionIdManager
// from the idle-TTL sweeper path (see vendor streamable_http.go comments).
func TestDetectClientHintFromRequest(t *testing.T) {
	t.Run("nil_request", func(t *testing.T) {
		got := ClientHintFromRequest(nil)
		if got != "" {
			t.Errorf("ClientHintFromRequest(nil) = %q, want empty string", got)
		}
	})

	t.Run("request_with_ua_header", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		r.Header.Set("User-Agent", "Claude/1.2.3 (macOS)")
		got := ClientHintFromRequest(r)
		if got != "claude-desktop" {
			t.Errorf("ClientHintFromRequest(UA=Claude) = %q, want claude-desktop", got)
		}
	})

	t.Run("request_without_ua", func(t *testing.T) {
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		r.Header.Del("User-Agent")
		got := ClientHintFromRequest(r)
		if got != "unknown" {
			t.Errorf("ClientHintFromRequest(no UA) = %q, want unknown", got)
		}
	})

	t.Run("request_with_mcp_client_info_header", func(t *testing.T) {
		// Some clients set X-MCP-Client or similar custom headers.
		// We accept common names alongside User-Agent.
		r := httptest.NewRequest(http.MethodPost, "/mcp", nil)
		r.Header.Set("User-Agent", "mcp-remote/0.1.20")
		r.Header.Set("X-MCP-Client", "claude-code")
		got := ClientHintFromRequest(r)
		// UA identifies mcp-remote, which is more specific than the
		// hop-agnostic X-MCP-Client signal, so UA wins.
		if got != "mcp-remote" {
			t.Errorf("ClientHintFromRequest(UA=mcp-remote, X-MCP-Client=claude-code) = %q, want mcp-remote", got)
		}
	})
}

// TestDetectClientHintNormalized exercises the helper's contract that the
// output is always a valid normalized hint suitable for persisting as-is:
// lowercase, no whitespace, drawn from a closed enum.
func TestDetectClientHintNormalized(t *testing.T) {
	validHints := map[string]struct{}{
		"claude-desktop": {},
		"claude-code":    {},
		"claude-web":     {},
		"cursor":         {},
		"chatgpt":        {},
		"vscode":         {},
		"mcp-remote":     {},
		"unknown":        {},
	}

	uas := []string{
		"",
		"Claude/1.0",
		"claude-code/1.0",
		"Cursor/1.0",
		"ChatGPT/1.0",
		"vscode/1.0",
		"claude.ai/web",
		"mcp-remote/0.1",
		"MyTool/1.0",
		"Mozilla/5.0",
	}
	for _, ua := range uas {
		h := DetectClientHint(ua, "", "")
		if _, ok := validHints[h]; !ok {
			t.Errorf("DetectClientHint(%q) = %q — not in the allowed hint set", ua, h)
		}
	}
}

// TestSessionRegistry_GenerateWithDataAndHint_Populates verifies that the
// existing GenerateWithDataAndHint path (already in kc/session.go) writes
// the hint into the MCPSession. This test codifies the contract that a
// hint passed in is retrievable intact via GetSession.
func TestSessionRegistry_GenerateWithDataAndHint_Populates(t *testing.T) {
	reg := NewSessionRegistry(testLogger())
	hint := "claude-desktop"

	sessionID := reg.GenerateWithDataAndHint(&KiteSessionData{Email: "u@x.com"}, hint)
	if sessionID == "" {
		t.Fatal("GenerateWithDataAndHint returned empty session ID")
	}

	session, err := reg.GetSession(sessionID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if session.ClientHint != hint {
		t.Errorf("session.ClientHint = %q, want %q", session.ClientHint, hint)
	}
}

// TestSessionRegistry_GenerateWithDataAndHint_EmptyHint verifies that an
// empty hint is accepted without error — callers that have no request
// context (SSE, stdio, sweeper) must still be able to generate sessions.
func TestSessionRegistry_GenerateWithDataAndHint_EmptyHint(t *testing.T) {
	reg := NewSessionRegistry(testLogger())

	sessionID := reg.GenerateWithDataAndHint(&KiteSessionData{Email: "u@x.com"}, "")
	session, err := reg.GetSession(sessionID)
	if err != nil {
		t.Fatalf("GetSession failed: %v", err)
	}
	if session.ClientHint != "" {
		t.Errorf("session.ClientHint = %q, want empty for no-hint path", session.ClientHint)
	}
}
