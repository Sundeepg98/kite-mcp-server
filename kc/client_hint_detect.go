package kc

import (
	"net/http"
	"strings"
)

// ─────────────────────────────────────────────────────────────────────────────
// Client hint detection
//
// ClientHint is a short, normalized string identifying which MCP client
// created a session. It is derived from HTTP request headers and OAuth
// metadata available at session creation time (before any tool call), and
// surfaced by the list_mcp_sessions MCP tool and the dashboard so users
// can see "which client am I connected from?".
//
// The detector is a pure function — it makes no I/O and has no state. It
// is safe to call from any HTTP handler or goroutine.
//
// Priority order (see task brief and TestDetectClientHintPrecedence):
//   1. HTTP User-Agent header   — most reliable, sent on every request
//   2. OAuth client_name        — from dynamic client registration
//   3. MCP initialize clientInfo.name — self-reported, last resort
//   4. "unknown"                — nothing matched
//
// Output is drawn from a small closed set so consumers can switch on it
// without worrying about free-form UA string drift.
// ─────────────────────────────────────────────────────────────────────────────

// Known normalized hints. Keep this list in sync with the docstring on
// MCPSession.ClientHint and with any UI that filters/sums by hint.
const (
	HintClaudeDesktop = "claude-desktop"
	HintClaudeCode    = "claude-code"
	HintClaudeWeb     = "claude-web"
	HintCursor        = "cursor"
	HintChatGPT       = "chatgpt"
	HintVSCode        = "vscode"
	HintMCPRemote     = "mcp-remote"
	HintUnknown       = "unknown"
)

// DetectClientHint returns a normalized hint based on the three signals
// available at session creation time. See the package comment above for
// priority order.
//
// Behavior:
//   - Tries userAgent first. If it matches a known pattern, that wins.
//   - Falls through to oauthClientName, then mcpClientInfoName.
//   - When nothing matches (or all inputs are empty), returns HintUnknown.
//
// The function is deliberately permissive — it returns a value for every
// input, including empty strings, rather than signalling errors. Sessions
// without an identifiable client are reported as "unknown" rather than
// blocking the session from being created.
func DetectClientHint(userAgent, oauthClientName, mcpClientInfoName string) string {
	if h := hintFromUserAgent(userAgent); h != HintUnknown {
		return h
	}
	if h := hintFromOAuthName(oauthClientName); h != HintUnknown {
		return h
	}
	if h := hintFromMCPClientInfo(mcpClientInfoName); h != HintUnknown {
		return h
	}
	return HintUnknown
}

// ClientHintFromRequest extracts a normalized client hint from an HTTP
// request. Returns an empty string when the request is nil (e.g. when
// called from the mcp-go idle sweeper path), letting the caller fall
// back to its own default behavior.
//
// When r is non-nil, this function always returns a non-empty hint
// (the normalized string "unknown" if no headers match).
func ClientHintFromRequest(r *http.Request) string {
	if r == nil {
		return ""
	}
	ua := r.Header.Get("User-Agent")
	// Some MCP clients additionally send X-MCP-Client as a fallback
	// identifier. Treat it as a weak supplement to UA — UA still wins.
	mcpClient := r.Header.Get("X-MCP-Client")
	return DetectClientHint(ua, "", mcpClient)
}

// hintFromUserAgent matches HTTP User-Agent strings to a normalized hint.
// Order matters — more specific matches come first (e.g. "claude-code"
// before "claude" which would otherwise capture Claude Desktop).
func hintFromUserAgent(ua string) string {
	if ua == "" {
		return HintUnknown
	}
	l := strings.ToLower(ua)

	switch {
	// Claude Code CLI — matches "claude-code/x.y.z" precisely to avoid
	// collision with Claude Desktop ("claude/x.y.z"). The hyphen in the
	// prefix is load-bearing.
	case strings.Contains(l, "claude-code"):
		return HintClaudeCode

	// Cursor IDE — sends "Cursor/<ver>" or "cursor/<ver>".
	case strings.Contains(l, "cursor"):
		return HintCursor

	// ChatGPT — desktop app or chatgpt.com web.
	case strings.Contains(l, "chatgpt"):
		return HintChatGPT

	// VS Code — "vscode/<ver>", "Visual Studio Code" literal, or
	// the Microsoft-Edge-style identifier.
	case strings.Contains(l, "vscode"),
		strings.Contains(l, "visual studio code"):
		return HintVSCode

	// Claude.ai web — served from claude.ai, typically via mcp-remote.
	// Matches "claude.ai/..." in the UA.
	case strings.Contains(l, "claude.ai"):
		return HintClaudeWeb

	// mcp-remote proxy (the node.js helper that brokers MCP for web
	// clients). Surfaces "mcp-remote" literally or a node-fetch wrapper
	// that references the repo.
	case strings.Contains(l, "mcp-remote"):
		return HintMCPRemote

	// Claude Desktop — "Claude/<ver>" or "claude-desktop/<ver>". Check
	// this AFTER claude-code, claude.ai, and mcp-remote above because
	// "claude" is a substring of all three.
	case strings.Contains(l, "claude-desktop"),
		strings.HasPrefix(l, "claude/"):
		return HintClaudeDesktop
	}
	return HintUnknown
}

// hintFromOAuthName matches an OAuth dynamic client registration's
// client_name to a normalized hint. Client names tend to be
// human-readable ("Claude Desktop", "Visual Studio Code") so we match
// on case-folded substrings rather than literal IDs.
func hintFromOAuthName(name string) string {
	if name == "" {
		return HintUnknown
	}
	l := strings.ToLower(name)

	switch {
	// More-specific matches first (same rationale as in hintFromUserAgent).
	case strings.Contains(l, "claude code"),
		strings.Contains(l, "claude-code"):
		return HintClaudeCode

	case strings.Contains(l, "cursor"):
		return HintCursor

	case strings.Contains(l, "chatgpt"),
		strings.Contains(l, "chat gpt"):
		return HintChatGPT

	case strings.Contains(l, "vscode"),
		strings.Contains(l, "visual studio code"):
		return HintVSCode

	case strings.Contains(l, "claude.ai"),
		strings.Contains(l, "claude (claude.ai)"),
		strings.Contains(l, "claude ai"):
		return HintClaudeWeb

	case strings.Contains(l, "mcp-remote"),
		strings.Contains(l, "mcp remote"):
		return HintMCPRemote

	case strings.Contains(l, "claude desktop"),
		strings.Contains(l, "claude-desktop"):
		return HintClaudeDesktop
	}
	return HintUnknown
}

// hintFromMCPClientInfo matches the MCP initialize payload's
// clientInfo.name to a normalized hint. This is the MCP-native
// self-identification field, so values tend to be lowercase and
// hyphenated (e.g. "claude-ai", "cursor-vscode", "claude-code").
func hintFromMCPClientInfo(name string) string {
	if name == "" {
		return HintUnknown
	}
	l := strings.ToLower(name)

	switch {
	// claude-ai is the name Claude.ai web sets in MCP initialize — map
	// it to claude-web so it matches the UA-derived hint.
	case strings.Contains(l, "claude-ai"),
		strings.Contains(l, "claude.ai"):
		return HintClaudeWeb

	case strings.Contains(l, "claude-code"):
		return HintClaudeCode

	case strings.Contains(l, "cursor"):
		return HintCursor

	case strings.Contains(l, "chatgpt"):
		return HintChatGPT

	case strings.Contains(l, "vscode"),
		strings.Contains(l, "visual studio code"),
		strings.Contains(l, "copilot"):
		return HintVSCode

	case strings.Contains(l, "mcp-remote"):
		return HintMCPRemote

	case strings.Contains(l, "claude-desktop"),
		strings.Contains(l, "claude desktop"):
		return HintClaudeDesktop
	}
	return HintUnknown
}
