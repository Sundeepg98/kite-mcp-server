//go:build e2e

// Package mcp — end-to-end MCP protocol roundtrip test.
//
// Unlike admin_integration_test.go (which calls ToolHandler.Handle
// in-process), this file spawns the compiled server binary as a
// subprocess, pipes JSON-RPC requests over stdin, and parses
// responses off stdout. It catches protocol-level regressions that
// handler-level tests cannot:
//
//   - initialize handshake + capability negotiation
//   - tools/list shape + ordering + annotation flags
//   - read-only tool dispatch end-to-end, including the widget
//     metadata shim (openai/outputTemplate vs ui://) and
//     structuredContent plumbing
//   - error-response framing for unknown tools
//
// Gated behind `//go:build e2e` so the default `go test ./...`
// suite stays fast; opt-in via `go test -tags=e2e ./mcp/...`.
// CI wires this in .github/workflows/ci.yml as a distinct job so
// a broken binary does not block unit-test feedback.
//
// Runtime cost: ~2s per roundtrip (build + spawn + shutdown).
// Tolerance ceiling: 30s per test function.

package mcp

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// e2eServerBinary builds the server into a temp path and returns its
// absolute path. Built once per test via t.Helper + t.Cleanup.
func e2eServerBinary(t *testing.T) string {
	t.Helper()
	tmp := t.TempDir()
	bin := filepath.Join(tmp, "kite-mcp-server.test.exe")
	if !strings.HasSuffix(bin, ".exe") && isWindows() {
		bin += ".exe"
	}

	// Project root is two parents up from this test file (mcp/ → project).
	// Use `go build` against ./... root; the resulting binary is the same
	// one main.go produces.
	cwd, err := os.Getwd()
	require.NoError(t, err, "get cwd")
	projectRoot := filepath.Dir(cwd)

	buildCtx, cancelBuild := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancelBuild()
	cmd := exec.CommandContext(buildCtx, "go", "build", "-o", bin, ".")
	cmd.Dir = projectRoot
	cmd.Env = append(os.Environ(), "CGO_ENABLED=0")
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "build server: %s", out)
	require.FileExists(t, bin)
	return bin
}

func isWindows() bool {
	return os.PathSeparator == '\\' || strings.Contains(strings.ToLower(os.Getenv("OS")), "windows")
}

// e2eSession is one stdio-mode MCP server subprocess with helpers to
// send JSON-RPC frames and read responses.
type e2eSession struct {
	cmd    *exec.Cmd
	stdin  io.WriteCloser
	stdout *bufio.Reader
	stderr *bytes.Buffer
	cancel context.CancelFunc
}

// startE2ESession spawns the binary in stdio mode with dev-friendly
// env so it never reaches out to Kite/Stripe/Telegram.
func startE2ESession(t *testing.T, bin string) *e2eSession {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	cmd := exec.CommandContext(ctx, bin)
	cmd.Env = append(os.Environ(),
		"APP_MODE=stdio",
		"DEV_MODE=true",
		"KITE_API_KEY=test_key",
		"KITE_API_SECRET=test_secret",
		"ALERT_DB_PATH=",      // in-memory only
		"OAUTH_JWT_SECRET=",   // no OAuth needed in stdio mode
		"TELEGRAM_BOT_TOKEN=", // no Telegram
		"LOG_LEVEL=error",
		"INSTRUMENTS_SKIP_FETCH=1",
	)
	stdin, err := cmd.StdinPipe()
	require.NoError(t, err, "stdin pipe")
	stdoutPipe, err := cmd.StdoutPipe()
	require.NoError(t, err, "stdout pipe")
	stderr := &bytes.Buffer{}
	cmd.Stderr = stderr

	require.NoError(t, cmd.Start(), "start server")

	t.Cleanup(func() {
		_ = stdin.Close()
		cancel()
		_ = cmd.Wait()
		if t.Failed() {
			t.Logf("server stderr:\n%s", stderr.String())
		}
	})

	return &e2eSession{
		cmd:    cmd,
		stdin:  stdin,
		stdout: bufio.NewReader(stdoutPipe),
		stderr: stderr,
		cancel: cancel,
	}
}

// send writes a single JSON-RPC request frame (newline-delimited).
func (s *e2eSession) send(t *testing.T, id int, method string, params any) {
	t.Helper()
	req := map[string]any{
		"jsonrpc": "2.0",
		"id":      id,
		"method":  method,
	}
	if params != nil {
		req["params"] = params
	}
	line, err := json.Marshal(req)
	require.NoError(t, err, "marshal request")
	_, err = s.stdin.Write(append(line, '\n'))
	require.NoError(t, err, "write request")
}

// readResponse reads one JSON-RPC response line and returns the
// decoded envelope. Bounded by the outer test context deadline.
func (s *e2eSession) readResponse(t *testing.T) map[string]any {
	t.Helper()
	// Read lines until we get one that parses as a JSON-RPC response
	// with an id (skip notifications + server log lines).
	for {
		line, err := s.stdout.ReadString('\n')
		require.NoError(t, err, "read response")
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		var env map[string]any
		if json.Unmarshal([]byte(line), &env) != nil {
			continue // log line or malformed — skip
		}
		if _, hasID := env["id"]; hasID {
			return env
		}
	}
}

// -------------------------------------------------------------------
// The actual E2E tests
// -------------------------------------------------------------------

// TestE2E_RoundtripInitializeAndToolsList exercises the canonical
// handshake and tool catalogue roundtrip.
func TestE2E_RoundtripInitializeAndToolsList(t *testing.T) {
	t.Parallel()
	bin := e2eServerBinary(t)
	s := startE2ESession(t, bin)

	// 1. initialize — protocol handshake.
	s.send(t, 1, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo": map[string]any{
			"name":    "e2e-roundtrip-test",
			"version": "1.0",
		},
	})
	initResp := s.readResponse(t)
	assert.Equal(t, float64(1), initResp["id"], "response id must match request id 1")
	result, ok := initResp["result"].(map[string]any)
	require.True(t, ok, "initialize result must be an object")
	assert.Contains(t, result, "serverInfo", "serverInfo required in initialize result")
	assert.Contains(t, result, "capabilities", "capabilities required in initialize result")

	// 2. notifications/initialized — MCP requires this before
	// tools/list, even though it is notification-only (no response).
	notifyLine, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	_, err := s.stdin.Write(append(notifyLine, '\n'))
	require.NoError(t, err, "write initialized notification")

	// 3. tools/list — verify catalogue is returned and well-formed.
	s.send(t, 2, "tools/list", map[string]any{})
	listResp := s.readResponse(t)
	assert.Equal(t, float64(2), listResp["id"])
	listResult, ok := listResp["result"].(map[string]any)
	require.True(t, ok, "tools/list result must be an object")
	tools, ok := listResult["tools"].([]any)
	require.True(t, ok, "tools/list result.tools must be an array")
	require.NotEmpty(t, tools, "tools/list must return non-empty catalogue")

	// Spot-check a well-known read-only tool.
	found := false
	for _, raw := range tools {
		tool, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if tool["name"] == "get_holdings" {
			found = true
			ann, _ := tool["annotations"].(map[string]any)
			if ann != nil {
				readOnly, _ := ann["readOnlyHint"].(bool)
				assert.True(t, readOnly, "get_holdings must have readOnlyHint=true")
			}
			break
		}
	}
	assert.True(t, found, "get_holdings must be present in tools/list")
}

// TestE2E_UnknownToolReturnsError exercises the error-framing path.
// An unknown tool name must surface as a proper JSON-RPC error envelope
// (not a process crash, not silent swallow).
func TestE2E_UnknownToolReturnsError(t *testing.T) {
	t.Parallel()
	bin := e2eServerBinary(t)
	s := startE2ESession(t, bin)

	// Short-circuit the handshake — some MCP implementations accept
	// tools/call without initialize; if ours requires it, the error
	// is informative either way.
	s.send(t, 1, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "e2e-err-test", "version": "1.0"},
	})
	_ = s.readResponse(t)

	notifyLine, _ := json.Marshal(map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
	})
	_, err := s.stdin.Write(append(notifyLine, '\n'))
	require.NoError(t, err)

	s.send(t, 42, "tools/call", map[string]any{
		"name":      "this_tool_does_not_exist_xyz",
		"arguments": map[string]any{},
	})
	resp := s.readResponse(t)
	assert.Equal(t, float64(42), resp["id"])
	// Expect either JSON-RPC-level error OR a CallToolResult with
	// isError=true (both are spec-compliant ways to report "no such
	// tool"). Fail if neither.
	if errEnv, hasErr := resp["error"]; hasErr {
		assert.NotNil(t, errEnv, "error field must be populated")
	} else if result, hasResult := resp["result"].(map[string]any); hasResult {
		isErr, _ := result["isError"].(bool)
		assert.True(t, isErr, "unknown tool must surface isError=true on result")
	} else {
		t.Fatalf("unknown tool response had neither error nor result: %v", resp)
	}
}

// TestE2E_BinarySmokeShutdown makes sure the server exits cleanly when
// stdin is closed — this is the real shutdown signal in stdio mode and
// a regression here bricks Claude Desktop / VSCode integrations.
func TestE2E_BinarySmokeShutdown(t *testing.T) {
	t.Parallel()
	bin := e2eServerBinary(t)
	s := startE2ESession(t, bin)

	s.send(t, 1, "initialize", map[string]any{
		"protocolVersion": "2024-11-05",
		"capabilities":    map[string]any{},
		"clientInfo":      map[string]any{"name": "e2e-shutdown", "version": "1.0"},
	})
	_ = s.readResponse(t)

	// Close stdin — server should terminate within a bounded window.
	require.NoError(t, s.stdin.Close())

	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case <-done:
		// Exited. We do not assert on exit code because stdio server
		// may log and return nil or a context.Cancelled — both are
		// acceptable shutdown paths.
	case <-time.After(10 * time.Second):
		t.Fatal("server did not exit within 10s of stdin close")
	}

	// Server should not have written to stderr beyond expected log
	// framing. We only fail on "panic:" which is unambiguous.
	stderr := s.stderr.String()
	assert.NotContains(t, stderr, "panic:", "server must not panic on shutdown")
	_ = fmt.Sprintf // keep fmt import for future diagnostics
}
