package mcp

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/mark3labs/mcp-go/server"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// TestHTTPRoundtrip_InitToolsList exercises the streamable-HTTP transport
// in-process via httptest.NewServer. Unlike e2e_roundtrip_test.go (which
// builds + spawns the server binary and pipes JSON-RPC over stdio — gated
// behind //go:build e2e for cost reasons), this test runs against an
// in-process server.NewStreamableHTTPServer wrapper and stays in the
// default `go test ./...` suite so the wire-handshake path is covered on
// every CI run.
//
// Coverage:
//  1. POST /mcp init → 200 + Mcp-Session-Id header allocated
//  2. POST /mcp notifications/initialized → 2xx (202 spec, 200 lenient)
//  3. POST /mcp tools/list → 200 with non-trivial tools array
//
// Mirrors the wire shape exercised by tests/e2e/specs/tool-surface.spec.ts
// (Playwright) but stays inside the Go test suite — fast, no network, no
// browser. Catches the same regression class: handshake / session
// allocation / tools/list framing.
func TestHTTPRoundtrip_InitToolsList(t *testing.T) {
	t.Parallel()

	mgr := newTestManager(t)

	mcpSrv := server.NewMCPServer("kite-mcp-server-roundtrip-test", "1.0",
		server.WithToolCapabilities(true),
	)
	// EnableTrading=true so order-placement tools register, ensuring the
	// tools/list response contains a meaningful surface (~111 tools).
	// The roundtrip assertion does not call any tool — it only inspects
	// the catalogue length and the schema of well-known stable tools.
	RegisterTools(mcpSrv, mgr, "", nil, mgr.Logger, true)

	streamable := server.NewStreamableHTTPServer(mcpSrv)

	ts := httptest.NewServer(streamable)
	t.Cleanup(ts.Close)

	httpClient := &http.Client{Timeout: 10 * time.Second}

	// --- Step 1: initialize -------------------------------------------------
	initReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      1,
		"method":  "initialize",
		"params": map[string]any{
			"protocolVersion": "2025-06-18",
			"capabilities":    map[string]any{},
			"clientInfo":      map[string]any{"name": "go-roundtrip-test", "version": "0.1.0"},
		},
	}
	initBody, err := json.Marshal(initReq)
	require.NoError(t, err, "marshal initialize")

	req, err := http.NewRequest(http.MethodPost, ts.URL+"/mcp", bytes.NewReader(initBody))
	require.NoError(t, err, "build initialize request")
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")

	resp, err := httpClient.Do(req)
	require.NoError(t, err, "POST /mcp initialize")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "/mcp initialize must return 200")

	sessionID := resp.Header.Get("Mcp-Session-Id")
	require.NotEmpty(t, sessionID, "Mcp-Session-Id header must be allocated by initialize")

	initBodyResp, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read initialize response body")
	initEnv := parseJSONRPCBody(t, resp.Header.Get("Content-Type"), initBodyResp)
	require.NotNil(t, initEnv["result"], "initialize response must carry a result")

	// --- Step 2: notifications/initialized ---------------------------------
	notifReq := map[string]any{
		"jsonrpc": "2.0",
		"method":  "notifications/initialized",
		"params":  map[string]any{},
	}
	notifBody, err := json.Marshal(notifReq)
	require.NoError(t, err)

	req, err = http.NewRequest(http.MethodPost, ts.URL+"/mcp", bytes.NewReader(notifBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", sessionID)

	resp, err = httpClient.Do(req)
	require.NoError(t, err, "POST /mcp notifications/initialized")
	defer resp.Body.Close()

	// Spec says 202; some implementations return 200. Accept any 2xx.
	require.Less(t, resp.StatusCode, 300,
		"notifications/initialized must return 2xx (got %d)", resp.StatusCode)

	// --- Step 3: tools/list ------------------------------------------------
	listReq := map[string]any{
		"jsonrpc": "2.0",
		"id":      2,
		"method":  "tools/list",
	}
	listBody, err := json.Marshal(listReq)
	require.NoError(t, err)

	req, err = http.NewRequest(http.MethodPost, ts.URL+"/mcp", bytes.NewReader(listBody))
	require.NoError(t, err)
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Accept", "application/json, text/event-stream")
	req.Header.Set("Mcp-Session-Id", sessionID)

	resp, err = httpClient.Do(req)
	require.NoError(t, err, "POST /mcp tools/list")
	defer resp.Body.Close()

	require.Equal(t, http.StatusOK, resp.StatusCode, "/mcp tools/list must return 200")

	listBodyResp, err := io.ReadAll(resp.Body)
	require.NoError(t, err, "read tools/list response body")
	listEnv := parseJSONRPCBody(t, resp.Header.Get("Content-Type"), listBodyResp)

	result, ok := listEnv["result"].(map[string]any)
	require.True(t, ok, "tools/list response must have an object result; got %T", listEnv["result"])

	rawTools, ok := result["tools"].([]any)
	require.True(t, ok, "tools/list result.tools must be an array; got %T", result["tools"])

	assert.Greater(t, len(rawTools), 50,
		"tools/list must expose a non-trivial catalogue (got %d)", len(rawTools))

	// Verify a handful of stable tool names are present so a future
	// regression that silently drops well-known tools is caught here.
	wantPresent := []string{"get_profile", "get_holdings", "get_quotes", "get_orders"}
	gotNames := make(map[string]bool, len(rawTools))
	for _, raw := range rawTools {
		toolMap, ok := raw.(map[string]any)
		if !ok {
			continue
		}
		if name, ok := toolMap["name"].(string); ok {
			gotNames[name] = true
		}
	}
	for _, want := range wantPresent {
		assert.Truef(t, gotNames[want],
			"tools/list result must include %q (stable tool); got %d names total", want, len(gotNames))
	}
}

// parseJSONRPCBody decodes a JSON-RPC envelope from either application/json
// or text/event-stream — mcp-go's StreamableHTTPServer can emit either
// based on Accept negotiation. Mirrors the parseJsonRpcBody helper in the
// Playwright tool-surface spec.
func parseJSONRPCBody(t *testing.T, contentType string, body []byte) map[string]any {
	t.Helper()
	if strings.Contains(contentType, "text/event-stream") {
		// SSE frame: "event: ...\ndata: <json>\n\n". Extract the first
		// data: line and JSON-decode it.
		dataLine := regexp.MustCompile(`(?m)^data:\s*(\{.*\})`).FindSubmatch(body)
		require.NotNil(t, dataLine, "SSE body must contain a data: line with JSON; got: %s", string(body))
		var env map[string]any
		require.NoError(t, json.Unmarshal(dataLine[1], &env), "JSON-decode SSE data line")
		return env
	}
	var env map[string]any
	require.NoError(t, json.Unmarshal(body, &env),
		"JSON-decode response body (content-type=%s): %s", contentType, string(body))
	return env
}
