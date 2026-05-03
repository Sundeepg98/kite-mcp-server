import { test, expect, type APIRequestContext, type APIResponse } from '@playwright/test';

/**
 * /mcp tools/list — wire-level tool surface smoke check.
 *
 * The Go-side test mcp/tool_surface_lock_test.go is the CANONICAL pin —
 * it hashes GetAllTools() and pins the digest. That test owns drift
 * detection and the diff/update workflow.
 *
 * This spec is a redundant WIRE-LEVEL smoke check: it asks the running
 * server for its tools/list response and verifies the surface is
 * structurally sound (non-empty, contains known stable tools, has a
 * non-trivial size). It does NOT pin an exact SHA — that turned out to
 * drift constantly whenever tools are added/removed and produced noise
 * without catching anything the Go test didn't already catch first.
 *
 * What this spec catches that the Go test doesn't:
 *   - Tool registered in Go but never exposed via JSON-RPC wiring.
 *   - Whole-surface regression (e.g. crash drops everything to zero).
 *   - Server auth/transport regressions blocking tools/list.
 *
 * What this spec INTENTIONALLY doesn't catch (and shouldn't):
 *   - Exact set of tool names — that's the Go test's job.
 *   - Description / inputSchema drift — also Go test's job.
 *
 * If the live server requires auth on /mcp (production-style), this
 * spec skips. CI MUST run with OAuth disabled (no JWT secret) to enable
 * the unauth'd code path.
 *
 * MCP STREAMABLE-HTTP HANDSHAKE NOTE:
 *   /mcp is a session-based streamable-HTTP transport per MCP spec
 *   2025-06-18 (mcp-go's StreamableHTTPServer). Calls require:
 *     1. POST initialize → 200 + Mcp-Session-Id response header
 *     2. POST notifications/initialized + Mcp-Session-Id → 202
 *     3. POST tools/list (or any other) + Mcp-Session-Id → 200
 *   Posting tools/list without prior initialize returns 404
 *   "Invalid session ID" (upstream mcp-go behavior, not a bug).
 */

const MCP_HANDSHAKE_HEADERS = {
  'Content-Type': 'application/json',
  Accept: 'application/json, text/event-stream',
};

interface ToolDef {
  name: string;
  // Other fields exist (description, inputSchema, ...) but we don't pin them
  // here — that's the unit test's job. We only care about the name set.
}

interface JSONRPCResponse {
  jsonrpc?: string;
  id?: number | string | null;
  result?: { tools?: ToolDef[] };
  error?: { code: number; message: string };
}

/** Result of `mcpInitialize` — either the live session id, or a skip marker. */
interface InitResult {
  sessionId?: string;
  skipReason?: string;
}

/**
 * Perform MCP `initialize` and return the allocated Mcp-Session-Id.
 * Returns `{ skipReason }` if the server requires auth (401/403) — the
 * caller should `test.skip` in that case.
 */
async function mcpInitialize(request: APIRequestContext): Promise<InitResult> {
  const initResp = await request.post('/mcp', {
    data: {
      jsonrpc: '2.0',
      id: 1,
      method: 'initialize',
      params: {
        protocolVersion: '2025-06-18',
        capabilities: {},
        clientInfo: { name: 'playwright-e2e', version: '0.1.0' },
      },
    },
    headers: MCP_HANDSHAKE_HEADERS,
    maxRedirects: 0,
  });

  const status = initResp.status();
  if (status === 401 || status === 403) {
    return {
      skipReason:
        `/mcp initialize returned ${status} — server has OAuth enabled. ` +
        `Run the smoke suite against an unauth'd local boot to exercise this spec.`,
    };
  }
  expect(status, '/mcp initialize returns 200').toBe(200);

  const sessionId = initResp.headers()['mcp-session-id'];
  expect(sessionId, 'Mcp-Session-Id header allocated by initialize').toBeTruthy();

  // Per MCP spec, the client must follow up with notifications/initialized
  // before issuing further requests. Returns 202 (no body).
  const notifResp = await request.post('/mcp', {
    data: { jsonrpc: '2.0', method: 'notifications/initialized', params: {} },
    headers: { ...MCP_HANDSHAKE_HEADERS, 'Mcp-Session-Id': sessionId },
    maxRedirects: 0,
  });
  // Accept any 2xx — spec says 202, but be lenient on 200.
  expect(
    notifResp.status(),
    'notifications/initialized accepted (2xx)',
  ).toBeLessThan(300);

  return { sessionId };
}

/**
 * Parse a JSON-RPC response body that may be either plain JSON or an
 * SSE event-stream chunk (mcp-go can emit either depending on
 * Accept negotiation and tool semantics).
 */
async function parseJsonRpcBody(probe: APIResponse): Promise<JSONRPCResponse> {
  const contentType = probe.headers()['content-type'] || '';
  if (contentType.includes('text/event-stream')) {
    const text = await probe.text();
    // SSE format: "event: ...\ndata: <json>\n\n". Pluck the first data: line.
    const match = text.match(/^data:\s*(\{.*\})/m);
    expect(match, 'SSE body has data: line with JSON').not.toBeNull();
    return JSON.parse(match![1]);
  }
  return probe.json();
}

test.describe('/mcp tools/list — wire-level tool surface smoke', () => {
  test('exposes a non-trivial surface containing known stable tools', async ({ request }) => {
    // Wire-level smoke check. Strict SHA-pin lives in mcp/tool_surface_lock_test.go (Go-side, canonical).
    const init = await mcpInitialize(request);
    if (init.skipReason) {
      test.skip(true, init.skipReason);
      return;
    }
    const sessionId = init.sessionId!;

    const probe = await request.post('/mcp', {
      data: {
        jsonrpc: '2.0',
        id: 2,
        method: 'tools/list',
        params: {},
      },
      headers: { ...MCP_HANDSHAKE_HEADERS, 'Mcp-Session-Id': sessionId },
      maxRedirects: 0,
    });

    expect(probe.status(), '/mcp tools/list returns 200').toBe(200);

    const body = await parseJsonRpcBody(probe);

    expect(body, 'JSON-RPC response has result').toHaveProperty('result');
    expect(body.result, 'result has tools array').toHaveProperty('tools');
    const tools = body.result!.tools!;
    expect(Array.isArray(tools), 'tools is an array').toBe(true);

    // Surface size sanity floor. We ship ~93 tools in unauth/ENABLE_TRADING=false
    // mode and 122 in full mode at HEAD; a dramatic regression (e.g. half the
    // tools fail to register) trips this with a clearer error than
    // "single tool missing" would give.
    expect(tools.length, 'tools surface is non-trivial (>80 entries)').toBeGreaterThan(80);

    // Known-stable tools that should always be visible — read-only, present
    // in both unauth and full-trading mode. If any of these go missing, it's
    // a real wiring regression (not just a tool-name churn).
    //   - get_holdings, get_quotes, get_profile, search_instruments, get_ohlc:
    //     read-only, no ENABLE_TRADING gating, no per-user gating.
    //     Verified empirically against an unauth /mcp boot (tools/list count=93).
    //   - place_order is intentionally NOT asserted: it's gated by
    //     ENABLE_TRADING and not visible in the CI smoke posture.
    const toolNames = tools.map((t) => t.name);
    expect(toolNames).toContain('get_holdings');
    expect(toolNames).toContain('get_quotes');
    expect(toolNames).toContain('get_profile');
    expect(toolNames).toContain('search_instruments');
    expect(toolNames).toContain('get_ohlc');
  });

  test('responds to tools/list within 5s (perf budget)', async ({ request }) => {
    // Soft latency budget. Local-loopback + cached tool registry should
    // be tens of ms; 5s is generous and only fires if something is
    // pathologically slow (e.g. broken middleware, deadlocked init).
    const init = await mcpInitialize(request);
    if (init.skipReason) {
      test.skip(true, '/mcp requires auth — skip latency check');
      return;
    }
    const sessionId = init.sessionId!;

    const t0 = Date.now();
    const probe = await request.post('/mcp', {
      data: { jsonrpc: '2.0', id: 2, method: 'tools/list', params: {} },
      headers: { ...MCP_HANDSHAKE_HEADERS, 'Mcp-Session-Id': sessionId },
    });

    expect(probe.status(), '/mcp tools/list returns 200').toBe(200);
    const elapsed = Date.now() - t0;
    expect(elapsed, '/mcp tools/list under 5s').toBeLessThan(5000);
  });
});
