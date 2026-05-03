import { test, expect, type APIRequestContext, type APIResponse } from '@playwright/test';
import { createHash } from 'node:crypto';

/**
 * /mcp tools/list — tool surface lock.
 *
 * The Go side already has a tool-surface-lock unit test
 * (mcp/tool_surface_lock_test.go) that hashes GetAllTools() and pins the
 * digest. This spec is the WIRE-LEVEL counterpart: it asks the running
 * server for its tools/list response and verifies the hash matches.
 *
 * Why both? The Go test catches in-package regressions. THIS test
 * catches regressions in registration / wiring — a tool that compiles
 * and is in GetAllTools() but isn't actually exposed via the JSON-RPC
 * tools/list (or vice versa) would show up here and not in the unit
 * test.
 *
 * The hash is computed identically to the Go side:
 *   names = sorted list of tool names
 *   hash = SHA256(names.join('\n'))
 *
 * If the live server requires auth on /mcp (production-style), this
 * spec skips. CI MUST run with OAuth disabled (no JWT secret) to enable
 * the unauth'd code path.
 *
 * UPDATING THE HASH:
 *   1. Run the Go-side surface-lock test; copy expectedSurfaceHash
 *      from mcp/tool_surface_lock_test.go.
 *   2. Update EXPECTED_SURFACE_HASH below.
 *   3. The two values MUST match — they are the same contract.
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

// MUST stay in sync with mcp/tool_surface_lock_test.go expectedSurfaceHash.
// The intent: one hash, two places that recompute it from independent
// vantage points (Go in-process / TS over the wire).
const EXPECTED_SURFACE_HASH =
  'fb5e9d0362f28cc1ada295ae5ad2325a33a93cfa465423bd272cd9787b7ea898';

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

test.describe('/mcp tools/list — wire-level tool surface lock', () => {
  test('returns the locked set of tool names (SHA256-pinned)', async ({ request }) => {
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
    expect(tools.length, 'tools is non-empty').toBeGreaterThan(0);
    // Sanity floor: we ship 100+ tools today (117 at HEAD). A regression
    // that drops surface dramatically would trip this before the hash
    // check, with a clearer error.
    expect(tools.length, 'tools surface has 50+ entries').toBeGreaterThan(50);

    // Compute the hash exactly as the Go side does (mcp/tool_surface_lock_test.go).
    const names = tools.map((t) => t.name).sort();
    const hash = createHash('sha256').update(names.join('\n')).digest('hex');

    if (hash !== EXPECTED_SURFACE_HASH) {
      // Provide a useful drift report (matches the Go test's diff output).
      // Not splitting into added/removed because we don't have the locked
      // golden list here — the Go test owns that. We give the names + hash
      // so a maintainer can copy them across.
      throw new Error(
        `Tool surface drift detected over the wire.\n` +
          `  expected: ${EXPECTED_SURFACE_HASH}\n` +
          `  actual:   ${hash}\n` +
          `  tool count: ${names.length}\n` +
          `  first 5: ${names.slice(0, 5).join(', ')}\n` +
          `Update both EXPECTED_SURFACE_HASH (here) AND the Go-side ` +
          `mcp/tool_surface_lock_test.go expectedSurfaceHash. They must match.`,
      );
    }
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
