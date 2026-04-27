import { test, expect } from '@playwright/test';
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
 */

// MUST stay in sync with mcp/tool_surface_lock_test.go expectedSurfaceHash.
// The intent: one hash, two places that recompute it from independent
// vantage points (Go in-process / TS over the wire).
const EXPECTED_SURFACE_HASH =
  'fb5e9d0362f28cc1ada295ae5ad2325a33a93cfa465423bd272cd9787b7ea898';

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

test.describe('/mcp tools/list — wire-level tool surface lock', () => {
  test('returns the locked set of tool names (SHA256-pinned)', async ({ request }) => {
    const probe = await request.post('/mcp', {
      data: {
        jsonrpc: '2.0',
        id: 1,
        method: 'tools/list',
        params: {},
      },
      // Some MCP transports require these headers; setting them avoids a
      // confusing 415 if the server is strict. Harmless if not required.
      headers: {
        'Content-Type': 'application/json',
        Accept: 'application/json, text/event-stream',
      },
      maxRedirects: 0,
    });

    const status = probe.status();

    // Auth required: skip with a clear marker. This spec is meant for
    // the unauth'd CI invocation only.
    if (status === 401 || status === 403) {
      test.skip(
        true,
        `/mcp returned ${status} — server has OAuth enabled. ` +
          `Run the smoke suite against an unauth'd local boot to exercise this spec.`,
      );
      return;
    }

    expect(status, '/mcp tools/list returns 200').toBe(200);

    // Body could be plain JSON or an SSE event-stream chunk. Handle both.
    let body: JSONRPCResponse;
    const contentType = probe.headers()['content-type'] || '';
    if (contentType.includes('text/event-stream')) {
      const text = await probe.text();
      // SSE format: "event: ...\ndata: <json>\n\n". Pluck the first data: line.
      const match = text.match(/^data:\s*(\{.*\})/m);
      expect(match, 'SSE body has data: line with JSON').not.toBeNull();
      body = JSON.parse(match![1]);
    } else {
      body = await probe.json();
    }

    expect(body, 'JSON-RPC response has result').toHaveProperty('result');
    expect(body.result, 'result has tools array').toHaveProperty('tools');
    const tools = body.result!.tools!;
    expect(Array.isArray(tools), 'tools is an array').toBe(true);
    expect(tools.length, 'tools is non-empty').toBeGreaterThan(0);

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
    const t0 = Date.now();
    const probe = await request.post('/mcp', {
      data: { jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} },
      headers: { 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' },
    });

    if (probe.status() === 401 || probe.status() === 403) {
      test.skip(true, '/mcp requires auth — skip latency check');
      return;
    }

    const elapsed = Date.now() - t0;
    expect(elapsed, '/mcp tools/list under 5s').toBeLessThan(5000);
  });
});
