import { test, expect } from '@playwright/test';

/**
 * /healthz smoke — proves the server is alive and the legacy flat-JSON
 * shape is intact. Real production users (load balancers, fly.io
 * health-checks, monitoring scripts) hit this endpoint; a regression
 * here breaks deploys silently.
 *
 * Surface contract pinned (must stay backwards-compatible per app/http.go
 * comment "Shape is unchanged for legacy callers"):
 *   GET /healthz                → 200 + { status, uptime, version, tools }
 *   GET /healthz?format=json    → 200 + richer component-level shape
 *
 * We intentionally do NOT pin the `version` value (changes per build) or
 * the exact `tools` count (let the tool-surface-lock spec own that).
 * We DO pin the field NAMES — those are the wire contract.
 */

test.describe('/healthz — server liveness', () => {
  test('legacy shape returns 200 with required fields', async ({ request }) => {
    const res = await request.get('/healthz');
    expect(res.status(), 'healthz must return 200').toBe(200);

    const body = await res.json();
    // Legacy shape — every field below is consumed by external callers.
    // Fly.io health-checks parse `status`. Our own dashboard parses
    // `uptime`/`version`. Removing any of these is a wire-protocol break.
    expect(body, 'healthz body has status').toHaveProperty('status');
    expect(body, 'healthz body has uptime').toHaveProperty('uptime');
    expect(body, 'healthz body has version').toHaveProperty('version');
    expect(body, 'healthz body has tools').toHaveProperty('tools');

    // Status must be a healthy sentinel — empty string would indicate an
    // unwired handler.
    expect(typeof body.status, 'status is string').toBe('string');
    expect(body.status.length, 'status is non-empty').toBeGreaterThan(0);
  });

  test('?format=json returns 200 with richer component body', async ({ request }) => {
    const res = await request.get('/healthz?format=json');
    expect(res.status(), 'healthz?format=json must return 200').toBe(200);

    // Per app/http.go comments: this shape "surfaces degraded states (audit
    // disabled, audit buffer dropping, risk freeze, etc.)". We only assert
    // it parses as JSON and is an object — surfacing the inner key set is
    // for the unit test in app/healthz_handler_test.go (already covers it).
    const body = await res.json();
    expect(typeof body, 'rich body is an object').toBe('object');
    expect(body, 'rich body is non-null').not.toBeNull();
  });

  test('unknown sub-paths return 404, not 200', async ({ request }) => {
    // /healthz/foo must NOT match the /healthz handler. Net/http exact
    // match for the registered pattern; a regression here would mean
    // the handler was registered with a trailing slash and is acting as
    // a prefix match (potential information-disclosure surface).
    const res = await request.get('/healthz/should-not-exist');
    expect(res.status(), '/healthz/sub must not 200').not.toBe(200);
  });
});
