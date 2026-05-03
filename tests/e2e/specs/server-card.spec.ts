import { test, expect } from '@playwright/test';

/**
 * /.well-known/mcp/server-card.json — MCP server discovery card.
 *
 * MCP Registry indexers, mcp-remote, and the awesome-mcp-servers ecosystem
 * crawl this URL to fetch metadata about the server (name, version,
 * tools-count, description, vendor, etc.). A regression here means we
 * silently drop out of registries.
 *
 * We pin the MINIMUM viable card shape — adding fields is OK, removing
 * fields is the regression we're catching.
 */

test.describe('/.well-known/mcp/server-card.json — MCP discovery card', () => {
  test('returns 200 + valid JSON with required fields', async ({ request }) => {
    const res = await request.get('/.well-known/mcp/server-card.json');
    expect(res.status(), 'server-card 200').toBe(200);

    // Content-Type should be application/json (or json+charset).
    const ct = res.headers()['content-type'] || '';
    expect(ct.toLowerCase(), 'content-type is JSON').toContain('json');

    const body = await res.json();
    // Minimum-viable MCP server card. We don't lock the schema version
    // string itself (might bump), only that ONE identity field
    // is present so registries can dedupe entries.
    // SEP-1649 nests identity at serverInfo.name; SEP-2127 promotes to top level. Accept either.
    const identity = body.name ?? body.server_name ?? body.id ?? body.serverInfo?.name;
    expect(identity, 'server-card identity field').toBeTruthy();
  });

  test('Content-Type prevents browser HTML interpretation', async ({ request }) => {
    // If a misconfigured Content-Type let a browser interpret this as
    // HTML, an attacker who could inject characters into the card body
    // would have an XSS vector against anyone who clicks the URL.
    // Guarantee text/html is NOT served here.
    const res = await request.get('/.well-known/mcp/server-card.json');
    const ct = (res.headers()['content-type'] || '').toLowerCase();
    expect(ct, 'card is not served as HTML').not.toContain('text/html');
  });
});
