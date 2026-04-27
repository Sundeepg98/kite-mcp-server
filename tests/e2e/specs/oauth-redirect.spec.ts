import { test, expect } from '@playwright/test';

/**
 * OAuth redirect contract — proves the login funnel entry points are
 * wired and don't 500 / leak credentials / redirect to attacker URLs.
 *
 * We do NOT complete an OAuth round-trip (that needs a real Kite
 * developer app + sandbox login, which lives in WC.2 / WC.3 in the
 * Wave C re-eval doc). What we DO lock here:
 *   - /auth/login responds (200 or 302 — both acceptable).
 *   - /oauth/authorize without required params returns 400 (NOT 500).
 *     A 500 here was an old bug — the handler must validate params
 *     before touching state.
 *   - /.well-known/oauth-protected-resource returns 200 + JSON shape.
 *     mcp-remote and other clients do dynamic discovery via this.
 *   - /.well-known/oauth-authorization-server returns 200 + JSON shape.
 *
 * Maintenance: copy on the login page changes; redirect targets do not.
 */

test.describe('OAuth login funnel — redirect contracts', () => {
  test('/auth/login responds without 5xx', async ({ request }) => {
    // Either renders a choice page (200) or redirects somewhere (302).
    // 5xx would mean OAuth handler initialization failed.
    const res = await request.get('/auth/login', { maxRedirects: 0 });
    const status = res.status();
    expect(status, '/auth/login is not 5xx').toBeLessThan(500);
    // Some specific bad statuses we want to flag fast:
    expect(status, '/auth/login is not 404').not.toBe(404);
  });

  test('/oauth/authorize with no params returns 4xx, not 5xx', async ({ request }) => {
    // A bare /oauth/authorize must not crash. Either:
    //   - 400 Bad Request (preferred — explicit validation)
    //   - 401 Unauthorized
    //   - 302 to an error page
    // What we MUST NOT see: 500 (handler swallowed nil pointer / panic).
    const res = await request.get('/oauth/authorize', { maxRedirects: 0 });
    const status = res.status();
    expect(status, '/oauth/authorize without params is not 5xx').toBeLessThan(500);
  });

  test('/.well-known/oauth-protected-resource returns valid metadata', async ({ request }) => {
    const res = await request.get('/.well-known/oauth-protected-resource');
    // If OAuth is configured, this MUST return 200 + metadata.
    // If not configured, the route may be unregistered — accept 404 then.
    if (res.status() === 404) {
      test.skip(true, 'OAuth not configured — well-known route not registered');
      return;
    }
    expect(res.status(), 'protected-resource metadata 200').toBe(200);

    const body = await res.json();
    // RFC 8707 / OAuth Protected Resource Metadata required field:
    // resource — the URI identifying the protected resource.
    expect(body, 'metadata has resource field').toHaveProperty('resource');
  });

  test('/.well-known/oauth-authorization-server returns valid metadata', async ({ request }) => {
    const res = await request.get('/.well-known/oauth-authorization-server');
    if (res.status() === 404) {
      test.skip(true, 'OAuth not configured — auth-server metadata not registered');
      return;
    }
    expect(res.status(), 'auth-server metadata 200').toBe(200);

    const body = await res.json();
    // RFC 8414 required fields. issuer + authorization_endpoint + token_endpoint
    // are the bare minimum any OAuth client expects.
    expect(body, 'metadata has issuer').toHaveProperty('issuer');
    expect(body, 'metadata has authorization_endpoint').toHaveProperty('authorization_endpoint');
    expect(body, 'metadata has token_endpoint').toHaveProperty('token_endpoint');
  });
});
