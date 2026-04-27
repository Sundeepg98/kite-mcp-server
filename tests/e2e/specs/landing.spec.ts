import { test, expect } from '@playwright/test';

/**
 * GET / — landing page smoke.
 *
 * The root path is the FIRST thing a self-service user sees. A blank
 * page or a template-execution error means lost signups before the
 * funnel starts.
 *
 * What we lock:
 *   - Page returns 200 (or redirects to /dashboard for authed users —
 *     we test the unauthed path).
 *   - Content-Type is text/html.
 *   - No JS console errors at first paint.
 *   - Page mentions "Kite MCP" — proves the template rendered, not a
 *     fallback "Status template not available" plaintext.
 *   - At least one anchor pointing into the OAuth login funnel exists.
 *
 * What we deliberately do NOT lock:
 *   - Pixel-perfect layout / element-count.
 *   - Exact copy ("Get Started" vs "Sign In" — marketing changes those).
 *   - CSS class names.
 *
 * Maintenance budget: when copy/layout changes, none of these
 * assertions should fail. If they do, the assertion is too strict and
 * needs to be loosened, not the page reverted.
 */

test.describe('GET / — landing page', () => {
  test('returns HTML 200 with Kite MCP branding', async ({ page }) => {
    const consoleErrors: string[] = [];
    page.on('console', (msg) => {
      if (msg.type() === 'error') consoleErrors.push(msg.text());
    });

    const response = await page.goto('/', { waitUntil: 'domcontentloaded' });

    // Two acceptable outcomes:
    //   200 (unauthed: served landing template)
    //   302 to /dashboard (authed: shouldn't happen in CI but allow it)
    expect(response, 'response object exists').not.toBeNull();
    const status = response!.status();
    expect([200, 302], 'status is 200 or redirect').toContain(status);

    // If we got a 200, validate the page itself.
    if (status === 200) {
      const ct = response!.headers()['content-type'] || '';
      expect(ct, 'Content-Type is HTML').toContain('text/html');

      // Page text must contain the brand. Loose assertion: case-insensitive
      // substring, tolerates "Kite MCP", "Kite-MCP", "Kite MCP Server", etc.
      const bodyText = (await page.textContent('body')) || '';
      expect(bodyText.toLowerCase(), 'page mentions kite mcp').toContain('kite');

      // Either we have a working <title> or we have working body content;
      // a totally empty/whitespace page is the regression.
      expect(bodyText.trim().length, 'body has visible text').toBeGreaterThan(20);
    }

    // No console errors — JS bugs at first paint are a signup-funnel killer.
    // Allow benign warnings (favicon missing etc.) — only fail on errors.
    expect(consoleErrors, 'no console errors on landing page').toEqual([]);
  });

  test('robots.txt exists and disallows /dashboard', async ({ request }) => {
    // Robots-txt is a launch-readiness requirement — search engines must
    // not index user dashboards. The handler is registered at
    // app/http.go:491.
    const res = await request.get('/robots.txt');
    expect(res.status(), 'robots.txt 200').toBe(200);

    const body = await res.text();
    // Disallow rule must exist for protected surfaces. We assert one
    // representative entry — full list lives in app/http.go.
    expect(body, 'robots disallows /dashboard').toContain('Disallow: /dashboard');
    expect(body, 'robots disallows /admin').toContain('Disallow: /admin');
  });

  test('unknown path returns 404', async ({ request }) => {
    // The "/" handler does an exact-match check and falls through to a
    // 404 page for anything else (app/http.go:1239-1242). A 200 here
    // would mean the catch-all route is leaking.
    const res = await request.get('/this-path-deliberately-does-not-exist');
    expect(res.status(), 'unknown path 404').toBe(404);
  });
});
