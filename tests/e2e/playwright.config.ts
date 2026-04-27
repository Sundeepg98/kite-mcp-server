import { defineConfig, devices } from '@playwright/test';

/**
 * Thin-smoke Playwright config for kite-mcp-server.
 *
 * Design philosophy:
 *   - One browser (chromium) — no cross-browser parity matrix at this stage.
 *     Cross-browser is for the day a user-facing widget regression bites; we
 *     are not there yet. Adding it costs ~3x CI minutes.
 *   - Fully parallel within a file but file-isolated — every spec must boot
 *     state from scratch. No shared fixtures.
 *   - No video / no trace by default (cost: ~50MB per run). Enable on CI
 *     failure-only via the trace: 'retain-on-failure' setting below.
 *   - HEADLESS by default. The `npm run test:headed` script flips that for
 *     local debug only.
 *
 * The TARGET_BASE_URL env var lets CI override the default for split
 * server/test orchestration. If unset, tests assume the server is already
 * running on http://127.0.0.1:8080 (the binary's hard-coded default).
 *
 * @see https://playwright.dev/docs/test-configuration
 */
export default defineConfig({
  testDir: './specs',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 1 : 0,
  workers: process.env.CI ? 2 : undefined,
  reporter: process.env.CI ? [['github'], ['html', { open: 'never' }]] : 'list',
  timeout: 30_000,
  expect: {
    timeout: 5_000,
  },
  use: {
    baseURL: process.env.TARGET_BASE_URL || 'http://127.0.0.1:8080',
    trace: 'retain-on-failure',
    screenshot: 'only-on-failure',
    video: 'off',
    // Don't follow redirects automatically for tests that assert on
    // 30x semantics — individual tests opt-in to manual handling.
    ignoreHTTPSErrors: true,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
  // No webServer block: we expect the kite-mcp-server binary to be
  // started OUT-OF-BAND (by the GH Actions workflow / by the developer
  // locally). This keeps the suite portable across deployment targets:
  // it can run against localhost, against a fly.io preview, against a
  // staging URL — just by changing TARGET_BASE_URL.
});
