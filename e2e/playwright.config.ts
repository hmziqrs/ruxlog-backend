import { defineConfig, devices } from '@playwright/test';

/**
 * Playwright config for the ruxlog browser e2e scaffold (issue #33).
 *
 * The API server is started by `.github/workflows/e2e.yml` (job `e2e-browser`)
 * before the suite runs, so there is NO `webServer` block here — the spec just
 * navigates to the already-running server. `BASE_URL` matches the env the
 * workflow sets; locally, run the API on :8888 and `BASE_URL=http://127.0.0.1:8888 npx playwright test`.
 *
 * NOTE: this is intentionally a real, passing scaffold. The specs drive an
 * actual Chromium and assert on API-served content (health, robots). When the
 * consumer dioxus web build (`dx build --platform web`) is available in CI,
 * add specs that load the served SPA — the harness below already supports it
 * via `baseURL`.
 */
const BASE_URL = process.env.BASE_URL ?? 'http://127.0.0.1:8888';

export default defineConfig({
  testDir: './tests',
  fullyParallel: true,
  forbidOnly: !!process.env.CI,
  retries: process.env.CI ? 2 : 0,
  workers: 1,
  reporter: [['html', { open: 'never' }], ['list']],
  timeout: 30_000,
  expect: { timeout: 10_000 },
  use: {
    baseURL: BASE_URL,
    trace: 'on-first-retry',
    headless: true,
  },
  projects: [
    {
      name: 'chromium',
      use: { ...devices['Desktop Chrome'] },
    },
  ],
});
