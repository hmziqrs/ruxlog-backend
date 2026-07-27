import { test, expect } from '@playwright/test';

/**
 * Real browser-driven smoke against the live ruxlog API (issue #33 scaffold).
 *
 * These specs drive an actual Chromium (not an echo stub). They currently
 * assert on API-served responses — `/healthz` (JSON) and `/robots.txt` (text)
 * — produced by the server the e2e workflow boots. When the consumer dioxus web
 * build is available in CI, additional specs here will load the served SPA.
 */

test.describe('ruxlog API — browser-driven smoke', () => {
  test('/healthz reports a healthy JSON payload', async ({ page }) => {
    const resp = await page.goto('/healthz');
    expect(resp?.status()).toBe(200);

    // The body is JSON; the rendered body text is the raw JSON string.
    const body = await page.locator('body').textContent();
    expect(body).toBeTruthy();
    expect(body).toContain('healthy');
    expect(body).toContain('"database":"ok"');
    expect(body).toContain('"redis":"ok"');
  });

  test('/robots.txt is served as crawl rules', async ({ page }) => {
    const resp = await page.goto('/robots.txt');
    expect(resp?.status()).toBe(200);

    const body = await page.locator('body').textContent();
    expect(body).toBeTruthy();
    expect(body).toContain('User-agent:');
    expect(body).toContain('Sitemap:');
  });

  test('unknown route does not crash the server', async ({ page }) => {
    // A random miss should 404 (or 4xx), not 500 — proves the server stays up.
    const resp = await page.goto('/__definitely_not_a_route__');
    expect(resp?.status()).toBeGreaterThanOrEqual(400);
    expect(resp?.status()).toBeLessThan(500);
  });
});
