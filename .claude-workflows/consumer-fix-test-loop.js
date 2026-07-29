export const meta = {
  name: 'consumer-fix-test-loop',
  description: 'Iteratively fix consumer-dioxus console errors and verify in a real browser until clean',
  phases: [
    { title: 'Environment', detail: 'verify backend/consumer up, check data, best-effort seed' },
    { title: 'Test', detail: 'Playwright: navigate routes, capture console + visible errors' },
    { title: 'Fix', detail: 'diagnose each error, apply correct fix, confirm wasm compiles' },
    { title: 'Final', detail: 'full route sweep + screenshot, confirm zero errors' },
  ],
}

const CONSUMER = 'http://127.0.0.1:1108'
const API = 'http://localhost:1100'

const CONTEXT = `
PROJECT: ruxlog. consumer-dioxus is a Dioxus 0.8.0-alpha FULLSTACK SSR app (WASM client).
- Consumer dev server (dx serve, hot-reloads on Rust change): ${CONSUMER}  (also reachable as localhost:1108)
- Backend API (axum): ${API}  (APP_API_URL). Postgres on localhost:1101.
- The consumer page is served from 127.0.0.1:1108; it fetches the API at localhost:1100 (CROSS-ORIGIN).
- CSP is delivered by a per-request nonce middleware: frontend/consumer-dioxus/src/csp_nonce.rs
  (CSP_TEMPLATE constant — script-src 'self' 'nonce-<v>' 'wasm-unsafe-eval' 'unsafe-eval', connect-src 'self', ...).
  A matching static <meta> fallback is in frontend/consumer-dioxus/index.html (client-only build).
  Admin + backend CSP live in frontend/admin-dioxus/index.html and backend/api/src/middlewares/security_headers.rs.
- KNOWN ISSUE already observed: connect-src 'self' BLOCKS the cross-origin API fetch to ${API}
  (error: "Connecting to '${API}/csrf/v1/generate' violates Content-Security-Policy directive connect-src 'self'").
  The app LEGITIMATELY needs to call the API cross-origin, so connect-src must include the API origin.
  PREFERRED FIX: make the nonce middleware read the API origin (consumer env APP_API_URL, or std::env::var)
  at request time and inject it into connect-src (env-correct, works in dev + prod). Mirror in index.html meta.
- After editing consumer Rust, dx serve rebuilds the WASM automatically; allow time for it.
- Everything else is in .env.dev. Be surgical; match surrounding code style. Do NOT add 'unsafe-inline' to script-src.
`

const TEST_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['clean', 'errors', 'visibleErrors', 'routesTested', 'summary'],
  properties: {
    clean: { type: 'boolean', description: 'true if ZERO console errors across all tested routes' },
    errors: { type: 'array', items: { type: 'object', additionalProperties: false,
      required: ['message', 'kind', 'sourceHint', 'route'],
      properties: {
        message: { type: 'string' },
        kind: { type: 'string', enum: ['csp', 'js', 'network', 'resource', 'other'] },
        sourceHint: { type: 'string', description: 'file/component/URL the error points at' },
        route: { type: 'string' },
      } } },
    visibleErrors: { type: 'array', items: { type: 'string' }, description: 'rendered "Application error" / error text on screen' },
    routesTested: { type: 'array', items: { type: 'string' } },
    summary: { type: 'string' },
  },
}

const FIX_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['changes', 'compiled', 'notes'],
  properties: {
    changes: { type: 'array', items: { type: 'object', additionalProperties: false,
      required: ['file', 'change'], properties: { file: { type: 'string' }, change: { type: 'string' } } } },
    compiled: { type: 'boolean', description: 'did \`cargo build --target wasm32-unknown-unknown -p consumer-dioxus\` succeed?' },
    notes: { type: 'string' },
  },
}

const ENV_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['backendUp', 'consumerUp', 'postCount', 'seedAttempted', 'seedResult', 'notes'],
  properties: {
    backendUp: { type: 'boolean' },
    consumerUp: { type: 'boolean' },
    postCount: { type: 'integer', description: 'approx published post count (-1 if unknown)' },
    seedAttempted: { type: 'boolean' },
    seedResult: { type: 'string' },
    notes: { type: 'string' },
  },
}

phase('Environment')
const env = await agent(`${CONTEXT}

TASK: verify the dev environment is ready for browser testing.
1. curl -s -o /dev/null -w "%{http_code}" ${API}/healthz  -> backendUp (expect 200). If NOT up, report backendUp=false (the operator is starting it separately; do NOT start it yourself).
2. curl -s -o /dev/null -w "%{http_code}" ${CONSUMER}/    -> consumerUp (expect 200).
3. Estimate published post count: try \`curl -s "${API}/api/v1/posts?per_page=1"\` or similar public posts endpoint; count items / total. -1 if you cannot determine.
4. SEED (best-effort, ONLY if postCount==0): seeding is via the interactive TUI (\`cargo run --bin ruxlog_tui\` under backend/api with .env.dev) or the HTTP /admin/seed/v1 endpoints (requires seed-system feature + admin auth). If postCount==0 AND you can seed non-interactively without disrupting running services, do so; otherwise set seedAttempted=true with seedResult explaining it was skipped (interactive-only). Do NOT block on seeding.
Return the ENV_SCHEMA. Keep it brief.`, { schema: ENV_SCHEMA, phase: 'Environment' })
log(`env: backend=${env.backendUp} consumer=${env.consumerUp} posts~=${env.postCount} seed=${env.seedResult}`)

// ---- the test->fix->retest loop ----
const MAX_ITERS = 5
let lastSig = null
let lastTest = null

function signature(t) {
  // stable signature of the error set to detect no-progress
  return t.errors.map(e => e.kind + '::' + e.sourceHint).sort().join(' | ') + ' || ' + t.visibleErrors.sort().join(' | ')
}

for (let i = 1; i <= MAX_ITERS; i++) {
  phase(`Test-${i}`)
  lastTest = await agent(`${CONTEXT}

You are the BROWSER TESTER. Use the Playwright MCP tools (browser_navigate, browser_wait_for, browser_console_messages, browser_snapshot, browser_click) to drive a real browser.

Iteration ${i} of ${MAX_ITERS}. A fix may have just been applied; dx serve rebuilds the WASM on file change (takes ~30-90s), so the served page may be briefly stale.

Procedure:
1. browser_navigate to ${CONSUMER}/  (fresh load).
2. browser_wait_for time:3 (let it settle / hydrate).
3. browser_console_messages with level:"error" -> collect ALL error messages.
4. ALSO navigate each of these routes, waiting ~2s each, and collect their console errors too:
     ${CONSUMER}/search , ${CONSUMER}/about , ${CONSUMER}/contact , ${CONSUMER}/privacy
   (use browser_navigate per route; after each, browser_console_messages level:"error".)
5. If this is iteration >1 AND you still see the SAME CSP error that was just fixed (e.g. connect-src still blocking the API), the build may be stale: browser_wait_for time:20, then browser_navigate to ${CONSUMER}/ again and re-read console ONCE. Use the post-wait result as final.
6. Capture any visible on-screen error text (e.g. "Application error", panic text) via browser_snapshot -> visibleErrors.
7. De-duplicate errors; for each, set kind (csp/js/network/resource/other) and sourceHint (the file/component/URL the message points at, e.g. "connect-src 'self' blocks ${API}" or "consumer-dioxus.js:3319" or "CookieConsent").
Ignore the favicon.ico 404 (cosmetic) UNLESS it is the only remaining error.
Return TEST_SCHEMA. clean=true only if there are ZERO non-cosmetic console errors across all routes.`, { schema: TEST_SCHEMA, phase: `Test-${i}` })

  log(`Test-${i}: ${lastTest.errors.length} error(s), clean=${lastTest.clean} — ${lastTest.summary.slice(0,120)}`)

  if (lastTest.clean) { log('CLEAN — exiting loop'); break }

  const sig = signature(lastTest)
  if (sig === lastSig) {
    log(`No progress vs previous iteration (same error signature) — stopping loop to avoid spinning. Investigate manually.`)
    break
  }
  lastSig = sig

  phase(`Fix-${i}`)
  const fix = await agent(`${CONTEXT}

You are the FIXER. Below is the current set of browser console errors from the consumer app. Diagnose each from its source and apply a CORRECT, minimal fix (not a hack). Match surrounding code style.

CURRENT ERRORS (iteration ${i}):
${JSON.stringify(lastTest, null, 2)}

Guidance:
- CSP errors (connect-src / img-src / etc. blocking legitimate origins): the app legitimately needs cross-origin API/media access. For connect-src, PREFERRED fix = make the nonce middleware (frontend/consumer-dioxus/src/csp_nonce.rs, CSP_TEMPLATE) read the API origin at request time (consumer env APP_API_URL or std::env::var("APP_API_URL")) and inject it into connect-src, and mirror in index.html meta. Keep script-src as 'self' 'nonce-<v>' 'wasm-unsafe-eval' 'unsafe-eval' — NEVER add 'unsafe-inline'.
- JS/runtime errors (TypeError, undefined, panic in a component): read the component source the stack points at, find the unsafe unwrap/cast/undefined-access, and make it handle the absent/error case (like the CookieConsent fix pattern).
- Network 404s for app assets: fix the reference or note it.
- After editing, VERIFY it compiles with the check matching your edit's target:
    * SERVER-side change (csp_nonce.rs, main.rs, anything under #[cfg(feature="server")]):
        cargo check -p consumer-dioxus --features server
    * CLIENT-side change (a component, hook, or #[cfg(target_arch="wasm32")] code):
        cargo check -p consumer-dioxus --target wasm32-unknown-unknown
  Run the matching one (or both if unsure). This confirms the fix compiles AND gives dx serve time to rebuild.
  Note: a CSP connect-src fix is SERVER-side — dx must rebuild the SSR server for the new header to be served;
  the cargo check --features server provides that window. Set compiled=true only if the check succeeds.
- CRITICAL for CSP fixes: the consumer app is served from 127.0.0.1:1108 but calls the API at localhost:1100
  (cross-origin). connect-src MUST include the API origin. Determine the API origin from the consumer's env
  (read frontend/consumer-dioxus/src/env* for how APP_API_URL is exposed; prefer injecting it into connect-src
  at request time in the nonce middleware so it is correct in dev AND prod). Mirror in index.html meta.
  NEVER add 'unsafe-inline' to script-src.
- Do NOT edit files unrelated to the errors. One logical change per error.
Return FIX_SCHEMA with the list of {file, change} and compiled status.`, { schema: FIX_SCHEMA, phase: `Fix-${i}` })
  log(`Fix-${i}: ${fix.changes.length} change(s), compiled=${fix.compiled} — ${fix.notes.slice(0,120)}`)
  if (!fix.compiled) { log('Fix did not compile — will re-test to confirm state.') }
}

phase('Final')
const FINAL_SCHEMA = {
  type: 'object', additionalProperties: false,
  required: ['clean', 'remainingErrors', 'routesVerified', 'screenshotTaken', 'summary'],
  properties: {
    clean: { type: 'boolean' },
    remainingErrors: { type: 'array', items: { type: 'string' } },
    routesVerified: { type: 'array', items: { type: 'string' } },
    screenshotTaken: { type: 'boolean' },
    summary: { type: 'string' },
  },
}
const final = await agent(`${CONTEXT}

You are the FINAL VERIFIER. The fix-test loop has run ${MAX_ITERS > 0 ? '(see prior phases)' : ''}.
Do a clean, thorough verification in the browser (Playwright tools):
1. browser_navigate ${CONSUMER}/ , browser_wait_for time:3, browser_console_messages level:"error".
2. Visit /, /search, /about, /contact, /privacy and confirm no console errors and no "Application error" on screen.
3. Take a screenshot of the home page (browser_take_screenshot) as evidence — set screenshotTaken=true.
4. If the home page shows posts (postCount>0), click into one post and confirm it renders without console errors.
Return FINAL_SCHEMA: clean (zero non-cosmetic errors), remainingErrors list, routesVerified, screenshotTaken, and a concise summary of the final state + any issue that could not be resolved.`, { schema: FINAL_SCHEMA, phase: 'Final' })

return { env, iterations_run: MAX_ITERS, lastTest, final }
