//! Per-request Content-Security-Policy nonce layer for the Dioxus fullstack
//! SSR origin.
//!
//! # Why this exists
//!
//! Dioxus 0.8 fullstack SSR injects inline `<script>` tags into every HTML
//! response to carry hydration state. One of them —
//! `window.initial_dioxus_hydration_data = "<base64>"` — is **dynamic per
//! render** (serialized CBOR of the virtual DOM), so it cannot be allow-listed
//! with a stable `'sha256-…'` hash, and it cannot be omitted (the WASM client
//! reads it at boot). A static `script-src 'self'` policy therefore
//! *structurally cannot* load the app: it blocks that script, and it also
//! blocks `WebAssembly.instantiateStreaming` (which needs `'wasm-unsafe-eval'`,
//! plus `'unsafe-eval'` because dioxus-web's `WebEvaluator` compiles strings
//! via `new Function()` for `document::eval` / `document::Title`).
//!
//! Granting `'unsafe-inline'` would re-enable every injected `<script>` /
//! `on*` handler / `javascript:` URI — i.e. disable the stored-XSS
//! defence-in-depth for `dangerous_inner_html` post content. Instead this
//! layer emits a **per-request nonce**: it rewrites only the Dioxus-injected
//! inline scripts to carry `nonce="<random>"` and serves
//! `script-src 'self' 'nonce-<random>' 'wasm-unsafe-eval' 'unsafe-eval'`.
//! Inline scripts are still denied unless they carry THIS request's nonce —
//! which an attacker injecting HTML into post content can neither predict nor
//! attach — so the ammonia + CSP layered XSS control is preserved.
//!
//! # SAFETY-CRITICAL INVARIANT
//!
//! Only the known Dioxus hydration scripts are noncified (matched by content
//! signature in [`should_nonce_script`]). Any other inline `<script>` — in
//! particular one inside the user-content `<main>` region that survived
//! ammonia — is left WITHOUT a nonce and is therefore blocked by the policy.
//! Do **not** change [`should_nonce_script`] to a blanket "nonce every
//! script": that would arm exactly the ammonia-bypass attack this layer
//! exists to prevent. The regression test `attacker_script_is_NOT_nonced`
//! guards this property.

use axum::{
    body::{to_bytes, Body},
    extract::Request,
    http::{header, HeaderValue, StatusCode},
    middleware::Next,
    response::Response,
};
use base64::Engine;

/// Maximum HTML body size we are willing to buffer/rewrite (16 MiB). Documents
/// are far smaller; a response exceeding this is served unchanged (with a 500
/// to signal the overflow) rather than risk OOM or a half-rewritten body.
const MAX_HTML_BODY: usize = 16 * 1024 * 1024;

/// Random bytes in a nonce (144 bits > CSP's 128-bit minimum). Base64 of 18
/// bytes is 24 chars, no padding.
const NONCE_BYTES: usize = 18;

/// The CSP applied to the SSR document, with the per-request nonce and the
/// runtime API origin interpolated. `wasm-unsafe-eval` unblocks
/// `WebAssembly.instantiateStreaming`; `unsafe-eval` unblocks dioxus-web's
/// `new Function()` document eval. Neither weakens the stored-XSS control: they
/// only gate eval/WASM entry from an already-running JS context, which
/// `script-src 'self'` (no `'unsafe-inline'`) withholds from injected HTML.
/// `frame-ancestors 'none'` is carried here as a real HTTP header (browsers
/// ignore it in a `<meta>`).
///
/// `connect-src` lists `'self'` plus the cross-origin backend API origin
/// (`{CONNECT_ORIGINS}`, resolved at request time by [`api_connect_origin`]).
/// The consumer WASM is served from the SSR origin (e.g. 127.0.0.1:1108) but
/// legitimately fetches the axum API on a different origin (e.g. localhost:1100)
/// — the CSRF-token bootstrap, server functions, media — so a bare
/// `connect-src 'self'` blocks every such fetch. The origin is read from the
/// same env (`APP_API_URL` / `SITE_URL`) the client's `env::APP_API_URL` is
/// built from, so it is correct in both dev and prod.
const CSP_TEMPLATE: &str = concat!(
    "default-src 'self'; ",
    "script-src 'self' 'nonce-{NONCE}' 'wasm-unsafe-eval' 'unsafe-eval'; ",
    "style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; ",
    "font-src 'self' https://fonts.gstatic.com; ",
    "img-src 'self' data: https:; ",
    "media-src 'self'; ",
    "connect-src 'self' {CONNECT_ORIGINS}; ",
    "object-src 'none'; ",
    "base-uri 'self'; ",
    "frame-ancestors 'none'; ",
    "form-action 'self'"
);

/// axum `from_fn` middleware: for every HTML document response, generate a
/// per-request nonce, rewrite the Dioxus hydration scripts to carry it, strip
/// the static `<meta>` CSP (which cannot encode a nonce and would
/// intersect-block the nonce'd scripts), and emit the nonce-based
/// `Content-Security-Policy` header. Non-HTML responses (JSON server fns,
/// WASM, CSS, assets) and content-encoded responses pass through untouched.
pub async fn csp_nonce_middleware(request: Request, next: Next) -> Response {
    let response = next.run(request).await;

    // Only HTML documents carry scripts we need to authorize, and only
    // un-encoded bodies can be safely rewritten.
    if !is_html_response(&response) || has_content_encoding(&response) {
        return response;
    }

    let nonce = generate_nonce();
    let (mut parts, body) = response.into_parts();
    let body_bytes = match to_bytes(body, MAX_HTML_BODY).await {
        Ok(b) => b,
        Err(_) => {
            // Unreachable for real HTML docs (< MAX_HTML_BODY). Returning a
            // bare 500 is preferable to emitting a rewritten-but-wrong or
            // truncated body under a nonce policy.
            parts.status = StatusCode::INTERNAL_SERVER_ERROR;
            return Response::from_parts(parts, Body::empty());
        }
    };

    let html = String::from_utf8_lossy(&body_bytes).into_owned();
    let rewritten = rewrite_html(&html, &nonce);

    // The body changed length; drop the old Content-Length (and any inner CSP
    // header) and re-emit both.
    parts.headers.remove(header::CONTENT_LENGTH);
    parts.headers.remove(header::CONTENT_SECURITY_POLICY);
    parts.headers.insert(
        header::CONTENT_LENGTH,
        HeaderValue::from_str(&rewritten.len().to_string()).unwrap(),
    );
    parts.headers.insert(header::CONTENT_SECURITY_POLICY, csp_value(&nonce));
    Response::from_parts(parts, Body::from(rewritten))
}

/// Strip the static `<meta http-equiv="Content-Security-Policy">` tag, then
/// noncify the Dioxus hydration scripts.
fn rewrite_html(html: &str, nonce: &str) -> String {
    let without_meta = strip_csp_meta(html);
    noncify_dioxus_scripts(&without_meta, nonce)
}

/// Generate a fresh CSP nonce from the OS CSPRNG. `getrandom::fill` failure
/// means the OS has no entropy — there is no safe fallback for a security
/// nonce, so we panic rather than emit a predictable one.
fn generate_nonce() -> String {
    let mut buf = [0u8; NONCE_BYTES];
    getrandom::fill(&mut buf).expect("getrandom::fill failed: OS entropy source unavailable");
    base64::engine::general_purpose::STANDARD.encode(buf)
}

fn csp_value(nonce: &str) -> HeaderValue {
    let raw = CSP_TEMPLATE
        .replace("{NONCE}", nonce)
        .replace("{CONNECT_ORIGINS}", &api_connect_origin());
    HeaderValue::from_str(&raw).expect("CSP template renders to valid header ASCII")
}

/// Resolve the cross-origin backend API origin to allow in `connect-src`. The
/// consumer WASM client fetches the axum API (CSRF bootstrap, server functions,
/// media) from `env::APP_API_URL`, which is built from the `SITE_URL` env (see
/// `env.rs`). We resolve the same value here at **request time** so the policy
/// tracks the runtime environment (correct in prod, where the URL is usually
/// set at container launch rather than baked in), falling back through the
/// compile-time env the client was built with and then the `env::APP_API_URL`
/// default — so the allow-list is never wrong-by-default.
fn api_connect_origin() -> String {
    let raw = std::env::var("APP_API_URL")
        .ok()
        .or_else(|| std::option_env!("SITE_URL").map(String::from))
        .unwrap_or_else(|| "http://localhost:1100".to_string());
    origin_of(&raw)
}

/// Reduce a URL to its CSP source origin (`scheme://host[:port]`) by dropping
/// any path / query / fragment. CSP sources are origin-scoped, so a trailing
/// path would silently narrow the allow-list. A schemeless value (`host:port`)
/// is normalized to `http://`, mirroring `configure_http_client` in `main.rs`.
fn origin_of(url: &str) -> String {
    let (scheme, rest) = match url.find("://") {
        Some(idx) => (&url[..idx], &url[idx + 3..]),
        None => ("http", url),
    };
    let authority = rest
        .split(|c| matches!(c, '/' | '?' | '#'))
        .next()
        .filter(|s| !s.is_empty())
        .unwrap_or("");
    format!("{scheme}://{authority}")
}

fn is_html_response(response: &Response) -> bool {
    response
        .headers()
        .get(header::CONTENT_TYPE)
        .and_then(|v| v.to_str().ok())
        .map(|v| v.to_ascii_lowercase().contains("text/html"))
        .unwrap_or(false)
}

fn has_content_encoding(response: &Response) -> bool {
    response.headers().get(header::CONTENT_ENCODING).is_some()
}

/// Remove any `<meta http-equiv="Content-Security-Policy" ...>` tag. A static
/// `<meta>` cannot carry a per-request nonce, and when both a `<meta>` CSP and
/// an HTTP-header CSP are present the browser enforces the **intersection**
/// — so a strict `script-src 'self'` meta would silently block every nonce'd
/// script. The header emitted by this layer is the sole, authoritative policy.
fn strip_csp_meta(html: &str) -> String {
    static RE: std::sync::OnceLock<regex::Regex> = std::sync::OnceLock::new();
    let re = RE.get_or_init(|| {
        // `<meta`, any attrs (across newlines, no `>`), the http-equiv CSP
        // pair, any further attrs, then the closing `>` (incl. self-closing).
        regex::Regex::new(
            r#"(?i)<meta\b[^>]*\bhttp-equiv\s*=\s*["']?Content-Security-Policy["']?[^>]*>"#,
        )
        .expect("static CSP meta regex compiles")
    });
    re.replace_all(html, "").into_owned()
}

/// Inject `nonce="<nonce>"` into the opening tag of the known Dioxus-injected
/// inline scripts only. The matching is content-signature based (see
/// [`should_nonce_script`]) and never touches scripts inside user content.
fn noncify_dioxus_scripts(html: &str, nonce: &str) -> String {
    let mut out = String::with_capacity(html.len() + 64);
    let mut rest = html;

    while let Some(open_rel) = rest.find("<script") {
        let (before, from_open) = rest.split_at(open_rel);
        out.push_str(before);

        // Boundary check: `<script` must be followed by a tag terminator
        // (`>`, `/`, or whitespace). This avoids false matches on text like
        // `<scripting` or an escaped sample, and guarantees forward progress.
        let next = from_open.as_bytes().get(7).copied();
        if !matches!(next, Some(b'>' | b'/' | b' ' | b'\t' | b'\n' | b'\r')) {
            // Not a real `<script` tag — emit the literal and continue after it.
            out.push_str("<script");
            rest = &from_open["<script".len()..];
            continue;
        }

        // End of the opening tag (the first `>`).
        let Some(tag_end_rel) = from_open.find('>') else {
            out.push_str(from_open);
            break;
        };
        let opening_tag = &from_open[..=tag_end_rel]; // `<script …>`
        let after_tag = &from_open[tag_end_rel + 1..];

        // Matching `</script>` close.
        let Some(close_rel) = after_tag.find("</script>") else {
            out.push_str(from_open);
            break;
        };
        let content = &after_tag[..close_rel];
        let after_close = &after_tag[close_rel + "</script>".len()..];

        if should_nonce_script(opening_tag, content) {
            out.push_str("<script nonce=\"");
            out.push_str(nonce);
            out.push_str("\"");
            out.push_str(&opening_tag["<script".len()..]); // attrs + `>`
        } else {
            out.push_str(opening_tag);
        }
        out.push_str(content);
        out.push_str("</script>");

        rest = after_close;
    }
    out.push_str(rest);
    out
}

/// Decide whether an inline `<script>` block is a known Dioxus-injected
/// hydration script that should carry the nonce. This is the load-bearing
/// safety decision — see the module-level SAFETY-CRITICAL INVARIANT.
///
/// Returns `true` **only** for:
/// - the SSR hydration bootstrap (`window.hydrate_queue` — static), and
/// - the SSR hydration payload (`window.initial_dioxus_hydration_data=` —
///   dynamic per render), and
/// - our index.html fallback shim (contains `|| "gA=="`).
///
/// Returns `false` for external scripts (`src=`), non-JS script types
/// (`application/ld+json` etc.), and — critically — anything else, so that an
/// attacker `<script>` that bypassed ammonia inside `<main>` stays blocked.
fn should_nonce_script(opening_tag: &str, content: &str) -> bool {
    let tag = opening_tag.to_ascii_lowercase();
    // External script — authorized by 'self', never nonce.
    if tag.contains("src=") {
        return false;
    }
    // Non-executed script type (JSON-LD data blocks) — not subject to CSP.
    if tag.contains("type=\"application/")
        || tag.contains("type='application/")
        || tag.contains("type=application/")
    {
        return false;
    }
    let body = content.trim_start();
    if body.starts_with("window.hydrate_queue") {
        return true;
    }
    if body.starts_with("window.initial_dioxus_hydration_data=") {
        // The `=` immediately follows the identifier, which distinguishes the
        // SSR data assignment from our fallback shim (which has whitespace and
        // a `|| "gA=="` fallback instead).
        return true;
    }
    if content.contains("|| \"gA==\"") {
        return true;
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn ssr_bootstrap_script_is_nonced() {
        let html = r#"<div id="main"><script>window.hydrate_queue=[];window.dx_hydrate=(id,data)=>{};</script><!--x--></div>"#;
        let out = noncify_dioxus_scripts(html, "NONCE123");
        assert!(out.contains(r#"<script nonce="NONCE123">window.hydrate_queue"#));
    }

    #[test]
    fn ssr_hydration_data_script_is_nonced() {
        // Dynamic per-render payload — exercises the un-hashable case nonces exist for.
        let html = r#"<script>window.initial_dioxus_hydration_data="mBqBGPaCGGEYL";</script>"#;
        let out = noncify_dioxus_scripts(html, "N1");
        assert!(out.contains(r#"<script nonce="N1">window.initial_dioxus_hydration_data="#));
    }

    #[test]
    fn fallback_shim_is_nonced() {
        let html = r#"<script>
            // Some static builds ship a shell index without SSR hydration bytes.
            window.initial_dioxus_hydration_data =
                window.initial_dioxus_hydration_data || "gA==";
        </script>"#;
        let out = noncify_dioxus_scripts(html, "SHIM");
        assert!(out.contains(r#"<script nonce="SHIM">"#));
        assert!(out.contains(r#"|| "gA==""#));
    }

    #[test]
    fn external_script_is_not_nonced() {
        // External module loader is covered by 'self'; nonceing it is pointless.
        let html = r#"<script type="module" async src="/./wasm/consumer-dioxus.js"></script>"#;
        let out = noncify_dioxus_scripts(html, "X");
        assert!(!out.contains("nonce="));
        assert!(out.contains(r#"src="/./wasm/consumer-dioxus.js""#));
    }

    #[test]
    fn jsonld_script_is_not_nonced() {
        let html = r#"<script type="application/ld+json">{"@type":"WebSite"}</script>"#;
        let out = noncify_dioxus_scripts(html, "X");
        assert!(!out.contains("nonce="));
    }

    /// CRITICAL REGRESSION: an attacker `<script>` inside the user-content
    /// `<main>` region (i.e. one that bypassed ammonia) must NOT receive the
    /// nonce. If it did, it would execute under the nonce policy — exactly the
    /// stored-XSS this layer exists to prevent.
    #[test]
    fn attacker_script_is_NOT_nonced() {
        let html = r#"<main><article><script>alert(document.cookie)</script></article></main>"#;
        let out = noncify_dioxus_scripts(html, "SECRET");
        assert!(
            !out.contains("nonce="),
            "an untrusted inline script must never receive the nonce, got: {out}"
        );
        // The attacker script is preserved verbatim (CSP then blocks it).
        assert!(out.contains("<script>alert(document.cookie)</script>"));
    }

    #[test]
    fn script_like_text_is_not_treated_as_a_tag() {
        // Escaped/text occurrence of "<script" must not trigger rewriting.
        let html = r#"<code>&lt;script&gt;not a tag&lt;/script&gt;</code>"#;
        let out = noncify_dioxus_scripts(html, "X");
        assert!(!out.contains("nonce="));
    }

    #[test]
    fn csp_meta_is_stripped_from_document() {
        let html = r#"<head>
            <meta name="viewport" content="width=device-width"/>
            <meta http-equiv="Content-Security-Policy" content="default-src 'self'; script-src 'self'"/>
            <title>x</title>
        </head>"#;
        let out = strip_csp_meta(html);
        assert!(!out.contains("http-equiv"), "CSP meta must be removed: {out}");
        // Non-CSP meta survives.
        assert!(out.contains(r#"name="viewport""#));
    }

    #[test]
    fn rewrite_strips_meta_and_noncifies_only_dioxus_scripts() {
        let html = r#"<!doctype html><head>
            <meta http-equiv="Content-Security-Policy" content="script-src 'self'"/>
        </head><body><div id="main">
            <script>window.hydrate_queue=[];</script>
            <main><script>evil()</script></main>
            <script type="application/ld+json">{"@type":"WebSite"}</script>
        </div></body>"#;
        let out = rewrite_html(html, "NONCE");
        assert!(!out.contains("http-equiv"), "meta stripped");
        assert!(out.contains(r#"<script nonce="NONCE">window.hydrate_queue"#));
        assert!(
            !out.contains("<script>evil()</script>".replace("<script>", "<script nonce").as_str()),
            "evil script must not be nonced: {out}"
        );
        assert!(!out.contains("nonce=\"NONCE\">evil"), "evil script blocked: {out}");
    }

    #[test]
    fn nonce_is_high_entropy_base64() {
        let a = generate_nonce();
        let b = generate_nonce();
        assert_ne!(a, b, "nonces must be per-call unique");
        assert!(a.len() >= 20, "nonce should be ~24 base64 chars, got {}", a.len());
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '+' || c == '/'),
            "nonce must be base64");
    }

    #[test]
    fn csp_header_contains_nonce_and_keywords_not_unsafe_inline() {
        let v = csp_value("ABC123").to_str().unwrap().to_string();
        assert!(v.contains("'nonce-ABC123'"));
        assert!(v.contains("'wasm-unsafe-eval'"));
        assert!(v.contains("'unsafe-eval'"));
        assert!(v.contains("frame-ancestors 'none'"));
        // Check ONLY the script-src directive: style-src legitimately uses
        // 'unsafe-inline' for the app's injected styles, so a whole-header
        // check would false-positive. script-src must never grant it.
        let script_src = v
            .split("script-src ")
            .nth(1)
            .and_then(|s| s.split(';').next())
            .unwrap_or("");
        assert!(
            !script_src.contains("'unsafe-inline'"),
            "script-src must not grant 'unsafe-inline': {v}"
        );
    }

    #[test]
    fn origin_of_strips_path_query_fragment_and_normalizes_scheme() {
        // Bare origin passes through unchanged.
        assert_eq!(origin_of("http://localhost:1100"), "http://localhost:1100");
        // Trailing slash / path / query / fragment are dropped (CSP sources are
        // origin-scoped; a path would silently narrow the allow-list).
        assert_eq!(origin_of("http://localhost:1100/"), "http://localhost:1100");
        assert_eq!(
            origin_of("https://api.example.com/csrf/v1/generate?x=1#t"),
            "https://api.example.com"
        );
        // Schemeless host:port is normalized to http, matching main.rs.
        assert_eq!(origin_of("localhost:1100"), "http://localhost:1100");
    }

    #[test]
    fn csp_connect_src_includes_self_and_api_origin() {
        let v = csp_value("ABC123").to_str().unwrap().to_string();
        // connect-src must list 'self' AND the cross-origin API origin so the
        // WASM client's CSRF-bootstrap / server-fn fetches are not blocked.
        let connect_src = v
            .split("connect-src ")
            .nth(1)
            .and_then(|s| s.split(';').next())
            .unwrap_or("");
        assert!(connect_src.contains("'self'"), "connect-src must keep 'self': {v}");
        assert!(
            connect_src.contains("http://") || connect_src.contains("https://"),
            "connect-src must include the API origin: {v}"
        );
    }
}
