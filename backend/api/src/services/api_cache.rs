//! 3rd-party API response caching (issue #5).
//!
//! [`cached_get`] is a read-through cache for outbound GET requests: it checks
//! the shared redis pool BEFORE issuing the HTTP call and populates it on a
//! miss. Use it for idempotent, relatively-static upstream reads (OIDC JWKS,
//! billing-provider plan lookups, etc.) — never for request-specific calls.
//!
//! # Fail-open
//! If redis is unavailable (no pool installed / transient blip), the HTTP GET
//! still runs and the caller never sees a redis error. Caching is a pure
//! optimization — a redis outage degrades to "uncached latency", never to a
//! user-visible failure.
//!
//! # Feature gate
//! Gated behind `cache` (OFF in `basic`, ON in `full`). The representative
//! live usage is the Google JWKS fetch in `google_auth_v1::service`
//! (`fetch_google_jwks` reads redis; `fetch_google_jwks_bypass_cache` writes
//! it on success). That path uses the [`crate::services::cache`] primitives
//! directly because the JWKS fetch carries custom validation (status check,
//! R-5 bypass-cache retry semantics); [`cached_get`] below is the general
//! helper for simpler GET-and-parse call sites.

use serde::{de::DeserializeOwned, Serialize};
use tracing::{debug, error, warn};

use crate::{
    error::{ErrorCode, ErrorResponse},
    services::cache,
};

/// Read-through cached GET.
///
/// - redis hit  → return the cached body (deserialized into `T`), no HTTP.
/// - redis miss → `http.get(url)`, parse into `T`, populate redis under `key`
///   with `ttl_secs`, return `T`.
///
/// Non-2xx / parse failures surface as [`ErrorCode::ExternalServiceError`];
/// redis read/write failures are logged and ignored (fail-open).
///
/// `T` must be both `Serialize` (to populate the cache) and `DeserializeOwned`
/// (to read it back).
pub async fn cached_get<T>(
    http: &reqwest::Client,
    url: &str,
    key: &str,
    ttl_secs: u64,
) -> Result<T, ErrorResponse>
where
    T: Serialize + DeserializeOwned,
{
    // Redis fast path.
    if let Some(pool) = cache::global_pool() {
        match cache::get::<T>(pool, key).await {
            Ok(Some(cached)) => {
                debug!(key = %key, "api cache hit");
                return Ok(cached);
            }
            Ok(None) => {}
            Err(e) => warn!(error = %e, key = %key, "api cache get failed (non-fatal)"),
        }
    }

    // Miss → upstream HTTP GET.
    let resp = http.get(url).send().await.map_err(|e| {
        error!(error = ?e, url = %url, "cached_get: HTTP fetch failed");
        ErrorResponse::new(ErrorCode::ExternalServiceError).with_message("Upstream fetch failed")
    })?;
    let status = resp.status();
    let bytes = resp.bytes().await.map_err(|e| {
        error!(error = ?e, "cached_get: response body read failed");
        ErrorResponse::new(ErrorCode::ExternalServiceError).with_message("Upstream fetch failed")
    })?;
    if !status.is_success() {
        error!(status = %status, url = %url, "cached_get: upstream returned non-2xx");
        return Err(ErrorResponse::new(ErrorCode::ExternalServiceError)
            .with_message("Upstream fetch failed"));
    }
    let parsed: T = serde_json::from_slice(&bytes).map_err(|e| {
        error!(error = ?e, "cached_get: failed to parse upstream response");
        ErrorResponse::new(ErrorCode::ExternalServiceError)
            .with_message("Malformed upstream response")
    })?;

    // Populate cache (best-effort).
    if let Some(pool) = cache::global_pool() {
        if let Err(e) = cache::set(pool, key, &parsed, ttl_secs).await {
            warn!(error = %e, key = %key, "api cache set failed (non-fatal)");
        }
    }

    Ok(parsed)
}
