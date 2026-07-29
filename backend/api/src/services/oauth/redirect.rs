//! Post-login success-redirect origin validation, shared across all OAuth
//! providers. Lifted verbatim (in semantics) from `google_auth_v1` so every
//! provider applies the same open-redirect defense: the success path always
//! lands on our own route, and only the ORIGIN (operator-controlled via
//! `FRONTEND_URL`) is allowed — and only if it passes the explicit allow-list
//! (`OAUTH_ALLOWED_REDIRECT_ORIGINS`) when one is configured.

use tracing::warn;

use crate::error::{ErrorCode, ErrorResponse};

/// Build the post-login success redirect, validating the ORIGIN
/// (scheme + host [+ port]) against an allow-list before issuing the redirect.
///
/// Fail closed: if `FRONTEND_URL` is unset AND no allow-list is configured, we
/// reject rather than redirect to an unvalidated default. (V-LOW-REDIRECT: this
/// open-redirect defense was originally authored in `google_auth_v1` and lifted
/// here so every OAuth provider applies it identically.)
#[allow(clippy::result_large_err)]
pub fn build_allowed_success_redirect(path: &str) -> Result<String, ErrorResponse> {
    let frontend_url = std::env::var("FRONTEND_URL").ok();
    let allowed: Vec<String> = std::env::var("OAUTH_ALLOWED_REDIRECT_ORIGINS")
        .ok()
        .map(|raw| {
            raw.split(',')
                .map(|s| s.trim().trim_end_matches('/').to_string())
                .filter(|s| !s.is_empty())
                .collect()
        })
        .unwrap_or_default();

    let origin = if allowed.is_empty() {
        // No explicit allow-list: trust FRONTEND_URL's own origin.
        let base = frontend_url.as_deref().unwrap_or("");
        if base.is_empty() {
            warn!("No OAUTH_ALLOWED_REDIRECT_ORIGINS and no FRONTEND_URL; refusing post-login redirect");
            return Err(ErrorResponse::new(ErrorCode::ConfigurationError)
                .with_message("Post-login redirect origin is not configured"));
        }
        base.trim_end_matches('/').to_string()
    } else {
        // Explicit allow-list present: FRONTEND_URL's origin must be in it.
        match frontend_url.as_deref() {
            Some(raw) => {
                let candidate = origin_of(raw)?;
                if allowed.iter().any(|a| a == &candidate) {
                    candidate
                } else {
                    warn!(origin = %candidate, "FRONTEND_URL origin rejected by OAUTH_ALLOWED_REDIRECT_ORIGINS");
                    return Err(ErrorResponse::new(ErrorCode::ConfigurationError)
                        .with_message("Post-login redirect origin is not allowed"));
                }
            }
            None => {
                warn!("OAUTH_ALLOWED_REDIRECT_ORIGINS set but FRONTEND_URL missing");
                return Err(ErrorResponse::new(ErrorCode::ConfigurationError)
                    .with_message("Post-login redirect origin is not configured"));
            }
        }
    };

    Ok(format!("{origin}{path}"))
}

/// Extract the origin (scheme://host[:port]) of an absolute URL string, rejecting
/// anything that is not an absolute http(s) URL so a malformed/poisoned value can
/// never be smuggled through the allow-list comparison.
#[allow(clippy::result_large_err)]
fn origin_of(url: &str) -> Result<String, ErrorResponse> {
    let parsed = reqwest::Url::parse(url).map_err(|e| {
        warn!(error = ?e, url = %url, "FRONTEND_URL is not a valid absolute URL");
        ErrorResponse::new(ErrorCode::InternalServerError).with_message("Invalid FRONTEND_URL")
    })?;
    if !matches!(parsed.scheme(), "http" | "https") {
        warn!(scheme = %parsed.scheme(), "FRONTEND_URL must be http(s)");
        return Err(
            ErrorResponse::new(ErrorCode::InternalServerError).with_message("Invalid FRONTEND_URL")
        );
    }
    let host = parsed.host_str().ok_or_else(|| {
        warn!(url = %url, "FRONTEND_URL has no host");
        ErrorResponse::new(ErrorCode::InternalServerError).with_message("Invalid FRONTEND_URL")
    })?;
    let port = parsed.port();
    Ok(match port {
        Some(p) => format!("{}://{}:{}", parsed.scheme(), host, p),
        None => format!("{}://{}", parsed.scheme(), host),
    })
}
