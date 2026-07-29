//! ruxlog adapter: builds a [`rux_request_gate::RateLimitLayer`] wired with the
//! app's 429 error envelope so the wire contract (ErrorCode::RateLimited /
//! SRV_004 + `Retry-After` + `x-ratelimit-*` headers) is unchanged. The
//! fixed-window Lua, the fail-closed 503, and the IP-spoofing regression tests
//! now live in the crate.

use axum::response::IntoResponse;

use crate::error::{ErrorCode, ErrorResponse};
use crate::state::AppState;

pub use rux_request_gate::RateLimitLayer;

/// Build the per-IP/per-path rate-limit layer for a route.
///
/// The 429 body is built from the app's `ErrorResponse` (SRV_004) via the
/// crate's `on_block` hook, matching the pre-extraction response byte-for-byte.
/// The crate still injects the `x-ratelimit-*` + `Retry-After` headers itself.
pub fn rate_limit_layer(state: &AppState, max_requests: u64, window_secs: u64) -> RateLimitLayer {
    RateLimitLayer::builder(state.redis_pool.clone(), max_requests, window_secs)
        .on_block(|info| {
            ErrorResponse::new(ErrorCode::RateLimited)
                .with_message(format!(
                    "Too many requests. Try again in {} seconds.",
                    info.retry_after_secs
                ))
                .with_retry_after(info.retry_after_secs)
                .into_response()
        })
        .build()
}
