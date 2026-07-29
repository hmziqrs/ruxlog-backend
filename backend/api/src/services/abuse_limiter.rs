//! ruxlog adapter over the [`rux_request_gate`] crate.
//!
//! The rate-limiting / abuse-limiting *logic* now lives in the standalone,
//! domain-free [`rux_request_gate`] crate. This module is the thin ruxlog-side
//! adapter kept at the historical `services::abuse_limiter` path so existing
//! call sites compile unchanged. It maps the crate's [`LimiterDecision`] /
//! [`rux_request_gate::GateError`] onto the app's [`ErrorResponse`] and bridges
//! the crate's observability hooks to ruxlog's OpenTelemetry counters.
//!
//! `limiter()` keeps its exact pre-extraction signature, so the controller call
//! sites are untouched. `dedup_nx` / `release_dedup` / `check` are consumed
//! directly from the crate (their signatures changed; callers updated).

use serde_json::json;

use crate::error::{ErrorCode, ErrorResponse};
use crate::utils::telemetry;

pub use rux_request_gate::{AbuseLimiterConfig, BlockScope, LimiterDecision};

/// OpenTelemetry bridge: forwards the crate's limiter callbacks to ruxlog's
/// `limiter.*` counters (the counters that previously lived inline here).
#[derive(Clone, Copy, Default)]
pub(crate) struct TelemetryHooks;

impl rux_request_gate::LimiterHooks for TelemetryHooks {
    fn on_check(&self) {
        telemetry::limiter_metrics().checks.add(1, &[]);
    }
    fn on_allowed(&self, _short_count: u64, _long_count: u64) {
        telemetry::limiter_metrics().allowed.add(1, &[]);
    }
    fn on_blocked(
        &self,
        scope: BlockScope,
        _retry_after_secs: u64,
        _short_count: u64,
        _long_count: u64,
    ) {
        let m = telemetry::limiter_metrics();
        m.blocked.add(1, &[]);
        match scope {
            BlockScope::Temp => m.temp_blocks.add(1, &[]),
            BlockScope::Long => m.long_blocks.add(1, &[]),
        }
    }
}

/// Abuse-limit check mapped onto `ErrorResponse` (see [`map_limiter_result`]
/// for the response contract).
pub async fn limiter(
    redis_pool: &rux_request_gate::RedisPool,
    key_prefix: &str,
    config: AbuseLimiterConfig,
) -> Result<(), ErrorResponse> {
    let res = rux_request_gate::check(redis_pool, &TelemetryHooks, key_prefix, config).await;
    map_limiter_result(res)
}

/// Map a crate limiter result onto the app's `ErrorResponse` contract. Pure
/// (no Redis) so the mapping is unit-tested directly:
/// - `Allowed` -> `Ok`.
/// - `Blocked` -> `ErrorCode::TooManyAttempts` (429) + `Retry-After` + context.
/// - store error -> `ErrorCode::ServiceUnavailable` (503).
/// - malformed result -> `ErrorCode::InternalServerError` (500).
pub(crate) fn map_limiter_result(
    res: Result<rux_request_gate::LimiterDecision, rux_request_gate::GateError>,
) -> Result<(), ErrorResponse> {
    use rux_request_gate::{GateError, LimiterDecision};
    match res {
        Ok(LimiterDecision::Allowed { .. }) => Ok(()),
        Ok(LimiterDecision::Blocked { retry_after_secs, .. }) => Err(ErrorResponse::new(ErrorCode::TooManyAttempts)
            .with_message(format!(
                "Too many attempts. Try again in {} seconds.",
                retry_after_secs
            ))
            .with_retry_after(retry_after_secs)
            .with_context(json!({ "retryAfter": retry_after_secs }))),
        Err(GateError::StoreUnavailable(detail)) => Err(ErrorResponse::new(ErrorCode::ServiceUnavailable)
            .with_message("Limiter unavailable (Redis error)")
            .with_details(detail)),
        Err(GateError::UnexpectedResult) => Err(ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("Limiter returned unexpected result")),
    }
}

#[cfg(test)]
mod tests {
    //! Pin the limiter decision → ErrorResponse status mapping (the contract
    //! the request-gate extraction must preserve), without needing Redis.
    use super::*;
    use axum::response::IntoResponse;
    use rux_request_gate::{BlockScope, GateError, LimiterDecision};

    #[test]
    fn allowed_maps_ok() {
        assert!(map_limiter_result(Ok(LimiterDecision::Allowed {
            short_count: 1,
            long_count: 0,
        }))
        .is_ok());
    }

    #[test]
    fn blocked_maps_to_429() {
        let resp = map_limiter_result(Ok(LimiterDecision::Blocked {
            scope: BlockScope::Temp,
            retry_after_secs: 42,
            short_count: 5,
            long_count: 9,
        }))
        .unwrap_err()
        .into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::TOO_MANY_REQUESTS);
    }

    #[test]
    fn store_unavailable_maps_to_503() {
        let resp = map_limiter_result(Err(GateError::StoreUnavailable("boom".into())))
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::SERVICE_UNAVAILABLE);
    }

    #[test]
    fn unexpected_result_maps_to_500() {
        let resp = map_limiter_result(Err(GateError::UnexpectedResult))
            .unwrap_err()
            .into_response();
        assert_eq!(resp.status(), axum::http::StatusCode::INTERNAL_SERVER_ERROR);
    }
}
