//! Per-IP/per-path fixed-window rate-limit tower layer.
//!
//! Emits `x-ratelimit-{limit,remaining,reset}` + `Retry-After`. **Fail-CLOSED**:
//! a store error yields 503 (the count cannot be trusted). The 429 body and the
//! 503 body are produced by caller-supplied closures (sensible defaults ship
//! with the crate), so the crate owns no error vocabulary.

use std::future::Future;
use std::pin::Pin;
use std::sync::Arc;
use std::task::{Context, Poll};

use axum::http::{HeaderName, HeaderValue};
use axum::response::{IntoResponse, Response};
use tower::{Layer, Service};
use tower_sessions_redis_store::fred::interfaces::LuaInterface;
use tower_sessions_redis_store::fred::types::FromValue;
use tracing::{debug, warn};

use crate::ip::{ClientIpSource, IpSource};
use crate::store::{RedisPool, RedisValue};

// Standard rate limit header names (not in http::header module).
static X_RATELIMIT_LIMIT: HeaderName = HeaderName::from_static("x-ratelimit-limit");
static X_RATELIMIT_REMAINING: HeaderName = HeaderName::from_static("x-ratelimit-remaining");
static X_RATELIMIT_RESET: HeaderName = HeaderName::from_static("x-ratelimit-reset");

/// Fixed-window counter Lua script.
///
/// KEYS[1] = rate limit key, ARGV[1] = max_requests (unused), ARGV[2] = window (TTL).
/// Returns `[count, ttl]`.
const SLIDING_WINDOW_SCRIPT: &str = r#"
local key = KEYS[1]
local max_requests = tonumber(ARGV[1])
local ttl = tonumber(ARGV[2])

local count = redis.call('INCR', key)
if count == 1 then
    redis.call('EXPIRE', key, ttl)
end

local current_ttl = redis.call('TTL', key)
if current_ttl < 0 then current_ttl = ttl end

return {count, current_ttl}
"#;

/// Context handed to the `on_block` closure.
#[derive(Debug, Clone, Copy)]
pub struct BlockInfo {
    pub retry_after_secs: u64,
    pub max_requests: u64,
    pub window_secs: u64,
    pub count: u64,
    pub ttl: u64,
}

type BlockFn = Arc<dyn Fn(BlockInfo) -> Response + Send + Sync>;
type UnavailableFn = Arc<dyn Fn() -> Response + Send + Sync>;

/// Tower layer that wraps an inner service with per-IP/per-path rate limiting.
#[derive(Clone)]
pub struct RateLimitLayer {
    pool: RedisPool,
    max_requests: u64,
    window_secs: u64,
    ip_source: Arc<dyn IpSource>,
    on_block: BlockFn,
    on_unavailable: UnavailableFn,
}

impl RateLimitLayer {
    /// Construct with the default `ClientIpSource` IP resolver and the crate's
    /// default 429/503 response bodies.
    #[cfg(feature = "axum-client-ip")]
    pub fn new(pool: RedisPool, max_requests: u64, window_secs: u64) -> Self {
        Self {
            pool,
            max_requests,
            window_secs,
            ip_source: Arc::new(ClientIpSource),
            on_block: Arc::new(default_on_block),
            on_unavailable: Arc::new(default_on_unavailable),
        }
    }

    /// Construct with a custom IP source (always available, even without the
    /// `axum-client-ip` feature).
    pub fn with_ip(
        pool: RedisPool,
        max_requests: u64,
        window_secs: u64,
        ip_source: Arc<dyn IpSource>,
    ) -> Self {
        Self {
            pool,
            max_requests,
            window_secs,
            ip_source,
            on_block: Arc::new(default_on_block),
            on_unavailable: Arc::new(default_on_unavailable),
        }
    }

    /// Start a builder to override IP source / response closures.
    #[cfg(feature = "axum-client-ip")]
    pub fn builder(pool: RedisPool, max_requests: u64, window_secs: u64) -> RateLimitLayerBuilder {
        RateLimitLayerBuilder {
            layer: Self::new(pool, max_requests, window_secs),
        }
    }
}

/// Builder for [`RateLimitLayer`].
#[cfg(feature = "axum-client-ip")]
pub struct RateLimitLayerBuilder {
    layer: RateLimitLayer,
}

#[cfg(feature = "axum-client-ip")]
impl RateLimitLayerBuilder {
    pub fn ip_source(mut self, ip: Arc<dyn IpSource>) -> Self {
        self.layer.ip_source = ip;
        self
    }
    pub fn on_block<F>(mut self, f: F) -> Self
    where
        F: Fn(BlockInfo) -> Response + Send + Sync + 'static,
    {
        self.layer.on_block = Arc::new(f);
        self
    }
    pub fn on_unavailable<F>(mut self, f: F) -> Self
    where
        F: Fn() -> Response + Send + Sync + 'static,
    {
        self.layer.on_unavailable = Arc::new(f);
        self
    }
    pub fn build(self) -> RateLimitLayer {
        self.layer
    }
}

impl<Inner> Layer<Inner> for RateLimitLayer {
    type Service = RateLimitMiddleware<Inner>;

    fn layer(&self, inner: Inner) -> Self::Service {
        RateLimitMiddleware {
            inner,
            layer: self.clone(),
        }
    }
}

/// Tower middleware service that enforces rate limits via Redis.
#[derive(Clone)]
pub struct RateLimitMiddleware<Inner> {
    inner: Inner,
    layer: RateLimitLayer,
}

impl<Inner> Service<axum::extract::Request> for RateLimitMiddleware<Inner>
where
    Inner: Service<axum::extract::Request, Response = Response> + Clone + Send + 'static,
    Inner::Future: Send + 'static,
{
    type Response = Inner::Response;
    type Error = Inner::Error;
    type Future = Pin<Box<dyn Future<Output = Result<Self::Response, Self::Error>> + Send>>;

    fn poll_ready(&mut self, cx: &mut Context<'_>) -> Poll<Result<(), Self::Error>> {
        self.inner.poll_ready(cx)
    }

    fn call(&mut self, req: axum::extract::Request) -> Self::Future {
        let layer = self.layer.clone();
        let mut inner = self.inner.clone();

        Box::pin(async move {
            let ip = layer.ip_source.resolve(&req);
            let path = req.uri().path().to_string();
            let key = format!("ratelimit:{}:{}", ip, path);

            let keys = vec![key.clone()];
            let args: Vec<RedisValue> = vec![
                RedisValue::from(layer.max_requests as i64),
                RedisValue::from(layer.window_secs as i64),
            ];

            let result: Result<Vec<RedisValue>, _> =
                LuaInterface::eval(&layer.pool, SLIDING_WINDOW_SCRIPT, keys, args).await;

            let (count, ttl) = match result {
                Ok(values) => {
                    let count = u64::from_value(values[0].clone()).unwrap_or(1);
                    let ttl = u64::from_value(values[1].clone()).unwrap_or(layer.window_secs);
                    (count, ttl)
                }
                Err(err) => {
                    // Fail closed: if Redis is unavailable we cannot enforce a
                    // per-IP limit, so rejecting (503) is safer than silently
                    // allowing unbounded traffic.
                    warn!(
                        error = %err,
                        key = %key,
                        "Redis error during rate limit check, rejecting (fail-closed)"
                    );
                    return Ok((layer.on_unavailable)());
                }
            };

            if count > layer.max_requests {
                debug!(
                    ip = %ip,
                    path,
                    count,
                    max_requests = layer.max_requests,
                    window_secs = layer.window_secs,
                    "Rate limit exceeded"
                );

                let retry_after = ttl;
                let info = BlockInfo {
                    retry_after_secs: retry_after,
                    max_requests: layer.max_requests,
                    window_secs: layer.window_secs,
                    count,
                    ttl,
                };

                let mut response = (layer.on_block)(info);
                let headers = response.headers_mut();
                insert_header(headers, &X_RATELIMIT_LIMIT, layer.max_requests);
                insert_header(headers, &X_RATELIMIT_REMAINING, 0u64);
                insert_header(headers, &X_RATELIMIT_RESET, ttl);
                insert_header(headers, &axum::http::header::RETRY_AFTER, retry_after);

                return Ok(response);
            }

            // Allowed — run the inner service and attach rate limit headers.
            let response = inner.call(req).await?;

            let remaining = layer.max_requests.saturating_sub(count);
            let mut response = response;
            let headers = response.headers_mut();
            insert_header(headers, &X_RATELIMIT_LIMIT, layer.max_requests);
            insert_header(headers, &X_RATELIMIT_REMAINING, remaining);
            insert_header(headers, &X_RATELIMIT_RESET, ttl);

            Ok(response)
        })
    }
}

/// Helper to insert a numeric header value, falling back gracefully.
fn insert_header(headers: &mut axum::http::HeaderMap, name: &HeaderName, value: u64) {
    let val = HeaderValue::from_str(&value.to_string())
        .unwrap_or_else(|_| HeaderValue::from_static("0"));
    headers.insert(name, val);
}

/// Default 429 body (overridable via the builder). Minimal JSON; the host app
/// typically overrides with its own error envelope.
fn default_on_block(info: BlockInfo) -> Response {
    (
        axum::http::StatusCode::TOO_MANY_REQUESTS,
        axum::Json(serde_json::json!({
            "error": "rate_limited",
            "message": format!("Too many requests. Try again in {} seconds.", info.retry_after_secs),
            "retryAfter": info.retry_after_secs,
        })),
    )
        .into_response()
}

/// Default 503 body (overridable via the builder). Matches the pre-extraction
/// inline response exactly.
fn default_on_unavailable() -> Response {
    (
        axum::http::StatusCode::SERVICE_UNAVAILABLE,
        axum::Json(serde_json::json!({
            "error": "rate limit service unavailable",
            "message": "Could not reach the rate-limit store. Try again shortly."
        })),
    )
        .into_response()
}
