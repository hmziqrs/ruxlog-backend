//! Redis-backed request gates for Axum — domain-free and reusable.
//!
//! Three primitives, each with explicit fail semantics:
//! - **Abuse limiter** ([`check`]): dual-threshold (short temp-block / long
//!   block) sliding-window counter over a Redis ZSET. Returns a
//!   [`LimiterDecision`]; **fail-CLOSED** on a store error.
//! - **Rate-limit layer** ([`RateLimitLayer`]): per-IP/per-path fixed-window
//!   tower middleware emitting `x-ratelimit-*` + `Retry-After`. **Fail-CLOSED**
//!   (503) on a store error.
//! - **Idempotency/dedup** ([`dedup_nx`]/[`release_dedup`]): one-shot `SET NX`
//!   claim. **Fail-OPEN** — a store outage must not 5xx the caller.
//!
//! The crate depends on no application types: it talks to Redis via the
//! [`RateLimitStore`] trait (default impl for the `fred` `Pool` re-exported by
//! `tower-sessions-redis-store`) and emits raw axum responses.

#![forbid(unsafe_code)]

mod abuse;
mod error;
mod hooks;
mod ip;
mod layer;
mod store;

pub use abuse::{check, dedup_nx, release_dedup, AbuseLimiterConfig, BlockScope, LimiterDecision};
pub use error::GateError;
pub use hooks::{LimiterHooks, NoHooks};
pub use ip::{FnIpSource, IpSource};
#[cfg(feature = "axum-client-ip")]
pub use ip::ClientIpSource;
pub use layer::{BlockInfo, RateLimitLayer, RateLimitLayerBuilder};
pub use store::{RateLimitStore, RedisPool, RedisValue};
