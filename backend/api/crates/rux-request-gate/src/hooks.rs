//! Observability hook point.
//!
//! Replaces a hard-wired metrics dependency: the crate emits no telemetry
//! itself; the consumer supplies a [`LimiterHooks`] impl (default [`NoHooks`]
//! is a no-op). Object-safe so it can be held as `Arc<dyn LimiterHooks>`.

use crate::abuse::BlockScope;

/// Observability callbacks for the abuse limiter. All methods have no-op
/// defaults; override only what you need.
pub trait LimiterHooks: Send + Sync {
    fn on_check(&self) {}
    #[allow(unused_variables)]
    fn on_allowed(&self, short_count: u64, long_count: u64) {}
    #[allow(unused_variables)]
    fn on_blocked(
        &self,
        scope: BlockScope,
        retry_after_secs: u64,
        short_count: u64,
        long_count: u64,
    ) {
    }
}

/// No-op hooks (the default).
#[derive(Clone, Copy, Default, Debug)]
pub struct NoHooks;

impl LimiterHooks for NoHooks {}
