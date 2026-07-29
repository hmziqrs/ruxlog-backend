//! The minimal Redis surface the gate needs, behind a trait so the failure
//! modes are unit-testable without a live Redis.

use async_trait::async_trait;

// Access fred only through the tower-sessions-redis-store re-export so the
// version always tracks the one the host app already depends on.
pub use tower_sessions_redis_store::fred::prelude::Pool as RedisPool;
pub use tower_sessions_redis_store::fred::types::Value as RedisValue;

use crate::error::GateError;

/// Atomic `EVAL` over a Redis backend.
///
/// Implement this to plug in a non-fred backend or a test double. The default
/// impl covers the `fred` [`RedisPool`] used by `tower-sessions-redis-store`.
#[async_trait]
pub trait RateLimitStore: Send + Sync {
    /// Run `script` with `keys`/`args`, returning the reply as a `Vec<Value>`.
    /// Store/backend errors MUST be mapped to [`GateError::StoreUnavailable`].
    async fn eval(
        &self,
        script: &str,
        keys: Vec<String>,
        args: Vec<RedisValue>,
    ) -> Result<Vec<RedisValue>, GateError>;
}

#[async_trait]
impl RateLimitStore for RedisPool {
    async fn eval(
        &self,
        script: &str,
        keys: Vec<String>,
        args: Vec<RedisValue>,
    ) -> Result<Vec<RedisValue>, GateError> {
        use tower_sessions_redis_store::fred::interfaces::LuaInterface;
        // Identical to the pre-extraction call site: the return-type annotation
        // drives fred's FromRedis inference.
        let res: Result<Vec<RedisValue>, _> = LuaInterface::eval(self, script, keys, args).await;
        res.map_err(|e| GateError::StoreUnavailable(e.to_string()))
    }
}
