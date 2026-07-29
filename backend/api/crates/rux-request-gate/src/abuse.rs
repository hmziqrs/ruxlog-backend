//! Dual-threshold abuse limiter + one-shot dedup, both backed by atomic Lua.

use tracing::{debug, error, instrument, warn};
use tower_sessions_redis_store::fred::types::FromValue;

use crate::error::GateError;
use crate::hooks::LimiterHooks;
use crate::store::{RateLimitStore, RedisValue};

#[derive(Clone, Copy, Debug)]
pub struct AbuseLimiterConfig {
    pub temp_block_attempts: usize,
    pub temp_block_range: usize,    // seconds
    pub temp_block_duration: usize, // seconds
    pub block_retry_limit: usize,   // long threshold
    pub block_range: usize,         // seconds
    pub block_duration: usize,      // seconds
}

#[derive(Debug, Clone, Copy)]
pub enum BlockScope {
    Temp,
    Long,
}

#[derive(Debug, Clone)]
pub enum LimiterDecision {
    Allowed {
        short_count: u64,
        long_count: u64,
    },
    Blocked {
        scope: BlockScope,
        retry_after_secs: u64,
        short_count: u64,
        long_count: u64,
    },
}

const LUA_SCRIPT: &str = r#"
-- KEYS: attempts_key, block_key, seq_key
-- ARGV: temp_window, temp_threshold, temp_block_duration, long_window, long_threshold, long_block_duration, attempts_ttl

local attempts_key = KEYS[1]
local block_key = KEYS[2]
local seq_key = KEYS[3]

local temp_window = tonumber(ARGV[1])
local temp_threshold = tonumber(ARGV[2])
local temp_block_duration = tonumber(ARGV[3])
local long_window = tonumber(ARGV[4])
local long_threshold = tonumber(ARGV[5])
local long_block_duration = tonumber(ARGV[6])
local attempts_ttl = tonumber(ARGV[7])

local now = redis.call('TIME')
local now_sec = tonumber(now[1])

-- If already blocked, return the remaining TTL immediately
local existing_ttl = redis.call('TTL', block_key)
if existing_ttl and existing_ttl > 0 then
  -- Maintain attempts bookkeeping (optional): push the attempt but do not affect block state
  local seq = redis.call('INCR', seq_key)
  redis.call('EXPIRE', seq_key, attempts_ttl)
  local member = string.format('%d:%d', now_sec, seq)
  redis.call('ZADD', attempts_key, now_sec, member)
  redis.call('EXPIRE', attempts_key, attempts_ttl)
  local short_count = redis.call('ZCOUNT', attempts_key, now_sec - temp_window, now_sec)
  local long_count  = redis.call('ZCOUNT', attempts_key, now_sec - long_window, now_sec)
  return {0, existing_ttl, short_count, long_count, 'existing'}
end

local max_window = math.max(temp_window, long_window)
redis.call('ZREMRANGEBYSCORE', attempts_key, '-inf', now_sec - max_window)

local seq = redis.call('INCR', seq_key)
redis.call('EXPIRE', seq_key, attempts_ttl)
local member = string.format('%d:%d', now_sec, seq)
redis.call('ZADD', attempts_key, now_sec, member)
redis.call('EXPIRE', attempts_key, attempts_ttl)

local short_count = redis.call('ZCOUNT', attempts_key, now_sec - temp_window, now_sec)
local long_count  = redis.call('ZCOUNT', attempts_key, now_sec - long_window, now_sec)

if short_count >= temp_threshold then
  redis.call('SET', block_key, '1', 'EX', temp_block_duration, 'NX')
  local ttl = redis.call('TTL', block_key)
  if ttl < 0 then ttl = 0 end
  return {0, ttl, short_count, long_count, 'temp'}
elseif long_count >= long_threshold then
  redis.call('SET', block_key, '1', 'EX', long_block_duration, 'NX')
  local ttl = redis.call('TTL', block_key)
  if ttl < 0 then ttl = 0 end
  return {0, ttl, short_count, long_count, 'long'}
else
  return {1, 0, short_count, long_count, 'none'}
end
"#;

// Helpers: convert fred Value into primitives using FromValue.
#[inline]
fn to_u64(v: &RedisValue) -> Option<u64> {
    u64::from_value(v.clone()).ok()
}
#[inline]
fn to_value_string(v: &RedisValue) -> Option<String> {
    String::from_value(v.clone()).ok()
}

/// Execute the limiter in Redis via a single atomic Lua script. **Fail-CLOSED**:
/// a store error or malformed result yields `Err(GateError)`. A `Blocked`
/// decision is an `Ok` variant — the caller decides how to respond.
#[instrument(skip(store, hooks), fields(
    scope = %key_prefix,
    decision,
    short_count,
    long_count,
    retry_after
))]
pub async fn check(
    store: &dyn RateLimitStore,
    hooks: &dyn LimiterHooks,
    key_prefix: &str,
    config: AbuseLimiterConfig,
) -> Result<LimiterDecision, GateError> {
    hooks.on_check();

    debug!(
        temp_threshold = config.temp_block_attempts,
        temp_window = config.temp_block_range,
        long_threshold = config.block_retry_limit,
        long_window = config.block_range,
        "Checking abuse limiter"
    );
    let attempts_key = format!("abuse_limiter:attempts:{}", key_prefix);
    let block_key = format!("abuse_limiter:block:{}", key_prefix);
    let seq_key = format!("abuse_limiter:seq:{}", key_prefix);

    let attempts_ttl = std::cmp::max(config.temp_block_range, config.block_range) + 60; // slack 60s

    let keys = vec![attempts_key, block_key, seq_key];
    let args: Vec<RedisValue> = vec![
        RedisValue::from(config.temp_block_range as i64),
        RedisValue::from(config.temp_block_attempts as i64),
        RedisValue::from(config.temp_block_duration as i64),
        RedisValue::from(config.block_range as i64),
        RedisValue::from(config.block_retry_limit as i64),
        RedisValue::from(config.block_duration as i64),
        RedisValue::from(attempts_ttl as i64),
    ];

    let values = match store.eval(LUA_SCRIPT, keys, args).await {
        Ok(v) => v,
        Err(err) => {
            error!(
                error = %err,
                key_prefix = %key_prefix,
                "Redis error during limiter check"
            );
            return Err(err);
        }
    };

    if values.len() != 5 {
        error!(
            value_count = values.len(),
            key_prefix = %key_prefix,
            "Unexpected Lua script result length"
        );
        return Err(GateError::UnexpectedResult);
    }

    let allowed = to_u64(&values[0]).unwrap_or(0);
    let retry_after = to_u64(&values[1]).unwrap_or(0);
    let short_count = to_u64(&values[2]).unwrap_or(0);
    let long_count = to_u64(&values[3]).unwrap_or(0);
    let reason = to_value_string(&values[4]).unwrap_or_else(|| "none".to_string());

    if allowed == 1 {
        debug!(short_count, long_count, "Request allowed");
        tracing::Span::current().record("decision", "allowed");
        tracing::Span::current().record("short_count", short_count);
        tracing::Span::current().record("long_count", long_count);

        hooks.on_allowed(short_count, long_count);

        return Ok(LimiterDecision::Allowed {
            short_count,
            long_count,
        });
    }

    let scope = match reason.as_str() {
        "temp" => BlockScope::Temp,
        "long" => BlockScope::Long,
        _ => BlockScope::Temp,
    };

    warn!(
        scope = ?scope,
        retry_after = retry_after,
        short_count,
        long_count,
        reason = %reason,
        "Request blocked by abuse limiter"
    );

    tracing::Span::current().record("decision", "blocked");
    tracing::Span::current().record("short_count", short_count);
    tracing::Span::current().record("long_count", long_count);
    tracing::Span::current().record("retry_after", retry_after);

    hooks.on_blocked(scope, retry_after, short_count, long_count);

    Ok(LimiterDecision::Blocked {
        scope,
        retry_after_secs: retry_after,
        short_count,
        long_count,
    })
}

/// One-shot dedup gate: atomic `SET key 1 EX ttl NX`.
///
/// Returns `true` when the key was newly created (the caller should proceed
/// with the gated work) and `false` when it already existed (short-circuit —
/// the work was already recorded this window).
///
/// **Fail-OPEN**: a store error yields `true`, so a dedup outage cannot 5xx
/// the caller. This is load-bearing for public view-tracking and webhook
/// idempotency (DOS-TRACKVIEW-2). The fail-open contract is baked into the
/// `bool` return type — there is no `Result` to misuse.
pub async fn dedup_nx(store: &dyn RateLimitStore, key: &str, ttl_secs: usize) -> bool {
    const DEDUP: &str = "return redis.call('SET', KEYS[1], '1', 'EX', ARGV[1], 'NX') and 1 or 0";
    let keys = vec![key.to_string()];
    let args: Vec<RedisValue> = vec![RedisValue::from(ttl_secs as i64)];
    match store.eval(DEDUP, keys, args).await {
        Ok(v) => v.first().and_then(to_u64).unwrap_or(0) == 1,
        Err(err) => {
            warn!(error = %err, %key, "dedup check failed (fail-open)");
            true
        }
    }
}

/// Release a dedup claim early (best-effort `DEL`) so a gated operation that
/// failed after claiming can be retried within the window. Silent on a store
/// error (the key simply TTLs out).
pub async fn release_dedup(store: &dyn RateLimitStore, key: &str) {
    const DEL: &str = "return redis.call('DEL', KEYS[1])";
    let keys = vec![key.to_string()];
    if let Err(err) = store.eval(DEL, keys, Vec::<RedisValue>::new()).await {
        warn!(error = %err, %key, "dedup release failed (fail-open)");
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::hooks::NoHooks;
    use crate::store::RateLimitStore;
    use async_trait::async_trait;

    /// Test double: returns a canned reply on every `eval`.
    struct MockStore<F>(F)
    where
        F: Fn() -> Result<Vec<RedisValue>, GateError> + Send + Sync;

    #[async_trait]
    impl<F> RateLimitStore for MockStore<F>
    where
        F: Fn() -> Result<Vec<RedisValue>, GateError> + Send + Sync,
    {
        async fn eval(
            &self,
            _script: &str,
            _keys: Vec<String>,
            _args: Vec<RedisValue>,
        ) -> Result<Vec<RedisValue>, GateError> {
            (self.0)()
        }
    }

    fn canned(vals: Vec<i64>, reason: &str) -> Vec<RedisValue> {
        let mut v: Vec<RedisValue> = vals.into_iter().map(RedisValue::from).collect();
        v.push(RedisValue::from(reason));
        v
    }

    const CFG: AbuseLimiterConfig = AbuseLimiterConfig {
        temp_block_attempts: 3,
        temp_block_range: 60,
        temp_block_duration: 300,
        block_retry_limit: 5,
        block_range: 3600,
        block_duration: 86400,
    };

    #[tokio::test]
    async fn dedup_nx_is_fail_open_on_store_error() {
        // The single most important regression guard: a Redis blip must NOT
        // suppress the gated work (must return true).
        let store = MockStore(|| Err(GateError::StoreUnavailable("boom".into())));
        assert!(dedup_nx(&store, "k", 300).await);
    }

    #[tokio::test]
    async fn dedup_nx_returns_true_when_created() {
        let store = MockStore(|| Ok(vec![RedisValue::from(1i64)]));
        assert!(dedup_nx(&store, "k", 300).await);
    }

    #[tokio::test]
    async fn dedup_nx_returns_false_when_existing() {
        let store = MockStore(|| Ok(vec![RedisValue::from(0i64)]));
        assert!(!dedup_nx(&store, "k", 300).await);
    }

    #[tokio::test]
    async fn release_dedup_is_silent_on_store_error() {
        let store = MockStore(|| Err(GateError::StoreUnavailable("boom".into())));
        // Must not panic and must return ().
        release_dedup(&store, "k").await;
    }

    #[tokio::test]
    async fn check_is_fail_closed_on_store_error() {
        let store = MockStore(|| Err(GateError::StoreUnavailable("boom".into())));
        let r = check(&store, &NoHooks, "k", CFG).await;
        assert!(matches!(r, Err(GateError::StoreUnavailable(_))));
    }

    #[tokio::test]
    async fn check_rejects_unexpected_result_arity() {
        let store = MockStore(|| Ok(vec![RedisValue::from(1i64), RedisValue::from(2i64)])); // 2 != 5
        let r = check(&store, &NoHooks, "k", CFG).await;
        assert!(matches!(r, Err(GateError::UnexpectedResult)));
    }

    #[tokio::test]
    async fn check_parses_allowed() {
        let store = MockStore(move || Ok(canned(vec![1, 0, 2, 3], "none")));
        match check(&store, &NoHooks, "k", CFG).await {
            Ok(LimiterDecision::Allowed { short_count, long_count }) => {
                assert_eq!((short_count, long_count), (2, 3));
            }
            other => panic!("expected Allowed, got {:?}", other),
        }
    }

    #[tokio::test]
    async fn check_parses_blocked_temp() {
        let store = MockStore(move || Ok(canned(vec![0, 60, 5, 9], "temp")));
        match check(&store, &NoHooks, "k", CFG).await {
            Ok(LimiterDecision::Blocked { scope, retry_after_secs, short_count, long_count }) => {
                assert!(matches!(scope, BlockScope::Temp));
                assert_eq!((retry_after_secs, short_count, long_count), (60, 5, 9));
            }
            other => panic!("expected Blocked(Temp), got {:?}", other),
        }
    }

    #[tokio::test]
    async fn check_parses_blocked_long() {
        let store = MockStore(move || Ok(canned(vec![0, 3600, 5, 9], "long")));
        match check(&store, &NoHooks, "k", CFG).await {
            Ok(LimiterDecision::Blocked { scope, retry_after_secs, .. }) => {
                assert!(matches!(scope, BlockScope::Long));
                assert_eq!(retry_after_secs, 3600);
            }
            other => panic!("expected Blocked(Long), got {:?}", other),
        }
    }
}
