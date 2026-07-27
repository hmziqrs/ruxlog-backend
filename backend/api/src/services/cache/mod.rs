//! Generic redis-backed cache over the shared fred `redis_pool` (issues #5 + #10).
//!
//! Provides read-through primitives (`get` / `set` / `invalidate` /
//! `invalidate_pattern` / `count_pattern`), a namespaced [`CacheKey`] builder,
//! and post-view convenience wrappers used by the entity layer.
//!
//! # Fail-open contract
//! Every helper surfaces redis errors to the caller, but **read-path callers
//! MUST treat a cache miss/error as "proceed to the source of truth"** and only
//! log. A redis blip must never turn into a user-visible error on a read path —
//! caching is a pure optimization.
//!
//! # Process-global pool
//! The SeaORM entity layer (`post::Entity::find_by_id_or_slug`) does NOT hold an
//! [`AppState`](crate::AppState) and therefore cannot reach `state.redis_pool`.
//! Rather than thread a pool argument through every entity method (and every
//! controller call site — issue #10 asks to edit only `post/actions.rs`), we
//! install the pool ONCE at startup into a process-global slot and read it via
//! [`global_pool`]. This mirrors the existing `LazyLock`-based in-process JWKS
//! cache pattern in `google_auth_v1::service` and keeps the post entity's public
//! signature unchanged.
//!
//! # Feature gate
//! The whole module is feature-gated behind `cache` (OFF in `basic`, ON in
//! `full`). When the feature is off the code is not compiled, so a default
//! `cargo build` is completely unaffected — no new redis traffic, no behavior
//! change.

use std::sync::OnceLock;

use serde::{de::DeserializeOwned, Serialize};
use tower_sessions_redis_store::fred::{
    interfaces::{ClientLike, KeysInterface},
    prelude::Pool as RedisPool,
    types::{ClusterHash, CustomCommand, Expiration},
};

/// Default TTL (seconds) for a cached single-post view response (#10). Short on
/// purpose: posts change rarely but view counters/paywall state are per-request,
/// so a minute-long TTL bounds staleness after an edit even if an explicit
/// invalidate were ever missed.
pub const POST_VIEW_TTL_SECS: u64 = 60;

/// Default TTL (seconds) for a cached 3rd-party API response (#5). OIDC JWKS
/// rotate ~daily and billing plan catalogs are near-static; 30 minutes balances
/// freshness against hammering the upstream on every request.
pub const API_TTL_SECS: u64 = 1800;

/// Namespace prefix for the single-post view cache. `find_by_id_or_slug` stores
/// under `{prefix}{id_or_slug}` so both id- and slug-keyed lookups share one
/// space; `delete` (where the slug is unknown) and the admin "invalidate all"
/// endpoint wipe the whole prefix. Writes/deletes are rare on a blog, so a
/// prefix wipe is cheap and avoids serving a stale slug entry.
pub const POST_VIEW_PREFIX: &str = "post:view:";

// ─────────────────────────────────────────────────────────────────────────
// Process-global pool handle
// ─────────────────────────────────────────────────────────────────────────
static GLOBAL_POOL: OnceLock<RedisPool> = OnceLock::new();

/// Install the shared redis pool into the process-global cache slot. Called
/// ONCE from `main.rs` (manifest `main_init`) after the pool connects.
/// Idempotent: a second call is a no-op — the first pool wins, which is correct
/// since every caller passes a clone of the same pool.
pub fn install_pool(pool: RedisPool) {
    let _ = GLOBAL_POOL.set(pool);
}

/// Borrow the process-global cache pool, if installed. Returns `None` before
/// [`install_pool`] has run or in non-HTTP consumers (e.g. the TUI) that never
/// install it — callers MUST treat `None` as "caching unavailable, bypass".
pub fn global_pool() -> Option<&'static RedisPool> {
    GLOBAL_POOL.get()
}

// ─────────────────────────────────────────────────────────────────────────
// CacheKey builder
// ─────────────────────────────────────────────────────────────────────────

/// Namespaced cache-key builder. Centralizing key construction prevents ad-hoc
/// string formatting from drifting between the writer (entity layer / api_cache)
/// and the reader/invalidator (admin CRUD, update/delete).
pub struct CacheKey;
impl CacheKey {
    /// Single-post view cache: `post:view:{id_or_slug}`.
    pub fn post_view(id_or_slug: &str) -> String {
        format!("{POST_VIEW_PREFIX}{id_or_slug}")
    }

    /// Generic 3rd-party API response cache: `api:3p:{namespace}:{hash}`.
    /// `hash` is caller-defined (e.g. the URL or a hash of the request params).
    pub fn api_3p(namespace: &str, hash: &str) -> String {
        format!("api:3p:{namespace}:{hash}")
    }

    /// JWK set cache for an OIDC provider: `api:jwks:{provider}`.
    pub fn jwks(provider: &str) -> String {
        format!("api:jwks:{provider}")
    }
}

// ─────────────────────────────────────────────────────────────────────────
// Primitives — all take the pool explicitly so they are reusable both from
// handlers (which have `state.redis_pool`) and from the entity layer (which
// uses `global_pool()`). Errors propagate as `Box<dyn Error + Send + Sync>`,
// matching the existing `app_constant::Entity::sync_all_to_redis` pattern.
// ─────────────────────────────────────────────────────────────────────────

/// Read a cached value. `Ok(None)` = miss. Redis/deser errors propagate so the
/// caller can decide; read-path callers should log-and-treat-as-miss.
pub async fn get<T: DeserializeOwned>(
    pool: &RedisPool,
    key: &str,
) -> Result<Option<T>, Box<dyn std::error::Error + Send + Sync>> {
    let raw: Option<String> = pool.get(key).await?;
    match raw {
        Some(s) => {
            let value = serde_json::from_str::<T>(&s)?;
            Ok(Some(value))
        }
        None => Ok(None),
    }
}

/// Write a value with a TTL (seconds). Errors propagate; read-path callers
/// should ignore them (best-effort populate).
pub async fn set<T: Serialize>(
    pool: &RedisPool,
    key: &str,
    value: &T,
    ttl_secs: u64,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    let serialized = serde_json::to_string(value)?;
    pool.set::<(), _, _>(
        key,
        serialized,
        Some(Expiration::EX(ttl_secs as i64)),
        None,
        false,
    )
    .await?;
    Ok(())
}

/// Delete a single key. `Ok(())` regardless of whether the key existed.
pub async fn invalidate(
    pool: &RedisPool,
    key: &str,
) -> Result<(), Box<dyn std::error::Error + Send + Sync>> {
    pool.del::<(), _>(key).await?;
    Ok(())
}

/// Run `KEYS <pattern>` and collect the matching key names.
///
/// fred 10.1 exposes no `keys()` method on `Pool`; the custom-command escape
/// hatch (`ClientLike::custom`) is the supported way to run it. `KEYS` is O(N)
/// but the cache namespaces here are bounded (≈ # of posts / upstream
/// endpoints), so this is acceptable on the rare admin / write path — see the
/// note on [`invalidate_pattern`].
async fn keys_matching(
    pool: &RedisPool,
    pattern: &str,
) -> Result<Vec<String>, Box<dyn std::error::Error + Send + Sync>> {
    // `ClusterHash::FirstKey` is fred's default hashing policy; it is irrelevant
    // for this stack's centralized (non-cluster) deployment but required by the
    // `CustomCommand` constructor.
    let cmd = CustomCommand::new_static("KEYS", ClusterHash::FirstKey, false);
    let keys: Vec<String> = pool
        .custom::<Vec<String>, _>(cmd, vec![pattern.to_string()])
        .await?;
    Ok(keys)
}

/// Delete every key matching a `KEYS`-style glob pattern (e.g. `"post:view:*"`).
/// Returns the number of keys deleted. Uses `KEYS` — acceptable here because
/// cache namespaces are bounded (≈ # of posts / # of upstream endpoints) and
/// this is an admin / rare-write path; for an unbounded namespace a SCAN-based
/// variant would be preferable (noted as a follow-up).
pub async fn invalidate_pattern(
    pool: &RedisPool,
    pattern: &str,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let keys = keys_matching(pool, pattern).await?;
    let mut removed: u64 = 0;
    for key in keys {
        // `del::<(), _>(&str)` mirrors the proven pattern in
        // `app_constant::Entity::sync_all_to_redis`.
        pool.del::<(), _>(key.as_str()).await?;
        removed += 1;
    }
    Ok(removed)
}

/// Count the keys matching a glob pattern (admin stats / inspect). Uses `KEYS`.
pub async fn count_pattern(
    pool: &RedisPool,
    pattern: &str,
) -> Result<u64, Box<dyn std::error::Error + Send + Sync>> {
    let keys = keys_matching(pool, pattern).await?;
    Ok(keys.len() as u64)
}

// ─────────────────────────────────────────────────────────────────────────
// Post-view cache convenience wrappers (used by `post::Entity` + admin CRUD)
// ─────────────────────────────────────────────────────────────────────────

/// Invalidate a single post's id-keyed view cache (`post:view:{id}`). Best
/// effort: logs and ignores redis errors so a redis blip cannot break an
/// update/delete. NB: a slug-keyed entry for the same post is NOT dropped here
/// (the slug is not always known at the call site); it expires via the 60s TTL,
/// or an operator can wipe the whole prefix via [`invalidate_post_view_all`].
pub async fn invalidate_post_view_id(id: i32) {
    if let Some(pool) = global_pool() {
        let key = CacheKey::post_view(&id.to_string());
        if let Err(e) = invalidate(pool, &key).await {
            tracing::warn!(error = %e, %key, "post cache invalidate failed (non-fatal)");
        }
    }
}

/// Invalidate EVERY cached post view (`post:view:*`). Returns the number of
/// keys removed. Used on post `delete` (the slug is unknown there) and by the
/// admin "invalidate all" endpoint. Best-effort: on a redis error logs and
/// returns `0`.
pub async fn invalidate_post_view_all() -> u64 {
    if let Some(pool) = global_pool() {
        match invalidate_pattern(pool, &format!("{POST_VIEW_PREFIX}*")).await {
            Ok(n) => return n,
            Err(e) => tracing::warn!(error = %e, "post cache prefix invalidate failed (non-fatal)"),
        }
    }
    0
}
