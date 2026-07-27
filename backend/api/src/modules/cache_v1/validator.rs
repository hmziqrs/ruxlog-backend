use serde::{Deserialize, Serialize};
use validator::Validate;

/// Admin post-cache invalidation request (issue #10 "post cache CRUD").
///
/// - `post_id` omitted / `None` → invalidate the ENTIRE post-view cache
///   (`post:view:*`). Use after a bulk import / a DB-level edit that bypassed
///   the entity layer's targeted invalidation.
/// - `post_id` `Some(id)`     → invalidate just that post's id-keyed entry
///   (`post:view:{id}`). Slug-keyed entries for the same post expire via the
///   60s TTL; for an immediate full wipe, omit `post_id`.
#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct V1CachePostInvalidatePayload {
    #[serde(default)]
    pub post_id: Option<i32>,
}
