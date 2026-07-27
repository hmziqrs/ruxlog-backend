use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_macros::debug_handler;
use serde_json::json;
use tracing::instrument;

use crate::{
    error::{ErrorCode, ErrorResponse},
    extractors::ValidatedJson,
    services::{auth::AuthSession, cache},
    AppState,
};

use super::validator::V1CachePostInvalidatePayload;

/// `POST /cache/v1/post/invalidate` — drop cached post-view entries (issue #10
/// "post cache CRUD"). `post_id` in the body targets a single id-keyed entry;
/// omitting it wipes the whole `post:view:*` prefix.
#[debug_handler]
#[instrument(skip(state, auth), fields(user_id = auth.user.as_ref().map(|u| u.id)))]
pub async fn invalidate_post(
    State(state): State<AppState>,
    auth: AuthSession,
    payload: ValidatedJson<V1CachePostInvalidatePayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    // `auth` is only used for the tracing field; the ROLE_ADMIN tier is enforced
    // by the `route_layer` on the sub-router, so no further check is needed.
    let _ = auth;

    match payload.post_id {
        Some(id) => {
            let key = cache::CacheKey::post_view(&id.to_string());
            cache::invalidate(&state.redis_pool, &key)
                .await
                .map_err(|e| {
                    ErrorResponse::new(ErrorCode::InternalServerError)
                        .with_message("Failed to invalidate post cache")
                        .with_details(e.to_string())
                })?;
            Ok((
                StatusCode::OK,
                Json(json!({
                    "invalidated": "single",
                    "post_id": id,
                    "key": key,
                })),
            ))
        }
        None => {
            let removed = cache::invalidate_pattern(
                &state.redis_pool,
                &format!("{}*", cache::POST_VIEW_PREFIX),
            )
            .await
            .map_err(|e| {
                ErrorResponse::new(ErrorCode::InternalServerError)
                    .with_message("Failed to invalidate post cache")
                    .with_details(e.to_string())
            })?;
            Ok((
                StatusCode::OK,
                Json(json!({
                    "invalidated": "all",
                    "keys_removed": removed,
                    "prefix": cache::POST_VIEW_PREFIX,
                })),
            ))
        }
    }
}

/// `POST /cache/v1/post/stats` — inspect the post-view cache (issue #10 "post
/// cache CRUD"). Returns the number of cached post-view keys under the
/// `post:view:*` prefix. Read-only; safe to call frequently.
#[debug_handler]
#[instrument(skip(state, auth), fields(user_id = auth.user.as_ref().map(|u| u.id)))]
pub async fn post_stats(
    State(state): State<AppState>,
    auth: AuthSession,
) -> Result<impl IntoResponse, ErrorResponse> {
    let _ = auth;

    let pattern = format!("{}*", cache::POST_VIEW_PREFIX);
    let count = cache::count_pattern(&state.redis_pool, &pattern)
        .await
        .map_err(|e| {
            ErrorResponse::new(ErrorCode::InternalServerError)
                .with_message("Failed to read post cache stats")
                .with_details(e.to_string())
        })?;
    Ok((
        StatusCode::OK,
        Json(json!({
            "post_cache_keys": count,
            "prefix": cache::POST_VIEW_PREFIX,
        })),
    ))
}
