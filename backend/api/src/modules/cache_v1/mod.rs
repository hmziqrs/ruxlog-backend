pub mod controller;
pub mod validator;

use axum::{middleware, routing::post, Router};

use crate::{middlewares::auth_guard, AppState};

/// Issue #10 "post cache CRUD" — admin-only inspect + invalidate over the redis
/// post-view cache populated by `post::Entity::find_by_id_or_slug`.
///
/// The whole module is feature-gated under `cache` (see `modules/mod.rs` + the
/// `/cache/v1` router nest), so every route here exists only when caching is
/// compiled in. All routes are behind `verified_with_role::<ROLE_ADMIN>` so only
/// staff can wipe / inspect the cache.
pub fn routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/post/invalidate", post(controller::invalidate_post))
        .route("/post/stats", post(controller::post_stats))
        .route_layer(middleware::from_fn(
            auth_guard::verified_with_role::<{ auth_guard::ROLE_ADMIN }>,
        ))
}
