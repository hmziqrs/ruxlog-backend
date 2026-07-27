pub mod controller;
pub mod validator;

use axum::{middleware, routing::post, Router};

use crate::{middlewares::auth_guard, AppState};

/// In-app notification inbox + admin/internal create-and-dispatch.
pub fn routes() -> Router<AppState> {
    // Admin / internal: create a notification for an arbitrary user (and fan
    // out push when FCM is configured).
    let admin = Router::<AppState>::new()
        .route("/create", post(controller::admin_create))
        .route_layer(middleware::from_fn(
            auth_guard::verified_with_role::<{ auth_guard::ROLE_ADMIN }>,
        ));

    // Authenticated (any logged-in user): read + mark-read on OWN inbox only.
    let authenticated = Router::<AppState>::new()
        .route("/list", post(controller::list))
        .route("/unread_count", post(controller::unread_count))
        .route("/mark_read", post(controller::mark_read))
        .route("/mark_all_read", post(controller::mark_all_read))
        .route_layer(middleware::from_fn(auth_guard::authenticated));

    admin.merge(authenticated)
}
