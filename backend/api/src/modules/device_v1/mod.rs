pub mod controller;
pub mod validator;

use axum::{middleware, routing::post, Router};

use crate::{middlewares::auth_guard, AppState};

/// Device (FCM registration token) management — all routes require a logged-in,
/// email-verified user.
pub fn routes() -> Router<AppState> {
    Router::<AppState>::new()
        .route("/register", post(controller::register))
        .route("/list", post(controller::list))
        .route("/delete", post(controller::delete))
        .route_layer(middleware::from_fn(auth_guard::verified))
}
