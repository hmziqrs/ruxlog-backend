pub mod controller;
pub mod service;
pub mod validator;

use axum::{
    routing::{get, post},
    Router,
};

use crate::AppState;

/// Facebook Sign-In routes, mounted at `/auth/facebook/v1`.
///
/// All three entry points mirror `google_auth_v1`:
/// - `GET /login`     → redirect to Facebook's authorize URL (server-side flow).
/// - `GET /callback`  → Facebook redirects here with `?code=...&state=...`.
/// - `POST /exchange` → client-side flow: the SPA posts the code+state it
///   received and we exchange/verify/server-session in one JSON round-trip.
/// - `GET /user`      → the authenticated user's profile (handy for the SPA).
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(controller::facebook_login))
        .route("/callback", get(controller::facebook_callback))
        .route("/exchange", post(controller::facebook_exchange))
        .route("/user", get(controller::facebook_user_info))
}
