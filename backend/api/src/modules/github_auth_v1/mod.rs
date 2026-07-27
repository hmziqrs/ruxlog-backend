pub mod controller;
pub mod service;
pub mod validator;

use axum::{
    routing::{get, post},
    Router,
};

use crate::AppState;

/// GitHub Sign-In routes, mounted at `/auth/github/v1`. Mirrors `google_auth_v1`:
/// `GET /login`, `GET /callback`, `POST /exchange`, `GET /user`.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(controller::github_login))
        .route("/callback", get(controller::github_callback))
        .route("/exchange", post(controller::github_exchange))
        .route("/user", get(controller::github_user_info))
}
