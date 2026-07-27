pub mod controller;
pub mod service;
pub mod validator;

use axum::{
    routing::{get, post},
    Router,
};

use crate::AppState;

/// Sign-in-with-Apple routes, mounted at `/auth/apple/v1`. Mirrors
/// `google_auth_v1`: `GET /login`, `GET /callback`, `POST /exchange`, `GET /user`.
///
/// Apple's id_token (OIDC) carries the user identity, so this flow follows the
/// Google pattern most closely: authorize → exchange code → verify the signed
/// id_token against Apple's JWKS → resolve/link/create the user.
pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/login", get(controller::apple_login))
        .route("/callback", get(controller::apple_callback))
        .route("/exchange", post(controller::apple_exchange))
        .route("/user", get(controller::apple_user_info))
}
