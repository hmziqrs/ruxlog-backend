//! Mail routes: inbound bounce/complaint webhook + admin suppression CRUD.
//!
//! The admin suppression API is **always-on** (the `email_suppression` table is
//! always-on, and SMTP-only deployments must be able to clear stale rows). The
//! webhook receiver body is gated by `mail-cloudflare` inside the handler; the
//! route itself is always registered so the path is stable.

pub mod controller;
pub mod validator;

use axum::{
    extract::DefaultBodyLimit,
    middleware,
    routing::{get, post},
    Router,
};

use crate::{config, middlewares::auth_guard, AppState};

pub fn routes() -> Router<AppState> {
    let admin = Router::<AppState>::new()
        .route(
            "/suppression",
            get(controller::list_suppressions)
                .post(controller::create_suppression)
                .delete(controller::delete_suppression),
        )
        .route_layer(middleware::from_fn(
            auth_guard::verified_with_role::<{ auth_guard::ROLE_ADMIN }>,
        ));

    let public = Router::<AppState>::new()
        // Inbound bounce/complaint/delivery webhook (CSRF-exempt; verified by
        // an operator-owned HMAC secret inside the handler).
        .route(
            "/webhook/{provider}",
            post(controller::mail_webhook_receiver),
        );

    admin
        .merge(public)
        // Cap body size: the public webhook is the key unbounded-body surface.
        .layer(DefaultBodyLimit::max(config::body_limits::DEFAULT))
}
