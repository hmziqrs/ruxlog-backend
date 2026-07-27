pub mod controller;
pub mod validator;

use axum::{middleware, routing::post, Router};

use crate::{middlewares::auth_guard, AppState};

pub fn routes() -> Router<AppState> {
    // Self-service OTP flow: a logged-in, still-unverified user verifies their
    // email or requests a fresh code. Stays behind `unverified`.
    let base = Router::<AppState>::new()
        .route("/verify", post(controller::verify))
        .route("/resend", post(controller::resend))
        .route_layer(middleware::from_fn(auth_guard::unverified));

    // Admin CRUD (issue #42): list / delete / force-issue a verification code.
    // The whole module is already feature-gated under `user-management` (see
    // `modules/mod.rs` + the `/email_verification/v1` router nest), so these
    // routes only exist when that feature is on — no per-route cfg needed.
    // `verified_with_role::<ROLE_ADMIN>` enforces the admin tier on top of a
    // fully-verified session.
    let admin = Router::<AppState>::new()
        .route("/admin/list", post(controller::admin_list))
        .route("/admin/delete", post(controller::admin_delete))
        .route("/admin/issue_code", post(controller::admin_issue_code))
        .route_layer(middleware::from_fn(
            auth_guard::verified_with_role::<{ auth_guard::ROLE_ADMIN }>,
        ));

    base.merge(admin)
}
