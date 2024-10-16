use axum::{
    extract::State,
    http::StatusCode,
    middleware,
    response::{IntoResponse, Json},
    routing::{self, get, post, put},
    Router,
};
use axum_login::login_required;
use serde_json::json;
use tower_http::trace::TraceLayer;

use crate::middlewares::user_status;
use crate::{modules::email_verification_v1, services::auth::AuthBackend};

use super::{
    modules::{auth_v1, user_v1},
    AppState,
};

pub fn router() -> Router<AppState> {
    let auth_v1_routes = Router::new()
        .route("/register", post(auth_v1::controller::register))
        .route("/log_out", post(auth_v1::controller::log_out))
        .route("/log_in", post(auth_v1::controller::log_in));

    let user_v1_routes = Router::new()
        .route("/update", put(user_v1::controller::update_profile))
        .route_layer(middleware::from_fn(user_status::only_verified))
        .route("/get", get(user_v1::controller::get_profile))
        .route_layer(login_required!(AuthBackend));

    // let csrf_v1_routes: Router<AppState> =
    //     Router::new()
    //     .route("/check", post(csrf_v1::controller::check_key))
    //     .route_layer(login_required!(AuthBackend))
    //     .route("/get", post(csrf_v1::controller::get_key));

    let email_verification_v1_routes = Router::new()
        .route("/verify", post(email_verification_v1::controller::verify))
        .route("/resend", post(email_verification_v1::controller::verify))
        .route_layer(middleware::from_fn(user_status::only_unverified))
        .route_layer(login_required!(AuthBackend));

    Router::new()
        .route("/", routing::get(handler))
        .nest("/auth/v1", auth_v1_routes)
        .nest("/user/v1", user_v1_routes)
        .nest("/email_verification/v1", email_verification_v1_routes)
        // .nest("/csrf/v1", csrf_v1_routes)
        .layer(TraceLayer::new_for_http())
}

async fn handler(s: State<AppState>) -> impl IntoResponse {
    println!("{:?}", s.db_pool.status());
    (StatusCode::OK, Json(json!({"message": "success"})))
}
