use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_macros::debug_handler;
use axum_valid::Valid;
use serde_json::json;

use crate::{
    db::models::user::User,
    modules::auth_v1::validator::{V1LoginPayload, V1RegisterPayload},
    services::auth::{AuthSession, Credentials},
    AppState,
};

#[debug_handler]
pub async fn log_out(mut auth: AuthSession) -> impl IntoResponse {
    match auth.logout().await {
        Ok(_) => (StatusCode::OK, Json(json!({"message": "Logged out"}))),
        Err(_) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({"message": "An error occurred while logging out"})),
        ),
    }
}

#[debug_handler]
pub async fn log_in(
    _state: State<AppState>,
    mut auth: AuthSession,
    payload: Valid<Json<V1LoginPayload>>,
) -> impl IntoResponse {
    let payload = payload.into_inner().0;
    let user = auth.authenticate(Credentials::Password(payload)).await;

    match user {
        Ok(Some(user)) => match auth.login(&user).await {
            Ok(_) => (StatusCode::OK, Json(json!(user))),
            Err(err) => (
                StatusCode::INTERNAL_SERVER_ERROR,
                Json(json!({
                    "error": err.to_string(),
                    "message": "An error occurred while logging in",
                })),
            ),
        },
        Ok(None) => (
            StatusCode::NOT_FOUND,
            Json(json!({
                "error": "User not found",
                "message": "No user with this email exists",
            })),
        ),
        Err(err) => (
            StatusCode::INTERNAL_SERVER_ERROR,
            Json(json!({
                "error": err.to_string(),
                "message": "An error occurred while fetching the user",
            })),
        ),
    }
    .into_response()
}

#[debug_handler]
pub async fn register(
    state: State<AppState>,
    payload: Valid<Json<V1RegisterPayload>>,
) -> impl IntoResponse {
    let payload = payload.into_inner().0.into_new_user();

    match User::create(&state.db_pool, payload).await {
        Ok(user) => (StatusCode::CREATED, Json(json!(user))),
        Err(err) => (
            StatusCode::CONFLICT,
            Json(json!({
                "error": err.to_string(),
                "message": "Failed to create user",
            })),
        ),
    }
}
