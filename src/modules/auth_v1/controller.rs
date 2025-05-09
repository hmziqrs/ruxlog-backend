use axum::{
    extract::{State},
    http::StatusCode,
    response::IntoResponse,
    Json,
};
use axum_macros::debug_handler;

use serde_json::json;

use crate::{
    db::sea_models::user,
    error::{ErrorCode, ErrorResponse, },
    extractors::ValidatedJson,
    modules::auth_v1::validator::{V1LoginPayload, V1RegisterPayload},
    services::auth::{AuthSession, Credentials},
    AppState,
};

#[debug_handler]
pub async fn log_out(mut auth: AuthSession) -> Result<impl IntoResponse, ErrorResponse> {
    match auth.logout().await {
        Ok(_) => Ok((StatusCode::OK, Json(json!({"message": "Logged out"})))),
        Err(_) => Err(ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("An error occurred while logging out")),
    }
}

#[debug_handler]
pub async fn log_in(
    _state: State<AppState>,
    mut auth: AuthSession,
    payload: ValidatedJson<V1LoginPayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let user = auth.authenticate(Credentials::Password(payload.0)).await;

    match user {
        Ok(Some(user)) => match auth.login(&user).await {
            Ok(_) => Ok((StatusCode::OK, Json(json!(user)))),
            Err(err) => Err(ErrorResponse::new(ErrorCode::InternalServerError)
                .with_message("An error occurred while logging in")
                .with_details(err.to_string())),
        },
        Ok(None) => Err(ErrorResponse::new(ErrorCode::InvalidCredentials)),
        Err(err) => Err(err.into()),
    }
}

#[debug_handler]
pub async fn register(
    state: State<AppState>,
    payload: ValidatedJson<V1RegisterPayload>, ) -> Result<impl IntoResponse, ErrorResponse> {
    let payload = payload.0;


    match user::Entity::create(&state.sea_db, payload.into_new_user()).await {
        Ok(user) => Ok((StatusCode::CREATED, Json(json!(user)))),
        Err(err) => Err(err.into()),
    }
}
