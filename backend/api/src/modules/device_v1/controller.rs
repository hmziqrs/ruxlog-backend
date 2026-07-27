use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_macros::debug_handler;
use serde_json::json;
use tracing::instrument;

use crate::{
    db::sea_models::device,
    error::{ErrorCode, ErrorResponse},
    extractors::ValidatedJson,
    services::auth::AuthSession,
    AppState,
};

use super::validator::{V1DeleteDevicePayload, V1RegisterDevicePayload};

/// Register (or refresh) a push token for the current user. Idempotent: the
/// `(user_id, token)` unique constraint makes a re-register an upsert.
#[debug_handler]
#[instrument(skip(state, auth, payload), fields(user_id = auth.user.as_ref().map(|u| u.id)))]
pub async fn register(
    state: State<AppState>,
    auth: AuthSession,
    payload: ValidatedJson<V1RegisterDevicePayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let user = auth.user.unwrap(); // safe behind auth_guard::verified
    let model = device::Entity::upsert(
        &state.sea_db,
        device::NewDevice {
            user_id: user.id,
            token: payload.token.clone(),
            platform: payload.platform.clone(),
        },
    )
    .await?;

    Ok((StatusCode::OK, Json(json!({ "id": model.id }))))
}

/// List the current user's registered devices (newest first).
#[debug_handler]
#[instrument(skip(state, auth), fields(user_id = auth.user.as_ref().map(|u| u.id)))]
pub async fn list(
    state: State<AppState>,
    auth: AuthSession,
) -> Result<impl IntoResponse, ErrorResponse> {
    let user = auth.user.unwrap();
    let devices = device::Entity::list_for_user(&state.sea_db, user.id).await?;
    Ok((StatusCode::OK, Json(json!({ "devices": devices }))))
}

/// Unregister a push token for the current user.
#[debug_handler]
#[instrument(skip(state, auth, payload), fields(user_id = auth.user.as_ref().map(|u| u.id)))]
pub async fn delete(
    state: State<AppState>,
    auth: AuthSession,
    payload: ValidatedJson<V1DeleteDevicePayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let user = auth.user.unwrap();
    let removed = device::Entity::delete_for_user(&state.sea_db, user.id, &payload.token).await?;
    if removed == 0 {
        return Err(ErrorResponse::new(ErrorCode::RecordNotFound)
            .with_message("No device found for this token"));
    }
    Ok((StatusCode::OK, Json(json!({ "removed": removed }))))
}
