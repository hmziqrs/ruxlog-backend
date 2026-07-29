use axum::{extract::State, http::StatusCode, response::IntoResponse, Json};
use axum_macros::debug_handler;
use serde_json::json;
use tracing::{info, instrument};

use crate::{
    db::sea_models::notification,
    error::{ErrorCode, ErrorResponse},
    extractors::ValidatedJson,
    services::{auth::AuthSession, notification::NotificationService},
    AppState,
};

use super::validator::{
    V1AdminCreateNotificationPayload, V1ListNotificationsPayload, V1MarkReadPayload,
};

/// Paginated inbox for the current user (newest first).
#[debug_handler]
#[instrument(skip(state, auth), fields(user_id = auth.user.as_ref().map(|u| u.id)))]
pub async fn list(
    state: State<AppState>,
    auth: AuthSession,
    payload: ValidatedJson<V1ListNotificationsPayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let user = auth.user.unwrap(); // safe behind auth_guard::authenticated
    let page = payload.page.unwrap_or(1);
    let per_page = payload.per_page.unwrap_or(notification::Entity::PER_PAGE);
    let result =
        notification::Entity::list_for_user(&state.sea_db, user.id, page, per_page).await?;
    let items = result.data;
    let total = result.total;
    Ok((
        StatusCode::OK,
        Json(json!({
            "notifications": items,
            "total": total,
            "page": page,
            "per_page": per_page,
        })),
    ))
}

/// Unread count for the bell badge.
#[debug_handler]
#[instrument(skip(state, auth), fields(user_id = auth.user.as_ref().map(|u| u.id)))]
pub async fn unread_count(
    state: State<AppState>,
    auth: AuthSession,
) -> Result<impl IntoResponse, ErrorResponse> {
    let user = auth.user.unwrap();
    let count = notification::Entity::unread_count(&state.sea_db, user.id).await?;
    Ok((StatusCode::OK, Json(json!({ "unread": count }))))
}

/// Mark a single OWN notification read.
#[debug_handler]
#[instrument(skip(state, auth, payload), fields(user_id = auth.user.as_ref().map(|u| u.id)))]
pub async fn mark_read(
    state: State<AppState>,
    auth: AuthSession,
    payload: ValidatedJson<V1MarkReadPayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let user = auth.user.unwrap();
    let updated = notification::Entity::mark_read(&state.sea_db, user.id, payload.id).await?;
    if updated.is_none() {
        return Err(ErrorResponse::new(ErrorCode::RecordNotFound)
            .with_message("Notification not found for this user"));
    }
    Ok((StatusCode::OK, Json(json!({ "ok": true }))))
}

/// Mark every unread OWN notification read. Returns the count marked.
#[debug_handler]
#[instrument(skip(state, auth), fields(user_id = auth.user.as_ref().map(|u| u.id)))]
pub async fn mark_all_read(
    state: State<AppState>,
    auth: AuthSession,
) -> Result<impl IntoResponse, ErrorResponse> {
    let user = auth.user.unwrap();
    let marked = notification::Entity::mark_all_read(&state.sea_db, user.id).await?;
    Ok((StatusCode::OK, Json(json!({ "marked": marked }))))
}

/// Admin/internal: create a notification for an arbitrary user and fan it out
/// as push to that user's devices. The in-app row is always inserted; push is
/// best-effort (skipped with a `warn!` when `state.fcm` is `None`, and stale
/// device tokens are pruned when FCM reports `UNREGISTERED`).
#[debug_handler]
#[instrument(skip(state, auth, payload), fields(target_user_id = payload.user_id))]
pub async fn admin_create(
    state: State<AppState>,
    auth: AuthSession,
    payload: ValidatedJson<V1AdminCreateNotificationPayload>,
) -> Result<impl IntoResponse, ErrorResponse> {
    let _admin = auth.user.unwrap(); // safe behind ROLE_ADMIN guard

    // `state.fcm` exists whenever the `notifications` feature is on (this
    // module is gated by that same feature), so no cfg gymnastics needed here.
    let svc = NotificationService::new(state.sea_db.clone(), state.fcm.clone());

    let model = svc
        .create_and_dispatch(
            payload.user_id,
            payload.kind,
            payload.title.clone(),
            payload.body.clone(),
            payload.data.clone(),
        )
        .await?;

    info!(
        notification_id = model.id,
        target_user_id = payload.user_id,
        "Admin created notification"
    );
    Ok((StatusCode::CREATED, Json(json!({ "id": model.id }))))
}
