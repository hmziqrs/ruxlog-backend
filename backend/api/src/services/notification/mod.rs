//! Notification dispatch service.
//!
//! Wraps the "persist an in-app notification row AND fan it out as a push to
//! the recipient's registered devices" flow. The in-app row is the durable
//! source of truth: it is ALWAYS inserted, even when push is disabled
//! (`state.fcm` is `None`) or every device is stale. Push is a best-effort
//! side effect.
//!
//! Other modules that want to emit a notification (e.g. `post_comment_v1` when
//! a comment is added) should call [`notify_user`]. Wiring those callers is
//! intentionally OUT OF SCOPE for the FCM backend unit — the helper is exposed
//! so the integrator can add call sites incrementally.

use std::sync::Arc;

use sea_orm::DatabaseConnection;
use tower_sessions_redis_store::fred::prelude::Pool as RedisPool;

use crate::db::sea_models::{device, notification};
use crate::error::DbResult;
use ruxlog_types::enums::NotificationKind;

/// Stateless-ish helper holding the DB handle and an optional FCM client.
///
/// Constructed per request from `AppState`; the expensive parts (DB pool, FCM
/// client) are `Clone`-cheap. The optional `redis` parameter on the free
/// [`notify_user`] helper is reserved for a future pub/sub broadcast path and
/// is currently unused.
pub struct NotificationService {
    db: DatabaseConnection,
    fcm: Option<Arc<rux_fcm::FcmClient>>,
}

impl NotificationService {
    pub fn new(db: DatabaseConnection, fcm: Option<Arc<rux_fcm::FcmClient>>) -> Self {
        Self { db, fcm }
    }

    /// Insert a notification for `user_id` and fan it out as push to that
    /// user's devices. See [`dispatch`] for the full semantics.
    pub async fn create_and_dispatch(
        &self,
        user_id: i32,
        kind: NotificationKind,
        title: impl Into<String>,
        body: impl Into<String>,
        data: Option<serde_json::Value>,
    ) -> DbResult<notification::Model> {
        dispatch(
            &self.db,
            self.fcm.as_ref(),
            user_id,
            kind,
            title.into(),
            body.into(),
            data,
        )
        .await
    }
}

/// Free helper for cross-module notification dispatch.
///
/// `redis` is accepted (and ignored) so a future pub/sub broadcast can be
/// layered in without changing call sites. Callers that have no `RedisPool`
/// handy may pass `None`.
#[allow(clippy::too_many_arguments)]
pub async fn notify_user(
    db: &DatabaseConnection,
    fcm: Option<&Arc<rux_fcm::FcmClient>>,
    _redis: Option<&RedisPool>,
    user_id: i32,
    kind: NotificationKind,
    title: impl Into<String>,
    body: impl Into<String>,
    data: Option<serde_json::Value>,
) -> DbResult<notification::Model> {
    dispatch(db, fcm, user_id, kind, title.into(), body.into(), data).await
}

/// Shared core: persist the row, then best-effort push.
///
/// Failure modes that do NOT fail the whole call (in-app is already durable):
/// - no FCM client configured ⇒ `warn!` + skip push;
/// - device list load fails ⇒ `warn!` + return the row;
/// - per-device send fails ⇒ `warn!` and continue;
/// - FCM reports `Unregistered` ⇒ prune that device row + continue.
async fn dispatch(
    db: &DatabaseConnection,
    fcm: Option<&Arc<rux_fcm::FcmClient>>,
    user_id: i32,
    kind: NotificationKind,
    title: String,
    body: String,
    data: Option<serde_json::Value>,
) -> DbResult<notification::Model> {
    // 1. Persist the in-app notification (always — this is the durable record).
    let model = notification::Entity::create(
        db,
        notification::NewNotification {
            user_id,
            kind,
            title: title.clone(),
            body: body.clone(),
            data: data.clone(),
        },
    )
    .await?;

    // 2. Best-effort push fan-out.
    let Some(client) = fcm else {
        tracing::warn!(
            user_id,
            notification_id = model.id,
            "FCM client not configured; push skipped (in-app notification persisted)"
        );
        return Ok(model);
    };

    let devices = match device::Entity::list_for_user(db, user_id).await {
        Ok(d) => d,
        Err(err) => {
            tracing::warn!(
                error = %err,
                user_id,
                notification_id = model.id,
                "Failed to load devices for push fan-out; in-app notification persisted"
            );
            return Ok(model);
        }
    };

    if devices.is_empty() {
        return Ok(model);
    }

    // Mirror the structured `data` blob (only when it is a JSON object) into
    // the FCM `data` block.
    let data_map = data.as_ref().and_then(|v| v.as_object()).cloned();

    for dev in devices {
        let msg = rux_fcm::FcmMessage {
            token: dev.token.clone(),
            notification: Some(rux_fcm::Notification {
                title: Some(title.clone()),
                body: Some(body.clone()),
            }),
            data: data_map.clone(),
            android: None,
            webpush: None,
        };
        match client.send(msg).await {
            Ok(name) => {
                tracing::debug!(
                    device_id = dev.id,
                    fcm_name = %name,
                    "FCM delivered"
                );
            }
            Err(rux_fcm::FcmError::Unregistered) => {
                tracing::info!(
                    device_id = dev.id,
                    "FCM token unregistered; pruning stale device"
                );
                if let Err(err) = device::Entity::prune_by_id(db, dev.id).await {
                    tracing::warn!(
                        error = %err,
                        device_id = dev.id,
                        "Failed to prune unregistered device"
                    );
                }
            }
            Err(err) => {
                tracing::warn!(
                    error = %err,
                    device_id = dev.id,
                    "FCM send failed; device left in place"
                );
            }
        }
    }

    Ok(model)
}
