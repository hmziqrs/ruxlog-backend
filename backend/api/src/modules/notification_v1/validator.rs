use serde::{Deserialize, Serialize};
use validator::Validate;

use ruxlog_types::enums::NotificationKind;

/// `POST /notification/v1/list` — paginated inbox read (1-based page).
#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct V1ListNotificationsPayload {
    /// 1-based; 0 / omitted ⇒ 1.
    #[validate(range(min = 0, max = 10_000))]
    pub page: Option<u64>,
    /// Clamped to [1, 100] at the action layer; 0 / omitted ⇒ default (20).
    #[validate(range(min = 0, max = 100))]
    pub per_page: Option<u64>,
}

/// `POST /notification/v1/mark_read` — mark a single OWN notification read.
#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct V1MarkReadPayload {
    #[validate(range(min = 1))]
    pub id: i32,
}

/// `POST /notification/v1/create` (admin) — create + push for an arbitrary user.
#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct V1AdminCreateNotificationPayload {
    #[validate(range(min = 1))]
    pub user_id: i32,
    pub kind: NotificationKind,
    #[validate(length(min = 1, max = 256))]
    pub title: String,
    #[validate(length(min = 1, max = 2048))]
    pub body: String,
    /// Arbitrary JSON payload mirrored to FCM `data` (must be an object to be
    /// forwarded; non-object / omitted is fine and simply omits the `data`
    /// block on the wire).
    pub data: Option<serde_json::Value>,
}
