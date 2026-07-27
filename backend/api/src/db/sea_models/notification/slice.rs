use sea_orm::prelude::DateTimeWithTimeZone;
use serde::{Deserialize, Serialize};

use super::NotificationKind;

/// Insert DTO for a new notification.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewNotification {
    pub user_id: i32,
    pub kind: NotificationKind,
    pub title: String,
    pub body: String,
    pub data: Option<serde_json::Value>,
}

/// Lightweight notification list item (the `user_id` is implicit — rows are
/// always scoped to the requesting user at the controller layer).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NotificationListItem {
    pub id: i32,
    pub kind: NotificationKind,
    pub title: String,
    pub body: String,
    pub data: Option<serde_json::Value>,
    pub read_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
}
