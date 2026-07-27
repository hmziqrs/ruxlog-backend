use sea_orm::prelude::DateTimeWithTimeZone;
use serde::{Deserialize, Serialize};

/// Insert/upsert DTO for a device registration.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewDevice {
    pub user_id: i32,
    pub token: String,
    pub platform: String,
}

/// Lightweight device list item (excludes `user_id`; rows are always scoped to
/// the requesting user at the controller layer).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct DeviceListItem {
    pub id: i32,
    pub platform: String,
    pub token: String,
    pub created_at: DateTimeWithTimeZone,
    pub last_seen_at: DateTimeWithTimeZone,
}
