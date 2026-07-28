use sea_orm::prelude::DateTimeWithTimeZone;
use sea_orm::FromQueryResult;
use serde::{Deserialize, Serialize};

use super::SuppressionReason;

/// Insert payload for a manual admin blacklist add.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewSuppression {
    pub recipient: String,
    pub reason: SuppressionReason,
    pub source: Option<String>,
    pub diagnostic: Option<String>,
    pub permanent: bool,
}

/// Upsert payload used by the bounce/complaint paths and the sync-bounce
/// feedback loop. `permanent` is sticky: once a recipient is permanently
/// suppressed (complaint / hard bounce) it is never downgraded.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct SuppressionUpsert {
    pub reason: SuppressionReason,
    pub source: Option<String>,
    pub diagnostic: Option<String>,
    pub permanent: bool,
}

/// Filter + pagination for admin suppression listings.
#[derive(Clone, Debug, Serialize, Deserialize, Default)]
pub struct SuppressionQuery {
    #[serde(default)]
    pub page: Option<u64>,
    pub reason: Option<SuppressionReason>,
    pub permanent: Option<bool>,
    pub search: Option<String>,
}

/// Lightweight suppression row for admin listings.
#[derive(Clone, Debug, Serialize, Deserialize, FromQueryResult)]
pub struct SuppressionListItem {
    pub id: i32,
    pub recipient: String,
    pub reason: SuppressionReason,
    pub permanent: bool,
    pub source: Option<String>,
    pub last_seen: DateTimeWithTimeZone,
    pub created_at: DateTimeWithTimeZone,
}
