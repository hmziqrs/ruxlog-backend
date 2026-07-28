use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

pub use ruxlog_types::enums::SuppressionReason;

/// One row per recipient on the email suppression (blacklist) list.
///
/// Enforced by [`crate::services::mail::router::MailRouter`] before any send:
/// a `permanent` row, or a non-permanent `bounce` row whose `last_seen` is
/// within the soft-bounce cooldown, short-circuits delivery. Populated from
/// Cloudflare's synchronous `permanent_bounces`, the inbound bounce/complaint
/// webhook, or the admin suppression API.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "email_suppression")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    /// Canonicalized recipient address (trim + lowercase), unique.
    pub recipient: String,
    pub reason: SuppressionReason,
    /// Origin of the entry (e.g. `cf-send-sync`, `cf-webhook`, `admin`).
    pub source: Option<String>,
    /// Provider diagnostic (SMTP reply / CF error) — server-side only, never
    /// surfaced to clients (PII / echo risk).
    pub diagnostic: Option<String>,
    /// Hard bounce / complaint → permanent suppression. Soft bounces are
    /// `false` and time-bounded via `last_seen`.
    pub permanent: bool,
    pub last_seen: DateTimeWithTimeZone,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {}

impl ActiveModelBehavior for ActiveModel {}
