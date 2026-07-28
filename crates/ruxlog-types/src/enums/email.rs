use serde::{Deserialize, Serialize};

/// Why a recipient is on the email suppression (blacklist) list.
///
/// - `Bounce` — delivery permanently (or, within the soft cooldown, transiently)
///   failed. Populated from Cloudflare's synchronous `permanent_bounces` or an
///   inbound bounce webhook event.
/// - `Complaint` — the recipient flagged the message as spam (Feedback Loop).
///   Always treated as permanent.
/// - `Manual` — an administrator added the address by hand via the suppression
///   admin API.
#[cfg_attr(
    feature = "backend",
    derive(sea_orm::DeriveActiveEnum, strum::EnumIter)
)]
#[cfg_attr(feature = "backend", sea_orm(rs_type = "String", db_type = "Text"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum SuppressionReason {
    #[serde(rename = "bounce")]
    #[cfg_attr(feature = "backend", sea_orm(string_value = "bounce"))]
    Bounce,
    #[serde(rename = "complaint")]
    #[cfg_attr(feature = "backend", sea_orm(string_value = "complaint"))]
    Complaint,
    #[serde(rename = "manual")]
    #[cfg_attr(feature = "backend", sea_orm(string_value = "manual"))]
    Manual,
}
