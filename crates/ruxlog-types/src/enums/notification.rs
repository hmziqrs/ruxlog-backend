use serde::{Deserialize, Serialize};

/// Kind/category of an in-app + push notification. Stored as `TEXT` on the
/// `notifications` table (migration 000054); the string values are stable
/// (never rename a `string_value` once shipped — existing rows depend on it).
#[cfg_attr(
    feature = "backend",
    derive(sea_orm::DeriveActiveEnum, strum::EnumIter)
)]
#[cfg_attr(feature = "backend", sea_orm(rs_type = "String", db_type = "Text"))]
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash, Serialize, Deserialize)]
pub enum NotificationKind {
    #[serde(rename = "NewComment")]
    #[cfg_attr(feature = "backend", sea_orm(string_value = "new_comment"))]
    NewComment,

    #[serde(rename = "NewFollower")]
    #[cfg_attr(feature = "backend", sea_orm(string_value = "new_follower"))]
    NewFollower,

    #[serde(rename = "PaymentReceived")]
    #[cfg_attr(feature = "backend", sea_orm(string_value = "payment_received"))]
    PaymentReceived,

    #[serde(rename = "PostPublished")]
    #[cfg_attr(feature = "backend", sea_orm(string_value = "post_published"))]
    PostPublished,

    #[serde(rename = "Mention")]
    #[cfg_attr(feature = "backend", sea_orm(string_value = "mention"))]
    Mention,

    #[serde(rename = "System")]
    #[cfg_attr(feature = "backend", sea_orm(string_value = "system"))]
    System,
}
