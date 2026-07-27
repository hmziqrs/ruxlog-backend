use sea_orm::prelude::DateTimeWithTimeZone;
use serde::{Deserialize, Serialize};

/// Input for creating a provider→user link. The caller resolves the local
/// `user_id` (existing account or freshly created) before calling
/// [`super::Entity::link`].
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct NewOauthIdentity {
    pub user_id: i32,
    pub provider: String,
    pub provider_user_id: String,
    pub created_at: DateTimeWithTimeZone,
}
