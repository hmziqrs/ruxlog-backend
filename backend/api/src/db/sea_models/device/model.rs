use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A registered push target: one FCM/registration token belonging to a user.
/// `(user_id, token)` is unique (see migration 000053); re-registering the same
/// token for a user upserts in place rather than duplicating.
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "devices")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub user_id: i32,
    /// FCM registration token (web/apns/android). Free-form text; size bounded
    /// at the validator layer.
    pub token: String,
    /// Coarse client platform hint, e.g. "web" / "android" / "ios". Stored for
    /// diagnostics + future per-platform targeting.
    pub platform: String,
    pub created_at: DateTimeWithTimeZone,
    pub updated_at: DateTimeWithTimeZone,
    /// Bumped on every upsert/send so stale-but-still-valid tokens can be aged
    /// out by inactivity.
    pub last_seen_at: DateTimeWithTimeZone,
}

#[derive(Copy, Clone, Debug, EnumIter, DeriveRelation)]
pub enum Relation {
    #[sea_orm(
        belongs_to = "super::super::user::Entity",
        from = "Column::UserId",
        to = "super::super::user::Column::Id"
    )]
    User,
}

impl Related<super::super::user::Entity> for Entity {
    fn to() -> RelationDef {
        Relation::User.def()
    }
}

impl ActiveModelBehavior for ActiveModel {}
