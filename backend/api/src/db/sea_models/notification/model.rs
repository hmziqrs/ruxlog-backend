use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

pub use ruxlog_types::enums::NotificationKind;

/// A single in-app notification addressed to a user. Push fan-out is a
/// best-effort side effect of `INSERT` (see `services::notification`); this row
/// is the durable source of truth, so a notification is never lost even when
/// the user has zero registered devices or FCM is disabled.
#[derive(Clone, Debug, PartialEq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "notifications")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub user_id: i32,
    pub kind: NotificationKind,
    pub title: String,
    pub body: String,
    /// Arbitrary structured payload (e.g. `{"post_id": 42}`), mirrored to FCM
    /// `data` on push. Nullable — many notifications have no payload.
    #[sea_orm(column_type = "JsonBinary", nullable)]
    pub data: Option<Json>,
    /// `NULL` until the user marks the row read.
    pub read_at: Option<DateTimeWithTimeZone>,
    pub created_at: DateTimeWithTimeZone,
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
