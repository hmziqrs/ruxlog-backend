use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A third-party (OAuth / OIDC) identity linked to a local `users` row.
///
/// This is the multi-provider generalization of the legacy single-provider
/// `users.google_id` column: one user may hold several linked identities
/// (Facebook, GitHub, Apple, ...), each scoped to a `provider` namespace. The
/// pair `(provider, provider_user_id)` is globally unique (enforced by a DB
/// index), so a single provider account can be bound to at most one local user.
///
/// `provider_user_id` is the opaque, provider-scoped subject identifier (e.g.
/// the Facebook/GitHub numeric id, the Apple `sub`). It is NOT the email —
/// emails change and are not unique across providers. It is stored as plaintext
/// because the unique index needs to match it exactly for lookups (unlike the
/// deterministic-encryption path used for `users.google_id`, which predates this
/// table and remains for Google only).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "user_oauth_identities")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub user_id: i32,
    /// Lowercased provider namespace, e.g. `"facebook"`, `"github"`, `"apple"`.
    pub provider: String,
    /// Opaque provider-scoped subject id (NOT the email).
    pub provider_user_id: String,
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
