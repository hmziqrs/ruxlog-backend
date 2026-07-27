use sea_orm::entity::prelude::*;
use serde::{Deserialize, Serialize};

/// A registered WebAuthn (passkey) credential.
///
/// Issue #4. The `public_key` column holds the full
/// `webauthn_rs::prelude::Passkey` serialized via its serde impl (serde_json
/// bytes), which embeds the COSE public key, the credential id, the
/// authenticator's signature counter, and the user-verified flag — everything
/// the server needs to later reconstruct the credential for authentication.
///
/// The standalone `credential_id` column (base64url of the raw credential id)
/// is the opaque lookup key used to resolve a credential back to its user on
/// discoverable login (no username is sent during passkey login; the
/// authenticator returns the credential id, which we hex/base64-match here).
///
/// `counter` mirrors `Passkey.counter` as a plain BIGINT so clone detection
/// can run a cheap read (current counter) before the authoritative
/// conditional UPDATE on each login — a second assertion whose counter is not
/// strictly greater than the stored one is rejected as a possible cloned
/// authenticator (per the WebAuthn spec's signature-counter guidance).
#[derive(Clone, Debug, PartialEq, Eq, DeriveEntityModel, Serialize, Deserialize)]
#[sea_orm(table_name = "passkey_credentials")]
pub struct Model {
    #[sea_orm(primary_key)]
    pub id: i32,
    pub user_id: i32,
    /// base64url(`Passkey.cred_id`) — opaque, unique lookup key.
    pub credential_id: String,
    /// Serialized `webauthn_rs::prelude::Passkey` (serde_json bytes).
    /// Never serialize to clients — it holds the public key material.
    #[serde(skip_serializing)]
    pub public_key: Vec<u8>,
    /// Highest seen authenticator signature counter (clone detection).
    /// Defaults to 0 (authenticators that do not support counters always
    /// report 0; the clone-detection check treats 0 as "do not enforce").
    pub counter: i64,
    /// Optional client-supplied label for the device (e.g. "MacBook Touch ID").
    pub device_type: Option<String>,
    /// Optional transports array echoed by the authenticator (e.g. ["internal"]).
    pub transports: Option<Json>,
    pub created_at: DateTimeWithTimeZone,
    pub last_used_at: Option<DateTimeWithTimeZone>,
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
