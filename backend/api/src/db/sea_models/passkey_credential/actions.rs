use crate::error::{DbResult, ErrorCode, ErrorResponse};
use chrono::Utc;
use sea_orm::{entity::prelude::*, Order, QueryOrder, Set};

use super::*;

/// base64url-no-pad encoding of a raw WebAuthn credential id. The credential
/// id is an authenticator-generated opaque byte string; we store it as
/// base64url text so the `/remove` and `/list` endpoints can hand it back to
/// the client verbatim (matching the WebAuthn convention the browser uses).
pub fn encode_credential_id(cred_id: &[u8]) -> String {
    use base64::{engine::general_purpose::URL_SAFE_NO_PAD, Engine as _};
    URL_SAFE_NO_PAD.encode(cred_id)
}

impl Entity {
    /// Persist a freshly-registered passkey. The `webauthn_rs::prelude::Passkey`
    /// is serialized (serde_json bytes) into `public_key` so it can be
    /// reconstructed for authentication; `credential_id` is the base64url of
    /// `passkey.cred_id()`.
    ///
    /// `counter` starts at 0: a freshly-created credential has not been used
    /// yet, and the public `Passkey` API does not expose the registration
    /// counter directly. The first successful assertion's counter is written by
    /// [`Entity::touch_counter`]; 0 also means "not enforced" in the clone-
    /// detection check (a 0 counter is spec-exempt), so this is safe.
    ///
    /// Gated behind `auth-passkey` because it references `Passkey`; the model
    /// itself (and the lookup/delete functions below) are feature-agnostic.
    #[cfg(feature = "auth-passkey")]
    pub async fn create<T: ConnectionTrait>(
        conn: &T,
        user_id: i32,
        passkey: &webauthn_rs::prelude::Passkey,
        device_type: Option<String>,
        transports: Option<Json>,
    ) -> DbResult<Model> {
        let credential_id = encode_credential_id(passkey.cred_id().as_slice());
        let public_key = serde_json::to_vec(passkey).map_err(|err| {
            ErrorResponse::new(ErrorCode::InternalServerError)
                .with_message("Failed to serialize passkey")
                .with_details(err.to_string())
        })?;
        let now = Utc::now().fixed_offset();

        let model = ActiveModel {
            user_id: Set(user_id),
            credential_id: Set(credential_id),
            public_key: Set(public_key),
            counter: Set(0),
            device_type: Set(device_type),
            transports: Set(transports),
            created_at: Set(now),
            last_used_at: Set(None),
            ..Default::default()
        };

        match model.insert(conn).await {
            Ok(m) => Ok(m),
            Err(err) => Err(err.into()),
        }
    }

    /// All passkeys registered to a user (oldest first).
    pub async fn list_by_user<T: ConnectionTrait>(conn: &T, user_id: i32) -> DbResult<Vec<Model>> {
        match Self::find()
            .filter(Column::UserId.eq(user_id))
            .order_by(Column::CreatedAt, Order::Asc)
            .all(conn)
            .await
        {
            Ok(rows) => Ok(rows),
            Err(err) => Err(err.into()),
        }
    }

    /// Resolve a credential by its base64url credential id (discoverable login).
    pub async fn find_by_credential_id<T: ConnectionTrait>(
        conn: &T,
        credential_id: &str,
    ) -> DbResult<Option<Model>> {
        match Self::find()
            .filter(Column::CredentialId.eq(credential_id))
            .one(conn)
            .await
        {
            Ok(opt) => Ok(opt),
            Err(err) => Err(err.into()),
        }
    }

    /// Record the authenticator's latest signature counter + last-used time.
    /// `new_counter` is authoritative for clone detection: the caller has
    /// already rejected any assertion whose counter is not strictly greater
    /// than the stored value, so this is a plain SET (no conditional).
    pub async fn touch_counter<T: ConnectionTrait>(
        conn: &T,
        id: i32,
        new_counter: u32,
    ) -> DbResult<()> {
        let now = Utc::now().fixed_offset();
        let mut active: ActiveModel = Self::find()
            .filter(Column::Id.eq(id))
            .one(conn)
            .await
            .map_err(ErrorResponse::from)?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::RecordNotFound)
                    .with_message("Passkey credential not found")
            })?
            .into();
        active.counter = Set(new_counter as i64);
        active.last_used_at = Set(Some(now));
        active
            .update(conn)
            .await
            .map(|_| ())
            .map_err(ErrorResponse::from)
    }

    /// Delete a credential owned by `user_id`. Returns the number of rows
    /// removed (0 ⇒ not found or not owned — caller treats as not-found).
    pub async fn delete_by_credential_id_for_user<T: ConnectionTrait>(
        conn: &T,
        credential_id: &str,
        user_id: i32,
    ) -> DbResult<u64> {
        match Self::delete_many()
            .filter(Column::CredentialId.eq(credential_id))
            .filter(Column::UserId.eq(user_id))
            .exec(conn)
            .await
        {
            Ok(res) => Ok(res.rows_affected),
            Err(err) => Err(err.into()),
        }
    }
}
