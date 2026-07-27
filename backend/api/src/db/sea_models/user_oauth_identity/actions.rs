use crate::error::DbResult;
use sea_orm::{entity::prelude::*, Set};
use tracing::{info, instrument, warn};

use super::*;

impl Entity {
    /// Look up an identity link by `(provider, provider_user_id)`. This is the
    /// first check of an OAuth finish: if the provider account is already linked
    /// to a local user, we log that user in directly (no creation, no email
    /// gate). Returns `Ok(None)` when no link exists yet.
    pub async fn find_by_provider<T: ConnectionTrait>(
        conn: &T,
        provider: &str,
        provider_user_id: &str,
    ) -> DbResult<Option<Model>> {
        match Self::find()
            .filter(Column::Provider.eq(provider))
            .filter(Column::ProviderUserId.eq(provider_user_id))
            .one(conn)
            .await
        {
            Ok(model) => Ok(model),
            Err(err) => Err(err.into()),
        }
    }

    /// Create a new `users → provider` link row. Callers MUST have already
    /// resolved a local `user_id` (either an existing account the IdP verified
    /// ownership of, or a freshly created one). The unique index on
    /// `(provider, provider_user_id)` makes a double-link a hard error rather
    /// than a silent second account.
    #[instrument(skip(conn), fields(user_id = new.user_id, provider = %new.provider))]
    pub async fn link<T: ConnectionTrait>(conn: &T, new: NewOauthIdentity) -> DbResult<Model> {
        let active = ActiveModel {
            user_id: Set(new.user_id),
            provider: Set(new.provider),
            provider_user_id: Set(new.provider_user_id),
            created_at: Set(new.created_at),
            ..Default::default()
        };

        match active.insert(conn).await {
            Ok(model) => {
                info!(identity_id = model.id, "Linked OAuth provider identity");
                Ok(model)
            }
            Err(err) => {
                warn!(error = %err, "Failed to link OAuth provider identity");
                Err(err.into())
            }
        }
    }

    /// Remove every provider identity for a user (used when a user wants to
    /// unlink all third-party accounts). Returns the number of rows removed.
    pub async fn delete_for_user<T: ConnectionTrait>(conn: &T, user_id: i32) -> DbResult<u64> {
        match Self::delete_many()
            .filter(Column::UserId.eq(user_id))
            .exec(conn)
            .await
        {
            Ok(res) => Ok(res.rows_affected),
            Err(err) => Err(err.into()),
        }
    }
}
