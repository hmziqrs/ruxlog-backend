use crate::error::{DbResult, DbResultExt};
use sea_orm::{entity::prelude::*, Order, QueryOrder, Set};
use tracing::{info, instrument};

use super::{ActiveModel, Column, Entity, Model, NewDevice};

impl Entity {
    /// Upsert a device for `(user_id, token)`. On conflict (same user + token),
    /// refresh `platform` + bump `last_seen_at`/`updated_at`. Otherwise insert.
    #[instrument(skip(conn), fields(user_id = new.user_id))]
    pub async fn upsert(conn: &DbConn, new: NewDevice) -> DbResult<Model> {
        let now = chrono::Utc::now().fixed_offset();

        let existing = Self::find()
            .filter(Column::UserId.eq(new.user_id))
            .filter(Column::Token.eq(new.token.clone()))
            .one(conn)
            .await
            .map_err_to_response()?;

        if let Some(model) = existing {
            let mut am: ActiveModel = model.into();
            am.platform = Set(new.platform);
            am.last_seen_at = Set(now);
            am.updated_at = Set(now);
            let updated = am.update(conn).await.map_err_to_response()?;
            info!(device_id = updated.id, "Device refreshed");
            Ok(updated)
        } else {
            let am = ActiveModel {
                user_id: Set(new.user_id),
                token: Set(new.token),
                platform: Set(new.platform),
                created_at: Set(now),
                updated_at: Set(now),
                last_seen_at: Set(now),
                ..Default::default()
            };
            let inserted = am.insert(conn).await.map_err_to_response()?;
            info!(device_id = inserted.id, "Device registered");
            Ok(inserted)
        }
    }

    /// All devices for a user, newest first (for push fan-out).
    pub async fn list_for_user(conn: &DbConn, user_id: i32) -> DbResult<Vec<Model>> {
        Self::find()
            .filter(Column::UserId.eq(user_id))
            .order_by(Column::CreatedAt, Order::Desc)
            .all(conn)
            .await
            .map_err_to_response()
    }

    /// Delete a single `(user_id, token)` row. Returns the number of rows
    /// actually removed (0 ⇒ no such device for this user).
    pub async fn delete_for_user(conn: &DbConn, user_id: i32, token: &str) -> DbResult<u64> {
        let res = Self::delete_many()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::Token.eq(token))
            .exec(conn)
            .await
            .map_err_to_response()?;
        Ok(res.rows_affected)
    }

    /// Prune a device row by primary key — used by the push fan-out loop when
    /// FCM reports the token as `UNREGISTERED`. (Named `prune_by_id` to avoid
    /// shadowing the inherent `Entity::delete_by_id`.)
    pub async fn prune_by_id(conn: &DbConn, id: i32) -> DbResult<()> {
        Self::delete_by_id(id)
            .exec(conn)
            .await
            .map_err_to_response()?;
        Ok(())
    }
}
