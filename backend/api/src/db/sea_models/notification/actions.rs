use crate::error::{DbResult, DbResultExt};
use ruxlog_types::PaginatedList;
use sea_orm::{entity::prelude::*, Order, QueryOrder, Set};
use tracing::{info, instrument};

use super::{ActiveModel, Column, Entity, Model, NewNotification};

impl Entity {
    /// Default (and max) page size for the inbox listing.
    pub const PER_PAGE: u64 = 20;

    #[instrument(skip(conn, new), fields(user_id = new.user_id))]
    pub async fn create(conn: &DbConn, new: NewNotification) -> DbResult<Model> {
        let now = chrono::Utc::now().fixed_offset();
        let am = ActiveModel {
            user_id: Set(new.user_id),
            kind: Set(new.kind),
            title: Set(new.title),
            body: Set(new.body),
            data: Set(new.data),
            read_at: Set(None),
            created_at: Set(now),
            ..Default::default()
        };
        let inserted = am.insert(conn).await.map_err_to_response()?;
        info!(notification_id = inserted.id, "Notification created");
        Ok(inserted)
    }

    /// Newest-first paginated inbox for a user. `page` is 1-based; `per_page`
    /// is clamped to `[1, 100]` (0 ⇒ default).
    pub async fn list_for_user(
        conn: &DbConn,
        user_id: i32,
        page: u64,
        per_page: u64,
    ) -> DbResult<PaginatedList<Model>> {
        let per_page = if per_page == 0 {
            Self::PER_PAGE
        } else {
            per_page.min(100)
        };
        let page = if page == 0 { 1 } else { page };

        let paginator = Self::find()
            .filter(Column::UserId.eq(user_id))
            .order_by(Column::CreatedAt, Order::Desc)
            .paginate(conn, per_page);
        let total = paginator.num_items().await.map_err_to_response()?;
        let items = paginator.fetch_page(page - 1).await.map_err_to_response()?;
        Ok(PaginatedList::new(items, total, page, per_page))
    }

    /// Count of unread notifications for a user (bell badge).
    pub async fn unread_count(conn: &DbConn, user_id: i32) -> DbResult<u64> {
        Self::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::ReadAt.is_null())
            .count(conn)
            .await
            .map_err_to_response()
    }

    /// Mark a single notification read, scoped to `user_id` (a user cannot mark
    /// another user's notification). Returns the updated row, or `None` if no
    /// matching unread row exists for this user.
    pub async fn mark_read(conn: &DbConn, user_id: i32, id: i32) -> DbResult<Option<Model>> {
        let now = chrono::Utc::now().fixed_offset();
        let model = Self::find()
            .filter(Column::Id.eq(id))
            .filter(Column::UserId.eq(user_id))
            .one(conn)
            .await
            .map_err_to_response()?;
        if let Some(m) = model {
            let mut am: ActiveModel = m.into();
            am.read_at = Set(Some(now));
            let updated = am.update(conn).await.map_err_to_response()?;
            Ok(Some(updated))
        } else {
            Ok(None)
        }
    }

    /// Mark every unread notification for a user as read. Returns the number of
    /// rows updated.
    pub async fn mark_all_read(conn: &DbConn, user_id: i32) -> DbResult<u64> {
        let now = chrono::Utc::now().fixed_offset();
        let unread = Self::find()
            .filter(Column::UserId.eq(user_id))
            .filter(Column::ReadAt.is_null())
            .all(conn)
            .await
            .map_err_to_response()?;
        let count = unread.len() as u64;
        for m in unread {
            let mut am: ActiveModel = m.into();
            am.read_at = Set(Some(now));
            am.update(conn).await.map_err_to_response()?;
        }
        Ok(count)
    }
}
