use crate::error::{DbResult, ErrorCode, ErrorResponse};
use ruxlog_types::PaginatedList;
use sea_orm::entity::prelude::*;
use sea_orm::{ConnectionTrait, DatabaseBackend, Order, QueryOrder, QuerySelect, Statement};
use tracing::{instrument, warn};

use super::{
    Column, Entity, Model, NewSuppression, SuppressionListItem, SuppressionQuery,
    SuppressionReason, SuppressionUpsert,
};

/// String value stored in the `reason` column for each variant. Must match the
/// `SuppressionReason` `DeriveActiveEnum` string_value mapping.
fn reason_str(r: SuppressionReason) -> &'static str {
    match r {
        SuppressionReason::Bounce => "bounce",
        SuppressionReason::Complaint => "complaint",
        SuppressionReason::Manual => "manual",
    }
}

impl Entity {
    pub const PER_PAGE: u64 = 50;

    /// Send-path lookup: returns the row for a canonicalized recipient, if any.
    /// The router decides enforcement (permanent vs. soft-cooldown) from the
    /// returned fields.
    #[instrument(skip(conn), fields(recipient))]
    pub async fn find_by_recipient(conn: &DbConn, recipient: &str) -> DbResult<Option<Model>> {
        Self::find()
            .filter(Column::Recipient.eq(recipient))
            .one(conn)
            .await
            .map_err(Into::into)
    }

    /// Insert or update a suppression row **atomically**. `permanent` is
    /// **sticky**: once a recipient is permanently suppressed it is never
    /// downgraded, and a permanent reason (complaint / hard bounce) is never
    /// downgraded to bounce. `last_seen` is bumped to now so the soft-bounce
    /// cooldown window resets. Complaints and Manual blocks are always permanent.
    ///
    /// Implemented as a single `INSERT ... ON CONFLICT DO UPDATE` so the
    /// sticky-permanent decision is evaluated server-side — a plain
    /// read-then-write races under concurrent webhook events and can let a
    /// soft-bounce write downgrade a just-written permanent complaint.
    #[instrument(skip(conn), fields(recipient))]
    pub async fn upsert(conn: &DbConn, recipient: &str, up: SuppressionUpsert) -> DbResult<Model> {
        let now = chrono::Utc::now().fixed_offset();
        // Only `Bounce` may be non-permanent; Complaint and Manual are always
        // permanent (no soft-cooldown semantics for them).
        let perm = up.permanent || up.reason != SuppressionReason::Bounce;

        const SQL: &str = r#"INSERT INTO email_suppression
            (recipient, reason, source, diagnostic, permanent, last_seen, created_at, updated_at)
            VALUES ($1, $2, $3, $4, $5, $6, $6, $6)
            ON CONFLICT (recipient) DO UPDATE SET
                permanent = email_suppression.permanent OR EXCLUDED.permanent,
                reason = CASE WHEN email_suppression.permanent
                              THEN email_suppression.reason ELSE EXCLUDED.reason END,
                source = EXCLUDED.source,
                diagnostic = EXCLUDED.diagnostic,
                last_seen = EXCLUDED.last_seen,
                updated_at = EXCLUDED.updated_at"#;
        conn.execute(Statement::from_sql_and_values(
            DatabaseBackend::Postgres,
            SQL,
            vec![
                recipient.into(),
                reason_str(up.reason).into(),
                up.source.into(),
                up.diagnostic.into(),
                perm.into(),
                now.into(),
            ],
        ))
        .await?;

        // Read back the committed row (single indexed lookup) for the caller.
        Self::find_by_recipient(conn, recipient)
            .await?
            .ok_or_else(|| {
                ErrorResponse::new(ErrorCode::IntegrityError)
                    .with_message("email_suppression upsert returned no row")
            })
    }

    /// Manual admin blacklist add (upserts; canonicalizes the recipient).
    pub async fn create(conn: &DbConn, new: NewSuppression) -> DbResult<Model> {
        let recipient = new.recipient.trim().to_lowercase();
        if recipient.is_empty() {
            return Err(ErrorResponse::new(ErrorCode::InvalidEmailFormat)
                .with_message("Recipient cannot be empty"));
        }
        Self::upsert(
            conn,
            &recipient,
            SuppressionUpsert {
                reason: new.reason,
                source: new.source.or_else(|| Some("admin".to_string())),
                diagnostic: new.diagnostic,
                permanent: new.permanent,
            },
        )
        .await
    }

    /// Remove a recipient from the suppression list. Returns `true` if a row
    /// was deleted.
    pub async fn delete_by_recipient(conn: &DbConn, recipient: &str) -> DbResult<bool> {
        let res = Self::delete_many()
            .filter(Column::Recipient.eq(recipient))
            .exec(conn)
            .await?;
        Ok(res.rows_affected > 0)
    }

    /// Paginated, filtered admin listing.
    pub async fn find_with_query(
        conn: &DbConn,
        query: SuppressionQuery,
    ) -> DbResult<PaginatedList<SuppressionListItem>> {
        let mut q = Self::find().select_only().columns([
            Column::Id,
            Column::Recipient,
            Column::Reason,
            Column::Permanent,
            Column::Source,
            Column::LastSeen,
            Column::CreatedAt,
        ]);

        if let Some(reason) = query.reason {
            q = q.filter(Column::Reason.eq(reason));
        }
        if let Some(permanent) = query.permanent {
            q = q.filter(Column::Permanent.eq(permanent));
        }
        if let Some(search) = &query.search {
            q = q.filter(Column::Recipient.contains(search.as_str()));
        }

        q = q.order_by(Column::LastSeen, Order::Desc);

        let page = match query.page {
            Some(p) if p > 0 => p,
            _ => 1,
        };

        let paginator = q
            .into_model::<SuppressionListItem>()
            .paginate(conn, Self::PER_PAGE);
        let total = paginator.num_items().await?;
        let items = paginator.fetch_page(page - 1).await?;

        Ok(PaginatedList::new(items, total, page, Self::PER_PAGE))
    }

    /// Find a row by id (admin detail) or a 404 error.
    pub async fn find_by_id_with_404(conn: &DbConn, id: i32) -> DbResult<Model> {
        match Self::find_by_id(id).one(conn).await {
            Ok(Some(model)) => Ok(model),
            Ok(None) => {
                warn!(suppression_id = id, "Suppression entry not found");
                Err(ErrorResponse::new(ErrorCode::RecordNotFound)
                    .with_message(format!("Suppression entry {id} not found")))
            }
            Err(err) => Err(err.into()),
        }
    }
}
