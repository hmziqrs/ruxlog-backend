//! Raw-SQL pagination helpers (Postgres).
//!
//! These helpers centralize the `LIMIT`/`OFFSET` placeholder arithmetic and the
//! total-row `COUNT` that were previously duplicated by every analytics handler
//! (GitHub issue #23 — "remove raw LIMIT/OFFSET pagination"). The SeaORM
//! [`Paginator`](sea_orm::Paginator) only covers `Select<E>` queries built from
//! entities, but the analytics endpoints run hand-written SQL through
//! [`Statement::from_sql_and_values`], so they need this statement-level helper
//! instead.

use sea_orm::{DatabaseBackend, DbConn, DbErr, FromQueryResult, Statement, Value};

/// A lightweight page result for raw SQL pagination.
///
/// Unlike [`crate::db::sea_models::pagination::PagedResult`], this does not
/// impose a [`Page`](crate::db::sea_models::pagination::Page) metadata shape on
/// the caller. It returns just the decoded rows and the total row count, leaving
/// the response envelope (e.g. `AnalyticsMeta`) to the caller. This is the shape
/// the analytics endpoints use, which keep their own metadata.
#[derive(Debug, Clone)]
pub struct PagedRaw<T> {
    /// The rows for the requested page window.
    pub rows: Vec<T>,
    /// Total number of rows the unbounded query would return (for pagination meta).
    pub total: u64,
}

#[derive(Debug, FromQueryResult)]
struct CountRow {
    total: i64,
}

/// Paginate a raw Postgres `SELECT` body.
///
/// `data_sql` must be the statement that produces the result rows — including
/// any CTEs, `WHERE`, `GROUP BY` and `ORDER BY` — **without** a `LIMIT`/
/// `OFFSET` clause and **without** a `COUNT(*) OVER ()` window column. It must
/// use Postgres positional placeholders `$1 .. $N` matching the order of
/// `params`.
///
/// The helper issues two statements against `conn`:
///  1. `SELECT COUNT(*)::BIGINT AS total FROM (<data_sql>) AS __ruxlog_pg_inner`
///     bound with `params` → total row count.
///  2. `<data_sql>` with `LIMIT $N+1 OFFSET $N+2` appended, binding `params`
///     followed by `per_page` and the computed row offset → the page window.
///
/// `page` is 1-indexed (a value of `0` is treated as `1`); `per_page` of `0` is
/// treated as `1` to avoid emitting an invalid `LIMIT 0`.
///
/// This removes the per-handler `LIMIT $N OFFSET $N` plumbing, the
/// `let limit = ...; let offset = ...;` arithmetic and the
/// `COUNT(*) OVER () AS total` column that were duplicated across the analytics
/// handlers (see GitHub issue #23).
///
/// *Note:* queries whose pagination unit differs from their output row shape
/// (e.g. `publishing_trends`, which paginates a `ROW_NUMBER()` window over
/// distinct buckets but emits one row per `(bucket, status)`) cannot use this
/// helper without changing their `total` semantics; those keep their bespoke
/// pagination and are documented inline.
pub async fn paginate_query<T>(
    conn: &DbConn,
    data_sql: &str,
    params: Vec<Value>,
    page: u64,
    per_page: u64,
) -> Result<PagedRaw<T>, DbErr>
where
    T: FromQueryResult + Send + Sync,
{
    let current_page = if page == 0 { 1 } else { page };
    let page_size = if per_page == 0 { 1 } else { per_page };
    let limit: i64 = page_size as i64;
    let offset: i64 = (current_page.saturating_sub(1) * page_size) as i64;

    // --- total row count -------------------------------------------------
    // Wrapping the unbounded body in a COUNT subquery is equivalent to the old
    // `COUNT(*) OVER () AS total` window column, but computed once and reused.
    let count_sql =
        format!("SELECT COUNT(*)::BIGINT AS total FROM (\n{data_sql}\n) AS __ruxlog_pg_inner");
    let count_stmt =
        Statement::from_sql_and_values(DatabaseBackend::Postgres, count_sql, params.clone());
    let total = CountRow::find_by_statement(count_stmt)
        .one(conn)
        .await?
        .map(|row| row.total)
        .unwrap_or(0)
        .max(0) as u64;

    // --- page window -----------------------------------------------------
    // `LIMIT`/`OFFSET` are appended as the next two placeholders after the
    // caller-supplied bind parameters, so the original `$1..$N` stay stable.
    let placeholder = params.len();
    let paged_sql = format!(
        "{data_sql}\nLIMIT ${limit_ph} OFFSET ${offset_ph}",
        limit_ph = placeholder + 1,
        offset_ph = placeholder + 2,
    );
    let mut paged_params = params;
    paged_params.push(Value::BigInt(Some(limit)));
    paged_params.push(Value::BigInt(Some(offset)));
    let paged_stmt =
        Statement::from_sql_and_values(DatabaseBackend::Postgres, paged_sql, paged_params);
    let rows = T::find_by_statement(paged_stmt).all(conn).await?;

    Ok(PagedRaw { rows, total })
}
