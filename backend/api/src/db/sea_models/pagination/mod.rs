pub mod raw;

pub use raw::paginate_query;

// Re-export the canonical envelope from `ruxlog-types` so backend callers can
// reach it via `crate::db::sea_models::pagination::PaginatedList`.
pub use ruxlog_types::PaginatedList;
