//! Frontend pagination envelope.
//!
//! Historically `oxstore` carried its own copy of `PaginatedList<T>`. It now
//! re-exports the single canonical definition from `ruxlog-types` so the wire
//! shape `{data, total, page, per_page}` has exactly one source of truth shared
//! by backend and frontend.
//!
//! `oxstore/src/lib.rs` does `pub use pagination::*`, so every existing
//! `use oxstore::PaginatedList` site keeps resolving unchanged.
pub use ruxlog_types::pagination::PaginatedList;
