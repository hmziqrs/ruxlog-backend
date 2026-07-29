pub mod enums;
pub mod error;
pub mod pagination;
pub mod query;
pub mod types;

// Canonical pagination envelope — re-exported at the crate root so both the
// backend (`ruxlog_types::PaginatedList`) and the frontend oxstore re-export
// resolve to the single shared definition.
pub use pagination::PaginatedList;

#[cfg(feature = "slug")]
pub mod slug;
