use serde::{Deserialize, Serialize};
use std::ops::{Deref, DerefMut};

/// The canonical paginated envelope for ruxlog list endpoints.
///
/// This is the **single** pagination shape used across the backend (entity
/// actions, services, HTTP controllers) and the frontend (deserialized directly
/// via `.json::<PaginatedList<T>>()`). It is intentionally flat —
/// `{ data, total, page, per_page }` — because that is the live wire format the
/// API already emits and the frontend already consumes; it lives here in
/// `ruxlog-types` (serde-only, no sea-orm dependency) so both sides share one
/// definition.
///
/// The derived navigation helpers (`total_pages`, `has_next_page`,
/// `has_previous_page`) are computed from the flat fields — they are **not**
/// serialized, so the wire shape stays exactly `{data,total,page,per_page}`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PaginatedList<T> {
    pub data: Vec<T>,
    pub total: u64,
    pub page: u64,
    pub per_page: u64,
}

impl<T> PaginatedList<T> {
    pub fn new(data: Vec<T>, total: u64, page: u64, per_page: u64) -> Self {
        Self {
            data,
            total,
            page,
            per_page,
        }
    }

    /// Total number of pages implied by `total` / `per_page`.
    ///
    /// Uses ceiling division. A `per_page` of `0` yields `0` pages (there is no
    /// valid page window when the page size is empty).
    pub fn total_pages(&self) -> u64 {
        if self.per_page == 0 {
            0
        } else {
            self.total.div_ceil(self.per_page)
        }
    }

    /// Whether a page after `page` exists.
    pub fn has_next_page(&self) -> bool {
        self.page < self.total_pages()
    }

    /// Whether a page before `page` exists (i.e. `page` is not the first).
    pub fn has_previous_page(&self) -> bool {
        self.page > 1
    }

    /// Transform the page items while preserving the pagination metadata.
    ///
    /// Useful for sanitization/serialization passes (e.g. stripping secret
    /// fields from admin results) that must keep `total`/`page`/`per_page`
    /// identical to the source query.
    pub fn map<U>(self, mut f: impl FnMut(T) -> U) -> PaginatedList<U> {
        let data = self.data.into_iter().map(&mut f).collect();
        PaginatedList {
            data,
            total: self.total,
            page: self.page,
            per_page: self.per_page,
        }
    }
}

impl<T> Deref for PaginatedList<T> {
    type Target = Vec<T>;

    fn deref(&self) -> &Self::Target {
        &self.data
    }
}

impl<T> DerefMut for PaginatedList<T> {
    fn deref_mut(&mut self) -> &mut Self::Target {
        &mut self.data
    }
}

impl<T> IntoIterator for PaginatedList<T> {
    type Item = T;
    type IntoIter = std::vec::IntoIter<T>;

    fn into_iter(self) -> Self::IntoIter {
        self.data.into_iter()
    }
}

#[cfg(test)]
mod tests {
    use super::PaginatedList;

    // ── JSON round-trip preserves the flat wire shape ──

    #[test]
    fn json_roundtrip_preserves_flat_shape() {
        // The wire format MUST be exactly {data,total,page,per_page} — this is
        // the contract the frontend deserializes. Adding/removing/renaming a
        // serialized field here breaks every list endpoint's consumer.
        let list = PaginatedList::new(vec![1_u32, 2, 3], 9, 1, 3);
        let json = serde_json::to_string(&list).unwrap();
        assert_eq!(
            json,
            r#"{"data":[1,2,3],"total":9,"page":1,"per_page":3}"#
        );
        let back: PaginatedList<u32> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, list);
    }

    #[test]
    fn json_roundtrip_empty() {
        let list: PaginatedList<i32> = PaginatedList::new(vec![], 0, 1, 20);
        let json = serde_json::to_string(&list).unwrap();
        assert_eq!(
            json,
            r#"{"data":[],"total":0,"page":1,"per_page":20}"#
        );
        let back: PaginatedList<i32> = serde_json::from_str(&json).unwrap();
        assert_eq!(back, list);
    }

    // ── total_pages ──

    #[test]
    fn total_pages_ceil_division() {
        let list = PaginatedList::new(vec![1_u32], 10, 1, 3);
        // ceil(10/3) = 4
        assert_eq!(list.total_pages(), 4);
    }

    #[test]
    fn total_pages_exact_multiple() {
        let list = PaginatedList::new(vec![1_u32], 9, 1, 3);
        assert_eq!(list.total_pages(), 3);
    }

    #[test]
    fn total_pages_zero_per_page_is_zero() {
        let list = PaginatedList::new(vec![1_u32], 9, 1, 0);
        assert_eq!(list.total_pages(), 0);
    }

    #[test]
    fn total_pages_zero_total_is_zero() {
        let list: PaginatedList<u32> = PaginatedList::new(vec![], 0, 1, 20);
        assert_eq!(list.total_pages(), 0);
    }

    // ── has_next_page ──

    #[test]
    fn has_next_page_true_on_middle_page() {
        let list = PaginatedList::new(vec![1_u32, 2, 3], 9, 1, 3);
        assert!(list.has_next_page());
    }

    #[test]
    fn has_next_page_false_on_last_page_exact() {
        // Last page that exactly fills total: no further page.
        let list = PaginatedList::new(vec![7_u32, 8, 9], 9, 3, 3);
        assert!(!list.has_next_page());
    }

    #[test]
    fn has_next_page_false_on_empty_list() {
        let list: PaginatedList<i32> = PaginatedList::new(vec![], 0, 1, 20);
        assert!(!list.has_next_page());
    }

    #[test]
    fn has_next_page_false_when_single_full_page() {
        let list = PaginatedList::new(vec![1_u32, 2], 2, 1, 2);
        assert!(!list.has_next_page());
    }

    // ── has_previous_page ──

    #[test]
    fn has_previous_page_false_on_first_page() {
        let list = PaginatedList::new(vec![1_u32, 2, 3], 9, 1, 3);
        assert!(!list.has_previous_page());
    }

    #[test]
    fn has_previous_page_true_on_page_two() {
        let list = PaginatedList::new(vec![4_u32, 5, 6], 9, 2, 3);
        assert!(list.has_previous_page());
    }

    // ── map preserves metadata ──

    #[test]
    fn map_preserves_metadata_and_transforms_items() {
        let list = PaginatedList::new(vec![1_u32, 2, 3], 9, 1, 3);
        let mapped = list.map(|n| format!("x{n}"));
        assert_eq!(mapped.data, vec!["x1".to_string(), "x2".into(), "x3".into()]);
        assert_eq!(mapped.total, 9);
        assert_eq!(mapped.page, 1);
        assert_eq!(mapped.per_page, 3);
        assert!(mapped.has_next_page());
    }

    // ── Deref / IntoIterator ──

    #[test]
    fn deref_returns_inner_data() {
        let list = PaginatedList::new(vec![10_u32, 20, 30], 3, 1, 10);
        assert_eq!(list.len(), 3);
        assert_eq!(list[0], 10);
        assert_eq!(list[2], 30);
    }

    #[test]
    fn into_iter_yields_all_items() {
        let list = PaginatedList::new(vec!["a", "b", "c"], 3, 1, 10);
        let collected: Vec<&str> = list.into_iter().collect();
        assert_eq!(collected, vec!["a", "b", "c"]);
    }
}
