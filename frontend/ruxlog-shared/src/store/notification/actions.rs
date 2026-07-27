use super::{
    MarkReadPayload, NotificationItem, NotificationListQuery, NotificationState, UnreadCount,
};
use oxcore::http;
use oxstore::{list_state_abstraction, state_request_abstraction, PaginatedList};

impl NotificationState {
    /// Fetch one page of the current user's notifications (newest first).
    ///
    /// Hits `POST /notification/v1/list` with `{ page, per_page }`. The response
    /// is decoded into the standard [`PaginatedList`] shape (`data`, `total`,
    /// `page`, `per_page`).
    pub async fn list(&self, page: u64, per_page: u64) {
        let query = NotificationListQuery::new(page, per_page);
        let _ = list_state_abstraction::<PaginatedList<NotificationItem>, _>(
            &self.list,
            http::post("/notification/v1/list", &query).send(),
            "notifications",
        )
        .await;
    }

    /// Refresh the unread count for the current user.
    ///
    /// `POST /notification/v1/unread_count` returns `{ "count": N }`.
    pub async fn unread_count(&self) {
        let _ = list_state_abstraction::<UnreadCount, _>(
            &self.unread_count,
            http::post("/notification/v1/unread_count", &serde_json::json!({})).send(),
            "notification_unread_count",
        )
        .await;
    }

    /// Mark a single notification as read by id.
    ///
    /// `POST /notification/v1/mark_read` with `{ id }`.
    pub async fn mark_read(&self, id: i32) {
        let payload = MarkReadPayload { id };
        let meta = payload.clone();
        let _ = state_request_abstraction(
            &self.mark_read,
            Some(meta),
            http::post("/notification/v1/mark_read", &payload).send(),
            "notification_mark_read",
            |_resp: &serde_json::Value| (Some(Some(())), None),
        )
        .await;
    }

    /// Mark every notification for the current user as read.
    ///
    /// `POST /notification/v1/mark_all_read`.
    pub async fn mark_all_read(&self) {
        let _ = state_request_abstraction(
            &self.mark_all_read,
            None,
            http::post("/notification/v1/mark_all_read", &serde_json::json!({})).send(),
            "notification_mark_all_read",
            |_resp: &serde_json::Value| (Some(Some(())), None),
        )
        .await;
    }
}
