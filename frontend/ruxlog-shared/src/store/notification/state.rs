use chrono::{DateTime, Utc};
use dioxus::prelude::*;
use oxstore::{PaginatedList, StateFrame};
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// A single in-app notification row. Mirrors the backend `notification` entity
/// (UNIT `fcm-backend`). `kind` is the backend `NotificationKind` string value
/// (e.g. `"new_comment"`, `"system"`).
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotificationItem {
    pub id: i32,
    pub user_id: i32,
    #[serde(default)]
    pub kind: String,
    #[serde(default)]
    pub title: String,
    #[serde(default)]
    pub body: String,
    /// Optional FCM `data` payload (arbitrary JSON object).
    #[serde(default)]
    pub data: Option<serde_json::Value>,
    /// Present once the recipient has opened the notification.
    #[serde(default)]
    pub read_at: Option<DateTime<Utc>>,
    pub created_at: DateTime<Utc>,
}

impl NotificationItem {
    pub fn is_read(&self) -> bool {
        self.read_at.is_some()
    }
}

/// Request body for `POST /notification/v1/list` (paginated, newest first).
/// Matches the backend `V1ListPayload { page, per_page }`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct NotificationListQuery {
    #[serde(default = "default_page")]
    pub page: u64,
    #[serde(default = "default_per_page")]
    pub per_page: u64,
}

impl NotificationListQuery {
    pub fn new(page: u64, per_page: u64) -> Self {
        Self { page, per_page }
    }
}

impl Default for NotificationListQuery {
    fn default() -> Self {
        Self {
            page: default_page(),
            per_page: default_per_page(),
        }
    }
}

fn default_page() -> u64 {
    1
}

fn default_per_page() -> u64 {
    20
}

/// Request body for `POST /notification/v1/mark_read`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct MarkReadPayload {
    pub id: i32,
}

/// Response from `POST /notification/v1/unread_count`.
/// Tolerates both `{"count": N}` and `{"unread_count": N}` shapes from the
/// backend so the frontend is robust to either serialization.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Default)]
pub struct UnreadCount {
    #[serde(default, alias = "unread_count")]
    pub count: u64,
}

/// Singleton store for in-app notifications.
pub struct NotificationState {
    /// Paginated list of the current user's notifications (newest first).
    pub list: GlobalSignal<StateFrame<PaginatedList<NotificationItem>>>,
    /// Latest unread count for the bell badge.
    pub unread_count: GlobalSignal<StateFrame<UnreadCount>>,
    /// Single-notification mark-read lifecycle.
    pub mark_read: GlobalSignal<StateFrame<Option<()>, MarkReadPayload>>,
    /// Mark-all-read lifecycle.
    pub mark_all_read: GlobalSignal<StateFrame<Option<()>>>,
}

impl NotificationState {
    pub fn new() -> Self {
        Self {
            list: GlobalSignal::new(|| StateFrame::new()),
            unread_count: GlobalSignal::new(|| StateFrame::new()),
            mark_read: GlobalSignal::new(|| StateFrame::new()),
            mark_all_read: GlobalSignal::new(|| StateFrame::new()),
        }
    }

    pub fn reset(&self) {
        *self.list.write() = StateFrame::new();
        *self.unread_count.write() = StateFrame::new();
        *self.mark_read.write() = StateFrame::new();
        *self.mark_all_read.write() = StateFrame::new();
    }
}

static NOTIFICATION_STATE: OnceLock<NotificationState> = OnceLock::new();

pub fn use_notification() -> &'static NotificationState {
    NOTIFICATION_STATE.get_or_init(NotificationState::new)
}
