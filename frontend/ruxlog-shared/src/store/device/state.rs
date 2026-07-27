use chrono::{DateTime, Utc};
use dioxus::prelude::*;
use oxstore::StateFrame;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

/// A registered push device. Mirrors the backend `device` entity
/// (UNIT `fcm-backend`): `devices(id, user_id, token, platform, created_at,
/// updated_at, last_seen_at)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceItem {
    pub id: i32,
    pub user_id: i32,
    pub token: String,
    #[serde(default)]
    pub platform: String,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub updated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_seen_at: Option<DateTime<Utc>>,
}

/// Request body for `POST /device/v1/register` — upserts a device token for
/// the current user on `(user_id, token)`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceRegisterPayload {
    pub token: String,
    pub platform: String,
}

/// Request body for `POST /device/v1/delete`.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq)]
pub struct DeviceDeletePayload {
    pub token: String,
}

/// Singleton store for FCM device registration.
pub struct DeviceState {
    pub register: GlobalSignal<StateFrame<Option<()>, DeviceRegisterPayload>>,
    pub list: GlobalSignal<StateFrame<Vec<DeviceItem>>>,
    pub remove: GlobalSignal<StateFrame<Option<()>, DeviceDeletePayload>>,
}

impl DeviceState {
    pub fn new() -> Self {
        Self {
            register: GlobalSignal::new(|| StateFrame::new()),
            list: GlobalSignal::new(|| StateFrame::new()),
            remove: GlobalSignal::new(|| StateFrame::new()),
        }
    }

    pub fn reset(&self) {
        *self.register.write() = StateFrame::new();
        *self.list.write() = StateFrame::new();
        *self.remove.write() = StateFrame::new();
    }
}

static DEVICE_STATE: OnceLock<DeviceState> = OnceLock::new();

pub fn use_device() -> &'static DeviceState {
    DEVICE_STATE.get_or_init(DeviceState::new)
}
