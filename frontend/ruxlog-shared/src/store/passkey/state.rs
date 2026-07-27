use chrono::{DateTime, FixedOffset};
use dioxus::prelude::*;
use oxstore::StateFrame;
use serde::{Deserialize, Serialize};
use std::sync::OnceLock;

// The authenticated user type is owned by the auth store; reuse it so a
// successful passkey login can populate `use_auth().user` directly.
use crate::store::auth::AuthUser;

/// `/register/begin` response. `challenge` is handed to
/// `navigator.credentials.create`; `registration_state` is an opaque blob the
/// client MUST echo back verbatim to `/register/finish` (it is the
/// cryptographically-bound WebAuthn challenge state, client-held so the
/// server stays stateless).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterBeginResponse {
    pub challenge: serde_json::Value,
    pub registration_state: serde_json::Value,
}

/// `/login/begin` response. `challenge` is handed to
/// `navigator.credentials.get`; `authentication_state` is the opaque blob to
/// echo back to `/login/finish`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginBeginResponse {
    pub challenge: serde_json::Value,
    pub authentication_state: serde_json::Value,
}

/// `/register/finish` payload. `credential` is the serialized browser
/// `PublicKeyCredential` from `navigator.credentials.create`; `registration_state`
/// is the blob returned by `/register/begin`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RegisterFinishPayload {
    pub credential: serde_json::Value,
    pub registration_state: serde_json::Value,
    pub device_type: Option<String>,
    pub transports: Option<serde_json::Value>,
}

/// `/login/finish` payload.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFinishPayload {
    pub credential: serde_json::Value,
    pub authentication_state: serde_json::Value,
}

/// `/login/finish` response. The session is issued server-side via the cookie
/// (same as password login); `user` is returned so the UI can populate the
/// auth store without a follow-up fetch.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LoginFinishResponse {
    pub status: String,
    pub user: AuthUser,
}

/// A registered passkey (client-facing view — matches the backend
/// `PasskeyCredentialView`). `credential_id` is echoed back to `/remove`.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PasskeyCredential {
    pub id: i32,
    pub credential_id: String,
    pub device_type: Option<String>,
    pub transports: Option<serde_json::Value>,
    pub created_at: DateTime<FixedOffset>,
    pub last_used_at: Option<DateTime<FixedOffset>>,
}

/// `/list` response.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ListResponse {
    pub data: Vec<PasskeyCredential>,
}

pub struct PasskeyState {
    /// `/register/begin` result (challenge + state).
    pub register_begin: GlobalSignal<StateFrame<Option<RegisterBeginResponse>>>,
    /// `/register/finish` result (the newly-registered credential view).
    pub register: GlobalSignal<StateFrame<Option<PasskeyCredential>>>,
    /// `/login/begin` result (challenge + state).
    pub login_begin: GlobalSignal<StateFrame<Option<LoginBeginResponse>>>,
    /// `/login/finish` result (the authenticated user).
    pub login: GlobalSignal<StateFrame<Option<AuthUser>>>,
    /// `/list` result (the user's credentials).
    pub list: GlobalSignal<StateFrame<Vec<PasskeyCredential>>>,
    /// `/remove` result.
    pub remove: GlobalSignal<StateFrame<Option<()>>>,
}

impl PasskeyState {
    pub fn new() -> Self {
        Self {
            register_begin: GlobalSignal::new(|| StateFrame::new()),
            register: GlobalSignal::new(|| StateFrame::new()),
            login_begin: GlobalSignal::new(|| StateFrame::new()),
            login: GlobalSignal::new(|| StateFrame::new()),
            list: GlobalSignal::new(|| StateFrame::new()),
            remove: GlobalSignal::new(|| StateFrame::new()),
        }
    }

    pub fn reset(&self) {
        *self.register_begin.write() = StateFrame::new();
        *self.register.write() = StateFrame::new();
        *self.login_begin.write() = StateFrame::new();
        *self.login.write() = StateFrame::new();
        *self.list.write() = StateFrame::new();
        *self.remove.write() = StateFrame::new();
    }
}

static PASSKEY_STATE: OnceLock<PasskeyState> = OnceLock::new();

pub fn use_passkey() -> &'static PasskeyState {
    PASSKEY_STATE.get_or_init(PasskeyState::new)
}
