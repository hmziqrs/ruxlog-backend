//! FCM HTTP v1 client.

use std::sync::Arc;

use serde::{Deserialize, Serialize};

use crate::auth::ServiceAccount;
use crate::error::FcmError;

/// The `notification` block of an FCM v1 message. Both fields optional so the
/// same struct serves data-only messages too.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Notification {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub title: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub body: Option<String>,
}

/// An FCM v1 `message` body. Serialized camelCase; every optional block is
/// omitted when `None` so the wire payload matches the FCM REST contract.
///
/// `android` / `webpush` are intentionally `serde_json::Value` (rather than
/// strongly-typed) so platform-specific overrides (TTL, priority, notification
/// channel, fcm_options, …) can be passed through verbatim without the client
/// crate having to model the full surface.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FcmMessage {
    pub token: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub notification: Option<Notification>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub data: Option<serde_json::Map<String, serde_json::Value>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub android: Option<serde_json::Value>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub webpush: Option<serde_json::Value>,
}

/// Firebase Cloud Messaging (HTTP v1) client.
///
/// Holds a shared `reqwest::Client` (caller-built, timeout-configured), the
/// Firebase `project_id`, and an `Arc<ServiceAccount>` for token minting. Safe
/// to clone-cheaply via the inner `Arc`s — `FcmClient` itself is constructed
/// once and stored in `AppState`.
pub struct FcmClient {
    pub http: reqwest::Client,
    pub project_id: String,
    pub sa: Arc<ServiceAccount>,
}

impl FcmClient {
    pub fn new(sa: ServiceAccount, project_id: String, http: reqwest::Client) -> Self {
        Self {
            http,
            project_id,
            sa: Arc::new(sa),
        }
    }

    /// Send a single message. Returns the FCM-assigned `name`
    /// (`projects/{project_id}/messages/{message_id}`).
    ///
    /// On a permanent token failure (`UNREGISTERED` / HTTP 404) returns
    /// [`FcmError::Unregistered`] so the caller can prune the stale device row.
    pub async fn send(&self, msg: FcmMessage) -> Result<String, FcmError> {
        let access = self.sa.mint_access_token(&self.http).await?;
        let url = format!(
            "https://fcm.googleapis.com/v1/projects/{}/messages:send",
            self.project_id
        );

        let resp = self
            .http
            .post(&url)
            .bearer_auth(&access.token)
            .json(&serde_json::json!({ "message": msg }))
            .send()
            .await?;

        let status = resp.status().as_u16();
        let body = resp.text().await.unwrap_or_default();

        if status == 200 || status == 201 {
            let parsed: serde_json::Value = serde_json::from_str(&body)
                .map_err(|e| FcmError::Api(status, format!("parse response: {e}")))?;
            return parsed
                .get("name")
                .and_then(|v| v.as_str())
                .map(|s| s.to_string())
                .ok_or_else(|| FcmError::Api(status, "missing 'name' in response".to_string()));
        }

        // FCM reports a stale/invalid registration token as a 404 or with an
        // error body containing `UNREGISTERED`. Map both to the sentinel so the
        // fan-out loop can prune the device.
        if status == 404 || body.to_uppercase().contains("UNREGISTERED") {
            return Err(FcmError::Unregistered);
        }

        Err(FcmError::Api(status, body))
    }
}
