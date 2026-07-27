use super::{DeviceDeletePayload, DeviceItem, DeviceRegisterPayload, DeviceState};
use oxcore::http;
use oxstore::{list_state_abstraction, state_request_abstraction};

impl DeviceState {
    /// Register (upsert) an FCM token for the current user.
    ///
    /// `POST /device/v1/register` with `{ token, platform }`.
    pub async fn register(&self, token: String, platform: String) {
        let payload = DeviceRegisterPayload {
            token: token.clone(),
            platform: platform.clone(),
        };
        let meta = payload.clone();
        let _ = state_request_abstraction(
            &self.register,
            Some(meta),
            http::post("/device/v1/register", &payload).send(),
            "device_register",
            |_resp: &serde_json::Value| (Some(Some(())), None),
        )
        .await;
    }

    /// List the current user's registered devices.
    ///
    /// `POST /device/v1/list` returns a plain JSON array of devices.
    pub async fn list(&self) {
        let _ = list_state_abstraction::<Vec<DeviceItem>, _>(
            &self.list,
            http::post("/device/v1/list", &serde_json::json!({})).send(),
            "devices",
        )
        .await;
    }

    /// Delete a registered device by its token.
    ///
    /// `POST /device/v1/delete` with `{ token }`.
    pub async fn delete(&self, token: String) {
        let payload = DeviceDeletePayload {
            token: token.clone(),
        };
        let meta = payload.clone();
        let _ = state_request_abstraction(
            &self.remove,
            Some(meta),
            http::post("/device/v1/delete", &payload).send(),
            "device_delete",
            |_resp: &serde_json::Value| (Some(Some(())), None),
        )
        .await;
    }
}
