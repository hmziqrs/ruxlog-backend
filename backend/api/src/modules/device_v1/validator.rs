use serde::{Deserialize, Serialize};
use validator::Validate;

/// `POST /device/v1/register` — register or refresh a push token.
#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct V1RegisterDevicePayload {
    /// FCM registration token (web/apns/android). Bounded length so a runaway
    /// client cannot store arbitrary text in the column.
    #[validate(length(min = 1, max = 4096))]
    pub token: String,
    /// Coarse platform hint: "web" / "android" / "ios" / …
    #[validate(length(min = 1, max = 64))]
    pub platform: String,
}

/// `POST /device/v1/delete` — unregister a push token.
#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct V1DeleteDevicePayload {
    #[validate(length(min = 1, max = 4096))]
    pub token: String,
}
