//! Validators for the WebAuthn passkey endpoints (issue #4).
//!
//! The WebAuthn core types are embedded directly in the finish payloads: the
//! client receives the opaque challenge + state objects from the `/begin`
//! endpoint and echoes them back verbatim in the `/finish` request. Because
//! `webauthn-rs` is built with `danger-allow-state-serialisation`, the state
//! types (`PasskeyRegistration`, `PasskeyAuthentication`) are
//! (de)serializable; the credential types (`RegisterPublicKeyCredential`,
//! `PublicKeyCredential`) always are. The WebAuthn core cryptographically
//! binds each state to the challenge it was minted with, so a tampered or
//! replayed state is rejected at `/finish`.

use serde::{Deserialize, Serialize};
use validator::Validate;
use webauthn_rs::prelude::{
    PasskeyAuthentication, PasskeyRegistration, PublicKeyCredential, RegisterPublicKeyCredential,
};

/// `/register/finish` payload. `registration_state` is the opaque blob
/// returned by `/register/begin` (client-held challenge state).
#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct V1RegisterFinishPayload {
    pub credential: RegisterPublicKeyCredential,
    pub registration_state: PasskeyRegistration,
    /// Optional client-supplied label for the device.
    #[validate(length(max = 128))]
    pub device_type: Option<String>,
    /// Optional client-supplied transports array (e.g. ["internal","hybrid"]).
    pub transports: Option<serde_json::Value>,
}

/// `/login/finish` payload. `authentication_state` is the opaque blob returned
/// by `/login/begin` (client-held challenge state).
#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct V1LoginFinishPayload {
    pub credential: PublicKeyCredential,
    pub authentication_state: PasskeyAuthentication,
}

/// `/remove` payload. `credential_id` is the base64url id returned by `/list`.
#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct V1RemovePasskeyPayload {
    #[validate(length(min = 1, max = 512))]
    pub credential_id: String,
}
