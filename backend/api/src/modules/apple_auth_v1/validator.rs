use serde::{Deserialize, Serialize};
use validator::Validate;

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct AppleCallbackQuery {
    #[validate(length(min = 1))]
    pub code: String,
    #[validate(length(min = 1))]
    pub state: String,
}

#[derive(Debug, Deserialize, Serialize, Validate)]
pub struct AppleExchangeRequest {
    #[validate(length(min = 1))]
    pub code: String,
    #[validate(length(min = 1))]
    pub state: String,
}

/// Verified claims of an Apple `id_token`. Apple is OIDC: the user identity
/// (`sub`, `email`) lives in the signed id_token, not in a userinfo endpoint.
///
/// NB: Apple serializes `email_verified` and `is_private_email` as the STRINGS
/// `"true"` / `"false"` (not booleans), so they are decoded as `Option<String>`
/// and compared against the literal `"true"`.
#[derive(Debug, Clone, Deserialize)]
pub struct AppleIdTokenClaims {
    pub iss: String,
    pub aud: String,
    pub sub: String,
    pub email: Option<String>,
    #[serde(default)]
    pub email_verified: Option<String>,
    #[serde(default)]
    pub is_private_email: Option<String>,
    #[serde(default)]
    pub nonce: Option<String>,
}

impl AppleIdTokenClaims {
    /// True iff Apple asserts this email is verified (`email_verified == "true"`).
    pub fn is_email_verified(&self) -> bool {
        self.email_verified.as_deref() == Some("true")
    }
}
