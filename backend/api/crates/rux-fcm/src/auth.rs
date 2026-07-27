//! Google service-account authentication for FCM.
//!
//! Implements the OAuth2 JWT-bearer grant flow:
//!   1. Build an RS256 JWT signed with the service-account private key
//!      (iss = client_email, scope = firebase.messaging, aud = token endpoint).
//!   2. POST it to `https://oauth2.googleapis.com/token` as
//!      `grant_type=urn:ietf:params:oauth:grant-type:jwt-bearer`.
//!   3. Cache the returned access token in an internal `RwLock` and refresh it
//!      ~5 minutes before expiry so per-send latency stays flat.

use chrono::Utc;
use jsonwebtoken::{encode, Algorithm, EncodingKey, Header};
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tokio::sync::RwLock;

use crate::error::FcmError;

/// OAuth2 scope required to send FCM v1 messages.
const FCM_SCOPE: &str = "https://www.googleapis.com/auth/firebase.messaging";
/// Google OAuth2 token endpoint (also the JWT `aud`).
const TOKEN_URL: &str = "https://oauth2.googleapis.com/token";
/// Lifetime requested for each access token (Google-issued tokens are 1h).
const TOKEN_TTL_SECS: i64 = 3600;
/// Refresh this far ahead of the real expiry so a slow token endpoint never
/// serves an already-expired token to a send.
const REFRESH_LEAD_SECS: i64 = 300;

/// Raw shape of the Google service-account JSON key file — only the fields we
/// need are decoded.
#[derive(Debug, Deserialize)]
struct RawServiceAccount {
    private_key: String,
    private_key_id: String,
    client_email: String,
    project_id: String,
}

/// A Google service account authorized for Firebase Cloud Messaging.
///
/// Holds the signing material plus an internal token cache. Cheap to share via
/// `Arc` (the cache uses an `RwLock`, so cloning is NOT needed — share one
/// instance).
pub struct ServiceAccount {
    pub client_email: String,
    pub project_id: String,
    // CRYP-FCM-1: the private key is a long-lived signing secret. Wrap it in
    // `secrecy::SecretString` so a derived `Debug` / accidental `{:?}` of this
    // struct never leaks it (redacts to `<redacted>`).
    private_key: SecretString,
    private_key_id: String,
    cache: RwLock<CachedToken>,
}

#[derive(Default)]
struct CachedToken {
    token: Option<String>,
    expires_at: i64,
}

/// A freshly-minted (or cached) OAuth2 access token.
#[derive(Debug, Clone)]
pub struct AccessToken {
    pub token: String,
    pub expires_at: i64,
}

/// JWT-bearer grant claims.
#[derive(Serialize)]
struct Claims {
    iss: String,
    scope: String,
    aud: String,
    iat: i64,
    exp: i64,
}

#[derive(Deserialize)]
struct TokenResponse {
    access_token: String,
    #[serde(default = "default_expires_in")]
    expires_in: i64,
}

fn default_expires_in() -> i64 {
    TOKEN_TTL_SECS
}

impl ServiceAccount {
    /// Load a service account from a Google service-account JSON key file.
    pub fn from_path(path: &str) -> Result<Self, FcmError> {
        let bytes = std::fs::read(path)
            .map_err(|e| FcmError::MissingConfig(format!("read service account {}: {e}", path)))?;
        let json = String::from_utf8(bytes)
            .map_err(|e| FcmError::MissingConfig(format!("service account not utf-8: {e}")))?;
        Self::from_json_str(&json)
    }

    /// Load a service account from an in-memory JSON string (the contents of a
    /// Google service-account key file).
    pub fn from_json_str(json: &str) -> Result<Self, FcmError> {
        let raw: RawServiceAccount = serde_json::from_str(json)
            .map_err(|e| FcmError::Auth(format!("invalid service account JSON: {e}")))?;
        Ok(Self::from_raw(raw))
    }

    fn from_raw(raw: RawServiceAccount) -> Self {
        Self {
            client_email: raw.client_email,
            project_id: raw.project_id,
            private_key: SecretString::new(raw.private_key.into()),
            private_key_id: raw.private_key_id,
            cache: RwLock::new(CachedToken::default()),
        }
    }

    /// Return a valid OAuth2 access token, minting one (and caching it) on
    /// demand. Cached tokens are reused until ~5 minutes before expiry.
    pub async fn mint_access_token(&self, http: &reqwest::Client) -> Result<AccessToken, FcmError> {
        let now = Utc::now().timestamp();

        // Fast path: a cached token still has comfortable remaining life.
        {
            let guard = self.cache.read().await;
            if let Some(token) = guard.token.as_ref() {
                if guard.expires_at - now > REFRESH_LEAD_SECS {
                    return Ok(AccessToken {
                        token: token.clone(),
                        expires_at: guard.expires_at,
                    });
                }
            }
        }

        // Slow path: mint a new token. Two concurrent senders racing here is
        // harmless (idempotent) — at worst one extra token is minted.
        let mut header = Header::new(Algorithm::RS256);
        header.kid = Some(self.private_key_id.clone());

        let claims = Claims {
            iss: self.client_email.clone(),
            scope: FCM_SCOPE.to_string(),
            aud: TOKEN_URL.to_string(),
            iat: now,
            exp: now + TOKEN_TTL_SECS,
        };

        let key = EncodingKey::from_rsa_pem(self.private_key.expose_secret().as_bytes())
            .map_err(|e| FcmError::Auth(format!("invalid private key: {e}")))?;
        let assertion = encode(&header, &claims, &key)
            .map_err(|e| FcmError::Auth(format!("jwt encode: {e}")))?;

        // JWT-bearer grant: form-encoded body, NOT JSON.
        let form = format!(
            "grant_type=urn%3Aietf%3Aparams%3Aoauth%3Agrant-type%3Ajwt-bearer&assertion={assertion}"
        );

        let resp = http
            .post(TOKEN_URL)
            .header(
                reqwest::header::CONTENT_TYPE,
                "application/x-www-form-urlencoded",
            )
            .body(form)
            .send()
            .await?;

        let status = resp.status();
        let body = resp.text().await.unwrap_or_default();
        if !status.is_success() {
            return Err(FcmError::Auth(format!(
                "token endpoint returned {}: {}",
                status.as_u16(),
                body
            )));
        }

        let parsed: TokenResponse = serde_json::from_str(&body)
            .map_err(|e| FcmError::Auth(format!("token response parse: {e}")))?;

        let expires_at = now + parsed.expires_in;
        let token = AccessToken {
            token: parsed.access_token.clone(),
            expires_at,
        };

        // Publish to cache.
        {
            let mut guard = self.cache.write().await;
            *guard = CachedToken {
                token: Some(parsed.access_token),
                expires_at,
            };
        }

        Ok(token)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn from_json_str_rejects_invalid_json() {
        let err = ServiceAccount::from_json_str("not json").expect_err("must reject");
        assert!(matches!(err, FcmError::Auth(_)));
    }

    #[test]
    fn from_json_str_parses_required_fields() {
        let json = serde_json::json!({
            "private_key": "-----BEGIN PRIVATE KEY-----\nxx\n-----END PRIVATE KEY-----\n",
            "private_key_id": "kid-123",
            "client_email": "fcm@test.iam.gserviceaccount.com",
            "project_id": "test-project",
        })
        .to_string();
        let sa = ServiceAccount::from_json_str(&json).expect("must parse");
        assert_eq!(sa.client_email, "fcm@test.iam.gserviceaccount.com");
        assert_eq!(sa.project_id, "test-project");
        assert_eq!(sa.private_key_id, "kid-123");
        // CRYP-FCM-1: the private key is wrapped in `SecretString`, whose Debug
        // redacts — a leaked `{:?}` of the secret material would be caught here.
        let dbg = format!("{:?}", &sa.private_key);
        assert!(
            !dbg.contains("BEGIN PRIVATE KEY"),
            "private key leaked into Debug: {}",
            dbg
        );
    }
}
