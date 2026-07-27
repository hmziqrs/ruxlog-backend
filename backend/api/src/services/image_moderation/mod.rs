//! Pluggable image-content moderation gate (issue #9: NSFW/nude filter on upload).
//!
//! Real NSFW/nude detection needs an external model or API, so this module
//! exposes a small trait ([`ImageModerator`]) that the media upload path calls
//! *before* persisting bytes to S3. Two implementations ship:
//!
//! - [`NoOpModerator`]: always returns `safe`. This is the implicit default
//!   when the `image-moderation` feature is compiled in but no provider is
//!   configured (`IMAGE_MODERATION_ENABLED=false` or `IMAGE_MODERATION_URL`
//!   unset), so uploads keep working without a moderation backend.
//! - [`HttpModerator`]: POSTs the raw image bytes to a configurable provider
//!   (`IMAGE_MODERATION_URL`) with a bearer token (`IMAGE_MODERATION_API_KEY`)
//!   and parses the `{ "safe": bool, "scores": {...} }` JSON response.
//!
//! Feature-gated behind `image-moderation`. The verdict is intentionally NOT
//! persisted (no audit log yet) — an audit table can be layered on later
//! without changing this trait, so that is noted as a follow-up in the work
//! unit rather than baked into the upload path now.
//!
//! Fail-open policy lives at the single call site (`media_v1::controller`):
//! a provider *error* allows the upload through (with a logged warning) so a
//! moderation outage cannot take the whole upload pipeline down, while a
//! provider *verdict* of `safe: false` always rejects.

use std::collections::HashMap;

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};
use tracing::warn;

/// Provider classification result. `safe == false` means the moderator flagged
/// the image and the upload MUST be rejected with
/// `ErrorCode::OperationNotAllowed`.
///
/// `scores` is provider-defined (e.g. `{ "nsfw": 0.98 }`); it is used only for
/// logging/observability — the boolean `safe` is the gating decision. It
/// defaults to empty so providers that only return the boolean still parse.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ModerationVerdict {
    pub safe: bool,
    #[serde(default)]
    pub scores: HashMap<String, f32>,
}

/// Failures raised by a moderator backend. The upload call site treats these as
/// transient and FAILS OPEN (allows the upload, logs the error) rather than
/// blocking every upload during a provider outage.
#[derive(Debug, thiserror::Error)]
pub enum ModerationError {
    /// The HTTP request itself failed (connect/read/timeout).
    #[error("moderation HTTP request failed: {0}")]
    Http(#[from] reqwest::Error),
    /// The provider returned a non-success HTTP status.
    #[error("moderation provider returned status {0}")]
    Status(reqwest::StatusCode),
    /// The provider response could not be parsed into [`ModerationVerdict`].
    #[error("moderation provider returned malformed response: {0}")]
    Parse(String),
}

/// Pluggable image-content classifier. Concrete impls MUST be `Send + Sync`
/// (the trait enforces it) so the trait object can live on `AppState` as
/// `Arc<dyn ImageModerator + Send + Sync>`.
#[async_trait]
pub trait ImageModerator: Send + Sync {
    /// Classify `bytes` (declared content type `ctype`) and return a verdict.
    async fn classify(
        &self,
        bytes: &[u8],
        ctype: &str,
    ) -> Result<ModerationVerdict, ModerationError>;
}

// ── NoOpModerator ─────────────────────────────────────────────────────────

/// Pass-through moderator that approves every image. The implicit default when
/// no provider is configured, so uploads are never blocked by the *absence* of
/// a moderation backend (only by an explicit `safe: false` verdict).
#[derive(Debug, Clone, Default)]
pub struct NoOpModerator;

#[async_trait]
impl ImageModerator for NoOpModerator {
    async fn classify(
        &self,
        _bytes: &[u8],
        _ctype: &str,
    ) -> Result<ModerationVerdict, ModerationError> {
        Ok(ModerationVerdict {
            safe: true,
            scores: HashMap::new(),
        })
    }
}

// ── HttpModerator ─────────────────────────────────────────────────────────

/// Moderator that delegates classification to an external HTTP endpoint.
///
/// The request body is the raw image `bytes`, the declared content type is sent
/// as the `Content-Type` header, and the API key is sent as a `Bearer` token.
/// The endpoint MUST respond with a JSON object of shape
/// `{ "safe": bool, "scores": {...} }` (see [`ModerationVerdict`]).
///
/// `api_key` is wrapped in [`secrecy::SecretString`] so a derived `Debug` /
/// accidental `{:?}` never leaks it — the same CRYP convention used by the
/// billing providers and the FCM service-account key.
#[derive(Clone)]
pub struct HttpModerator {
    http: reqwest::Client,
    url: String,
    api_key: SecretString,
}

impl std::fmt::Debug for HttpModerator {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        // Manual impl: never emit the bearer token. Mirrors the
        // `ObjectStorageConfig` redaction in `state.rs`.
        f.debug_struct("HttpModerator")
            .field("url", &self.url)
            .field("api_key", &"<redacted>")
            .finish()
    }
}

impl HttpModerator {
    /// Build a new HTTP moderator. `http` SHOULD be the shared, timeout-bounded
    /// client from `AppState::http_client` (never a bare `reqwest::Client::new()`,
    /// see V-MED-10) so a wedged provider cannot pin the upload handler thread
    /// indefinitely.
    pub fn new(http: reqwest::Client, url: String, api_key: String) -> Self {
        Self {
            http,
            url,
            api_key: SecretString::new(api_key.into()),
        }
    }
}

#[async_trait]
impl ImageModerator for HttpModerator {
    async fn classify(
        &self,
        bytes: &[u8],
        ctype: &str,
    ) -> Result<ModerationVerdict, ModerationError> {
        let resp = self
            .http
            .post(&self.url)
            .bearer_auth(self.api_key.expose_secret())
            .header(reqwest::header::CONTENT_TYPE, ctype)
            .body(bytes.to_vec())
            .send()
            .await?;

        let status = resp.status();
        if !status.is_success() {
            // Best-effort body capture for diagnostics; ignore a read failure.
            let body = resp.text().await.unwrap_or_default();
            warn!(
                status = %status,
                body = %body,
                "Image moderation provider returned a non-success status"
            );
            return Err(ModerationError::Status(status));
        }

        let verdict: ModerationVerdict = resp
            .json()
            .await
            .map_err(|e| ModerationError::Parse(e.to_string()))?;

        Ok(verdict)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[tokio::test]
    async fn noop_moderator_always_safe() {
        let noop = NoOpModerator;
        let bytes = b"not really an image";
        let verdict = noop.classify(bytes, "image/png").await.unwrap();
        assert!(verdict.safe);
        assert!(verdict.scores.is_empty());
    }

    #[test]
    fn moderation_verdict_deserializes_provider_shape() {
        // The exact shape the HttpModerator contract promises from a provider.
        let raw = r#"{"safe": false, "scores": {"nsfw": 0.98, "safe": 0.02}}"#;
        let verdict: ModerationVerdict = serde_json::from_str(raw).unwrap();
        assert!(!verdict.safe);
        assert_eq!(verdict.scores.get("nsfw").copied(), Some(0.98));
    }

    #[test]
    fn moderation_verdict_defaults_missing_scores() {
        // A provider that only returns the boolean still parses.
        let raw = r#"{"safe": true}"#;
        let verdict: ModerationVerdict = serde_json::from_str(raw).unwrap();
        assert!(verdict.safe);
        assert!(verdict.scores.is_empty());
    }

    #[test]
    fn http_moderator_debug_redacts_api_key() {
        let moderator = HttpModerator::new(
            reqwest::Client::new(),
            "https://moderator.example/classify".to_string(),
            "super-secret-bearer-token".to_string(),
        );
        let rendered = format!("{:?}", moderator);
        assert!(
            !rendered.contains("super-secret-bearer-token"),
            "api_key leaked into Debug output: {}",
            rendered
        );
        assert!(
            rendered.contains("<redacted>"),
            "redaction marker missing: {}",
            rendered
        );
        // Non-secret field is still present so the redaction didn't nuke the
        // whole struct.
        assert!(
            rendered.contains("moderator.example"),
            "url missing from Debug output: {}",
            rendered
        );
    }
}
