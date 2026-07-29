//! Generic mail provider trait + shared outbound/inbound types.
//!
//! Every mail integration (SMTP, Cloudflare Email) implements [`MailProvider`].
//! The [`crate::services::mail::router::MailRouter`] holds the initialized
//! providers and runs the cross-cutting send-time guards (recipient validation,
//! suppression-list pre-check, rate limiting, idempotency dedup) once for every
//! provider before delegating, then feeds synchronous bounces back into the
//! suppression list. This mirrors the billing `BillingProvider`/`BillingRouter`
//! split in `services::billing`.

use async_trait::async_trait;
use serde::{Deserialize, Serialize};

/// Outbound email handed to a [`MailProvider`]. The **provider** owns the
/// verified sender address (`MAIL_FROM_ADDRESS` + optional `MAIL_FROM_NAME`),
/// not the caller — so `OutboundEmail` carries only the recipient and content.
#[derive(Debug, Clone)]
pub struct OutboundEmail {
    pub to: String,
    pub subject: String,
    pub html: Option<String>,
    pub text: Option<String>,
    /// Template bucket key. Drives router behaviour: transactional templates
    /// (`verification`/`password_reset`) skip the per-recipient rate limiter
    /// (the controller already bounds them), skip dedup (the code changes each
    /// request), and suppress silently (anti account-enumeration). See
    /// [`TEMPLATE_VERIFICATION`] / [`TEMPLATE_PASSWORD_RESET`] / [`TEMPLATE_NEWSLETTER`].
    pub template: Option<&'static str>,
}

/// Template buckets used by [`OutboundEmail::template`].
pub const TEMPLATE_VERIFICATION: &str = "verification";
pub const TEMPLATE_PASSWORD_RESET: &str = "password_reset";
pub const TEMPLATE_NEWSLETTER: &str = "newsletter";

/// `true` for templates that are already rate-limited at the controller layer
/// (keyed on `user_id`) and must never reveal a suppressed recipient.
pub fn is_transactional(template: Option<&str>) -> bool {
    matches!(
        template,
        Some(TEMPLATE_VERIFICATION) | Some(TEMPLATE_PASSWORD_RESET)
    )
}

/// Receipt returned by [`MailProvider::send`]. `permanent_bounces` carries the
/// recipients the provider rejected synchronously (Cloudflare returns these in
/// the send response) so the router can upsert suppression rows.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct SendReceipt {
    #[serde(default)]
    pub delivered: u32,
    #[serde(default)]
    pub queued: u32,
    #[serde(default)]
    pub permanent_bounces: Vec<String>,
}

/// Incoming webhook event from a provider (raw body + full headers, because
/// every provider signs differently).
///
/// This shape is shared with the billing stack, so it lives in
/// `rux-provider-core` and is re-exported here so every existing
/// `use super::provider::WebhookEvent` / `crate::services::mail::provider::WebhookEvent`
/// import keeps resolving unchanged.
pub use rux_provider_core::WebhookEvent;

/// Canonical mail event vocabulary. Each provider's `verify_webhook` translates
/// its native event into one of these so the dispatch is provider-agnostic.
pub mod canonical {
    /// Delivery permanently failed (hard bounce) — suppress the recipient.
    pub const BOUNCED: &str = "email.bounced";
    /// The recipient filed a spam complaint (Feedback Loop) — suppress.
    pub const COMPLAINED: &str = "email.complained";
    /// Successful delivery — metric only.
    pub const DELIVERED: &str = "email.delivered";
}

/// Parsed inbound mail event after verification.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ParsedMailEvent {
    /// One of [`canonical`] constants.
    pub event_type: String,
    pub recipient: String,
    pub message_id: Option<String>,
    /// Diagnostic reason (SMTP reply / provider error) — kept server-side only.
    pub diagnostic: Option<String>,
    /// Whether this is a permanent suppression (hard bounce / complaint).
    pub permanent: bool,
    pub ts: Option<i64>,
    pub data: serde_json::Value,
}

/// Common mail operations every provider must support.
#[async_trait]
pub trait MailProvider: Send + Sync {
    /// Name of this provider (e.g. "smtp", "cloudflare").
    fn provider_name(&self) -> &'static str;

    /// Send an outbound email. The provider MUST NOT record `mail_metrics`
    /// itself — the router records telemetry once after delegation so both
    /// providers report identically.
    async fn send(&self, msg: OutboundEmail) -> Result<SendReceipt, MailError>;

    /// Verify and parse an inbound webhook event. The default body rejects:
    /// providers without an inbound channel (SMTP) need not override it, and a
    /// missing webhook secret fail-closes every event. Mirrors the default-`Err`
    /// idiom used by `BillingProvider::create_post_checkout`.
    async fn verify_webhook(&self, event: WebhookEvent) -> Result<ParsedMailEvent, MailError> {
        let _ = event;
        Err(MailError::WebhookVerification(format!(
            "provider '{}' has no inbound webhook",
            self.provider_name()
        )))
    }
}

/// Every [`MailProvider`] object is a [`rux_provider_core::Provider`]. This
/// opts the dyn-trait into the framework marker so `ProviderRegistry<dyn
/// MailProvider>` (used by [`crate::services::mail::router::MailRouter`])
/// satisfies its `P: Provider` bound. The marker carries no methods, so the 15
/// existing `impl MailProvider for ...` blocks compile unchanged and
/// `obj.provider_name()` on a `dyn MailProvider` stays unambiguous.
impl rux_provider_core::Provider for dyn MailProvider {}

/// Errors from mail operations.
#[derive(Debug, thiserror::Error)]
pub enum MailError {
    #[error("mail configuration error: {0}")]
    Config(String),

    #[error("mail provider API error: {0}")]
    ProviderApi(String),

    #[error("mail HTTP request failed: {0}")]
    Request(#[from] reqwest::Error),

    /// Rate limited by the router's abuse limiter. Carries the seconds the
    /// client should wait before retrying.
    #[error("rate limited; retry in {retry_after_secs}s")]
    Throttled { retry_after_secs: u64 },

    /// The rate limiter's Redis backend is unavailable. Fail-closed (503) to
    /// match the limiter's own contract — see `abuse_limiter.rs`.
    #[error("mail rate limiter unavailable")]
    LimiterUnavailable,

    /// The recipient is on the suppression list and this send path surfaces it
    /// (the admin/manual path). Transactional paths swallow suppression
    /// silently, so this variant carries NO recipient (PII hygiene).
    #[error("recipient suppressed")]
    Suppressed,

    #[error("invalid recipient: {0}")]
    InvalidRecipient(String),

    #[error("webhook verification failed: {0}")]
    WebhookVerification(String),

    #[error("{0}")]
    Other(String),
}

/// Narrow the shared [`rux_provider_core::FrameworkError`] (returned by
/// `ProviderRegistry` lookups) into [`MailError`], preserving mail's exact
/// error variant + message conventions — in particular a missing provider
/// stays `MailError::Config("mail provider '{name}' not initialized")` (drift
/// point #1 vs billing, which uses a different mapping for its webhook path).
impl From<rux_provider_core::FrameworkError> for MailError {
    fn from(err: rux_provider_core::FrameworkError) -> Self {
        match err {
            rux_provider_core::FrameworkError::ProviderNotRegistered(name) => {
                MailError::Config(format!("mail provider '{name}' not initialized"))
            }
            rux_provider_core::FrameworkError::Config(msg) => MailError::Config(msg),
            rux_provider_core::FrameworkError::ProviderApi(msg) => MailError::ProviderApi(msg),
            rux_provider_core::FrameworkError::Other(msg) => MailError::Other(msg),
        }
    }
}
