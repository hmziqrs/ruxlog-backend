//! Multi-provider mail router with the cross-cutting send-time guards.
//!
//! `MailRouter` holds the initialized [`MailProvider`]s and, unlike the billing
//! router, also owns the Redis pool + DB connection so the four guards run in
//! exactly one place for every provider:
//! 1. recipient canonicalization + RFC-5321 validation (header-injection safe),
//! 2. suppression-list pre-check (fail-open on DB error),
//! 3. per-recipient + provider-quota rate limiting (fail-closed on Redis error;
//!    skipped for transactional templates already bounded at the controller),
//! 4. content dedup (newsletter only).
//!
//! It then delegates to the selected provider, records telemetry once, and feeds
//! synchronous permanent bounces back into the suppression list. Mirrors
//! `services::billing::router::BillingRouter`.

use std::sync::Arc;

use async_trait::async_trait;
use chrono::Utc;
use rux_provider_core::ProviderRegistry;
use sea_orm::DatabaseConnection;
use sha2::{Digest, Sha256};
use tower_sessions_redis_store::fred::prelude::Pool as RedisPool;
use tracing::{debug, instrument, warn};

use crate::db::sea_models::email_suppression::{Entity as SuppressionEntity, SuppressionUpsert};
use crate::services::abuse_limiter::{self, AbuseLimiterConfig, LimiterDecision};
use crate::utils::telemetry;
use ruxlog_types::enums::SuppressionReason;

use super::provider::{
    is_transactional, MailError, MailProvider, OutboundEmail, ParsedMailEvent, SendReceipt,
    WebhookEvent, TEMPLATE_NEWSLETTER,
};

// ── Rate-limit budgets ───────────────────────────────────────────────────
// Tunable constants (deliberately not env knobs to keep the surface small).
// `temp_*` is the short burst window; `block_*` is the sustained window, mirroring
// every other AbuseLimiterConfig in the codebase.

/// Per-recipient outbound budget: 5 sends / 10 min, else a 1h block.
pub const MAIL_RCPT_CFG: AbuseLimiterConfig = AbuseLimiterConfig {
    temp_block_attempts: 5,
    temp_block_range: 10 * 60,
    temp_block_duration: 60 * 60,
    block_retry_limit: 30,
    block_range: 24 * 60 * 60,
    block_duration: 24 * 60 * 60,
};

/// Provider-quota outbound budget: bounds total blast volume (e.g. a newsletter
/// send) against the upstream per-minute limit. 50 / min, else a 5 min block.
pub const MAIL_PROVIDER_CFG: AbuseLimiterConfig = AbuseLimiterConfig {
    temp_block_attempts: 50,
    temp_block_range: 60,
    temp_block_duration: 5 * 60,
    block_retry_limit: 500,
    block_range: 60 * 60,
    block_duration: 60 * 60,
};

/// Bundled router limits so `MailRouter::new` stays under clippy's
/// `too_many_arguments` threshold.
#[derive(Clone)]
pub struct MailRouterLimits {
    pub rcpt: AbuseLimiterConfig,
    pub provider: AbuseLimiterConfig,
    /// TTL for the content-dedup key, in seconds.
    pub dedup_ttl_secs: usize,
    /// How long a soft (non-permanent) bounce suppresses a recipient, in seconds.
    pub soft_cooldown_secs: i64,
}

impl Default for MailRouterLimits {
    fn default() -> Self {
        Self {
            rcpt: MAIL_RCPT_CFG,
            provider: MAIL_PROVIDER_CFG,
            dedup_ttl_secs: 300,
            soft_cooldown_secs: 24 * 60 * 60,
        }
    }
}

pub struct MailRouter {
    registry: ProviderRegistry<dyn MailProvider>,
    redis_pool: RedisPool,
    db: DatabaseConnection,
    limits: MailRouterLimits,
    rate_limit_enabled: bool,
}

impl MailRouter {
    pub fn new(
        providers: std::collections::HashMap<String, Arc<dyn MailProvider>>,
        default_provider: String,
        redis_pool: RedisPool,
        db: DatabaseConnection,
        limits: MailRouterLimits,
        rate_limit_enabled: bool,
    ) -> Self {
        Self {
            registry: ProviderRegistry::new(providers, default_provider),
            redis_pool,
            db,
            limits,
            rate_limit_enabled,
        }
    }

    /// Names of the registered providers (diagnostics).
    pub fn provider_names(&self) -> Vec<&str> {
        self.registry.provider_names()
    }

    fn get_provider(&self, name: &str) -> Result<&Arc<dyn MailProvider>, MailError> {
        // Forwarded to the shared registry; FrameworkError is narrowed back to
        // MailError::Config("mail provider '{name}' not initialized") by the
        // From-impl in provider.rs — preserving the exact pre-refactor error
        // variant + message (drift point #1 vs billing).
        self.registry.get(name).map_err(MailError::from)
    }

    /// `Ok(true)` if `recipient` must be suppressed. `Err(())` on a DB error →
    /// the caller fails OPEN (a suppression outage must not blackhole all OTP
    /// sends) and bumps the `suppression_check_failed` counter.
    async fn lookup_suppressed(&self, recipient: &str) -> Result<bool, ()> {
        let row = match SuppressionEntity::find_by_recipient(&self.db, recipient).await {
            Ok(m) => m,
            Err(e) => {
                // PII: log only the recipient domain, never the full address.
                let domain = recipient.split('@').nth(1).unwrap_or("unknown");
                warn!(error = %e, %domain, "suppression lookup failed (fail-open)");
                return Err(());
            }
        };
        let Some(row) = row else {
            return Ok(false);
        };
        let now = Utc::now().timestamp();
        let within_cooldown = now - row.last_seen.timestamp() <= self.limits.soft_cooldown_secs;
        Ok(row.permanent || (row.reason == SuppressionReason::Bounce && within_cooldown))
    }

    /// Enforce per-recipient + provider-quota buckets. Fail-closed (503) on a
    /// Redis eval error — the limiter itself returns 503 for the same case.
    async fn check_rate(&self, recipient: &str) -> Result<(), MailError> {
        self.enforce(&format!("mail:send:rcpt:{recipient}"), self.limits.rcpt)
            .await?;
        self.enforce(
            &format!("mail:send:provider:{}", self.registry.default_provider()),
            self.limits.provider,
        )
        .await?;
        Ok(())
    }

    async fn enforce(&self, key: &str, cfg: AbuseLimiterConfig) -> Result<(), MailError> {
        match rux_request_gate::check(&self.redis_pool, &abuse_limiter::TelemetryHooks, key, cfg).await {
            Ok(LimiterDecision::Allowed { .. }) => Ok(()),
            Ok(LimiterDecision::Blocked {
                retry_after_secs, ..
            }) => {
                telemetry::mail_router_metrics().throttled.add(1, &[]);
                Err(MailError::Throttled { retry_after_secs })
            }
            Err(e) => {
                warn!(error = %e, %key, "mail rate limiter Redis error (fail-closed 503)");
                Err(MailError::LimiterUnavailable)
            }
        }
    }

    /// Best-effort release of a dedup claim so a failed send (throttle / provider
    /// error) can be retried within the window instead of being suppressed as a
    /// duplicate. Fail-open: a Redis blip just leaves the key to TTL (worst case
    /// a near-term retry is deduped; the next send after the TTL proceeds).
    async fn release_dedup(&self, key: Option<&str>) {
        if let Some(key) = key {
            rux_request_gate::release_dedup(&self.redis_pool, key).await;
        }
    }

    fn dedup_key(&self, msg: &OutboundEmail) -> String {
        let mut h = Sha256::new();
        h.update(msg.to.as_bytes());
        h.update(msg.subject.as_bytes());
        if let Some(b) = &msg.html {
            h.update(b.as_bytes());
        }
        if let Some(b) = &msg.text {
            h.update(b.as_bytes());
        }
        let digest = hex::encode(h.finalize());
        format!("mail:dedup:{}:{digest}", msg.template.unwrap_or("default"))
    }

    /// Record synchronous permanent bounces from the provider receipt into the
    /// suppression list. This is the core deliverability guarantee: a recipient
    /// the provider already rejected permanently is never tried again.
    async fn record_sync_bounces(&self, provider_name: &str, bounces: &[String]) {
        let router_metrics = telemetry::mail_router_metrics();
        for rcpt in bounces {
            let canonical = canonicalize_recipient(rcpt).unwrap_or_else(|_| rcpt.clone());
            let upsert = SuppressionUpsert {
                reason: SuppressionReason::Bounce,
                source: Some(format!("{provider_name}-send-sync")),
                diagnostic: None,
                permanent: true,
            };
            match SuppressionEntity::upsert(&self.db, &canonical, upsert).await {
                Ok(_) => router_metrics.bounced_sync.add(1, &[]),
                Err(e) => warn!(error = %e, "failed to upsert sync-bounce suppression"),
            }
        }
    }
}

#[async_trait]
impl MailProvider for MailRouter {
    fn provider_name(&self) -> &'static str {
        "router"
    }

    #[instrument(skip(self, msg), fields(provider = %self.registry.default_provider(), recipient_domain, result))]
    async fn send(&self, msg: OutboundEmail) -> Result<SendReceipt, MailError> {
        let metrics = telemetry::mail_metrics();
        let router_metrics = telemetry::mail_router_metrics();
        let start = std::time::Instant::now();

        // (1) Canonicalize + validate the recipient (header-injection safe).
        let mut msg = msg;
        msg.to = canonicalize_recipient(&msg.to)?;
        let recipient_domain = msg.to.split('@').nth(1).unwrap_or("unknown");
        tracing::Span::current().record("recipient_domain", recipient_domain);

        let transactional = is_transactional(msg.template);

        // (2) Suppression pre-check (fail-open on DB error).
        let suppressed = match self.lookup_suppressed(&msg.to).await {
            Ok(true) => true,
            Ok(false) => false,
            Err(()) => {
                router_metrics.suppression_check_failed.add(1, &[]);
                false
            }
        };
        if suppressed {
            router_metrics.suppressed.add(1, &[]);
            if transactional {
                // Anti account-enumeration: drop silently, look identical to a
                // successful send from the client's perspective.
                debug!(template = ?msg.template, "suppressed transactional send dropped");
                return Ok(SendReceipt::default());
            }
            return Err(MailError::Suppressed);
        }

        // (3) Content dedup — newsletter only, and BEFORE rate-limiting so a true
        // duplicate within the window short-circuits without burning a
        // provider-quota token (otherwise re-submitting a blast self-DoSes all
        // non-transactional mail). The claim is RELEASED on any later failure
        // (rate-limit throttle or provider error) so a throttled send can be
        // retried rather than silently dropped as a "duplicate" — dedup marks
        // *delivered* content, not merely *attempted* content. Transactional
        // codes change each request, so dedup is a no-op there.
        let dedup_claim = if msg.template == Some(TEMPLATE_NEWSLETTER) {
            let key = self.dedup_key(&msg);
            if rux_request_gate::dedup_nx(&self.redis_pool, &key, self.limits.dedup_ttl_secs).await
            {
                Some(key) // newly claimed -> proceed, release on failure
            } else {
                // Already delivered within the window -> short-circuit.
                router_metrics.deduped.add(1, &[]);
                debug!("duplicate newsletter send suppressed");
                return Ok(SendReceipt::default());
            }
        } else {
            None
        };

        // (4) Rate limiting — skipped for transactional templates (the controller
        // already bounds them, keyed on user_id, so this avoids a double-limit
        // with a different error code).
        if self.rate_limit_enabled && !transactional {
            if let Err(e) = self.check_rate(&msg.to).await {
                self.release_dedup(dedup_claim.as_deref()).await;
                return Err(e);
            }
        }

        // (5) Delegate to the selected provider.
        let provider = self.get_provider(self.registry.default_provider())?;
        let provider_name = provider.provider_name();
        let receipt = match provider.send(msg).await {
            Ok(r) => r,
            Err(e) => {
                metrics.emails_failed.add(1, &[]);
                tracing::Span::current().record("result", "failure");
                // Release the dedup claim so this (failed) send can be retried
                // within the window instead of being suppressed as a duplicate.
                self.release_dedup(dedup_claim.as_deref()).await;
                return Err(e);
            }
        };

        metrics.emails_sent.add(1, &[]);
        metrics
            .send_duration
            .record(start.elapsed().as_millis() as f64, &[]);
        tracing::Span::current().record("result", "success");

        // (6) Feed synchronous permanent bounces back into the suppression list.
        if !receipt.permanent_bounces.is_empty() {
            self.record_sync_bounces(provider_name, &receipt.permanent_bounces)
                .await;
        }

        Ok(receipt)
    }

    async fn verify_webhook(&self, event: WebhookEvent) -> Result<ParsedMailEvent, MailError> {
        // Uniform webhook dispatch through the shared registry. A missing
        // provider narrows to MailError::Config("mail provider '{name}' not
        // initialized") via the From-impl — PRESERVES drift point #1 (mail
        // surfaces registry misses as Config, billing surfaces them as
        // WebhookVerification in its own verify_webhook).
        let provider = self.registry.get_for_webhook(&event).map_err(MailError::from)?;
        provider.verify_webhook(event).await
    }
}

/// Canonicalize + validate a single recipient mailbox. Trims and lowercases,
/// rejects CR/LF (header injection), comma/semicolon/angle-brackets (multiple or
/// display-name addresses), and anything without exactly one `@` with non-empty
/// local + domain. Both providers get the same validation (lettre's mailbox
/// parser would otherwise cover only the SMTP path).
pub fn canonicalize_recipient(input: &str) -> Result<String, MailError> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return Err(MailError::InvalidRecipient(
            "recipient is empty".to_string(),
        ));
    }
    if trimmed.contains('\r') || trimmed.contains('\n') {
        return Err(MailError::InvalidRecipient(
            "recipient must not contain line breaks".to_string(),
        ));
    }
    if trimmed.contains(',')
        || trimmed.contains(';')
        || trimmed.contains('<')
        || trimmed.contains('>')
    {
        return Err(MailError::InvalidRecipient(
            "recipient must be a single mailbox without display name".to_string(),
        ));
    }
    let lower = trimmed.to_lowercase();
    match lower.split_once('@') {
        Some((local, domain))
            if !local.is_empty() && !domain.is_empty() && !domain.contains('@') =>
        {
            Ok(lower)
        }
        _ => Err(MailError::InvalidRecipient(
            "recipient is not a valid email address".to_string(),
        )),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn canonicalize_trims_and_lowercases() {
        assert_eq!(
            canonicalize_recipient("  Foo@Example.COM ").unwrap(),
            "foo@example.com"
        );
    }

    #[test]
    fn canonicalize_rejects_header_injection() {
        assert!(canonicalize_recipient("a@b.com\r\nBcc: x@y.com").is_err());
        assert!(canonicalize_recipient("a\n@b.com").is_err());
    }

    #[test]
    fn canonicalize_rejects_multiple_or_displayname() {
        assert!(canonicalize_recipient("a@b.com,c@d.com").is_err());
        assert!(canonicalize_recipient("Name <a@b.com>").is_err());
        assert!(canonicalize_recipient("a@b.com;d@c.com").is_err());
    }

    #[test]
    fn canonicalize_rejects_malformed() {
        assert!(canonicalize_recipient("noatsign").is_err());
        assert!(canonicalize_recipient("@b.com").is_err()); // empty local
        assert!(canonicalize_recipient("a@").is_err()); // empty domain
        assert!(canonicalize_recipient("a@@b.com").is_err()); // two @
        assert!(canonicalize_recipient("   ").is_err());
    }
}
