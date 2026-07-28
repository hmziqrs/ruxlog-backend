//! Cloudflare Email Sending [`MailProvider`].
//!
//! Posts to `POST {base}/accounts/{account_id}/email/sending/send` (bearer
//! auth with the API token) and parses the recipient-grouped delivery status
//! (`delivered` / `queued` / `permanent_bounces`). Synchronous
//! `permanent_bounces` are returned in the [`SendReceipt`] so the router can
//! upsert suppression rows. The inbound `verify_webhook` authenticates an
//! **operator-owned** envelope (a Cloudflare Worker that consumes the Email
//! Service event Queue and re-POSTs under a shared HMAC secret — Cloudflare
//! does not natively POST signed email events).

use async_trait::async_trait;
use secrecy::{ExposeSecret, SecretString};
use serde::{Deserialize, Serialize};

use crate::services::webhook_util;

use super::provider::{
    canonical, MailError, MailProvider, OutboundEmail, ParsedMailEvent, SendReceipt, WebhookEvent,
};
use super::router::canonicalize_recipient;

/// Cloudflare Email Sending provider. `api_token` + `webhook_secret` are
/// `SecretString` (redacting `Debug`); `expose_secret()` is used only at the
/// HTTP / signing call sites.
#[derive(Debug)]
pub struct CloudflareMailProvider {
    account_id: String,
    api_token: SecretString,
    webhook_secret: SecretString,
    endpoint: String,
    from_address: String,
    from_name: Option<String>,
    http_client: reqwest::Client,
    /// Optional sandbox allowlist (`CLOUDFLARE_EMAIL_ALLOWED_ADDRESSES`); when
    /// set, sends to any recipient not on the list are refused.
    allowed_addresses: Option<Vec<String>>,
}

impl CloudflareMailProvider {
    /// Build from resolved config. Fails (returns `MailError::Config`) on a
    /// missing/empty required field; the boot selector in `main.rs` panics on
    /// that so a misconfigured `MAIL_PROVIDER=cloudflare` fails loud.
    #[allow(clippy::too_many_arguments)]
    pub fn new(
        account_id: String,
        api_token: SecretString,
        webhook_secret: SecretString,
        base_url: String,
        from_address: String,
        from_name: Option<String>,
        http_client: reqwest::Client,
        allowed_addresses: Option<Vec<String>>,
    ) -> Result<Self, MailError> {
        if account_id.trim().is_empty() {
            return Err(MailError::Config(
                "CLOUDFLARE_EMAIL_ACCOUNT_ID cannot be empty".to_string(),
            ));
        }
        if api_token.expose_secret().is_empty() {
            return Err(MailError::Config(
                "CLOUDFLARE_EMAIL_API_TOKEN cannot be empty".to_string(),
            ));
        }
        if from_address.trim().is_empty() {
            return Err(MailError::Config(
                "MAIL_FROM_ADDRESS cannot be empty".to_string(),
            ));
        }
        let endpoint = format!(
            "{}/accounts/{account_id}/email/sending/send",
            base_url.trim_end_matches('/')
        );
        Ok(Self {
            account_id,
            api_token,
            webhook_secret,
            endpoint,
            from_address,
            from_name: from_name
                .map(|n| n.trim().to_string())
                .filter(|n| !n.is_empty()),
            http_client,
            allowed_addresses: allowed_addresses.map(|addrs| {
                addrs
                    .into_iter()
                    .map(|a| a.trim().to_lowercase())
                    .filter(|a| !a.is_empty())
                    .collect::<Vec<_>>()
            }),
        })
    }

    /// Compose the RFC 5322 `From` value (display name + address when a name is
    /// configured, else the bare address).
    fn sender_field(&self) -> String {
        match &self.from_name {
            Some(name) => format!("{name} <{}>", self.from_address),
            None => self.from_address.clone(),
        }
    }

    pub fn provider_id(&self) -> &str {
        &self.account_id
    }
}

#[async_trait]
impl MailProvider for CloudflareMailProvider {
    fn provider_name(&self) -> &'static str {
        "cloudflare"
    }

    async fn send(&self, msg: OutboundEmail) -> Result<SendReceipt, MailError> {
        // Sandbox allowlist (pre-prod safety).
        if let Some(allowed) = &self.allowed_addresses {
            if !allowed.iter().any(|a| a.eq_ignore_ascii_case(&msg.to)) {
                return Err(MailError::InvalidRecipient(
                    "recipient not in sandbox allowlist".to_string(),
                ));
            }
        }

        let from = self.sender_field();
        let body = CfSendRequest {
            to: msg.to.as_str(),
            from: from.as_str(),
            subject: msg.subject.as_str(),
            text: msg.text.as_deref(),
            html: msg.html.as_deref(),
        };

        let response = self
            .http_client
            .post(self.endpoint.as_str())
            .bearer_auth(self.api_token.expose_secret())
            .json(&body)
            .send()
            .await?;

        let status = response.status();
        let text = response.text().await?;

        let parsed: CfApiResponse<CfResult> = serde_json::from_str(&text).map_err(|e| {
            MailError::ProviderApi(format!(
                "Cloudflare returned invalid JSON (HTTP {}): {e}",
                status.as_u16()
            ))
        })?;

        if !status.is_success() || !parsed.success {
            let details = if parsed.errors.is_empty() {
                format!("HTTP {}", status.as_u16())
            } else {
                parsed
                    .errors
                    .iter()
                    .map(|e| format!("{}: {}", e.code, e.message))
                    .collect::<Vec<_>>()
                    .join(", ")
            };
            return Err(MailError::ProviderApi(details));
        }

        let result = parsed.result.unwrap_or_default();
        Ok(SendReceipt {
            delivered: result.delivered.len() as u32,
            queued: result.queued.len() as u32,
            permanent_bounces: result.permanent_bounces,
        })
    }

    async fn verify_webhook(&self, event: WebhookEvent) -> Result<ParsedMailEvent, MailError> {
        // Fail-closed: an unset secret rejects every event (no silent insecure mode).
        let secret = self.webhook_secret.expose_secret();
        if secret.is_empty() {
            return Err(MailError::WebhookVerification(
                "no webhook secret configured".to_string(),
            ));
        }

        // The timestamp is REQUIRED and bound into the signed message, so a
        // captured signed body cannot be replayed indefinitely (CWE-294). The
        // operator Worker signs HMAC-SHA256(secret, "{ts}.{body}") and sends the
        // same `ts` in `X-Mail-Webhook-Timestamp`.
        let ts_str = webhook_util::header_str(&event.headers, "x-mail-webhook-timestamp")
            .ok_or_else(|| {
                MailError::WebhookVerification("missing x-mail-webhook-timestamp".to_string())
            })?;
        let ts: i64 = ts_str.parse().map_err(|_| {
            MailError::WebhookVerification("non-numeric x-mail-webhook-timestamp".to_string())
        })?;
        let now = chrono::Utc::now().timestamp();
        if !webhook_util::timestamp_fresh(ts, now) {
            return Err(MailError::WebhookVerification(
                "stale webhook timestamp".to_string(),
            ));
        }

        let provided = event
            .headers
            .get("x-mail-webhook-signature")
            .and_then(|v| v.to_str().ok())
            .unwrap_or("");
        // Recompute the MAC over the exact signed message bytes: "{ts}.{body}".
        let mut signed: Vec<u8> = Vec::with_capacity(ts_str.len() + 1 + event.payload.len());
        signed.extend_from_slice(ts_str.as_bytes());
        signed.push(b'.');
        signed.extend_from_slice(&event.payload);
        if !webhook_util::verify_hmac_sha256_hex(secret.as_bytes(), &signed, provided) {
            return Err(MailError::WebhookVerification(
                "invalid signature".to_string(),
            ));
        }

        let raw: serde_json::Value = serde_json::from_slice(&event.payload)
            .map_err(|e| MailError::WebhookVerification(format!("invalid envelope JSON: {e}")))?;
        let env: CfMailEnvelope = serde_json::from_value(raw.clone())
            .map_err(|e| MailError::WebhookVerification(format!("invalid envelope: {e}")))?;

        let event_type = match env.event_type.as_str() {
            "bounced" => canonical::BOUNCED,
            "complained" => canonical::COMPLAINED,
            "delivered" => canonical::DELIVERED,
            other => {
                return Err(MailError::WebhookVerification(format!(
                    "unknown event type '{other}'"
                )))
            }
        }
        .to_string();

        // Strict: reject (do not store) a malformed recipient so an
        // un-enforceable row can't be written into email_suppression.
        let recipient = canonicalize_recipient(&env.recipient).map_err(|_| {
            MailError::WebhookVerification("invalid recipient in envelope".to_string())
        })?;

        Ok(ParsedMailEvent {
            // Complaints are always a permanent suppression.
            permanent: env.permanent || event_type == canonical::COMPLAINED,
            event_type,
            recipient,
            message_id: env.message_id,
            diagnostic: env.diagnostic,
            ts: env.ts,
            data: raw,
        })
    }
}

// ── Cloudflare Email Sending wire types ───────────────────────────────────

#[derive(Serialize)]
struct CfSendRequest<'a> {
    to: &'a str,
    from: &'a str,
    subject: &'a str,
    #[serde(skip_serializing_if = "Option::is_none")]
    text: Option<&'a str>,
    #[serde(skip_serializing_if = "Option::is_none")]
    html: Option<&'a str>,
}

#[derive(Deserialize)]
struct CfApiError {
    code: u32,
    message: String,
}

#[derive(Deserialize)]
struct CfApiResponse<T> {
    success: bool,
    #[serde(default)]
    errors: Vec<CfApiError>,
    result: Option<T>,
}

#[derive(Deserialize, Default)]
struct CfResult {
    #[serde(default)]
    delivered: Vec<String>,
    #[serde(default)]
    queued: Vec<String>,
    #[serde(default)]
    permanent_bounces: Vec<String>,
}

/// Our defined inbound envelope (the reference Worker POSTs this shape).
#[derive(Deserialize)]
struct CfMailEnvelope {
    event_type: String,
    recipient: String,
    message_id: Option<String>,
    diagnostic: Option<String>,
    #[serde(default)]
    permanent: bool,
    ts: Option<i64>,
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::services::mail::provider::{canonical, WebhookEvent};
    use axum::http::HeaderMap;
    use secrecy::SecretString;

    fn provider() -> CloudflareMailProvider {
        CloudflareMailProvider::new(
            "accid".to_string(),
            SecretString::from("tok".to_string()),
            SecretString::from("sec".to_string()),
            "https://api.cloudflare.com/client/v4".to_string(),
            "no-reply@example.com".to_string(),
            None,
            reqwest::Client::new(),
            None,
        )
        .unwrap()
    }

    #[test]
    fn rejects_empty_config() {
        let r = CloudflareMailProvider::new(
            String::new(),
            SecretString::from("t".to_string()),
            SecretString::from("s".to_string()),
            "https://x".to_string(),
            "f@x.com".to_string(),
            None,
            reqwest::Client::new(),
            None,
        );
        assert!(matches!(r, Err(MailError::Config(_))));
    }

    /// Sign `"{ts}.{body}"` with HMAC-SHA256 (the operator Worker's contract).
    fn sign(secret: &str, ts: &str, body: &[u8]) -> String {
        let mut msg = Vec::with_capacity(ts.len() + 1 + body.len());
        msg.extend_from_slice(ts.as_bytes());
        msg.push(b'.');
        msg.extend_from_slice(body);
        webhook_util::hmac_sha256_hex(secret.as_bytes(), &msg)
    }

    /// Build a validly-signed event with a fresh timestamp.
    fn signed_event(body: &[u8]) -> WebhookEvent {
        let ts = chrono::Utc::now().timestamp().to_string();
        let sig = sign("sec", &ts, body);
        let mut headers = HeaderMap::new();
        headers.insert("x-mail-webhook-signature", sig.parse().unwrap());
        headers.insert("x-mail-webhook-timestamp", ts.parse().unwrap());
        WebhookEvent {
            provider: "cloudflare".to_string(),
            payload: body.to_vec(),
            headers,
            query: None,
        }
    }

    #[tokio::test]
    async fn verify_webhook_accepts_valid_signature_and_canonicalizes() {
        let p = provider();
        let body =
            br#"{"event_type":"complained","recipient":"VICTIM@Example.com","permanent":false}"#;
        let parsed = p.verify_webhook(signed_event(body)).await.unwrap();
        assert_eq!(parsed.event_type, canonical::COMPLAINED);
        assert_eq!(parsed.recipient, "victim@example.com");
        // complaint forced permanent
        assert!(parsed.permanent);
    }

    #[tokio::test]
    async fn verify_webhook_rejects_bad_signature() {
        let p = provider();
        let body = br#"{"event_type":"delivered","recipient":"a@b.com"}"#;
        // Fresh timestamp, but a signature computed with the wrong secret.
        let ts = chrono::Utc::now().timestamp().to_string();
        let sig = sign("wrong-secret", &ts, body);
        let mut headers = HeaderMap::new();
        headers.insert("x-mail-webhook-signature", sig.parse().unwrap());
        headers.insert("x-mail-webhook-timestamp", ts.parse().unwrap());
        let ev = WebhookEvent {
            provider: "cloudflare".to_string(),
            payload: body.to_vec(),
            headers,
            query: None,
        };
        assert!(p.verify_webhook(ev).await.is_err());
    }

    #[tokio::test]
    async fn verify_webhook_failcloses_on_empty_secret() {
        let p = CloudflareMailProvider::new(
            "accid".to_string(),
            SecretString::from("tok".to_string()),
            SecretString::from(String::new()),
            "https://api.cloudflare.com/client/v4".to_string(),
            "no-reply@example.com".to_string(),
            None,
            reqwest::Client::new(),
            None,
        )
        .unwrap();
        let ev = WebhookEvent {
            provider: "cloudflare".to_string(),
            payload: b"{}".to_vec(),
            headers: HeaderMap::new(),
            query: None,
        };
        assert!(p.verify_webhook(ev).await.is_err());
    }

    #[tokio::test]
    async fn verify_webhook_rejects_stale_timestamp() {
        let p = provider();
        let body = br#"{"event_type":"bounced","recipient":"a@b.com","permanent":true}"#;
        // 1 hour ago — outside the ±5 min window.
        let stale = (chrono::Utc::now().timestamp() - 3600).to_string();
        let sig = sign("sec", &stale, body);
        let mut headers = HeaderMap::new();
        headers.insert("x-mail-webhook-signature", sig.parse().unwrap());
        headers.insert("x-mail-webhook-timestamp", stale.parse().unwrap());
        let ev = WebhookEvent {
            provider: "cloudflare".to_string(),
            payload: body.to_vec(),
            headers,
            query: None,
        };
        assert!(p.verify_webhook(ev).await.is_err());
    }

    #[tokio::test]
    async fn verify_webhook_rejects_missing_timestamp() {
        let p = provider();
        let body = br#"{"event_type":"bounced","recipient":"a@b.com","permanent":true}"#;
        // Signature header present but NO timestamp header -> reject (required).
        let sig = sign("sec", "0", body);
        let mut headers = HeaderMap::new();
        headers.insert("x-mail-webhook-signature", sig.parse().unwrap());
        let ev = WebhookEvent {
            provider: "cloudflare".to_string(),
            payload: body.to_vec(),
            headers,
            query: None,
        };
        assert!(p.verify_webhook(ev).await.is_err());
    }

    #[tokio::test]
    async fn verify_webhook_rejects_body_only_signature_replay() {
        // A body-only signature (the old, replayable contract) must NOT verify
        // now that the timestamp is bound into the signed message — proves a
        // captured body-only signed payload can no longer be replayed.
        let p = provider();
        let body = br#"{"event_type":"bounced","recipient":"a@b.com","permanent":true}"#;
        let body_only_sig = webhook_util::hmac_sha256_hex(b"sec", body);
        let ts = chrono::Utc::now().timestamp().to_string();
        let mut headers = HeaderMap::new();
        headers.insert("x-mail-webhook-signature", body_only_sig.parse().unwrap());
        headers.insert("x-mail-webhook-timestamp", ts.parse().unwrap());
        let ev = WebhookEvent {
            provider: "cloudflare".to_string(),
            payload: body.to_vec(),
            headers,
            query: None,
        };
        assert!(p.verify_webhook(ev).await.is_err());
    }

    // ── send path (wiremock: real HTTP contract) ──────────────────────────

    #[tokio::test]
    async fn send_posts_bearer_json_and_parses_permanent_bounces() {
        use wiremock::matchers::{body_partial_json, header, method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/accounts/accid/email/sending/send"))
            .and(header("authorization", "Bearer tok"))
            .and(body_partial_json(serde_json::json!({
                "to": "victim@example.com",
                "from": "no-reply@example.com",
                "subject": "Hi",
            })))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": true,
                "errors": [],
                "result": {
                    "delivered": ["victim@example.com"],
                    "queued": [],
                    "permanent_bounces": ["bad@example.com"],
                }
            })))
            .expect(1)
            .mount(&server)
            .await;

        let p = CloudflareMailProvider::new(
            "accid".to_string(),
            SecretString::from("tok".to_string()),
            SecretString::from("sec".to_string()),
            server.uri(),
            "no-reply@example.com".to_string(),
            None,
            reqwest::Client::new(),
            None,
        )
        .unwrap();

        let receipt = p
            .send(OutboundEmail {
                to: "victim@example.com".to_string(),
                subject: "Hi".to_string(),
                html: Some("<p>hi</p>".to_string()),
                text: None,
                template: None,
            })
            .await
            .expect("send should succeed");

        assert_eq!(receipt.delivered, 1);
        assert_eq!(receipt.queued, 0);
        assert_eq!(
            receipt.permanent_bounces,
            vec!["bad@example.com".to_string()]
        );
    }

    #[tokio::test]
    async fn send_maps_cf_rejection_to_provider_api_error() {
        use wiremock::matchers::{method, path};
        use wiremock::{Mock, MockServer, ResponseTemplate};

        let server = MockServer::start().await;
        Mock::given(method("POST"))
            .and(path("/accounts/accid/email/sending/send"))
            .respond_with(ResponseTemplate::new(200).set_body_json(serde_json::json!({
                "success": false,
                "errors": [{ "code": 7103, "message": "invalid recipient" }],
                "result": null,
            })))
            .mount(&server)
            .await;

        let p = CloudflareMailProvider::new(
            "accid".to_string(),
            SecretString::from("tok".to_string()),
            SecretString::from("sec".to_string()),
            server.uri(),
            "no-reply@example.com".to_string(),
            None,
            reqwest::Client::new(),
            None,
        )
        .unwrap();

        let res = p
            .send(OutboundEmail {
                to: "x@example.com".to_string(),
                subject: "Hi".to_string(),
                html: None,
                text: Some("hi".to_string()),
                template: None,
            })
            .await;
        assert!(matches!(res, Err(MailError::ProviderApi(_))), "got {res:?}");
    }

    #[tokio::test]
    async fn send_rejects_recipient_not_in_sandbox_allowlist() {
        // No mock server: the allowlist short-circuits before any HTTP call.
        let p = CloudflareMailProvider::new(
            "accid".to_string(),
            SecretString::from("tok".to_string()),
            SecretString::from("sec".to_string()),
            "https://api.cloudflare.com/client/v4".to_string(),
            "no-reply@example.com".to_string(),
            None,
            reqwest::Client::new(),
            Some(vec!["allowed@example.com".to_string()]),
        )
        .unwrap();

        let res = p
            .send(OutboundEmail {
                to: "other@example.com".to_string(),
                subject: "Hi".to_string(),
                html: None,
                text: Some("hi".to_string()),
                template: None,
            })
            .await;
        assert!(
            matches!(res, Err(MailError::InvalidRecipient(_))),
            "got {res:?}"
        );
    }
}
