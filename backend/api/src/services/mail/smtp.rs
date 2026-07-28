use std::env;

use async_trait::async_trait;
use lettre::message::header::ContentType;
use lettre::{
    transport::smtp::authentication::Credentials, AsyncSmtpTransport, AsyncTransport, Message,
    Tokio1Executor,
};
use tracing::instrument;

use super::provider::{MailError, MailProvider, OutboundEmail, SendReceipt};

/// Default to STARTTLS (port 587) unless an implicit-TLS mode is requested.
const TLS_MODE_IMPLICIT: &str = "tls";

/// Resolve the desired TLS mode for the SMTP transport.
///
/// Implicit TLS (SMTPS, port 465) is selected when either:
///   - `SMTP_TLS_MODE=tls` is set, or
///   - `SMTP_PORT=465` is set.
///
/// Otherwise the transport falls back to the existing STARTTLS (port 587)
/// behaviour via `starttls_relay`.
///
/// Reading `SMTP_PORT` here does not change the underlying relay port that
/// lettre selects (`relay`/`starttls_relay` pin 465/587 respectively); it is
/// only consulted to detect the implicit-TLS intent.
fn use_implicit_tls() -> bool {
    if let Ok(mode) = env::var("SMTP_TLS_MODE") {
        if mode.eq_ignore_ascii_case(TLS_MODE_IMPLICIT) {
            return true;
        }
    }
    matches!(env::var("SMTP_PORT").ok().as_deref(), Some("465"))
}

/// Build the shared SMTP transport from `SMTP_*` env vars. Panics (boot-fail)
/// when `MAIL_PROVIDER=smtp` and any required var is missing — fail-loud is the
/// current contract, preserved by the provider selector in `main.rs`.
#[instrument(name = "smtp_connection_init")]
pub async fn create_connection() -> AsyncSmtpTransport<Tokio1Executor> {
    let host = env::var("SMTP_HOST").expect("SMTP_HOST must be set");
    let username = env::var("SMTP_USERNAME").expect("SMTP_USERNAME must be set");
    let password = env::var("SMTP_PASSWORD").expect("SMTP_PASSWORD must be set");

    let implicit_tls = use_implicit_tls();
    tracing::info!(
        smtp_host = %host,
        smtp_user = %username,
        tls_mode = if implicit_tls { "implicit(tls/465)" } else { "starttls(587)" },
        "Initializing SMTP transport"
    );

    let creds = Credentials::new(username, password);

    // Select the transport based on the configured TLS mode:
    //   - implicit TLS (SMTPS, port 465): a full TLS connection is established
    //     up-front via `relay` (Tls::Wrapper). Use this when SMTP_TLS_MODE=tls
    //     or SMTP_PORT=465.
    //   - otherwise: STARTTLS upgrade over a plain connection via
    //     `starttls_relay` (the original behaviour).
    let transport = if implicit_tls {
        AsyncSmtpTransport::<Tokio1Executor>::relay(&host)
            .expect("failed to build implicit-TLS SMTP transport")
    } else {
        AsyncSmtpTransport::<Tokio1Executor>::starttls_relay(&host)
            .expect("failed to build STARTTLS SMTP transport")
    }
    .credentials(creds)
    .build();

    tracing::info!("SMTP transport built");
    transport
}

/// SMTP [`MailProvider`]. Wraps a pre-built lettre transport and the verified
/// sender address; the router records telemetry after delegation, so `send`
/// does not touch `mail_metrics` itself.
pub struct SmtpMailProvider {
    transport: AsyncSmtpTransport<Tokio1Executor>,
    from_address: String,
    from_name: Option<String>,
}

impl SmtpMailProvider {
    pub fn new(
        transport: AsyncSmtpTransport<Tokio1Executor>,
        from_address: String,
        from_name: Option<String>,
    ) -> Self {
        Self {
            transport,
            from_address,
            from_name,
        }
    }

    /// Compose the RFC 5322 `From` header value for the configured sender.
    fn sender_header(&self) -> String {
        match &self.from_name {
            Some(name) if !name.trim().is_empty() => {
                format!("{name} <{}>", self.from_address)
            }
            _ => self.from_address.clone(),
        }
    }
}

#[async_trait]
impl MailProvider for SmtpMailProvider {
    fn provider_name(&self) -> &'static str {
        "smtp"
    }

    async fn send(&self, msg: OutboundEmail) -> Result<SendReceipt, MailError> {
        let from = self.sender_header().parse().map_err(|e| {
            MailError::Config(format!(
                "invalid sender address '{value}': {e}",
                value = self.from_address
            ))
        })?;
        let to = msg
            .to
            .parse()
            .map_err(|_| MailError::InvalidRecipient("invalid recipient address".to_string()))?;

        let (content_type, body) = match (&msg.html, &msg.text) {
            (Some(html), _) => (ContentType::TEXT_HTML, html.clone()),
            (None, Some(text)) => (ContentType::TEXT_PLAIN, text.clone()),
            (None, None) => (ContentType::TEXT_PLAIN, String::new()),
        };

        let email = Message::builder()
            .from(from)
            .to(to)
            .subject(msg.subject.as_str())
            .header(content_type)
            .body(body)
            .map_err(|e| MailError::ProviderApi(format!("failed to build message: {e}")))?;

        self.transport
            .send(email)
            .await
            .map_err(|e| MailError::ProviderApi(e.to_string()))?;

        // lettre confirms delivery synchronously: treat a successful send as
        // delivered. SMTP has no notion of synchronous permanent bounces.
        Ok(SendReceipt {
            delivered: 1,
            queued: 0,
            permanent_bounces: Vec::new(),
        })
    }
}
