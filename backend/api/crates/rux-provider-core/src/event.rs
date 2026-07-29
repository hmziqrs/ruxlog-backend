//! The single [`WebhookEvent`] envelope shared by every provider domain.

/// Incoming webhook event from a provider.
///
/// Carries the **raw** request body and the **full** header set, because every
/// provider signs differently: Stripe/Paddle/Airwallex read timestamp+signature
/// pairs, PayPal needs five headers for its verify API, Mercado Pago uses
/// `x-signature` + `x-request-id`, Cloudflare Email signs the raw body. The
/// previous single-`signature` shape forced the controller to guess one header
/// per provider and dropped the rest. `query` is forwarded because Mercado
/// Pago's signature scheme signs over `data.id` taken from the webhook URL's
/// query string (not the body).
///
/// This is the one type both the mail and billing stacks duplicated
/// field-for-field; it lives here so the receiver/verifier path is uniform
/// across domains.
#[derive(Debug, Clone)]
pub struct WebhookEvent {
    /// Provider that sent this event.
    pub provider: String,
    /// Raw payload bytes (exactly as received — never re-encoded JSON).
    pub payload: Vec<u8>,
    /// All request headers; each provider reads the ones it needs.
    pub headers: http::HeaderMap,
    /// The raw URL query string of the incoming webhook request. `None` for
    /// providers/tests that don't use it.
    pub query: Option<String>,
}
