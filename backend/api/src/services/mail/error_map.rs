//! Maps a [`MailError`] to a client-safe [`ErrorResponse`].
//!
//! Callers route every client-facing mail error through [`mail_error_to_response`]
//! rather than feeding a raw `MailError` to `with_details`/`with_context` —
//! `MailError` is neither `Serialize` nor `Into<String>`, and its `ProviderApi`
//! payload can echo the recipient address (PII) from the provider's error body.
//! Client messages are deliberately generic; the raw detail stays in server
//! `tracing` logs (the call sites already log it).

use crate::error::{ErrorCode, ErrorResponse};

use super::provider::MailError;

/// Convert a [`MailError`] into a scrubbed [`ErrorResponse`].
pub fn mail_error_to_response(err: &MailError) -> ErrorResponse {
    match err {
        MailError::Throttled { retry_after_secs } => ErrorResponse::new(ErrorCode::RateLimited)
            .with_message("Too many email requests, please try again later")
            .with_retry_after(*retry_after_secs),
        MailError::LimiterUnavailable => ErrorResponse::new(ErrorCode::ServiceUnavailable)
            .with_message("Mail rate limiter temporarily unavailable"),
        // Carries no recipient by construction (PII hygiene).
        MailError::Suppressed => {
            ErrorResponse::new(ErrorCode::EmailSuppressed).with_message("Email delivery suppressed")
        }
        MailError::InvalidRecipient(_) => ErrorResponse::new(ErrorCode::InvalidEmailFormat)
            .with_message("Invalid recipient email address"),
        MailError::Config(_) => ErrorResponse::new(ErrorCode::ConfigurationError)
            .with_message("Email service is not configured"),
        MailError::WebhookVerification(_) => {
            ErrorResponse::new(ErrorCode::Unauthorized).with_message("Webhook verification failed")
        }
        // Generic client message; raw provider body stays in server logs only.
        MailError::ProviderApi(_) | MailError::Request(_) | MailError::Other(_) => {
            ErrorResponse::new(ErrorCode::ExternalServiceError)
                .with_message("The email could not be sent")
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn throttled_maps_to_429_with_retry_after() {
        let r = mail_error_to_response(&MailError::Throttled {
            retry_after_secs: 42,
        });
        assert_eq!(r.code, ErrorCode::RateLimited);
        assert_eq!(r.retry_after, Some(42));
    }

    #[test]
    fn suppressed_maps_to_422_and_carries_no_recipient() {
        let r = mail_error_to_response(&MailError::Suppressed);
        assert_eq!(r.code, ErrorCode::EmailSuppressed);
        // The variant itself holds no address; the message must not embed one.
        assert!(!r.message.contains('@'));
    }

    #[test]
    fn provider_api_message_is_generic_no_pii() {
        let r = mail_error_to_response(&MailError::ProviderApi(
            "boom for victim@example.com".to_string(),
        ));
        assert_eq!(r.code, ErrorCode::ExternalServiceError);
        assert!(!r.message.contains("victim@example.com"));
    }

    #[test]
    fn invalid_recipient_maps_to_400() {
        let r = mail_error_to_response(&MailError::InvalidRecipient("bad".to_string()));
        assert_eq!(r.code, ErrorCode::InvalidEmailFormat);
    }
}
