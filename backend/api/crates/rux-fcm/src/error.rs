//! Error type for the FCM client.

#[derive(Debug, thiserror::Error)]
pub enum FcmError {
    /// A required configuration value (service-account path/JSON) was missing
    /// or unreadable.
    #[error("missing config: {0}")]
    MissingConfig(String),

    /// Service-account / OAuth2 token-mint failure (bad JSON, bad key, token
    /// endpoint returned non-2xx).
    #[error("auth: {0}")]
    Auth(String),

    /// An upstream HTTP/transport failure.
    #[error("http: {0}")]
    Http(#[from] reqwest::Error),

    /// The FCM v1 endpoint responded with a non-success status.
    #[error("api {0}: {1}")]
    Api(u16, String),

    /// The target registration token is no longer valid (FCM reports
    /// `UNREGISTERED` / HTTP 404). Callers should prune the device row.
    #[error("token unregistered")]
    Unregistered,
}
