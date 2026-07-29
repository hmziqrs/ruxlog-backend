//! Shared framework error base.

/// Domain-free error base for provider-framework operations (registry lookup,
/// webhook dispatch). This is the shared subset both `MailError` and
/// `BillingError` repeated; the domain error enums convert *from* this via a
/// domain-specific `From` impl that preserves the domain's error variant and
/// message conventions (e.g. mail maps `ProviderNotRegistered` to
/// `MailError::Config("mail provider '{name}' not initialized")`, billing
/// maps it to `BillingError::Config("Provider '{name}' not initialized")`).
///
/// The domain routers therefore never leak a `FrameworkError` across their
/// boundaries — it is always narrowed to the domain error at the call site.
#[derive(Debug, thiserror::Error)]
pub enum FrameworkError {
    #[error("configuration error: {0}")]
    Config(String),

    #[error("provider API error: {0}")]
    ProviderApi(String),

    /// No provider registered under the requested name (registry miss).
    #[error("provider '{0}' is not registered")]
    ProviderNotRegistered(String),

    #[error("{0}")]
    Other(String),
}
