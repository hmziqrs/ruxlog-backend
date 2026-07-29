//! Generic provider registry + the outbound selection contract.

use std::collections::HashMap;
use std::sync::Arc;

use crate::error::FrameworkError;
use crate::event::WebhookEvent;
use crate::provider::Provider;

/// Map of initialized providers keyed by name, plus the default provider name.
///
/// Generic over `P: ?Sized + Provider` so each domain instantiates it once as
/// `ProviderRegistry<dyn MailProvider>` / `ProviderRegistry<dyn BillingProvider>`
/// while sharing a single lookup/iteration implementation. Domain routers
/// compose this rather than re-implementing the `HashMap` + `get` / `has` /
/// `names` trio.
///
/// The `?Sized` bound is what lets `P` be a `dyn Trait` object — `Arc<dyn P>`
/// is itself sized, so `get` returns a usable `&Arc<P>`.
pub struct ProviderRegistry<P: ?Sized + Provider> {
    providers: HashMap<String, Arc<P>>,
    default_provider: String,
}

impl<P: ?Sized + Provider> ProviderRegistry<P> {
    pub fn new(providers: HashMap<String, Arc<P>>, default_provider: String) -> Self {
        Self {
            providers,
            default_provider,
        }
    }

    /// Look up a provider by name. `Err(FrameworkError::ProviderNotRegistered)`
    /// when absent — the caller (a domain router) maps this to its domain
    /// error, preserving that domain's error variant and message conventions.
    pub fn get(&self, name: &str) -> Result<&Arc<P>, FrameworkError> {
        self.providers
            .get(name)
            .ok_or_else(|| FrameworkError::ProviderNotRegistered(name.to_string()))
    }

    /// The default provider (the one outbound sends/checkouts route to when no
    /// override/geo rule selects otherwise).
    pub fn get_default(&self) -> Result<&Arc<P>, FrameworkError> {
        let name = self.default_provider.clone();
        self.get(&name)
    }

    /// Uniform webhook-dispatch lookup: resolve the provider named in the
    /// event envelope. Both domain routers' `verify_webhook` go through this.
    pub fn get_for_webhook(&self, event: &WebhookEvent) -> Result<&Arc<P>, FrameworkError> {
        let name = event.provider.clone();
        self.get(&name)
    }

    /// `true` if a provider is registered under `name`.
    pub fn has_provider(&self, name: &str) -> bool {
        self.providers.contains_key(name)
    }

    /// Names of the registered providers (diagnostics). Unordered.
    pub fn provider_names(&self) -> Vec<&str> {
        self.providers.keys().map(|s| s.as_str()).collect()
    }

    /// The default provider name.
    pub fn default_provider(&self) -> &str {
        &self.default_provider
    }

    /// Read-only access to the underlying map — e.g. so a domain's own
    /// routing logic (such as billing's `GeoRouter`, which is NOT in this
    /// crate and does not implement any trait defined here) can iterate the
    /// available providers verbatim, including its skip-uninitialized-provider
    /// behavior.
    pub fn providers(&self) -> &HashMap<String, Arc<P>> {
        &self.providers
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    struct Dummy;

    // Local test-only provider trait (mirrors how the mail/billing domains
    // declare their own provider trait + opt its dyn into the Provider marker).
    trait TestProvider: Send + Sync {
        fn provider_name(&self) -> &'static str;
    }
    impl TestProvider for Dummy {
        fn provider_name(&self) -> &'static str {
            "dummy"
        }
    }
    impl Provider for dyn TestProvider {}

    fn reg() -> ProviderRegistry<dyn TestProvider> {
        let mut p: HashMap<String, Arc<dyn TestProvider>> = HashMap::new();
        p.insert("a".into(), Arc::new(Dummy));
        ProviderRegistry::new(p, "a".into())
    }

    #[test]
    fn get_returns_registered() {
        let r = reg();
        assert!(r.get("a").is_ok());
        assert_eq!(r.get("a").unwrap().provider_name(), "dummy");
    }

    #[test]
    fn get_missing_is_provider_not_registered() {
        let r = reg();
        match r.get("missing") {
            Err(e) => assert!(matches!(e, FrameworkError::ProviderNotRegistered(_))),
            Ok(_) => panic!("expected an error for the missing provider"),
        }
    }

    #[test]
    fn get_default_resolves() {
        let r = reg();
        assert!(r.get_default().is_ok());
    }

    #[test]
    fn has_provider_and_names() {
        let r = reg();
        assert!(r.has_provider("a"));
        assert!(!r.has_provider("b"));
        assert_eq!(r.provider_names(), vec!["a"]);
    }

    #[test]
    fn default_provider_accessor() {
        let r = reg();
        assert_eq!(r.default_provider(), "a");
    }

    #[test]
    fn providers_map_accessor() {
        let r = reg();
        assert!(r.providers().contains_key("a"));
    }

    #[test]
    fn get_for_webhook_resolves_envelope_provider() {
        let r = reg();
        let ev = WebhookEvent {
            provider: "a".into(),
            payload: Vec::new(),
            headers: http::HeaderMap::new(),
            query: None,
        };
        assert!(r.get_for_webhook(&ev).is_ok());
    }

    #[test]
    fn get_for_webhook_missing_is_provider_not_registered() {
        let r = reg();
        let ev = WebhookEvent {
            provider: "nope".into(),
            payload: Vec::new(),
            headers: http::HeaderMap::new(),
            query: None,
        };
        assert!(matches!(
            r.get_for_webhook(&ev),
            Err(FrameworkError::ProviderNotRegistered(_))
        ));
    }
}
