//! Domain-free plumbing shared by the mail and billing provider stacks.
//!
//! ## Scope rule
//! This crate owns ONLY provider-agnostic plumbing:
//! - the [`WebhookEvent`] envelope (copied field-for-field between the two
//!   domains before extraction),
//! - the [`Provider`] marker supertrait (carrying only `provider_name()`),
//! - the generic [`ProviderRegistry<P>`] (the `HashMap<String, Arc<P>>` +
//!   `get`/`has`/`names` trio both routers duplicated),
//! - the shared [`FrameworkError`] base, and
//! - the `providers()` map accessor a domain router exposes to its own
//!   selection logic (e.g. billing's `GeoRouter`).
//!
//! **Nothing domain-specific crosses into this crate.** In particular:
//! `ParsedMailEvent` / `ParsedWebhook`, the `canonical` vocabularies, all
//! domain IO types (`OutboundEmail` / `SendReceipt` / `CheckoutSession` / ...),
//! `MailError` / `BillingError` (which convert *from* [`FrameworkError`] but
//! stay defined in-domain), the `MailRouter` / `BillingRouter` send/checkout
//! guards, and `GeoRouter`'s geo rule logic all remain in their domains. The
//! domain traits stay parametric on the consumer side: `MailProvider` and
//! `BillingProvider` become `: Provider` subtraits but keep their own
//! domain-typed operations.

#![forbid(unsafe_code)]

mod error;
mod event;
mod provider;
mod registry;

pub use error::FrameworkError;
pub use event::WebhookEvent;
pub use provider::Provider;
pub use registry::ProviderRegistry;
