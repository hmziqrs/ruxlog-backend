//! The [`Provider`] marker trait.

/// Marker trait asserting "this is a provider object" — the bound used by
/// [`crate::ProviderRegistry`] so its generic parameter is provably a provider
/// dyn-trait rather than an arbitrary unsized type.
///
/// ## Why `provider_name()` is NOT on this trait
/// The original design plan called for `Provider` to carry `provider_name()`.
/// That does not compose with Rust's trait rules without a large blast radius:
/// - making `MailProvider: Provider` a supertrait requires every one of the 15
///   existing `impl <Domain>Provider for ...` blocks to add a separate
///   `impl Provider for ...` (supertrait methods cannot be defined inside the
///   subtrait's `impl` block), which violates the tight blast-radius goal
///   (the 13 leaf provider impl files + 2 controllers must stay unedited); and
/// - a blanket `impl<T: MailProvider> Provider for T` is rejected by the
///   orphan rule (E0210), since `Provider` is foreign and `T` is an uncovered
///   type parameter.
///
/// Instead, `provider_name()` stays declared on each domain trait
/// (`MailProvider`, `BillingProvider`), and each domain opts its dyn-trait into
/// this marker via an explicit `impl rux_provider_core::Provider for
/// dyn <Domain>Provider {}` (a `dyn LocalTrait` is a local type under the
/// orphan rule, so this is permitted). The result: the 15 leaf impls compile
/// unchanged, `obj.provider_name()` on a `dyn <Domain>Provider` stays
/// unambiguous, and `ProviderRegistry<dyn MailProvider>` still satisfies its
/// `P: Provider` bound.
pub trait Provider: Send + Sync {}
