//! Re-export of the webhook signature-verification primitives.
//!
//! The verification logic now lives in the standalone [`rux_webhook_crypto`]
//! crate — a pure crypto leaf with no ruxlog/SeaORM/AppState coupling, reusable
//! by external projects. This module re-exports its full public surface so the
//! existing `crate::services::webhook_util::*` import paths across the billing
//! providers and the mail webhook receiver keep compiling unchanged.
//!
//! `services::billing::webhook_util` re-exports these in turn for the billing
//! call sites that predate the promotion out of `billing`.
pub use rux_webhook_crypto::{
    ct_eq, header_str, hmac_sha256_hex, standard_webhooks_key, timestamp_fresh, verify_ed25519,
    verify_hmac_sha256_hex, verify_standard_webhooks, MAX_SKEW_SECS,
};
