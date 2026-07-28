//! Re-export of the always-on webhook verification primitives.
//!
//! These historically lived here under `billing`, which made them unreachable
//! from any feature that is not `billing` (the mail bounce/complaint webhook
//! receiver is one such consumer). They were promoted to the always-on
//! [`crate::services::webhook_util`] module so any feature can verify inbound
//! signatures without pulling in `billing`. This shim keeps the existing
//! `crate::services::billing::webhook_util::*` import paths working for the
//! billing providers unchanged.
pub use crate::services::webhook_util::{
    ct_eq, header_str, hmac_sha256_hex, standard_webhooks_key, timestamp_fresh, verify_ed25519,
    verify_hmac_sha256_hex, verify_standard_webhooks, MAX_SKEW_SECS,
};
