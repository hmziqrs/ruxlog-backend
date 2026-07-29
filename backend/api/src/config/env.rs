//! Consolidated environment-variable parsing helpers.
//!
//! Previously these lived as private functions inside `main.rs` (and a couple
//! were duplicated in `utils/telemetry.rs`). They are the single canonical
//! implementation now, used both by [`crate::config::Settings::from_env`] (the
//! typed config layer constructed once at boot) and by the remaining boot-time
//! wiring in `main.rs` that has not yet been migrated onto `Settings`
//! (mail/billing/FCM/image-moderation provider construction — phase 2/3).
//!
//! All helpers are fail-open with explicit defaults; the fail-closed
//! (`expect`/panic) decisions live at the call sites that know which variable
//! is mandatory (e.g. `ObjectStorageConfig::from_env`, `Settings::from_env`).

use std::env;

/// Parse a boolean env var. Recognizes `1|true|yes|on` (true) and
/// `0|false|no|off` (false), case-insensitively; any other value (including a
/// malformed one) falls back to `default`. Unset -> `default`.
pub fn env_bool(key: &str, default: bool) -> bool {
    env::var(key)
        .ok()
        .and_then(|value| {
            let normalized = value.trim().to_ascii_lowercase();
            match normalized.as_str() {
                "1" | "true" | "yes" | "on" => Some(true),
                "0" | "false" | "no" | "off" => Some(false),
                _ => None,
            }
        })
        .unwrap_or(default)
}

/// Parse a `u64` env var with a default. Unset or non-numeric -> `default`.
pub fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

/// Parse a `u8` percentage env var with a default, clamped to `0..=100`.
/// Unset or non-numeric -> `default` (then clamped).
pub fn env_u8(key: &str, default: u8) -> u8 {
    let candidate = env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u8>().ok())
        .unwrap_or(default);
    candidate.clamp(0, 100)
}

/// Read the first non-empty value from a list of fallback env keys. If none is
/// set (or all empty), return `default` (which may be `None`).
pub fn env_with_fallback(keys: &[&str], default: Option<&str>) -> Option<String> {
    for key in keys {
        if let Ok(value) = env::var(key) {
            if !value.trim().is_empty() {
                return Some(value);
            }
        }
    }

    default.map(|value| value.to_string())
}

/// Parse a `u64` env var by name with a default (alias of [`env_u64`] kept for
/// the mail/billing boot wiring that already used this name).
pub fn parse_env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}
