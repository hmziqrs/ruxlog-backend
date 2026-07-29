//! Typed, fail-closed configuration for the API.
//!
//! [`Settings`] is constructed exactly once at boot via [`Settings::from_env`]
//! and threaded through `AppState` as `Arc<Settings>`. It replaces the
//! previously-scattered `std::env::var` reads in `main.rs` for the always-on
//! core (cookie key, HTTP bind, site URLs, object storage, image optimizer)
//! with a single validated struct, so a misconfigured deployment fails loud at
//! startup instead of on the first request.
//!
//! Fail-closed (mandatory) values panic inside `from_env` with the SAME
//! operator-actionable messages the old inline `expect` calls used, so boot
//! diagnostics are unchanged. Fail-open values keep their existing defaults
//! (e.g. `HOST=0.0.0.0`, `SITE_URL=http://localhost:8888`).
//!
//! Scope: this is the MVP (always-on core). Provider-specific configuration
//! (mail/billing OAuth creds, FCM, webauthn) and the `sea_connect`/`redis`
//! connection helpers are intentionally NOT yet migrated onto `Settings` —
//! those are shared with the `ruxlog_tui` binary (seed-system) which has its
//! own boot path, and the telemetry OTLP path is gated separately. They will
//! reuse this pattern in a later phase.

use axum_client_ip::ClientIpSource;

use crate::config::env::{env_bool, env_with_fallback};
#[cfg(feature = "image-optimization")]
use crate::config::env::{env_u64, env_u8};

// V-MED-8: `ObjectStorageConfig` holds `access_key` + `secret_key`. A derived
// `Debug` would print them in full. The manual impl below redacts the secrets
// to the literal "<redacted>" while still printing the non-secret fields.
// (Moved here from `state.rs` so the typed config layer owns the type; `state`
// re-exports it for source-compatible access by existing consumers.)
#[derive(Clone)]
pub struct ObjectStorageConfig {
    // S3-compatible storage (Cloudflare R2, Garage, AWS S3, etc.)
    pub region: String,
    pub account_id: String,
    pub bucket: String,
    pub access_key: String,
    pub secret_key: String,
    pub public_url: String,
    pub endpoint: String,
}

impl std::fmt::Debug for ObjectStorageConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("ObjectStorageConfig")
            .field("region", &self.region)
            .field("account_id", &self.account_id)
            .field("bucket", &self.bucket)
            .field("access_key", &"<redacted>")
            .field("secret_key", &"<redacted>")
            .field("public_url", &self.public_url)
            .field("endpoint", &self.endpoint)
            .finish()
    }
}

impl ObjectStorageConfig {
    /// Read S3-compatible storage config from env, fail-closed on the
    /// mandatory connection fields. Mirrors the inline block that previously
    /// lived in `main.rs` verbatim (same keys, same `expect` messages, same
    /// `public_url <- endpoint` fallback) so boot diagnostics are unchanged.
    pub fn from_env() -> Self {
        let bucket = env_with_fallback(&["S3_BUCKET", "AWS_S3_BUCKET"], None)
            .expect("S3_BUCKET or AWS_S3_BUCKET must be set");
        let access_key = env_with_fallback(&["S3_ACCESS_KEY", "AWS_ACCESS_KEY_ID"], None)
            .expect("S3_ACCESS_KEY or AWS_ACCESS_KEY_ID must be set");
        let secret_key = env_with_fallback(&["S3_SECRET_KEY", "AWS_SECRET_ACCESS_KEY"], None)
            .expect("S3_SECRET_KEY or AWS_SECRET_ACCESS_KEY must be set");
        let endpoint =
            env_with_fallback(&["S3_ENDPOINT", "AWS_ENDPOINT", "GARAGE_S3_ENDPOINT"], None)
                .expect("S3_ENDPOINT, AWS_ENDPOINT, or GARAGE_S3_ENDPOINT must be set");
        let public_url =
            env_with_fallback(&["S3_PUBLIC_URL", "AWS_S3_PUBLIC_URL"], None)
                .unwrap_or_else(|| {
                    // Fall back to direct endpoint when explicit public URL is missing.
                    endpoint.clone()
                });
        let region = env_with_fallback(
            &[
                "S3_REGION",
                "GARAGE_S3_REGION",
                "AWS_S3_REGION",
                "AWS_REGION",
            ],
            Some("auto"),
        )
        .unwrap();
        let account_id = std::env::var("S3_ACCOUNT_ID").unwrap_or_else(|_| "local".to_string());

        Self {
            region,
            account_id,
            bucket,
            access_key,
            secret_key,
            public_url,
            endpoint,
        }
    }
}

/// Image-optimization tuning (cfg `image-optimization`). Moved here from
/// `state.rs`; `state` re-exports it for source-compatible access.
#[cfg(feature = "image-optimization")]
#[derive(Clone, Debug)]
pub struct OptimizerConfig {
    pub enabled: bool,
    pub max_pixels: u64,
    pub keep_original: bool,
    pub default_webp_quality: u8,
}

#[cfg(feature = "image-optimization")]
impl OptimizerConfig {
    pub fn from_env() -> Self {
        Self {
            enabled: env_bool("OPTIMIZE_ON_UPLOAD", true),
            // DOS-MEDIA-OPTIMIZER: 12Mpx (~4000x3000) is ample for blog imagery
            // and ~3x cheaper to decode/resize/re-encode than the prior 40Mpx
            // default, which let a 2 MiB PNG declare ~40Mpx and pin a worker.
            max_pixels: env_u64("OPTIMIZER_MAX_PIXELS", 12_000_000),
            keep_original: env_bool("OPTIMIZER_KEEP_ORIGINAL", true),
            default_webp_quality: env_u8("OPTIMIZER_WEBP_QUALITY_DEFAULT", 80),
        }
    }
}

/// HTTP bind + cookie-transport settings.
pub struct HttpSettings {
    pub host: String,
    pub port: String,
    pub ip_source: ClientIpSource,
    pub cookie_secure: bool,
}

impl HttpSettings {
    pub fn from_env() -> Self {
        let host = std::env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
        let port = std::env::var("PORT").unwrap_or_else(|_| "8888".to_string());
        let ip_source = std::env::var("IP_SOURCE")
            .unwrap_or_else(|_| "ConnectInfo".to_string())
            .parse::<ClientIpSource>()
            .expect("Invalid IP_SOURCE value");
        let cookie_secure = env_bool("COOKIE_SECURE", true);
        Self {
            host,
            port,
            ip_source,
            cookie_secure,
        }
    }
}

/// Public-facing site URLs/names used by the feed, sitemap, and newsletter
/// confirmation handlers. All fail-open with the same defaults the handlers
/// previously used inline.
pub struct SiteSettings {
    pub url: String,
    pub name: String,
    pub consumer_site_url: String,
}

impl SiteSettings {
    pub fn from_env() -> Self {
        Self {
            url: std::env::var("SITE_URL")
                .unwrap_or_else(|_| "http://localhost:8888".to_string()),
            name: std::env::var("SITE_NAME").unwrap_or_else(|_| "Ruxlog".to_string()),
            consumer_site_url: std::env::var("CONSUMER_SITE_URL")
                .unwrap_or_else(|_| "https://ruxlog.com".to_string()),
        }
    }
}

/// The typed, fail-closed boot configuration. Constructed once via
/// [`Settings::from_env`] and shared (behind `Arc`) across `AppState`.
///
/// NOTE: deliberately does NOT `derive(Debug)` — it carries the raw
/// `cookie_key` secret, and a derived `Debug` would leak it in logs/panics.
pub struct Settings {
    /// Validated `COOKIE_KEY` (the `validate_cookie_key` contract is enforced
    /// in `from_env`). Held here so every consumer (cookie signing, keyed code
    /// hashing) reads one fixed-for-process value instead of re-reading env.
    pub cookie_key: String,
    pub http: HttpSettings,
    pub site: SiteSettings,
    pub object_storage: ObjectStorageConfig,
    #[cfg(feature = "image-optimization")]
    pub optimizer: OptimizerConfig,
}

impl Settings {
    /// Read and validate the always-on core configuration from the process
    /// environment. Fail-closed: a missing `COOKIE_KEY`, the known committed
    /// placeholder, or a missing mandatory S3 field panics here with the same
    /// message the old inline checks produced.
    ///
    /// Does NOT install the field-encryption key into the process-wide
    /// `utils::field_crypto` slot — that side-effecting install is still
    /// performed by `state::load_field_enc_key()` in `main.rs` so the
    /// SeaORM model layer can reach it (kept separate to preserve the exact
    /// CRYP-KM-003 previous/prev-key install behavior).
    pub fn from_env() -> Self {
        let cookie_key = std::env::var("COOKIE_KEY").expect("COOKIE_KEY must be set");
        // V-CRIT-1: refuse the known committed placeholder, empty/whitespace,
        // and sub-32-byte keys BEFORE any derivation. Panicking here is
        // intentional — booting on a weak/known cookie key is worse than
        // failing to boot. See CRYPTO_AUDIT.md V-CRIT-1 / V-HIGH-3.
        if let Err(reason) = crate::state::validate_cookie_key(&cookie_key) {
            panic!("{}", reason);
        }

        let object_storage = ObjectStorageConfig::from_env();

        #[cfg(feature = "image-optimization")]
        let optimizer = OptimizerConfig::from_env();

        let http = HttpSettings::from_env();
        let site = SiteSettings::from_env();

        Self {
            cookie_key,
            http,
            site,
            object_storage,
            #[cfg(feature = "image-optimization")]
            optimizer,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn set_cookie_key(strong: &str) {
        std::env::set_var("COOKIE_KEY", strong);
    }

    /// The mandatory S3 fields are read with `expect`; a missing bucket panics
    /// at boot (fail-closed) rather than silently producing an empty config.
    #[test]
    fn object_storage_panics_when_bucket_missing() {
        let prev_bucket = std::env::var("S3_BUCKET").ok();
        let prev_aws = std::env::var("AWS_S3_BUCKET").ok();
        std::env::remove_var("S3_BUCKET");
        std::env::remove_var("AWS_S3_BUCKET");

        let result = std::panic::catch_unwind(ObjectStorageConfig::from_env);
        assert!(
            result.is_err(),
            "ObjectStorageConfig::from_env must panic when S3_BUCKET is missing"
        );

        // Restore env.
        match prev_bucket {
            Some(v) => std::env::set_var("S3_BUCKET", v),
            None => std::env::remove_var("S3_BUCKET"),
        }
        match prev_aws {
            Some(v) => std::env::set_var("AWS_S3_BUCKET", v),
            None => std::env::remove_var("AWS_S3_BUCKET"),
        }
    }

    /// Settings::from_env refuses the known committed COOKIE_KEY placeholder
    /// (V-CRIT-1) and panics, even though it is longer than 32 bytes.
    #[test]
    fn settings_reject_known_cookie_key_placeholder() {
        let prev = std::env::var("COOKIE_KEY").ok();
        set_cookie_key("CHANGE_ME_rotate_me_generate_with_openssl_rand_hex_32___");

        let result = std::panic::catch_unwind(Settings::from_env);
        assert!(
            result.is_err(),
            "Settings::from_env must panic on the known COOKIE_KEY placeholder"
        );

        match prev {
            Some(v) => std::env::set_var("COOKIE_KEY", v),
            None => std::env::remove_var("COOKIE_KEY"),
        }
    }

    /// SiteSettings preserves the documented fail-open defaults.
    #[test]
    fn site_settings_defaults() {
        let prev_url = std::env::var("SITE_URL").ok();
        let prev_name = std::env::var("SITE_NAME").ok();
        let prev_consumer = std::env::var("CONSUMER_SITE_URL").ok();
        std::env::remove_var("SITE_URL");
        std::env::remove_var("SITE_NAME");
        std::env::remove_var("CONSUMER_SITE_URL");

        let site = SiteSettings::from_env();
        assert_eq!(site.url, "http://localhost:8888");
        assert_eq!(site.name, "Ruxlog");
        assert_eq!(site.consumer_site_url, "https://ruxlog.com");

        match prev_url {
            Some(v) => std::env::set_var("SITE_URL", v),
            None => std::env::remove_var("SITE_URL"),
        }
        match prev_name {
            Some(v) => std::env::set_var("SITE_NAME", v),
            None => std::env::remove_var("SITE_NAME"),
        }
        match prev_consumer {
            Some(v) => std::env::set_var("CONSUMER_SITE_URL", v),
            None => std::env::remove_var("CONSUMER_SITE_URL"),
        }
    }
}
