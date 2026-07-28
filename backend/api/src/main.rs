#[cfg(feature = "admin-acl")]
use axum::extract::State;
use axum::{http::HeaderName, middleware, Extension};
use axum_client_ip::ClientIpSource;
use axum_extra::extract::cookie::SameSite;
use std::{env, net::SocketAddr, time::Duration};
use tower_http::{
    compression::CompressionLayer,
    cors::{AllowOrigin, CorsLayer},
};
use tower_sessions::{cookie::Key, Expiry, SessionManagerLayer};
use tower_sessions_redis_store::RedisStore;

use ruxlog::utils::cors::get_allowed_origins;
use ruxlog::{
    db, middlewares, router,
    services::redis::init_redis_store,
    state::{validate_cookie_key, AppState, ObjectStorageConfig},
    utils::telemetry,
};

#[cfg(feature = "admin-acl")]
use ruxlog::services::acl_service::AclService;

#[cfg(feature = "admin-routes")]
use ruxlog::services::{route_blocker_config, route_blocker_service::RouteBlockerService};

#[cfg(feature = "image-optimization")]
use ruxlog::state::OptimizerConfig;

#[cfg(feature = "billing")]
use ruxlog::services::billing::BillingProvider;

#[cfg(feature = "billing")]
use ruxlog::services::billing::router::{BillingRouter, GeoRouter, GeoRulesConfig};

fn env_bool(key: &str, default: bool) -> bool {
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

#[cfg_attr(not(feature = "full"), allow(dead_code))]
fn env_u64(key: &str, default: u64) -> u64 {
    env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

#[cfg_attr(not(feature = "full"), allow(dead_code))]
fn env_u8(key: &str, default: u8) -> u8 {
    let candidate = env::var(key)
        .ok()
        .and_then(|value| value.trim().parse::<u8>().ok())
        .unwrap_or(default);
    candidate.clamp(0, 100)
}

fn env_with_fallback(keys: &[&str], default: Option<&str>) -> Option<String> {
    for key in keys {
        if let Ok(value) = env::var(key) {
            if !value.trim().is_empty() {
                return Some(value);
            }
        }
    }

    default.map(|value| value.to_string())
}

fn parse_env_u64(name: &str, default: u64) -> u64 {
    env::var(name)
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(default)
}

/// Build the [`MailRouter`] from `MAIL_PROVIDER` + provider-specific env. The
/// selected provider's required env is read with `expect` (fail-loud boot) so a
/// misconfigured provider is caught at startup, not on the first send. `mailer`
/// is an `Arc<MailRouter>` (non-Option): mail is unconditional, and a selected
/// provider without its creds must fail loud rather than silently no-op every
/// send.
async fn build_mail_router(
    db: sea_orm::DatabaseConnection,
    redis_pool: tower_sessions_redis_store::fred::prelude::Pool,
    http_client: reqwest::Client,
) -> std::sync::Arc<ruxlog::services::mail::MailRouter> {
    use ruxlog::services::mail::{router::MailRouterLimits, smtp::SmtpMailProvider};
    use ruxlog::services::mail::{MailProvider, MailRouter};
    use std::collections::HashMap;

    let selected = env::var("MAIL_PROVIDER").unwrap_or_else(|_| "smtp".to_string());
    let rate_limit_enabled = env_bool("MAIL_RATE_LIMIT_ENABLED", true);
    let limits = MailRouterLimits {
        dedup_ttl_secs: parse_env_u64("MAIL_DEDUP_TTL_SECS", 300) as usize,
        soft_cooldown_secs: parse_env_u64("MAIL_SOFT_BOUNCE_COOLDOWN_SECS", 86_400) as i64,
        ..MailRouterLimits::default()
    };
    let from_address =
        env::var("MAIL_FROM_ADDRESS").unwrap_or_else(|_| "no-reply@domain.tld".to_string());
    let from_name = env::var("MAIL_FROM_NAME")
        .ok()
        .map(|s| s.trim().to_string())
        .filter(|s| !s.is_empty());

    let mut providers: HashMap<String, std::sync::Arc<dyn MailProvider>> = HashMap::new();
    let default = match selected.as_str() {
        "cloudflare" => {
            #[cfg(feature = "mail-cloudflare")]
            {
                use ruxlog::services::mail::cloudflare::CloudflareMailProvider;
                use secrecy::SecretString;

                let account_id = env::var("CLOUDFLARE_EMAIL_ACCOUNT_ID")
                    .expect("MAIL_PROVIDER=cloudflare requires CLOUDFLARE_EMAIL_ACCOUNT_ID");
                let api_token = SecretString::from(
                    env::var("CLOUDFLARE_EMAIL_API_TOKEN")
                        .expect("MAIL_PROVIDER=cloudflare requires CLOUDFLARE_EMAIL_API_TOKEN"),
                );
                let webhook_secret = SecretString::from(
                    env::var("CLOUDFLARE_EMAIL_WEBHOOK_SECRET").unwrap_or_default(),
                );
                let base_url = env::var("CLOUDFLARE_EMAIL_API_BASE_URL")
                    .unwrap_or_else(|_| "https://api.cloudflare.com/client/v4".to_string());
                let allowed = env::var("CLOUDFLARE_EMAIL_ALLOWED_ADDRESSES")
                    .ok()
                    .filter(|s| !s.trim().is_empty())
                    .map(|s| {
                        s.split(',')
                            .map(|x| x.trim().to_string())
                            .collect::<Vec<_>>()
                    });
                let cf = CloudflareMailProvider::new(
                    account_id,
                    api_token,
                    webhook_secret,
                    base_url,
                    from_address,
                    from_name,
                    http_client,
                    allowed,
                )
                .expect("failed to build Cloudflare mail provider");
                providers.insert("cloudflare".to_string(), std::sync::Arc::new(cf));
                "cloudflare"
            }
            #[cfg(not(feature = "mail-cloudflare"))]
            {
                let _ = http_client;
                panic!(
                    "MAIL_PROVIDER=cloudflare but the 'mail-cloudflare' feature is not enabled in this build"
                );
            }
        }
        // default (and explicit "smtp")
        _ => {
            let transport = ruxlog::services::mail::smtp::create_connection().await;
            let smtp = SmtpMailProvider::new(transport, from_address, from_name);
            providers.insert("smtp".to_string(), std::sync::Arc::new(smtp));
            "smtp"
        }
    };

    tracing::info!(provider = %default, rate_limit_enabled, "Mail router initialized");
    std::sync::Arc::new(MailRouter::new(
        providers,
        default.to_string(),
        redis_pool,
        db,
        limits,
        rate_limit_enabled,
    ))
}

#[tokio::main]
async fn main() -> Result<(), Box<dyn std::error::Error>> {
    dotenvy::dotenv().ok();

    let _telemetry_guard = telemetry::init();

    telemetry::init_pool_metrics();

    let cookie_key_str = env::var("COOKIE_KEY").expect("COOKIE_KEY must be set");
    // V-CRIT-1: refuse the known committed placeholder, empty/whitespace, and
    // sub-32-byte keys BEFORE Key::derive_from. The previous length-only guard
    // passed for the placeholder because it is >32 bytes, so production could
    // boot on a publicly-known key. Panicking here is intentional — booting on
    // a weak/known cookie key is worse than failing to boot. See
    // CRYPTO_AUDIT.md V-CRIT-1 / V-HIGH-3.
    if let Err(reason) = validate_cookie_key(&cookie_key_str) {
        panic!("{}", reason);
    }

    let sea_db = db::sea_connect::get_sea_connection().await;

    let (redis_pool, redis_connection) = init_redis_store().await?;

    let bucket = env_with_fallback(&["S3_BUCKET", "AWS_S3_BUCKET"], None)
        .expect("S3_BUCKET or AWS_S3_BUCKET must be set");
    let access_key = env_with_fallback(&["S3_ACCESS_KEY", "AWS_ACCESS_KEY_ID"], None)
        .expect("S3_ACCESS_KEY or AWS_ACCESS_KEY_ID must be set");
    let secret_key = env_with_fallback(&["S3_SECRET_KEY", "AWS_SECRET_ACCESS_KEY"], None)
        .expect("S3_SECRET_KEY or AWS_SECRET_ACCESS_KEY must be set");
    let endpoint = env_with_fallback(&["S3_ENDPOINT", "AWS_ENDPOINT", "GARAGE_S3_ENDPOINT"], None)
        .expect("S3_ENDPOINT, AWS_ENDPOINT, or GARAGE_S3_ENDPOINT must be set");
    let public_url = env_with_fallback(&["S3_PUBLIC_URL", "AWS_S3_PUBLIC_URL"], None)
        .unwrap_or_else(|| {
            // Fall back to direct endpoint when explicit public URL is missing.
            endpoint.clone()
        });

    let object_storage = ObjectStorageConfig {
        region: env_with_fallback(
            &[
                "S3_REGION",
                "GARAGE_S3_REGION",
                "AWS_S3_REGION",
                "AWS_REGION",
            ],
            Some("auto"),
        )
        .unwrap(),
        account_id: env::var("S3_ACCOUNT_ID").unwrap_or_else(|_| "local".to_string()),
        bucket,
        access_key,
        secret_key,
        public_url,
        endpoint,
    };

    // V-MED-8: do NOT log the raw ObjectStorageConfig — even with the manual
    // Debug impl redacting access_key/secret_key, emitting the whole struct at
    // debug level is unnecessary surface. Log only the non-secret fields that
    // are useful for diagnosing startup wiring.
    tracing::debug!(
        bucket = %object_storage.bucket,
        region = %object_storage.region,
        endpoint = %object_storage.endpoint,
        public_url = %object_storage.public_url,
        "Object Storage configured (access_key/secret_key redacted)"
    );
    let s3_config = aws_config::from_env()
        .endpoint_url(&object_storage.endpoint)
        .credentials_provider(aws_sdk_s3::config::Credentials::new(
            &object_storage.access_key,
            &object_storage.secret_key,
            None,
            None,
            "S3Compatible",
        ))
        .region(aws_sdk_s3::config::Region::new(
            object_storage.region.clone(),
        ))
        .load()
        .await;

    let s3_client = aws_sdk_s3::Client::new(&s3_config);

    // V-LOW-PRINTLN: the previous boot-time `println!("Buckets:")` loop dumped
    // every bucket name + creation date to stdout. That is unnecessary startup
    // noise AND a minor information disclosure in shared/logged consoles (bucket
    // names are sometimes sensitive). Bucket wiring is already logged in a
    // redacted form just above (`tracing::debug!` of bucket/region/endpoint),
    // so echoing the full S3 list adds nothing. Removed entirely.
    #[cfg(feature = "image-optimization")]
    let optimizer = OptimizerConfig {
        enabled: env_bool("OPTIMIZE_ON_UPLOAD", true),
        // DOS-MEDIA-OPTIMIZER: 12Mpx (~4000x3000) is ample for blog imagery and
        // ~3x cheaper to decode/resize/re-encode than the prior 40Mpx default,
        // which let a 2 MiB PNG declare ~40Mpx and pin a worker for seconds.
        max_pixels: env_u64("OPTIMIZER_MAX_PIXELS", 12_000_000),
        keep_original: env_bool("OPTIMIZER_KEEP_ORIGINAL", true),
        default_webp_quality: env_u8("OPTIMIZER_WEBP_QUALITY_DEFAULT", 80),
    };

    // V-MED-10: ONE shared, timeout-configured reqwest::Client for all outbound
    // billing + Google HTTP calls. Built once here so a slow/hanging upstream
    // can never pin a handler thread indefinitely (CWE-400/CWE-770). Cloned
    // cheaply (it is internally an `Arc`) into each provider and the Google
    // userinfo/JWKS fetch. See `state::build_http_client`.
    let http_client = ruxlog::state::build_http_client();

    // Mail router (SMTP or Cloudflare, selected by MAIL_PROVIDER). Built after
    // http_client since the Cloudflare provider reuses the shared client.
    let mailer = build_mail_router(sea_db.clone(), redis_pool.clone(), http_client.clone()).await;

    #[cfg(feature = "billing")]
    let billing_router: std::sync::Arc<BillingRouter> = {
        use ruxlog::services::billing::{
            airwallex::AirwallexProvider, crypto::CryptoProvider,
            lemon_squeezy::LemonSqueezyProvider, mercado_pago::MercadoPagoProvider,
            paddle::PaddleProvider, paypal::PayPalProvider, polar::PolarProvider,
            razorpay::RazorpayProvider, revolut::RevolutProvider, stripe::StripeProvider,
        };
        // Each provider receives the shared client so it never falls back to
        // constructing its own `reqwest::Client::new()`.
        let http_client = http_client.clone();

        fn try_init<F>(name: &str, init: F) -> Option<(String, std::sync::Arc<dyn BillingProvider>)>
        where
            F: FnOnce() -> Option<std::sync::Arc<dyn BillingProvider>>,
        {
            match init() {
                Some(p) => {
                    tracing::info!(provider = name, "Billing provider initialized");
                    Some((name.to_string(), p))
                }
                None => {
                    tracing::info!(
                        provider = name,
                        "Billing provider skipped (missing env vars)"
                    );
                    None
                }
            }
        }

        let mut providers: std::collections::HashMap<String, std::sync::Arc<dyn BillingProvider>> =
            std::collections::HashMap::new();

        // Stripe
        if let Some((k, v)) = try_init("stripe", || {
            let secret = env::var("STRIPE_SECRET_KEY").ok()?;
            let wh = env::var("STRIPE_WEBHOOK_SECRET").ok()?;
            Some(std::sync::Arc::new(
                StripeProvider::new(secret, wh).with_http_client(http_client.clone()),
            ) as std::sync::Arc<dyn BillingProvider>)
        }) {
            providers.insert(k, v);
        }

        // Polar.sh
        if let Some((k, v)) = try_init("polar", || {
            let token = env::var("POLAR_ACCESS_TOKEN").ok()?;
            let wh = env::var("POLAR_WEBHOOK_SECRET").ok()?;
            Some(std::sync::Arc::new(
                PolarProvider::new(token, wh).with_http_client(http_client.clone()),
            ) as std::sync::Arc<dyn BillingProvider>)
        }) {
            providers.insert(k, v);
        }

        // LemonSqueezy — key MUST match `provider_name()` ("lemon_squeezy") so the
        // webhook path `/webhook/lemon_squeezy` resolves on the router. The prior
        // `"lemonsqueezy"` registration 404'd every LemonSqueezy webhook (plan 1e).
        if let Some((k, v)) = try_init("lemon_squeezy", || {
            let api_key = env::var("LEMONSQUEEZY_API_KEY").ok()?;
            let wh = env::var("LEMONSQUEEZY_WEBHOOK_SECRET").ok()?;
            let store_id = env::var("LEMONSQUEEZY_STORE_ID").ok()?;
            Some(std::sync::Arc::new(
                LemonSqueezyProvider::new(api_key, wh, store_id)
                    .with_http_client(http_client.clone()),
            ) as std::sync::Arc<dyn BillingProvider>)
        }) {
            providers.insert(k, v);
        }

        // Paddle — verifies webhooks with an Ed25519 public key (PADDLE_PUBLIC_KEY,
        // hex of 32 bytes). Without it the provider verifies fail-closed.
        if let Some((k, v)) = try_init("paddle", || {
            let client_token = env::var("PADDLE_CLIENT_TOKEN").ok()?;
            let wh = env::var("PADDLE_WEBHOOK_SECRET").ok()?;
            let mut provider =
                PaddleProvider::new(client_token, wh).with_http_client(http_client.clone());
            match env::var("PADDLE_PUBLIC_KEY") {
                Ok(hex_key) if !hex_key.trim().is_empty() => {
                    provider = provider.with_public_key(&hex_key).ok()?;
                }
                _ => tracing::warn!(
                    "PADDLE_PUBLIC_KEY not set; Paddle webhooks will fail verification until it is configured"
                ),
            }
            Some(std::sync::Arc::new(provider) as std::sync::Arc<dyn BillingProvider>)
        }) {
            providers.insert(k, v);
        }

        // Crypto (single chain)
        if let Some((k, v)) = try_init("crypto", || {
            let wallet = env::var("CRYPTO_WALLET_ADDRESS").ok()?;
            let api_url = env::var("CRYPTO_API_URL")
                .unwrap_or_else(|_| "https://api.blockcypher.com/v1".to_string());
            let api_key = env::var("CRYPTO_API_KEY").unwrap_or_else(|_| String::new());
            let currency = env::var("CRYPTO_CURRENCY").unwrap_or_else(|_| "BTC".to_string());
            Some(std::sync::Arc::new(
                CryptoProvider::new(wallet, api_url, api_key, currency)
                    .with_http_client(http_client.clone()),
            ) as std::sync::Arc<dyn BillingProvider>)
        }) {
            providers.insert(k, v);
        }

        // Crypto (multi-chain)
        if let Some((k, v)) = try_init("crypto_multi", || {
            let provider = ruxlog::services::billing::crypto::MultiChainCryptoProvider::from_env()
                .ok()?
                .with_http_client(http_client.clone());
            Some(std::sync::Arc::new(provider) as std::sync::Arc<dyn BillingProvider>)
        }) {
            providers.insert(k, v);
        }

        // Razorpay
        if let Some((k, v)) = try_init("razorpay", || {
            let key_id = env::var("RAZORPAY_KEY_ID").ok()?;
            let key_secret = env::var("RAZORPAY_KEY_SECRET").ok()?;
            let wh = env::var("RAZORPAY_WEBHOOK_SECRET").ok()?;
            Some(std::sync::Arc::new(
                RazorpayProvider::new(key_id, key_secret, wh).with_http_client(http_client.clone()),
            ) as std::sync::Arc<dyn BillingProvider>)
        }) {
            providers.insert(k, v);
        }

        // Mercado Pago
        if let Some((k, v)) = try_init("mercado_pago", || {
            let access_token = env::var("MERCADO_PAGO_ACCESS_TOKEN").ok()?;
            let wh = env::var("MERCADO_PAGO_WEBHOOK_SECRET").ok()?;
            Some(std::sync::Arc::new(
                MercadoPagoProvider::new(access_token, wh).with_http_client(http_client.clone()),
            ) as std::sync::Arc<dyn BillingProvider>)
        }) {
            providers.insert(k, v);
        }

        // Airwallex
        if let Some((k, v)) = try_init("airwallex", || {
            let client_id = env::var("AIRWALLEX_CLIENT_ID").ok()?;
            let api_key = env::var("AIRWALLEX_API_KEY").ok()?;
            let wh = env::var("AIRWALLEX_WEBHOOK_SECRET").ok()?;
            Some(std::sync::Arc::new(
                AirwallexProvider::new(client_id, api_key, wh)
                    .with_http_client(http_client.clone()),
            ) as std::sync::Arc<dyn BillingProvider>)
        }) {
            providers.insert(k, v);
        }

        // Revolut
        if let Some((k, v)) = try_init("revolut", || {
            let api_key = env::var("REVOLUT_API_KEY").ok()?;
            let wh = env::var("REVOLUT_WEBHOOK_SECRET").ok()?;
            Some(std::sync::Arc::new(
                RevolutProvider::new(api_key, wh).with_http_client(http_client.clone()),
            ) as std::sync::Arc<dyn BillingProvider>)
        }) {
            providers.insert(k, v);
        }

        // PayPal — webhooks are verified via PayPal's verify-webhook-signature
        // API, which requires the webhook ID PayPal issues on registration
        // (PAYPAL_WEBHOOK_ID). Without it the provider verifies fail-closed.
        if let Some((k, v)) = try_init("paypal", || {
            let client_id = env::var("PAYPAL_CLIENT_ID").ok()?;
            let client_secret = env::var("PAYPAL_CLIENT_SECRET").ok()?;
            let wh = env::var("PAYPAL_WEBHOOK_SECRET").ok()?;
            let mut provider = PayPalProvider::new(client_id, client_secret, wh)
                .with_http_client(http_client.clone());
            if let Ok(id) = env::var("PAYPAL_WEBHOOK_ID") {
                if !id.is_empty() {
                    provider = provider.with_webhook_id(id);
                }
            }
            if provider.webhook_id.is_none() {
                tracing::warn!(
                    "PAYPAL_WEBHOOK_ID not set; PayPal webhooks will fail verification until it is configured"
                );
            }
            Some(std::sync::Arc::new(provider) as std::sync::Arc<dyn BillingProvider>)
        }) {
            providers.insert(k, v);
        }

        if providers.is_empty() {
            tracing::warn!("No billing providers initialized (missing env vars). Billing endpoints will return errors.");
        }

        let names: Vec<_> = providers.keys().collect();
        tracing::info!(providers = ?names, "Billing providers available");

        let geo_config = GeoRulesConfig::from_env();
        let geo_router = GeoRouter::new(geo_config);

        std::sync::Arc::new(BillingRouter::new(providers, geo_router))
    };

    // ── Service construction added for the issues batch (2026-07-27) ──
    // #29 Firebase Cloud Messaging (in-app/push). Stays None unless
    // FCM_ENABLED + a service-account JSON are present; in-app rows still persist.
    #[cfg(feature = "notifications")]
    let fcm: Option<std::sync::Arc<rux_fcm::FcmClient>> = {
        if env_bool("FCM_ENABLED", false) {
            let project_id = env::var("FCM_PROJECT_ID")
                .ok()
                .filter(|s| !s.trim().is_empty());
            let sa_path = env::var("FCM_SERVICE_ACCOUNT_PATH")
                .ok()
                .filter(|s| !s.trim().is_empty());
            match (project_id, sa_path) {
                (Some(pid), Some(path)) => match rux_fcm::ServiceAccount::from_path(&path) {
                    Ok(sa) => Some(std::sync::Arc::new(rux_fcm::FcmClient::new(
                        sa,
                        pid,
                        http_client.clone(),
                    ))),
                    Err(err) => {
                        tracing::warn!(
                            error = %err,
                            "FCM service-account load failed; push disabled \
                             (in-app notifications still work)"
                        );
                        None
                    }
                },
                _ => {
                    tracing::warn!(
                        "FCM_ENABLED=true but FCM_PROJECT_ID or FCM_SERVICE_ACCOUNT_PATH \
                         not set; push disabled"
                    );
                    None
                }
            }
        } else {
            None
        }
    };

    // #4 passkey/WebAuthn service.
    #[cfg(feature = "auth-passkey")]
    let webauthn_service: Option<std::sync::Arc<ruxlog::services::webauthn::WebauthnService>> =
        match ruxlog::services::webauthn::WebauthnService::from_env() {
            Ok(svc) => {
                tracing::info!("WebAuthn passkey service enabled");
                Some(std::sync::Arc::new(svc))
            }
            Err(e) => {
                tracing::warn!(
                    error = %e,
                    "WebAuthn passkey service disabled (invalid configuration; passkey endpoints will return 503)"
                );
                None
            }
        };

    // #9 image moderation gate (HttpModerator hits a configurable provider).
    #[cfg(feature = "image-moderation")]
    let image_moderator: Option<
        std::sync::Arc<dyn ruxlog::services::image_moderation::ImageModerator + Send + Sync>,
    > = {
        use ruxlog::services::image_moderation::{HttpModerator, ImageModerator};
        let enabled = env_bool("IMAGE_MODERATION_ENABLED", false);
        let url = env_with_fallback(&["IMAGE_MODERATION_URL"], None);
        let api_key = env_with_fallback(&["IMAGE_MODERATION_API_KEY"], None).unwrap_or_default();
        if enabled {
            match url {
                Some(url) if !url.trim().is_empty() => {
                    tracing::info!(url = %url, "Image moderation enabled (HttpModerator)");
                    Some(
                        std::sync::Arc::new(HttpModerator::new(http_client.clone(), url, api_key))
                            as std::sync::Arc<dyn ImageModerator + Send + Sync>,
                    )
                }
                _ => {
                    tracing::warn!(
                        "IMAGE_MODERATION_ENABLED=true but IMAGE_MODERATION_URL is unset/empty; \
                         moderation disabled and uploads will be accepted unmoderated"
                    );
                    None
                }
            }
        } else {
            None
        }
    };

    // #5/#10 install the shared redis pool into the cache service's process-global slot.
    #[cfg(feature = "cache")]
    {
        ruxlog::services::cache::install_pool(redis_pool.clone());
    }

    let state = AppState {
        sea_db,
        redis_pool: redis_pool.clone(),
        mailer,
        object_storage,
        s3_client,
        secret_key: cookie_key_str.as_bytes().to_vec(),
        field_enc_key: ruxlog::state::load_field_enc_key(),
        #[cfg(feature = "image-optimization")]
        optimizer,
        meter: telemetry::global_meter(),
        http_client,
        #[cfg(feature = "billing")]
        billing_router,
        // --- Fields added for the issues batch (2026-07-27) ---
        #[cfg(feature = "notifications")]
        fcm,
        #[cfg(feature = "auth-passkey")]
        webauthn: webauthn_service,
        #[cfg(feature = "image-moderation")]
        image_moderator,
    };

    // Bootstrap application constants from environment (only fills missing keys) and warm Redis.
    #[cfg(feature = "admin-acl")]
    {
        if let Err(err) = AclService::bootstrap_from_env(State(state.clone())).await {
            tracing::error!(error = %err, "Failed to bootstrap ACL constants from env");
        } else {
            tracing::info!("ACL constants bootstrapped from env");
        }
    }

    #[cfg(feature = "admin-routes")]
    {
        let sync_interval_secs = env_u64("ROUTE_BLOCKER_SYNC_INTERVAL_SECS", 60 * 30);
        route_blocker_config::set_sync_interval_secs(sync_interval_secs);

        if let Err(err) = RouteBlockerService::initialize_redis_sync(&state).await {
            tracing::error!(
                error = %err,
                "Initial route blocker Redis sync failed; continuing without warm cache"
            );
        } else {
            tracing::info!("Initial route blocker Redis sync completed successfully");
        }

        let state_for_blocker = state.clone();
        tokio::spawn(async move {
            let notify = route_blocker_config::notifier();

            // Set initial next sync time
            route_blocker_config::set_next_sync_at(route_blocker_config::calculate_next_sync());

            loop {
                if route_blocker_config::is_paused() {
                    tokio::select! {
                        _ = notify.notified() => {},
                        _ = tokio::time::sleep(Duration::from_secs(5)) => {},
                    }
                    continue;
                }

                let force_sync = route_blocker_config::take_force_sync_flag();

                if !force_sync {
                    let interval_secs = route_blocker_config::get_sync_interval_secs();
                    let next_sync = route_blocker_config::calculate_next_sync();
                    route_blocker_config::set_next_sync_at(next_sync);

                    let sleep = tokio::time::sleep(Duration::from_secs(interval_secs));
                    tokio::pin!(sleep);

                    tokio::select! {
                        _ = &mut sleep => {},
                        _ = notify.notified() => {
                            // config change: restart loop to re-read state.
                            continue;
                        }
                    }
                }

                if route_blocker_config::is_paused() {
                    continue;
                }

                route_blocker_config::set_sync_running(true);
                let sync_start = chrono::Utc::now();

                if let Err(err) =
                    RouteBlockerService::initialize_redis_sync(&state_for_blocker).await
                {
                    tracing::error!(
                        error = %err,
                        "Periodic route blocker Redis sync failed"
                    );
                } else {
                    tracing::info!("Periodic route blocker Redis sync completed successfully");
                }

                route_blocker_config::set_last_sync_at(sync_start);
                route_blocker_config::set_sync_running(false);
                route_blocker_config::set_next_sync_at(route_blocker_config::calculate_next_sync());
            }
        });
    }

    #[cfg(feature = "scheduler")]
    ruxlog::services::scheduler::start_scheduler(state.clone());

    tracing::info!("Redis successfully established.");
    let session_store = RedisStore::new(redis_pool);
    // Derive the cookie signing+encryption key via HKDF-SHA256 rather than the
    // previous raw SHA-512 of COOKIE_KEY (a fast hash is the wrong tool for key
    // derivation: a weak COOKIE_KEY collapses to a brute-forceable key). cookie's
    // Key::derive_from applies HKDF-SHA256 to the material. Note: changing the
    // KDF rotates the derived key, so existing private cookies/sessions
    // invalidate and users re-authenticate once. See plan Phase 2d.
    let cookie_key = Key::derive_from(cookie_key_str.as_bytes());

    // Secure cookies by default; dev/local sets COOKIE_SECURE=false. A permanent
    // .with_secure(false) blocked the Secure flag in production. See plan 2e.
    let cookie_secure = env_bool("COOKIE_SECURE", true);

    let session_layer = SessionManagerLayer::new(session_store)
        .with_expiry(Expiry::OnInactivity(time::Duration::hours(24 * 14)))
        .with_same_site(SameSite::Lax)
        .with_secure(cookie_secure)
        .with_http_only(true)
        // CRYP-SESS-006: pin the session cookie name to a constant. Letting the
        // cookie name float (or derive from a configurable value) widens the
        // surface for cookie-fixing / confused-deputy issues across deployments;
        // a fixed, known name is what the CSRF guard and frontend expect.
        .with_name("ruxlog.sid")
        .with_private(cookie_key);

    let compression = CompressionLayer::new();
    let cors = CorsLayer::new()
        .allow_methods([
            axum::http::Method::GET,
            axum::http::Method::POST,
            axum::http::Method::PUT,
            axum::http::Method::DELETE,
            axum::http::Method::OPTIONS,
        ])
        .allow_headers(vec![
            HeaderName::from_static("csrf-token"),
            axum::http::header::ACCEPT,
            axum::http::header::CONTENT_TYPE,
            axum::http::header::ACCEPT_ENCODING,
            axum::http::header::CONTENT_ENCODING,
        ])
        .expose_headers(vec![
            axum::http::header::ACCESS_CONTROL_ALLOW_CREDENTIALS,
            axum::http::header::ACCESS_CONTROL_ALLOW_ORIGIN,
            axum::http::header::SET_COOKIE,
        ])
        .allow_origin(AllowOrigin::list(get_allowed_origins()))
        .allow_credentials(true)
        .max_age(Duration::from_secs(360));

    let ip_source: ClientIpSource = env::var("IP_SOURCE")
        .unwrap_or_else(|_| "ConnectInfo".to_string())
        .parse()
        .expect("Invalid IP_SOURCE value");

    // Clone the database connection for the Extension layer (used by auth middleware)
    let db_extension = Extension(state.sea_db.clone());
    // V-HIGH-2: also provide the Redis pool as an Extension so the auth guards
    // can build `AuthBackend` with the Redis handle required for the
    // per-request session-revocation `SISMEMBER`.
    let redis_extension = Extension(state.redis_pool.clone());

    #[cfg_attr(not(feature = "full"), allow(unused_mut))]
    let mut app = router::router(state.clone())
        .layer(ip_source.into_extension())
        .layer(db_extension)
        .layer(redis_extension)
        // NOTE: `session_layer` is applied *after* `csrf_guard` below so that it
        // is the OUTER layer. Order matters: later `.layer()` calls wrap the
        // earlier ones, so a request flows session_layer → csrf_guard → router.
        // The Session is therefore present in the request extensions when
        // `csrf_guard` runs, letting it recompute the per-session HMAC token.
        //     config: governor_conf,
        // })
        .layer(compression)
        .layer(middleware::from_fn(
            middlewares::http_metrics::track_metrics,
        ))
        .layer(middleware::from_fn(
            middlewares::request_id::request_id_middleware,
        ))
        .layer(middleware::from_fn(middlewares::cors::origin_guard))
        .layer(middleware::from_fn(middlewares::static_csrf::csrf_guard))
        .layer(session_layer)
        .layer(cors);

    #[cfg(feature = "admin-routes")]
    {
        app = app.layer(middlewares::route_blocker::RouteBlockerLayer::new(
            state.clone(),
        ));
    }

    let app = app.with_state(state);

    let host = env::var("HOST").unwrap_or_else(|_| "0.0.0.0".to_string());
    let port = env::var("PORT").unwrap_or_else(|_| "8888".to_string());
    let address = format!("{}:{}", host, port);
    let address = address.parse::<std::net::SocketAddr>()?;
    tracing::info!("Listening on http://{}", address);
    let listener = tokio::net::TcpListener::bind(address).await?;
    axum::serve(
        listener,
        app.into_make_service_with_connect_info::<SocketAddr>(),
    )
    .await?;

    redis_connection.await??;

    Ok(())
}
