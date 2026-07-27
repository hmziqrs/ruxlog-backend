use chrono::Utc;
use jsonwebtoken::{
    decode, decode_header, encode, Algorithm, DecodingKey, EncodingKey, Header, Validation,
};
use serde::Deserialize;
use tracing::{error, warn};

use crate::error::{ErrorCode, ErrorResponse};

use super::validator::AppleIdTokenClaims;

const APPLE_AUTH_URL: &str = "https://appleid.apple.com/auth/authorize";
const APPLE_TOKEN_URL: &str = "https://appleid.apple.com/auth/token";
const APPLE_JWKS_URL: &str = "https://appleid.apple.com/auth/keys";
const APPLE_ISSUER: &str = "https://appleid.apple.com";

/// Resolved Apple Sign-in configuration loaded from env. Apple's `client_secret`
/// is NOT a static value — it is a per-request ES256-signed JWT minted from the
/// team/key id + the EC private key (see [`mint_apple_client_secret`]).
pub struct AppleConfig {
    /// Services ID / app_id (`client_id` in Apple's OAuth terms).
    pub client_id: String,
    pub team_id: String,
    pub key_id: String,
    pub redirect_uri: String,
    /// P-256 EC private key (Apple .p8 contents), PEM-decoded bytes.
    pub private_key_pem: String,
}

/// Load Apple config from env. The private key is read from `APPLE_PRIVATE_KEY`
/// (the .p8 contents, newlines literal or `\n`-escaped) with a
/// `APPLE_PRIVATE_KEY_PATH` file fallback (keeps the secret out of the process
/// env / git, mirroring the FCM service-account pattern).
#[allow(clippy::result_large_err)]
pub fn load_apple_config() -> Result<AppleConfig, ErrorResponse> {
    let client_id = std::env::var("APPLE_CLIENT_ID").map_err(|_| {
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("APPLE_CLIENT_ID not configured")
    })?;
    let team_id = std::env::var("APPLE_TEAM_ID").map_err(|_| {
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("APPLE_TEAM_ID not configured")
    })?;
    let key_id = std::env::var("APPLE_KEY_ID").map_err(|_| {
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("APPLE_KEY_ID not configured")
    })?;
    let redirect_uri = std::env::var("APPLE_REDIRECT_URI").map_err(|_| {
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("APPLE_REDIRECT_URI not configured")
    })?;

    let private_key_pem = match std::env::var("APPLE_PRIVATE_KEY") {
        Ok(raw) if !raw.trim().is_empty() => unescape_pem_newlines(&raw),
        _ => {
            // File fallback: read the .p8 from disk so the key never sits in env.
            let path = std::env::var("APPLE_PRIVATE_KEY_PATH").map_err(|_| {
                ErrorResponse::new(ErrorCode::InternalServerError)
                    .with_message("APPLE_PRIVATE_KEY or APPLE_PRIVATE_KEY_PATH not configured")
            })?;
            std::fs::read_to_string(&path).map_err(|e| {
                ErrorResponse::new(ErrorCode::InternalServerError)
                    .with_message("Failed to read Apple private key file")
                    .with_details(e.to_string())
            })?
        }
    };

    Ok(AppleConfig {
        client_id,
        team_id,
        key_id,
        redirect_uri,
        private_key_pem,
    })
}

/// `.env`-stored PEMs often arrive with literal `\n` sequences; normalize them
/// to real newlines so `from_ec_pem` parses the key.
fn unescape_pem_newlines(raw: &str) -> String {
    if raw.contains("\\n") {
        raw.replace("\\n", "\n")
    } else {
        raw.to_string()
    }
}

/// Mint Apple's `client_secret` JWT (ES256) for one token exchange. The JWT is
/// short-lived (~6 months is Apple's max); we mint fresh each request so there
/// is no stale-secret window. Mirrors the FCM service-account JWT pattern using
/// `jsonwebtoken`'s EC encoding key.
#[allow(clippy::result_large_err)]
pub fn mint_apple_client_secret(cfg: &AppleConfig) -> Result<String, ErrorResponse> {
    let mut header = Header::new(Algorithm::ES256);
    header.kid = Some(cfg.key_id.clone());

    let now = Utc::now().timestamp();
    let claims = serde_json::json!({
        "iss": cfg.team_id,
        "iat": now,
        "exp": now + 157_77000, // ~6 months — Apple's documented maximum
        "aud": APPLE_ISSUER,
        "sub": cfg.client_id,
    });

    let encoding_key = EncodingKey::from_ec_pem(cfg.private_key_pem.as_bytes()).map_err(|e| {
        error!(error = ?e, "Failed to parse Apple EC private key");
        ErrorResponse::new(ErrorCode::ConfigurationError)
            .with_message("Invalid Apple private key (expected P-256 PEM)")
            .with_details(e.to_string())
    })?;

    encode(&header, &claims, &encoding_key).map_err(|e| {
        error!(error = ?e, "Failed to sign Apple client_secret JWT");
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("Failed to mint Apple client_secret")
            .with_details(e.to_string())
    })
}

/// Build the Apple authorize URL with PKCE + session-bound state + OIDC nonce.
/// We request `response_type=code` only and set `response_mode=query`, so Apple
/// redirects back with a GET `?code=...&state=...` (matching our other
/// providers' GET callbacks); the id_token is then obtained from the token
/// endpoint, not the callback.
pub fn build_apple_authorize_url(
    cfg: &AppleConfig,
    state_secret: &str,
    pkce_challenge: &str,
    nonce: &str,
) -> Result<String, ErrorResponse> {
    let mut url = reqwest::Url::parse(APPLE_AUTH_URL).map_err(|e| {
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("Invalid Apple auth URL")
            .with_details(e.to_string())
    })?;
    {
        let mut q = url.query_pairs_mut();
        q.append_pair("response_type", "code");
        q.append_pair("response_mode", "query");
        q.append_pair("client_id", &cfg.client_id);
        q.append_pair("redirect_uri", &cfg.redirect_uri);
        q.append_pair("state", state_secret);
        q.append_pair("scope", "name email");
        q.append_pair("code_challenge", pkce_challenge);
        q.append_pair("code_challenge_method", "S256");
        q.append_pair("nonce", nonce);
    }
    Ok(url.to_string())
}

/// Apple's token endpoint response. We only consume `id_token` (the OIDC
/// identity); the access/refresh tokens are unused for our login flow.
#[derive(Debug, Deserialize)]
pub struct AppleTokenResponse {
    #[allow(dead_code)]
    pub access_token: String,
    #[serde(default)]
    #[allow(dead_code)]
    pub refresh_token: Option<String>,
    pub id_token: String,
}

/// Exchange an Apple authorization code for tokens via a hand-rolled form POST.
/// We cannot use the `oauth2` crate's exchange here because Apple's
/// `client_secret` is a per-request signed JWT, not a static value. The PKCE
/// `code_verifier` MUST be echoed (Apple enforces PKCE when a `code_challenge`
/// was sent in the authorize request); pass `None` only if the authorize
/// request did not use PKCE.
pub async fn exchange_apple_code(
    http_client: &reqwest::Client,
    cfg: &AppleConfig,
    code: &str,
    client_secret_jwt: &str,
    code_verifier: Option<&str>,
) -> Result<AppleTokenResponse, ErrorResponse> {
    let mut form_params: Vec<(&str, &str)> = vec![
        ("grant_type", "authorization_code"),
        ("code", code),
        ("redirect_uri", cfg.redirect_uri.as_str()),
        ("client_id", cfg.client_id.as_str()),
        ("client_secret", client_secret_jwt),
    ];
    if let Some(verifier) = code_verifier {
        form_params.push(("code_verifier", verifier));
    }

    let resp = http_client
        .post(APPLE_TOKEN_URL)
        .form(&form_params)
        .send()
        .await
        .map_err(|e| {
            error!(error = ?e, "Failed to POST Apple token endpoint");
            ErrorResponse::new(ErrorCode::ExternalServiceError)
                .with_message("Failed to exchange Apple authorization code")
        })?;

    let status = resp.status();
    if !status.is_success() {
        let body = resp.text().await.unwrap_or_default();
        error!(status = %status, body = %body, "Apple token endpoint returned non-2xx");
        return Err(ErrorResponse::new(ErrorCode::ExternalServiceError)
            .with_message("Apple rejected the authorization code")
            .with_details(body));
    }

    resp.json::<AppleTokenResponse>().await.map_err(|e| {
        error!(error = ?e, "Failed to parse Apple token response");
        ErrorResponse::new(ErrorCode::ExternalServiceError)
            .with_message("Failed to parse Apple token response")
    })
}

/// A single RSA signing key from Apple's JWKS.
#[derive(Clone, Debug, Deserialize)]
struct AppleJwkKey {
    kid: Option<String>,
    n: String,
    e: String,
}

#[derive(Debug, Deserialize)]
struct AppleJwkSet {
    keys: Vec<AppleJwkKey>,
}

/// Verify an Apple `id_token`'s signature and claims against the published
/// JWKS. Mirrors `google_auth_v1::service::verify_google_id_token` (single
/// fetch, RS256, aud/iss/exp validation, optional nonce binding) but without
/// the cache — Apple logins are infrequent enough that a fresh JWKS fetch per
/// login is acceptable.
#[allow(clippy::result_large_err)]
pub async fn verify_apple_id_token(
    id_token: &str,
    expected_aud: &str,
    expected_nonce: Option<&str>,
) -> Result<AppleIdTokenClaims, ErrorResponse> {
    let header = decode_header(id_token).map_err(|e| {
        warn!(error = ?e, "Apple id_token header decode failed");
        ErrorResponse::new(ErrorCode::InvalidToken).with_message("Malformed Apple id_token")
    })?;
    if header.alg != Algorithm::RS256 {
        warn!(alg = ?header.alg, "Rejecting Apple id_token with non-RS256 alg");
        return Err(ErrorResponse::new(ErrorCode::InvalidToken)
            .with_message("Unsupported Apple id_token algorithm"));
    }

    let keys = fetch_apple_jwks(http_client_for_jwks()?).await?;
    let signing_key = header
        .kid
        .as_deref()
        .and_then(|kid| keys.iter().find(|k| k.kid.as_deref() == Some(kid)))
        .ok_or_else(|| {
            warn!("No matching Apple signing key for id_token kid");
            ErrorResponse::new(ErrorCode::InvalidToken)
                .with_message("Untrusted Apple id_token signer")
        })?;

    let decoding_key =
        DecodingKey::from_rsa_components(&signing_key.n, &signing_key.e).map_err(|e| {
            error!(error = ?e, "Failed to build RSA decoding key from Apple JWKS");
            ErrorResponse::new(ErrorCode::InternalServerError)
                .with_message("Invalid Apple signing key")
        })?;

    let mut validation = Validation::new(Algorithm::RS256);
    validation.set_audience(&[expected_aud]);
    validation.set_issuer(&[APPLE_ISSUER]);

    let token_data =
        decode::<AppleIdTokenClaims>(id_token, &decoding_key, &validation).map_err(|e| {
            warn!(error = ?e, "Apple id_token verification failed");
            ErrorResponse::new(ErrorCode::InvalidToken).with_message("Invalid Apple id_token")
        })?;

    // OIDC nonce binding (V-LOW-NONCE): if we sent a nonce, require it echoed.
    if let Some(expected) = expected_nonce {
        match &token_data.claims.nonce {
            Some(actual) if actual == expected => { /* bound */ }
            other => {
                warn!(
                    ?other,
                    "Apple id_token nonce missing or mismatched — rejecting login"
                );
                return Err(ErrorResponse::new(ErrorCode::InvalidToken)
                    .with_message("Invalid Apple id_token"));
            }
        }
    }

    Ok(token_data.claims)
}

/// Build a short-timeout reqwest client for the JWKS fetch (V-MED-10: bound so a
/// wedged Apple endpoint cannot pin the login handler).
fn http_client_for_jwks() -> Result<reqwest::Client, ErrorResponse> {
    reqwest::Client::builder()
        .redirect(reqwest::redirect::Policy::none())
        .connect_timeout(std::time::Duration::from_secs(5))
        .timeout(std::time::Duration::from_secs(15))
        .pool_idle_timeout(std::time::Duration::from_secs(30))
        .build()
        .map_err(|e| {
            error!(error = ?e, "Failed to build Apple JWKS HTTP client");
            ErrorResponse::new(ErrorCode::ExternalServiceError).with_message("JWKS fetch failed")
        })
}

async fn fetch_apple_jwks(http_client: reqwest::Client) -> Result<Vec<AppleJwkKey>, ErrorResponse> {
    let resp = http_client.get(APPLE_JWKS_URL).send().await.map_err(|e| {
        error!(error = ?e, "Failed to fetch Apple JWKS");
        ErrorResponse::new(ErrorCode::ExternalServiceError).with_message("JWKS fetch failed")
    })?;

    let status = resp.status();
    let bytes = resp.bytes().await.map_err(|e| {
        error!(error = ?e, "Failed to read Apple JWKS body");
        ErrorResponse::new(ErrorCode::ExternalServiceError).with_message("JWKS fetch failed")
    })?;

    if !status.is_success() {
        error!(status = %status, "Apple JWKS endpoint returned non-2xx");
        return Err(
            ErrorResponse::new(ErrorCode::ExternalServiceError).with_message("JWKS fetch failed")
        );
    }

    let parsed: AppleJwkSet = serde_json::from_slice(&bytes).map_err(|e| {
        error!(error = ?e, "Failed to parse Apple JWKS JSON");
        ErrorResponse::new(ErrorCode::ExternalServiceError).with_message("Malformed JWKS")
    })?;

    Ok(parsed.keys)
}
