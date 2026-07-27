//! Session-bound, single-use OAuth state stored in Redis.
//!
//! This is the shared CSRF/PKCE binding used by every third-party OAuth
//! provider module (Facebook, GitHub, Apple). It mirrors the proven
//! `google_auth_v1` implementation: the authorize request's CSRF `state`
//! secret is bound to the caller's tower-session id, and the PKCE verifier +
//! optional OIDC nonce are recovered atomically at the callback via `GETDEL`
//! (single-use, replay-proof).
//!
//! Kept provider-agnostic so each provider module only worries about its own
//! authorize/token/userinfo shape, not the session + state plumbing.

use oauth2::PkceCodeVerifier;
use serde::Deserialize;
use serde_json::json;
use tower_sessions::Session;
use tower_sessions_redis_store::fred::prelude::*;
use tracing::{error, warn};

use crate::error::{ErrorCode, ErrorResponse};
use crate::AppState;

/// Extract the caller's tower-sessions id, required to bind the OAuth state.
/// Fail closed: without a session we cannot bind state, so we refuse to proceed.
#[allow(clippy::result_large_err)]
pub fn oauth_session_id(session: &Session) -> Result<String, ErrorResponse> {
    session.id().map(|id| id.to_string()).ok_or_else(|| {
        warn!("OAuth attempted without a session id");
        ErrorResponse::new(ErrorCode::Unauthorized).with_message("No active session")
    })
}

/// Persist the (session-bound) state → {PKCE verifier, OIDC nonce} mapping,
/// single-use, 10 min. The nonce rides alongside the verifier so it is recovered
/// atomically at the callback and used to validate an OIDC `id_token`
/// (`nonce` claim) when the provider issues one (e.g. Apple). For pure-OAuth2
/// providers (Facebook, GitHub) the nonce is unused and stored as `None`.
/// `pkce_verifier_secret` may be empty for providers that do not use PKCE
/// (Facebook); an empty value round-trips as `None` at consume time.
pub async fn store_oauth_state(
    state: &AppState,
    session_id: &str,
    state_secret: &str,
    pkce_verifier_secret: &str,
    nonce: Option<&str>,
) -> Result<(), ErrorResponse> {
    let key = format!("oauth:state:{}:{}", session_id, state_secret);
    let payload = json!({ "v": pkce_verifier_secret, "n": nonce }).to_string();
    state
        .redis_pool
        .set::<(), _, _>(
            &key,
            payload,
            Some(fred::types::Expiration::EX(600)),
            None,
            false,
        )
        .await
        .map_err(|e| {
            error!(error = ?e, "Failed to store OAuth state");
            ErrorResponse::new(ErrorCode::InternalServerError)
                .with_message("Failed to store OAuth state")
        })
}

#[derive(Deserialize)]
struct StoredState {
    v: String,
    #[serde(default)]
    n: Option<String>,
}

/// The single-use OAuth state recovered at the callback: the PKCE verifier plus
/// the optional OIDC nonce bound to that authorize request.
pub struct ConsumedOauthState {
    /// `None` when the provider flow does not use PKCE (stored empty).
    pub pkce_verifier: Option<PkceCodeVerifier>,
    pub nonce: Option<String>,
}

/// Atomically look up AND delete the session-bound state, returning the PKCE
/// verifier and OIDC nonce. `GETDEL` makes the state single-use in one
/// round-trip (a replayed state observes `None`). Fails closed if the state is
/// missing, expired, or belongs to another session.
pub async fn consume_oauth_state(
    state: &AppState,
    session_id: &str,
    state_secret: &str,
) -> Result<ConsumedOauthState, ErrorResponse> {
    let key = format!("oauth:state:{}:{}", session_id, state_secret);

    let stored: Option<String> = state.redis_pool.getdel(&key).await.map_err(|e| {
        error!(error = ?e, "Failed to consume OAuth state");
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("Failed to verify OAuth state")
    })?;

    let stored = stored.ok_or_else(|| {
        warn!("Invalid, expired, already-consumed, or session-mismatched OAuth state");
        ErrorResponse::new(ErrorCode::InvalidToken).with_message("Invalid OAuth state")
    })?;

    let parsed: StoredState = serde_json::from_str(&stored).map_err(|e| {
        error!(error = ?e, "Failed to parse stored OAuth state");
        ErrorResponse::new(ErrorCode::InternalServerError).with_message("Corrupt OAuth state")
    })?;

    Ok(ConsumedOauthState {
        pkce_verifier: if parsed.v.is_empty() {
            None
        } else {
            Some(PkceCodeVerifier::new(parsed.v))
        },
        nonce: parsed.n,
    })
}
