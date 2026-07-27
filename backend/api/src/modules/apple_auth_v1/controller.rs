use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Json,
};
use axum_macros::debug_handler;
use oauth2::PkceCodeChallenge;
use serde_json::json;
use tower_sessions::Session;
use tracing::{info, instrument, warn};

use crate::{
    error::{ErrorCode, ErrorResponse},
    extractors::ValidatedJson,
    extractors::ValidatedQuery,
    services::{auth::AuthSession, oauth},
    AppState,
};

use super::{
    service::{
        build_apple_authorize_url, exchange_apple_code, load_apple_config,
        mint_apple_client_secret, verify_apple_id_token,
    },
    validator::{AppleCallbackQuery, AppleExchangeRequest},
};

/// `GET /auth/apple/v1/login` — begin the Apple Sign-in flow.
///
/// Builds Apple's authorize URL with PKCE + session-bound CSRF state + OIDC
/// nonce, persists the state single-use in redis, and redirects the browser to
/// Apple. `response_mode=query` keeps Apple's redirect as a GET `?code&state`,
/// matching our other providers.
#[debug_handler]
#[instrument(skip(state, session), fields(result))]
pub async fn apple_login(
    State(state): State<AppState>,
    session: Session,
) -> Result<impl IntoResponse, ErrorResponse> {
    info!("Initiating Apple Sign-in");

    let cfg = load_apple_config()?;
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();
    let nonce = oauth::generate_oauth_nonce();
    let csrf = oauth2::CsrfToken::new_random();

    let auth_url = build_apple_authorize_url(&cfg, csrf.secret(), pkce_challenge.as_str(), &nonce)?;

    let session_id = oauth::oauth_session_id(&session)?;
    oauth::store_oauth_state(
        &state,
        &session_id,
        csrf.secret(),
        pkce_verifier.secret(),
        Some(&nonce),
    )
    .await?;

    info!("Generated Apple auth URL with PKCE + session-bound CSRF state + OIDC nonce");
    tracing::Span::current().record("result", "success");

    Ok(Redirect::temporary(&auth_url))
}

/// `GET /auth/apple/v1/callback` — server-side flow completion.
#[debug_handler]
#[instrument(skip(state, auth, query), fields(user_id, result))]
pub async fn apple_callback(
    State(state): State<AppState>,
    mut auth: AuthSession,
    ValidatedQuery(query): ValidatedQuery<AppleCallbackQuery>,
) -> Result<impl IntoResponse, ErrorResponse> {
    info!("Processing Apple OAuth callback");

    let user = finish_apple_code(&state, &mut auth, &query.code, &query.state).await?;

    info!(user_id = user.id, "Apple login successful");
    tracing::Span::current().record("result", "success");

    let redirect_url = oauth::build_allowed_success_redirect("/auth/apple/success")?;
    Ok(Redirect::temporary(&redirect_url))
}

/// `POST /auth/apple/v1/exchange` — client-side flow.
#[debug_handler]
#[instrument(skip(state, auth, payload), fields(user_id, result))]
pub async fn apple_exchange(
    State(state): State<AppState>,
    mut auth: AuthSession,
    ValidatedJson(payload): ValidatedJson<AppleExchangeRequest>,
) -> Result<impl IntoResponse, ErrorResponse> {
    info!("Processing Apple OAuth code exchange from client");

    let user = finish_apple_code(&state, &mut auth, &payload.code, &payload.state).await?;

    info!(
        user_id = user.id,
        "Apple login successful via client exchange"
    );
    tracing::Span::current().record("result", "success");

    Ok((
        StatusCode::OK,
        Json(json!({
            "success": true,
            "user": user,
            "message": "Successfully authenticated with Apple"
        })),
    ))
}

#[debug_handler(state = AppState)]
pub async fn apple_user_info(auth: AuthSession) -> Result<impl IntoResponse, ErrorResponse> {
    match auth.user {
        Some(user) => Ok((StatusCode::OK, Json(json!(user)))),
        None => Err(ErrorResponse::new(ErrorCode::Unauthorized)),
    }
}

/// Shared code-exchange + id_token verification + user resolution + session
/// start for the callback and client-exchange flows.
async fn finish_apple_code(
    state: &AppState,
    auth: &mut AuthSession,
    code: &str,
    state_secret: &str,
) -> Result<crate::db::sea_models::user::Model, ErrorResponse> {
    // Consume the single-use state: PKCE verifier + OIDC nonce.
    let session_id = oauth::oauth_session_id(auth.session())?;
    let oauth_state = oauth::consume_oauth_state(state, &session_id, state_secret).await?;
    // Echo the PKCE verifier in the token exchange (Apple enforces PKCE when a
    // code_challenge was sent).
    let code_verifier = oauth_state
        .pkce_verifier
        .as_ref()
        .map(|v| v.secret().to_string());
    let nonce = oauth_state.nonce;

    let cfg = load_apple_config()?;
    let client_secret_jwt = mint_apple_client_secret(&cfg)?;

    // Exchange the code (hand-rolled: Apple's client_secret is a signed JWT).
    let token_resp = exchange_apple_code(
        &state.http_client,
        &cfg,
        code,
        &client_secret_jwt,
        code_verifier.as_deref(),
    )
    .await?;

    // Verify the id_token (RS256, Apple JWKS) and bind it to our nonce.
    let claims =
        verify_apple_id_token(&token_resp.id_token, &cfg.client_id, nonce.as_deref()).await?;

    let email = claims.email.clone().ok_or_else(|| {
        warn!("Apple id_token carried no email; cannot create/link account");
        ErrorResponse::new(ErrorCode::OperationNotAllowed)
            .with_message("Apple did not provide an email address")
    })?;

    // Apple may hand back a "Hide My Email" relay address. We treat relay
    // addresses as verified iff Apple says so (email_verified == "true"); they
    // are real, deliverable Apple-owned addresses.
    let email_verified = claims.is_email_verified();
    let name = "Apple User".to_string(); // Apple only sends the name once, on first auth, in the callback `user` blob.

    let user = oauth::find_or_create_user_for_oauth(
        state,
        "apple",
        &claims.sub,
        email,
        name,
        email_verified,
    )
    .await?;

    oauth::finish_oauth_login(state, auth, &user, "Apple").await?;
    Ok(user)
}
