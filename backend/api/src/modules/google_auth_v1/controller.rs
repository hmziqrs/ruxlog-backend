use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Json,
};
use axum_macros::debug_handler;
use oauth2::{
    reqwest::async_http_client, AuthorizationCode, CsrfToken, PkceCodeChallenge, Scope,
    TokenResponse,
};
use serde_json::json;
use tower_sessions::Session;
use tracing::{error, info, instrument, warn};

use crate::{
    db::sea_models::{user, user_session},
    error::{ErrorCode, ErrorResponse},
    extractors::ValidatedJson,
    extractors::ValidatedQuery,
    services::{auth::AuthSession, oauth},
    AppState,
};

use super::{
    service::{get_google_oauth_client, verify_google_id_token, GoogleIdTokenClaims},
    validator::{GoogleCallbackQuery, GoogleExchangeRequest, GoogleUserInfo},
};

#[debug_handler]
#[instrument(skip(state, session), fields(result))]
pub async fn google_login(
    State(state): State<AppState>,
    session: Session,
) -> Result<impl IntoResponse, ErrorResponse> {
    info!("Initiating Google OAuth login");

    let client = get_google_oauth_client()?;

    // PKCE: protect the authorization-code exchange against code interception /
    // replay. The verifier is stored server-side and consumed at the callback.
    let (pkce_challenge, pkce_verifier) = PkceCodeChallenge::new_random_sha256();

    // V-LOW-NONCE: a fresh OIDC nonce per authorize request. We send it to
    // Google (so it is echoed in the signed id_token) and store it server-side,
    // bound to the session + CSRF state. At the callback we require the verified
    // id_token's `nonce` claim to match exactly — binding the issued token to
    // THIS request and defeating token-injection / replay. oauth2 4.4 has no
    // dedicated nonce builder, so it goes through the generic `nonce` authorize
    // parameter via `add_extra_param`.
    let nonce = oauth::generate_oauth_nonce();

    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("openid".to_string()))
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("profile".to_string()))
        .add_extra_param("nonce", nonce.clone())
        .set_pkce_challenge(pkce_challenge)
        .url();

    // Bind the CSRF state to THIS browser session so a state issued to one
    // session cannot complete the flow in another (login CSRF / state replay).
    // The stored value is the PKCE verifier, which makes the lookup non-vacuous
    // (key != value) and lets us recover the verifier at the callback.
    let session_id = oauth::oauth_session_id(&session)?;
    oauth::store_oauth_state(
        &state,
        &session_id,
        csrf_token.secret(),
        pkce_verifier.secret(),
        Some(&nonce),
    )
    .await?;

    info!("Generated auth URL with PKCE + session-bound CSRF state + OIDC nonce");
    tracing::Span::current().record("result", "success");

    Ok(Redirect::temporary(auth_url.as_str()))
}

#[debug_handler]
#[instrument(skip(state, auth, query), fields(user_id, result))]
pub async fn google_callback(
    State(state): State<AppState>,
    mut auth: AuthSession,
    ValidatedQuery(query): ValidatedQuery<GoogleCallbackQuery>,
) -> Result<impl IntoResponse, ErrorResponse> {
    info!("Processing Google OAuth callback");

    let session_id = oauth::oauth_session_id(auth.session())?;
    let oauth_state = oauth::consume_oauth_state(&state, &session_id, &query.state).await?;

    let client = get_google_oauth_client()?;
    let mut exchange = client.exchange_code(AuthorizationCode::new(query.code));
    if let Some(verifier) = oauth_state.pkce_verifier {
        exchange = exchange.set_pkce_verifier(verifier);
    }
    let token_result = exchange
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            error!(error = ?e, "Failed to exchange authorization code");
            tracing::Span::current().record("result", "token_exchange_failed");
            ErrorResponse::new(ErrorCode::ExternalServiceError)
                .with_message("Failed to exchange authorization code")
                .with_details(e.to_string())
        })?;

    let user = finish_google_login(
        &state,
        &mut auth,
        token_result,
        oauth_state.nonce.as_deref(),
    )
    .await?;

    info!(user_id = user.id, "Google login successful");
    tracing::Span::current().record("result", "success");

    // V-LOW-REDIRECT: validate the post-login success origin against an
    // allow-list before issuing the redirect. We always land on our own
    // `/auth/google/success` route; the ORIGIN (scheme+host+port) must be one we
    // trust, otherwise an open-redirect-like confusion is possible via a
    // tampered FRONTEND_URL at runtime.
    let redirect_url = oauth::build_allowed_success_redirect("/auth/google/success")?;

    Ok(Redirect::temporary(&redirect_url))
}

#[debug_handler(state = AppState)]
pub async fn google_user_info(auth: AuthSession) -> Result<impl IntoResponse, ErrorResponse> {
    match auth.user {
        Some(user) => Ok((StatusCode::OK, Json(json!(user)))),
        None => Err(ErrorResponse::new(ErrorCode::Unauthorized)),
    }
}

/// Exchange authorization code from client-side OAuth callback
///
/// Flow:
/// 1. Client calls GET /auth/google/v1/login to get auth URL
/// 2. Client redirects user to Google OAuth (with client's redirect_uri)
/// 3. Google redirects back to CLIENT with code and state
/// 4. Client POSTs code and state to this endpoint
/// 5. API exchanges code (with PKCE verifier), verifies the id_token, creates
///    session, returns user info
#[debug_handler]
#[instrument(skip(state, auth, payload), fields(user_id, result))]
pub async fn google_exchange(
    State(state): State<AppState>,
    mut auth: AuthSession,
    ValidatedJson(payload): ValidatedJson<GoogleExchangeRequest>,
) -> Result<impl IntoResponse, ErrorResponse> {
    info!("Processing Google OAuth code exchange from client");

    let session_id = oauth::oauth_session_id(auth.session())?;
    let oauth_state = oauth::consume_oauth_state(&state, &session_id, &payload.state).await?;

    let client = get_google_oauth_client()?;
    let mut exchange = client.exchange_code(AuthorizationCode::new(payload.code));
    if let Some(verifier) = oauth_state.pkce_verifier {
        exchange = exchange.set_pkce_verifier(verifier);
    }
    let token_result = exchange
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            error!(error = ?e, "Failed to exchange authorization code");
            tracing::Span::current().record("result", "token_exchange_failed");
            ErrorResponse::new(ErrorCode::ExternalServiceError)
                .with_message("Failed to exchange authorization code")
                .with_details(e.to_string())
        })?;

    let user = finish_google_login(
        &state,
        &mut auth,
        token_result,
        oauth_state.nonce.as_deref(),
    )
    .await?;

    info!(
        user_id = user.id,
        "Google login successful via client exchange"
    );
    tracing::Span::current().record("result", "success");

    Ok((
        StatusCode::OK,
        Json(json!({
            "success": true,
            "user": user,
            "message": "Successfully authenticated with Google"
        })),
    ))
}

/// Shared post-exchange logic: verify the id_token signature/claims (defense in
/// depth), fetch profile data via userinfo, cross-check that the cryptographically
/// verified identity matches the userinfo, then create/link the user + session.
async fn finish_google_login(
    state: &AppState,
    auth: &mut AuthSession,
    token_result: oauth2::StandardTokenResponse<
        super::service::IdTokenFields,
        oauth2::basic::BasicTokenType,
    >,
    expected_nonce: Option<&str>,
) -> Result<user::Model, ErrorResponse> {
    let access_token = token_result.access_token().secret();

    // Verify the id_token signature against Google's JWKS when present. This is
    // defense-in-depth: the access token already came from Google's token
    // endpoint for our PKCE-bound code. We additionally require the id_token's
    // `sub`/`email` to match the userinfo response so a token-substitution
    // attack can't pin a verified identity to a different profile.
    // The openid scope is requested, so Google always returns an id_token.
    // Requiring it (and verifying its signature) closes the defense-in-depth
    // gap of trusting only the bearer-authenticated userinfo endpoint.
    let id_token = token_result
        .extra_fields()
        .id_token
        .as_deref()
        .ok_or_else(|| {
            warn!("Google token response omitted id_token; rejecting login");
            tracing::Span::current().record("result", "missing_id_token");
            ErrorResponse::new(ErrorCode::InvalidToken)
                .with_message("OAuth identity verification failed")
        })?;

    let client_id = std::env::var("GOOGLE_CLIENT_ID").map_err(|_| {
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("GOOGLE_CLIENT_ID not configured")
    })?;
    let id_claims: Option<GoogleIdTokenClaims> =
        match verify_google_id_token(id_token, &client_id, expected_nonce).await {
            Ok(claims) => Some(claims),
            Err(err) => {
                warn!(error = ?err, "id_token verification failed; rejecting login");
                return Err(err);
            }
        };

    let user_info = fetch_google_user_info(&state.http_client, access_token).await?;
    info!(google_id = %user_info.id, email = %user_info.email, "Retrieved user info from Google");

    // Cross-check the verified id_token identity against the userinfo payload.
    if let Some(claims) = &id_claims {
        if claims.sub != user_info.id || claims.email != user_info.email {
            warn!(
                id_sub = %claims.sub,
                userinfo_id = %user_info.id,
                "id_token/userinfo identity mismatch — rejecting login"
            );
            return Err(ErrorResponse::new(ErrorCode::InvalidToken)
                .with_message("OAuth identity verification failed"));
        }
    }

    let user = find_or_create_user(state, user_info).await?;
    tracing::Span::current().record("user_id", user.id);

    auth.login(&user).await.map_err(|e| {
        error!(error = %e, user_id = user.id, "Failed to create session");
        tracing::Span::current().record("result", "session_creation_failed");
        ErrorResponse::new(ErrorCode::InternalServerError).with_message("Failed to create session")
    })?;

    let session_row = user_session::Entity::create(
        &state.sea_db,
        user_session::NewUserSession::new(user.id, Some("Google OAuth".to_string()), None),
    )
    .await
    .ok();

    // V-HIGH-2: record the PG-row -> tower-session-id mapping so
    // `sessions_terminate` can later DEL the live tower-sessions record. The
    // password-login path does the same; OAuth login previously omitted this,
    // leaving Google-logged-in sessions un-revocable. `auth.login` cycles the
    // session id (None until saved), so save first to materialize it.
    if (auth.session().save().await).is_ok() {
        if let (Some(row), Some(tower_sid)) = (session_row.as_ref(), auth.session().id()) {
            crate::modules::auth_v1::controller::record_session_mapping(
                &state.redis_pool,
                row.id,
                &tower_sid.to_string(),
            )
            .await;
        }
    }

    Ok(user)
}

async fn fetch_google_user_info(
    // V-MED-10: use the shared, timeout-configured client from `AppState` so a
    // hanging Google userinfo endpoint can never pin this handler thread.
    http_client: &reqwest::Client,
    access_token: &str,
) -> Result<GoogleUserInfo, ErrorResponse> {
    http_client
        .get("https://www.googleapis.com/oauth2/v2/userinfo")
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            error!(error = ?e, "Failed to fetch user info from Google");
            ErrorResponse::new(ErrorCode::ExternalServiceError)
                .with_message("Failed to fetch user info from Google")
        })?
        .json()
        .await
        .map_err(|e| {
            error!(error = ?e, "Failed to parse user info from Google");
            ErrorResponse::new(ErrorCode::ExternalServiceError)
                .with_message("Failed to parse user info from Google")
        })
}

async fn find_or_create_user(
    state: &AppState,
    user_info: GoogleUserInfo,
) -> Result<user::Model, ErrorResponse> {
    if let Some(existing_user) =
        user::Entity::find_by_google_id(&state.sea_db, user_info.id.clone()).await?
    {
        info!(
            user_id = existing_user.id,
            "Existing user found by Google ID"
        );
        return Ok(existing_user);
    }

    if let Some(existing_user) =
        user::Entity::find_by_email(&state.sea_db, user_info.email.clone()).await?
    {
        // Linking a Google identity onto an existing local account is only safe
        // when the IdP has verified the account actually owns that email.
        // Otherwise an attacker controlling an unverified-at-IdP Google account
        // with the victim's email would take over the account. Fail closed: do
        // not link and do not create a duplicate (the email is already taken).
        if !user_info.verified_email {
            warn!(
                user_id = existing_user.id,
                email = %user_info.email,
                "Refusing to link Google account: IdP email is not verified"
            );
            return Err(ErrorResponse::new(ErrorCode::OperationNotAllowed)
                .with_message("Unable to link this Google account"));
        }

        info!(
            user_id = existing_user.id,
            "Linking Google account to existing user"
        );

        use sea_orm::ActiveModelTrait;
        let mut active: user::ActiveModel = existing_user.clone().into();
        active.google_id = sea_orm::Set(Some(user_info.id.clone()));
        active.oauth_provider = sea_orm::Set(Some("google".to_string()));
        active.updated_at = sea_orm::Set(chrono::Utc::now().fixed_offset());

        let existing_user = active.update(&state.sea_db).await.map_err(|e| {
            error!(error = ?e, "Failed to link Google account");
            ErrorResponse::new(ErrorCode::InternalServerError)
                .with_message("Failed to link Google account")
        })?;

        return Ok(existing_user);
    }

    // OAUTH-CREATE-UNVERIFIED: the link branch above (line ~552) refuses to bind
    // a Google identity to an existing account unless the IdP verified the
    // email. The CREATE branch must apply the SAME gate — otherwise an attacker
    // who sets an unverified-at-Google primary email to a victim's address gets
    // a brand-new verified (is_verified=true) local account in the victim's name
    // (trust spoofing) and squats the email so the victim can never register.
    // Fail closed: do not auto-create; the user signs up via normal email
    // verification instead.
    if !user_info.verified_email {
        warn!(
            email = %user_info.email,
            "Refusing to create account from Google: IdP email is not verified"
        );
        return Err(ErrorResponse::new(ErrorCode::OperationNotAllowed)
            .with_message("Google has not verified this email address"));
    }

    info!("Creating new user from Google account");
    user::Entity::create_from_google(
        &state.sea_db,
        user_info.id.clone(),
        user_info.email.clone(),
        user_info.name.clone(),
    )
    .await
}
