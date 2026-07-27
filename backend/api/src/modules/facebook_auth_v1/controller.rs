use axum::{
    extract::State,
    http::StatusCode,
    response::{IntoResponse, Redirect},
    Json,
};
use axum_macros::debug_handler;
use oauth2::{reqwest::async_http_client, AuthorizationCode, CsrfToken, Scope, TokenResponse};
use serde_json::json;
use tower_sessions::Session;
use tracing::{error, info, instrument, warn};

use crate::{
    error::{ErrorCode, ErrorResponse},
    extractors::ValidatedJson,
    extractors::ValidatedQuery,
    services::{auth::AuthSession, oauth},
    AppState,
};

use super::{
    service::get_facebook_oauth_client,
    validator::{FacebookCallbackQuery, FacebookExchangeRequest, FacebookUserInfo},
};

/// `GET /auth/facebook/v1/login` — begin the Facebook OAuth flow.
///
/// Builds the Facebook authorize URL with a session-bound CSRF `state` (no
/// PKCE — Facebook does not support it), persists the state single-use in redis,
/// and redirects the browser to Facebook. The state secret binds the authorize
/// request to THIS browser session so a state issued to one session cannot
/// complete the flow in another (login-CSRF / state-replay defense).
#[debug_handler]
#[instrument(skip(state, session), fields(result))]
pub async fn facebook_login(
    State(state): State<AppState>,
    session: Session,
) -> Result<impl IntoResponse, ErrorResponse> {
    info!("Initiating Facebook OAuth login");

    let client = get_facebook_oauth_client()?;
    let (auth_url, csrf_token) = client
        .authorize_url(CsrfToken::new_random)
        .add_scope(Scope::new("email".to_string()))
        .add_scope(Scope::new("public_profile".to_string()))
        .url();

    // Bind the CSRF state to THIS browser session. Empty PKCE verifier: Facebook
    // does not use PKCE; an empty value round-trips as `None` at consume time.
    let session_id = oauth::oauth_session_id(&session)?;
    oauth::store_oauth_state(&state, &session_id, csrf_token.secret(), "", None).await?;

    info!("Generated Facebook auth URL with session-bound CSRF state");
    tracing::Span::current().record("result", "success");

    Ok(Redirect::temporary(auth_url.as_str()))
}

/// `GET /auth/facebook/v1/callback` — server-side flow completion.
///
/// Facebook redirects here with `?code=...&state=...`. We consume the
/// single-use state, exchange the code for an access token, fetch the user's
/// Graph profile, resolve/link/create the local user, start a session, and
/// redirect to the SPA success route.
#[debug_handler]
#[instrument(skip(state, auth, query), fields(user_id, result))]
pub async fn facebook_callback(
    State(state): State<AppState>,
    mut auth: AuthSession,
    ValidatedQuery(query): ValidatedQuery<FacebookCallbackQuery>,
) -> Result<impl IntoResponse, ErrorResponse> {
    info!("Processing Facebook OAuth callback");

    let session_id = oauth::oauth_session_id(auth.session())?;
    let _oauth_state = oauth::consume_oauth_state(&state, &session_id, &query.state).await?;

    let client = get_facebook_oauth_client()?;
    let token_result = client
        .exchange_code(AuthorizationCode::new(query.code))
        // No PKCE verifier: Facebook does not support PKCE.
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            error!(error = ?e, "Failed to exchange Facebook authorization code");
            tracing::Span::current().record("result", "token_exchange_failed");
            ErrorResponse::new(ErrorCode::ExternalServiceError)
                .with_message("Failed to exchange authorization code")
                .with_details(e.to_string())
        })?;

    let access_token = token_result.access_token().secret();
    let user_info = fetch_facebook_user_info(&state.http_client, access_token).await?;
    let user = finish_facebook_login(&state, &mut auth, user_info).await?;

    info!(user_id = user.id, "Facebook login successful");
    tracing::Span::current().record("result", "success");

    let redirect_url = oauth::build_allowed_success_redirect("/auth/facebook/success")?;
    Ok(Redirect::temporary(&redirect_url))
}

/// `POST /auth/facebook/v1/exchange` — client-side flow.
///
/// The SPA receives the code+state directly from Facebook (redirect_uri pointed
/// at the SPA), then POSTs them here. We exchange + verify + server-session and
/// return the user as JSON.
#[debug_handler]
#[instrument(skip(state, auth, payload), fields(user_id, result))]
pub async fn facebook_exchange(
    State(state): State<AppState>,
    mut auth: AuthSession,
    ValidatedJson(payload): ValidatedJson<FacebookExchangeRequest>,
) -> Result<impl IntoResponse, ErrorResponse> {
    info!("Processing Facebook OAuth code exchange from client");

    let session_id = oauth::oauth_session_id(auth.session())?;
    let _oauth_state = oauth::consume_oauth_state(&state, &session_id, &payload.state).await?;

    let client = get_facebook_oauth_client()?;
    let token_result = client
        .exchange_code(AuthorizationCode::new(payload.code))
        .request_async(async_http_client)
        .await
        .map_err(|e| {
            error!(error = ?e, "Failed to exchange Facebook authorization code");
            tracing::Span::current().record("result", "token_exchange_failed");
            ErrorResponse::new(ErrorCode::ExternalServiceError)
                .with_message("Failed to exchange authorization code")
                .with_details(e.to_string())
        })?;

    let access_token = token_result.access_token().secret();
    let user_info = fetch_facebook_user_info(&state.http_client, access_token).await?;
    let user = finish_facebook_login(&state, &mut auth, user_info).await?;

    info!(
        user_id = user.id,
        "Facebook login successful via client exchange"
    );
    tracing::Span::current().record("result", "success");

    Ok((
        StatusCode::OK,
        Json(json!({
            "success": true,
            "user": user,
            "message": "Successfully authenticated with Facebook"
        })),
    ))
}

#[debug_handler(state = AppState)]
pub async fn facebook_user_info(auth: AuthSession) -> Result<impl IntoResponse, ErrorResponse> {
    match auth.user {
        Some(user) => Ok((StatusCode::OK, Json(json!(user)))),
        None => Err(ErrorResponse::new(ErrorCode::Unauthorized)),
    }
}

/// Fetch the user's Facebook profile via the Graph API `/me` endpoint.
async fn fetch_facebook_user_info(
    // V-MED-10: reuse the shared, timeout-configured client from AppState.
    http_client: &reqwest::Client,
    access_token: &str,
) -> Result<FacebookUserInfo, ErrorResponse> {
    http_client
        .get("https://graph.facebook.com/v18.0/me")
        .query(&[("fields", "id,name,email")])
        .bearer_auth(access_token)
        .send()
        .await
        .map_err(|e| {
            error!(error = ?e, "Failed to fetch user info from Facebook");
            ErrorResponse::new(ErrorCode::ExternalServiceError)
                .with_message("Failed to fetch user info from Facebook")
        })?
        .json()
        .await
        .map_err(|e| {
            error!(error = ?e, "Failed to parse user info from Facebook");
            ErrorResponse::new(ErrorCode::ExternalServiceError)
                .with_message("Failed to parse user info from Facebook")
        })
}

/// Resolve the Facebook identity to a local user and start a server session.
///
/// Facebook does NOT expose a per-email `verified` flag on `/me`. Graph API
/// returns only the user's primary, deliverable email — per Facebook's policy
/// these are verified at signup. We therefore treat a present `email` as
/// IdP-verified (the same trust basis Google's `verified_email=true` provides)
/// and apply the shared `find_or_create_user_for_oauth` email-verified gate. If
/// the user denied the email permission (`email` is `None`) we cannot create or
/// link an account and fail closed.
async fn finish_facebook_login(
    state: &AppState,
    auth: &mut AuthSession,
    user_info: FacebookUserInfo,
) -> Result<crate::db::sea_models::user::Model, ErrorResponse> {
    let email = user_info.email.clone().ok_or_else(|| {
        warn!("Facebook returned no email; cannot create/link account");
        ErrorResponse::new(ErrorCode::OperationNotAllowed)
            .with_message("Facebook did not provide an email address")
    })?;

    let name = user_info
        .name
        .unwrap_or_else(|| "Facebook User".to_string());
    let user = oauth::find_or_create_user_for_oauth(
        state,
        "facebook",
        &user_info.id,
        email,
        name,
        // Graph API emails are verified by Facebook policy (see fn doc).
        true,
    )
    .await?;

    oauth::finish_oauth_login(state, auth, &user, "Facebook").await?;
    Ok(user)
}
