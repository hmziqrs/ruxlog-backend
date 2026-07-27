use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};

use crate::error::{ErrorCode, ErrorResponse};

/// Build the Facebook OAuth2 client from env config.
///
/// Facebook's server-side OAuth flow does NOT support PKCE (the dialog ignores
/// `code_challenge`), so we rely on the session-bound CSRF `state` alone for
/// replay protection — the same single-use, redis-backed state every other
/// provider uses. The `client_secret` is sent in the token exchange.
///
/// Required env: `FACEBOOK_CLIENT_ID`, `FACEBOOK_CLIENT_SECRET`,
/// `FACEBOOK_REDIRECT_URI`.
pub fn get_facebook_oauth_client() -> Result<BasicClient, ErrorResponse> {
    let client_id = std::env::var("FACEBOOK_CLIENT_ID").map_err(|_| {
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("FACEBOOK_CLIENT_ID not configured")
    })?;
    let client_secret = std::env::var("FACEBOOK_CLIENT_SECRET").map_err(|_| {
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("FACEBOOK_CLIENT_SECRET not configured")
    })?;
    let redirect_url = std::env::var("FACEBOOK_REDIRECT_URI").map_err(|_| {
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("FACEBOOK_REDIRECT_URI not configured")
    })?;

    let auth_url = AuthUrl::new("https://www.facebook.com/v18.0/dialog/oauth".to_string())
        .map_err(|e| {
            ErrorResponse::new(ErrorCode::InternalServerError)
                .with_message("Invalid Facebook auth URL")
                .with_details(e.to_string())
        })?;
    let token_url = TokenUrl::new(
        "https://graph.facebook.com/v18.0/oauth/access_token".to_string(),
    )
    .map_err(|e| {
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("Invalid Facebook token URL")
            .with_details(e.to_string())
    })?;

    let client = BasicClient::new(
        ClientId::new(client_id),
        Some(ClientSecret::new(client_secret)),
        auth_url,
        Some(token_url),
    )
    .set_redirect_uri(RedirectUrl::new(redirect_url).map_err(|e| {
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("Invalid Facebook redirect URI")
            .with_details(e.to_string())
    })?);

    Ok(client)
}
