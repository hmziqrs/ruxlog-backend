use oauth2::basic::BasicClient;
use oauth2::{AuthUrl, ClientId, ClientSecret, RedirectUrl, TokenUrl};

use crate::error::{ErrorCode, ErrorResponse};

/// Build the GitHub OAuth2 client from env config. GitHub supports PKCE, so the
/// controller uses a PKCE challenge/verifier in addition to the session-bound
/// CSRF state (matching the `google_auth_v1` flow). Required env:
/// `GITHUB_CLIENT_ID`, `GITHUB_CLIENT_SECRET`, `GITHUB_REDIRECT_URI`.
pub fn get_github_oauth_client() -> Result<BasicClient, ErrorResponse> {
    let client_id = std::env::var("GITHUB_CLIENT_ID").map_err(|_| {
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("GITHUB_CLIENT_ID not configured")
    })?;
    let client_secret = std::env::var("GITHUB_CLIENT_SECRET").map_err(|_| {
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("GITHUB_CLIENT_SECRET not configured")
    })?;
    let redirect_url = std::env::var("GITHUB_REDIRECT_URI").map_err(|_| {
        ErrorResponse::new(ErrorCode::InternalServerError)
            .with_message("GITHUB_REDIRECT_URI not configured")
    })?;

    let auth_url =
        AuthUrl::new("https://github.com/login/oauth/authorize".to_string()).map_err(|e| {
            ErrorResponse::new(ErrorCode::InternalServerError)
                .with_message("Invalid GitHub auth URL")
                .with_details(e.to_string())
        })?;
    let token_url = TokenUrl::new("https://github.com/login/oauth/access_token".to_string())
        .map_err(|e| {
            ErrorResponse::new(ErrorCode::InternalServerError)
                .with_message("Invalid GitHub token URL")
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
            .with_message("Invalid GitHub redirect URI")
            .with_details(e.to_string())
    })?);

    Ok(client)
}
